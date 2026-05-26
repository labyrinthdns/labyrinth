package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/internal/pool"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/resolver"
	"github.com/labyrinthdns/labyrinth/security"
)

// Handler processes a raw DNS query and returns a raw DNS response.
type Handler interface {
	Handle(query []byte, clientAddr net.Addr) ([]byte, error)
}

// MainHandler ties together parsing, resolution, and response assembly.
type MainHandler struct {
	resolver      *resolver.Resolver
	cache         *cache.Cache
	limiter       *security.RateLimiter
	rrl           *security.RRL
	acl           *security.ACL
	metrics       *metrics.Metrics
	logger        *slog.Logger
	noCacheNets   []*net.IPNet
	privateFilter bool
	blocklist     interface {
		IsBlocked(string) bool
		BlockingMode() string
		CustomIP() string
	}

	// DNS Cookies (RFC 7873)
	cookiesEnabled bool
	cookieSecret   []byte // 16-byte server secret for HMAC

	// ECS forwarding
	ecsEnabled     bool
	ecsMaxPrefix   int // IPv4 source-prefix ceiling
	ecsMaxPrefixV6 int // IPv6 source-prefix ceiling

	// downstreamUDPBufferSize is the EDNS0 UDP payload size advertised in
	// outgoing OPT records on responses to clients. RFC 9018 / DNS Flag Day
	// 2020 recommends 1232 to avoid IP fragmentation, which closes the
	// off-path fragment-injection cache-poisoning vector. 0 means "use
	// the safe default" (1232).
	downstreamUDPBufferSize int

	// OnQuery is an optional callback invoked after each query is resolved.
	// Parameters: client IP, qname, qtype, rcode (may be "BLOCKED"), whether served from cache, duration in ms.
	OnQuery func(client, qname, qtype, rcode string, cached bool, durationMs float64)
}

// SetPrivateFilter enables or disables private address filtering.
func (h *MainHandler) SetPrivateFilter(enabled bool) {
	h.privateFilter = enabled
}

// SetBlocklist configures an optional blocklist for the handler.
func (h *MainHandler) SetBlocklist(bl interface {
	IsBlocked(string) bool
	BlockingMode() string
	CustomIP() string
}) {
	h.blocklist = bl
}

// NewMainHandler creates a new MainHandler.
func NewMainHandler(
	res *resolver.Resolver,
	c *cache.Cache,
	rl *security.RateLimiter,
	rrl *security.RRL,
	acl *security.ACL,
	m *metrics.Metrics,
	logger *slog.Logger,
) *MainHandler {
	return &MainHandler{
		resolver: res,
		cache:    c,
		limiter:  rl,
		rrl:      rrl,
		acl:      acl,
		metrics:  m,
		logger:   logger,
	}
}

// EnableCookies enables DNS cookie support (RFC 7873).
// A random 16-byte server secret is generated at startup. M-6: if the OS
// RNG fails we refuse to enable cookies rather than fall back to a public
// literal (which would defeat the anti-spoofing property entirely).
func (h *MainHandler) EnableCookies() error {
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		h.cookiesEnabled = false
		h.cookieSecret = nil
		if h.logger != nil {
			h.logger.Error("DNS cookies disabled: failed to generate server secret", "error", err)
		}
		return fmt.Errorf("dns cookies: secret generation failed: %w", err)
	}
	h.cookiesEnabled = true
	h.cookieSecret = secret
	return nil
}

// EnableCookiesWithSecret enables DNS cookies with a specific secret (for testing).
func (h *MainHandler) EnableCookiesWithSecret(secret []byte) {
	h.cookiesEnabled = true
	h.cookieSecret = make([]byte, len(secret))
	copy(h.cookieSecret, secret)
}

// SetECS enables or disables ECS forwarding.
// maxPrefix and maxPrefixV6 cap the source-prefix length we forward upstream
// for IPv4 and IPv6 clients respectively. Pass 0 or out-of-range values to
// accept the RFC 7871 §11.1 recommended defaults (/24 IPv4, /56 IPv6).
func (h *MainHandler) SetECS(enabled bool, maxPrefix int) {
	h.SetECSPrefixes(enabled, maxPrefix, 0)
}

// SetECSPrefixes is the IPv6-aware extension of SetECS. The legacy SetECS
// is preserved as a convenience wrapper for callers that only care about
// IPv4 limits.
func (h *MainHandler) SetECSPrefixes(enabled bool, maxPrefixV4, maxPrefixV6 int) {
	h.ecsEnabled = enabled
	h.ecsMaxPrefix = maxPrefixV4
	h.ecsMaxPrefixV6 = maxPrefixV6
}

// buildOutboundECS prepares the EDNS Client Subnet option (RFC 7871) that
// the resolver should forward upstream for this query. Policy: passthrough.
//
//   - If the client sent ECS in its OPT record, forward it. Source prefix is
//     clamped down to the operator's ECSMaxPrefix ceiling. A client-sent
//     SourcePrefixLen of 0 is an explicit opt-out and is preserved verbatim
//     (the upstream sees "/0" and MUST NOT subnet-tailor).
//   - If the client did not send ECS, do nothing — we do not synthesize
//     from clientIP. (Synthesis would leak the resolver's clients' subnets
//     to every authoritative server, which is the privacy hazard RFC 7871
//     §11 calls out.)
//   - Reserved / private / loopback / CGNAT / link-local source addresses
//     are stripped: such ranges are never globally meaningful to any
//     upstream CDN and would only serve as a side-channel fingerprint of
//     the operator's network.
//
// Returns nil when no ECS should be forwarded for this query.
func (h *MainHandler) buildOutboundECS(opt *dns.EDNS0) *dns.ECSOption {
	if !h.ecsEnabled || opt == nil {
		return nil
	}
	clientECS, err := dns.ExtractECSFromOPT(opt)
	if err != nil || clientECS == nil {
		return nil
	}
	// Honour explicit /0 opt-out — forward unchanged so the upstream sees it.
	if clientECS.SourcePrefixLen == 0 {
		out := *clientECS
		out.ScopePrefixLen = 0
		return &out
	}
	// Suppress non-public source addresses entirely.
	if security.IsReservedIP(clientECS.Address) {
		return nil
	}

	// Cap source prefix at the operator's per-family ceiling (RFC 7871
	// §11.1 recommends /24 for IPv4 and /56 for IPv6). Out-of-range or
	// zero configuration falls back to those recommended defaults.
	maxV4 := h.ecsMaxPrefix
	if maxV4 <= 0 || maxV4 > 32 {
		maxV4 = 24
	}
	maxV6 := h.ecsMaxPrefixV6
	if maxV6 <= 0 || maxV6 > 128 {
		maxV6 = 56
	}
	src := clientECS.SourcePrefixLen
	switch clientECS.Family {
	case 1: // IPv4
		if int(src) > maxV4 {
			src = uint8(maxV4)
		}
	case 2: // IPv6
		if int(src) > maxV6 {
			src = uint8(maxV6)
		}
	default:
		return nil // unknown family — strip
	}

	out := dns.ECSOption{
		Family:          clientECS.Family,
		SourcePrefixLen: src,
		ScopePrefixLen:  0, // outgoing queries always set scope=0
		Address:         dns.TruncateIP(clientECS.Address, src),
	}
	return &out
}

// chooseCacheECSKey decides under which ECS scope the result of this query
// should be stored or fetched from cache. The rules follow RFC 7871 §7.3:
//
//   - No outbound ECS was sent → cache globally (key "").
//   - Upstream returned scope=0 → cache globally (one entry serves all
//     clients, even though we sent ECS).
//   - Upstream returned scope>0 → cache under the truncated client subnet
//     at the returned scope length. Clients whose subnet falls within that
//     scope share the entry; clients in a different subnet get their own.
//
// outboundECS is the ECS option we sent upstream (or were going to);
// upstreamECS is the option the upstream echoed back (nil if no ECS was
// returned). Either may be nil.
func chooseCacheECSKey(outboundECS, upstreamECS *dns.ECSOption) string {
	if outboundECS == nil {
		return ""
	}
	if upstreamECS == nil {
		// Upstream is ECS-unaware — treat the answer as global. CDN behaviour
		// here is the same as if we had never sent ECS.
		return ""
	}
	if upstreamECS.ScopePrefixLen == 0 {
		return ""
	}
	scoped := dns.ECSOption{
		Family:          outboundECS.Family,
		SourcePrefixLen: upstreamECS.ScopePrefixLen,
		Address:         dns.TruncateIP(outboundECS.Address, upstreamECS.ScopePrefixLen),
	}
	return scoped.CacheKey()
}

// SetDownstreamUDPBufferSize configures the EDNS0 UDP payload size this
// server advertises to clients in outgoing OPT records. Per RFC 9018 /
// DNS Flag Day 2020, the safe default is 1232 (IPv6 minimum MTU 1280
// minus 40-byte IPv6 header minus 8-byte UDP header). Values outside
// [512, 65535] are silently clamped to 1232 by advertisedUDPBufferSize.
func (h *MainHandler) SetDownstreamUDPBufferSize(size int) {
	h.downstreamUDPBufferSize = size
}

// advertisedUDPBufferSize returns the EDNS0 UDP payload size to put on
// the wire in outgoing OPT records. Falls back to the RFC 9018 default
// of 1232 for unset (0) and out-of-range values, so a misconfigured
// integer can never produce a pathological OPT record.
func (h *MainHandler) advertisedUDPBufferSize() uint16 {
	const (
		defaultSize = 1232
		minSize     = 512   // RFC 6891 §6.2.5 mandated minimum
		maxSize     = 65535 // uint16 ceiling
	)
	v := h.downstreamUDPBufferSize
	if v < minSize || v > maxSize {
		return defaultSize
	}
	return uint16(v)
}

// nowFunc returns the current Unix timestamp. Overridden in tests.
var nowFunc = func() uint32 { return uint32(time.Now().Unix()) }

// generateServerCookie produces a 16-byte server cookie per RFC 9018:
// Version(1) + Reserved(3) + Timestamp(4) + Hash(8).
// Hash = SipHash-2-4(ClientCookie | Version | Reserved | Timestamp | ClientIP, Secret).
func (h *MainHandler) generateServerCookie(clientCookie []byte, clientIP string) []byte {
	return h.generateServerCookieAt(clientCookie, clientIP, nowFunc())
}

func (h *MainHandler) generateServerCookieAt(clientCookie []byte, clientIP string, timestamp uint32) []byte {
	cookie := make([]byte, 16)
	cookie[0] = 1 // Version = 1 (RFC 9018)
	// cookie[1:4] = 0 (Reserved)
	binary.BigEndian.PutUint32(cookie[4:8], timestamp)

	// SipHash input: Client Cookie + header (Version+Reserved+Timestamp) + Client IP bytes
	ipBytes := parseIPBytes(clientIP)
	msg := make([]byte, 0, 8+8+len(ipBytes))
	msg = append(msg, clientCookie...)
	msg = append(msg, cookie[:8]...) // Version + Reserved + Timestamp
	msg = append(msg, ipBytes...)

	var key [16]byte
	copy(key[:], h.cookieSecret)
	hash := security.SipHash24(key, msg)
	binary.LittleEndian.PutUint64(cookie[8:16], hash)

	return cookie
}

// validateServerCookie checks whether a received server cookie is valid and
// not older than 1 hour per RFC 9018 §4.3.
func (h *MainHandler) validateServerCookie(clientCookie, serverCookie []byte, clientIP string) bool {
	if len(serverCookie) != 16 || serverCookie[0] != 1 {
		return false
	}
	timestamp := binary.BigEndian.Uint32(serverCookie[4:8])
	now := nowFunc()
	if now > timestamp && now-timestamp > 3600 {
		return false // expired (1 hour)
	}
	expected := h.generateServerCookieAt(clientCookie, clientIP, timestamp)
	return subtle.ConstantTimeCompare(serverCookie, expected) == 1
}

// parseIPBytes returns the raw IP bytes for the given address string.
func parseIPBytes(ipStr string) []byte {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return []byte(ipStr)
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4
	}
	return ip.To16()
}

// appendECSToResponse parses a packed wire-format response, appends the
// given EDNS Client Subnet option to the existing OPT record (or builds
// one if none is present), and re-packs. Used to echo the client's ECS
// back per RFC 7871 §7.2.1 so the client knows the answer was geo-tailored.
// Returns the original bytes on any parse/encode error.
func appendECSToResponse(resp []byte, ecs *dns.ECSOption) []byte {
	if ecs == nil {
		return resp
	}
	msg, err := dns.Unpack(resp)
	if err != nil {
		return resp
	}
	ecsOpt := dns.BuildECS(ecs)
	found := false
	for i, rr := range msg.Additional {
		if rr.Type != dns.TypeOPT {
			continue
		}
		optData := make([]byte, 4+len(ecsOpt.Data))
		binary.BigEndian.PutUint16(optData[0:2], ecsOpt.Code)
		binary.BigEndian.PutUint16(optData[2:4], uint16(len(ecsOpt.Data)))
		copy(optData[4:], ecsOpt.Data)
		msg.Additional[i].RData = append(msg.Additional[i].RData, optData...)
		msg.Additional[i].RDLength = uint16(len(msg.Additional[i].RData))
		found = true
		break
	}
	if !found {
		const defaultSize uint16 = 1232
		msg.Additional = append(msg.Additional,
			dns.BuildOPTWithOptions(defaultSize, false, []dns.EDNSOption{ecsOpt}))
	}
	out, err := dns.Pack(msg, make([]byte, 4096))
	if err != nil {
		return resp
	}
	return append([]byte(nil), out...)
}

// addEDEToResponse appends an EDE option to the response OPT record.
// If no OPT record exists, one is created using the handler's advertised
// UDP buffer size (RFC 9018 / DNS Flag Day 2020 ceiling).
func (h *MainHandler) addEDEToResponse(resp *dns.Message, code uint16, text string) {
	edeOpt := dns.BuildEDEOption(code, text)

	// Look for existing OPT record in Additional
	for i, rr := range resp.Additional {
		if rr.Type == dns.TypeOPT {
			// Append EDE option data to existing OPT RDATA
			optData := make([]byte, 4+len(edeOpt.Data))
			binary.BigEndian.PutUint16(optData[0:2], edeOpt.Code)
			binary.BigEndian.PutUint16(optData[2:4], uint16(len(edeOpt.Data)))
			copy(optData[4:], edeOpt.Data)
			resp.Additional[i].RData = append(resp.Additional[i].RData, optData...)
			resp.Additional[i].RDLength = uint16(len(resp.Additional[i].RData))
			return
		}
	}

	// No OPT record found — create one with EDE using the handler's
	// advertised UDP buffer size (RFC 9018 / DNS Flag Day 2020 ceiling).
	// This branch only fires when an upstream response lacked an OPT,
	// so the value is a fallback rather than a per-query advertisement.
	resp.Additional = append(resp.Additional, dns.BuildOPTWithOptions(h.advertisedUDPBufferSize(), false, []dns.EDNSOption{edeOpt}))
}

// addEDEToRawResponse parses a wire-format response, appends an EDE option,
// and re-packs it. Returns the original bytes on any error.
func (h *MainHandler) addEDEToRawResponse(resp []byte, code uint16, text string) []byte {
	msg, err := dns.Unpack(resp)
	if err != nil {
		return resp
	}
	h.addEDEToResponse(msg, code, text)
	out, packErr := h.packToOwnedBytes(msg)
	if packErr != nil {
		return resp
	}
	return out
}

// packToOwnedBytes packs msg using a pooled buffer and returns an owned
// copy of the wire bytes. The pooled buffer is always released before
// return. H-5: closes the use-after-pool race where concurrent goroutines
// would receive each other's response payload because `dns.Pack` returns
// a slice into the pooled buffer's backing array.
func (h *MainHandler) packToOwnedBytes(msg *dns.Message) ([]byte, error) {
	bufPtr := pool.GetBuffer()
	buf := *bufPtr
	packed, err := dns.Pack(msg, buf)
	if err != nil {
		pool.PutBuffer(bufPtr)
		return nil, err
	}
	out := append([]byte(nil), packed...)
	pool.PutBuffer(bufPtr)
	return out, nil
}

// SetNoCacheClients configures the list of client IPs/CIDRs that should bypass the cache.
func (h *MainHandler) SetNoCacheClients(cidrs []string) {
	for _, cidr := range cidrs {
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			h.noCacheNets = append(h.noCacheNets, ipNet)
		}
	}
}

// shouldBypassCache returns true if the given client IP should bypass the cache.
func (h *MainHandler) shouldBypassCache(clientIP string) bool {
	if len(h.noCacheNets) == 0 {
		return false
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	for _, ipNet := range h.noCacheNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func (h *MainHandler) Handle(query []byte, clientAddr net.Addr) ([]byte, error) {
	start := time.Now()

	// Extract client IP
	clientIP := extractIP(clientAddr)

	// Global ACL check (fast pre-parse check without zone context).
	// Zone-specific ACL is checked after the query is parsed.
	if h.acl != nil && !h.acl.Check(clientIP) {
		return h.buildError(query, dns.RCodeRefused)
	}

	// Rate limit check
	if h.limiter != nil && !h.limiter.Allow(clientIP) {
		h.metrics.IncRateLimited()
		h.metrics.IncResponses("REFUSED")
		return h.buildError(query, dns.RCodeRefused)
	}

	// 1. Parse incoming query
	msg, err := dns.Unpack(query)
	if err != nil {
		h.metrics.IncResponses("FORMERR")
		return h.buildError(query, dns.RCodeFormErr)
	}

	// 2. Validate
	if msg.Header.QR() {
		return nil, errors.New("received response as query")
	}
	if msg.Header.Opcode() != dns.OpcodeQuery {
		h.metrics.IncResponses("NOTIMP")
		return h.buildError(query, dns.RCodeNotImp)
	}
	if len(msg.Questions) != 1 {
		h.metrics.IncResponses("FORMERR")
		return h.buildError(query, dns.RCodeFormErr)
	}

	q := msg.Questions[0]
	qtypeStr := dns.TypeToString[q.Type]
	if qtypeStr == "" {
		qtypeStr = "OTHER"
	}
	h.metrics.IncQueries(qtypeStr)

	// 2.4 Per-zone ACL check (requires parsed qname)
	if h.acl != nil && !h.acl.CheckWithZone(clientIP, q.Name) {
		h.metrics.IncResponses("REFUSED")
		return h.buildError(query, dns.RCodeRefused)
	}

	// 2.5 Blocklist check
	if h.blocklist != nil && h.blocklist.IsBlocked(q.Name) {
		h.metrics.IncBlockedQueries()
		resp, err := h.buildBlockedResponse(msg, q)
		if err != nil {
			return nil, err
		}
		// Add EDE "Blocked" (RFC 8914, info code 15) if client supports EDNS0
		if msg.EDNS0 != nil {
			resp = h.addEDEToRawResponse(resp, dns.EDECodeBlocked, "blocked")
		}
		duration := time.Since(start)
		h.metrics.ObserveQueryDuration(duration)
		h.metrics.IncResponses("BLOCKED")
		durationMs := float64(duration.Microseconds()) / 1000.0
		h.logger.Debug("query_blocked", "client", clientIP, "qname", q.Name, "qtype", qtypeStr)
		if h.OnQuery != nil {
			h.OnQuery(clientIP, q.Name, qtypeStr, "BLOCKED", true, durationMs)
		}
		return resp, nil
	}

	// 2.6 Minimal ANY response (RFC 8482): return synthetic HINFO instead
	// of resolving, to prevent DNS amplification via ANY queries.
	if q.Type == dns.TypeANY {
		resp, err := h.buildMinimalANYResponse(msg, q)
		if err != nil {
			return nil, err
		}
		duration := time.Since(start)
		h.metrics.ObserveQueryDuration(duration)
		h.metrics.IncResponses("NOERROR")
		durationMs := float64(duration.Microseconds()) / 1000.0
		h.logger.Debug("minimal_any_response", "client", clientIP, "qname", q.Name)
		if h.OnQuery != nil {
			h.OnQuery(clientIP, q.Name, qtypeStr, "NOERROR", false, durationMs)
		}
		return resp, nil
	}

	bypassCache := h.shouldBypassCache(clientIP)

	// 2.7 Build outbound ECS from the client's OPT record (RFC 7871).
	// Passthrough policy: only forward what the client itself sent. Nil
	// when the client opted out or ECS is disabled.
	outboundECS := h.buildOutboundECS(msg.EDNS0)

	// 3. Cache lookup. Try the global key first; that one is shared across
	// all clients and matches authoritative answers with scope=0 (RFC 7871
	// §7.3.1). On miss, if we have an outbound ECS, fall back to a scoped
	// lookup so geo-tailored entries can still be reused by clients whose
	// subnet maps to the same key.
	if !bypassCache {
		var entry *cache.Entry
		var ok bool
		entry, ok = h.cache.Get(q.Name, q.Type, q.Class)
		if !ok && outboundECS != nil {
			entry, ok = h.cache.GetWithECS(q.Name, q.Type, q.Class, outboundECS.CacheKey())
		}
		if ok {
			h.metrics.IncCacheHits()
			resp, err := h.buildCacheResponseECS(msg, entry, outboundECS)
			if err == nil {
				duration := time.Since(start)
				h.metrics.ObserveQueryDuration(duration)
				durationMs := float64(duration.Microseconds()) / 1000.0
				h.logger.Info("query_resolved",
					"client", clientIP,
					"qname", q.Name,
					"qtype", qtypeStr,
					"cache_hit", true,
					"duration_ms", durationMs,
				)
				cacheRCode := dns.RCodeToString[entry.RCODE]
				if cacheRCode == "" {
					cacheRCode = "NOERROR"
				}
				if h.OnQuery != nil {
					h.OnQuery(clientIP, q.Name, qtypeStr, cacheRCode, true, durationMs)
				}
				return resp, nil
			}
		}
	}
	h.metrics.IncCacheMisses()

	// 4. Recursive resolution
	result, err := h.resolver.ResolveWithECS(q.Name, q.Type, q.Class, outboundECS)

	// Serve stale (RFC 8767): if resolution failed (Go error or SERVFAIL),
	// try serving expired cache entry before giving up.
	resolveOK := err == nil && result != nil && result.RCODE != dns.RCodeServFail
	if !resolveOK {
		if staleEntry, ok := h.cache.GetStale(q.Name, q.Type, q.Class); ok {
			h.logger.Info("serving stale cache", "qname", q.Name, "qtype", qtypeStr)
			resp, buildErr := h.buildCacheResponse(msg, staleEntry)
			if buildErr == nil {
				// Add EDE "Stale Answer" (RFC 8914, info code 1)
				if msg.EDNS0 != nil {
					staleResp, parseErr := dns.Unpack(resp)
					if parseErr == nil {
						h.addEDEToResponse(staleResp, dns.EDECodeStaleAnswer, "serve-stale")
						// H-5: copy packed bytes off the pooled buffer before the
						// caller (UDP/TCP listener) reads them. packToOwnedBytes
						// copies and returns the buffer to the pool atomically.
						if owned, packErr := h.packToOwnedBytes(staleResp); packErr == nil {
							resp = owned
						}
					}
				}
				duration := time.Since(start)
				h.metrics.ObserveQueryDuration(duration)
				h.metrics.IncResponses("NOERROR")
				if h.OnQuery != nil {
					h.OnQuery(clientIP, q.Name, qtypeStr, "NOERROR", true, float64(duration.Microseconds())/1000.0)
				}
				return resp, nil
			}
		}
		// Check for DNSSEC bogus — add EDE info code 6
		if result != nil && result.DNSSECStatus == "bogus" && msg.EDNS0 != nil {
			bogusResp, buildErr := h.buildErrorWithEDE(query, dns.RCodeServFail, dns.EDECodeDNSSECBogus, "DNSSEC validation failure")
			if buildErr == nil {
				h.metrics.IncResponses("SERVFAIL")
				return bogusResp, nil
			}
		}
		if err != nil {
			h.metrics.IncResponses("SERVFAIL")
			if msg.EDNS0 != nil {
				resp, buildErr := h.buildErrorWithEDE(query, dns.RCodeServFail, dns.EDECodeNetworkError, err.Error())
				if buildErr == nil {
					return resp, nil
				}
			}
			return h.buildError(query, dns.RCodeServFail)
		}
	}

	// 5. Cache store
	rcodeStr := dns.RCodeToString[result.RCODE]
	if rcodeStr == "" {
		rcodeStr = "UNKNOWN"
	}

	if !bypassCache {
		// RFC 7871 §7.3: scope=0 (or no ECS in response) → global cache;
		// scope>0 → key under truncated client subnet at that scope.
		ecsKey := chooseCacheECSKey(outboundECS, result.UpstreamECS)
		var ecsScope uint8
		if result.UpstreamECS != nil {
			ecsScope = result.UpstreamECS.ScopePrefixLen
		}
		if result.RCODE == dns.RCodeNoError && len(result.Answers) > 0 {
			// H-6: filter private addresses BEFORE inserting into the
			// cache. Previously the filter only ran in buildResponse,
			// so a first query that admitted a private IP would poison
			// the cache for every later client (DNS-rebinding bypass).
			// Filtering at the write site means subsequent cache hits
			// (buildCacheResponse) are clean by construction.
			answersToCache := result.Answers
			if h.privateFilter {
				answersToCache = security.FilterPrivateAddresses(answersToCache)
			}
			if ecsKey == "" {
				h.cache.StoreWithStatus(q.Name, q.Type, q.Class, answersToCache, result.Authority, result.DNSSECStatus)
			} else {
				h.cache.StoreWithECSStatus(q.Name, q.Type, q.Class, ecsKey, ecsScope, answersToCache, result.Authority, result.DNSSECStatus)
			}
		} else if result.RCODE == dns.RCodeNXDomain {
			// Negative caching is kept global for now: RFC 7871 §7.3 does
			// not forbid per-subnet negatives, but NXDOMAIN scoping at
			// authoritative servers is rare and per-subnet negatives
			// would inflate cache pressure on the common case.
			h.cache.StoreNegative(q.Name, q.Type, q.Class, cache.NegNXDomain, result.RCODE, result.Authority)
		} else if result.RCODE == dns.RCodeNoError && len(result.Answers) == 0 {
			h.cache.StoreNegative(q.Name, q.Type, q.Class, cache.NegNoData, result.RCODE, result.Authority)
		}
	}

	// 6. Build response
	duration := time.Since(start)
	h.metrics.ObserveQueryDuration(duration)
	h.metrics.IncResponses(rcodeStr)

	durationMs := float64(duration.Microseconds()) / 1000.0
	h.logger.Info("query_resolved",
		"client", clientIP,
		"qname", q.Name,
		"qtype", qtypeStr,
		"rcode", rcodeStr,
		"answer_count", len(result.Answers),
		"cache_hit", false,
		"duration_ms", durationMs,
	)

	if h.OnQuery != nil {
		h.OnQuery(clientIP, q.Name, qtypeStr, rcodeStr, false, durationMs)
	}

	resp, buildErr := h.buildResponse(msg, result)
	if buildErr != nil {
		return nil, buildErr
	}

	// RFC 7871 §7.2.1: if the client signalled ECS, echo back our derived
	// option with the authoritative SCOPE PREFIX-LENGTH so the client knows
	// the answer was (or was not) geo-tailored.
	if outboundECS != nil {
		var scope uint8
		if result.UpstreamECS != nil {
			scope = result.UpstreamECS.ScopePrefixLen
		}
		echo := dns.ECSOption{
			Family:          outboundECS.Family,
			SourcePrefixLen: outboundECS.SourcePrefixLen,
			ScopePrefixLen:  scope,
			Address:         outboundECS.Address,
		}
		resp = appendECSToResponse(resp, &echo)
	}

	// Add EDE for SERVFAIL (no reachable authority) if client supports EDNS0
	if result.RCODE == dns.RCodeServFail && msg.EDNS0 != nil {
		resp = h.addEDEToRawResponse(resp, dns.EDECodeNoReachableAuthority, "")
	}

	// Add cookie response if client sent a cookie option
	if h.cookiesEnabled && msg.EDNS0 != nil {
		resp = h.addCookieToResponse(resp, msg.EDNS0, clientIP)
	}

	// 7. Response Rate Limiting (anti-amplification)
	if h.rrl != nil {
		action := h.rrl.AllowResponse(clientIP, q.Name, rcodeStr)
		switch action {
		case security.RRLDrop:
			return nil, nil // silently drop
		case security.RRLSlip:
			// Send truncated response (TC=1) to force TCP retry
			return h.buildSlipResponse(query)
		}
	}

	return resp, nil
}

func (h *MainHandler) buildError(query []byte, rcode uint8) ([]byte, error) {
	if len(query) < 12 {
		// Minimal header-only error response
		buf := make([]byte, 12)
		flags := dns.NewFlagBuilder().SetQR(true).SetRA(true).SetRCODE(rcode).Build()
		binary.BigEndian.PutUint16(buf[2:4], flags)
		return buf, nil
	}

	// H-5: this function previously did `defer pool.PutBuffer(bufPtr)`
	// and returned `buf[:N]` — a slice into the pooled buffer that the
	// caller continues using after the defer fires. We now copy before
	// release so the caller owns its bytes.
	bufPtr := pool.GetBuffer()
	buf := *bufPtr
	copy(buf, query[:12])

	// Set flags: QR=1, RA=1, RCODE
	flags := binary.BigEndian.Uint16(buf[2:4])
	flags |= 1 << 15 // QR
	flags |= 1 << 7  // RA
	flags = (flags & 0xFFF0) | uint16(rcode)
	binary.BigEndian.PutUint16(buf[2:4], flags)

	// Zero answer/authority/additional counts
	binary.BigEndian.PutUint16(buf[6:8], 0)
	binary.BigEndian.PutUint16(buf[8:10], 0)
	binary.BigEndian.PutUint16(buf[10:12], 0)

	// Keep question section intact
	offset := 12
	qdcount := binary.BigEndian.Uint16(query[4:6])
	for i := 0; i < int(qdcount) && offset < len(query); i++ {
		_, newOffset, err := dns.DecodeName(query, offset)
		if err != nil {
			out := append([]byte(nil), buf[:12]...)
			pool.PutBuffer(bufPtr)
			return out, nil
		}
		offset = newOffset + 4
	}

	if offset > len(query) {
		offset = len(query)
	}
	copy(buf[12:], query[12:offset])
	out := append([]byte(nil), buf[:offset]...)
	pool.PutBuffer(bufPtr)
	return out, nil
}

// buildSlipResponse creates a minimal response with TC=1 (truncated) to force
// the client to retry over TCP. Used by RRL slip to rate-limit without dropping.
func (h *MainHandler) buildSlipResponse(query []byte) ([]byte, error) {
	resp, err := h.buildError(query, dns.RCodeNoError)
	if err != nil {
		return nil, err
	}
	if len(resp) >= 4 {
		flags := binary.BigEndian.Uint16(resp[2:4])
		flags |= 1 << 9 // TC bit
		binary.BigEndian.PutUint16(resp[2:4], flags)
	}
	return resp, nil
}

// buildCacheResponseECS is the ECS-aware variant of buildCacheResponse.
// When the client sent ECS in its query, the response carries an ECS
// option echoing the source prefix the client provided alongside the
// SCOPE PREFIX-LENGTH from the cached entry (RFC 7871 §7.2.1). When the
// client did not send ECS, the behaviour is identical to buildCacheResponse.
func (h *MainHandler) buildCacheResponseECS(query *dns.Message, entry *cache.Entry, outboundECS *dns.ECSOption) ([]byte, error) {
	resp, err := h.buildCacheResponse(query, entry)
	if err != nil {
		return nil, err
	}
	if outboundECS == nil {
		return resp, nil
	}
	echo := dns.ECSOption{
		Family:          outboundECS.Family,
		SourcePrefixLen: outboundECS.SourcePrefixLen,
		ScopePrefixLen:  entry.ECSScope,
		Address:         outboundECS.Address,
	}
	return appendECSToResponse(resp, &echo), nil
}

func (h *MainHandler) buildCacheResponse(query *dns.Message, entry *cache.Entry) ([]byte, error) {
	// RFC 4035 §3.2.2: a recursive name server MUST clear the AD bit on a
	// response unless and until it itself verified the data; if it did verify
	// (or the client opted out of verification with CD=1), AD propagates.
	// RFC 4035 §3.2.2 also says the server MUST copy the CD bit from the
	// query to the response so the client knows whether validation was
	// performed.
	setAD := entry.DNSSECStatus == "secure" && !query.Header.CD()

	// RFC 4035 §3.2.1: strip DNSSEC RRs for non-DO clients (see buildResponse
	// comment for the full rationale).
	answers := entry.Records
	authority := entry.Authority
	qtype := uint16(0)
	if len(query.Questions) > 0 {
		qtype = query.Questions[0].Type
	}
	if !clientWantsDNSSEC(query) {
		answers = stripDNSSECRRs(answers, qtype)
		authority = stripDNSSECRRs(authority, qtype)
	}

	resp := &dns.Message{
		Header: dns.Header{
			ID: query.Header.ID,
			Flags: dns.NewFlagBuilder().
				SetQR(true).
				SetRD(query.Header.RD()).
				SetRA(true).
				SetAD(setAD).
				SetCD(query.Header.CD()).
				SetRCODE(entry.RCODE).
				Build(),
		},
		Questions: query.Questions,
		Answers:   answers,
		Authority: authority,
	}

	// Add OPT if client sent one
	if query.EDNS0 != nil {
		resp.Additional = append(resp.Additional, dns.BuildOPT(h.advertisedUDPBufferSize(), query.EDNS0.DOFlag))
	}

	// H-5: pack into an owned slice so the caller doesn't read pooled memory.
	packed, err := h.packToOwnedBytes(resp)
	if err != nil {
		return nil, err
	}
	return h.maybeTruncateUDP(packed, query), nil
}

// buildMinimalANYResponse returns a synthetic HINFO response per RFC 8482,
// preventing DNS amplification attacks via ANY queries.
func (h *MainHandler) buildMinimalANYResponse(query *dns.Message, q dns.Question) ([]byte, error) {
	// HINFO RDATA: <CPU-length> <CPU-string> <OS-length> <OS-string>
	// CPU = "RFC8482", OS = ""
	cpu := []byte("RFC8482")
	rdata := make([]byte, 1+len(cpu)+1)
	rdata[0] = byte(len(cpu))
	copy(rdata[1:], cpu)
	rdata[1+len(cpu)] = 0 // empty OS string

	resp := &dns.Message{
		Header: dns.Header{
			ID: query.Header.ID,
			Flags: dns.NewFlagBuilder().
				SetQR(true).
				SetRD(query.Header.RD()).
				SetRA(true).
				SetRCODE(dns.RCodeNoError).
				Build(),
		},
		Questions: query.Questions,
		Answers: []dns.ResourceRecord{{
			Name:     q.Name,
			Type:     dns.TypeHINFO,
			Class:    dns.ClassIN,
			TTL:      0,
			RDLength: uint16(len(rdata)),
			RData:    rdata,
		}},
	}

	if query.EDNS0 != nil {
		resp.Additional = append(resp.Additional, dns.BuildOPT(h.advertisedUDPBufferSize(), query.EDNS0.DOFlag))
	}

	// H-5: pack into an owned slice (was: dns.Pack into pooled buf, then PutBuffer, then return slice).
	packed, err := h.packToOwnedBytes(resp)
	if err != nil {
		return nil, err
	}
	return h.maybeTruncateUDP(packed, query), nil
}

func (h *MainHandler) buildResponse(query *dns.Message, result *resolver.ResolveResult) ([]byte, error) {
	// Apply private address filtering before building the response
	answers := result.Answers
	if h.privateFilter {
		answers = security.FilterPrivateAddresses(answers)
	}
	authority := result.Authority
	additional := result.Additional

	// RFC 4035 §3.2.1: when the client did not signal DNSSEC support (no
	// EDNS or DO=0), the server MUST NOT include DNSSEC RR types in the
	// response unless the client explicitly asked for them by qtype.
	// Sending RRSIGs to a non-DO client wastes bandwidth and confuses
	// strict legacy stubs.
	qtype := uint16(0)
	if len(query.Questions) > 0 {
		qtype = query.Questions[0].Type
	}
	if !clientWantsDNSSEC(query) {
		answers = stripDNSSECRRs(answers, qtype)
		authority = stripDNSSECRRs(authority, qtype)
		additional = stripDNSSECRRs(additional, qtype)
	}

	// RFC 4035 §3.2.2: set AD only when this resolver validated the data
	// as Secure. The CD bit MUST be copied from the query to the response.
	// AD is never set when the client requested validation-bypass (CD=1).
	setAD := result.DNSSECStatus == "secure" && !query.Header.CD()
	resp := &dns.Message{
		Header: dns.Header{
			ID: query.Header.ID,
			Flags: dns.NewFlagBuilder().
				SetQR(true).
				SetRD(query.Header.RD()).
				SetRA(true).
				SetAD(setAD).
				SetCD(query.Header.CD()).
				SetRCODE(result.RCODE).
				Build(),
		},
		Questions:  query.Questions,
		Answers:    answers,
		Authority:  authority,
		Additional: additional,
	}

	// Add OPT if client sent one
	if query.EDNS0 != nil {
		resp.Additional = append(resp.Additional, dns.BuildOPT(h.advertisedUDPBufferSize(), query.EDNS0.DOFlag))
	}

	// H-5: pack into an owned slice.
	packed, err := h.packToOwnedBytes(resp)
	if err != nil {
		return nil, err
	}

	return h.maybeTruncateUDP(packed, query), nil
}

// maybeTruncateUDP enforces the effective UDP response size cap on a packed
// DNS message and returns the (possibly-truncated) bytes. The cap is
// min(client-advertised, h.advertisedUDPBufferSize()): we honour the client's
// stated buffer but never exceed our own configured ceiling, even if a
// hostile client claims it can receive 65535 bytes. Client values below the
// RFC 6891 §6.2.5 minimum of 512 bytes are ignored and treated as 512: a
// broken middlebox advertising UDPSize=0 or 30 cannot induce us to truncate
// fully RFC-compliant responses. Oversized responses are truncated per
// RFC 1035 §4.1.1 — TC bit set, ANCount/NSCount/ARCount zeroed,
// header+question section only — forcing the client to retry over TCP,
// where reassembly uses 32-bit per-connection sequence numbers and is
// structurally immune to off-path fragment-injection (Brandt et al, USENIX
// Security 2018). RFC 9018 / DNS Flag Day 2020.
func (h *MainHandler) maybeTruncateUDP(packed []byte, query *dns.Message) []byte {
	const rfc6891MinUDPSize = 512
	maxSize := rfc6891MinUDPSize
	if query.EDNS0 != nil && int(query.EDNS0.UDPSize) >= rfc6891MinUDPSize {
		maxSize = int(query.EDNS0.UDPSize)
	}
	if ceiling := int(h.advertisedUDPBufferSize()); maxSize > ceiling {
		maxSize = ceiling
	}
	if len(packed) <= maxSize {
		return packed
	}

	// Set TC bit and send only header + question section (RFC 1035 §4.1.1).
	// This avoids sending a malformed message with partial records.
	binary.BigEndian.PutUint16(packed[2:4], binary.BigEndian.Uint16(packed[2:4])|(1<<9))
	binary.BigEndian.PutUint16(packed[6:8], 0)   // ANCount = 0
	binary.BigEndian.PutUint16(packed[8:10], 0)  // NSCount = 0
	binary.BigEndian.PutUint16(packed[10:12], 0) // ARCount = 0
	// Keep header (12 bytes) + question section only
	qEnd := 12
	qdcount := binary.BigEndian.Uint16(packed[4:6])
	for i := 0; i < int(qdcount) && qEnd < len(packed); i++ {
		_, n, err := dns.DecodeName(packed, qEnd)
		if err != nil {
			break
		}
		qEnd = n + 4 // skip QTYPE + QCLASS
	}
	if qEnd > maxSize {
		qEnd = 12                                  // question itself too big, send header only
		binary.BigEndian.PutUint16(packed[4:6], 0) // QDCount = 0
	}
	return packed[:qEnd]
}

func (h *MainHandler) buildBlockedResponse(query *dns.Message, q dns.Question) ([]byte, error) {
	resp := &dns.Message{
		Header: dns.Header{
			ID:    query.Header.ID,
			Flags: dns.NewFlagBuilder().SetQR(true).SetRD(query.Header.RD()).SetRA(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
		Questions: query.Questions,
	}

	mode := "nxdomain"
	if h.blocklist != nil {
		mode = h.blocklist.BlockingMode()
	}

	switch mode {
	case "null_ip":
		resp.Header.Flags = dns.NewFlagBuilder().SetQR(true).SetRD(query.Header.RD()).SetRA(true).SetRCODE(dns.RCodeNoError).Build()
		if q.Type == dns.TypeA {
			resp.Answers = []dns.ResourceRecord{{
				Name: q.Name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 0, RDLength: 4, RData: []byte{0, 0, 0, 0},
			}}
		} else if q.Type == dns.TypeAAAA {
			resp.Answers = []dns.ResourceRecord{{
				Name: q.Name, Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 0, RDLength: 16, RData: make([]byte, 16),
			}}
		}
	case "custom_ip":
		customIP := "0.0.0.0"
		if h.blocklist != nil {
			customIP = h.blocklist.CustomIP()
		}
		ip := net.ParseIP(customIP)
		if ip != nil && q.Type == dns.TypeA {
			ipv4 := ip.To4()
			if ipv4 != nil {
				resp.Header.Flags = dns.NewFlagBuilder().SetQR(true).SetRD(query.Header.RD()).SetRA(true).SetRCODE(dns.RCodeNoError).Build()
				resp.Answers = []dns.ResourceRecord{{
					Name: q.Name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 0, RDLength: 4, RData: ipv4,
				}}
			}
		}
	}
	// default: nxdomain - already set

	// H-5: pack into an owned slice.
	return h.packToOwnedBytes(resp)
}

// buildErrorWithEDE creates an error response with an Extended DNS Error option.
func (h *MainHandler) buildErrorWithEDE(query []byte, rcode uint8, edeCode uint16, edeText string) ([]byte, error) {
	resp, err := h.buildError(query, rcode)
	if err != nil {
		return nil, err
	}

	// Parse, add EDE OPT, re-pack
	msg, parseErr := dns.Unpack(resp)
	if parseErr != nil {
		return resp, nil // fallback to plain error
	}
	h.addEDEToResponse(msg, edeCode, edeText)
	// H-5: pack into an owned slice.
	out, packErr := h.packToOwnedBytes(msg)
	if packErr != nil {
		return resp, nil
	}
	return out, nil
}

// addCookieToResponse processes DNS cookie options in the response.
// If the client sent a cookie option, the server echoes back the client cookie
// plus a generated server cookie.
func (h *MainHandler) addCookieToResponse(resp []byte, edns *dns.EDNS0, clientIP string) []byte {
	// Find cookie option in client EDNS0
	var clientCookie []byte
	for _, opt := range edns.Options {
		if opt.Code == dns.EDNSOptionCodeCookie {
			clientCookie, _ = dns.ParseCookieOption(opt.Data)
			break
		}
	}
	if len(clientCookie) != 8 {
		return resp // no valid client cookie
	}

	serverCookie := h.generateServerCookie(clientCookie, clientIP)

	// Build cookie response: client cookie (8) + server cookie (16) per RFC 9018
	cookieData := make([]byte, 8+len(serverCookie))
	copy(cookieData[:8], clientCookie)
	copy(cookieData[8:], serverCookie)
	cookieOpt := dns.EDNSOption{Code: dns.EDNSOptionCodeCookie, Data: cookieData}

	msg, err := dns.Unpack(resp)
	if err != nil {
		return resp
	}

	// Add cookie option to existing OPT record or create new one
	found := false
	for i, rr := range msg.Additional {
		if rr.Type == dns.TypeOPT {
			optData := make([]byte, 4+len(cookieOpt.Data))
			binary.BigEndian.PutUint16(optData[0:2], cookieOpt.Code)
			binary.BigEndian.PutUint16(optData[2:4], uint16(len(cookieOpt.Data)))
			copy(optData[4:], cookieOpt.Data)
			msg.Additional[i].RData = append(msg.Additional[i].RData, optData...)
			msg.Additional[i].RDLength = uint16(len(msg.Additional[i].RData))
			found = true
			break
		}
	}
	if !found {
		msg.Additional = append(msg.Additional, dns.BuildOPTWithOptions(h.advertisedUDPBufferSize(), false, []dns.EDNSOption{cookieOpt}))
	}

	// H-5: pack into an owned slice.
	out, packErr := h.packToOwnedBytes(msg)
	if packErr != nil {
		return resp
	}
	return out
}

// clientWantsDNSSEC returns true if the client signalled DNSSEC support by
// including an EDNS0 OPT record with the DO bit set.
func clientWantsDNSSEC(query *dns.Message) bool {
	return query.EDNS0 != nil && query.EDNS0.DOFlag
}

// isDNSSECRRType reports whether t is one of the DNSSEC-meta RR types that
// must be stripped from responses to clients that did not opt in via DO.
func isDNSSECRRType(t uint16) bool {
	switch t {
	case dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeDS, dns.TypeNSEC,
		dns.TypeNSEC3, dns.TypeNSEC3PARAM:
		return true
	}
	return false
}

// stripDNSSECRRs filters DNSSEC-meta records out of rrs unless they match the
// client's query type (e.g. an explicit `RRSIG example.com` query keeps the
// RRSIG records, but an `A example.com` query without DO does not).
// Implements RFC 4035 §3.2.1.
func stripDNSSECRRs(rrs []dns.ResourceRecord, qtype uint16) []dns.ResourceRecord {
	if len(rrs) == 0 {
		return rrs
	}
	// For an RRSIG query, also keep RRSIGs whose covered type matches the
	// implicit intent; but the simplest correct rule is to keep RRs whose
	// own rr.Type equals qtype. That covers the qtype==RRSIG / qtype==DNSKEY
	// etc. direct query case without surprising heuristics.
	out := make([]dns.ResourceRecord, 0, len(rrs))
	for _, rr := range rrs {
		if isDNSSECRRType(rr.Type) && rr.Type != qtype {
			continue
		}
		out = append(out, rr)
	}
	return out
}

func extractIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	addrStr := addr.String()
	host, _, err := net.SplitHostPort(addrStr)
	if err != nil {
		return strings.TrimRight(addrStr, ":")
	}
	return host
}
