package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
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
	ecsEnabled   bool
	ecsMaxPrefix int

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
// A random 16-byte server secret is generated at startup.
func (h *MainHandler) EnableCookies() {
	h.cookiesEnabled = true
	h.cookieSecret = make([]byte, 16)
	if _, err := rand.Read(h.cookieSecret); err != nil {
		// Fallback: use a fixed secret (should not happen in practice)
		h.cookieSecret = []byte("labyrinth-secret")
	}
}

// EnableCookiesWithSecret enables DNS cookies with a specific secret (for testing).
func (h *MainHandler) EnableCookiesWithSecret(secret []byte) {
	h.cookiesEnabled = true
	h.cookieSecret = make([]byte, len(secret))
	copy(h.cookieSecret, secret)
}

// SetECS enables or disables ECS forwarding.
func (h *MainHandler) SetECS(enabled bool, maxPrefix int) {
	h.ecsEnabled = enabled
	h.ecsMaxPrefix = maxPrefix
}

// generateServerCookie computes HMAC-SHA256(clientCookie + clientIP + secret)[:8].
func (h *MainHandler) generateServerCookie(clientCookie []byte, clientIP string) []byte {
	mac := hmac.New(sha256.New, h.cookieSecret)
	mac.Write(clientCookie)
	mac.Write([]byte(clientIP))
	sum := mac.Sum(nil)
	result := make([]byte, 8)
	copy(result, sum[:8])
	return result
}

// addEDEToResponse appends an EDE option to the response OPT record.
// If no OPT record exists, one is created.
func addEDEToResponse(resp *dns.Message, code uint16, text string) {
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

	// No OPT record found — create one with EDE
	resp.Additional = append(resp.Additional, dns.BuildOPTWithOptions(4096, false, []dns.EDNSOption{edeOpt}))
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

	// 3. Cache lookup
	if !bypassCache {
		if entry, ok := h.cache.Get(q.Name, q.Type, q.Class); ok {
			h.metrics.IncCacheHits()
			resp, err := h.buildCacheResponse(msg, entry)
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
	result, err := h.resolver.Resolve(q.Name, q.Type, q.Class)

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
						addEDEToResponse(staleResp, dns.EDECodeStaleAnswer, "serve-stale")
						buf := make([]byte, 4096)
						if packed, packErr := dns.Pack(staleResp, buf); packErr == nil {
							resp = packed
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
			return h.buildError(query, dns.RCodeServFail)
		}
	}

	// 5. Cache store
	rcodeStr := dns.RCodeToString[result.RCODE]
	if rcodeStr == "" {
		rcodeStr = "UNKNOWN"
	}

	if !bypassCache {
		if result.RCODE == dns.RCodeNoError && len(result.Answers) > 0 {
			h.cache.Store(q.Name, q.Type, q.Class, result.Answers, result.Authority)
		} else if result.RCODE == dns.RCodeNXDomain {
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

	buf := make([]byte, 4096)
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
			return buf[:12], nil
		}
		offset = newOffset + 4
	}

	if offset > len(query) {
		offset = len(query)
	}
	copy(buf[12:], query[12:offset])
	return buf[:offset], nil
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

func (h *MainHandler) buildCacheResponse(query *dns.Message, entry *cache.Entry) ([]byte, error) {
	resp := &dns.Message{
		Header: dns.Header{
			ID: query.Header.ID,
			Flags: dns.NewFlagBuilder().
				SetQR(true).
				SetRD(query.Header.RD()).
				SetRA(true).
				SetRCODE(entry.RCODE).
				Build(),
		},
		Questions: query.Questions,
		Answers:   entry.Records,
		Authority: entry.Authority,
	}

	// Add OPT if client sent one
	if query.EDNS0 != nil {
		resp.Additional = append(resp.Additional, dns.BuildOPT(4096, query.EDNS0.DOFlag))
	}

	buf := make([]byte, 4096)
	return dns.Pack(resp, buf)
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
		resp.Additional = append(resp.Additional, dns.BuildOPT(4096, query.EDNS0.DOFlag))
	}

	buf := make([]byte, 4096)
	return dns.Pack(resp, buf)
}

func (h *MainHandler) buildResponse(query *dns.Message, result *resolver.ResolveResult) ([]byte, error) {
	// Apply private address filtering before building the response
	answers := result.Answers
	if h.privateFilter {
		answers = security.FilterPrivateAddresses(answers)
	}

	resp := &dns.Message{
		Header: dns.Header{
			ID: query.Header.ID,
			Flags: dns.NewFlagBuilder().
				SetQR(true).
				SetRD(query.Header.RD()).
				SetRA(true).
				SetRCODE(result.RCODE).
				Build(),
		},
		Questions:  query.Questions,
		Answers:    answers,
		Authority:  result.Authority,
		Additional: result.Additional,
	}

	// Add OPT if client sent one
	if query.EDNS0 != nil {
		resp.Additional = append(resp.Additional, dns.BuildOPT(4096, query.EDNS0.DOFlag))
	}

	buf := make([]byte, 4096)
	packed, err := dns.Pack(resp, buf)
	if err != nil {
		return nil, err
	}

	// Check if response exceeds client's UDP buffer
	maxSize := 512
	if query.EDNS0 != nil {
		maxSize = int(query.EDNS0.UDPSize)
	}
	if len(packed) > maxSize {
		// Set TC bit and send only header + question section (RFC 1035 §4.1.1).
		// This avoids sending a malformed message with partial records.
		binary.BigEndian.PutUint16(packed[2:4], binary.BigEndian.Uint16(packed[2:4])|(1<<9))
		binary.BigEndian.PutUint16(packed[6:8], 0)  // ANCount = 0
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
			qEnd = 12 // question itself too big, send header only
			binary.BigEndian.PutUint16(packed[4:6], 0) // QDCount = 0
		}
		packed = packed[:qEnd]
	}

	return packed, nil
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

	buf := make([]byte, 4096)
	return dns.Pack(resp, buf)
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
	addEDEToResponse(msg, edeCode, edeText)
	buf := make([]byte, 4096)
	packed, packErr := dns.Pack(msg, buf)
	if packErr != nil {
		return resp, nil
	}
	return packed, nil
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

	// Build cookie response: client cookie (8) + server cookie (8)
	cookieData := make([]byte, 16)
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
		msg.Additional = append(msg.Additional, dns.BuildOPTWithOptions(4096, false, []dns.EDNSOption{cookieOpt}))
	}

	buf := make([]byte, 4096)
	packed, packErr := dns.Pack(msg, buf)
	if packErr != nil {
		return resp
	}
	return packed
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
