package server

import (
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
	resolver    *resolver.Resolver
	cache       *cache.Cache
	limiter     *security.RateLimiter
	rrl         *security.RRL
	acl         *security.ACL
	metrics     *metrics.Metrics
	logger      *slog.Logger
	noCacheNets []*net.IPNet
	blocklist   interface {
		IsBlocked(string) bool
		BlockingMode() string
		CustomIP() string
	}

	// OnQuery is an optional callback invoked after each query is resolved.
	// Parameters: client IP, qname, qtype, rcode (may be "BLOCKED"), whether served from cache, duration in ms.
	OnQuery func(client, qname, qtype, rcode string, cached bool, durationMs float64)
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

	// ACL check
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
	if err != nil {
		// Serve stale: if resolution fails, try serving expired cache (RFC 8767)
		if staleEntry, ok := h.cache.GetStale(q.Name, q.Type, q.Class); ok {
			h.logger.Info("serving stale cache", "qname", q.Name, "qtype", qtypeStr)
			resp, buildErr := h.buildCacheResponse(msg, staleEntry)
			if buildErr == nil {
				return resp, nil
			}
		}
		h.metrics.IncResponses("SERVFAIL")
		return h.buildError(query, dns.RCodeServFail)
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

	// 7. Response Rate Limiting (anti-amplification)
	if h.rrl != nil {
		action := h.rrl.AllowResponse(clientIP, q.Name, rcodeStr)
		switch action {
		case security.RRLDrop:
			return nil, nil // silently drop
		case security.RRLSlip:
			// Send truncated response (TC=1) to force TCP retry
			return h.buildError(query, dns.RCodeNoError)
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

func (h *MainHandler) buildResponse(query *dns.Message, result *resolver.ResolveResult) ([]byte, error) {
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
		Answers:    result.Answers,
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
		// Set TC bit and truncate
		binary.BigEndian.PutUint16(packed[2:4], binary.BigEndian.Uint16(packed[2:4])|(1<<9))
		packed = packed[:maxSize]
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
