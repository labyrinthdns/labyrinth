// rfcCompliance — curated list of the RFCs Labyrinth implements, surfaced on
// the AboutPage as a compliance matrix. The point isn't exhaustive coverage
// (every recursive resolver implements bits of dozens of RFCs); it's the
// "load-bearing" RFCs and the operator-visible ones — what a security/SRE
// reader scanning this page would want to confirm before deployment.
//
// Structure: entries are grouped semantically rather than chronologically.
// `since` is the Labyrinth version that shipped the behaviour (best-effort
// from CHANGELOG); a missing `since` means "core, since v0.1". Entries are
// flat — no nested groups — so the matrix can be filtered with a single
// string predicate without flattening logic in the UI.

export type ComplianceCategory =
  | 'core'
  | 'dnssec'
  | 'nsec-aggressive'
  | 'edns'
  | 'transport-security'
  | 'special-use'
  | 'error-signalling'
  | 'caching'
  | 'blocking'

export interface ComplianceEntry {
  rfc: string
  section?: string
  title: string
  summary: string
  category: ComplianceCategory
  since?: string
}

export const COMPLIANCE_ENTRIES: ComplianceEntry[] = [
  // Core protocol
  { rfc: 'RFC 1034', title: 'Domain Names — Concepts and Facilities', summary: 'Iterative resolution from root, delegation walk, CNAME chasing.', category: 'core' },
  { rfc: 'RFC 1035', title: 'Domain Names — Implementation', summary: 'Wire format, message header, EDNS-less query/response baseline.', category: 'core' },
  { rfc: 'RFC 2181', title: 'Clarifications to the DNS Specification', summary: 'TTL handling, CNAME corner cases, response field semantics.', category: 'core' },
  { rfc: 'RFC 2308', title: 'Negative Caching', summary: 'NXDOMAIN / NODATA cached with SOA-MINIMUM TTL, type-bitmap awareness.', category: 'core' },
  { rfc: 'RFC 3596', title: 'AAAA Records', summary: 'IPv6 address records — full parity with A in iterative path.', category: 'core' },
  { rfc: 'RFC 3597', title: 'Handling Unknown RR Types', summary: 'Unknown RDATA passed through verbatim without re-interpretation.', category: 'core' },
  { rfc: 'RFC 5452', title: 'Forgery Resilience', summary: 'Random query IDs, source-port randomisation, in-bailiwick checks. Empirical source-port randomisation pin landed v0.7.4.', category: 'core' },
  { rfc: 'RFC 6604', title: 'xNAME RCODE and Status Bits', summary: 'CNAME synthesis preserves AA, AD, RCODE per §3.', category: 'core' },
  { rfc: 'RFC 6672', title: 'DNAME Redirection', summary: 'DNAME substitution, CNAME synthesis chained correctly.', category: 'core' },
  { rfc: 'RFC 9156', title: 'QNAME Minimisation', summary: 'Default-on minimisation with NS-label probing; full fallback on referral.', category: 'core' },
  { rfc: 'RFC 9460', title: 'SVCB / HTTPS RR', summary: 'Type 64/65 parsed and surfaced; AliasMode and ServiceMode passed through.', category: 'core' },

  // DNSSEC validation
  { rfc: 'RFC 4034', title: 'DNSSEC Resource Records', summary: 'DNSKEY, RRSIG, NSEC, DS — parse and validate.', category: 'dnssec' },
  { rfc: 'RFC 4035', title: 'DNSSEC Protocol Modifications', summary: 'Chain-of-trust from root, AD bit semantics, DO-bit propagation.', category: 'dnssec' },
  { rfc: 'RFC 4509', section: '§2.4', title: 'SHA-256 in DS Records — Reserved Digest 0', summary: 'Digest type 0 (IANA-reserved) treated as unusable, unconditionally.', category: 'dnssec', since: 'v0.6.25' },
  { rfc: 'RFC 5011', title: 'Automated Trust Anchor Updates', summary: 'Root KSK rollover handled via revocation bit + standby key tracking.', category: 'dnssec' },
  { rfc: 'RFC 5155', title: 'NSEC3 Hashed Authenticated Denial of Existence', summary: 'NSEC3 walk, opt-out flag handling, iteration-count cap.', category: 'dnssec' },
  { rfc: 'RFC 6605', title: 'ECDSA in DNSSEC', summary: 'Algorithms 13 (P-256/SHA-256) and 14 (P-384/SHA-384).', category: 'dnssec' },
  { rfc: 'RFC 6840', section: '§5.9', title: 'CD Bit Propagation', summary: 'Client CD=1 propagates to forward-mode upstream queries (v0.6.25).', category: 'dnssec', since: 'v0.6.25' },
  { rfc: 'RFC 6975', title: 'Signaling Cryptographic Algorithm Understanding (DAU/DHU/N3U)', summary: 'EDNS options 5/6/7 signal supported algorithms upstream.', category: 'dnssec' },
  { rfc: 'RFC 8624', section: '§3.1 / §3.3', title: 'DNSSEC Algorithm Implementation Requirements', summary: 'MUST-NOT algorithms (RSAMD5, DSA, DSA-NSEC3, RSASHA1-NSEC3) gated by IANA-named constants.', category: 'dnssec', since: 'v0.6.25' },
  { rfc: 'RFC 9018', title: 'Interoperable Domain Name System Cookies', summary: 'COOKIE option encoded per §3 with the standard server-cookie key.', category: 'dnssec' },
  { rfc: 'RFC 9276', title: 'NSEC3 Iteration and Salt Guidance', summary: 'Iteration counts above 100 rejected at validation per §3.1.', category: 'dnssec' },
  { rfc: 'RFC 4035', section: '§4.6', title: 'Algorithm Rollover — Dual-Signature Acceptance', summary: 'Validator iterates ALL RRSIGs; one valid signature suffices during a multi-algorithm rollover. Four-corner pin locks the iteration.', category: 'dnssec', since: 'v0.6.42' },
  { rfc: 'RFC 7344 / RFC 8078', title: 'Child-Signalled DS Updates (CDS / CDNSKEY)', summary: 'CDS (type 59) and CDNSKEY (type 60) parsers + RFC 8078 §4 "delete" sentinel classifier. Anti-hijack guard rejects mixed sentinel + publish records.', category: 'dnssec', since: 'v0.6.43' },
  { rfc: 'RFC 5011', section: '§2.1 / §2.4', title: 'Full Trust-Anchor Lifecycle', summary: 'Five-state machine (AddPending → Valid → Missing → Removed, plus Revoked via §2.1) with 30-day hold-downs and substitution-attack defence.', category: 'dnssec', since: 'v0.6.43' },
  { rfc: 'RFC 7646', title: 'Negative Trust Anchors (NTA)', summary: 'Operator-installed time-bounded validation override per zone subtree. Runtime install / remove via UI; suffix-walk matcher with §6 bounded-lifetime safety.', category: 'dnssec', since: 'v0.6.42' },
  { rfc: 'RFC 8901', title: 'Multi-Signer DNSSEC', summary: 'Two-operator model: both KSKs in apex DNSKEY, parent publishes one DS per signer, answer signed by either operator validates.', category: 'dnssec', since: 'v0.7.4' },

  // Aggressive use of DNSSEC denials
  { rfc: 'RFC 8198', section: '§5.2', title: 'Aggressive NXDOMAIN Synthesis', summary: 'NSEC/NSEC3 ranges synthesise NXDOMAIN for subsequent queries without re-asking the auth.', category: 'nsec-aggressive', since: 'v0.6.20' },
  { rfc: 'RFC 8198', section: '§5.4', title: 'Aggressive NODATA Synthesis', summary: 'Type-bitmap-aware NODATA synthesis for queries hitting cached NSEC/NSEC3.', category: 'nsec-aggressive', since: 'v0.6.22' },

  // EDNS / Cookies / Padding
  { rfc: 'RFC 6891', title: 'EDNS(0)', summary: 'OPT pseudo-record, extended RCODE (12-bit), DO flag handling.', category: 'edns' },
  { rfc: 'RFC 7828', title: 'edns-tcp-keepalive', summary: 'TCP-only — server-side keepalive timeout advertised in OPT.', category: 'edns', since: 'v0.6.20' },
  { rfc: 'RFC 7830 + RFC 8467', title: 'EDNS(0) Padding', summary: 'DoT/DoH responses padded to 468-byte block boundary (§4.1 recommendation).', category: 'edns', since: 'v0.6.20' },
  { rfc: 'RFC 7871', title: 'Client Subnet (ECS)', summary: 'Outbound ECS forwarding configurable per-zone; client privacy preserved by default.', category: 'edns' },
  { rfc: 'RFC 7873', section: '§5.3 / §5.4', title: 'DNS Cookies (server-side cache + BADCOOKIE retry)', summary: 'Server-cookie cache avoids per-query BADCOOKIE round trip; outbound retry handles cold cache.', category: 'edns', since: 'v0.6.21' },
  { rfc: 'RFC 7873', section: '§5.4', title: 'Strict Cookie Mode — Cookie-less UDP Refused', summary: 'Operator opt-in: UDP queries without a client cookie get BADCOOKIE + server cookie; TCP/DoT/DoH skip the gate.', category: 'edns', since: 'v0.7.3' },
  { rfc: 'RFC 8467', section: '§6', title: 'Padding Never on Plaintext Transports', summary: 'PADDING option honoured only on encrypted transports (DoT/DoH); plaintext TCP responses pass through unpadded.', category: 'edns', since: 'v0.7.1' },

  // Transport security
  { rfc: 'RFC 7858', title: 'DNS over TLS (DoT)', summary: 'TCP/853 with strict TLS 1.2+ and EDNS padding for response privacy.', category: 'transport-security' },
  { rfc: 'RFC 8484', title: 'DNS over HTTPS (DoH)', summary: 'application/dns-message GET and POST; HTTP/2 multiplexing.', category: 'transport-security' },
  { rfc: 'RFC 9250', title: 'DNS over QUIC (DoQ)', summary: 'QUIC/853 transport with per-query streams; HTTP/3 not required.', category: 'transport-security' },

  // Special-use names
  { rfc: 'RFC 6303', title: 'Locally-Served DNS Zones', summary: 'RFC 1918, RFC 4193 (ULA), link-local (RFC 3927/4291) PTR served locally — never forwarded.', category: 'special-use', since: 'v0.6.21' },
  { rfc: 'RFC 6761', title: 'Special-Use Domain Names', summary: 'test., example., invalid., localhost. short-circuited per §6.', category: 'special-use' },
  { rfc: 'RFC 6762', title: 'Multicast DNS', summary: '.local single-label and dotted names refused (not multicast-resolved).', category: 'special-use' },
  { rfc: 'RFC 7686', title: '.onion Special Use', summary: 'Tor hidden-service names refused at resolver per §2.', category: 'special-use' },
  { rfc: 'RFC 8375', title: '.home.arpa', summary: 'Locally-served zone for residential routers per §6.', category: 'special-use' },

  // Error signalling
  { rfc: 'RFC 8914', title: 'Extended DNS Errors (EDE)', summary: 'EDE codes 0-27 (IANA-complete through Jan 2026). RFC 9606 (25), RFC 9539 (26), RFC 9276 (27) backfill landed in v0.7.1.', category: 'error-signalling', since: 'v0.6.23' },

  // Caching
  { rfc: 'RFC 8767', section: '§3.1', title: 'Serve-Stale + Stale-While-Refresh', summary: 'Stale answer served when origin fails; async refresh kicked in parallel.', category: 'caching', since: 'v0.6.22' },
  { rfc: 'RFC 9520', title: 'Negative Caching of DNS Resolution Failures', summary: 'Bounded LRU failure cache absorbs retry storms against broken upstreams.', category: 'caching', since: 'v0.6.22' },

  // Blocking
  { rfc: 'RFC 8659', title: 'DNS Certification Authority Authorization (CAA)', summary: 'CAA records resolved and returned verbatim — not enforced (operator concern).', category: 'core' },
]

export const CATEGORY_LABELS: Record<ComplianceCategory, string> = {
  core: 'Core Protocol',
  dnssec: 'DNSSEC Validation',
  'nsec-aggressive': 'Aggressive NSEC/NSEC3',
  edns: 'EDNS / Cookies / Padding',
  'transport-security': 'Transport Security',
  'special-use': 'Special-Use Names',
  'error-signalling': 'Extended Errors',
  caching: 'Caching',
  blocking: 'Blocking & Policy',
}
