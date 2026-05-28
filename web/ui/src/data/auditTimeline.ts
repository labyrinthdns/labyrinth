// auditTimeline — chronological record of the RFC pin work that
// landed in each release from the v0.6.32 audit kickoff through the
// current series. Curated by hand from CHANGELOG.md — the goal isn't
// an exhaustive feature list (the changelog is canonical) but a
// scannable "what RFC behaviour did this release lock down" view
// for the operator answering "is the resolver getting safer over
// time, and what was the most recent harden?".
//
// Each entry: version + release date + ordered list of pin/harden
// items with the RFC reference and a one-line summary. Order is
// newest-first so the timeline UI renders the latest changes at the
// top without re-sorting.

export interface AuditEntry {
  rfc: string
  summary: string
  // kind: 'harden' = pin test locking existing behaviour,
  //       'added' = new feature with pin,
  //       'fixed' = real bug fix.
  kind: 'harden' | 'added' | 'fixed'
}

export interface AuditRelease {
  version: string
  date: string // YYYY-MM-DD
  theme: string
  entries: AuditEntry[]
}

export const AUDIT_TIMELINE: AuditRelease[] = [
  {
    version: 'v0.7.8',
    date: '2026-05-28',
    theme: 'M6.1 — Fuzz harness',
    entries: [
      { rfc: 'RFC 7873 / RFC 4034', kind: 'added', summary: 'Fuzz entry points for ParseCookieOption / Unpack / ParseDNSKEY / ParseDS with seeded corpora.' },
    ],
  },
  {
    version: 'v0.7.7',
    date: '2026-05-28',
    theme: 'Root priming pin',
    entries: [
      { rfc: 'RFC 8109', kind: 'harden', summary: 'PrimeRootHints query shape pinned (QNAME=root, QTYPE=NS, QCLASS=IN). Ready flag set even on failure.' },
    ],
  },
  {
    version: 'v0.7.6',
    date: '2026-05-28',
    theme: 'Compliance matrix refresh',
    entries: [
      { rfc: 'RFCs 4035 / 7344 / 5011 / 7646 / 8901 / 7873 / 8467', kind: 'added', summary: 'About-page matrix lists all seven new RFCs from this audit cycle.' },
    ],
  },
  {
    version: 'v0.7.5',
    date: '2026-05-28',
    theme: 'UI-M6 — Security panel',
    entries: [
      { rfc: 'RFC 7873 / RRL', kind: 'added', summary: '/api/security endpoint + Security dashboard page (cookies / rate-limit / RRL).' },
    ],
  },
  {
    version: 'v0.7.4',
    date: '2026-05-28',
    theme: 'Source port + multi-signer pins',
    entries: [
      { rfc: 'RFC 5452 §10', kind: 'harden', summary: 'Empirical outbound UDP source-port randomisation pin (≥30 distinct ports across 50 dials).' },
      { rfc: 'RFC 8901', kind: 'harden', summary: 'Multi-signer model pin: two operators, two DS records, answer signed by either validates.' },
    ],
  },
  {
    version: 'v0.7.3',
    date: '2026-05-28',
    theme: 'Strict cookie mode',
    entries: [
      { rfc: 'RFC 7873 §5.4', kind: 'added', summary: 'Operator-opt-in strict mode: UDP cookie-less queries answered with BADCOOKIE.' },
      { rfc: '(internal)', kind: 'fixed', summary: 'Latent bug: security.dns_cookies config was dead — main.go never called EnableCookies. Now wired.' },
    ],
  },
  {
    version: 'v0.7.2',
    date: '2026-05-28',
    theme: 'Runtime NTA management',
    entries: [
      { rfc: 'RFC 7646', kind: 'added', summary: 'POST / DELETE /api/dnssec/nta with 30-day duration ceiling; UI add / remove controls.' },
    ],
  },
  {
    version: 'v0.7.1',
    date: '2026-05-28',
    theme: 'EDE backfill + padding policy',
    entries: [
      { rfc: 'RFC 9606 / RFC 9539 / RFC 9276', kind: 'added', summary: 'EDE codes 25 / 26 / 27 backfilled. Full IANA 0-27 table pin.' },
      { rfc: 'RFC 8467 §6', kind: 'harden', summary: 'Four-corner truth table: padding only on encrypted transports.' },
    ],
  },
  {
    version: 'v0.7.0',
    date: '2026-05-28',
    theme: 'UI-M1 — DNSSEC dashboard',
    entries: [
      { rfc: 'RFC 7646', kind: 'added', summary: '/api/dnssec endpoint + /dnssec dashboard page with NTA table.' },
    ],
  },
  {
    version: 'v0.6.43',
    date: '2026-05-28',
    theme: 'CDS + RFC 5011 lifecycle',
    entries: [
      { rfc: 'RFC 7344 / RFC 8078', kind: 'added', summary: 'CDS (type 59) / CDNSKEY (type 60) parsers + RFC 8078 §4 delete sentinel classifier.' },
      { rfc: 'RFC 5011 §2.1 / §2.4', kind: 'added', summary: 'Five-state trust anchor lifecycle (AddPending → Valid → Missing → Removed, plus Revoked) with 30-day hold-downs.' },
    ],
  },
  {
    version: 'v0.6.42',
    date: '2026-05-28',
    theme: 'Rollover pin + NTA core',
    entries: [
      { rfc: 'RFC 4035 §4.6', kind: 'harden', summary: 'Algorithm rollover dual-signature acceptance: four-corner truth table.' },
      { rfc: 'RFC 7646', kind: 'added', summary: 'Negative Trust Anchor core: store, suffix-walk matcher, ReasonNTAOverride, config wiring.' },
    ],
  },
]
