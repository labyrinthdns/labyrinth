# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.8.x   | :white_check_mark: |
| < 0.8   | :x:                |

## Reporting a Vulnerability

LabyrinthDNS takes security seriously. If you discover a security vulnerability,
please report it privately **before** filing a public issue.

**Do not** report security vulnerabilities through public GitHub issues.

### How to report

1. **Email**: Send details to the maintainer via a private channel.
2. **GitHub Security Advisories**: Navigate to the repository's
   [Security Advisories](https://github.com/labyrinthdns/labyrinth/security/advisories)
   tab and create a new advisory draft.

Please include:
- A description of the vulnerability
- Steps to reproduce (proof of concept preferred)
- Affected versions
- Impact assessment
- Any suggested mitigation (if known)

### What to expect

- **Acknowledgement** within 48 hours of your report.
- **Initial assessment** within 5 business days.
- A coordinated disclosure timeline agreed with you.

We aim to release a fix within 14 days for HIGH/CRITICAL findings,
depending on complexity.

## Scope

The following are in scope for security reports:
- LabyrinthDNS resolver binary and its source code
- Web dashboard and REST API
- Configuration handling
- Dependency vulnerabilities

The following are **out of scope**:
- The marketing website (labyrinthdns.com) — report separately
- Third-party services (GitHub, Docker Hub, CDNs)
- Social engineering of project maintainers

## Security-relevant configuration

Operators should review the following settings for secure deployment:

- **`security.private_address_filter`** — Enable to strip RFC 1918 / CGNAT /
  link-local answers from upstream responses (DNS rebinding protection).
- **`security.dns_cookies`** — Enable DNS Cookies (RFC 7873) for UDP
  anti-amplification.
- **`security.dns_cookies_enforce`** — Strict mode: refuse cookie-less UDP.
- **`security.rate_limit`** — Query rate limiting per client.
- **`security.rrl`** — Response Rate Limiting for amplification defense.
- **`access_control`** — Restrict which clients may use the resolver.
- **`web.auth`** — Always set a strong password_hash. Use `labyrinth hash`.
- **`resolver.dnssec_enabled`** — Enable DNSSEC validation.
- **`resolver.harden_below_nxdomain`** — Enable RFC 8020 hardening.
- **`server.max_udp_size: 1232`** — Recommended EDNS0 buffer (Flag Day 2020).

## Known security features

| Feature | RFC | Description |
|---------|-----|-------------|
| DNSSEC validation | 4033–4035 | Full signature verification, trust chain |
| DNS Cookies | 7873 | Server cookies, BADCOOKIE enforcement |
| 0x20 case randomization | 5452 $9.2 | Anti-spoofing query randomization |
| Source port randomization | 5452 | Kernel-assigned ephemeral ports |
| Response Rate Limiting | — | Token-bucket per /24 + /56 |
| Query rate limiting | — | Per-client query budget |
| ACL / recursion controls | 5358 | Per-zone + global access control |
| Private address filtering | — | DNS rebinding protection |
| Bailiwick enforcement | 5452 $3 | In-bailiwick sanitisation |
| Extended DNS Errors | 8914 | Granular error signalling |
| Crypto budgets | — | Bounded DNSSEC verification work |
| Request budgets | — | Bounded query fan-out (NXNS defense) |
| Config bounds clamping | — | Operator-typo OOM/panic protection |

## Acknowledgments

We thank the security research community for responsibly disclosing
issues and helping make LabyrinthDNS more secure.
