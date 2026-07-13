# RFC Compliance Matrix

_Generated from test files and implementation audit — 2026-07-06_

| RFC | Title | Status | Test / Implementation |
|-----|-------|--------|----------------------|
| **Core DNS Protocol** |
| RFC 1034 | Domain Names — Concepts and Facilities | ✅ | `server/rfc1034_aa_bit_test.go` |
| RFC 1035 | Domain Names — Implementation and Specification | ✅ | `server/rfc1035_opcode_test.go`, `server/rfc1035_qclass_test.go`, `server/rfc1035_qdcount_test.go` |
| RFC 2181 | Clarifications to the DNS Specification | ✅ | `cache/rfc2181_rrset_test.go`, `resolver/rfc2181_cname_test.go` |
| **Transport** |
| RFC 7766 | DNS over TCP — Implementation Recommendations | ✅ | `resolver/rfc7766_tcp_fallback_test.go`, `server/stream_no_truncate_test.go` |
| RFC 7858 | DNS over TLS (DoT) | ✅ | `server/dot.go`, `server/dot_test.go` |
| RFC 8484 | DNS Queries over HTTPS (DoH) | ✅ | `web/api_doh.go`, `web/api_doh_vary_test.go` |
| RFC 9103 | Zone Transfer over TLS (XFR-over-TLS) | ✅ | `xfr/client.go` |
| RFC 9250 | DNS over QUIC (DoQ) | ✅ | `server/doq.go` |
| RFC 9210 | DNS Transport over TCP — Operational Requirements | ✅ | `server/rfc9210_tcp_idle_test.go` |
| **EDNS0** |
| RFC 6891 | Extension Mechanisms for DNS (EDNS0) | ✅ | `server/rfc6891_extrcode_test.go`, `server/rfc6891_opt_owner_test.go`, `server/rfc6891_udp_buffer_size_test.go` |
| RFC 7830 | EDNS(0) Padding Option | ✅ | `dns/rfc7830_padding_test.go` |
| RFC 8467 | Padding Policies for EDNS(0) | ✅ | `server/rfc8467_padding_policy_test.go` |
| RFC 7828 | edns-tcp-keepalive EDNS0 Option | ✅ | `dns/rfc7828_keepalive_test.go` |
| **DNSSEC** |
| RFC 4033 | DNSSEC Introduction and Requirements | ✅ | `dnssec/` package |
| RFC 4034 | Resource Records for DNSSEC | ✅ | `dnssec/rfc4034_canonical_order_test.go`, `dnssec/rfc4034_canonical_property_test.go`, `dnssec/rfc4034_canonical_rdata_test.go`, `dnssec/rfc4034_labels_test.go`, `dnssec/rfc4034_sep_advisory_test.go`, `dnssec/rfc4034_zone_key_test.go` |
| RFC 4035 | DNSSEC Protocol Modifications | ✅ | `dnssec/rfc4035_algorithm_rollover_test.go`, `dnssec/rfc4035_clock_skew_test.go`, `dnssec/rfc4035_rrsig_origttl_test.go`, `dnssec/rfc4035_signer_bailiwick_test.go`, `dnssec/rfc4035_verify_cap_test.go`, `dnssec/rfc4035_wildcard_owner_test.go`, `dnssec/rfc4035_wildcard_proof_test.go`, `server/rfc4035_ad_bit_test.go`, `server/rfc4035_do_mirror_test.go`, `server/rfc4035_strip_dnssec_integration_test.go` |
| RFC 4509 | DS Digest Type SHA-256 | ✅ | `dnssec/rfc4509_ds_digest_zero_test.go`, `dnssec/rfc4509_strongest_ds_test.go` |
| RFC 5011 | Automated Updates of DNSSEC Trust Anchors | ✅ | `dnssec/rfc5011_lifecycle.go`, `dnssec/rfc5011_lifecycle_test.go`, `dnssec/rfc5011_revoke_test.go` |
| RFC 5155 | DNSSEC — NSEC3 | ✅ | `dnssec/rfc5155_nsec3_hash_alg_test.go`, `cache/rfc5155_optout_test.go` |
| RFC 6605 | ECDSA for DNSSEC (P-256 / P-384) | ✅ | `dnssec/rfc6605_hash_pairing_test.go` |
| RFC 6840 | Clarifications and Implementation Notes for DNSSEC | ✅ | `dnssec/rfc6840_dnskey_match_test.go`, `dnssec/rfc6840_unsupported_alg_test.go`, `resolver/rfc6840_cd_bit_test.go` |
| RFC 7344 | CDS and CDNSKEY Records | ✅ | `dnssec/rfc7344_cds_test.go`, `dnssec/cds.go` |
| RFC 7646 | Negative Trust Anchors (NTA) | ✅ | `dnssec/rfc7646_nta_test.go`, `dnssec/nta.go` |
| RFC 8624 | DNSSEC Algorithm Implementation Status | ✅ | `dnssec/rfc8624_must_not_algorithms_test.go` |
| RFC 8901 | Multi-Signer DNSSEC Models | ✅ | `dnssec/rfc8901_multi_signer_test.go` |
| RFC 9276 | Guidance for NSEC3 Parameter Settings | ✅ | `dnssec/rfc9276_nsec3_iter_test.go` |
| RFC 6975 | DNSSEC Algorithm Understood Option (DAU/DHU/N3U) | ✅ | `dns/rfc6975_test.go` |
| **Caching** |
| RFC 2308 | Negative Caching of DNS Queries (NCACHE) | ✅ | `cache/rfc2308_negative_ttl_test.go` |
| RFC 8020 | Harden-below-NXDOMAIN | ✅ | `cache/cache.go` `hardenBelowNX` |
| RFC 8198 | Aggressive Use of DNSSEC-Validated Cache (NSEC/NSEC3) | ✅ | `cache/rfc8198_delegation_nsec_test.go`, `cache/rfc8198_nodata_aggressive_test.go`, `cache/rfc8198_nsec3_aggressive_test.go`, `cache/rfc8198_nsec3_delegation_test.go`, `cache/rfc8198_nsec3_nodata_test.go`, `cache/rfc8198_nsec_aggressive_test.go` |
| RFC 8767 | Serving Stale Data to Improve DNS Resiliency | ✅ | `cache/rfc8767_stale_max_age_test.go`, `cache/rfc8767_stale_while_refresh_test.go` |
| RFC 9520 | Negative Caching of Resolution Failures | ✅ | `resolver/rfc9520_ede_cached_test.go`, `resolver/rfc9520_failure_cache_gate_test.go`, `resolver/rfc9520_failure_cache_test.go`, `resolver/failure_cache.go` |
| **Security** |
| RFC 5452 | Measures for Making DNS More Resilient against Forged Answers | ✅ | `resolver/rfc5452_0x20_test.go`, `resolver/rfc5452_source_port_test.go`, `resolver/rfc5452_txid_entropy_test.go` |
| RFC 7871 | EDNS Client Subnet (ECS) | ✅ | `dns/ecs.go`, `resolver/ecs_test.go`, `server/ecs_handler_test.go` |
| RFC 7873 | DNS Cookies | ✅ | Various `rfc7873_*_test.go` files in `server/` and `resolver/` |
| RFC 9018 | Interoperable DNS Server Cookies | ✅ | `server/rfc9018_cookie_ip_binding_test.go`, `server/rfc9018_cookie_rotation_test.go` |
| **Error Reporting** |
| RFC 8914 | Extended DNS Errors (EDE) | ✅ | Codes 0–29 defined, IANA-pinned, emitted for DNSSEC/DNS64/NSEC-cache/stale/reachability/etc. See all `rfc8914_*_test.go` files |
| **Resolution** |
| RFC 8109 | Priming Stub Resolvers (Root Hints) | ✅ | `resolver/rfc8109_root_priming_test.go` |
| RFC 8305 | Happy Eyeballs v2 | ✅ | `resolver/resolver.go` `resolveNSHappyEyeballs`, `resolver/rfc8305_happy_eyeballs_test.go` |
| RFC 9156 | DNS Query Name Minimisation (QNAME) | ✅ | `resolver/rfc9156_qmin_test.go` |
| RFC 6672 | DNAME Redirection | ✅ | `resolver/rfc6672_dname_bailiwick_test.go`, `resolver/rfc6672_dname_synth_test.go` |
| RFC 6147 | DNS64 — DNS Extensions for NAT64 | ✅ | `resolver/dns64.go`, `resolver/dns64_test.go` |
| RFC 6303 | Locally Served DNS Zones | ✅ | `resolver/rfc6303_locally_served.go`, `resolver/rfc6303_locally_served_test.go`, `server/rfc6303_private_reverse_handler_test.go` |
| RFC 6761 | Special-Use Domain Names | ✅ | `resolver/specialuse.go` |
| RFC 7686 | .onion Special-Use Domain | ✅ | `server/rfc7686_onion_handler_test.go` |
| RFC 8482 | Minimal ANY Query Responses | ✅ | `server/rfc8482_minimal_any_test.go` |
| **Other** |
| RFC 9460 | Service Binding (SVCB/HTTPS) | ✅ | `dns/rfc9460_svcb_test.go` |
| RFC 3597 | Handling of Unknown RR Types | ✅ | `dns/rfc3597_unknown_rr_test.go` |

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ Compliant | Tested and verified against one or more RFC-pinned test files |
| ◐ Partial | Core behaviour implemented, edge cases or optimisations deferred |
| ❌ Missing | Not yet implemented (listed in PLAN.md for future milestones) |

## Missing (Future Milestones)

| RFC | Title | Notes |
|-----|-------|-------|
| RFC 8945 | DNS Transaction Signatures (TSIG) | Not yet implemented |
| RFC 9432 | Catalog Zones | Planned for M4.2 |
