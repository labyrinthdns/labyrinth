package security

// Loop detection for DNS resolution.
//
// Three kinds of loops are detected:
//
// 1. NS Loop — delegation chain cycles (A→B→A) detected via a visited set
//    of (nameserver IP, query name) tuples. Maximum resolution depth: 30 steps.
//    Implementation: resolver.visitedSet.Has/Add in resolver/resolver.go.
//
// 2. CNAME Loop — CNAME chain cycles (A→B→C→A) detected via a visited set
//    of target names. Maximum CNAME depth: 10 hops.
//    Implementation: resolver.visitedSet.HasCNAME/AddCNAME in resolver/resolver.go.
//
// 3. Compression Pointer Loop — pointer that references itself or creates a
//    cycle in name decoding. Maximum pointer follows: 128. Each pointer must
//    reference a strictly earlier offset.
//    Implementation: dns.DecodeName in dns/name.go.
