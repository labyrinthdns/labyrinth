package dnssec

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestDNSKEYMatching_OrphanStrongDSPlusWeakLiveDS pins the
// svrmail.access.net.id failure mode:
//
//   - Parent publishes an orphan SHA-256 DS for a retired keytag, AND
//   - the live KSK is only covered by a SHA-1 DS.
//
// With allow_sha1=false the orphan kept usableDS=true while
// dnskeysMatchingDS returned empty → Bogus → public fallback, even though
// Cloudflare/Google Secure the zone via the SHA-1 DS. Matching under
// weak-digest policy must succeed so the trust-chain walker can return
// Insecure instead of Bogus.
func TestDNSKEYMatching_OrphanStrongDSPlusWeakLiveDS(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kskRData := encodeDNSKEYRData(257, 3, dns.AlgED25519, pub)
	ksk, err := dns.ParseDNSKEY(kskRData)
	if err != nil {
		t.Fatal(err)
	}
	owner := "access.example."
	keyRR := dns.ResourceRecord{
		Name: owner, Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: kskRData,
	}

	sha1Sum := sha1.Sum(buildDSDigestInput(owner, ksk))
	liveWeakDS := &dns.DSRecord{
		KeyTag: ksk.KeyTag(), Algorithm: dns.AlgED25519,
		DigestType: dns.DigestSHA1, Digest: sha1Sum[:],
	}
	orphanStrongDS := &dns.DSRecord{
		KeyTag: 2771, Algorithm: dns.AlgED25519,
		DigestType: dns.DigestSHA256, Digest: make([]byte, 32), // no matching key
	}
	dsList := []*dns.DSRecord{orphanStrongDS, liveWeakDS}

	v := &Validator{} // allowSHA1 defaults to false

	if got := v.dnskeysMatchingDS([]dns.ResourceRecord{keyRR}, dsList, owner); len(got) != 0 {
		t.Fatalf("policy-strict match must be empty (orphan SHA-256 + SHA-1-only live key), got %d", len(got))
	}
	if got := v.dnskeysMatchingDSAllowingWeak([]dns.ResourceRecord{keyRR}, dsList, owner); len(got) != 1 {
		t.Fatalf("weak-allowing match must authenticate the live KSK, got %d", len(got))
	}

	// Control: a real SHA-256 DS for the live key still matches under strict policy.
	sha256Sum := sha256.Sum256(buildDSDigestInput(owner, ksk))
	liveStrong := &dns.DSRecord{
		KeyTag: ksk.KeyTag(), Algorithm: dns.AlgED25519,
		DigestType: dns.DigestSHA256, Digest: sha256Sum[:],
	}
	if got := v.dnskeysMatchingDS([]dns.ResourceRecord{keyRR}, []*dns.DSRecord{liveStrong}, owner); len(got) != 1 {
		t.Fatalf("strict policy must accept a matching SHA-256 DS, got %d", len(got))
	}

	// Control: orphan strong DS alone must not match even with weak allowed.
	if got := v.dnskeysMatchingDSAllowingWeak([]dns.ResourceRecord{keyRR}, []*dns.DSRecord{orphanStrongDS}, owner); len(got) != 0 {
		t.Fatalf("orphan DS must not authenticate any key, got %d", len(got))
	}
}
