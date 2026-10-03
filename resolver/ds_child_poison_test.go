package resolver

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func rrsigRDataWithSigner(typeCovered uint16, signer string) []byte {
	fixed := make([]byte, 18)
	binary.BigEndian.PutUint16(fixed[0:2], typeCovered)
	fixed[2] = dns.AlgED25519
	fixed[3] = 2
	binary.BigEndian.PutUint32(fixed[4:8], 300)
	binary.BigEndian.PutUint32(fixed[8:12], 0xFFFFFFFF)
	binary.BigEndian.PutUint32(fixed[12:16], 0)
	binary.BigEndian.PutUint16(fixed[16:18], 1)
	rdata := append(fixed, encodeNameWire(signer)...)
	return append(rdata, 1, 2, 3)
}

func TestDSDenialSignedByChild(t *testing.T) {
	auth := []dns.ResourceRecord{{
		Name: "turkmmo.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
		RData: rrsigRDataWithSigner(dns.TypeNSEC, "turkmmo.com."),
	}}
	if !dsDenialSignedByChild("turkmmo.com", auth) {
		t.Fatal("expected child-signed DS denial to be detected")
	}

	parentAuth := []dns.ResourceRecord{{
		Name: "CK0POJMG874LJREF7EFN8430QVIT8BSM.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 900,
		RData: rrsigRDataWithSigner(dns.TypeNSEC3, "com."),
	}}
	if dsDenialSignedByChild("turkmmo.com", parentAuth) {
		t.Fatal("parent-signed denial must not be treated as child poison")
	}
}
