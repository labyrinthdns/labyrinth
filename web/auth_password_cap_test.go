package web

import (
	"strings"
	"testing"
)

// TestValidatePassword_RejectsOver72Bytes pins the bcrypt input cap
// on the password validation surface. bcrypt silently truncates input
// to 72 bytes — without an explicit cap, an operator choosing a
// 128-char "extra-secure" passphrase would learn only the hard way
// that bytes 73+ never participated in the hash, and that two
// passphrases sharing the same first 72 bytes are interchangeable.
//
// The pin asserts (a) a 73-byte input is refused by ValidatePassword,
// (b) a 72-byte input (the cap) is accepted, (c) the error message
// names the bcrypt limit so the operator understands the reason
// rather than thinking the input is rejected for security theatre.
func TestValidatePassword_RejectsOver72Bytes(t *testing.T) {
	pw73 := strings.Repeat("a", 73)
	err := ValidatePassword(pw73)
	if err == nil {
		t.Fatal("ValidatePassword accepted a 73-byte password — bcrypt cap not enforced")
	}
	if !strings.Contains(err.Error(), "bcrypt") {
		t.Errorf("error message should mention bcrypt so operator understands why: %v", err)
	}

	pw72 := strings.Repeat("a", 72)
	if err := ValidatePassword(pw72); err != nil {
		t.Errorf("ValidatePassword rejected a 72-byte password (the bcrypt cap): %v", err)
	}
}

// TestValidatePassword_RejectsShortPasswords — pre-existing minimum
// length check still holds. Negative control: this gate is independent
// of the new bcrypt cap.
func TestValidatePassword_RejectsShortPasswords(t *testing.T) {
	if err := ValidatePassword("short"); err == nil {
		t.Error("ValidatePassword accepted a 5-byte password — minimum length not enforced")
	}
	if err := ValidatePassword("just8byt"); err != nil {
		t.Errorf("ValidatePassword rejected a valid 8-byte password: %v", err)
	}
}

// TestHashPassword_RejectsOver72Bytes — companion pin so the
// HashPassword path also refuses oversized input. Without this, a
// caller that bypassed ValidatePassword would silently get a hash of
// only the first 72 bytes.
func TestHashPassword_RejectsOver72Bytes(t *testing.T) {
	pw73 := strings.Repeat("b", 73)
	_, err := HashPassword(pw73)
	if err == nil {
		t.Fatal("HashPassword silently truncated an over-72-byte input — must refuse instead")
	}
}
