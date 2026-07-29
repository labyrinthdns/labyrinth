package dns

import "testing"

func TestUnpackQuestionSimple(t *testing.T) {
	// "com" Type=A Class=IN
	buf := []byte{
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	}

	q, offset, err := UnpackQuestion(buf, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.Name != "com" {
		t.Errorf("Name: expected 'com', got '%s'", q.Name)
	}
	if q.Type != TypeA {
		t.Errorf("Type: expected %d, got %d", TypeA, q.Type)
	}
	if q.Class != ClassIN {
		t.Errorf("Class: expected %d, got %d", ClassIN, q.Class)
	}
	if offset != len(buf) {
		t.Errorf("offset: expected %d, got %d", len(buf), offset)
	}
}

func TestUnpackQuestionTruncatedName(t *testing.T) {
	// Label says 3 bytes but only 2 available
	buf := []byte{0x03, 'a', 'b'}
	_, _, err := UnpackQuestion(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestUnpackQuestionTruncatedType(t *testing.T) {
	// Valid name but missing type and class
	buf := []byte{0x03, 'c', 'o', 'm', 0x00}
	_, _, err := UnpackQuestion(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated for missing type, got %v", err)
	}
}

func TestUnpackQuestionTruncatedClass(t *testing.T) {
	// Valid name and type, but missing class
	buf := []byte{
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, // Type A
	}
	_, _, err := UnpackQuestion(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated for missing class, got %v", err)
	}
}

func TestUnpackQuestionWithCompressedName(t *testing.T) {
	// Build a message buffer: "example.com" at offset 0, then a question using a pointer
	buf := []byte{
		// "example.com" at offset 0
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		// Question: pointer to offset 0, Type=AAAA, Class=IN
		0xC0, 0x00,
		0x00, 0x1C, // Type AAAA
		0x00, 0x01, // Class IN
	}

	q, offset, err := UnpackQuestion(buf, 13)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.Name != "example.com" {
		t.Errorf("Name: expected 'example.com', got '%s'", q.Name)
	}
	if q.Type != TypeAAAA {
		t.Errorf("Type: expected %d, got %d", TypeAAAA, q.Type)
	}
	if q.Class != ClassIN {
		t.Errorf("Class: expected %d, got %d", ClassIN, q.Class)
	}
	if offset != len(buf) {
		t.Errorf("offset: expected %d, got %d", len(buf), offset)
	}
}
