package pool

import "testing"

func TestGetPutGetReusable(t *testing.T) {
	buf1 := GetBuffer()
	if buf1 == nil {
		t.Fatal("GetBuffer returned nil")
	}
	if len(*buf1) != 4096 {
		t.Errorf("expected 4096-byte buffer, got %d", len(*buf1))
	}

	// Mark the buffer
	(*buf1)[0] = 0xAA

	// Return and get again — should reuse
	PutBuffer(buf1)
	buf2 := GetBuffer()
	if buf2 == nil {
		t.Fatal("GetBuffer returned nil after Put")
	}
	if len(*buf2) != 4096 {
		t.Errorf("expected 4096-byte buffer, got %d", len(*buf2))
	}
}

func BenchmarkBufferPool(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buf := GetBuffer()
		PutBuffer(buf)
	}
}
