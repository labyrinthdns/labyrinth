package pool

import "sync"

// BufferPool provides reusable byte buffers to avoid per-query allocations.
var BufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 4096)
		return &buf
	},
}

// GetBuffer retrieves a buffer from the pool.
func GetBuffer() *[]byte {
	return BufferPool.Get().(*[]byte)
}

// PutBuffer returns a buffer to the pool.
func PutBuffer(buf *[]byte) {
	BufferPool.Put(buf)
}
