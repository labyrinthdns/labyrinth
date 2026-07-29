package dns

import "errors"

var (
	errTruncated      = errors.New("dns: message truncated")
	errBufferFull     = errors.New("dns: buffer full")
	errNameTooLong    = errors.New("dns: name exceeds 255 bytes")
	errLabelTooLong   = errors.New("dns: label exceeds 63 bytes")
	errPointerLoop    = errors.New("dns: compression pointer loop detected")
	errPointerForward = errors.New("dns: compression pointer references forward")
	errInvalidMessage = errors.New("dns: invalid message")
)
