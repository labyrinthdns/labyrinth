// Package soak contains a long-running soak test for the full resolver
// stack. The test itself lives in soak_test.go behind the `soak` build
// tag, so plain `go test ./...` skips it; run it via `make soak` or
// `go test -tags soak ./test/soak/`.
package soak
