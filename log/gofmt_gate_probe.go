package log

// GofmtGateProbe exists only to prove that the CI gofmt gate fails when a
// Go file drifts from gofmt output. It is intentionally misformatted: it
// uses spaces instead of tab indentation and stray spacing around tokens,
// so `gofmt -l` and `golangci-lint fmt --diff` must both flag it.
func GofmtGateProbe(  ) string {
    return  "probe"
}