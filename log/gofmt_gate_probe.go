package log

// GofmtGateProbe exists only to prove that the CI gofmt step fires its own
// "Go files are not gofmt-clean" annotation when a Go file drifts from
// gofmt output. It is intentionally misformatted: space indentation, stray
// spacing around tokens, and a missing trailing newline.
func GofmtGateProbe(  ) string {
    return  "probe"
}