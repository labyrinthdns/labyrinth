//go:build windows

package main

import "testing"

func TestSetupUnixSignals_WindowsNoop(t *testing.T) {
	setupUnixSignals(nil, nil)
}
