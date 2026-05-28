//go:build windows

package web

import (
	"errors"
	"os/exec"
	"testing"
)

func withRestartHooksReset(t *testing.T) {
	t.Helper()
	prevExec := restartExecutable
	prevEval := restartEvalSymlinks
	prevCmd := restartCommand
	prevExit := restartExit
	t.Cleanup(func() {
		restartExecutable = prevExec
		restartEvalSymlinks = prevEval
		restartCommand = prevCmd
		restartExit = prevExit
	})
}

func TestRestartSelf_ExecutableError(t *testing.T) {
	withRestartHooksReset(t)
	restartExecutable = func() (string, error) {
		return "", errors.New("exe error")
	}
	if err := restartSelf(); err == nil {
		t.Fatalf("expected executable error")
	}
}

func TestRestartSelf_EvalSymlinksError(t *testing.T) {
	withRestartHooksReset(t)
	restartExecutable = func() (string, error) { return "/some/path", nil }
	restartEvalSymlinks = func(string) (string, error) { return "", errors.New("symlink error") }
	if err := restartSelf(); err == nil {
		t.Fatalf("expected eval symlinks error")
	}
}

func TestRestartSelf_StartError(t *testing.T) {
	withRestartHooksReset(t)
	restartExecutable = func() (string, error) { return "ignored.exe", nil }
	restartEvalSymlinks = func(p string) (string, error) { return p, nil }
	restartCommand = func(string, ...string) *exec.Cmd {
		return exec.Command("this-command-should-not-exist-xyz")
	}
	restartExit = func(int) {
		t.Fatalf("restartExit must not be called when start fails")
	}

	if err := restartSelf(); err == nil {
		t.Fatalf("expected start error")
	}
}

func TestRestartSelf_Success(t *testing.T) {
	withRestartHooksReset(t)
	restartExecutable = func() (string, error) { return "ignored.exe", nil }
	restartEvalSymlinks = func(p string) (string, error) { return p, nil }
	restartCommand = func(string, ...string) *exec.Cmd {
		return exec.Command("cmd", "/c", "exit", "0")
	}

	exitCode := -1
	restartExit = func(code int) {
		exitCode = code
	}

	if err := restartSelf(); err != nil {
		t.Fatalf("restartSelf unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected restartExit(0), got %d", exitCode)
	}
}
