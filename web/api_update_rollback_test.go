package web

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestReplaceExecutableRollsBackSecondStageFailure(t *testing.T) {
	withUpdateHooksReset(t)

	installErr := errors.New("install rename failed")
	var calls [][2]string
	updateRemove = func(string) error { return nil }
	updateRename = func(oldPath, newPath string) error {
		calls = append(calls, [2]string{oldPath, newPath})
		if oldPath == "/tmp/new" && newPath == "/bin/labyrinth" {
			return installErr
		}
		return nil
	}

	err := replaceExecutable("/tmp/new", "/bin/labyrinth", true)
	if !errors.Is(err, installErr) {
		t.Fatalf("replaceExecutable error = %v, want wrapped install error", err)
	}
	want := [][2]string{
		{"/bin/labyrinth", "/bin/labyrinth.old"},
		{"/tmp/new", "/bin/labyrinth"},
		{"/bin/labyrinth.old", "/bin/labyrinth"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("rename calls = %#v, want %#v", calls, want)
	}
}

func TestReplaceExecutableReportsRollbackFailure(t *testing.T) {
	withUpdateHooksReset(t)

	installErr := errors.New("install rename failed")
	rollbackErr := errors.New("rollback rename failed")
	updateRemove = func(string) error { return nil }
	updateRename = func(oldPath, newPath string) error {
		switch {
		case oldPath == "/tmp/new":
			return installErr
		case oldPath == "/bin/labyrinth.old" && newPath == "/bin/labyrinth":
			return rollbackErr
		default:
			return nil
		}
	}

	err := replaceExecutable("/tmp/new", "/bin/labyrinth", true)
	if !errors.Is(err, installErr) {
		t.Fatalf("replaceExecutable error = %v, want wrapped install error", err)
	}
	if got := err.Error(); !strings.Contains(got, "rollback backup") || !strings.Contains(got, rollbackErr.Error()) {
		t.Fatalf("error %q does not report rollback failure", got)
	}
}

func TestReplaceExecutableWithoutBackupUsesSingleRename(t *testing.T) {
	withUpdateHooksReset(t)

	var calls [][2]string
	updateRename = func(oldPath, newPath string) error {
		calls = append(calls, [2]string{oldPath, newPath})
		return nil
	}
	if err := replaceExecutable("/tmp/new", "/bin/labyrinth", false); err != nil {
		t.Fatalf("replaceExecutable: %v", err)
	}
	want := [][2]string{{"/tmp/new", "/bin/labyrinth"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("rename calls = %#v, want %#v", calls, want)
	}
}
