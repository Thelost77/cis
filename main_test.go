package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileRoundTripInPlace(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "note.txt")
	want := []byte("hello from cis")
	if err := os.WriteFile(in, want, 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(in)
	if err != nil {
		t.Fatal(err)
	}
	askPassword = func() (string, error) { return "pw", nil }
	t.Cleanup(func() { askPassword = readPassword })

	if err := run([]string{"enc", in}); err != nil {
		t.Fatal(err)
	}
	encrypted, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(encrypted) == string(want) {
		t.Fatal("file was not encrypted")
	}
	info, err := os.Stat(in)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	if err := run([]string{"dec", in}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q", got)
	}
}

func TestWrongPasswordLeavesFile(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(in, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	askPassword = func() (string, error) { return "right", nil }
	t.Cleanup(func() { askPassword = readPassword })
	if err := run([]string{"enc", in}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	askPassword = func() (string, error) { return "wrong", nil }
	if err := run([]string{"dec", in}); err == nil {
		t.Fatal("expected error")
	}
	after, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("wrong password changed the file")
	}
}

func TestUnknownCommand(t *testing.T) {
	if err := run([]string{"lock"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestMissingCommand(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("expected error")
	}
}
