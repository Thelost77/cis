package main

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"testing"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// readTree returns the content of every regular file below root, temp files
// included.
func readTree(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func usePassword(t *testing.T, password string) {
	t.Helper()
	askPassword = func() (string, error) { return password, nil }
	t.Cleanup(func() { askPassword = readPassword })
}

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

func TestFolderRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := map[string]string{
		"a.txt":         "hello from cis",
		"sub/b.bin":     "\x00\x01\xff\x00",
		"sub/deep/c.sh": "#!/bin/sh\n",
	}
	writeTree(t, dir, want)
	script := filepath.Join(dir, "sub/deep/c.sh")
	if err := os.Chmod(script, 0o750); err != nil {
		t.Fatal(err)
	}
	usePassword(t, "pw")

	if err := run([]string{"enc", dir}); err != nil {
		t.Fatal(err)
	}
	encrypted := readTree(t, dir)
	if len(encrypted) != len(want) {
		t.Fatalf("got %d files, want %d", len(encrypted), len(want))
	}
	for name, plain := range want {
		if encrypted[name] == plain {
			t.Fatalf("%s was not encrypted", name)
		}
	}
	info, err := os.Stat(script)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}

	if err := run([]string{"dec", dir}); err != nil {
		t.Fatal(err)
	}
	if got := readTree(t, dir); !maps.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
}

func TestFolderWrongPasswordLeavesFiles(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "one", "sub/b.txt": "two"})
	usePassword(t, "right")
	if err := run([]string{"enc", dir}); err != nil {
		t.Fatal(err)
	}
	before := readTree(t, dir)
	usePassword(t, "wrong")
	if err := run([]string{"dec", dir}); err == nil {
		t.Fatal("expected error")
	}
	if after := readTree(t, dir); !maps.Equal(after, before) {
		t.Fatal("wrong password changed the folder")
	}
}

func TestFolderFailureLeavesFiles(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "one"})
	usePassword(t, "pw")
	if err := run([]string{"enc", dir}); err != nil {
		t.Fatal(err)
	}
	// dec stages a.txt, then fails on b.txt.
	writeTree(t, dir, map[string]string{"b.txt": "not a secret"})
	before := readTree(t, dir)
	if err := run([]string{"dec", dir}); err == nil {
		t.Fatal("expected error")
	}
	if after := readTree(t, dir); !maps.Equal(after, before) {
		t.Fatalf("failed dec changed the folder: %q", after)
	}
}

func TestFolderEncryptSkipsEncryptedFiles(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "one"})
	usePassword(t, "pw")
	if err := run([]string{"enc", dir}); err != nil {
		t.Fatal(err)
	}
	first := readTree(t, dir)
	writeTree(t, dir, map[string]string{"b.txt": "two"})

	if err := run([]string{"enc", dir}); err != nil {
		t.Fatal(err)
	}
	second := readTree(t, dir)
	if second["a.txt"] != first["a.txt"] {
		t.Fatal("a.txt was encrypted twice")
	}
	if second["b.txt"] == "two" {
		t.Fatal("b.txt was not encrypted")
	}

	if err := run([]string{"dec", dir}); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"a.txt": "one", "b.txt": "two"}
	if got := readTree(t, dir); !maps.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
}

func TestFolderSkipsSymlinks(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "one"})
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	usePassword(t, "pw")
	if err := run([]string{"enc", dir}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep me" {
		t.Fatal("enc changed a file outside the folder")
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&fs.ModeSymlink == 0 {
		t.Fatal("enc replaced the symlink")
	}
}

func TestEmptyFolder(t *testing.T) {
	usePassword(t, "pw")
	if err := run([]string{"enc", t.TempDir()}); err == nil {
		t.Fatal("expected error")
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
