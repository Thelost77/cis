package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"golang.org/x/term"
)

const version = "dev"

var askPassword = readPassword

var errAlreadyEncrypted = errors.New("already encrypted")

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "cis: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Println(usage())
		return nil
	case "--version", "version":
		fmt.Println(currentVersion())
		return nil
	case "enc":
		if len(args) > 2 {
			return fmt.Errorf("enc: extra argument")
		}
		if len(args) == 2 {
			return encryptFile(args[1])
		}
		return encryptNote()
	case "dec":
		if len(args) > 2 {
			return fmt.Errorf("dec: extra argument")
		}
		if len(args) == 2 {
			return decryptFile(args[1])
		}
		return decryptNote()
	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], usage())
	}
}

func encryptNote() error {
	plain, err := readPhrase()
	if err != nil {
		return err
	}
	password, err := askPassword()
	if err != nil {
		return err
	}
	blob, err := encrypt(plain, password)
	if err != nil {
		return err
	}
	fmt.Println(blob)
	return nil
}

func decryptNote() error {
	blob, err := readSecret()
	if err != nil {
		return err
	}
	password, err := askPassword()
	if err != nil {
		return err
	}
	plain, err := decrypt(blob, password)
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(plain); err != nil {
		return err
	}
	if term.IsTerminal(int(os.Stdout.Fd())) && (len(plain) == 0 || plain[len(plain)-1] != '\n') {
		_, err = os.Stdout.Write([]byte("\n"))
	}
	return err
}

func encryptFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return encryptDir(path)
	}
	plain, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	password, err := askPassword()
	if err != nil {
		return err
	}
	blob, err := encrypt(plain, password)
	if err != nil {
		return err
	}
	return replaceFile(path, []byte(blob+"\n"), info.Mode().Perm())
}

func decryptFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return decryptDir(path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	password, err := askPassword()
	if err != nil {
		return err
	}
	plain, err := decryptAuthenticated(string(data), password)
	if err != nil {
		return err
	}
	return replaceFile(path, plain, info.Mode().Perm())
}

func encryptDir(root string) error {
	paths, err := regularFiles(root)
	if err != nil {
		return err
	}
	password, err := askPassword()
	if err != nil {
		return err
	}
	return replaceFiles(paths, func(data []byte) ([]byte, error) {
		// A second run after an interrupted run must not encrypt a file twice.
		if _, err := decryptAuthenticated(string(data), password); err == nil {
			return nil, errAlreadyEncrypted
		}
		blob, err := encrypt(data, password)
		if err != nil {
			return nil, err
		}
		return []byte(blob + "\n"), nil
	})
}

func decryptDir(root string) error {
	paths, err := regularFiles(root)
	if err != nil {
		return err
	}
	password, err := askPassword()
	if err != nil {
		return err
	}
	return replaceFiles(paths, func(data []byte) ([]byte, error) {
		return decryptAuthenticated(string(data), password)
	})
}

// regularFiles returns the regular files below root. It does not follow
// symbolic links.
func regularFiles(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("%s: no regular files", root)
	}
	return paths, nil
}

// replaceFiles writes every result to a temp file before it renames any temp
// file. A failure before the first rename leaves all files unchanged.
func replaceFiles(paths []string, convert func([]byte) ([]byte, error)) error {
	type stagedFile struct{ tmp, path string }
	var staged []stagedFile
	defer func() {
		for _, s := range staged {
			_ = os.Remove(s.tmp)
		}
	}()
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out, err := convert(data)
		if err == errAlreadyEncrypted {
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		tmp, err := stageFile(path, out, info.Mode().Perm())
		if err != nil {
			return err
		}
		staged = append(staged, stagedFile{tmp, path})
	}
	total := len(staged)
	for len(staged) > 0 {
		if err := os.Rename(staged[0].tmp, staged[0].path); err != nil {
			return fmt.Errorf("replaced %d of %d files: %w", total-len(staged), total, err)
		}
		staged = staged[1:]
	}
	return nil
}

func replaceFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := stageFile(path, data, mode)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// stageFile writes data to a temp file next to path and returns its name.
func stageFile(path string, data []byte, mode os.FileMode) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".cis-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return tmp, nil
}

func readPhrase() ([]byte, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Phrase: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}
		return []byte(strings.TrimRight(line, "\r\n")), nil
	}
	return io.ReadAll(os.Stdin)
}

func readSecret() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Secret: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		tty, err := os.Open("/dev/tty")
		if err != nil {
			return "", fmt.Errorf("password: %w", err)
		}
		defer tty.Close()
		fd = int(tty.Fd())
	}
	fmt.Fprint(os.Stderr, "Password: ")
	pw, err := term.ReadPassword(fd)
	fmt.Fprint(os.Stderr, "\n")
	if err != nil {
		return "", err
	}
	return string(pw), nil
}

func usageError() error {
	return fmt.Errorf("missing command\n\n%s", usage())
}

func usage() string {
	return strings.TrimSpace(`
Usage: cis enc [file|folder]
       cis dec [file|folder]

enc encrypts a note or replaces a file in place.
dec decrypts a note or replaces a file in place.
With a folder, enc and dec replace each file in the folder.

The tool asks for the password.
`)
}

func currentVersion() string {
	if version != "" && version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if ok && info != nil && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
