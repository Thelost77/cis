package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
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
	sealed, err := encrypt(plain, stdinSize(), password)
	if err != nil {
		return err
	}
	return writeSecret(os.Stdout, sealed)
}

func decryptNote() error {
	secret, err := readSecret()
	if err != nil {
		return err
	}
	password, err := askPassword()
	if err != nil {
		return err
	}
	plain, err := decrypt(secret, stdinSize(), password)
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
	password, err := askPassword()
	if err != nil {
		return err
	}
	return replaceFiles([]string{path}, writeSecret, func(f *os.File, size int64) ([]byte, error) {
		return encrypt(f, size, password)
	})
}

func decryptFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return decryptDir(path)
	}
	password, err := askPassword()
	if err != nil {
		return err
	}
	return replaceFiles([]string{path}, writePlain, func(f *os.File, size int64) ([]byte, error) {
		return decryptAuthenticated(f, size, password)
	})
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
	return replaceFiles(paths, writeSecret, func(f *os.File, size int64) ([]byte, error) {
		// A second run after an interrupted run must not encrypt a file twice.
		if _, err := decryptAuthenticated(f, size, password); err == nil {
			return nil, errAlreadyEncrypted
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		return encrypt(f, size, password)
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
	return replaceFiles(paths, writePlain, func(f *os.File, size int64) ([]byte, error) {
		return decryptAuthenticated(f, size, password)
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

// A convertFunc reads the content of f, which has size bytes, and returns the
// new content.
type convertFunc func(f *os.File, size int64) ([]byte, error)

func writePlain(w io.Writer, plain []byte) error {
	_, err := w.Write(plain)
	return err
}

// replaceFiles writes every result to a temp file before it renames any temp
// file. A failure before the first rename leaves all files unchanged.
func replaceFiles(paths []string, write func(io.Writer, []byte) error, convert convertFunc) error {
	type stagedFile struct{ tmp, path string }
	var staged []stagedFile
	defer func() {
		for _, s := range staged {
			_ = os.Remove(s.tmp)
		}
	}()
	for _, path := range paths {
		tmp, err := stageFile(path, write, convert)
		if errors.Is(err, errAlreadyEncrypted) {
			continue
		}
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

// stageFile converts the content of path and writes the result to a temp file
// next to path. It returns the name of the temp file.
func stageFile(path string, write func(io.Writer, []byte) error, convert convertFunc) (string, error) {
	in, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return "", err
	}
	// The buffers of the previous file are garbage now. Free them before a
	// large file, so that peak memory stays near the size of one file.
	if info.Size() >= 16<<20 {
		runtime.GC()
	}
	data, err := convert(in, info.Size())
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
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
	if err := f.Chmod(info.Mode().Perm()); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := write(f, data); err != nil {
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

func readPhrase() (io.Reader, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Phrase: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}
		return strings.NewReader(strings.TrimRight(line, "\r\n")), nil
	}
	return os.Stdin, nil
}

func readSecret() (io.Reader, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Secret: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}
		return strings.NewReader(line), nil
	}
	return os.Stdin, nil
}

// stdinSize returns the size of stdin if stdin is a regular file. If not, it
// returns 0.
func stdinSize() int64 {
	info, err := os.Stdin.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return 0
	}
	return info.Size()
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
