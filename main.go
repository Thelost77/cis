package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"golang.org/x/term"
)

const version = "dev"

var askPassword = readPassword

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

func replaceFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".cis-*")
	if err != nil {
		return err
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
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
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
Usage: cis enc [file]
       cis dec [file]

enc encrypts a note or replaces a file in place.
dec decrypts a note or replaces a file in place.

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
