package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func encryptToString(plain []byte, password string) (string, error) {
	sealed, err := encrypt(bytes.NewReader(plain), int64(len(plain)), password)
	if err != nil {
		return "", err
	}
	var blob strings.Builder
	err = writeSecret(&blob, sealed)
	return blob.String(), err
}

func decryptString(blob, password string) ([]byte, error) {
	return decrypt(strings.NewReader(blob), int64(len(blob)), password)
}

func decryptAuthenticatedString(blob, password string) ([]byte, error) {
	return decryptAuthenticated(strings.NewReader(blob), int64(len(blob)), password)
}

func TestRoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte("hello world"),
		[]byte("zażółć gęślą jaźń"),
		[]byte{0, 1, 2, 255, 0},
		[]byte(""),
		bytes.Repeat([]byte("n"), 4096),
	}
	password := "test-password"
	for _, want := range cases {
		blob, err := encryptToString(want, password)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		got, err := decryptString(blob, password)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("round trip mismatch for %q", want)
		}
	}
}

func TestWrongPasswordReturnsGarbage(t *testing.T) {
	plain := []byte("a real secret note")
	blob, err := encryptToString(plain, "right")
	if err != nil {
		t.Fatal(err)
	}
	got, err := decryptString(blob, "wrong")
	if err != nil {
		t.Fatalf("wrong password must not error: %v", err)
	}
	if bytes.Equal(got, plain) {
		t.Fatal("wrong password returned the plaintext")
	}
}

func TestEncryptRejectsEmptyPassword(t *testing.T) {
	if _, err := encryptToString([]byte("x"), ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptRejectsEmptyPassword(t *testing.T) {
	if _, err := decryptString("AAAA", ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptRejectsInvalidBase64(t *testing.T) {
	if _, err := decryptString("!!!!", "pw"); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptRejectsShortSecret(t *testing.T) {
	blob := base64.StdEncoding.EncodeToString([]byte("too-short"))
	if _, err := decryptString(blob, "pw"); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptAuthenticatedRoundTrip(t *testing.T) {
	plain := []byte("file secret")
	blob, err := encryptToString(plain, "pw")
	if err != nil {
		t.Fatal(err)
	}
	got, err := decryptAuthenticatedString(blob, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("mismatch")
	}
}

func TestDecryptAuthenticatedWrongPassword(t *testing.T) {
	blob, err := encryptToString([]byte("file secret"), "right")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptAuthenticatedString(blob, "wrong"); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptTrimsWhitespace(t *testing.T) {
	plain := []byte("padded")
	blob, err := encryptToString(plain, "pw")
	if err != nil {
		t.Fatal(err)
	}
	got, err := decryptString("\n "+blob+" \n", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("trim failed")
	}
}

// The secret is from cis v0.2.0.
func TestDecryptsOldSecret(t *testing.T) {
	blob := "S08OKVwGZv+ZMLRsp/u0PeZY0IxcYU/cfIqhKcekHbf2oH7uKV1FjX00GfUj4qdl5w=="
	want := []byte("made by cis v0.2.0\n\x00\xff")
	got, err := decryptAuthenticatedString(blob, "fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
	got, err = decryptString(blob, "fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
}

func TestRoundTripWithWrongSizeHint(t *testing.T) {
	want := bytes.Repeat([]byte("n"), 100000)
	for _, hint := range []int64{0, 10, 1 << 20} {
		sealed, err := encrypt(bytes.NewReader(want), hint, "pw")
		if err != nil {
			t.Fatal(err)
		}
		var blob strings.Builder
		if err := writeSecret(&blob, sealed); err != nil {
			t.Fatal(err)
		}
		got, err := decryptAuthenticated(strings.NewReader(blob.String()), hint, "pw")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("round trip mismatch with size hint %d", hint)
		}
	}
}

func TestDecryptLargeSecretWithWhiteSpace(t *testing.T) {
	want := bytes.Repeat([]byte("0123456789abcdef"), 20000)
	blob, err := encryptToString(want, "pw")
	if err != nil {
		t.Fatal(err)
	}
	var wrapped strings.Builder
	for i := 0; i < len(blob); i += 76 {
		wrapped.WriteString(blob[i:min(i+76, len(blob))])
		wrapped.WriteString("\r\n")
	}
	secrets := map[string]string{
		"wrapped lines": wrapped.String(),
		"spaces around": " \t\n" + blob + " \t\n",
	}
	for name, secret := range secrets {
		got, err := decryptAuthenticatedString(secret, "pw")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: mismatch", name)
		}
	}
}

func TestDecryptRejectsLargeInvalidSecret(t *testing.T) {
	blob, err := encryptToString(bytes.Repeat([]byte("n"), 320000), "pw")
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{
		"invalid character":     blob[:100000] + "!" + blob[100001:],
		"padding in the middle": blob[:65534] + "==" + blob[65536:],
	}
	for name, secret := range secrets {
		if _, err := decryptString(secret, "pw"); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}
