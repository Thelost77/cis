package main

import (
	"bytes"
	"encoding/base64"
	"testing"
)

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
		blob, err := encrypt(want, password)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		got, err := decrypt(blob, password)
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
	blob, err := encrypt(plain, "right")
	if err != nil {
		t.Fatal(err)
	}
	got, err := decrypt(blob, "wrong")
	if err != nil {
		t.Fatalf("wrong password must not error: %v", err)
	}
	if bytes.Equal(got, plain) {
		t.Fatal("wrong password returned the plaintext")
	}
}

func TestEncryptRejectsEmptyPassword(t *testing.T) {
	if _, err := encrypt([]byte("x"), ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptRejectsEmptyPassword(t *testing.T) {
	if _, err := decrypt("AAAA", ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptRejectsInvalidBase64(t *testing.T) {
	if _, err := decrypt("!!!!", "pw"); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptRejectsShortSecret(t *testing.T) {
	blob := base64.StdEncoding.EncodeToString([]byte("too-short"))
	if _, err := decrypt(blob, "pw"); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptAuthenticatedRoundTrip(t *testing.T) {
	plain := []byte("file secret")
	blob, err := encrypt(plain, "pw")
	if err != nil {
		t.Fatal(err)
	}
	got, err := decryptAuthenticated(blob, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("mismatch")
	}
}

func TestDecryptAuthenticatedWrongPassword(t *testing.T) {
	blob, err := encrypt([]byte("file secret"), "right")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptAuthenticated(blob, "wrong"); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptTrimsWhitespace(t *testing.T) {
	plain := []byte("padded")
	blob, err := encrypt(plain, "pw")
	if err != nil {
		t.Fatal(err)
	}
	got, err := decrypt("\n "+blob+" \n", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("trim failed")
	}
}
