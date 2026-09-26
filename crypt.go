package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	nonceSize = 12
	tagSize   = 16
)

func deriveKey(password string) []byte {
	sum := sha256.Sum256([]byte(password))
	return sum[:]
}

func decodeSecret(blob, password string) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("password must not be empty")
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(blob))
	if err != nil {
		return nil, fmt.Errorf("secret is not valid base64")
	}
	if len(data) < nonceSize+tagSize {
		return nil, fmt.Errorf("secret is too short")
	}
	return data, nil
}

func encrypt(plaintext []byte, password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	block, err := aes.NewCipher(deriveKey(password))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if gcm.NonceSize() != nonceSize {
		return "", fmt.Errorf("unexpected nonce size")
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)
	return base64.StdEncoding.EncodeToString(out), nil
}

func decrypt(blob, password string) ([]byte, error) {
	data, err := decodeSecret(blob, password)
	if err != nil {
		return nil, err
	}
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize : len(data)-tagSize]
	block, err := aes.NewCipher(deriveKey(password))
	if err != nil {
		return nil, err
	}
	iv := make([]byte, nonceSize+4)
	copy(iv, nonce)
	iv[nonceSize+3] = 2
	plain := make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(plain, ciphertext)
	return plain, nil
}

func decryptAuthenticated(blob, password string) ([]byte, error) {
	data, err := decodeSecret(blob, password)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(deriveKey(password))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("wrong password or secret is not valid")
	}
	return plain, nil
}
