package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

const (
	nonceSize = 12
	tagSize   = 16
)

func deriveKey(password string) []byte {
	sum := sha256.Sum256([]byte(password))
	return sum[:]
}

// spaceFilter removes ASCII white space from a stream.
type spaceFilter struct{ r io.Reader }

func (f spaceFilter) Read(p []byte) (int, error) {
	for {
		n, err := f.r.Read(p)
		kept := 0
		for _, c := range p[:n] {
			switch c {
			case ' ', '\t', '\n', '\v', '\f', '\r':
			default:
				p[kept] = c
				kept++
			}
		}
		if kept > 0 || err != nil || len(p) == 0 {
			return kept, err
		}
	}
}

// decodeSecret reads a Base64 secret from r and returns the nonce, the
// ciphertext, and the tag. sizeHint is the expected size of the Base64 text.
func decodeSecret(r io.Reader, sizeHint int64, password string) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("password must not be empty")
	}
	var data []byte
	chunk := make([]byte, 1<<16)
	out := make([]byte, base64.StdEncoding.DecodedLen(len(chunk)))
	filtered := false
	for last := false; !last; {
		n, err := io.ReadFull(r, chunk)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			last = true
		} else if err != nil {
			return nil, err
		}
		m, err := base64.StdEncoding.Decode(out, chunk[:n])
		// A chunk that is not the last one has no padding, so it decodes to
		// n/4*3 bytes. White space in the chunk breaks this rule.
		if err != nil || (!last && m != n/4*3) {
			if filtered {
				return nil, fmt.Errorf("secret is not valid base64")
			}
			// The filter is slow. Use it only from the first chunk that
			// does not decode.
			r = spaceFilter{io.MultiReader(bytes.NewReader(bytes.Clone(chunk[:n])), r)}
			filtered, last = true, false
			continue
		}
		if data == nil {
			// Allocate after the first chunk decodes. Then input that is not
			// a secret uses no memory for the result.
			data = make([]byte, 0, max(base64.StdEncoding.DecodedLen(int(sizeHint)), m))
		}
		data = append(data, out[:m]...)
	}
	if len(data) < nonceSize+tagSize {
		return nil, fmt.Errorf("secret is too short")
	}
	return data, nil
}

// encrypt reads the plaintext from r and encrypts it in place. It returns the
// nonce, the ciphertext, and the tag. sizeHint is the expected size of the
// plaintext.
func encrypt(r io.Reader, sizeHint int64, password string) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("password must not be empty")
	}
	block, err := aes.NewCipher(deriveKey(password))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if gcm.NonceSize() != nonceSize {
		return nil, fmt.Errorf("unexpected nonce size")
	}
	// The buffer has room for the nonce, the plaintext, and the tag, so that
	// Seal encrypts in place. MinRead prevents a second allocation in ReadFrom.
	buf := bytes.NewBuffer(make([]byte, nonceSize, nonceSize+sizeHint+tagSize+bytes.MinRead))
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, err
	}
	nonce, plaintext := buf.Bytes()[:nonceSize], buf.Bytes()[nonceSize:]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// writeSecret writes sealed to w as one line of Base64.
func writeSecret(w io.Writer, sealed []byte) error {
	bw := bufio.NewWriterSize(w, 1<<16)
	enc := base64.NewEncoder(base64.StdEncoding, bw)
	if _, err := enc.Write(sealed); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	if err := bw.WriteByte('\n'); err != nil {
		return err
	}
	return bw.Flush()
}

// decrypt reads a secret from r and decrypts it in place. It does not check
// the tag.
func decrypt(r io.Reader, sizeHint int64, password string) ([]byte, error) {
	data, err := decodeSecret(r, sizeHint, password)
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
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

// decryptAuthenticated reads a secret from r, checks the tag, and decrypts
// the secret in place.
func decryptAuthenticated(r io.Reader, sizeHint int64, password string) ([]byte, error) {
	data, err := decodeSecret(r, sizeHint, password)
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
	ciphertext := data[nonceSize:]
	plain, err := gcm.Open(ciphertext[:0], data[:nonceSize], ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("wrong password or secret is not valid")
	}
	return plain, nil
}
