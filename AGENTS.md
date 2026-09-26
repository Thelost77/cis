# cis

`cis` encrypts and decrypts notes and files.

## Checks

```sh
go test ./...
go test -race ./...
go vet ./...
gofmt -d .
```

## Design

- Keep the CLI small. Use the Go standard library plus `golang.org/x/term`.
- Hash the password with SHA-256. Use the hash as an AES-256 key.
- Encode secrets in Base64.
- Replace a file in place with a temp file and rename.
- Keep the original file mode.
- Do not change a file when the password is wrong.
- Ask for the password. Do not take the password as an argument.
- Write errors to stderr and return non-zero.
