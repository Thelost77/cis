# cis

`cis` encrypts and decrypts notes and files.

The name is the Polish word for the yew tree.

The tool hashes the password with SHA-256. It uses the hash as an AES-256 key.
The tool then encodes the result in Base64.

## Features

- Encrypt a short note and print a Base64 secret
- Decrypt a Base64 secret and print the note
- Replace a file in place
- Ask for the password. Do not take the password as an argument
- Keep the original file mode
- Leave a file unchanged when the password is wrong
- No external runtime dependencies

## Requirements

- Go 1.26 or newer when you install from source
- Linux or macOS

## Installation

Make sure that the Go binary directory is in PATH. The usual path is `~/go/bin`.

Install the latest release:

```sh
go install github.com/Thelost77/cis@latest
```

Install a specific release:

```sh
go install github.com/Thelost77/cis@v0.1.0
```

From a checkout, use `go build -o cis .`.

## Use

The tool asks for the password. Do not put the password in the command.

Encrypt a short note:

```sh
cis enc
```

The tool asks for the phrase. The tool then prints a Base64 secret.

Decrypt a short note:

```sh
cis dec
```

The tool asks for the secret. The tool then prints the phrase.

Encrypt a file in place:

```sh
cis enc notes.txt
```

The tool replaces `notes.txt` with the Base64 secret.

Decrypt a file in place:

```sh
cis dec notes.txt
```

The tool replaces `notes.txt` with the original text.

Pipe a note:

```sh
pbpaste | cis enc
cis dec < secret.txt
```

Show help or the version:

```sh
cis --help
cis --version
```

## Behavior

- `cis enc` and `cis dec` with a file replace that file.
- A wrong password on a file does not change the file.
- A wrong password on a printed secret prints data that is not the original text.
- The tool keeps the original file mode.
- The tool hides notes from casual view. It does not stop a person who tries many passwords.

## License

MIT. See [LICENSE](LICENSE).
