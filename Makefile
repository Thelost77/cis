.PHONY: build install test vet clean

BINARY := cis
INSTALL_DIR ?= $(HOME)/.local/bin

build:
	go build -o $(BINARY) .

install: build
	install -m 0755 $(BINARY) $(INSTALL_DIR)/$(BINARY)

test:
	go test ./... -count=1
	go vet ./...

clean:
	rm -f $(BINARY)
