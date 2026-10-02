.PHONY: build test vet lint clean build-all manifest

BINARY=plugin
PLATFORMS=linux/amd64 linux/arm64 darwin/arm64
VERSION ?= $(shell git describe --tags --always 2>/dev/null | sed 's/^v//')
LDFLAGS=-s -w -X main.version=$(VERSION)

build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) .

test:
	go test ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

manifest: build
	./$(BINARY) manifest

clean:
	rm -rf $(BINARY) dist

build-all:
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%%/*} GOARCH=$${platform##*/} CGO_ENABLED=0 \
		go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-$${platform%%/*}-$${platform##*/} . || exit 1; \
	done
