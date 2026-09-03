BINARY  := serverok
PKG     := ./cmd/serverok
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
DIST    := dist

# Platforms shipped in a release. Keep in sync with .github/workflows/release.yml.
PLATFORMS := \
	linux/amd64 linux/arm64 linux/386 linux/arm \
	darwin/amd64 darwin/arm64 \
	freebsd/amd64

.PHONY: all build install test vet fmt lint run clean build-all checksums

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

install:
	CGO_ENABLED=0 go install -trimpath -ldflags "$(LDFLAGS)" $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

lint: fmt vet test

run: build
	./$(BINARY)

build-all: clean
	@mkdir -p $(DIST)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		out=$(DIST)/$(BINARY)_$${os}_$${arch}; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o $$out/$(BINARY) $(PKG) || exit 1; \
		tar -czf $(DIST)/$(BINARY)_$${os}_$${arch}.tar.gz -C $$out $(BINARY); \
		rm -rf $$out; \
	done
	@$(MAKE) checksums

checksums:
	@cd $(DIST) && (sha256sum *.tar.gz > checksums.txt 2>/dev/null || shasum -a 256 *.tar.gz > checksums.txt)
	@echo "artifacts in $(DIST)/"

clean:
	rm -rf $(DIST) $(BINARY)
