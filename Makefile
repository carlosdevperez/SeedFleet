# Simple build and verification targets for SeedFleet.

REPO_ROOT := $(CURDIR)
OUT_DIR := $(REPO_ROOT)/bin
SEEDFLEET := $(OUT_DIR)/seedfleet

GO_BUILD_FLAGS ?= -trimpath

.PHONY: all build clean fmt test race bench verify

all: build

build:
	mkdir -p "$(OUT_DIR)"
	go build $(GO_BUILD_FLAGS) -o "$(SEEDFLEET)" ./cmd/seedfleet

clean:
	rm -rf "$(OUT_DIR)"

fmt:
	find . -name '*.go' -type f -print0 | xargs -0 gofmt -s -w

test:
	go test ./...

race:
	go test -race ./...

bench:
	go test -run '^$$' -bench . -benchmem ./pkg/fleet/internal/scanner

verify:
	test -z "$$(gofmt -s -l .)"
	sh -n pkg/fleet/internal/dockerinstaller/install.sh
	go vet ./...
	go test ./...
