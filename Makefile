export CGO_ENABLED=0

VERSION := $(shell git describe --tags --dirty --always)

GOFLAGS := -ldflags "-X main.version=$(VERSION) -buildid=" -trimpath

# os/arch pairs to build. One target builds a plain "cheesecloth"; several
# build cheesecloth-<os>-<arch>, with .exe on windows either way.
TARGETS := $(shell go env GOOS)/$(shell go env GOARCH)

GOVULNCHECK := go run golang.org/x/vuln/cmd/govulncheck@v1.7.0
GOLANGCI_LINT := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2

define build-target
GOOS=$(word 1,$(subst /, ,$(1))) GOARCH=$(word 2,$(subst /, ,$(1))) go build $(GOFLAGS) -o cheesecloth$(if $(filter-out $(1),$(TARGETS)),-$(subst /,-,$(1)))$(if $(findstring windows/,$(1)),.exe) ./cmd/cheesecloth;
endef

build:
	$(foreach t,$(TARGETS),$(call build-target,$(t)))

release: build
	sha256sum cheesecloth-* | tee cheesecloth.sha256sums

test:
	CGO_ENABLED=1 go test -race ./...

coverage:
	CGO_ENABLED=1 go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

# netns-gated tests need CAP_NET_ADMIN; a user namespace is enough for all but
# the userspace device, whose control socket lives in /var/run: see test-wg-root
test-privileged:
	CGO_ENABLED=1 unshare -r go test -race ./...

# every wireguard test, with nothing skipped: CHEESECLOTH_REQUIRE_PRIVILEGED
# turns what these tests would skip into a failure, so a run that is not
# privileged after all says so instead of passing empty. This is what CI runs.
test-wg-root:
	CHEESECLOTH_REQUIRE_PRIVILEGED=1 sudo -E "$$(command -v go)" test -count=1 ./internal/wg

# local only: GitHub's runners refuse the uid_map write unshare -r needs
coverage-privileged:
	CGO_ENABLED=1 unshare -r go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

vulncheck:
	$(GOVULNCHECK) ./...

lint:
	$(GOLANGCI_LINT) run ./...

e2e: build
	tests/e2e.sh

clean:
	rm -f cheesecloth cheesecloth.exe cheesecloth-* cheesecloth.sha256sums coverage.out

.PHONY: build release test coverage test-privileged test-wg-root coverage-privileged vulncheck lint e2e clean
