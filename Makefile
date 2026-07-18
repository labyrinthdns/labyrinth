VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GO_VERSION ?= $(shell go version | cut -d' ' -f3)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.goVersion=$(GO_VERSION)

# Keep Go tooling inside repository-owned package roots. Using ./... after an
# npm install also discovers Go fixtures shipped in frontend node_modules.
GO_PACKAGES := . \
	./blocklist/... \
	./cache/... \
	./certmanager/... \
	./cmd/... \
	./config/... \
	./daemon/... \
	./dns/... \
	./dnssec/... \
	./internal/... \
	./log/... \
	./metrics/... \
	./resolver/... \
	./security/... \
	./server/... \
	./web \
	./xfr/...

.PHONY: build build-go webui test test-race soak bench fuzz lint vet check-go-package-scope docker clean cross install uninstall

# Build frontend then Go binary
build: webui
	go build -ldflags="$(LDFLAGS)" -o labyrinth .

# Build Go binary only (skip frontend)
build-go:
	go build -ldflags="$(LDFLAGS)" -o labyrinth .

# Build React frontend
webui:
	cd web/ui && npm ci --silent && npm run build

test:
	go test $(GO_PACKAGES) -v -count=1 -timeout 120s

test-race:
	go test $(GO_PACKAGES) -count=1 -race -timeout 180s

soak:
	go test -tags soak ./test/soak/ -run TestSoak -timeout 72h -v

bench:
	go test $(GO_PACKAGES) -bench=. -benchmem -run='^$' -timeout 120s

fuzz:
	go test ./dns/ -fuzz=FuzzUnpack -fuzztime=60s
	go test ./dns/ -fuzz=FuzzDecodeName -fuzztime=60s

lint:
	@if command -v golangci-lint > /dev/null 2>&1; then \
		golangci-lint run $(GO_PACKAGES); \
	else \
		go vet $(GO_PACKAGES); \
		if command -v staticcheck > /dev/null 2>&1; then staticcheck $(GO_PACKAGES); fi; \
	fi

vet:
	go vet $(GO_PACKAGES)

check-go-package-scope:
	@packages="$$(go list $(GO_PACKAGES))"; \
	! printf '%s\n' "$$packages" | grep -F '/node_modules/' || { \
		echo "first-party Go package selection included node_modules" >&2; \
		exit 1; \
	}

docker:
	docker build -t labyrinth:$(VERSION) .

clean:
	rm -f labyrinth labyrinth.exe labyrinth-*
	rm -rf web/ui/dist web/ui/node_modules
	go clean -testcache

cross: webui
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o labyrinth-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o labyrinth-linux-arm64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o labyrinth-darwin-amd64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o labyrinth-darwin-arm64 .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o labyrinth-windows-amd64.exe .
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o labyrinth-bench-linux-amd64 ./cmd/labyrinth-bench/
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o labyrinth-bench-linux-arm64 ./cmd/labyrinth-bench/
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o labyrinth-bench-darwin-amd64 ./cmd/labyrinth-bench/
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o labyrinth-bench-darwin-arm64 ./cmd/labyrinth-bench/
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o labyrinth-bench-windows-amd64.exe ./cmd/labyrinth-bench/

install:
	sudo bash install.sh

uninstall:
	sudo bash uninstall.sh
