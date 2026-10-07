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
	./secondary/... \
	./security/... \
	./server/... \
	./test/... \
	./web \
	./xfr/...

.PHONY: build build-go webui test test-race check-web-race-tests soak bench fuzz lint vet check-go-package-scope docker clean cross install uninstall

# Parallelism caps for ~8 GiB hosts and GitHub runners. Race builds roughly
# double RSS; unrestricted package parallelism OOMs the box (exit 143 /
# soft lockup / go test exit 2 "build failed"). Plain tests at -p 2 still
# peaked enough on ubuntu-latest to kill compile of server/web — keep -p 1.
# Override with e.g. `make test GO_TEST_P=2` if you have RAM.
GO_BUILD_P ?= 1
GO_TEST_P  ?= 1
GO_RACE_P  ?= 1
GO_LINT_P  ?= 2

# Packages worth the race-detector cost. Full-tree -race compile is what
# freezes the DNS host and kills CI; keep the hot path covered, rest via
# plain `make test`.
GO_RACE_PACKAGES := ./dns/... ./dnssec/... ./resolver/... ./cache/... ./server/... ./security/...

# ./web runs race-scoped rather than whole-package: it is the only package
# with 450+ tests, and instrumenting all of them buys little. The filter keeps
# the concurrency-shaped families — WebSocket streaming, ticker, JWT-secret
# rotation, login limiter, clientNum heap — which are the ones able to observe
# a race; the rest run under plain `make test`.
#
# Measured on this host, same binary, -test.parallel=1 pinned (as the lane runs):
#   whole ./web, GOMAXPROCS=1          563.6s
#   scoped,       GOMAXPROCS=1          522.9s
#   scoped,       GOMAXPROCS=WEB_RACE_P  43.2s
# So the filter is worth ~40s; GOMAXPROCS is worth ~480s. Peak RSS went DOWN
# with it (1076MB -> 877MB), so this is not a time-for-memory trade.
#
# GOMAXPROCS is raised but -parallel stays at 1 deliberately: several scoped
# tests assert wall-clock ratios (TestClientNumEvictionCostIsIndependentOfMapSize
# gates at 3.0x), and running them concurrently is what would make them flaky.
# Parallel runtime, serial tests.
WEB_RACE_TESTS := Atomic|Race|Concurren|QueryStreamWS|TimeSeriesWS|WSReadLimit|JWTSecret|LoginLimiter|HandleLogin_|ClientNumEviction|RecordQuery_|DiagnosticTrace|UpdateChecker_Ticker
WEB_RACE_P ?= 4

# Floor for the -run filter above. A regex that stops matching — because a
# test was renamed, or because of a typo — would let the ./web race lane pass
# in seconds having run ZERO tests. That is the same silent-pass shape as
# `make lint` falling back to `go vet`, so this makes it loud instead.
# Current match is 46; the floor sits below that so adding tests cannot trip
# it, while deleting enough of them must be noticed.
WEB_RACE_MIN ?= 40

# Build frontend then Go binary
build: webui
	go build -p $(GO_BUILD_P) -ldflags="$(LDFLAGS)" -o labyrinth .

# Build Go binary only (skip frontend)
build-go:
	go build -p $(GO_BUILD_P) -ldflags="$(LDFLAGS)" -o labyrinth .

# Build React frontend
webui:
	cd web/ui && npm ci --silent && npm run build

# SHORT=1 skips network EndToEnd tests (server/server_test.go). CI sets this
# so ubuntu-latest outbound UDP flakes don't fail the suite. Local default is
# full coverage; use `make test SHORT=1` for a fast offline run.
SHORT ?=
SHORT_FLAG := $(if $(SHORT),-short,)

test:
	go test -p $(GO_TEST_P) $(GO_PACKAGES) -count=1 -timeout 10m $(SHORT_FLAG)

test-integration:
	$(MAKE) test SHORT=

# Fails the lane if the -run filter matches too few ./web tests, rather than
# letting the race run succeed having executed nothing.
check-web-race-tests:
	@echo "checking WEB_RACE_TESTS matches >= $(WEB_RACE_MIN) tests in ./web"
	@n=`go test -list '$(WEB_RACE_TESTS)' ./web 2>/dev/null | grep -c '^Test' || true`; \
	if [ "$$n" -lt "$(WEB_RACE_MIN)" ]; then \
		echo "FAIL: WEB_RACE_TESTS matches $$n test(s) in ./web, expected >= $(WEB_RACE_MIN)." >&2; \
		echo "      The ./web race lane would pass without exercising anything." >&2; \
		echo "      Widen WEB_RACE_TESTS, or lower WEB_RACE_MIN deliberately." >&2; \
		exit 1; \
	fi; \
	echo "  ok: $$n tests match"

test-race: check-web-race-tests
	# Serial packages (-p 1) + low GOMAXPROCS: one race-instrumented compile
	# at a time. Still covers the concurrency-critical packages.
	GOMAXPROCS=$(GO_RACE_P) go test -p $(GO_RACE_P) -parallel $(GO_RACE_P) \
		$(GO_RACE_PACKAGES) -count=1 -race -timeout 15m $(SHORT_FLAG)
	# ./web second, scoped, and with a wider runtime: the scoped set costs
	# ~43s at GOMAXPROCS=$(WEB_RACE_P) versus ~523s at the lane's
	# GOMAXPROCS=$(GO_RACE_P). -parallel stays at $(GO_RACE_P) (1) so the
	# wall-clock-ratio tests keep running serially. The other ~405 ./web
	# tests run under plain `make test`, which still covers ./web in full.
	# See WEB_RACE_TESTS / WEB_RACE_P.
	GOMAXPROCS=$(WEB_RACE_P) go test -p $(GO_RACE_P) -parallel $(GO_RACE_P) \
		./web -run '$(WEB_RACE_TESTS)' -count=1 -race -timeout 15m $(SHORT_FLAG)

soak:
	go test -tags soak ./test/soak/ -run TestSoak -timeout 72h -v

bench:
	go test -p $(GO_TEST_P) $(GO_PACKAGES) -bench=. -benchmem -run='^$$' -timeout 120s

fuzz:
	go test ./dns/ -fuzz=FuzzUnpack -fuzztime=60s
	go test ./dns/ -fuzz=FuzzDecodeName -fuzztime=60s

lint:
	@if command -v golangci-lint > /dev/null 2>&1; then \
		golangci-lint run --concurrency=$(GO_LINT_P) $(GO_PACKAGES); \
	else \
		go vet -p $(GO_BUILD_P) $(GO_PACKAGES); \
		if command -v staticcheck > /dev/null 2>&1; then staticcheck $(GO_PACKAGES); fi; \
	fi

vet:
	go vet -p $(GO_BUILD_P) $(GO_PACKAGES)

check-go-package-scope:
	@packages="$$(go list $(GO_PACKAGES))" || exit 1; \
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
