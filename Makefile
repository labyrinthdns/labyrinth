VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GO_VERSION ?= $(shell go version | cut -d' ' -f3)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.goVersion=$(GO_VERSION)

.PHONY: build webui test bench fuzz lint docker clean cross install

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
	go test ./... -v -count=1 -timeout 120s

bench:
	go test ./... -bench=. -benchmem -run='^$$' -timeout 120s

fuzz:
	go test ./dns/ -fuzz=FuzzUnpack -fuzztime=60s
	go test ./dns/ -fuzz=FuzzDecodeName -fuzztime=60s

lint:
	go vet ./...
	@which staticcheck > /dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed, skipping"

docker:
	docker build -t labyrinth:$(VERSION) .

clean:
	rm -f labyrinth labyrinth.exe labyrinth-*
	rm -rf web/ui/dist web/ui/node_modules
	go clean -testcache

cross: webui
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o labyrinth-linux-amd64 .
	GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o labyrinth-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o labyrinth-windows-amd64.exe .

install:
	sudo bash install.sh

uninstall:
	sudo bash uninstall.sh
