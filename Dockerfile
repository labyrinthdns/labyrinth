# Stage 1: Build React frontend
FROM node:22-alpine AS webui
WORKDIR /src/web/ui
# Install dependencies first (layer caching)
COPY web/ui/package.json web/ui/package-lock.json ./
RUN npm ci --silent
# Build the SPA
COPY web/ui/ .
RUN npm run build

# Stage 2: Build Go binary
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev
WORKDIR /src
# Cache Go modules
COPY go.mod go.sum ./
RUN go mod download
# Copy source + pre-built frontend
COPY . .
COPY --from=webui /src/web/ui/dist ./web/ui/dist
# Build statically-linked binary
RUN GO_VER=$(go version | awk '{print $3}') && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w \
      -X main.version=${VERSION} \
      -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
      -X main.goVersion=${GO_VER}" \
      -o /labyrinth .

# Stage 3: Minimal runtime image
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache ca-certificates && \
    adduser -D -H labyrinth
COPY --from=build /labyrinth /usr/local/bin/labyrinth
USER labyrinth
EXPOSE 53/udp 53/tcp 9153/tcp
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://127.0.0.1:9153/api/system/health || exit 1
ENTRYPOINT ["labyrinth"]
# Keep the compiled loopback-only dashboard default. Operators must configure
# authentication before explicitly binding and publishing the admin port.
LABEL org.opencontainers.image.source="https://github.com/labyrinthdns/labyrinth"
LABEL org.opencontainers.image.description="Pure Go Recursive DNS Resolver"
LABEL org.opencontainers.image.licenses="MIT"
