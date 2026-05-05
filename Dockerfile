FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1 AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w \
  -X main.version=${VERSION} \
  -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -X 'main.goVersion=$(go version | cut -d\" \" -f3)'" \
  -o /labyrinth .

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache ca-certificates && \
    adduser -D -H labyrinth
COPY --from=build /labyrinth /usr/local/bin/labyrinth
USER labyrinth
EXPOSE 53/udp 53/tcp 9153/tcp
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://localhost:9153/metrics || exit 1
ENTRYPOINT ["labyrinth"]
LABEL org.opencontainers.image.source="https://github.com/labyrinthdns/labyrinth"
LABEL org.opencontainers.image.description="Pure Go Recursive DNS Resolver"
LABEL org.opencontainers.image.licenses="MIT"
