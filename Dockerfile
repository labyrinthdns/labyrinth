FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
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

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && \
    adduser -D -H labyrinth
COPY --from=build /labyrinth /usr/local/bin/labyrinth
USER labyrinth
EXPOSE 53/udp 53/tcp 9153/tcp
ENTRYPOINT ["labyrinth"]
LABEL org.opencontainers.image.source="https://github.com/labyrinthdns/labyrinth"
LABEL org.opencontainers.image.description="Pure Go Recursive DNS Resolver"
LABEL org.opencontainers.image.licenses="MIT"
