FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
RUN go build -ldflags="-s -w \
  -X main.version=$(git describe --tags --always 2>/dev/null || echo dev) \
  -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -X main.goVersion=$(go version | cut -d' ' -f3)" \
  -o /labyrinth .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && \
    adduser -D -H labyrinth
COPY --from=build /labyrinth /usr/local/bin/labyrinth
USER labyrinth
EXPOSE 53/udp 53/tcp 9153/tcp
ENTRYPOINT ["labyrinth"]
