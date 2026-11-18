# Build stage: cgo is required for libpcap.
FROM golang:1.26-alpine AS build
RUN apk add --no-cache gcc musl-dev libpcap-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/geoblock ./cmd/geoblock

# Runtime stage: libpcap for capture, iptables for blocking.
FROM alpine:3.22
RUN apk add --no-cache libpcap iptables ca-certificates
COPY --from=build /out/geoblock /usr/local/bin/geoblock
EXPOSE 2115
# Needs --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW to see and block
# host traffic. Mount the config at /etc/geoblock/config.json.
ENTRYPOINT ["/usr/local/bin/geoblock"]
CMD ["-config", "/etc/geoblock/config.json"]
