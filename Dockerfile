# Stage 1: Next.js Dashboard bauen
# Exakter Node-Pin statt Floating-Tag: Node 20 ist EOL und bekommt keine
# Sicherheitsfixes mehr — u. a. nicht für CVE-2026-111497 (Out-of-Bounds-Write im
# gebündelten Brotli-Decoder); 22.23.4 ist der Release mit diesem Fix. Die Stage
# liegt nicht im Runtime-Image (nur die daraus gebauten statischen Assets in
# internal/caddy/web), aber `npm ci` dekodiert hier Registry-Antworten — das soll
# nicht mit einer ungepatchten Toolchain passieren. Pin hier und in
# .gitlab-ci.yml (NODE_IMAGE) gemeinsam hochziehen.
FROM node:22.23.4-alpine AS dashboard-builder
WORKDIR /app/dashboard
COPY dashboard/package*.json ./
RUN npm ci --prefer-offline
COPY dashboard/ ./
RUN npm run build

# Stage 2: Go-Binary bauen
# Exakter Toolchain-Pin (passend zu `go 1.27.3` in go.mod und GO_IMAGE in
# .gitlab-ci.yml): die alte 1.24-Linie bekommt keine Security-Releases mehr und
# baute eine Standardbibliothek mit bekannten CVEs (net/http, http2, crypto/tls,
# crypto/x509, html/template, mime/multipart) direkt ins ausgelieferte Binary.
FROM golang:1.27.3-alpine AS go-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Dashboard-Output in embed.FS-Pfad kopieren (internal/caddy/web/)
COPY --from=dashboard-builder /app/dashboard/out ./internal/caddy/web/
ARG VERSION=dev
ARG BUILD_TIME
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}" \
    -o /domudns ./cmd/domudns

# Stage 3: Minimales Runtime-Image
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=go-builder /domudns /usr/local/bin/domudns
RUN mkdir -p /var/lib/domudns/data /etc/domudns
EXPOSE 53/udp 53/tcp 80/tcp 853/tcp 9090/tcp
VOLUME ["/var/lib/domudns/data", "/etc/domudns"]
ENTRYPOINT ["/usr/local/bin/domudns"]
CMD ["-config", "/etc/domudns/config.yaml"]
