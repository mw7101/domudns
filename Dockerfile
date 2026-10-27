# Stage 1: Next.js Dashboard bauen
FROM node:20-alpine AS dashboard-builder
WORKDIR /app/dashboard
COPY dashboard/package*.json ./
RUN npm ci --prefer-offline
COPY dashboard/ ./
RUN npm run build

# Stage 2: Go-Binary bauen
FROM golang:1.24-alpine AS go-builder
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
