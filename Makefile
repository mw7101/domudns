.PHONY: all build build-arm build-dashboard build-coredns build-coredns-arm test test-unit test-integration test-acme test-auth-zones test-security lint clean run run-dev install docker-build docker-compose-up docker-compose-down

# Variables
BINARY_NAME=domudns
CLI_NAME=domudns-cli
COREDNS_NAME=coredns
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -w -s"

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Directories
BUILD_DIR=build
CMD_DIR=cmd

all: test build

# Build Next.js Dashboard und kopiere Ausgabe in internal/caddy/web/
build-dashboard:
	@echo "Building Next.js Dashboard..."
	@cd dashboard && npm ci && npm run build
	@rm -rf internal/caddy/web
	@mkdir -p internal/caddy/web
	@cp -r dashboard/out/. internal/caddy/web/
	@echo "Dashboard build complete: internal/caddy/web/"

# Build for local platform (inkl. Dashboard)
build: build-dashboard
	@echo "Building $(BINARY_NAME) for local platform..."
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)/domudns
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(CLI_NAME) ./$(CMD_DIR)/cli
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Build for ARM (Raspberry Pi 3B) — Dashboard muss vorab mit build-dashboard gebaut werden
build-arm:
	@echo "Building $(BINARY_NAME) for ARM (Raspberry Pi 3B)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 \
		$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-arm ./$(CMD_DIR)/domudns
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 \
		$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(CLI_NAME)-arm ./$(CMD_DIR)/cli
	@echo "ARM build complete: $(BUILD_DIR)/$(BINARY_NAME)-arm"
	@echo "Size: $$(du -h $(BUILD_DIR)/$(BINARY_NAME)-arm | cut -f1)"

# Build CoreDNS with postgresql plugin for local platform
build-coredns:
	@echo "Building $(COREDNS_NAME) with postgresql plugin..."
	@chmod +x scripts/build-coredns-postgresql.sh 2>/dev/null || true
	./scripts/build-coredns-postgresql.sh $(BUILD_DIR) v1.11.3 local
	@echo "Size: $$(du -h $(BUILD_DIR)/$(COREDNS_NAME) | cut -f1)"

# Build CoreDNS with postgresql plugin for ARM (Raspberry Pi 3B)
build-coredns-arm:
	@echo "Building $(COREDNS_NAME) for ARM with postgresql plugin..."
	@chmod +x scripts/build-coredns-postgresql.sh 2>/dev/null || true
	./scripts/build-coredns-postgresql.sh $(BUILD_DIR) v1.11.3 arm
	@mv $(BUILD_DIR)/$(COREDNS_NAME) $(BUILD_DIR)/$(COREDNS_NAME)-arm
	@echo "Size: $$(du -h $(BUILD_DIR)/$(COREDNS_NAME)-arm | cut -f1)"

# Run all tests (unit + integration; unit includes security via ./...)
# Integration requires: PostgreSQL, make build-coredns
test: test-unit test-integration

# Unit tests (incl. security; integration excluded by build tag)
test-unit:
	@echo "=== Unit tests ==="
	$(GOTEST) -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@echo "Coverage:"
	@$(GOCMD) tool cover -func=coverage.out 2>/dev/null | grep total || true

# Integration tests (API, zone types, ACME; needs PostgreSQL + build-coredns)
test-integration:
	@echo "=== Integration tests ==="
	$(GOTEST) -v -tags=integration -timeout=5m ./test/integration/...

# ACME DNS-01 tests (unit + integration)
test-acme: test-acme-unit test-acme-integration

test-acme-unit:
	@echo "=== ACME unit tests ==="
	$(GOTEST) -v -run TestACME ./internal/caddy/api/

test-acme-integration:
	@echo "=== ACME integration tests ==="
	$(GOTEST) -v -tags=integration -run TestACME ./test/integration/...

# Auth-zones tests (collectAuthZones, GenerateCorefileFromConfig; also run as part of test-unit)
test-auth-zones:
	@echo "=== Auth-zones unit tests ==="
	$(GOTEST) -v -run "TestCollectAuthZones|TestGenerateCorefileFromConfig" ./cmd/domudns/... ./internal/coredns/...

# Security tests (also run as part of test-unit)
test-security:
	@echo "=== Security tests ==="
	$(GOTEST) -v ./test/security/...

# Lint code
lint:
	@echo "Running linters..."
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	PATH="$$(go env GOPATH)/bin:$$PATH" golangci-lint run --timeout=5m

# Format code (goimports from GOPATH/bin if not in PATH)
fmt:
	@echo "Formatting code..."
	gofmt -s -w .
	@PATH="$$(go env GOPATH)/bin:$$PATH" goimports -w . 2>/dev/null || echo "goimports not found (optional): go install golang.org/x/tools/cmd/goimports@latest"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out *.prof

# Run locally (requires sudo for port 53)
run:
	@echo "Running $(BINARY_NAME) locally..."
	@echo "Note: Requires sudo for port 53 binding"
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)/domudns
	sudo $(BUILD_DIR)/$(BINARY_NAME) -config configs/config.yaml

# Run with dev config (port 8081 for HTTP, PostgreSQL must be running)
run-dev:
	@echo "Running $(BINARY_NAME) with dev config..."
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)/domudns
	@echo "Note: Port 53 still requires sudo. Start PostgreSQL: docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=dnsstack -e POSTGRES_DB=dnsstack postgres:16-alpine"
	sudo $(BUILD_DIR)/$(BINARY_NAME) -config configs/config.dev.yaml

# Install to system
install: build-arm build-coredns-arm
	./scripts/install.sh $(BUILD_DIR)/$(BINARY_NAME)-arm $(BUILD_DIR)/$(COREDNS_NAME)-arm

# Update dependencies
deps:
	@echo "Updating dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	$(GOMOD) verify

# Generate mocks
mocks:
	@echo "Generating mocks..."
	@which mockgen > /dev/null || (echo "Installing mockgen..." && \
		go install github.com/golang/mock/mockgen@latest)
	go generate ./...

# Profile memory
profile-mem: build
	@echo "Running memory profiler..."
	$(BUILD_DIR)/$(BINARY_NAME) -memprofile=mem.prof -config configs/config.yaml &
	@PID=$$!; sleep 30; kill $$PID
	go tool pprof -http=:8080 mem.prof

# Profile CPU
profile-cpu: build
	@echo "Running CPU profiler..."
	$(BUILD_DIR)/$(BINARY_NAME) -cpuprofile=cpu.prof -config configs/config.yaml &
	@PID=$$!; sleep 30; kill $$PID
	go tool pprof -http=:8080 cpu.prof

# Benchmark
bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

# Docker build (Multi-Stage: Node.js Dashboard + Go-Binary)
docker-build:
	@echo "Building Docker image $(BINARY_NAME):$(VERSION)..."
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(BINARY_NAME):$(VERSION) \
		-t $(BINARY_NAME):latest \
		.

docker-compose-up:
	docker compose up -d

docker-compose-down:
	docker compose down

# Deploy to Raspberry Pi
deploy: build-arm build-coredns-arm
	@echo "Deploying to Raspberry Pi..."
	@read -p "Enter Pi hostname or IP: " PI_HOST; \
	scp $(BUILD_DIR)/$(BINARY_NAME)-arm $(BUILD_DIR)/$(COREDNS_NAME)-arm $$PI_HOST:/tmp/; \
	ssh $$PI_HOST "sudo systemctl stop coredns domudns 2>/dev/null; \
		sudo cp /tmp/domudns-arm /usr/local/bin/domudns; \
		sudo cp /tmp/coredns-arm /usr/local/bin/coredns; \
		sudo chmod +x /usr/local/bin/$(BINARY_NAME) /usr/local/bin/$(COREDNS_NAME); \
		sudo systemctl start coredns domudns"
	@echo "Deployment complete"

# Git-Hooks aktivieren (einmalig pro Checkout)
setup-hooks:
	@git config core.hooksPath .githooks
	@chmod +x .githooks/pre-push
	@echo "Git hooks aktiviert (.githooks/pre-push)"
	@echo "Deaktivieren: git config --unset core.hooksPath"

# Help
help:
	@echo "Available targets:"
	@echo "  build          - Build for local platform"
	@echo "  build-arm      - Build for Raspberry Pi (ARM)"
	@echo "  test           - Run all tests (unit + integration + security)"
	@echo "  test-unit      - Unit tests only"
	@echo "  test-integration - Integration tests (needs PostgreSQL + build-coredns)"
	@echo "  test-acme       - ACME DNS-01 tests (unit + integration)"
	@echo "  test-auth-zones - Auth-zones unit tests (Backend vs Config)"
	@echo "  test-security  - Security tests only"
	@echo "  lint           - Run linters"
	@echo "  fmt            - Format code"
	@echo "  clean          - Remove build artifacts"
	@echo "  run            - Run locally (requires sudo)"
	@echo "  install        - Install to system"
	@echo "  deps           - Update dependencies"
	@echo "  mocks          - Generate mocks"
	@echo "  profile-mem    - Profile memory usage"
	@echo "  profile-cpu    - Profile CPU usage"
	@echo "  bench          - Run benchmarks"
	@echo "  docker-build       - Build Docker image (Multi-Stage)"
	@echo "  docker-compose-up  - Start via docker compose"
	@echo "  docker-compose-down - Stop via docker compose"
	@echo "  deploy         - Deploy to Raspberry Pi"
	@echo "  setup-hooks    - Git-Hooks aktivieren (pre-push)"
	@echo "  help           - Show this help"
