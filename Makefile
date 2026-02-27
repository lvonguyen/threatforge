.PHONY: build run test test-coverage lint fmt vet docker-build docker-up docker-down docker-logs clean dev-setup help

# Variables
BINARY_NAME=threatforge
GO=go
DOCKER_COMPOSE=docker-compose

# Default target
help:
	@echo "ThreatForge - AI-Powered Threat Intelligence Platform"
	@echo ""
	@echo "Usage:"
	@echo "  make build          Build the binary"
	@echo "  make run            Run locally"
	@echo "  make test           Run tests"
	@echo "  make test-coverage  Run tests with coverage report"
	@echo "  make lint           Run linter"
	@echo "  make fmt            Format code"
	@echo "  make vet            Run go vet"
	@echo "  make docker-build   Build Docker image"
	@echo "  make docker-up      Start all services with Docker Compose"
	@echo "  make docker-down    Stop all services"
	@echo "  make docker-logs    Stream service logs"
	@echo "  make clean          Remove build artifacts"
	@echo "  make dev-setup      Install dependencies and tools"

# Build binary
build:
	$(GO) build -o bin/$(BINARY_NAME) ./cmd/server

# Run locally
run:
	$(GO) run ./cmd/server

# Run tests
test:
	$(GO) test -v ./...

# Run tests with coverage
test-coverage:
	$(GO) test -v -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

# Lint code
lint:
	golangci-lint run

# Format code
fmt:
	$(GO) fmt ./...
	gofmt -s -w .

# Vet code
vet:
	$(GO) vet ./...

# Build Docker image
docker-build:
	docker build -t $(BINARY_NAME):latest .

# Start all services (Redis + app)
docker-up:
	$(DOCKER_COMPOSE) up -d

# Stop all services
docker-down:
	$(DOCKER_COMPOSE) down

# Stream logs
docker-logs:
	$(DOCKER_COMPOSE) logs -f

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Development setup
dev-setup:
	$(GO) mod download
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
