BINARY := threat-service
IMAGE  ?= threat-assessment-service:latest

.PHONY: generate build run test integration-test lint docker-build

generate: ## Regenerate protobuf Go code from api/
	go generate ./...

build: ## Build the binary
	go build -o bin/$(BINARY) ./cmd/threat-service

run: ## Run the server locally
	go run ./cmd/threat-service

test: ## Run all tests
	go test ./...

integration-test: build ## Run grpcurl-based integration tests
	./test/integration/run.sh

lint: ## Run go vet
	go vet ./...

docker-build: ## Build the Docker image
	docker build -t $(IMAGE) .

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'
