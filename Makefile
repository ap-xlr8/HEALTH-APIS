.PHONY: build dev env test coverage integration-test lint vet security sca secret-scan docker-build container-scan clean ci-local

build:
	go build -o bin/healthos-api ./cmd/api

env:
	go run ./cmd/dev-env

dev:
	go run cmd/api/main.go

test:
	go test -race -cover ./...

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
	@coverage=$$(go tool cover -func=coverage.out | awk '/^total:/ { sub(/%/, "", $$3); print $$3 }'); \
	awk -v coverage="$$coverage" 'BEGIN { if (coverage < 80) exit 1 }'

integration-test:
	RUN_TESTCONTAINERS=1 go test -race -tags=integration ./...

lint:
	golangci-lint run ./...

vet:
	go vet ./...

security:
	gosec -fmt=json -out=results.json ./...

sca:
	go list -json -deps ./... | nancy sleuth

secret-scan:
	trufflehog git file://.

docker-build:
	docker build -t healthos-backend:latest .

container-scan:
	trivy image healthos-backend:latest

clean:
	rm -rf bin coverage.out coverage.func.txt results.json

ci-local: lint vet test coverage integration-test security sca secret-scan docker-build container-scan
