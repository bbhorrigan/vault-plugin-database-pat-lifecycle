TOOL = vault-plugin-secrets-snowflakepat
TEST = $$(go list ./...)

default: build

build:
	CGO_ENABLED=0 go build -o bin/$(TOOL) ./cmd/$(TOOL)

test:
	CGO_ENABLED=0 go test -v -count=1 -timeout=20m $(TEST)

testacc:
	CGO_ENABLED=0 VAULT_ACC=1 go test -v -count=1 -timeout=20m $(TEST)

vet:
	go vet ./...

fmt:
	gofmt -w .

.PHONY: build test testacc vet fmt
