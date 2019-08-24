all: build check

.PHONY: build
build:
	go build ./cmd/openapi-to-rego/...

.PHONY: check
check: check-fmt check-vet check-lint

.PHONY: check-fmt
check-fmt:
	./scripts/check-fmt.sh

.PHONY: check-vet
check-vet:
	./scripts/check-vet.sh

.PHONY: check-lint
check-lint:
	./scripts/check-lint.sh
