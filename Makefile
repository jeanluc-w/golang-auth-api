.PHONY: hooks tidy fmt vet vulncheck test test-integration docker-build cron ci

# Install the repo's git hooks (pre-commit: gofmt + vet + tidy + test) for
# this clone. Client-side hooks are per-clone, not per-repo, so this must be
# run once after cloning; see .githooks/pre-commit for what it checks.
hooks:
	git config core.hooksPath .githooks
	@echo "Hooks installed (core.hooksPath = .githooks)."

# Tidy go.mod/go.sum for both Go modules in this repo.
tidy:
	go mod tidy
	cd test/integration && go mod tidy

fmt:
	gofmt -w .

vet:
	go vet ./...
	cd test/integration && go vet ./...

# Scans this module's dependency tree for known vulnerabilities reachable
# from our code (govulncheck does call-graph analysis, not just version
# matching, so it doesn't flag vulnerable code we never actually call).
vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	cd test/integration && go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Fast unit tests only (main module). No Docker required.
test:
	go test ./... -race -cover

# Integration tests (test/integration module). Requires a running Docker
# daemon; spins up real Postgres + Redis containers via testcontainers-go.
test-integration:
	cd test/integration && go test ./... -v

# Builds the production image (see Dockerfile). Requires Docker.
docker-build:
	docker build -t auth-api:local .

# Runs the maintenance jobs once, against whatever DATABASE_URL (and the
# rest of the usual env) points at. This is what an external cron/CronJob
# should invoke on a schedule — see the README's "Maintenance / cron jobs"
# section. Not run automatically by anything in this repo.
cron:
	go run ./cmd/cron

# Everything CI runs, in one shot. Unlike `fmt`, this only checks formatting
# (fails on drift) rather than rewriting files.
ci: vet vulncheck
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then echo "The following files need 'make fmt':"; echo "$$out"; exit 1; fi
	go build ./...
	$(MAKE) test
	$(MAKE) test-integration
	$(MAKE) docker-build
