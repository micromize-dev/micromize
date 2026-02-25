TAG := $(shell git describe --tags --always --dirty)
CONTAINER_REPO ?= ghcr.io/micromize-dev/micromize
IMAGE_TAG ?= $(TAG)
CLANG_FORMAT ?= clang-format
OUTPUT_DIR := dist
GOARCHS := amd64 arm64
LDFLAGS := -X github.com/inspektor-gadget/inspektor-gadget/internal/version.version=v0.47.0 \
           -X main.Version=$(IMAGE_TAG) \
           -w -s -extldflags "-static"
GADGETS := fs-restrict cap-restrict ptrace-restrict binary-attestation
CONFORM_VERSION ?= v0.1.0-alpha.30

# This version number must be kept in sync with CI workflow lint one.
LINTER_IMAGE ?= golangci/golangci-lint:v2.10.1

.PHONY: setup-hooks
setup-hooks:
	go install github.com/siderolabs/conform/cmd/conform@$(CONFORM_VERSION)
	git config core.hooksPath .githooks
	@echo "Git hooks installed. Commit messages must follow the conventional commit format to pass CI."

.PHONY: license-check
license-check:
	@go run github.com/google/addlicense@v1.2.0 -check -l apache -c "The micromize authors" \
		$$(find . -name '*.go' -not -path './build/*')

.PHONY: license-add
license-add:
	@go run github.com/google/addlicense@v1.2.0 -y "" -l apache -c "The micromize authors" \
		$$(find . -name '*.go' -not -path './build/*')

.PHONY: lint
lint:
	docker build -t linter -f Dockerfiles/linter.Dockerfile --build-arg IMAGE=$(LINTER_IMAGE) Dockerfiles
	# XDG_CACHE_HOME is necessary to avoid this type of errors:
	# ERRO Running error: context loading failed: failed to load packages: failed to load with go/packages: err: exit status 1: stderr: failed to initialize build cache at /.cache/go-build: mkdir /.cache: permission denied
	# Process 15167 has exited with status 3
	# While GOLANGCI_LINT_CACHE is used to store golangci-lint cache.
	docker run --rm --env XDG_CACHE_HOME=/tmp/xdg_home_cache \
		--env GOLANGCI_LINT_CACHE=/tmp/golangci_lint_cache \
		--user $(shell id -u):$(shell id -g) -v $(shell pwd):/app -w /app \
		linter

.PHONY: clean
clean:
	rm -rf $(OUTPUT_DIR) build/src build/gadgets

.PHONY: build-all
build-all: $(GADGETS) build-app

.PHONY: test
test:
	go test ./...

.PHONY: build-gadgets
build-gadgets: $(GADGETS)

.PHONY: build-app
build-app: test $(GOARCHS)

$(GADGETS):
	sudo -E IG_SOURCE_PATH=$(CURDIR) ig image build \
		-t $(CONTAINER_REPO)/$@:$(IMAGE_TAG) \
		--update-metadata gadgets/$@
	
	mkdir -p build/gadgets
	
	sudo -E ig image export $(CONTAINER_REPO)/$@:$(IMAGE_TAG) build/gadgets/$@.tar

$(GOARCHS):
	@mkdir -p $(OUTPUT_DIR)
	@mkdir -p build/src
	
	# Copy source to build/src
	cp -r cmd internal go.mod go.sum build/src/
	
	# Copy gadgets to where main.go expects them
	mkdir -p build/src/cmd/micromize/build
	cp build/gadgets/*.tar build/src/cmd/micromize/build/
	
	# Build
	cd build/src && GOOS=linux GOARCH=$@ CGO_ENABLED=0 go build -tags release -ldflags "$(LDFLAGS)" -o ../../$(OUTPUT_DIR)/micromize-linux-$@ ./cmd/micromize

.PHONY: run-fs-restrict
run-fs-restrict:
	sudo -E ig run $(CONTAINER_REPO)/fs-restrict:$(IMAGE_TAG) $$PARAMS

.PHONY: run-cap-restrict
run-cap-restrict:
	sudo -E ig run $(CONTAINER_REPO)/cap-restrict:$(IMAGE_TAG) $$PARAMS

.PHONY: push
push:
	for gadget in $(GADGETS); do \
		sudo -E ig image push $(CONTAINER_REPO)/$$gadget:$(IMAGE_TAG); \
	done
	
.PHONY: clang-format
clang-format:
	$(CLANG_FORMAT) -i gadgets/*/*.bpf.c gadgets/*/*.bpf.h

# Dev deploy configuration
DEV_REGISTRY ?=
DEV_TAG ?= dev
DEV_NAMESPACE ?= micromize
DEV_HELM_ARGS ?=

.PHONY: dev-build
dev-build: ## Build Docker image for dev deployment
ifeq ($(strip $(DEV_REGISTRY)),)
	$(error DEV_REGISTRY is required. Set it via environment or argument: make dev-build DEV_REGISTRY=myacr.azurecr.io)
endif
	docker build --no-cache -t $(DEV_REGISTRY)/micromize:$(DEV_TAG) .

.PHONY: dev-push
dev-push: ## Push dev image to registry
ifeq ($(strip $(DEV_REGISTRY)),)
	$(error DEV_REGISTRY is required. Set it via environment or argument: make dev-push DEV_REGISTRY=myacr.azurecr.io)
endif
	docker push $(DEV_REGISTRY)/micromize:$(DEV_TAG)

.PHONY: dev-deploy
dev-deploy: ## Deploy to K8s cluster via Helm (assumes image already pushed)
ifeq ($(strip $(DEV_REGISTRY)),)
	$(error DEV_REGISTRY is required. Set it via environment or argument: make dev-deploy DEV_REGISTRY=myacr.azurecr.io)
endif
	helm upgrade --install micromize ./charts/micromize \
		-n $(DEV_NAMESPACE) --create-namespace \
		--set image.repository=$(DEV_REGISTRY)/micromize \
		--set image.tag=$(DEV_TAG) \
		--set image.pullPolicy=Always \
		--set logLevel=debug \
		--set filterNamespaces="default\,dev" \
		$(DEV_HELM_ARGS)
	kubectl rollout restart daemonset micromize -n $(DEV_NAMESPACE)
	kubectl rollout status daemonset micromize -n $(DEV_NAMESPACE) --timeout=120s

.PHONY: dev
dev: dev-build dev-push dev-deploy ## Build, push, and deploy to dev cluster

.PHONY: dev-logs
dev-logs: ## Tail logs from all dev pods
	kubectl logs -n $(DEV_NAMESPACE) -l app.kubernetes.io/name=micromize -f --prefix --all-containers

.PHONY: dev-status
dev-status: ## Show dev pod status
	kubectl get pods -n $(DEV_NAMESPACE) -l app.kubernetes.io/name=micromize -o wide

IG_VERSION ?= v0.49.1
IG_ARCHIVE_SHA256 ?= 1cc186b4ebe476da9c89b6ff2f38234b13d4eae3d2a3b597b3647393c2a223c0
SKIP_CHECKSUM ?= 0
.PHONY: update-includes
update-includes:
	@set -e; \
	rm -rf include/gadget; \
	mkdir -p include/gadget; \
	TMP_TAR=$$(mktemp); \
	echo "Downloading inspektor-gadget@$(IG_VERSION)..."; \
	curl -fsSL "https://github.com/inspektor-gadget/inspektor-gadget/archive/$(IG_VERSION).tar.gz" -o "$$TMP_TAR" || \
		{ echo "Error: failed to download archive for $(IG_VERSION)" >&2; rm -f "$$TMP_TAR"; exit 1; }; \
	if [ "$(SKIP_CHECKSUM)" = "0" ] && [ -n "$(IG_ARCHIVE_SHA256)" ]; then \
		echo "$(IG_ARCHIVE_SHA256)  $$TMP_TAR" | sha256sum -c - || \
			{ echo "Error: checksum verification failed" >&2; rm -f "$$TMP_TAR"; exit 1; }; \
	else \
		echo "Skipping checksum verification"; \
	fi; \
	tar -xzf "$$TMP_TAR" --strip-components=3 --wildcards -C include/gadget "*/include/gadget" || \
		{ echo "Error: failed to extract archive" >&2; rm -f "$$TMP_TAR"; exit 1; }; \
	rm -f "$$TMP_TAR"; \
	if ! find include/gadget -type f | grep -q .; then \
		echo "Error: include/gadget is empty after extraction" >&2; exit 1; \
	fi; \
	echo "Updated include/gadget from inspektor-gadget@$(IG_VERSION)"
