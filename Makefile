TAG := $(shell git describe --tags --always --dirty)
CONTAINER_REPO ?= ghcr.io/dorser/micromize
IMAGE_TAG ?= $(TAG)
CLANG_FORMAT ?= clang-format
OUTPUT_DIR := dist
GOARCHS := amd64 arm64
LDFLAGS := -X github.com/inspektor-gadget/inspektor-gadget/internal/version.version=v0.46.0 \
           -X main.Version=$(IMAGE_TAG) \
           -w -s -extldflags "-static"
GADGETS := fs-restrict kmod-restrict

.PHONY: build-all
build-all: $(GADGETS) $(GOARCHS)

.PHONY: build-gadgets
build-gadgets: $(GADGETS)

.PHONY: build-app
build-app: $(GOARCHS)

$(GADGETS):
	sudo -E ig image build \
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
	cd build/src && GOOS=linux GOARCH=$@ CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o ../../$(OUTPUT_DIR)/micromize-linux-$@ ./cmd/micromize

.PHONY: run-fs-restrict
run-fs-restrict:
	sudo -E ig run $(CONTAINER_REPO)/fs-restrict:$(IMAGE_TAG) $$PARAMS

.PHONY: run-kmod-restrict
run-kmod-restrict:
	sudo -E ig run $(CONTAINER_REPO)/kmod-restrict:$(IMAGE_TAG) $$PARAMS

.PHONY: push
push:
	for gadget in $(GADGETS); do \
		sudo -E ig image push $(CONTAINER_REPO)/$$gadget:$(IMAGE_TAG); \
	done
	
.PHONY: clang-format
clang-format:
	$(CLANG_FORMAT) -i gadgets/*/*.bpf.c gadgets/*/*.bpf.h
