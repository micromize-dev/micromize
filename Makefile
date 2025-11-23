TAG := $(shell git describe --tags --always --dirty)
CONTAINER_REPO ?= ghcr.io/dorser/micromize
IMAGE_TAG ?= $(TAG)
CLANG_FORMAT ?= clang-format

GADGETS := fs-restrict kmod-restrict

.PHONY: build
build: $(GADGETS)

.PHONY: $(GADGETS)
$(GADGETS):
	sudo -E ig image build \
		-t $(CONTAINER_REPO)/$@:$(IMAGE_TAG) \
		--update-metadata gadgets/$@

# PARAMS can be used to pass additional parameters locally. For example:
# PARAMS="-o jsonpretty" make run-fs-restrict
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
