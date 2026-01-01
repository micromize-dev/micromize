FROM ghcr.io/inspektor-gadget/gadget-builder:main AS gadget-builder

ARG IG_VERSION=v0.47.0
ARG IMAGE_TAG=dev

# Install ig
RUN wget -qO- https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${IG_VERSION}/ig-linux-amd64-${IG_VERSION}.tar.gz \
    | tar -xz -C /usr/local/bin ig

WORKDIR /app
COPY gadgets gadgets

# Build gadgets
RUN mkdir -p build/gadgets && \
    for gadget in fs-restrict cap-restrict ptrace-restrict; do \
        echo "Building gadget: $gadget" && \
        ig image build \
            --local \
            -t ghcr.io/micromize-dev/micromize/${gadget}:${IMAGE_TAG} \
            gadgets/${gadget} && \
        ig image export \
            ghcr.io/micromize-dev/micromize/${gadget}:${IMAGE_TAG} \
            build/gadgets/${gadget}.tar; \
    done

FROM golang:1.25.5-alpine AS builder

ARG IG_VERSION=v0.47.0
ARG IMAGE_TAG=dev

WORKDIR /app

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Copy built gadgets from the gadget-builder stage
# They need to be placed where embeds.go expects them (cmd/micromize/build/)
RUN mkdir -p cmd/micromize/build
COPY --from=gadget-builder /app/build/gadgets/*.tar cmd/micromize/build/

# Build the static binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -tags release \
    -ldflags "-X github.com/inspektor-gadget/inspektor-gadget/internal/version.version=${IG_VERSION} -X main.Version=${IMAGE_TAG} -w -s -extldflags '-static'" \
    -o /micromize \
    ./cmd/micromize

# Build the image
FROM scratch
COPY --from=builder /micromize /micromize

# Access to kernel debug filesystem (tracefs)
VOLUME ["/sys/kernel/debug"]

# Access to BPF filesystem for map pinning
VOLUME ["/sys/fs/bpf"]

# Access to cgroup hierarchy
VOLUME ["/sys/fs/cgroup"]

# Access to host process information
VOLUME ["/host/proc"]

# Access to host system information
VOLUME ["/host/sys"]

# Access to host binaries and libraries
VOLUME ["/host/bin"]
VOLUME ["/host/usr"]

# Access to host runtime files (sockets, etc.)
VOLUME ["/host/run"]

ENV HOST_ROOT=/host
ENTRYPOINT ["/micromize"]
