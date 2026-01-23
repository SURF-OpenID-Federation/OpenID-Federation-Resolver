FROM golang:1.25-alpine AS builder

# When building inside the monorepo we copy the whole repository into /src
# so local `replace` directives (e.g. resolver/go.mod -> ../) can be resolved.
WORKDIR /src

# Copy the repository (build context is the repo root in CI)
COPY . /src

# Default working dir for subsequent commands (we'll detect the module path below)
WORKDIR /src

# Detect whether the resolver module is at the repo root or in a subdirectory and
# build from the correct location. Place outputs in /out so the final stage can
# copy them deterministically regardless of build-context layout.
RUN set -euo pipefail; \
    # prefer the resolver submodule when present (monorepo + submodule layout)
    if [ -f /src/resolver/go.mod ]; then BUILD_DIR=/src/resolver; \
    elif [ -f /src/go.mod ]; then BUILD_DIR=/src; \
    else echo "No go.mod found in /src or /src/resolver" >&2; exit 1; fi; \
    echo "Building resolver from $BUILD_DIR"; \
    cd "$BUILD_DIR"; \
    if [ ! -f go.mod ]; then go mod init resolver; fi; \
    go env -w GOPROXY=https://proxy.golang.org,direct; \
    # tidy only the module (avoid pulling test-only deps from outside the module)
    go mod tidy; \
    mkdir -p /out; \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /out/federation-resolver .; \
    # ensure entrypoint is available regardless of layout
    if [ -f docker-entrypoint.sh ]; then cp docker-entrypoint.sh /out/docker-entrypoint.sh; \
    elif [ -f resolver/docker-entrypoint.sh ]; then cp resolver/docker-entrypoint.sh /out/docker-entrypoint.sh; fi

FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata curl
WORKDIR /root/

# Copy binary and entrypoint from builder's /out
COPY --from=builder /out/federation-resolver .
COPY --from=builder /out/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["./federation-resolver"]