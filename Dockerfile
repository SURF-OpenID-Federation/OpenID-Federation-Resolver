FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy source code first
COPY . .

RUN if [ ! -f go.mod ]; then go mod init resolver; fi && \
    go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o federation-resolver .

FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata curl
WORKDIR /root/

# Copy binary
COPY --from=builder /app/federation-resolver .

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["./federation-resolver"]