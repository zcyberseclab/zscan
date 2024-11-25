# Build stage
FROM golang:1.23.2-alpine AS builder

WORKDIR /app

# Install git for private dependencies
RUN apk add --no-cache git

# Set Go environment variables
ENV GO111MODULE=on
ENV GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=off

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod tidy && \
    go mod verify && \
    go mod download -x

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o zscan cmd/main.go

# Final stage
FROM alpine:latest

WORKDIR /app

# Install CA certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN adduser -D -H -h /app zscan

# Copy binary and configs
COPY --from=builder /app/zscan /app/
COPY --from=builder /app/config /app/config
COPY --from=builder /app/templates /app/templates

# Set ownership
RUN chown -R zscan:zscan /app

# Switch to non-root user
USER zscan

ENTRYPOINT ["/app/zscan"]