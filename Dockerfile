# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

# Set working directory
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy static files
COPY --from=builder /app/static ./static
COPY --from=builder /app/templates ./templates

# Copy the binary from builder
COPY --from=builder /app/main .

# Create a non-root user
RUN adduser -D -g '' appuser
USER appuser

# Expose port
EXPOSE 3000

# Set environment variables
ENV PORT=3000

# Run the application
CMD ["./main"] 