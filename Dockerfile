# Build Stage
FROM golang:latest AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy dependency files for efficient caching
COPY go.mod go.sum ./

# Download Go module dependencies
RUN go mod download

# Copy the rest of the application code
COPY . .

# Build a statically linked binary to avoid glibc dependency issues
# CGO_ENABLED=0 ensures no dynamic linking, GOOS=linux and GOARCH=amd64 build for Linux
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o main .

# Final Stage (Small Runtime Image)
FROM gcr.io/distroless/static:nonroot

# Set the working directory inside the runtime container
WORKDIR /

# Copy the statically linked binary from the build stage
COPY --from=builder /app/main .

# Run the binary as a non-root user for security
USER nonroot:nonroot

# Expose the application port
EXPOSE 80

# Set the default command to run the binary
CMD ["/main"]
