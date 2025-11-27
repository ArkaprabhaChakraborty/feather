.PHONY: all test example clean install-deps fmt vet check bench

all: test

# Install Capstone library
install-deps:
	@echo "Installing Capstone library..."
	@if [ "$$(uname)" = "Darwin" ]; then \
		brew install capstone; \
	elif [ -f /etc/debian_version ]; then \
		sudo apt-get install -y libcapstone-dev; \
	elif [ -f /etc/redhat-release ]; then \
		sudo dnf install -y capstone-devel; \
	else \
		echo "Please install Capstone manually or build from capstone-next/"; \
	fi

# Build Capstone from source (capstone-next)
build-capstone:
	@echo "Building Capstone from source..."
	cd ../capstone-next && \
	cmake -B build \
		-DCMAKE_BUILD_TYPE=Release \
		-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF \
		-DCAPSTONE_X86_SUPPORT=ON && \
	cmake --build build && \
	sudo cmake --install build

# Run tests
test:
	go test -v

# Run benchmarks
bench:
	go test -bench=. -benchmem

# Run example
example:
	cd example && go run main.go

# Build example binary
build-example:
	cd example && go build -o disasm main.go

# Clean build artifacts
clean:
	rm -f example/disasm
	go clean

# Format code
fmt:
	go fmt ./...

# Run go vet
vet:
	go vet ./...

# Check everything
check: fmt vet test

# Show help
help:
	@echo "Available targets:"
	@echo "  make install-deps    - Install Capstone library"
	@echo "  make build-capstone  - Build Capstone from capstone-next/"
	@echo "  make test            - Run tests"
	@echo "  make bench           - Run benchmarks"
	@echo "  make example         - Run example"
	@echo "  make build-example   - Build example binary"
	@echo "  make fmt             - Format code"
	@echo "  make vet             - Run go vet"
	@echo "  make check           - Format, vet, and test"
	@echo "  make clean           - Clean build artifacts"
