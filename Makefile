.PHONY: setup clone-proto generate-proto venv dev clean

# Default target
all: setup generate-proto

init:
	@touch ./proto/__init__.py
	@touch ./tests/__init__.py
	@touch ./utils/__init__.py

test:
	@uv run pytest

# Clone OpenSnitch repository to get proto files
clone-proto:
	@echo "Cloning OpenSnitch repository to get proto files..."
	@if [ -f "proto/opensnitch.proto" ]; then \
		echo "OpenSnitch protobuf file already exists"; \
	else \
		curl https://github.com/evilsocket/tree/master/proto/ui.proto >> proto/opensnitch.proto; \
	fi

# Generate Python code from proto files
generate-proto: clone-proto
	@echo "Generating Python code from proto files..."
	@if [ ! -d "proto" ]; then \
		mkdir -p ./proto; \
	fi
	python -m grpc_tools.protoc \
		-I=./proto \
		--python_out=./proto \
		--grpc_python_out=./proto \
		./proto/opensnitch.proto
	@touch ./proto/__init__.py
	@touch ./__init__.py
	@echo "Proto files generated successfully"

# Setup development environment using uv
setup:
	@echo "Setting up development environment..."
	@uv venv
	@uv pip install -e .
	@echo "Environment setup complete"

# Install dev dependencies
dev:
	@echo "Installing development dependencies..."
	@uv pip install -e ".[dev]"
	@echo "Development dependencies installed"

# Clean generated files
clean:
	@echo "Cleaning generated files..."
	@rm -rf ./proto/*_pb2*.py
	@rm -rf __pycache__
	@rm -rf *.egg-info
	@rm -rf .pytest_cache
	@echo "Clean complete"
