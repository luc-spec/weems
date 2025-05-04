.PHONY: setup get-proto generate-proto venv dev clean

# Default target
all: setup generate-proto

test:
	@uv run pytest

format: 
	@black ./*.py
	@black ./utils/*.py
	@black ./tests/*.py

# Get OpenSnitch proto file
get-proto:
	@echo "Cloning OpenSnitch repository to get proto files..."
	@if [ -f "./proto/opensnitch.proto" ]; then \
		echo "OpenSnitch protobuf file already exists"; \
	else \
		curl https://raw.githubusercontent.com/evilsocket/opensnitch/refs/heads/master/proto/ui.proto > proto/opensnitch.proto; \
	fi

# Generate Python code from proto files
generate-proto: get-proto
	@echo "Generating Python code from proto files..."
	@if [ ! -d "proto" ]; then mkdir -p ./proto; fi
	@python -m grpc_tools.protoc \
		-I=./proto \
		--python_out=./proto \
		--grpc_python_out=./proto \
		./proto/opensnitch.proto
	@touch ./proto/__init__.py
	@echo "Proto files generated successfully"

# Setup development environment using uv
setup:
	@echo "Setting up development environment..."
	@uv venv
	@if [ ! -d "./proto" ]; then mkdir -p ./proto; fi
	@if [ ! -d "./.weems" ]; then mkdir -p ./.weems; fi
	@touch ./__init__.py
	@touch ./proto/__init__.py
	@touch ./tests/__init__.py
	@touch ./utils/__init__.py
	@echo "Environment setup complete"

install:
	@uv pip install -e .

# Clean generated files
clean:
	@echo "Cleaning generated files..."
	@rm -rf ./proto/*_pb2*.py
	@rm -rf __pycache__
	@rm -rf *.egg-info
	@rm -rf .pytest_cache
	@echo "Clean complete"
