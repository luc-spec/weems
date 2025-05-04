{
  description = "OpenSnitch Agent Development Environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };
  
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Python environment
            (python313.withPackages (ps: with ps; [
              black
              grpcio
              grpcio-tools
              pip
              protobuf
              setuptools
            ]))
            
            # Development tools
            gnumake
            git
            git-lfs

            # UV package manager
            python313Packages.uv
            
            # Protobuf compilation tools
            protobuf

            stdenv.cc.cc.lib
            openssl
            glib
            zlib
            
            
          ];
          
          shellHook = ''
            export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [
              pkgs.stdenv.cc.cc.lib
              pkgs.zlib
              pkgs.glib
              pkgs.xorg.libX11
              pkgs.openssl
            ]}:$LD_LIBRARY_PATH"

            # Environment variables for grpc
            export GRPC_PYTHON_BUILD_SYSTEM_OPENSSL=1
            export GRPC_PYTHON_BUILD_SYSTEM_ZLIB=1
            
            # For debugging
            echo "LD_LIBRARY_PATH is set to: $LD_LIBRARY_PATH"
            
            # Optional: Check if libstdc++.so.6 is accessible
            find $LD_LIBRARY_PATH -name "libstdc++.so*" | sort

            echo "OpenSnitch Agent Development Environment"
            echo "----------------------------------------"
            echo "Available tools:"
            echo "  - Python with grpcio and protobuf packages"
            echo "  - UV package manager: $(uv --version)"
            echo "  - Protobuf compiler: $(protoc --version)"
            echo ""
            echo "Quick start:"
            echo "  1. Clone OpenSnitch repo to get proto files:"
            echo "     git clone https://github.com/evilsocket/opensnitch.git"
            echo "  2. Generate Python client from proto files:"
            echo "     python -m grpc_tools.protoc -I=./opensnitch/proto \\"
            echo "       --python_out=. --grpc_python_out=. \\"
            echo "       ./opensnitch/proto/ui.proto"
            echo ""
          '';
        };
      }
    );
}
