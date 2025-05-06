all: ./opensnitch_pb2.py

./ui_pb2.py: opensnitch.proto
	python3 -m grpc_tools.protoc -I. --python_out=./ --grpc_python_out=./proto/ opensnitch.proto

clean:
	@rm -rf ./opensnitch_pb2.py
	@rm -rf ./opensnitch_pb2_grpc.py
