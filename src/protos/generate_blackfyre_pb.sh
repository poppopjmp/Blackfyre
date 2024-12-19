#Generate protobuffs for python
protoc --python_out=../python/blackfyre/datatypes/protobuf  binary_context.proto
protoc --python_out=../python/blackfyre/datatypes/protobuf  pe_header.proto
protoc --python_out=../python/blackfyre/datatypes/protobuf  function_context.proto


#Generate protobuffs for java
protoc --java_out=../ghidra/Blackfyre/src/main/java binary_context.proto
protoc --java_out=../ghidra/Blackfyre/src/main/java pe_header.proto
protoc --java_out=../ghidra/Blackfyre/src/main/java function_context.proto
