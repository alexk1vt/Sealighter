ECHO OFF
set arg1=%1
ECHO ON
protoc -I=. --cpp_out=. %arg1%
protoc -I=. --grpc_out=. --plugin=protoc-gen-grpc="C:\Users\xande\source\repos\vcpkg\packages\grpc_x64-windows\tools\grpc\grpc_cpp_plugin.exe" %arg1%