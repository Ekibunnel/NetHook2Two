#!/bin/sh
# Builds and runs the portable core tests on Linux/macOS (needs protoc + libprotobuf-dev).
set -e
cd "$(dirname "$0")"
protoc -I protos --descriptor_set_out=test.desc --include_imports protos/*.proto
protoc -I protos --cpp_out=. protos/enums_clientserver.proto protos/steammessages_clientserver_login.proto protos/gc_test.proto protos/steammessages_player.steamclient.proto
g++ -std=c++17 -O1 -g -fsanitize=address,undefined -Wall -Wextra -Wno-unused-parameter \
    core_test.cpp ../NetHook2Two/core/*.cpp *.pb.cc -I. -o core_test $(pkg-config --cflags --libs protobuf)
./core_test "$@"
