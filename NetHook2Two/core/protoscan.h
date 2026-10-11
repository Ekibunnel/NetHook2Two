// Port of ProtobufDumper's ExecutableScanner + ProtobufCollector.
//
// Steam's client binaries embed serialized FileDescriptorProtos (one per .proto file).
// This scans a binary blob for them so that NetHook2Two can always decode packets using the
// protobuf definitions of the Steam client that is actually running, instead of a
// compiled-in snapshot of them.
//
// Portable C++ (no Windows headers) so that it can be unit tested anywhere.
#pragma once

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include <google/protobuf/descriptor.pb.h>

namespace nh2
{

struct ScanStats
{
	size_t candidates = 0; // "<something>.proto" markers that looked like a descriptor
	size_t accepted = 0;   // successfully collected descriptors
	size_t invalid = 0;    // candidates that failed to parse
};

// Scans `data` for embedded FileDescriptorProtos.
// Descriptors whose name is already in `seen` are skipped (first one wins, like ProtobufDumper).
void ScanBufferForDescriptors(
	const uint8_t *data,
	size_t length,
	std::vector<google::protobuf::FileDescriptorProto> &out,
	std::set<std::string> &seen,
	ScanStats &stats );

// Reads `path` fully and scans it. Returns false (and sets `error`) if the file couldn't be read.
bool ScanFileForDescriptors(
	const std::string &path,
	std::vector<google::protobuf::FileDescriptorProto> &out,
	std::set<std::string> &seen,
	ScanStats &stats,
	std::string &error );

// Returns how many bytes at the start of `data` look like one serialized FileDescriptorProto.
// Same rule as ProtobufCollector.ConsumeOneMessage: stop at end of data, at an unparsable field,
// or when field 1 (the file name) appears for the second time.
size_t ConsumeOneDescriptor( const uint8_t *data, size_t length );

} // namespace nh2
