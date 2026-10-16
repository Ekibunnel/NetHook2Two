// CMsgMulti (the "several messages in one" envelope) read with the same definitions the viewer uses, so the dump
// writer doesn't need generated protobuf classes (and therefore no protoc) for it.
//
// Portable C++ (no Windows headers).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "descriptor_store.h"

namespace nh2
{

struct MultiMessage
{
	uint32_t sizeUnzipped = 0; // 0 = message_body isn't compressed
	std::string body;
};

// Reads `data` as a CMsgMulti. Uses the definition found in Steam (or the built-in one) when `store` is given,
// otherwise (or if that type is missing) reads fields 1 (size_unzipped) and 2 (message_body) straight from the wire
// format, which is how Steam has always laid them out. False if the bytes aren't a valid message.
bool ParseMulti( const DescriptorStore *store, const uint8_t *data, size_t length, MultiMessage &out );

} // namespace nh2
