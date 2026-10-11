// Decodes raw Steam network packets (as NetHook2Two captures them) into something displayable.
//
// This is the runtime-descriptor equivalent of NetHookAnalyzer2: it reads the packet header, finds the
// protobuf type of the body (service methods, GC messages, EMsg name matching...) and walks the message
// with protobuf reflection, so no generated classes are needed and new Steam protobufs just work.
//
// Portable C++ (no Windows headers).
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "descriptor_store.h"
#include "node.h"

namespace nh2
{

// Quick facts about a packet, cheap enough to compute for every captured packet.
struct PacketSummary
{
	bool valid = false;
	bool isProto = false;
	uint32_t rawEMsg = 0;
	uint32_t emsg = 0;
	std::string emsgName;  // without "k_EMsg", empty if unknown
	std::string inner;     // service method name, GC message, legacy service method...
	uint64_t jobIdSource = ~0ull;
	uint64_t jobIdTarget = ~0ull;
	uint64_t steamId = 0;
	int32_t sessionId = 0;
	size_t size = 0;
};

struct DecodeOptions
{
	bool showUnsetFields = false;
};

class PacketDecoder
{
public:
	// `store` may be null; bodies are then displayed schemaless.
	explicit PacketDecoder( std::shared_ptr<const DescriptorStore> store );

	// `hookName` is the EMsg name as reported by Steam itself (may be empty).
	PacketSummary Summarize( const uint8_t *data, size_t length, const std::string &hookName ) const;

	Node Decode( const uint8_t *data, size_t length, const std::string &hookName, const DecodeOptions &options ) const;

private:
	std::shared_ptr<const DescriptorStore> store_;
};

// Helpers that are useful for the UI and tests.
std::string FormatSteamId( uint64_t steamId );  // "[U:1:12345] (STEAM_0:1:6172) = 76561197960278073"
std::string FormatUnixTime( int64_t seconds );  // "2024-01-31 12:34:56 UTC"
std::string HexDump( const uint8_t *data, size_t length, size_t bytesPerLine = 16 );

} // namespace nh2
