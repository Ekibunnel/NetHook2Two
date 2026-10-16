// Portable tests for the NetHook2Two core (scanner, descriptor store, decoder).
// Build: see tests/run_tests.sh
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <cstring>
#include <google/protobuf/stubs/common.h>

#include "../NetHook2Two/core/decoder.h"
#include "../NetHook2Two/core/descriptor_store.h"
#include "../NetHook2Two/core/locator.h"
#include "../NetHook2Two/core/protoscan.h"

#include "gc_test.pb.h"
#include "steammessages_clientserver_login.pb.h"
#include "steammessages_player.steamclient.pb.h"

namespace fs = std::filesystem;
using namespace nh2;

static int g_failures = 0;
#define CHECK( cond ) do { if ( !( cond ) ) { std::printf( "  FAIL line %d: %s\n", __LINE__, #cond ); g_failures++; } } while ( 0 )
#define CHECK_CONTAINS( text, needle ) do { if ( ( text ).find( needle ) == std::string::npos ) { std::printf( "  FAIL line %d: output does not contain '%s'\n", __LINE__, needle ); g_failures++; } } while ( 0 )

static std::vector<uint8_t> ReadAll( const std::string &path )
{
	std::ifstream f( path, std::ios::binary );
	return std::vector<uint8_t>( ( std::istreambuf_iterator<char>( f ) ), std::istreambuf_iterator<char>() );
}

static void PutU32( std::vector<uint8_t> &v, uint32_t x ) { for ( int i = 0; i < 4; i++ ) v.push_back( ( x >> ( 8 * i ) ) & 255 ); }
static void PutU64( std::vector<uint8_t> &v, uint64_t x ) { for ( int i = 0; i < 8; i++ ) v.push_back( ( x >> ( 8 * i ) ) & 255 ); }
static void PutU16( std::vector<uint8_t> &v, uint16_t x ) { for ( int i = 0; i < 2; i++ ) v.push_back( ( x >> ( 8 * i ) ) & 255 ); }

// Writes a fake "steamclient.dll": random junk containing the serialized descriptors (shuffled), including
// misleading 0x0A bytes and fake ".proto" names.
static void WriteFakeBinary( const std::string &path, const std::vector<std::string> &descriptors, unsigned seed )
{
	std::mt19937 rng( seed );
	std::vector<uint8_t> blob;
	auto junk = [ & ]( size_t n )
	{
		for ( size_t i = 0; i < n; i++ )
			blob.push_back( rng() % 5 == 0 ? 0x0A : static_cast<uint8_t>( rng() ) );
	};

	junk( 5000 );
	const std::string fakeName = "\x0A\x0Bnothing.proto\x12\x03xyz";
	blob.insert( blob.end(), fakeName.begin(), fakeName.end() ); // looks like a descriptor but is garbage
	junk( 777 );

	std::vector<std::string> order = descriptors;
	std::shuffle( order.begin(), order.end(), rng );
	for ( const auto &d : order )
	{
		blob.insert( blob.end(), d.begin(), d.end() );
		junk( 100 + rng() % 3000 );
	}

	std::ofstream out( path, std::ios::binary | std::ios::trunc );
	out.write( reinterpret_cast<const char *>( blob.data() ), static_cast<std::streamsize>( blob.size() ) );
}

static std::vector<uint8_t> MakeProtoPacket( const DescriptorStore &store, uint32_t emsg, const std::function<void( google::protobuf::Message &, const google::protobuf::Reflection * )> &fillHeader, const google::protobuf::Message &body )
{
	auto header = store.NewMessage( store.FindMessage( "CMsgProtoBufHeader" ) );
	fillHeader( *header, header->GetReflection() );

	std::string h = header->SerializeAsString();
	std::string b = body.SerializeAsString();

	std::vector<uint8_t> packet;
	PutU32( packet, emsg | 0x80000000u );
	PutU32( packet, static_cast<uint32_t>( h.size() ) );
	packet.insert( packet.end(), h.begin(), h.end() );
	packet.insert( packet.end(), b.begin(), b.end() );
	return packet;
}


// ---- locator tests -------------------------------------------------------------------------------------------

static void Put32At( std::vector<uint8_t> &v, size_t off, uint32_t x ) { for ( int i = 0; i < 4; i++ ) v[ off + i ] = ( x >> ( 8 * i ) ) & 255; }
static void Put16At( std::vector<uint8_t> &v, size_t off, uint16_t x ) { v[ off ] = x & 255; v[ off + 1 ] = x >> 8; }
static void PutBytes( std::vector<uint8_t> &v, size_t off, std::initializer_list<int> bytes ) { for ( int b : bytes ) v[ off++ ] = static_cast<uint8_t>( b ); }
static void PutString( std::vector<uint8_t> &v, size_t off, const char *s ) { for ( ; *s; s++ ) v[ off++ ] = static_cast<uint8_t>( *s ); }

// A tiny 64-bit PE image: .text with RecvPkt-like functions, .rdata with strings and .pdata with unwind info
// (including a chained entry, like the compiler emits for functions with a split prologue).
static std::vector<uint8_t> MakeFakeModule( bool withSecondPrologueCopy )
{
	std::vector<uint8_t> m( 0x4000, 0 );
	m[ 0 ] = 'M'; m[ 1 ] = 'Z';
	Put32At( m, 0x3C, 0x80 );
	Put32At( m, 0x80, 0x00004550 );
	Put16At( m, 0x84 + 2, 3 );          // sections
	Put16At( m, 0x84 + 16, 0xF0 );      // size of optional header
	const size_t opt = 0x84 + 20;
	Put16At( m, opt, 0x20B );
	Put32At( m, opt + 56, 0x4000 );     // SizeOfImage
	Put32At( m, opt + 60, 0x400 );      // SizeOfHeaders
	Put32At( m, opt + 112 + 24, 0x3000 ); // exception directory
	Put32At( m, opt + 112 + 28, 3 * 12 );

	auto section = [ & ]( int i, const char *name, uint32_t rva, uint32_t size, uint32_t flags )
	{
		const size_t s = opt + 0xF0 + i * 40;
		PutString( m, s, name );
		Put32At( m, s + 8, size );
		Put32At( m, s + 12, rva );
		Put32At( m, s + 16, size );
		Put32At( m, s + 36, flags );
	};
	section( 0, ".text", 0x1000, 0x1000, 0x60000020 );
	section( 1, ".rdata", 0x2000, 0x800, 0x40000040 );
	section( 2, ".pdata", 0x3000, 0x200, 0x40000040 );

	// strings: one real, one that is only the tail of a longer string
	PutString( m, 0x2101, "CCMInterface::RecvPkt" );
	PutString( m, 0x2201, "xxCCMInterface::RecvPkt" );
	const uint32_t kString = 0x2101;

	auto lea = [ & ]( size_t at, uint32_t target ) // lea rcx, [rip+disp]
	{
		PutBytes( m, at, { 0x48, 0x8D, 0x0D } );
		Put32At( m, at + 3, target - static_cast<uint32_t>( at + 7 ) );
	};

	// RecvPkt: prologue chunk 0x1000-0x1012, body chunk 0x1012-0x1080 (chained)
	PutBytes( m, 0x1000, { 0x48, 0x8B, 0xC4, 0x55, 0x48, 0x8D, 0xA8, 0x98, 0xF6, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0x60, 0x0A, 0x00, 0x00 } );
	PutBytes( m, 0x1012, { 0x48, 0x89, 0x58, 0x08, 0x48, 0x8B, 0xDA, 0x4C, 0x89, 0x70, 0xD0 } );
	lea( 0x1020, kString );
	PutBytes( m, 0x1030, { 0xB2, 0x01, 0x48, 0x89, 0x45, 0xA8, 0x48, 0x8B, 0xCB, 0xE8, 0, 0, 0, 0, 0x48, 0x8B, 0xD8, 0xC3 } );

	// something else that mentions the same name (a log helper): must be rejected by the structural check
	PutBytes( m, 0x1200, { 0x48, 0x83, 0xEC, 0x28 } );
	lea( 0x1204, kString );
	PutBytes( m, 0x1210, { 0x33, 0xC0, 0x48, 0x83, 0xC4, 0x28, 0xC3 } );

	if ( withSecondPrologueCopy )
	{
		// same 25 byte prologue prefix somewhere else -> the signature is ambiguous
		PutBytes( m, 0x1400, { 0x48, 0x8B, 0xC4, 0x55, 0x48, 0x8D, 0xA8, 0x10, 0x00, 0x00, 0x00, 0x48, 0x81, 0xEC, 0x20, 0x01, 0x00, 0x00,
			0x48, 0x89, 0x58, 0x08, 0x48, 0x8B, 0xDA, 0xC3 } );
	}

	// .pdata: RUNTIME_FUNCTION { begin, end, unwind } sorted by begin
	Put32At( m, 0x3000, 0x1000 ); Put32At( m, 0x3004, 0x1012 ); Put32At( m, 0x3008, 0x3040 );
	Put32At( m, 0x300C, 0x1012 ); Put32At( m, 0x3010, 0x1080 ); Put32At( m, 0x3014, 0x3080 );
	Put32At( m, 0x3018, 0x1200 ); Put32At( m, 0x301C, 0x1220 ); Put32At( m, 0x3020, 0x3040 );
	PutBytes( m, 0x3040, { 0x01, 0x00, 0x00, 0x00 } );                      // plain unwind info
	PutBytes( m, 0x3080, { 0x21, 0x00, 0x00, 0x00 } );                      // UNW_FLAG_CHAININFO, no codes...
	Put32At( m, 0x3084, 0x1000 ); Put32At( m, 0x3088, 0x1012 ); Put32At( m, 0x308C, 0x3040 ); // ...then the parent entry
	return m;
}

static LocateRequest FakeRecvPktRequest()
{
	LocateRequest r;
	r.name = "RecvPkt";
	r.arch = "x64";
	r.candidates = {
		{ "\x48\x8B\xC4\x55\x48\x8D\xA8\xCC\xCC\xCC\xCC\x48\x81\xEC\xCC\xCC\xCC\xCC\x48\x89\x58\x08\x48\x8B\xDA", "xxxxxxx????xxx????xxxxxxx" },
	};
	r.validate = LooksLikeRecvPkt;
	r.fallback = []( const ImageView &i, const LocateLog &l ) { return FindRecvPktByStringReference( i, l ); };
	return r;
}

// Lays a PE file out in memory the way the Windows loader does.
static std::vector<uint8_t> LoadModuleImage( const std::string &path )
{
	const std::vector<uint8_t> file = ReadAll( path );
	auto u32 = [ & ]( size_t o ) { uint32_t v = 0; std::memcpy( &v, &file[ o ], 4 ); return v; };
	auto u16 = [ & ]( size_t o ) { uint16_t v = 0; std::memcpy( &v, &file[ o ], 2 ); return v; };

	if ( file.size() < 0x200 )
		return {};

	const size_t pe = u32( 0x3C ), opt = pe + 24;
	const size_t imageSize = u32( opt + 56 ), headers = u32( opt + 60 );
	std::vector<uint8_t> image( imageSize, 0 );
	std::memcpy( image.data(), file.data(), std::min( headers, file.size() ) );

	const size_t table = opt + u16( pe + 20 );
	for ( int i = 0; i < u16( pe + 6 ); i++ )
	{
		const size_t s = table + i * 40;
		const size_t va = u32( s + 12 ), raw = u32( s + 16 ), ptr = u32( s + 20 );
		if ( raw != 0 && ptr + raw <= file.size() && va + raw <= imageSize )
			std::memcpy( &image[ va ], &file[ ptr ], raw );
	}
	return image;
}

int main( int argc, char **argv )
{
	using google::protobuf::FileDescriptorSet;

	google::protobuf::SetLogHandler( nullptr ); // random packets contain invalid UTF-8, which protobuf complains about
	const fs::path work = fs::temp_directory_path() / "nh2_core_test";
	fs::remove_all( work );
	fs::create_directories( work );

	std::vector<std::string> log;
	LogFn logFn = [ & ]( const std::string &s ) { log.push_back( s ); };

	std::printf( "== scanner on a real binary (libprotobuf) ==\n" );
	{
		std::vector<google::protobuf::FileDescriptorProto> files;
		std::set<std::string> seen;
		ScanStats stats;
		std::string error;
		const bool ok = ScanFileForDescriptors( argc > 1 ? argv[ 1 ] : "/usr/lib/x86_64-linux-gnu/libprotobuf.so.32", files, seen, stats, error );
		CHECK( ok );
		std::printf( "  found %zu descriptors (%zu candidates, %zu invalid)\n", files.size(), stats.candidates, stats.invalid );
		CHECK( seen.count( "google/protobuf/descriptor.proto" ) == 1 );
		CHECK( seen.count( "google/protobuf/any.proto" ) == 1 );
		CHECK( files.size() >= 8 );

		// they must be real: build a pool out of them
		google::protobuf::DescriptorPool pool;
		bool built = true;
		for ( const auto &f : files )
		{
			if ( f.name() == "google/protobuf/descriptor.proto" ) { built &= pool.BuildFile( f ) != nullptr; }
		}
		CHECK( built );
		CHECK( pool.FindMessageTypeByName( "google.protobuf.FileDescriptorProto" ) != nullptr );
	}

	std::printf( "== store: scan, cache, rescan on change ==\n" );
	FileDescriptorSet testSet;
	{
		auto bytes = ReadAll( "test.desc" );
		CHECK( testSet.ParseFromArray( bytes.data(), static_cast<int>( bytes.size() ) ) );
	}

	std::vector<std::string> serialized;
	for ( int i = 0; i < testSet.file_size(); i++ )
	{
		// gc_test.proto plays "a game's protobufs": only available through a descriptor set, not in the Steam binary
		if ( testSet.file( i ).name() != "gc_test.proto" )
			serialized.push_back( testSet.file( i ).SerializeAsString() );
	}

	// plus the real steammessages_base.proto descriptor, as Steam would have it
	{
		auto base = ReadAll( "steammessages_base.desc" );
		serialized.push_back( std::string( base.begin(), base.end() ) );
	}

	const std::string fakeDll = ( work / "steamclient64.dll" ).string();
	const std::string cacheDir = ( work / "cache" ).string();
	WriteFakeBinary( fakeDll, serialized, 1 );

	std::shared_ptr<DescriptorStore> store = std::make_shared<DescriptorStore>();
	store->Load( { fakeDll }, cacheDir, false, logFn );

	std::printf( "  %s\n", store->Summary().c_str() );
	CHECK( store->Targets().size() == 1 && store->Targets()[ 0 ].state == "scanned" );
	CHECK( store->Targets()[ 0 ].files == 4 ); // enums, login, player + steammessages_base (the garbage "nothing.proto" is rejected)
	CHECK( store->FileCount() == 5 );          // ...plus google/protobuf/descriptor.proto which base depends on
	CHECK( store->FindMessage( "CMsgClientLogon" ) != nullptr );
	CHECK( store->FindMessage( "CMsgProtoBufHeader" ) != nullptr );
	CHECK( store->FindService( "Player" ) != nullptr );
	CHECK( store->FindMessage( "CMsgClientHello" ) == nullptr );
	CHECK( store->EMsgName( 5514 ) == "ClientLogon" );
	CHECK( store->FindBodyForEMsg( 5514, "" ) == store->FindMessage( "CMsgClientLogon" ) );
	CHECK( store->FindBodyForEMsg( 751, "k_EMsgClientLogOnResponse" ) == store->FindMessage( "CMsgClientLogonResponse" ) );
	CHECK( store->FindBodyForEMsg( 818, "" ) == nullptr );
	CHECK( fs::exists( work / "cache" / "protos" / "steammessages_clientserver_login.proto" ) );
	{
		int pbsets = 0;
		for ( auto &e : fs::directory_iterator( cacheDir ) ) pbsets += e.path().extension() == ".pbset";
		CHECK( pbsets == 1 );
	}

	store = std::make_shared<DescriptorStore>();
	store->Load( { fakeDll }, cacheDir, false, logFn );
	CHECK( store->Targets()[ 0 ].state == "cache" );
	CHECK( store->FindMessage( "CMsgClientLogon" ) != nullptr );

	// "Steam update": the binary changes (new size) -> must rescan and replace the cache
	std::vector<std::string> updated = serialized;
	{
		google::protobuf::FileDescriptorProto extra;
		extra.set_name( "steammessages_new.proto" );
		auto *m = extra.add_message_type();
		m->set_name( "CMsgClientBrandNew" );
		auto *f = m->add_field();
		f->set_name( "x" ); f->set_number( 1 ); f->set_type( google::protobuf::FieldDescriptorProto::TYPE_UINT32 ); f->set_label( google::protobuf::FieldDescriptorProto::LABEL_OPTIONAL );
		updated.push_back( extra.SerializeAsString() );
	}
	WriteFakeBinary( fakeDll, updated, 2 );
	store = std::make_shared<DescriptorStore>();
	store->Load( { fakeDll }, cacheDir, false, logFn );
	CHECK( store->Targets()[ 0 ].state == "scanned" );
	CHECK( store->FindMessage( "CMsgClientBrandNew" ) != nullptr );
	{
		int pbsets = 0;
		for ( auto &e : fs::directory_iterator( cacheDir ) ) pbsets += e.path().extension() == ".pbset";
		CHECK( pbsets == 1 );
	}

	std::printf( "== store: missing target falls back to built-ins ==\n" );
	{
		auto fallback = std::make_shared<DescriptorStore>();
		fallback->Load( { ( work / "nope.dll" ).string() }, cacheDir, false, logFn );
		CHECK( fallback->Targets()[ 0 ].state == "missing" );
		CHECK( !fallback->HasSteamDefinitions() );
		CHECK( fallback->FindMessage( "CMsgProtoBufHeader" ) != nullptr );
		CHECK( fallback->FindMessage( "CMsgGCClient" ) != nullptr );
		PacketDecoder d( fallback );
		std::vector<uint8_t> p;
		PutU32( p, 1u | 0x80000000u );
		PutU32( p, 0 );
		auto node = d.Decode( p.data(), p.size(), "", DecodeOptions{} );
		CHECK_CONTAINS( NodeToText( node ), "CMsgProtoBufHeader" );
	}

	std::printf( "== decoder ==\n" );
	PacketDecoder decoder( store );

	// 1. ClientLogon with steam id, timestamp, nested blob, repeated, enum
	{
		CMsgClientLogon logon;
		logon.set_protocol_version( 65580 );
		logon.set_account_name( "gaben" );
		logon.set_client_supplied_steam_id( 76561197960287930ull );
		logon.set_client_language_rtime32_time( 1700000000 );
		logon.set_machine_id( std::string( "\x01\x02\x03\xFF", 4 ) );
		CMsgClientLogonChild nestedChild; nestedChild.set_label( "inside blob" ); nestedChild.set_account_steamid( 76561197960287930ull );
		logon.set_nested_blob( nestedChild.SerializeAsString() );
		logon.add_supported_things( 7 ); logon.add_supported_things( 9 );
		logon.add_children()->set_label( "child one" );
		logon.set_result( EResultTest::k_EResultTestFail );
		logon.set_ratio( 0.5f );
		logon.set_big( -42 );

		auto packet = MakeProtoPacket( *store, 5514, []( google::protobuf::Message &h, const google::protobuf::Reflection *r )
		{
			r->SetUInt64( &h, h.GetDescriptor()->FindFieldByName( "steamid" ), 76561197960287930ull );
			r->SetInt32( &h, h.GetDescriptor()->FindFieldByName( "client_sessionid" ), 1234 );
			r->SetUInt64( &h, h.GetDescriptor()->FindFieldByName( "jobid_source" ), 99 );
		}, logon );

		auto summary = decoder.Summarize( packet.data(), packet.size(), "k_EMsgClientLogon" );
		CHECK( summary.valid && summary.isProto && summary.emsg == 5514 && summary.emsgName == "ClientLogon" );
		CHECK( summary.jobIdSource == 99 && summary.sessionId == 1234 );
		CHECK( decoder.Summarize( packet.data(), packet.size(), "" ).emsgName == "ClientLogon" ); // name from the enum

		const Node node = decoder.Decode( packet.data(), packet.size(), "k_EMsgClientLogon", DecodeOptions{} );
		const std::string text = NodeToText( node );
		std::printf( "%s", text.c_str() );
		CHECK_CONTAINS( text, "EMsg ClientLogon (5514)" );
		CHECK_CONTAINS( text, "account_name (string): \"gaben\"" );
		CHECK_CONTAINS( text, "[U:1:" );
		CHECK_CONTAINS( text, "STEAM_0:" );
		CHECK_CONTAINS( text, "2023-11-14 22:13:20 UTC" );
		CHECK_CONTAINS( text, "inside blob" );
		CHECK_CONTAINS( text, "k_EResultTestFail" );
		CHECK_CONTAINS( text, "repeated uint32" );
		CHECK_CONTAINS( text, "child one" );
		CHECK_CONTAINS( text, "01 02 03 FF" );
		CHECK_CONTAINS( text, "big (int64): -42" );
		CHECK( text.find( "[unset]" ) == std::string::npos );

		DecodeOptions withUnset; withUnset.showUnsetFields = true;
		const std::string unsetText = NodeToText( decoder.Decode( packet.data(), packet.size(), "", withUnset ) );
		CHECK_CONTAINS( unsetText, "password (string): \"\"  [unset]" );
	}

	// 2. unknown fields (newer client than the definitions)
	{
		CMsgClientLogon logon;
		logon.set_account_name( "x" );
		logon.mutable_unknown_fields()->AddVarint( 900, 31337 );
		logon.mutable_unknown_fields()->AddLengthDelimited( 901, "hello world" );
		auto packet = MakeProtoPacket( *store, 5514, []( google::protobuf::Message &, const google::protobuf::Reflection * ) {}, logon );
		const std::string text = NodeToText( decoder.Decode( packet.data(), packet.size(), "", DecodeOptions{} ) );
		CHECK_CONTAINS( text, "unknown fields" );
		CHECK_CONTAINS( text, "field 900 (varint): 31337" );
		CHECK_CONTAINS( text, "\"hello world\"" );
	}

	// 3. service method request + response
	{
		CPlayer_GetGameBadgeLevels_Request req; req.set_appid( 570 );
		auto packet = MakeProtoPacket( *store, 151, []( google::protobuf::Message &h, const google::protobuf::Reflection *r )
		{
			r->SetString( &h, h.GetDescriptor()->FindFieldByName( "target_job_name" ), "Player.GetGameBadgeLevels#1" );
		}, req );
		auto summary = decoder.Summarize( packet.data(), packet.size(), "" );
		CHECK( summary.inner == "Player.GetGameBadgeLevels#1" );
		CHECK( summary.emsgName == "ServiceMethodCallFromClient" );
		std::string text = NodeToText( decoder.Decode( packet.data(), packet.size(), "", DecodeOptions{} ) );
		CHECK_CONTAINS( text, "CPlayer_GetGameBadgeLevels_Request" );
		CHECK_CONTAINS( text, "appid (uint32): 570" );

		CPlayer_GetGameBadgeLevels_Response resp; resp.set_player_level( 42 ); auto *b = resp.add_badges(); b->set_level( 3 ); b->set_series( 1 );
		packet = MakeProtoPacket( *store, 147, []( google::protobuf::Message &h, const google::protobuf::Reflection *r )
		{
			r->SetString( &h, h.GetDescriptor()->FindFieldByName( "target_job_name" ), "Player.GetGameBadgeLevels#1" );
		}, resp );
		text = NodeToText( decoder.Decode( packet.data(), packet.size(), "", DecodeOptions{} ) );
		CHECK_CONTAINS( text, "CPlayer_GetGameBadgeLevels_Response" );
		CHECK_CONTAINS( text, "player_level (uint32): 42" );
		CHECK_CONTAINS( text, "level (int32): 3" );

		// unknown service method -> raw fields
		packet = MakeProtoPacket( *store, 151, []( google::protobuf::Message &h, const google::protobuf::Reflection *r )
		{
			r->SetString( &h, h.GetDescriptor()->FindFieldByName( "target_job_name" ), "Mystery.DoThing#1" );
		}, req );
		text = NodeToText( decoder.Decode( packet.data(), packet.size(), "", DecodeOptions{} ) );
		CHECK_CONTAINS( text, "field 1 (varint): 570" );
		CHECK_CONTAINS( text, "not in the protobuf definitions" );
	}

	// 4. legacy service method wrapper
	{
		CPlayer_GetGameBadgeLevels_Request req; req.set_appid( 730 );
		auto legacy = store->NewMessage( store->FindMessage( "CMsgClientServiceMethodLegacy" ) );
		auto *r = legacy->GetReflection();
		r->SetString( legacy.get(), legacy->GetDescriptor()->FindFieldByName( "method_name" ), "Player.GetGameBadgeLevels#1" );
		r->SetString( legacy.get(), legacy->GetDescriptor()->FindFieldByName( "serialized_method" ), req.SerializeAsString() );
		auto packet = MakeProtoPacket( *store, 5594, []( google::protobuf::Message &, const google::protobuf::Reflection * ) {}, *legacy );
		CHECK( decoder.Summarize( packet.data(), packet.size(), "" ).inner == "Player.GetGameBadgeLevels#1" );
		const std::string text = NodeToText( decoder.Decode( packet.data(), packet.size(), "", DecodeOptions{} ) );
		CHECK_CONTAINS( text, "Service Method Request" );
		CHECK_CONTAINS( text, "appid (uint32): 730" );
	}

	// 5. game coordinator message, descriptors only known through a descriptor set
	{
		std::string gcSetPath = ( work / "gc.desc" ).string();
		{
			FileDescriptorSet gcSet;
			for ( int i = 0; i < testSet.file_size(); i++ )
				if ( testSet.file( i ).name() == "gc_test.proto" ) *gcSet.add_file() = testSet.file( i );
			std::ofstream out( gcSetPath, std::ios::binary );
			gcSet.SerializeToOstream( &out );
		}

		auto gcStore = std::make_shared<DescriptorStore>();
		gcStore->Load( { fakeDll, gcSetPath }, cacheDir, false, logFn );
		PacketDecoder gcDecoder( gcStore );

		CMsgClientHello hello; hello.set_version( 7 ); hello.set_client_name( "tester" );
		std::string hdr;
		{
			auto header = gcStore->NewMessage( gcStore->FindMessage( "CMsgProtoBufHeader" ) );
			hdr = header->SerializeAsString();
		}

		std::vector<uint8_t> payload;
		PutU32( payload, 4006u | 0x80000000u );
		PutU32( payload, static_cast<uint32_t>( hdr.size() ) );
		payload.insert( payload.end(), hdr.begin(), hdr.end() );
		const std::string hb = hello.SerializeAsString();
		payload.insert( payload.end(), hb.begin(), hb.end() );

		auto gcMsg = gcStore->NewMessage( gcStore->FindMessage( "CMsgGCClient" ) );
		auto *r = gcMsg->GetReflection();
		auto *d = gcMsg->GetDescriptor();
		r->SetUInt32( gcMsg.get(), d->FindFieldByName( "appid" ), 570 );
		r->SetUInt32( gcMsg.get(), d->FindFieldByName( "msgtype" ), 4006u | 0x80000000u );
		r->SetString( gcMsg.get(), d->FindFieldByName( "payload" ), std::string( payload.begin(), payload.end() ) );

		auto packet = MakeProtoPacket( *gcStore, 5452, []( google::protobuf::Message &, const google::protobuf::Reflection * ) {}, *gcMsg );
		auto summary = gcDecoder.Summarize( packet.data(), packet.size(), "" );
		CHECK( summary.inner == "GCClientHello (app 570)" );
		const std::string text = NodeToText( gcDecoder.Decode( packet.data(), packet.size(), "", DecodeOptions{} ) );
		std::printf( "%s", text.c_str() );
		CHECK_CONTAINS( text, "Game Coordinator Message" );
		CHECK_CONTAINS( text, "CMsgClientHello" );
		CHECK_CONTAINS( text, "client_name (string): \"tester\"" );

		// same message without GC definitions: schemaless
		const std::string raw = NodeToText( decoder.Decode( packet.data(), packet.size(), "", DecodeOptions{} ) );
		CHECK_CONTAINS( raw, "no protobuf definition known" );
		CHECK_CONTAINS( raw, "\"tester\"" );
	}

	// 5b. extra .proto sources in per game folders, selected by app id
	{
		auto store = std::make_shared<DescriptorStore>();
		store->Load( { fakeDll }, cacheDir, false, logFn, "extra_protos" );
		PacketDecoder dec( store );

		CHECK( store->GameFolders().size() == 3 ); // csgo, tf2, (extra)
		const GameFolderInfo *csgo = nullptr, *tf2 = nullptr, *loose = nullptr;
		for ( const GameFolderInfo &g : store->GameFolders() )
		{
			if ( g.name == "csgo" ) csgo = &g;
			if ( g.name == "tf2" ) tf2 = &g;
			if ( g.name == "(extra)" ) loose = &g;
		}
		CHECK( csgo && tf2 && loose );
		if ( csgo && tf2 && loose )
		{
			CHECK( csgo->files == 2 && csgo->failed == 1 ); // broken.proto is rejected, the rest is fine
			CHECK( !csgo->firstError.empty() );
			CHECK( tf2->files >= 3 && tf2->failed == 0 ); // game_msgs.proto, shared.proto and descriptor.proto fallback
			CHECK( loose->shared && loose->files == 1 );
		}

		CHECK( FormatAppIds( store->EffectiveAppIds( "csgo" ) ) == "730" );
		CHECK( FormatAppIds( store->EffectiveAppIds( "/TF2/" ) ) == "440" );

		auto makeGcPacket = [ & ]( uint32_t appId, uint32_t msgType, const std::string &body )
		{
			auto header = store->NewMessage( store->FindMessage( "CMsgProtoBufHeader" ) );
			const std::string hdr = header->SerializeAsString();
			std::vector<uint8_t> payload;
			PutU32( payload, msgType | 0x80000000u );
			PutU32( payload, static_cast<uint32_t>( hdr.size() ) );
			payload.insert( payload.end(), hdr.begin(), hdr.end() );
			payload.insert( payload.end(), body.begin(), body.end() );

			auto gcMsg = store->NewMessage( store->FindMessage( "CMsgGCClient" ) );
			auto *r = gcMsg->GetReflection();
			auto *d = gcMsg->GetDescriptor();
			r->SetUInt32( gcMsg.get(), d->FindFieldByName( "appid" ), appId );
			r->SetUInt32( gcMsg.get(), d->FindFieldByName( "msgtype" ), msgType | 0x80000000u );
			r->SetString( gcMsg.get(), d->FindFieldByName( "payload" ), std::string( payload.begin(), payload.end() ) );
			return MakeProtoPacket( *store, 5452, []( google::protobuf::Message &, const google::protobuf::Reflection * ) {}, *gcMsg );
		};

		auto bodyFor = [ & ]( uint32_t appId, const char *field, const char *value )
		{
			const auto candidates = store->GCBodyCandidates( 5000, appId );
			CHECK( !candidates.empty() );
			if ( candidates.empty() )
				return std::string();
			auto msg = store->NewMessage( candidates[ 0 ] );
			const auto *f = msg->GetDescriptor()->FindFieldByName( field );
			CHECK( f != nullptr );
			if ( f->cpp_type() == google::protobuf::FieldDescriptor::CPPTYPE_UINT32 )
				msg->GetReflection()->SetUInt32( msg.get(), f, static_cast<uint32_t>( std::atoi( value ) ) );
			else
				msg->GetReflection()->SetString( msg.get(), f, value );
			return msg->SerializeAsString();
		};

		// the same message id means something different in each game
		{
			const auto pkt = makeGcPacket( 730, 5000, bodyFor( 730, "cs_value", "42" ) );
			CHECK( dec.Summarize( pkt.data(), pkt.size(), "" ).inner == "GCPing (app 730)" );
			const std::string text = NodeToText( dec.Decode( pkt.data(), pkt.size(), "", DecodeOptions{} ) );
			CHECK_CONTAINS( text, "cs_value (uint32): 42" );
			CHECK_CONTAINS( text, "definitions: csgo" );
		}
		{
			const auto pkt = makeGcPacket( 440, 5000, bodyFor( 440, "tf_text", "hello tf2" ) );
			const std::string text = NodeToText( dec.Decode( pkt.data(), pkt.size(), "", DecodeOptions{} ) );
			CHECK_CONTAINS( text, "tf_text (string): \"hello tf2\"" );
			CHECK_CONTAINS( text, "definitions: tf2" );
		}

		// message only the csgo folder has: not offered for the tf2 app, but offered for apps nobody claimed? (no: csgo is bound)
		CHECK( !store->GCBodyCandidates( 5002, 730 ).empty() );
		CHECK( store->GCBodyCandidates( 5002, 440 ).empty() );
		CHECK( store->GCBodyCandidates( 5002, 999 ).empty() );

		// loose files are used for every app
		CHECK( !store->GCBodyCandidates( 5001, 999 ).empty() );
		CHECK( store->DefinitionSourceOf( store->GCBodyCandidates( 5001, 730 )[ 0 ] ) == "(extra)" );

		// rebinding at runtime: csgo folder is now for every app, tf2 owns 730
		const uint64_t versionBefore = store->BindingsVersion();
		AppBindings custom;
		custom[ "tf2" ] = { 730 };
		custom[ "csgo" ] = {};
		store->SetAppBindings( custom );
		CHECK( store->BindingsVersion() != versionBefore );
		{
			const auto candidates = store->GCBodyCandidates( 5000, 730 );
			CHECK( candidates.size() == 2 );
			CHECK( !candidates.empty() && store->DefinitionSourceOf( candidates[ 0 ] ) == "tf2" );
			const auto other = store->GCBodyCandidates( 5000, 12345 );
			CHECK( other.size() == 1 && store->DefinitionSourceOf( other[ 0 ] ) == "csgo" );
		}

		// bindings file
		{
			const AppBindings parsed = ParseAppBindings( "# comment\n/csgo/ : 730\r\n TF2 : 440, 441 # more\nbad line\nempty :\nnope : abc\n" );
			CHECK( parsed.size() == 3 );
			CHECK( FormatAppIds( parsed.at( "csgo" ) ) == "730" );
			CHECK( FormatAppIds( parsed.at( "tf2" ) ) == "440, 441" );
			CHECK( parsed.at( "empty" ).empty() );

			const std::string path = ( work / "appids.txt" ).string();
			std::string error;
			CHECK( SaveAppBindingsFile( path, parsed, error ) );
			AppBindings reloaded;
			CHECK( LoadAppBindingsFile( path, reloaded ) && reloaded == parsed );
			CHECK( !LoadAppBindingsFile( ( work / "does_not_exist.txt" ).string(), reloaded ) );

			std::vector<uint32_t> ids;
			CHECK( ParseAppIds( " 730 ,440;570 730", ids ) && ids.size() == 3 );
			CHECK( !ParseAppIds( "73x", ids ) );
			CHECK( !ParseAppIds( "99999999999", ids ) );
		}
	}

	// 5c. optional: a real collection of game protos (NH2_REAL_PROTOS=<extra folder>)
	if ( const char *real = std::getenv( "NH2_REAL_PROTOS" ) )
	{
		auto store = std::make_shared<DescriptorStore>();
		store->Load( { fakeDll }, cacheDir, false, nullptr, real );
		PacketDecoder dec( store );

		for ( const GameFolderInfo &g : store->GameFolders() )
			std::printf( "  %-12s files=%zu failed=%zu messages=%zu gc ids=%zu app=%s\n", g.name.c_str(), g.files, g.failed, g.messages, g.gcMessages, FormatAppIds( store->EffectiveAppIds( g.name ) ).c_str() );

		const auto candidates = store->GCBodyCandidates( 9109, 730 );
		CHECK( !candidates.empty() );
		if ( !candidates.empty() )
			std::printf( "  csgo 9109 -> %s (%s)\n", candidates[ 0 ]->full_name().c_str(), store->DefinitionSourceOf( candidates[ 0 ] ).c_str() );
	}

	// 5d. locating functions: patterns, config overrides, structural fallback
	{
		// pattern parsing
		Pattern p;
		std::string error;
		CHECK( ParsePattern( "48 8B ?? 55", "", p, error ) && p.bytes.size() == 4 && p.mask == "xx?x" );
		CHECK( ParsePattern( "0x48 8b ? 55", "", p, error ) && p.mask == "xx?x" );
		CHECK( ParsePattern( "\\x48\\x8B\\xCC\\x55", "", p, error ) && p.mask == "xx?x" );          // 0xCC = wildcard without mask
		CHECK( ParsePattern( "\\x48\\x8B\\xCC\\x55", "xxxx", p, error ) && p.mask == "xxxx" );       // ...but not with one
		CHECK( ParsePattern( "48 8B 00 55", "xx?x", p, error ) && p.mask == "xx?x" );
		CHECK( FormatPattern( p ) == "48 8B ?? 55" );
		CHECK( !ParsePattern( "48 8B", "x", p, error ) && !error.empty() );                           // mask length
		CHECK( !ParsePattern( "48 ZZ", "", p, error ) );
		CHECK( !ParsePattern( "?? ??", "", p, error ) );                                              // matches everything
		CHECK( !ParsePattern( "", "", p, error ) );
		CHECK( !ParsePattern( "\\x48\\x8", "", p, error ) );

		// config file
		SigConfig cfg;
		std::vector<std::string> problems;
		const int bad = cfg.Parse(
			"; comment\r\n"
			"[x64]\r\n"
			"RecvPkt.sig = 48 8B C4 55 ?? ?? 48   ; trailing comment\r\n"
			"recvpkt.mask = xxxx??x\r\n"
			"PchMsgNameFromEMsg.rva = 0x1234\r\n"
			"Bogus.sig = 48 ZZ\r\n"
			"[x86]\r\n"
			"RecvPkt.sig = \"\\x55\\x8B\\xEC\"\r\n"
			"Mask.only.mask = xx\r\n"
			"garbage line\r\n"
			"[other]\r\n"
			"RecvPkt.sig = 11 22\r\n",
			[ & ]( const std::string &l ) { problems.push_back( l ); } );
		CHECK( bad == 4 ); // Bogus.sig, garbage, [other] section key, .mask without .sig
		CHECK( cfg.Count() == 3 );
		const SigOverride *o = cfg.Find( "x64", "RecvPkt" );
		CHECK( o && o->hasPattern && FormatPattern( o->pattern ) == "48 8B C4 55 ?? ?? 48" );
		o = cfg.Find( "X64", "pchmsgnamefromemsg" );
		CHECK( o && o->hasRva && o->rva == 0x1234 && !o->hasPattern );
		o = cfg.Find( "x86", "RecvPkt" );
		CHECK( o && o->hasPattern && o->pattern.bytes.size() == 3 );
		CHECK( cfg.Find( "x64", "Nope" ) == nullptr );

		SigConfig tmpl;
		CHECK( tmpl.Parse( DefaultSigConfigTemplate(), nullptr ) == 0 && tmpl.Count() == 0 ); // everything is commented out
		std::string uncommented;
		{
			std::istringstream in( DefaultSigConfigTemplate() );
			std::string line;
			while ( std::getline( in, line ) )
			{
				if ( line.rfind( "; ", 0 ) == 0 && ( line.find( ".sig =" ) != std::string::npos || line.rfind( "; [x", 0 ) == 0 || line.find( ".mask =" ) != std::string::npos ) )
					line = line.substr( 2 );
				uncommented += line + "\n";
			}
		}
		SigConfig live;
		CHECK( live.Parse( uncommented, nullptr ) == 0 && live.Count() == 5 ); // 4 x64 + 1 x86 examples are valid

		// [general] settings and in-place ini updates
		{
			SigConfig g;
			CHECK( g.Parse( "[general]\nDumpToDisk = 0 ; off\nOther = yes\n[x64]\nRecvPkt.rva = 0x10\n", nullptr ) == 0 );
			CHECK( !g.GetBool( "DumpToDisk", true ) && g.GetBool( "other", false ) && g.GetBool( "Missing", true ) );
			CHECK( g.Count() == 1 );

			const std::string path = ( work / "cfg_edit.ini" ).string();
			std::remove( path.c_str() );
			CHECK( SetIniValue( path, "general", "DumpToDisk", "0" ) ); // creates the file and the section
			SigConfig fromNew;
			CHECK( fromNew.Load( path, nullptr ) && !fromNew.GetBool( "DumpToDisk", true ) );

			{
				std::ofstream out( path, std::ios::binary | std::ios::trunc );
				out << "; keep me\r\n[x64]\r\nRecvPkt.rva = 0x10\r\n\r\n[general]\r\n; DumpToDisk = 0 (comment)\r\nDumpToDisk = 1\r\n\r\n[x86]\r\nRecvPkt.rva = 0x20\r\n";
			}
			CHECK( SetIniValue( path, "general", "DumpToDisk", "0" ) );
			CHECK( SetIniValue( path, "general", "Extra", "5" ) ); // new key goes into the existing section
			const std::vector<uint8_t> raw = ReadAll( path );
			const std::string text( raw.begin(), raw.end() );
			CHECK_CONTAINS( text, "; keep me\r\n[x64]\r\nRecvPkt.rva = 0x10\r\n" );
			CHECK_CONTAINS( text, "; DumpToDisk = 0 (comment)\r\nDumpToDisk = 0\r\nExtra = 5\r\n\r\n[x86]\r\nRecvPkt.rva = 0x20\r\n" );
			SigConfig reloaded;
			reloaded.Load( path, nullptr );
			CHECK( !reloaded.GetBool( "DumpToDisk", true ) && reloaded.Count() == 2 );

			{
				std::ofstream out( path, std::ios::binary | std::ios::trunc );
				out << "[x64]\nRecvPkt.rva = 0x10\n";
			}
			CHECK( SetIniValue( path, "general", "DumpToDisk", "1" ) ); // section appended, LF kept
			const std::vector<uint8_t> raw2 = ReadAll( path );
			CHECK( std::string( raw2.begin(), raw2.end() ) == "[x64]\nRecvPkt.rva = 0x10\n\n[general]\nDumpToDisk = 1\n" );
		}

		// a fake module
		const std::vector<uint8_t> module = MakeFakeModule( false );
		const ImageView image{ module.data(), module.size() };
		auto quiet = []( const std::string & ) {};

		size_t start = 0;
		CHECK( FunctionStartFromUnwindInfo( image, 0x1030, start ) && start == 0x1000 ); // chained entry -> primary entry
		CHECK( FunctionStartFromUnwindInfo( image, 0x1005, start ) && start == 0x1000 );
		CHECK( FunctionStartFromUnwindInfo( image, 0x1210, start ) && start == 0x1200 );
		CHECK( !FunctionStartFromUnwindInfo( image, 0x1100, start ) );
		CHECK( LooksLikeRecvPkt( image, 0x1000 ) );
		CHECK( !LooksLikeRecvPkt( image, 0x1200 ) );

		const auto referencing = FindFunctionsReferencingString( image, "CCMInterface::RecvPkt" );
		CHECK( referencing.size() == 2 && referencing[ 0 ] == 0x1000 && referencing[ 1 ] == 0x1200 ); // tail-of-longer-string decoy ignored

		// 1. built-in signature
		{
			LocateResult r = Locate( image, FakeRecvPktRequest(), SigConfig(), quiet );
			CHECK( r.ok && r.rva == 0x1000 && r.how == "signature #1" );
		}

		// 2. structural fallback when no signature matches
		{
			LocateRequest request = FakeRecvPktRequest();
			request.candidates = { { "\x48\x8B\xC4\x55\x48\x8D\xA8\x11\x11\x11\x11", "xxxxxxxxxxx" } };
			LocateResult r = Locate( image, request, SigConfig(), quiet );
			CHECK( r.ok && r.rva == 0x1000 && r.how == "code analysis" );
		}

		// 3. an ambiguous signature is never used
		{
			const std::vector<uint8_t> twice = MakeFakeModule( true );
			const ImageView twiceImage{ twice.data(), twice.size() };
			LocateRequest request = FakeRecvPktRequest();
			LocateResult r = Locate( twiceImage, request, SigConfig(), quiet );
			CHECK( r.ok && r.rva == 0x1000 && r.how == "code analysis" ); // fallback still finds the right one

			request.fallback = nullptr;
			CHECK( !Locate( twiceImage, request, SigConfig(), quiet ).ok );
		}

		// 4. a signature that matches the wrong code is rejected by the check
		{
			LocateRequest request = FakeRecvPktRequest();
			request.candidates = { { "\x48\x83\xEC\x28\x48\x8D\x0D", "xxxxxxx" } }; // the log helper
			request.fallback = nullptr;
			CHECK( !Locate( image, request, SigConfig(), quiet ).ok );
		}

		// 5. config overrides
		{
			SigConfig c;
			c.Parse( "[x64]\nRecvPkt.rva = 0x1200\n", nullptr );
			LocateResult r = Locate( image, FakeRecvPktRequest(), c, quiet );
			CHECK( r.ok && r.rva == 0x1200 && r.how == "config rva" );

			c.Parse( "[x64]\nRecvPkt.sig = 33 C0 48 83 C4 28 C3\n", nullptr );
			r = Locate( image, FakeRecvPktRequest(), c, quiet );
			CHECK( r.ok && r.rva == 0x1210 && r.how == "config signature" );

			c.Parse( "[x64]\nRecvPkt.sig = DE AD BE EF\nRecvPkt.rva = 0x10\n", nullptr ); // useless override: back to the built-ins
			r = Locate( image, FakeRecvPktRequest(), c, quiet );
			CHECK( r.ok && r.rva == 0x1000 );

			c.Parse( "[x86]\nRecvPkt.rva = 0x1200\n", nullptr ); // other architecture
			r = Locate( image, FakeRecvPktRequest(), c, quiet );
			CHECK( r.ok && r.rva == 0x1000 && r.how == "signature #1" );
		}

		// garbage must not crash anything
		{
			std::vector<uint8_t> junk( 0x3000, 0x90 );
			CHECK( !Locate( ImageView{ junk.data(), junk.size() }, FakeRecvPktRequest(), SigConfig(), quiet ).ok );
			CHECK( !Locate( ImageView{ nullptr, 0 }, FakeRecvPktRequest(), SigConfig(), quiet ).ok );
			std::vector<uint8_t> broken = module;
			Put32At( broken, 0x3084, 0x3084 ); // chain entry pointing at itself
			Put32At( broken, 0x3088, 0x3090 );
			Put32At( broken, 0x308C, 0x3081 ); // ...and an indirect unwind loop
			size_t unused = 0;
			FunctionStartFromUnwindInfo( ImageView{ broken.data(), broken.size() }, 0x1030, unused );
		}
	}

	// 5e. optional: real steamclient64.dll files (NH2_REAL_DLLS=a.dll:b.dll)
	if ( const char *dlls = std::getenv( "NH2_REAL_DLLS" ) )
	{
		std::string list = dlls;
		size_t pos = 0;
		while ( pos < list.size() )
		{
			size_t next = list.find( ':', pos );
			if ( next == std::string::npos ) next = list.size();
			const std::string path = list.substr( pos, next - pos );
			pos = next + 1;

			const std::vector<uint8_t> image = LoadModuleImage( path );
			CHECK( !image.empty() );
			if ( image.empty() )
				continue;

			const ImageView view{ image.data(), image.size() };
			LocateRequest request = FakeRecvPktRequest();
			const LocateResult bySignature = Locate( view, request, SigConfig(), []( const std::string & ) {} );
			request.candidates.clear();
			const LocateResult byCode = Locate( view, request, SigConfig(), []( const std::string & ) {} );
			std::printf( "  %s: RecvPkt 0x%zx (%s), by code analysis 0x%zx\n", path.c_str(), bySignature.rva, bySignature.how.c_str(), byCode.rva );
			CHECK( bySignature.ok && byCode.ok && bySignature.rva == byCode.rva );
		}
	}

	// 6. non protobuf messages and garbage must never crash
	{
		std::vector<uint8_t> p;
		PutU32( p, 5 ); // emsg 5, non proto
		p.push_back( 36 ); PutU16( p, 2 ); PutU64( p, 1 ); PutU64( p, 2 ); p.push_back( 239 ); PutU64( p, 76561197960287930ull ); PutU32( p, 77 );
		p.push_back( 0xDE ); p.push_back( 0xAD );
		const std::string text = NodeToText( decoder.Decode( p.data(), p.size(), "k_EMsgJoinChat", DecodeOptions{} ) );
		CHECK_CONTAINS( text, "(Non-Protobuf)" );
		CHECK_CONTAINS( text, "sessionID (int32): 77" );
		CHECK_CONTAINS( text, "DE AD" );
		auto s = decoder.Summarize( p.data(), p.size(), "" );
		CHECK( s.jobIdTarget == 1 && s.jobIdSource == 2 && s.sessionId == 77 );

		std::mt19937 rng( 5 );
		for ( int i = 0; i < 20000; i++ )
		{
			std::vector<uint8_t> junk( rng() % 80 );
			for ( auto &b : junk ) b = static_cast<uint8_t>( rng() );
			if ( junk.size() >= 4 && i % 2 ) { junk[ 3 ] |= 0x80; } // protobuf flag
			if ( junk.size() >= 8 && i % 3 == 0 ) { junk[ 4 ] = 8; junk[ 5 ] = junk[ 6 ] = junk[ 7 ] = 0; }
			if ( junk.size() >= 8 && i % 7 == 0 ) { junk[ 0 ] = 0x8A; junk[ 1 ] = 0x15; junk[ 2 ] = 0; } // 5514
			decoder.Summarize( junk.data(), junk.size(), "" );
			decoder.Decode( junk.data(), junk.size(), "", DecodeOptions{} );
		}
		std::printf( "  20000 random packets decoded without crashing\n" );
	}

	std::printf( g_failures == 0 ? "ALL TESTS PASSED\n" : "%d FAILURES\n", g_failures );
	return g_failures == 0 ? 0 : 1;
}
