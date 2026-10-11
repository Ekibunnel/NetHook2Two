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
#include <google/protobuf/stubs/common.h>

#include "../NetHook2Two/core/decoder.h"
#include "../NetHook2Two/core/descriptor_store.h"
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
