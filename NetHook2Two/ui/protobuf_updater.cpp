#include "protobuf_updater.h"

#include "nh2_shared.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <filesystem>
#include <fstream>

#include "../steamclient.h"

namespace fs = std::filesystem;

namespace nh2win
{

namespace
{

std::mutex g_publishedMutex;
std::shared_ptr<const nh2::DescriptorStore> g_published;

std::string ModulePath( HMODULE module )
{
	char buffer[ MAX_PATH * 2 ] = {};
	const DWORD len = GetModuleFileNameA( module, buffer, static_cast<DWORD>( sizeof( buffer ) ) );
	return std::string( buffer, len );
}

std::string Trim( const std::string &s )
{
	const size_t b = s.find_first_not_of( " \t\r\n\"" );
	if ( b == std::string::npos )
		return std::string();
	const size_t e = s.find_last_not_of( " \t\r\n\"" );
	return s.substr( b, e - b + 1 );
}

} // namespace


ProtobufUpdater::~ProtobufUpdater()
{
	if ( thread_.joinable() )
		thread_.join();
}

std::shared_ptr<const nh2::DescriptorStore> ProtobufUpdater::Current() const
{
	std::lock_guard<std::mutex> lock( mutex_ );
	return current_;
}

std::string ProtobufUpdater::CacheDir() const
{
	// <steam>\nethook\protobufs
	const std::string exe = ModulePath( nullptr );
	const size_t slash = exe.find_last_of( "\\/" );
	const std::string root = slash == std::string::npos ? std::string( "." ) : exe.substr( 0, slash );
	return root + "\\nethook\\protobufs";
}

std::string ProtobufUpdater::ExtraDir() const
{
	return CacheDir() + "\\extra";
}

std::string ProtobufUpdater::BindingsPath() const
{
	return ( fs::path( CacheDir() ).parent_path() / "protobuf_appids.txt" ).string();
}

bool ProtobufUpdater::SaveBindings( const nh2::AppBindings &bindings, std::string &error )
{
	if ( !nh2::SaveAppBindingsFile( BindingsPath(), bindings, error ) )
		return false;

	std::shared_ptr<const nh2::DescriptorStore> store = Current();
	if ( store )
		store->SetAppBindings( bindings );

	return true;
}

void ProtobufUpdater::Start( bool forceRescan )
{
	if ( running_.exchange( true ) )
		return;

	if ( thread_.joinable() )
		thread_.join();

	thread_ = std::thread( [ this, forceRescan ]()
	{
		try
		{
			Run( forceRescan );
		}
		catch ( const std::exception &e )
		{
			g_logBuffer.Add( std::string( "Protobuf update failed: " ) + e.what() );
		}
		catch ( ... )
		{
			g_logBuffer.Add( "Protobuf update failed with an unknown error." );
		}

		running_ = false;
	} );
}

void ProtobufUpdater::Run( bool forceRescan )
{
	const std::string cacheDir = CacheDir();

	std::vector<std::string> targets;

	// 1. The Steam client library that is actually loaded in this process.
	HMODULE steamClient = GetModuleHandleA( STEAMCLIENT_DLL );
	if ( steamClient != nullptr )
		targets.push_back( ModulePath( steamClient ) );
	else
		g_logBuffer.Add( std::string( STEAMCLIENT_DLL ) + " is not loaded in this process, protobuf definitions can't be updated." );

	// 2. Optional extras: a list of more binaries / descriptor sets to scan (e.g. a game's executable or a
	//    .pb produced by `protoc --descriptor_set_out`), one path per line.
	const fs::path extraList = fs::path( cacheDir ).parent_path() / "protobuf_targets.txt";
	std::error_code ec;
	if ( fs::exists( extraList, ec ) )
	{
		std::ifstream in( extraList );
		std::string line;
		while ( std::getline( in, line ) )
		{
			line = Trim( line );
			if ( !line.empty() && line[ 0 ] != '#' )
				targets.push_back( line );
		}
	}

	// 3. Anything dropped into nethook\protobufs\extra
	const fs::path extraDir = fs::path( cacheDir ) / "extra";
	if ( fs::exists( extraDir, ec ) )
	{
		// Loose files are binaries / descriptor sets to scan. .proto sources and game folders are handled by
		// the store itself (extra\\<game>\\*.proto).
		for ( const auto &entry : fs::directory_iterator( extraDir, ec ) )
		{
			if ( !entry.is_regular_file( ec ) )
				continue;

			std::string ext = entry.path().extension().string();
			for ( char &c : ext )
				c = static_cast<char>( tolower( static_cast<unsigned char>( c ) ) );

			if ( ext != ".proto" )
				targets.push_back( entry.path().string() );
		}
	}

	g_logBuffer.Add( "Updating protobuf definitions..." );

	auto store = std::make_shared<nh2::DescriptorStore>();
	store->Load( targets, cacheDir, forceRescan, []( const std::string &line ) { g_logBuffer.Add( line ); }, extraDir.string() );

	nh2::AppBindings bindings;
	if ( nh2::LoadAppBindingsFile( BindingsPath(), bindings ) )
		store->SetAppBindings( bindings );

	{
		std::lock_guard<std::mutex> lock( mutex_ );
		current_ = std::move( store );
	}
	{
		std::lock_guard<std::mutex> lock( g_publishedMutex );
		g_published = Current();
	}

	version_++;
}

std::shared_ptr<const nh2::DescriptorStore> PublishedDescriptorStore()
{
	std::lock_guard<std::mutex> lock( g_publishedMutex );
	return g_published;
}

} // namespace nh2win
