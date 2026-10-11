#include "descriptor_store.h"

#include "protoscan.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>

#include <google/protobuf/compiler/parser.h>
#include <google/protobuf/io/tokenizer.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/text_format.h>

namespace fs = std::filesystem;
using namespace google::protobuf;

namespace nh2
{

#include "builtin_base_descriptor.inc"

namespace
{

// Messages that NetHook2Two needs to be able to decode even if Steam's own definitions can't be loaded
// (or don't contain them). Names and numbers match what the Steam client uses on the wire.
const char kBuiltinExtraProto[] = R"PROTO(
name: "nethook2_builtin.proto"
message_type {
  name: "CMsgGCClient"
  field { name: "appid" number: 1 label: LABEL_OPTIONAL type: TYPE_UINT32 }
  field { name: "msgtype" number: 2 label: LABEL_OPTIONAL type: TYPE_UINT32 }
  field { name: "payload" number: 3 label: LABEL_OPTIONAL type: TYPE_BYTES }
  field { name: "steamid" number: 4 label: LABEL_OPTIONAL type: TYPE_FIXED64 }
  field { name: "gcname" number: 5 label: LABEL_OPTIONAL type: TYPE_STRING }
  field { name: "ip" number: 6 label: LABEL_OPTIONAL type: TYPE_UINT32 }
  field { name: "flags" number: 7 label: LABEL_OPTIONAL type: TYPE_UINT32 }
}
message_type {
  name: "CMsgClientServiceMethodLegacy"
  field { name: "method_name" number: 1 label: LABEL_OPTIONAL type: TYPE_STRING }
  field { name: "serialized_method" number: 2 label: LABEL_OPTIONAL type: TYPE_BYTES }
  field { name: "is_notification" number: 3 label: LABEL_OPTIONAL type: TYPE_BOOL }
}
message_type {
  name: "CMsgClientServiceMethodLegacyResponse"
  field { name: "method_name" number: 1 label: LABEL_OPTIONAL type: TYPE_STRING }
  field { name: "serialized_method_response" number: 2 label: LABEL_OPTIONAL type: TYPE_BYTES }
}
)PROTO";

// Port of NetHookAnalyzer2's MessageTypeOverrides.BodyMap (keys are EMsg names without prefix).
const std::map<std::string, std::string> &BodyOverrides()
{
	static const std::map<std::string, std::string> overrides = {
		{ "ClientLogonGameServer", "CMsgClientLogon" },
		{ "ClientGamesPlayed", "CMsgClientGamesPlayed" },
		{ "ClientGamesPlayedNoDataBlob", "CMsgClientGamesPlayed" },
		{ "ClientGamesPlayedWithDataBlob", "CMsgClientGamesPlayed" },
		{ "ClientToGC", "CMsgGCClient" },
		{ "ClientFromGC", "CMsgGCClient" },
		{ "ClientFriendMsgIncoming", "CMsgClientFriendMsgIncoming" },
		{ "ClientFriendMsgEchoToSender", "CMsgClientFriendMsgIncoming" },
		{ "ClientCurrentUIMode", "CMsgClientUIMode" },
		{ "ClientGetNumberOfCurrentPlayersDP", "CMsgDPGetNumberOfCurrentPlayers" },
		{ "ClientGetNumberOfCurrentPlayersDPResponse", "CMsgDPGetNumberOfCurrentPlayersResponse" },
		{ "AMGameServerUpdate", "CMsgGameServerData" },
		{ "ClientDPUpdateAppJobReport", "CDataPublisher_ClientUpdateAppJob_Notification" },
		{ "ClientPlayingSessionState", "CMsgClientPlayingSessionState" },
		{ "ClientNetworkingCertRequestResponse", "CMsgClientNetworkingCertReply" },
		{ "ClientServiceMethodLegacy", "CMsgClientServiceMethodLegacy" },
		{ "ClientServiceMethodLegacyResponse", "CMsgClientServiceMethodLegacyResponse" },
	};
	return overrides;
}

// Generic game coordinator "shared object" messages, used by every game.
const std::map<std::string, std::string> &GCBodyOverrides()
{
	static const std::map<std::string, std::string> overrides = {
		{ "ESOMsg_Create", "CMsgSOSingleObject" },
		{ "ESOMsg_Destroy", "CMsgSOSingleObject" },
		{ "ESOMsg_Update", "CMsgSOSingleObject" },
		{ "ESOMsg_UpdateMultiple", "CMsgSOMultipleObjects" },
		{ "ESOMsg_CacheSubscribed", "CMsgSOCacheSubscribed" },
		{ "ESOMsg_CacheUnsubscribed", "CMsgSOCacheUnsubscribed" },
		{ "ESOMsg_CacheSubscriptionCheck", "CMsgSOCacheSubscriptionCheck" },
		{ "ESOMsg_CacheSubscriptionRefresh", "CMsgSOCacheSubscriptionRefresh" },
	};
	return overrides;
}

std::string ToLower( std::string s )
{
	std::transform( s.begin(), s.end(), s.begin(), []( unsigned char c ) { return static_cast<char>( std::tolower( c ) ); } );
	return s;
}

void ReplaceAll( std::string &s, const std::string &what, const std::string &with )
{
	if ( what.empty() )
		return;

	size_t pos = 0;
	while ( ( pos = s.find( what, pos ) ) != std::string::npos )
	{
		s.replace( pos, what.size(), with );
		pos += with.size();
	}
}

bool StartsWith( const std::string &s, const char *prefix )
{
	return s.rfind( prefix, 0 ) == 0;
}

bool EndsWith( const std::string &s, const std::string &suffix )
{
	return s.size() >= suffix.size() && s.compare( s.size() - suffix.size(), suffix.size(), suffix ) == 0;
}

std::string StripEMsgPrefix( const std::string &name )
{
	if ( StartsWith( name, "k_EMsg" ) )
		return name.substr( 6 );
	if ( StartsWith( name, "k_" ) )
		return name.substr( 2 );
	return name;
}

bool IsDescriptorSetFile( const std::string &path )
{
	const std::string ext = ToLower( fs::path( path ).extension().string() );
	return ext == ".pb" || ext == ".pbset" || ext == ".desc" || ext == ".binpb";
}

bool ReadDescriptorSet( const std::string &path, std::vector<FileDescriptorProto> &out, std::string &error )
{
	std::ifstream in( path, std::ios::binary );
	if ( !in )
	{
		error = "unable to open " + path;
		return false;
	}

	FileDescriptorSet set;
	if ( !set.ParseFromIstream( &in ) )
	{
		error = "not a valid FileDescriptorSet: " + path;
		return false;
	}

	for ( int i = 0; i < set.file_size(); i++ )
		out.push_back( set.file( i ) );

	return true;
}

std::string Fingerprint( const fs::path &path )
{
	std::error_code ec;
	const auto size = fs::file_size( path, ec );
	if ( ec )
		return std::string();

	const auto time = fs::last_write_time( path, ec );
	if ( ec )
		return std::string();

	std::ostringstream ss;
	ss << std::hex << static_cast<unsigned long long>( size ) << "-" << static_cast<unsigned long long>( time.time_since_epoch().count() );
	return ss.str();
}

bool IsSafeRelativePath( const std::string &name )
{
	if ( name.empty() || name[ 0 ] == '/' || name[ 0 ] == '\\' || name.find( ':' ) != std::string::npos )
		return false;

	return name.find( ".." ) == std::string::npos;
}

class CollectingErrors : public DescriptorPool::ErrorCollector
{
public:
	void AddError( const std::string &filename, const std::string &element_name, const Message *, ErrorLocation, const std::string &message ) override
	{
		if ( first.empty() )
			first = element_name + ": " + message;
	}

	std::string first;
};


class ProtoParseErrors : public io::ErrorCollector
{
public:
	void AddError( int line, int column, const std::string &message ) override
	{
		if ( first.empty() )
			first = "line " + std::to_string( line + 1 ) + ":" + std::to_string( column + 1 ) + ": " + message;
	}

	std::string first;
};

// Parses .proto source text into a FileDescriptorProto, without needing protoc.
bool ParseProtoFile( const fs::path &path, const std::string &virtualName, FileDescriptorProto &out, std::string &error )
{
	std::ifstream in( path, std::ios::binary );
	if ( !in )
	{
		error = "unable to open file";
		return false;
	}

	std::ostringstream buffer;
	buffer << in.rdbuf();
	std::string text = buffer.str();

	if ( text.compare( 0, 3, "\xEF\xBB\xBF" ) == 0 )
		text.erase( 0, 3 );

	io::ArrayInputStream input( text.data(), static_cast<int>( text.size() ) );
	ProtoParseErrors errors;
	io::Tokenizer tokenizer( &input, &errors );
	compiler::Parser parser;
	parser.RecordErrorsTo( &errors );

	FileDescriptorProto parsed;
	if ( !parser.Parse( &tokenizer, &parsed ) )
	{
		error = errors.first.empty() ? std::string( "syntax error" ) : errors.first;
		return false;
	}

	parsed.set_name( virtualName );
	out = std::move( parsed );
	return true;
}

std::string NormalizeFolderName( const std::string &name )
{
	std::string s = name;
	const size_t b = s.find_first_not_of( " \t\r\n/\\" );
	if ( b == std::string::npos )
		return std::string();
	const size_t e = s.find_last_not_of( " \t\r\n/\\" );
	return ToLower( s.substr( b, e - b + 1 ) );
}

} // namespace


struct DescriptorStore::PoolHolder
{
	DescriptorPool pool;
	std::unique_ptr<DynamicMessageFactory> factory;
	std::vector<std::string> fileNames;

	PoolHolder()
	{
		// Steam's definitions import files we may not have (or that aren't interesting). Don't fail on those.
		pool.AllowUnknownDependencies();
		factory.reset( new DynamicMessageFactory( &pool ) );
	}
};


struct DescriptorStore::Group
{
	GameFolderInfo info;
	PoolHolder holder;
	std::unordered_map<std::string, const Descriptor *> byLowerName;
	std::vector<std::pair<std::string, const Descriptor *>> bySize;
	std::unordered_multimap<uint32_t, std::string> gcNames;
};


DescriptorStore::DescriptorStore() = default;
DescriptorStore::~DescriptorStore() = default;


void DescriptorStore::BuildPool( PoolHolder &holder, std::vector<FileDescriptorProto> &files, const LogFn &log, size_t &built, size_t &failed )
{
	std::map<std::string, size_t> index;
	for ( size_t i = 0; i < files.size(); i++ )
		index.emplace( files[ i ].name(), i );

	std::set<std::string> done;
	std::set<std::string> inProgress;

	std::function<void( const std::string & )> build = [ & ]( const std::string &name )
	{
		if ( done.count( name ) != 0 || inProgress.count( name ) != 0 )
			return;

		inProgress.insert( name );

		FileDescriptorProto fallback;
		const FileDescriptorProto *proto = nullptr;

		auto it = index.find( name );
		if ( it != index.end() )
		{
			proto = &files[ it->second ];
		}
		else if ( name == "google/protobuf/descriptor.proto" )
		{
			// Everything with options depends on this one. We always have it compiled in.
			FileDescriptorProto::descriptor()->file()->CopyTo( &fallback );
			proto = &fallback;
		}

		if ( proto != nullptr )
		{
			for ( int i = 0; i < proto->dependency_size(); i++ )
				build( proto->dependency( i ) );

			CollectingErrors errors;
			const FileDescriptor *fd = holder.pool.BuildFileCollectingErrors( *proto, &errors );
			if ( fd != nullptr )
			{
				holder.fileNames.push_back( name );
				built++;
			}
			else
			{
				failed++;
				if ( log )
					log( "  could not use " + name + ": " + errors.first );
			}
		}

		inProgress.erase( name );
		done.insert( name );
	};

	// When two files define the same symbol only the first one can be used. Prefer the files other files depend on.
	std::map<std::string, int> importedBy;
	for ( const auto &f : files )
	{
		for ( int i = 0; i < f.dependency_size(); i++ )
			importedBy[ f.dependency( i ) ]++;
	}

	std::vector<std::string> order;
	for ( const auto &entry : index )
		order.push_back( entry.first );

	std::stable_sort( order.begin(), order.end(), [ & ]( const std::string &a, const std::string &b )
	{
		const int ca = importedBy.count( a ) ? importedBy[ a ] : 0;
		const int cb = importedBy.count( b ) ? importedBy[ b ] : 0;
		return ca > cb;
	} );

	for ( const std::string &name : order )
		build( name );
}


void DescriptorStore::IndexPool( PoolHolder &holder, bool isBuiltin )
{
	for ( const std::string &fileName : holder.fileNames )
	{
		const FileDescriptor *fd = holder.pool.FindFileByName( fileName );
		if ( fd == nullptr )
			continue;

		for ( int i = 0; i < fd->message_type_count(); i++ )
		{
			const Descriptor *d = fd->message_type( i );
			const std::string lower = ToLower( d->name() );

			if ( messagesByLowerName_.emplace( lower, d ).second )
				messagesBySize_.emplace_back( lower, d );
		}

		if ( isBuiltin )
			continue;

		serviceCount_ += static_cast<size_t>( fd->service_count() );

		for ( int i = 0; i < fd->enum_type_count(); i++ )
		{
			const EnumDescriptor *e = fd->enum_type( i );
			const bool isEMsg = e->full_name() == "EMsg";

			for ( int v = 0; v < e->value_count(); v++ )
			{
				const EnumValueDescriptor *value = e->value( v );

				if ( isEMsg )
				{
					if ( value->number() >= 0 )
						emsgNames_.emplace( static_cast<uint32_t>( value->number() ), StripEMsgPrefix( value->name() ) );
				}
				else if ( value->number() >= 0 && ( StartsWith( value->name(), "k_EMsg" ) || StartsWith( value->name(), "k_ESOMsg" ) ) )
				{
					gcNames_.emplace( static_cast<uint32_t>( value->number() ), value->name() );
				}
			}
		}
	}
}


void DescriptorStore::LoadBuiltins( const LogFn &log )
{
	builtin_.reset( new PoolHolder() );

	std::vector<FileDescriptorProto> files;

	FileDescriptorProto base;
	if ( base.ParseFromArray( kBuiltinBaseDescriptor, static_cast<int>( sizeof( kBuiltinBaseDescriptor ) ) ) )
		files.push_back( std::move( base ) );

	FileDescriptorProto extra;
	if ( TextFormat::ParseFromString( kBuiltinExtraProto, &extra ) )
		files.push_back( std::move( extra ) );

	size_t built = 0, failed = 0;
	BuildPool( *builtin_, files, log, built, failed );
}


void DescriptorStore::Load( const std::vector<std::string> &targets, const std::string &cacheDir, bool forceRescan, const LogFn &log,
	const std::string &extraProtoDir )
{
	auto say = [ & ]( const std::string &s ) { if ( log ) log( s ); };

	steam_.reset( new PoolHolder() );
	targets_.clear();

	std::vector<FileDescriptorProto> files;
	std::set<std::string> seen;
	bool scannedAnything = false;

	std::error_code ec;
	if ( !cacheDir.empty() )
		fs::create_directories( cacheDir, ec );

	for ( const std::string &target : targets )
	{
		TargetStatus status;
		status.path = target;

		const auto started = std::chrono::steady_clock::now();
		std::vector<FileDescriptorProto> fromTarget;
		std::string error;

		if ( IsDescriptorSetFile( target ) )
		{
			if ( ReadDescriptorSet( target, fromTarget, error ) )
				status.state = "descriptor set";
			else
			{
				status.state = "error";
				status.detail = error;
			}
		}
		else if ( !fs::exists( target, ec ) )
		{
			status.state = "missing";
		}
		else
		{
			const std::string fingerprint = Fingerprint( target );
			const std::string fileName = fs::path( target ).filename().string();
			const fs::path cacheFile = cacheDir.empty() || fingerprint.empty() ? fs::path() : fs::path( cacheDir ) / ( fileName + "." + fingerprint + ".pbset" );

			bool haveCache = false;
			if ( !forceRescan && !cacheFile.empty() && fs::exists( cacheFile, ec ) )
			{
				std::string cacheError;
				haveCache = ReadDescriptorSet( cacheFile.string(), fromTarget, cacheError ) && !fromTarget.empty();
				if ( !haveCache )
				{
					fromTarget.clear();
					say( "Cached protobufs for " + fileName + " are unusable (" + cacheError + "), rescanning." );
				}
			}

			if ( haveCache )
			{
				status.state = "cache";
			}
			else
			{
				say( "Scanning " + fileName + " for embedded protobufs..." );

				std::set<std::string> localSeen;
				ScanStats stats;
				if ( ScanFileForDescriptors( target, fromTarget, localSeen, stats, error ) )
				{
					status.state = "scanned";
					status.detail = std::to_string( stats.invalid ) + " invalid candidates skipped";
					scannedAnything = true;

					if ( !cacheFile.empty() && !fromTarget.empty() )
					{
						// Remove caches of older versions of this binary, then write the new one.
						for ( const auto &entry : fs::directory_iterator( cacheDir, ec ) )
						{
							const std::string name = entry.path().filename().string();
							if ( StartsWith( name, ( fileName + "." ).c_str() ) && EndsWith( name, ".pbset" ) && entry.path() != cacheFile )
								fs::remove( entry.path(), ec );
						}

						FileDescriptorSet set;
						for ( const auto &f : fromTarget )
							*set.add_file() = f;

						std::ofstream out( cacheFile, std::ios::binary | std::ios::trunc );
						if ( out )
							set.SerializeToOstream( &out );
					}
				}
				else
				{
					status.state = "error";
					status.detail = error;
				}
			}
		}

		status.files = fromTarget.size();
		status.seconds = std::chrono::duration<double>( std::chrono::steady_clock::now() - started ).count();

		for ( auto &f : fromTarget )
		{
			if ( seen.insert( f.name() ).second )
				files.push_back( std::move( f ) );
		}

		say( "  " + target + ": " + status.state + ( status.files ? ", " + std::to_string( status.files ) + " files" : std::string() ) + ( status.detail.empty() ? std::string() : " (" + status.detail + ")" ) );
		targets_.push_back( std::move( status ) );
	}

	size_t built = 0, failed = 0;
	BuildPool( *steam_, files, log, built, failed );
	fileCount_ = built;
	failedFiles_ = failed;

	LoadBuiltins( log );
	LoadExtraProtos( extraProtoDir, log );

	messagesByLowerName_.clear();
	messagesBySize_.clear();
	serviceCount_ = 0;
	emsgNames_.clear();
	gcNames_.clear();

	IndexPool( *steam_, false );
	IndexPool( *builtin_, true );

	std::stable_sort( messagesBySize_.begin(), messagesBySize_.end(),
		[]( const auto &a, const auto &b ) { return a.first.size() < b.first.size(); } );

	// Only count messages from Steam's definitions for the statistics.
	messageCount_ = 0;
	for ( const std::string &fileName : steam_->fileNames )
	{
		const FileDescriptor *fd = steam_->pool.FindFileByName( fileName );
		if ( fd != nullptr )
			messageCount_ += static_cast<size_t>( fd->message_type_count() );
	}

	// Human readable .proto dumps next to the cache, like ProtobufDumper would produce.
	if ( scannedAnything && !cacheDir.empty() )
	{
		for ( const std::string &fileName : steam_->fileNames )
		{
			if ( !IsSafeRelativePath( fileName ) )
				continue;

			const FileDescriptor *fd = steam_->pool.FindFileByName( fileName );
			if ( fd == nullptr )
				continue;

			const fs::path out = fs::path( cacheDir ) / "protos" / fs::path( fileName );
			fs::create_directories( out.parent_path(), ec );
			std::ofstream stream( out, std::ios::binary | std::ios::trunc );
			if ( stream )
				stream << fd->DebugString();
		}
	}

	std::ostringstream summary;
	summary << fileCount_ << " proto files, " << messageCount_ << " messages, " << serviceCount_ << " services";
	if ( failed != 0 )
		summary << " (" << failed << " files rejected)";
	if ( !gameFolders_.empty() )
	{
		size_t extraFiles = 0, extraFailed = 0;
		for ( const GameFolderInfo &g : gameFolders_ )
		{
			extraFiles += g.files;
			extraFailed += g.failed;
		}
		summary << "; " << gameFolders_.size() << " extra folders: " << extraFiles << " files";
		if ( extraFailed != 0 )
			summary << " (" << extraFailed << " failed)";
	}
	summary_ = summary.str();

	say( "Protobuf definitions ready: " + summary_ );
}


void DescriptorStore::LoadExtraProtos( const std::string &extraProtoDir, const LogFn &log )
{
	groups_.clear();
	gameFolders_.clear();

	if ( extraProtoDir.empty() )
		return;

	std::error_code ec;
	if ( !fs::is_directory( extraProtoDir, ec ) )
		return;

	struct Source
	{
		fs::path path;
		std::string virtualName;
	};

	auto loadGroup = [ & ]( const std::string &name, bool shared, const std::vector<Source> &sources )
	{
		std::unique_ptr<Group> group( new Group() );
		group->info.name = name;
		group->info.shared = shared;

		std::vector<FileDescriptorProto> files;
		std::set<std::string> names;

		for ( const Source &source : sources )
		{
			if ( IsDescriptorSetFile( source.path.string() ) )
			{
				std::vector<FileDescriptorProto> set;
				std::string error;
				if ( ReadDescriptorSet( source.path.string(), set, error ) )
				{
					for ( auto &f : set )
					{
						if ( names.insert( f.name() ).second )
							files.push_back( std::move( f ) );
					}
				}
				else
				{
					group->info.failed++;
					if ( group->info.firstError.empty() )
						group->info.firstError = source.virtualName + ": " + error;
					if ( log )
						log( "  " + name + "/" + source.virtualName + ": " + error );
				}
				continue;
			}

			FileDescriptorProto proto;
			std::string error;
			if ( ParseProtoFile( source.path, source.virtualName, proto, error ) )
			{
				if ( names.insert( proto.name() ).second )
					files.push_back( std::move( proto ) );
			}
			else
			{
				group->info.failed++;
				if ( group->info.firstError.empty() )
					group->info.firstError = source.virtualName + ": " + error;
				if ( log )
					log( "  " + name + "/" + source.virtualName + ": " + error );
			}
		}

		size_t built = 0, failed = 0;
		BuildPool( group->holder, files, [ & ]( const std::string &line )
		{
			if ( group->info.firstError.empty() )
			{
				const size_t at = line.find( "could not use " );
				group->info.firstError = at == std::string::npos ? line : line.substr( at + 14 );
			}
			if ( log )
				log( "  [" + name + "] " + line );
		}, built, failed );

		group->info.files = built;
		group->info.failed += failed;

		for ( const std::string &fileName : group->holder.fileNames )
		{
			const FileDescriptor *fd = group->holder.pool.FindFileByName( fileName );
			if ( fd == nullptr || StartsWith( fileName, "google/protobuf/" ) )
				continue;

			for ( int i = 0; i < fd->message_type_count(); i++ )
			{
				const Descriptor *d = fd->message_type( i );
				const std::string lower = ToLower( d->name() );
				if ( group->byLowerName.emplace( lower, d ).second )
					group->bySize.emplace_back( lower, d );
				group->info.messages++;
			}

			for ( int i = 0; i < fd->enum_type_count(); i++ )
			{
				const EnumDescriptor *e = fd->enum_type( i );
				for ( int v = 0; v < e->value_count(); v++ )
				{
					const EnumValueDescriptor *value = e->value( v );
					if ( value->number() >= 0 && e->full_name() != "EMsg" && ( StartsWith( value->name(), "k_EMsg" ) || StartsWith( value->name(), "k_ESOMsg" ) ) )
					{
						group->gcNames.emplace( static_cast<uint32_t>( value->number() ), value->name() );
						group->info.gcMessages++;
					}
				}
			}
		}

		std::stable_sort( group->bySize.begin(), group->bySize.end(),
			[]( const auto &a, const auto &b ) { return a.first.size() < b.first.size(); } );

		if ( log )
		{
			log( "  extra folder " + name + ": " + std::to_string( group->info.files ) + " files, " + std::to_string( group->info.messages ) + " messages, " +
				std::to_string( group->info.gcMessages ) + " GC message ids" +
				( group->info.failed ? ", " + std::to_string( group->info.failed ) + " failed" : std::string() ) );
		}

		gameFolders_.push_back( group->info );
		groups_.push_back( std::move( group ) );
	};

	// Loose files directly in the extra folder.
	std::vector<Source> loose;
	std::vector<fs::path> folders;

	for ( const auto &entry : fs::directory_iterator( extraProtoDir, ec ) )
	{
		if ( entry.is_directory( ec ) )
		{
			folders.push_back( entry.path() );
		}
		else if ( entry.is_regular_file( ec ) && ToLower( entry.path().extension().string() ) == ".proto" )
		{
			loose.push_back( { entry.path(), entry.path().filename().generic_string() } );
		}
	}

	std::sort( folders.begin(), folders.end() );

	for ( const fs::path &folder : folders )
	{
		std::vector<Source> sources;
		for ( const auto &entry : fs::recursive_directory_iterator( folder, fs::directory_options::skip_permission_denied, ec ) )
		{
			if ( !entry.is_regular_file( ec ) )
				continue;

			const std::string ext = ToLower( entry.path().extension().string() );
			if ( ext != ".proto" && !IsDescriptorSetFile( entry.path().string() ) )
				continue;

			const std::string relative = fs::relative( entry.path(), folder, ec ).generic_string();
			if ( ec || !IsSafeRelativePath( relative ) )
				continue;

			sources.push_back( { entry.path(), relative } );
		}

		if ( sources.empty() )
			continue;

		std::sort( sources.begin(), sources.end(), []( const Source &a, const Source &b ) { return a.virtualName < b.virtualName; } );
		loadGroup( folder.filename().string(), false, sources );
	}

	if ( !loose.empty() )
		loadGroup( "(extra)", true, loose );
}

void DescriptorStore::SetAppBindings( const AppBindings &bindings ) const
{
	AppBindings normalized;
	for ( const auto &entry : bindings )
	{
		const std::string key = NormalizeFolderName( entry.first );
		if ( !key.empty() )
			normalized[ key ] = entry.second;
	}

	std::lock_guard<std::mutex> lock( bindingsMutex_ );
	bindings_ = std::move( normalized );
	bindingsVersion_++;
}

AppBindings DescriptorStore::ExplicitAppBindings() const
{
	std::lock_guard<std::mutex> lock( bindingsMutex_ );
	return bindings_;
}

uint64_t DescriptorStore::BindingsVersion() const
{
	std::lock_guard<std::mutex> lock( bindingsMutex_ );
	return bindingsVersion_;
}

std::vector<uint32_t> DescriptorStore::EffectiveAppIds( const std::string &folderName ) const
{
	const std::string key = NormalizeFolderName( folderName );

	{
		std::lock_guard<std::mutex> lock( bindingsMutex_ );
		auto it = bindings_.find( key );
		if ( it != bindings_.end() )
			return it->second;
	}

	return DefaultAppIdsForFolder( key );
}

std::vector<const DescriptorStore::Group *> DescriptorStore::GroupsForApp( uint32_t appId ) const
{
	std::vector<const Group *> bound, unbound, shared;

	for ( const auto &group : groups_ )
	{
		if ( group->info.shared )
		{
			shared.push_back( group.get() );
			continue;
		}

		const std::vector<uint32_t> ids = EffectiveAppIds( group->info.name );
		if ( ids.empty() )
			unbound.push_back( group.get() );
		else if ( appId != 0 && std::find( ids.begin(), ids.end(), appId ) != ids.end() )
			bound.push_back( group.get() );
	}

	bound.insert( bound.end(), unbound.begin(), unbound.end() );
	bound.insert( bound.end(), shared.begin(), shared.end() );
	return bound;
}

std::string DescriptorStore::DefinitionSourceOf( const Descriptor *descriptor ) const
{
	if ( descriptor == nullptr )
		return std::string();

	for ( const auto &group : groups_ )
	{
		if ( descriptor->file()->pool() == &group->holder.pool )
			return group->info.name;
	}

	return std::string();
}


AppBindings ParseAppBindings( const std::string &text )
{
	AppBindings result;
	std::istringstream in( text );
	std::string line;

	while ( std::getline( in, line ) )
	{
		const size_t hash = line.find( '#' );
		if ( hash != std::string::npos )
			line.erase( hash );

		const size_t colon = line.find( ':' );
		if ( colon == std::string::npos )
			continue;

		const std::string folder = NormalizeFolderName( line.substr( 0, colon ) );
		if ( folder.empty() )
			continue;

		std::vector<uint32_t> ids;
		if ( ParseAppIds( line.substr( colon + 1 ), ids ) )
			result[ folder ] = std::move( ids );
	}

	return result;
}

std::string FormatAppBindings( const AppBindings &bindings )
{
	std::ostringstream out;
	out << "# NetHook2Two: which extra protobuf folder belongs to which game (app id).\n"
		   "# Format: <folder> : <appid>[, <appid>...]   An empty list means \"consult this folder for every app\".\n";
	for ( const auto &entry : bindings )
		out << "/" << entry.first << "/ : " << FormatAppIds( entry.second ) << "\n";
	return out.str();
}

bool LoadAppBindingsFile( const std::string &path, AppBindings &out )
{
	std::ifstream in( path, std::ios::binary );
	if ( !in )
		return false;

	std::ostringstream buffer;
	buffer << in.rdbuf();
	out = ParseAppBindings( buffer.str() );
	return true;
}

bool SaveAppBindingsFile( const std::string &path, const AppBindings &bindings, std::string &error )
{
	std::error_code ec;
	const fs::path p( path );
	if ( p.has_parent_path() )
		fs::create_directories( p.parent_path(), ec );

	std::ofstream out( p, std::ios::binary | std::ios::trunc );
	if ( !out )
	{
		error = "unable to write " + path;
		return false;
	}

	out << FormatAppBindings( bindings );
	return static_cast<bool>( out );
}

bool ParseAppIds( const std::string &text, std::vector<uint32_t> &out )
{
	out.clear();

	std::string token;
	auto flush = [ & ]() -> bool
	{
		if ( token.empty() )
			return true;
		if ( token.size() > 10 )
			return false;
		for ( char c : token )
		{
			if ( c < '0' || c > '9' )
				return false;
		}
		const unsigned long long value = std::stoull( token );
		if ( value > 0xFFFFFFFFull )
			return false;
		if ( value != 0 && std::find( out.begin(), out.end(), static_cast<uint32_t>( value ) ) == out.end() )
			out.push_back( static_cast<uint32_t>( value ) );
		token.clear();
		return true;
	};

	for ( char c : text )
	{
		if ( c == ',' || c == ';' || c == ' ' || c == '\t' || c == '\r' || c == '\n' )
		{
			if ( !flush() )
				return false;
		}
		else
			token.push_back( c );
	}

	return flush();
}

std::string FormatAppIds( const std::vector<uint32_t> &ids )
{
	std::string s;
	for ( size_t i = 0; i < ids.size(); i++ )
		s += ( i ? ", " : "" ) + std::to_string( ids[ i ] );
	return s;
}

std::vector<uint32_t> DefaultAppIdsForFolder( const std::string &folderName )
{
	static const std::map<std::string, std::vector<uint32_t>> defaults = {
		{ "csgo", { 730 } },
		{ "cs2", { 730 } },
		{ "tf2", { 440 } },
		{ "dota2", { 570 } },
		{ "deadlock", { 1422450 } },
		{ "underlords", { 1046930 } },
		{ "artifact", { 583950, 1269260 } },
	};

	auto it = defaults.find( NormalizeFolderName( folderName ) );
	return it == defaults.end() ? std::vector<uint32_t>() : it->second;
}


const Descriptor *DescriptorStore::FindMessage( const std::string &fullName ) const
{
	if ( steam_ )
	{
		if ( const Descriptor *d = steam_->pool.FindMessageTypeByName( fullName ) )
			return d;
	}

	if ( builtin_ )
		return builtin_->pool.FindMessageTypeByName( fullName );

	return nullptr;
}

const ServiceDescriptor *DescriptorStore::FindService( const std::string &name ) const
{
	if ( steam_ )
	{
		if ( const ServiceDescriptor *s = steam_->pool.FindServiceByName( name ) )
			return s;
	}

	if ( builtin_ )
		return builtin_->pool.FindServiceByName( name );

	return nullptr;
}

std::unique_ptr<Message> DescriptorStore::NewMessage( const Descriptor *descriptor ) const
{
	if ( descriptor == nullptr )
		return nullptr;

	PoolHolder *holder = nullptr;
	if ( steam_ && descriptor->file()->pool() == &steam_->pool )
		holder = steam_.get();
	else if ( builtin_ && descriptor->file()->pool() == &builtin_->pool )
		holder = builtin_.get();
	else
	{
		for ( const auto &group : groups_ )
		{
			if ( descriptor->file()->pool() == &group->holder.pool )
			{
				holder = &group->holder;
				break;
			}
		}
	}

	if ( holder == nullptr )
		return nullptr;

	const Message *prototype = holder->factory->GetPrototype( descriptor );
	if ( prototype == nullptr )
		return nullptr;

	return std::unique_ptr<Message>( prototype->New() );
}

std::string DescriptorStore::EMsgName( uint32_t emsg ) const
{
	auto it = emsgNames_.find( emsg );
	return it == emsgNames_.end() ? std::string() : it->second;
}

const Descriptor *DescriptorStore::FindMessageByLowerName( const std::string &lowerName ) const
{
	auto it = messagesByLowerName_.find( lowerName );
	return it == messagesByLowerName_.end() ? nullptr : it->second;
}

const Descriptor *DescriptorStore::ComputeBodyForEMsg( const std::string &emsgName ) const
{
	const auto &overrides = BodyOverrides();
	auto override = overrides.find( emsgName );
	if ( override != overrides.end() )
	{
		if ( const Descriptor *d = FindMessage( override->second ) )
			return d;
	}

	const std::string lower = ToLower( emsgName );
	if ( const Descriptor *d = FindMessageByLowerName( "cmsg" + lower ) )
		return d;

	// The analyzer also tried again without "Econ" and "AM" in the name.
	std::string alt = emsgName;
	ReplaceAll( alt, "Econ", "" );
	ReplaceAll( alt, "AM", "" );
	if ( alt != emsgName )
	{
		if ( const Descriptor *d = FindMessageByLowerName( "cmsg" + ToLower( alt ) ) )
			return d;
	}

	// ...and finally any CMsg type that ends with the EMsg name. Shortest first.
	if ( lower.size() >= 6 )
	{
		for ( const auto &candidate : messagesBySize_ )
		{
			if ( candidate.first.size() > lower.size() + 4 && StartsWith( candidate.first, "cmsg" ) && EndsWith( candidate.first, lower ) )
				return candidate.second;
		}
	}

	return nullptr;
}

const Descriptor *DescriptorStore::FindBodyForEMsg( uint32_t emsg, const std::string &emsgName ) const
{
	std::string name = emsgName.empty() ? EMsgName( emsg ) : StripEMsgPrefix( emsgName );
	if ( name.empty() )
		return nullptr;

	std::lock_guard<std::mutex> lock( cacheMutex_ );

	auto it = bodyCache_.find( name );
	if ( it != bodyCache_.end() )
		return it->second;

	const Descriptor *result = ComputeBodyForEMsg( name );
	bodyCache_.emplace( name, result );
	return result;
}

namespace
{

std::vector<std::string> RawNamesFor( const std::unordered_multimap<uint32_t, std::string> &names, uint32_t id )
{
	std::vector<std::string> result;
	auto range = names.equal_range( id );
	for ( auto it = range.first; it != range.second; ++it )
		result.push_back( it->second );
	std::sort( result.begin(), result.end() );
	return result;
}

// Same name mangling as NetHookAnalyzer2's MessageTypeFinder.GetGCMessageBodyTypeCandidates. Finds message types
// for the given enum value names, using `findExact` for "CMsg<name>" and `bySize` for suffix matches.
void CollectGCCandidates( const std::vector<std::string> &rawNames,
	const std::function<const Descriptor *( const std::string & )> &findExact,
	const std::vector<std::pair<std::string, const Descriptor *>> &bySize,
	std::vector<const Descriptor *> &result )
{
	auto add = [ & ]( const Descriptor *d )
	{
		if ( d != nullptr && std::find( result.begin(), result.end(), d ) == result.end() )
			result.push_back( d );
	};

	for ( const std::string &fullName : rawNames )
	{
		const std::string withoutK = fullName.substr( 2 ); // strip "k_"

		auto override = GCBodyOverrides().find( withoutK );
		if ( override != GCBodyOverrides().end() )
		{
			add( findExact( override->second ) );
			continue;
		}

		std::string typeName = fullName;
		ReplaceAll( typeName, "k_", "" );
		ReplaceAll( typeName, "ESOMsg", "" );
		typeName.erase( 0, typeName.find_first_not_of( '_' ) );
		ReplaceAll( typeName, "EMsg", "" );
		while ( StartsWith( typeName, "GC" ) )
			typeName.erase( 0, 2 );

		if ( typeName.empty() )
			continue;

		const size_t before = result.size();

		add( findExact( "CMsg" + typeName ) );

		for ( const auto &candidate : bySize )
		{
			const std::string &candidateName = candidate.second->name();
			if ( StartsWith( candidateName, "CMsg" ) && EndsWith( candidateName, typeName ) )
				add( candidate.second );
		}

		// Some enums carry a version digit the message doesn't have (..._ClientRequestWatchInfoFriends2).
		if ( result.size() == before && std::isdigit( static_cast<unsigned char>( typeName.back() ) ) )
		{
			std::string trimmed = typeName;
			while ( !trimmed.empty() && std::isdigit( static_cast<unsigned char>( trimmed.back() ) ) )
				trimmed.pop_back();

			if ( trimmed.size() >= 6 )
			{
				for ( const auto &candidate : bySize )
				{
					const std::string &candidateName = candidate.second->name();
					if ( StartsWith( candidateName, "CMsg" ) && EndsWith( candidateName, trimmed ) )
						add( candidate.second );
				}
			}
		}
	}
}

} // namespace

std::vector<std::string> DescriptorStore::GCMessageNames( uint32_t gcMsg, uint32_t appId ) const
{
	std::vector<std::string> names;

	auto addAll = [ & ]( const std::vector<std::string> &raw )
	{
		for ( const std::string &n : raw )
		{
			const std::string stripped = StripEMsgPrefix( n );
			if ( std::find( names.begin(), names.end(), stripped ) == names.end() )
				names.push_back( stripped );
		}
	};

	for ( const Group *group : GroupsForApp( appId ) )
		addAll( RawNamesFor( group->gcNames, gcMsg ) );

	addAll( RawNamesFor( gcNames_, gcMsg ) );
	return names;
}

std::vector<const Descriptor *> DescriptorStore::GCBodyCandidates( uint32_t gcMsg, uint32_t appId ) const
{
	std::vector<const Descriptor *> result;

	for ( const Group *group : GroupsForApp( appId ) )
	{
		const std::vector<std::string> raw = RawNamesFor( group->gcNames, gcMsg );
		if ( raw.empty() )
			continue;

		CollectGCCandidates( raw,
			[ group ]( const std::string &name ) -> const Descriptor *
			{
				auto it = group->byLowerName.find( ToLower( name ) );
				return it == group->byLowerName.end() ? nullptr : it->second;
			},
			group->bySize, result );
	}

	CollectGCCandidates( RawNamesFor( gcNames_, gcMsg ),
		[ this ]( const std::string &name ) { return FindMessage( name ); },
		messagesBySize_, result );

	return result;
}

} // namespace nh2
