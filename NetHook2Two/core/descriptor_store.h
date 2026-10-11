// Runtime protobuf definitions for NetHook2Two.
//
// The store scans Steam's own binaries (see protoscan.h) for the protobuf definitions they embed,
// builds a descriptor pool out of them and answers "which protobuf type is this message?" questions.
// Because the definitions come from the Steam client that is running right now, they are always current.
// Results are cached on disk, keyed by size + modification time of the scanned binary, so a Steam update
// is picked up automatically on the next start while an unchanged client starts instantly.
//
// Portable C++ (no Windows headers).
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/dynamic_message.h>

namespace nh2
{

using LogFn = std::function<void( const std::string & )>;

// A game folder inside nethook\protobufs\extra (for example "csgo"), made of .proto sources and/or descriptor sets.
// Every folder gets its own descriptor pool, so different games can ship their own versions of the same file.
struct GameFolderInfo
{
	std::string name;           // folder name as found on disk ("(extra)" for loose files in the extra folder itself)
	bool shared = false;        // loose files: always consulted, can't be bound to an app
	size_t files = 0;           // files that made it into the pool
	size_t failed = 0;          // files that could not be parsed / used
	size_t messages = 0;        // top level message types
	size_t gcMessages = 0;      // k_EMsg*/k_ESOMsg* enum values (game coordinator message ids)
	std::string firstError;
};

// folder name (lower case) -> app ids whose game coordinator messages use that folder.
using AppBindings = std::map<std::string, std::vector<uint32_t>>;

// "csgo : 730" / "/tf2/ : 440, 123" per line, '#' starts a comment. Folder names are normalized to lower case.
AppBindings ParseAppBindings( const std::string &text );
std::string FormatAppBindings( const AppBindings &bindings );
bool LoadAppBindingsFile( const std::string &path, AppBindings &out );
bool SaveAppBindingsFile( const std::string &path, const AppBindings &bindings, std::string &error );

// "730, 440" <-> ids. ParseAppIds returns false when something isn't a number.
bool ParseAppIds( const std::string &text, std::vector<uint32_t> &out );
std::string FormatAppIds( const std::vector<uint32_t> &ids );

// App ids for well known folder names (csgo -> 730, tf2 -> 440, ...). Used until the user binds the folder explicitly.
std::vector<uint32_t> DefaultAppIdsForFolder( const std::string &folderName );

struct TargetStatus
{
	std::string path;
	std::string state; // "scanned", "cache", "missing", "error"
	std::string detail;
	size_t files = 0;
	double seconds = 0;
};

class DescriptorStore
{
public:
	DescriptorStore();
	~DescriptorStore();

	DescriptorStore( const DescriptorStore & ) = delete;
	DescriptorStore &operator=( const DescriptorStore & ) = delete;

	// Builds the store. Call once, before sharing the store with other threads.
	//   targets:     Steam binaries to scan (e.g. steamclient64.dll). Files ending in .pb/.pbset/.desc/.binpb
	//                are read as serialized FileDescriptorSets instead (handy for game coordinator protos).
	//   cacheDir:    where scan results and .proto dumps are stored. Empty disables caching.
	//   forceRescan: ignore existing caches.
	//   extraProtoDir: optional folder with game sub folders full of .proto files (see GameFolderInfo). Loose
	//                .proto files directly inside it are loaded as a shared group.
	void Load( const std::vector<std::string> &targets, const std::string &cacheDir, bool forceRescan, const LogFn &log,
		const std::string &extraProtoDir = std::string() );

	// Message / service lookup. Steam-provided definitions win, built-in fallbacks are used if missing.
	const google::protobuf::Descriptor *FindMessage( const std::string &fullName ) const;
	const google::protobuf::ServiceDescriptor *FindService( const std::string &name ) const;

	// Creates an empty message of the given type (nullptr for null descriptors).
	std::unique_ptr<google::protobuf::Message> NewMessage( const google::protobuf::Descriptor *descriptor ) const;

	// Name of an EMsg from Steam's EMsg enum, without the "k_EMsg" prefix. Empty if unknown.
	std::string EMsgName( uint32_t emsg ) const;

	// Finds the protobuf type that is used as body of a top-level message. Port of NetHookAnalyzer2's
	// MessageTypeFinder.GetProtobufMessageBodyType, but working on runtime descriptors.
	const google::protobuf::Descriptor *FindBodyForEMsg( uint32_t emsg, const std::string &emsgName ) const;

	// Game coordinator message ids are reused between games, so this returns every plausible name
	// (enum value name) and body type for a given id, best candidate first.
	// `appId` selects the game folders to look into: folders bound to the app first, then folders that aren't bound to
	// any app, then loose extra files, and finally the definitions found in Steam's binaries. appId 0 = unknown app.
	std::vector<std::string> GCMessageNames( uint32_t gcMsg, uint32_t appId = 0 ) const;
	std::vector<const google::protobuf::Descriptor *> GCBodyCandidates( uint32_t gcMsg, uint32_t appId = 0 ) const;

	// Name of the extra game folder a descriptor came from; empty for Steam's own / built-in definitions.
	std::string DefinitionSourceOf( const google::protobuf::Descriptor *descriptor ) const;

	// Game folders and their app bindings. Bindings can be changed at any time from any thread.
	const std::vector<GameFolderInfo> &GameFolders() const { return gameFolders_; }
	void SetAppBindings( const AppBindings &bindings ) const;
	AppBindings ExplicitAppBindings() const;
	std::vector<uint32_t> EffectiveAppIds( const std::string &folderName ) const;
	uint64_t BindingsVersion() const;

	// Statistics for the UI.
	const std::vector<TargetStatus> &Targets() const { return targets_; }
	size_t FileCount() const { return fileCount_; }
	size_t MessageCount() const { return messageCount_; }
	size_t ServiceCount() const { return serviceCount_; }
	size_t FailedFileCount() const { return failedFiles_; }
	bool HasSteamDefinitions() const { return fileCount_ > 0; }
	const std::string &Summary() const { return summary_; }

private:
	struct PoolHolder;
	struct Group;

	void BuildPool( PoolHolder &holder, std::vector<google::protobuf::FileDescriptorProto> &files, const LogFn &log, size_t &built, size_t &failed );
	void IndexPool( PoolHolder &holder, bool isBuiltin );
	void LoadBuiltins( const LogFn &log );
	void LoadExtraProtos( const std::string &extraProtoDir, const LogFn &log );
	std::vector<const Group *> GroupsForApp( uint32_t appId ) const;
	const google::protobuf::Descriptor *ComputeBodyForEMsg( const std::string &emsgName ) const;
	const google::protobuf::Descriptor *FindMessageByLowerName( const std::string &lowerName ) const;

	std::unique_ptr<PoolHolder> steam_;
	std::unique_ptr<PoolHolder> builtin_;
	std::vector<std::unique_ptr<Group>> groups_;
	std::vector<GameFolderInfo> gameFolders_;

	mutable std::mutex bindingsMutex_;
	mutable AppBindings bindings_;
	mutable uint64_t bindingsVersion_ = 0;

	std::vector<TargetStatus> targets_;
	size_t fileCount_ = 0;
	size_t messageCount_ = 0;
	size_t serviceCount_ = 0;
	size_t failedFiles_ = 0;
	std::string summary_;

	std::map<uint32_t, std::string> emsgNames_;
	std::unordered_multimap<uint32_t, std::string> gcNames_;

	// Top-level message types by lower case name, and the same names sorted by length for suffix lookups.
	std::unordered_map<std::string, const google::protobuf::Descriptor *> messagesByLowerName_;
	std::vector<std::pair<std::string, const google::protobuf::Descriptor *>> messagesBySize_;

	mutable std::mutex cacheMutex_;
	mutable std::unordered_map<std::string, const google::protobuf::Descriptor *> bodyCache_;
};

} // namespace nh2
