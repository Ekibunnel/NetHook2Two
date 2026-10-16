// Keeps NetHook2Two's protobuf definitions in sync with the Steam client it is running in.
//
// On start (and on request) a worker thread scans steamclient(64).dll for embedded protobuf definitions
// (see core/protoscan.h), using a cache that is invalidated whenever the binary changes. The finished
// DescriptorStore is published atomically; the UI picks it up on its next frame.
#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "../core/descriptor_store.h"

namespace nh2win
{

class ProtobufUpdater
{
public:
	ProtobufUpdater() = default;
	~ProtobufUpdater();

	// Starts scanning in the background (no-op while a scan is already running).
	void Start( bool forceRescan );

	bool IsRunning() const { return running_; }
	std::shared_ptr<const nh2::DescriptorStore> Current() const;
	uint64_t Version() const { return version_; }

	std::string CacheDir() const;

	// <steam>\nethook\protobufs\extra: game folders full of .proto files (extra\csgo\*.proto, ...).
	std::string ExtraDir() const;

	// <steam>\nethook\protobuf_appids.txt: which extra folder belongs to which app id (game coordinator messages).
	std::string BindingsPath() const;

	// Applies and persists new bindings (also on the store that is currently published).
	bool SaveBindings( const nh2::AppBindings &bindings, std::string &error );

private:
	void Run( bool forceRescan );

	std::thread thread_;
	std::atomic<bool> running_{ false };
	std::atomic<uint64_t> version_{ 0 };

	mutable std::mutex mutex_;
	std::shared_ptr<const nh2::DescriptorStore> current_;
};

// The store the running ProtobufUpdater published last (null until the first scan finished). Safe to call from any thread.
std::shared_ptr<const nh2::DescriptorStore> PublishedDescriptorStore();

} // namespace nh2win
