// State shared between the hook threads (which capture packets inside Steam) and the UI thread.
#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace nh2win
{

struct CapturedPacket
{
	uint64_t id = 0;          // 1, 2, 3... in capture order
	uint64_t fileTime = 0;    // Windows FILETIME (100ns since 1601, UTC)
	bool outgoing = false;
	std::string hookName;     // EMsg name as reported by Steam itself (may be empty)
	std::vector<uint8_t> data;
};

// Hook threads push, the UI thread drains. Holds the lock only for a move/swap.
class PacketQueue
{
public:
	void Push( CapturedPacket &&packet );
	void Drain( std::vector<CapturedPacket> &out );

	uint64_t NextId() { return ++lastId_; }

private:
	std::mutex mutex_;
	std::vector<CapturedPacket> pending_;
	std::atomic<uint64_t> lastId_{ 0 };
};

// Keeps the most recent log lines for the UI's log tab.
class LogBuffer
{
public:
	void Add( const std::string &text );
	// Copies lines added after `sinceCounter`; returns the new counter.
	uint64_t CopyNew( uint64_t sinceCounter, std::vector<std::string> &out );

private:
	std::mutex mutex_;
	std::deque<std::string> lines_;
	uint64_t counter_ = 0;
};

extern PacketQueue g_packetQueue;
extern LogBuffer g_logBuffer;
extern std::atomic<bool> g_dumpToDisk;   // also write the classic nethook/<time>/*.bin files
extern std::string g_cfgPath;              // <steam>\nethook\nethook2two_cfg.ini (empty until known)
extern std::atomic<bool> g_quitRequested; // set to unload NetHook2Two

inline void RequestShutdown() { g_quitRequested = true; }

} // namespace nh2win
