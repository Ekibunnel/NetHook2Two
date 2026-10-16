#include "nh2_shared.h"

#include <algorithm>

namespace nh2win
{

PacketQueue g_packetQueue;
LogBuffer g_logBuffer;
std::atomic<bool> g_dumpToDisk{ true };
std::string g_cfgPath;
std::atomic<bool> g_quitRequested{ false };

void PacketQueue::Push( CapturedPacket &&packet )
{
	std::lock_guard<std::mutex> lock( mutex_ );
	pending_.push_back( std::move( packet ) );
}

void PacketQueue::Drain( std::vector<CapturedPacket> &out )
{
	std::lock_guard<std::mutex> lock( mutex_ );
	if ( out.empty() )
		out.swap( pending_ );
	else
	{
		for ( auto &p : pending_ )
			out.push_back( std::move( p ) );
		pending_.clear();
	}
}

void LogBuffer::Add( const std::string &text )
{
	std::lock_guard<std::mutex> lock( mutex_ );

	size_t start = 0;
	while ( start < text.size() )
	{
		size_t end = text.find( '\n', start );
		if ( end == std::string::npos )
			end = text.size();

		std::string line = text.substr( start, end - start );
		while ( !line.empty() && line.back() == '\r' )
			line.pop_back();

		if ( !line.empty() )
		{
			lines_.push_back( std::move( line ) );
			counter_++;
			if ( lines_.size() > 3000 )
				lines_.pop_front();
		}

		start = end + 1;
	}
}

uint64_t LogBuffer::CopyNew( uint64_t sinceCounter, std::vector<std::string> &out )
{
	std::lock_guard<std::mutex> lock( mutex_ );

	const uint64_t available = counter_ - sinceCounter;
	const size_t count = static_cast<size_t>( std::min<uint64_t>( available, lines_.size() ) );
	for ( size_t i = lines_.size() - count; i < lines_.size(); i++ )
		out.push_back( lines_[ i ] );

	return counter_;
}

} // namespace nh2win
