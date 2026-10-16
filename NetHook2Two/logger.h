

#ifndef NETHOOK_LOGGER_H_
#define NETHOOK_LOGGER_H_


#include <windows.h>
#include <string>

#include "steam/steamtypes.h"
#include "steam/emsg.h"

#ifdef DeleteFile
#undef DeleteFile
#endif

enum class ENetDirection
{
	k_eNetIncoming,
	k_eNetOutgoing,
};

class CLogger
{

public:
	CLogger() noexcept;

	void LogConsole( const char *szFmt, ... );
	void LogNetMessage( ENetDirection eDirection, const uint8 *pData, uint32 cubData );
	void LogSessionData( ENetDirection eDirection, const uint8 *pData, uint32 cubData );
	void LogOpenFile( HANDLE hFile, const char *szFmt, ... );

	HANDLE OpenFile( const char *szFileName, bool bSession );
	void CloseFile( HANDLE hFile) noexcept;
	void DeleteFile( const char *szFileName, bool bSession );

	const std::string &GetRootDir() const noexcept { return m_RootDir; }
	const std::string &GetLogDir() const noexcept { return m_LogDir; }

	// Creates the per-session dump folder on first use; returns its path.
	const std::string &EnsureLogDir();
	bool LogDirExists() const noexcept { return m_bLogDirCreated; }

private:
	const char *GetFileNameBase( ENetDirection eDirection, EMsg eMsg, uint8 serverType, uint64 packetId );
	void MultiplexMulti( ENetDirection eDirection, const uint8 *pData, uint32 cubData );

private:
	std::string m_RootDir;
	std::string m_LogDir;
	bool m_bLogDirCreated = false;

	uint32 m_uiMsgNum;

};

extern CLogger *g_pLogger;


#endif // !NETHOOK_LOGGER_H_
