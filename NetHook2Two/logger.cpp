
#include "logger.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <sstream>

#include "crypto.h"
#include "zip.h"
#include "binaryreader.h"

#include "steammessages_base.pb.h"
#include "ui/nh2_shared.h"


CLogger::CLogger() noexcept
{
	m_uiMsgNum = 0;
	char tempName[ MAX_PATH ];
	GetModuleFileName( nullptr, tempName, MAX_PATH );

	m_RootDir = tempName;
	m_RootDir = m_RootDir.substr( 0, m_RootDir.find_last_of( '\\' ) );
	m_RootDir += "\\nethook\\";

	// create root nethook log directory if it doesn't exist
	CreateDirectoryA( m_RootDir.c_str(), nullptr );

	time_t currentTime;
	time( &currentTime );

	std::ostringstream ss;
	ss << m_RootDir << currentTime << "\\";
	m_LogDir = ss.str();

	// the session directory is created lazily, right before the first file is written (see LogSessionData)
}


const std::string &CLogger::EnsureLogDir()
{
	if ( !m_bLogDirCreated )
	{
		CreateDirectoryA( m_RootDir.c_str(), nullptr );
		CreateDirectoryA( m_LogDir.c_str(), nullptr );
		m_bLogDirCreated = true;
	}
	return m_LogDir;
}


void CLogger::LogConsole( const char *szFmt, ... )
{
	va_list args;
	va_start( args, szFmt );

	va_list argsCopy;
	va_copy( argsCopy, args );
	const int buffSize = _vscprintf( szFmt, args ) + 1;
	va_end( args );

	if ( buffSize <= 1 )
	{
		va_end( argsCopy );
		return;
	}

	std::string text( static_cast<size_t>( buffSize ), '\0' );
	const int len = vsprintf_s( &text[ 0 ], static_cast<size_t>( buffSize ), szFmt, argsCopy );
	va_end( argsCopy );

	if ( len <= 0 )
		return;

	text.resize( static_cast<size_t>( len ) );

	// Shown in the Log tab of the NetHook2Two window.
	nh2win::g_logBuffer.Add( text );

	// ...and in the console, if there is one (it only exists if the window couldn't be created).
	HANDLE hOutput = GetStdHandle( STD_OUTPUT_HANDLE );
	if ( hOutput != nullptr && hOutput != INVALID_HANDLE_VALUE )
	{
		DWORD numWritten = 0;
		WriteFile( hOutput, text.c_str(), static_cast<DWORD>( text.size() ), &numWritten, nullptr );
	}
}

void CLogger::DeleteFile( const char *szFileName, bool bSession )
{
	std::string outputFile = ( bSession ? m_LogDir : m_RootDir );
	outputFile += szFileName;

	DeleteFileA( outputFile.c_str() );
}

void CLogger::LogNetMessage( ENetDirection eDirection, const uint8 *pData, uint32 cubData )
{
	if ( cubData < 4 )
		return;

	uint32 uiRawMsg;
	memcpy( &uiRawMsg, pData, sizeof( uiRawMsg ) );
	const EMsg eMsg = (EMsg)( uiRawMsg & 0x7FFFFFFFu );

	if ( eMsg == EMsg::k_EMsgMulti )
	{
		this->MultiplexMulti( eDirection, pData, cubData );
		return;
	}

	this->LogSessionData( eDirection, pData, cubData );
}

void CLogger::LogSessionData( ENetDirection eDirection, const uint8 *pData, uint32 cubData )
{
	uint32 uiRawMsg = 0;
	if ( cubData >= 4 )
		memcpy( &uiRawMsg, pData, sizeof( uiRawMsg ) );
	const EMsg eMsg = (EMsg)( uiRawMsg & 0x7FFFFFFFu );

	// Look the name up once; Steam knows its own message names best.
	const char *szName = g_pCrypto ? g_pCrypto->GetMessage( eMsg, 0xFF ) : nullptr;

	// Hand the packet to the live viewer. Its number is the one shown in the main window and used in the dump name.
	const uint64 packetId = nh2win::g_packetQueue.NextId();
	{
		nh2win::CapturedPacket packet;
		packet.id = packetId;

		FILETIME ft;
		GetSystemTimeAsFileTime( &ft );
		packet.fileTime = ( static_cast<uint64>( ft.dwHighDateTime ) << 32 ) | ft.dwLowDateTime;

		packet.outgoing = eDirection == ENetDirection::k_eNetOutgoing;
		packet.hookName = szName ? szName : "";
		packet.data.assign( pData, pData + cubData );
		nh2win::g_packetQueue.Push( std::move( packet ) );
	}

	if ( !nh2win::g_dumpToDisk )
		return;

	EnsureLogDir();

	std::string fullFile = m_LogDir;

	const char *outFile = GetFileNameBase( eDirection, eMsg, 0xFF, packetId );
	fullFile += outFile;

	std::string fullFileTmp = fullFile + ".tmp";
	std::string fullFileFinal = fullFile + ".bin";
	HANDLE hFile = CreateFile( fullFileTmp.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr );
	if ( hFile == INVALID_HANDLE_VALUE )
		return;

	DWORD numBytes = 0;
	WriteFile( hFile, pData, cubData, &numBytes, nullptr );

	CloseHandle( hFile );

	MoveFile( fullFileTmp.c_str(), fullFileFinal.c_str() );
}

HANDLE CLogger::OpenFile( const char *szFileName, bool bSession )
{
	if ( bSession )
		EnsureLogDir();
	std::string outputFile = ( bSession ? m_LogDir : m_RootDir );
	outputFile += szFileName;

	return CreateFile( outputFile.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr );
}

void CLogger::CloseFile( HANDLE hFile ) noexcept
{
	CloseHandle( hFile );
}

void CLogger::LogOpenFile( HANDLE hFile, const char *szFmt, ... )
{
	va_list args;
	va_start( args, szFmt );

	int buffSize = _vscprintf( szFmt, args ) + 1;

	if ( buffSize <= 1 )
		return;

	char *szBuff = new char[ buffSize ];
	memset( szBuff, 0, buffSize );

	const int len = vsprintf_s( szBuff, buffSize, szFmt, args );

	szBuff[ buffSize - 1 ] = 0;

	SetFilePointer( hFile, 0, nullptr, FILE_END );

	DWORD numBytes = 0;
	WriteFile( hFile, szBuff, len, &numBytes, nullptr );

	delete [] szBuff;
}

const char *CLogger::GetFileNameBase( ENetDirection eDirection, EMsg eMsg, uint8 serverType, uint64 packetId )
{
	static char szFileName[MAX_PATH];

	const char *szMsgName = g_pCrypto ? g_pCrypto->GetMessage( eMsg, serverType ) : nullptr;
	if ( szMsgName == nullptr )
		szMsgName = "";

	sprintf_s(
		szFileName, sizeof( szFileName ),
		"%03u_%s_%d_%s",
		static_cast<unsigned int>( packetId ),
		( eDirection == ENetDirection::k_eNetIncoming ? "in" : "out" ),
		static_cast<int>( eMsg ),
		szMsgName
	);

	return szFileName;
}

void CLogger::MultiplexMulti( ENetDirection eDirection, const uint8 *pData, uint32 cubData )
{
	struct ProtoHdr 
	{
		EMsg msg;
		int headerLength;
	};


	if ( cubData < sizeof( ProtoHdr ) )
		return;

	const ProtoHdr *pProtoHdr = (ProtoHdr*) pData;
	if ( pProtoHdr->headerLength < 0 || static_cast<uint32>( pProtoHdr->headerLength ) > cubData - sizeof( ProtoHdr ) )
	{
		g_pLogger->LogConsole("Invalid header length in multi message, ignoring\n");
		return;
	}


	CMsgProtoBufHeader protoheader;
	protoheader.ParseFromArray( pData + 8, pProtoHdr->headerLength );


	CMsgMulti multi;
	multi.ParseFromArray( pData + 8 + pProtoHdr->headerLength, cubData - 8 - pProtoHdr->headerLength );


	uint8 *pMsgData = nullptr;
	uint32 cubMsgData = 0;
	bool bDecomp = false;

	if ( multi.has_size_unzipped() && multi.size_unzipped() != 0 )
	{
		// decompress our data

		uint8 *pDecompressed = new uint8[ multi.size_unzipped() ];
		uint8 *pCompressed = (uint8 *)( multi.message_body().c_str() );
		const uint32 cubCompressed = multi.message_body().length();


		const bool bZip = CZip::Inflate( pCompressed, cubCompressed, pDecompressed, multi.size_unzipped() );

		if ( !bZip )
		{
			delete [] pDecompressed;

			g_pLogger->LogConsole("Unable to decompress buffer\n");
			return;
		}

		pMsgData = pDecompressed;
		cubMsgData = multi.size_unzipped();
		bDecomp = bZip;
	}
	else
	{
		pMsgData = (uint8 *)( multi.message_body().c_str() );
		cubMsgData = multi.message_body().length();
	}

	CBinaryReader reader( pMsgData, cubMsgData );

	while ( reader.GetSizeLeft() >= sizeof( uint32 ) )
	{
		const uint32 cubPayload = reader.Read<uint32>();
		if ( cubPayload > reader.GetSizeLeft() )
		{
			g_pLogger->LogConsole("Truncated message inside multi, ignoring the rest\n");
			break;
		}

		const uint8 *pPayload = reader.ReadBytes( cubPayload );

		this->LogNetMessage( eDirection, pPayload, cubPayload );
	}

	if ( bDecomp )
		delete [] pMsgData;
}
