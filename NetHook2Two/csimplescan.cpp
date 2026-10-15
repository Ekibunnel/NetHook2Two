

#include "csimplescan.h"
#include "logger.h"
#include <assert.h>

#define CREATEINTERFACE_PROCNAME	"CreateInterface"

// load/unload components
//class CSysModule;

//-----------------------------------------------------------------------------
// Purpose: returns a pointer to a function, given a module
// Input  : pModuleName - module name
//			*pName - proc name
//-----------------------------------------------------------------------------
static void *Sys_GetProcAddress( const char *pModuleName, const char *pName ) noexcept
{
	HMODULE hModule = GetModuleHandle( pModuleName );
	assert(hModule != nullptr);
	return GetProcAddress( hModule, pName );
}

//-----------------------------------------------------------------------------
// Purpose: returns the instance of the named module
// Input  : *pModuleName - name of the module
// Output : interface_instance_t - instance of that module
//-----------------------------------------------------------------------------
CreateInterfaceFn Sys_GetFactory( const char *pModuleName ) noexcept
{
#ifdef _WIN32
	return static_cast<CreateInterfaceFn>( Sys_GetProcAddress( pModuleName, CREATEINTERFACE_PROCNAME ) );
#elif defined(_LINUX)
	// see Sys_GetFactory( CSysModule *pModule ) for an explanation
	return (CreateInterfaceFn)( Sys_GetProcAddress( pModuleName, CREATEINTERFACE_PROCNAME ) );
#endif
}


CSimpleScan::CSimpleScan() noexcept
{
	m_bInterfaceSet = false;
	m_Interface = nullptr;
}

CSimpleScan::CSimpleScan( const char *filename ) noexcept
{
	SetDLL( filename );
}

bool CSimpleScan::SetDLL( const char *filename ) noexcept
{
	m_Interface = Sys_GetFactory( filename );

	CSigScan::sigscan_dllfunc = m_Interface;

	if (!CSigScan::GetDllMemInfo())
	{
		m_bInterfaceSet = false;
	}
	else
	{
		m_bInterfaceSet = (m_Interface != nullptr);
	}

	return m_bInterfaceSet;
}

bool CSimpleScan::FindFunction( const char * sig, const char *mask, void **func ) noexcept
{
	if ( !m_bInterfaceSet )
		return false;

	
	m_Signature.Init( ( unsigned char * )sig, ( char * )mask, strlen( mask ) );

	if ( !m_Signature.is_set )
		return false;

	*func = m_Signature.sig_addr;

	return true;
}


nh2::SigConfig g_sigConfig;

static void DoLocate( const nh2::ImageView *image, const nh2::LocateRequest *request, nh2::LocateResult *result ) noexcept
{
	try
	{
		*result = nh2::Locate( *image, *request, g_sigConfig,
			[]( const std::string &line ) { g_pLogger->LogConsole( "%s\n", line.c_str() ); } );
	}
	catch ( ... )
	{
	}
}

// Reading a module that was unmapped or partly protected must not take Steam down with us.
static bool SafeLocate( const nh2::ImageView *image, const nh2::LocateRequest *request, nh2::LocateResult *result ) noexcept
{
#ifdef _MSC_VER
	__try
	{
		DoLocate( image, request, result );
		return true;
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		return false;
	}
#else
	DoLocate( image, request, result );
	return true;
#endif
}

bool CSimpleScan::Locate( const nh2::LocateRequest &request, void **func ) noexcept
{
	if ( !m_bInterfaceSet )
		return false;

	nh2::ImageView image;
	const unsigned char *base = nullptr;
	size_t length = 0;
	if ( !CSigScan::GetImage( &base, &length ) )
		return false;

	image.base = base;
	image.size = length;

	nh2::LocateResult result;
	if ( !SafeLocate( &image, &request, &result ) )
	{
		g_pLogger->LogConsole( "%s: scanning the module failed unexpectedly.\n", request.name.c_str() );
		return false;
	}

	if ( !result.ok )
		return false;

	*func = const_cast<unsigned char *>( base ) + result.rva;
	g_pLogger->LogConsole( "%s found via %s.\n", request.name.c_str(), result.how.c_str() );
	return true;
}
