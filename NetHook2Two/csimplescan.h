#ifndef CSIMPLESCAN_H
#define CSIMPLESCAN_H

#include "sigscan.h"
#include "core/locator.h"

#include "steam/steamtypes.h"

#ifdef X64BITS
#define NH_ARCH "x64"
#else
#define NH_ARCH "x86"
#endif

// Overrides read from <steam>\nethook\nethook2two_cfg.ini (loaded once at start).
extern nh2::SigConfig g_sigConfig;

class CSimpleScan
{

public:
	CSimpleScan() noexcept;
	CSimpleScan( const char *filename ) noexcept;

	bool SetDLL( const char *filename ) noexcept;
	bool FindFunction( const char *sig, const char *mask, void **func ) noexcept;

	// Finds a function with the strategies described in core/locator.h (nethook2two_cfg.ini override, built-in
	// signatures, structural fallback). Logs what it did.
	bool Locate( const nh2::LocateRequest &request, void **func ) noexcept;

private:
	bool m_bInterfaceSet;

	CreateInterfaceFn m_Interface;
	CSigScan m_Signature;

};

#endif //CSIMPLESCAN_H
