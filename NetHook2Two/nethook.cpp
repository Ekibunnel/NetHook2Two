#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <google/protobuf/stubs/common.h>

#include "logger.h"
#include "crypto.h"
#include "net.h"
#include "steamclient.h"

#include "nh2_string.h"

#include "steammessages_base.pb.h"
#include "version.h"

#include "ui/nh2_shared.h"
#include "ui/protobuf_updater.h"
#include "ui/ui.h"

CLogger *g_pLogger = NULL;
CCrypto* g_pCrypto = NULL;
NetHook::CNet *g_pNet = NULL;

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

static BOOL g_bOwnsConsole = FALSE;

BOOL IsRunDll32()
{
	char szMainModulePath[MAX_PATH];
	DWORD dwMainModulePathLength = GetModuleFileNameA(NULL, szMainModulePath, sizeof(szMainModulePath));

	return stringCaseInsensitiveEndsWith(szMainModulePath, "\\rundll32.exe");
}

void PrintVersionInfo()
{
	g_pLogger->LogConsole("Initializing NetHook2Two...\n");

	if (*g_szBuiltFromCommitSha == '\0')
	{
		g_pLogger->LogConsole("Built at %s. No further build information available.\n", g_szBuildDate);
	}
	else
	{
		g_pLogger->LogConsole("Built at %s from %s", g_szBuildDate, g_szBuiltFromCommitSha);

		if (g_bBuiltFromDirty)
		{
			g_pLogger->LogConsole("/dirty");
		}

		g_pLogger->LogConsole(" (%s)\n", g_szBuiltFromCommitDate);
	}
}

//
// Called (through a remote thread) by `rundll32 NetHook2Two.dll,Eject`. It only asks the NetHook2Two thread to shut down;
// that thread then removes the hooks, destroys the window and unloads the DLL itself. Unloading from a remote
// FreeLibrary call isn't possible any more now that NetHook2Two owns a thread and a window.
//
extern "C" __declspec(dllexport) DWORD WINAPI NetHook2Two_RemoteEject(LPVOID)
{
	nh2win::RequestShutdown();
	return 0;
}

//
// The NetHook2Two thread: everything lives here, nothing heavy runs in DllMain (loader lock).
//
static DWORD WINAPI NetHook2TwoMain(LPVOID)
{
	// Take an extra reference to ourselves so the DLL can't be unloaded under this thread.
	HMODULE hSelf = NULL;
	GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)&NetHook2TwoMain, &hSelf);

	GOOGLE_PROTOBUF_VERIFY_VERSION;
	// Garbage packets make protobuf complain on stderr, which doesn't exist in Steam.
	google::protobuf::SetLogHandler(nullptr);

	LoadLibraryA(STEAMCLIENT_DLL);

	g_pLogger = new CLogger();
	PrintVersionInfo();

	// The window first, so that anything that goes wrong afterwards is visible in its log.
	const std::string iniPath = g_pLogger->GetRootDir() + "nethook2_ui.ini";
	char szError[256] = {};
	const bool bUi = nh2win::UiCreate("NetHook2Two", iniPath.c_str(), szError, sizeof(szError));

	if (!bUi)
	{
		g_bOwnsConsole = AllocConsole();
		g_pLogger->LogConsole("Unable to create the NetHook2Two window (%s). Falling back to console and dump files only.\n", szError);
	}

	g_pCrypto = new CCrypto();
	g_pNet = new NetHook::CNet();

	{
		nh2win::ProtobufUpdater updater;
		updater.Start(false);

		if (bUi)
		{
			nh2win::UiRun(updater);
		}
		else
		{
			while (!nh2win::g_quitRequested)
				Sleep(100);
		}

		// ~ProtobufUpdater waits for a running scan
	}

	// Tear down: hooks first, then give threads that are still inside a detour a moment to leave.
	delete g_pNet;
	g_pNet = NULL;
	delete g_pCrypto;
	g_pCrypto = NULL;

	Sleep(500);

	if (bUi)
		nh2win::UiDestroy();

	delete g_pLogger;
	g_pLogger = NULL;

	if (g_bOwnsConsole)
	{
		FreeConsole();
		g_bOwnsConsole = FALSE;
	}

	// Drop the reference taken above, then the one the injector's LoadLibrary created.
	// FreeLibraryAndExitThread unloads the DLL and ends this thread without returning into unloaded code.
	if (hSelf != NULL)
	{
		FreeLibrary(hSelf);
		FreeLibraryAndExitThread(hSelf, 0);
	}

	return 0;
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
{
	if (IsRunDll32())
	{
		return TRUE;
	}

	if ( fdwReason == DLL_PROCESS_ATTACH )
	{
		DisableThreadLibraryCalls(hinstDLL);

		HANDLE hThread = CreateThread(NULL, 0, NetHook2TwoMain, NULL, 0, NULL);
		if (hThread != NULL)
		{
			CloseHandle(hThread);
		}
	}

	return TRUE;
}
