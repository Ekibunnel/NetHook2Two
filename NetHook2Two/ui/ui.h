// The NetHook2Two window: an imgui based live packet viewer that runs on its own thread inside the hooked process.
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace nh2win
{

class ProtobufUpdater;

// Creates the window, Direct3D device and imgui context. Must be called on the thread that will call Run().
bool UiCreate( const char *windowTitle, const char *iniFilePath, char *errorOut, size_t errorOutSize );

// Message/render loop. Returns when the window is closed or nh2win::RequestShutdown() is called.
void UiRun( ProtobufUpdater &updater );

void UiDestroy();

} // namespace nh2win
