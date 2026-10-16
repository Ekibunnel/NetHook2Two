## NetHook2Two
<img width="1345" height="852" alt="image" src="https://github.com/user-attachments/assets/9cd8f32c-9671-4405-862a-9598c60592ec" />

NetHook2Two is a Windows DLL that is injected into the address space of a running Steam.exe process (or `steamcmd.exe`,
`srcds.exe`...), hooks the networking routines of the Steam client and shows every network message it sends or receives.

This whole thing is basically an Imgui windows strapped to already existing tools from [Steamkit](https://github.com/SteamRE/SteamKit), **ALL credits go to them**.

This version bundles what used to be three separate tools into one:

| Before | Now |
|---|---|
| NetHook2Two dumped raw `.bin` files | still does (optional), **and** shows every packet live in a window |
| NetHookAnalyzer2 (WinForms, compiled-in SteamKit types) parsed them | the window parses packets itself, in real time |
| ProtobufDumper had to be run by hand on `steamclient64.dll` | runs automatically each time NetHook2Two starts |

### What happens when NetHook2Two starts

1. A window (Dear ImGui, Direct3D 11) opens inside the Steam process, and the hooks are installed.
2. In the background, `steamclient64.dll` is scanned for the protobuf definitions Steam embeds in itself
   (a C++ port of ProtobufDumper's scanner, `core/protoscan.cpp`). The result is cached in
   `<steam>\nethook\protobufs\` keyed by the file's size and modification time, so after a Steam update the next start
   rescans automatically, and an unchanged client starts instantly. Readable `.proto` files are written to
   `<steam>\nethook\protobufs\protos\`.
3. Every packet appears in the list the moment it is sent/received. Select one to see it parsed - header, body,
   nested service-method requests/responses, game coordinator messages, unknown fields, hex dump - using the
   definitions of the Steam client that is actually running. No protobuf classes are compiled in, so new Steam
   messages show up without rebuilding anything.

### The window

* **Packet list** - `#`, time, direction, EMsg id, name, details (service method name / GC message / legacy service
  method), size. Up/Down/PageUp/PageDown change the selection. Right click a row to hide an EMsg (e.g. heart beats),
  show only it, or copy the raw bytes.
* **Filter** - space separated terms, all must match (name, id, method, `in`/`out`); prefix a term with `-` to exclude it:
  `friend -heartbeat`.
* **Pause / Clear / In / Out / Auto-scroll**.
* **Parsed** tab - a tree like NetHookAnalyzer2's. Steam IDs are shown as `[U:1:...]`/`STEAM_x:y:z`, timestamps
  (fields with `time` in the name) as dates, enums by name, blobs as hex, text and - when they parse - as nested
  protobufs. Right click any node to copy name/value/subtree. *View > Show unset fields* shows missing fields greyed out.
* **Hex**, **Text** (copyable plain text of the tree) and **Log** tabs.
* **Protobufs** menu - scan status, game folder / app id bindings, reload extra `.proto` files, rescan now (ignoring the cache), open the cache / extra folder.

Closing the window ejects NetHook2Two from the process.

### Usage

Run `NetHook2Two-Inject.cmd` (it asks for administrator rights) or, in an _elevated_ command prompt:

    rundll32 "<Path To NetHook2Two.dll>",Inject

Optionally with a process id or name for other processes, e.g. `Inject steamcmd.exe`. Unlike earlier versions there is
no console window; the window opens instead (a console is only created if the window can't be).

To stop: close the window, use *File > Eject NetHook2Two and close*, or run `NetHook2Two-Eject.cmd` /
`rundll32 "<Path To NetHook2Two.dll>",Eject`.

Make sure you're prepared for the possibility for Steam to crash. Using NetHook2Two isn't an exact science, and sometimes
things break. If NetHook2Two reports that function scans failed after a Steam update, the binary signatures in
`net.cpp` / `crypto.cpp` need updating.

NetHook requires the Microsoft Visual C++ Redistributable for your architecture
(https://aka.ms/vs/17/release/vc_redist.x64.exe / `vc_redist.x86.exe`).

### Adding more protobuf definitions
#### You can find up to date `.proto` at [SteamTracking/Protobufs](https://github.com/SteamTracking/Protobufs).

Game coordinator (GC) messages are defined by the games, not by Steam. To see them parsed, give NetHook2Two the
definitions - plain `.proto` files work, no `protoc` needed:

```
<steam>\nethook\protobufs\extra\csgo\cstrike15_gcmessages.proto
<steam>\nethook\protobufs\extra\csgo\steammessages.proto
<steam>\nethook\protobufs\extra\tf2\base_gcmessages.proto
...
```

* Every sub folder is one game and is its own import root: `import "steammessages.proto";` resolves inside the same
  folder (and `google/protobuf/descriptor.proto` is built in, you only need a copy if you want to). Games may therefore
  ship different versions of files with the same name, and reuse the same message ids, without clashing.
* **Binding folders to apps** - a GC message carries the app id of its game, and NetHook2Two uses the folder bound to
  that app id. Open *Protobufs > Game folders / app ids (GC)...* and fill in the app id(s) of each folder, e.g.
  `/csgo/ : 730` and `/tf2/ : 440`. The bindings are saved in `<steam>\nethook\protobuf_appids.txt` (editable by hand,
  one `folder : appid[, appid...]` per line) and apply immediately, also to the packets already in the list. Until you
  change them, well known folder names use their usual app id (`csgo`/`cs2` 730, `tf2` 440, `dota2` 570, `deadlock`
  1422450, `underlords` 1046930, `artifact` 583950 + 1269260). A folder without any app id is tried for every app, after
  the folders bound to the app of the message. The Parsed tab shows which folder a GC message was decoded with.
* Loose `.proto` files directly in `extra\` are loaded as a shared group that is used for every app.
* `.proto` files are re-read on every start and with *Protobufs > Reload extra .proto files*. A file that can't be used
  (syntax error, or it defines a symbol that another file of the same folder already defines - Steam dumps contain a
  few such duplicates) is skipped and listed in the Log; the other files of the folder keep working.
* Descriptor sets (`protoc --descriptor_set_out=game.pb --include_imports ...`) work the same way, inside a game folder
  or directly in `extra\`. Executables/DLLs that embed protobufs can be dropped into `extra\` or listed (one path per
  line) in `<steam>\nethook\protobuf_targets.txt`.

Anything unknown is still displayed field by field.

### Hooks signatures

NetHook2Two hooks four functions in `steamclient64.dll` (`SymmetricEncryptChosenIV`, `PchMsgNameFromEMsg`,
`BBuildAndAsyncSendFrame` and `RecvPkt`) and finds them again on every start:

1. a signature from `<steam>\nethook\nethook2two_cfg.ini`, if you provided one,
2. the built-in signature(s). A signature must match **exactly one** place in the code (ambiguous matches are skipped), and
   for `RecvPkt` the match must also look like the right function,
3. for `RecvPkt` only: when no signature matches, the function is found by analysing the code - it is the one that uses
   the string `CCMInterface::RecvPkt` (located through the PE exception table). This doesn't depend on the compiler's
   instruction choices, so it keeps working across normal Steam updates.

The Log tab shows how each function was found (`RecvPkt found via signature #1`, `... via code analysis`, `... via config
signature`). If a function can't be found, Steam keeps running, that hook is just missing.

To fix a hook without a new NetHook2Two build, edit `<steam>\nethook\nethook2two_cfg.ini` (a commented template is created
on the first run) and restart the hook:

```ini
[x64]
RecvPkt.sig  = 48 8B C4 55 48 8D A8 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 48 89 58 08 48 8B DA
RecvPkt.mask =                      ; optional: one 'x' (must match) or '?' (any byte) per byte
RecvPkt.rva  = 0x5BC990             ; optional: offset of the function from the module base, wins over .sig
```

* Sections are `[x64]` and `[x86]`; names are `SymmetricEncryptChosenIV`, `PchMsgNameFromEMsg`,
  `BBuildAndAsyncSendFrame` and `RecvPkt`.
* A signature is written as hex bytes with `??` for "any byte", or C style (`\x48\x8B\xCC`, where `0xCC` means "any
  byte" unless a `.mask` is given - the notation used in the source).
* It must point at the first byte of the function. A configured signature that matches several places uses the first;
  one that isn't found falls back to the built-in ones. Mistakes in the file are reported in the Log.

### Compiling

1. Run `.\SetupDependencies.ps1` in a PowerShell prompt to set up dependencies (vcpkg: detours, protobuf, zlib).
   Dear ImGui is bundled in `NetHook2Two\third_party\imgui`.
2. Build `NetHook2Two.sln` with Visual Studio (platform toolset v145; x64 for current 64-bit Steam, Win32 for the legacy client). C++17.
3. You'll get `NetHook2Two.dll`.

The protobuf scanning, descriptor handling and packet decoding (`NetHook2Two\core`) don't use any Windows APIs and have
unit tests: `tests/run_tests.sh` (needs `protoc` and the protobuf development files).


### Dump files and NetHookAnalyzer2

Unless switched off (*File > Also write dump files to disk*), packets are still written to `nethook/<timestamp>` inside
the Steam folder exactly as before, so NetHookAnalyzer2 can keep being used on them.

## License

NetHook2Two is a fork of [Steamkit](https://github.com/SteamRE/SteamKit) and so is under the [LGPL-2.1 license](https://choosealicense.com/licenses/lgpl-2.1/).
