// Finds functions inside a loaded module (steamclient64.dll) without depending on one exact byte pattern.
//
// For every hooked function there is an ordered list of strategies:
//   1. an override from nethook2two_cfg.ini (signature / mask, or a plain RVA),
//   2. the built-in signatures (each must match exactly once, and pass an optional sanity check),
//   3. an optional structural fallback (e.g. "the function that references the string 'CCMInterface::RecvPkt'",
//      found through the PE exception table), which survives recompiles that change the prologue.
//
// Everything here works on a memory image (module base + size), so it is portable C++ with no Windows headers and
// can be tested on Linux against a copy of steamclient64.dll laid out like a loaded module.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace nh2
{

using LocateLog = std::function<void( const std::string & )>;

// A loaded module: `base` points at the DOS header, `size` is SizeOfImage.
struct ImageView
{
	const uint8_t *base = nullptr;
	size_t size = 0;
};

// Byte pattern. mask[i] == 'x' means bytes[i] must match, '?' means any byte.
struct Pattern
{
	std::vector<uint8_t> bytes;
	std::string mask;
};

// Accepted forms:
//   hex bytes:  "48 8B C4 ?? ?? 55"   ("??" or "?" is a wildcard; an optional mask overrides that)
//   C escapes:  "\x48\x8B\xC4\xCC\xCC\x55" (0xCC is a wildcard when no mask is given, otherwise `mask` decides:
//               'x' = exact, '?' = any)
bool ParsePattern( const std::string &sig, const std::string &mask, Pattern &out, std::string &error );
std::string FormatPattern( const Pattern &pattern ); // "48 8B ?? 55"

// RVAs of up to `maxHits` matches inside the executable sections.
std::vector<size_t> FindPattern( const ImageView &image, const Pattern &pattern, size_t maxHits = 2 );

// RVAs of the functions (primary RUNTIME_FUNCTION entries, 64-bit PE only) that load the address of the C string
// `text` with a rip-relative lea. Uses the exception directory to turn code addresses into function starts.
std::vector<size_t> FindFunctionsReferencingString( const ImageView &image, const std::string &text );

// Function start for any code RVA inside it (follows chained unwind info). False if not found.
bool FunctionStartFromUnwindInfo( const ImageView &image, size_t rva, size_t &start );

// Sanity check for CCMInterface::RecvPkt( this, rawBuffer ): early in the function the raw buffer is handed to the
// packet factory:  mov dl, 1 ... mov rcx, <reg> ; call <factory>.
bool LooksLikeRecvPkt( const ImageView &image, size_t rva );
std::vector<size_t> FindRecvPktByStringReference( const ImageView &image, const LocateLog &log );

bool ReadableRva( const ImageView &image, size_t rva, size_t length );
bool IsExecutableRva( const ImageView &image, size_t rva );


//
// nethook2two_cfg.ini
//
//   [x64]                      ; or [x86]
//   RecvPkt.sig  = 48 8B C4 55 48 8D A8 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ??
//   RecvPkt.mask =                      ; optional, 'x' exact / '?' wildcard, same length as the signature
//   RecvPkt.rva  = 0x5BC990             ; optional, offset from the module base; wins over .sig
//
// Names: SymmetricEncryptChosenIV, PchMsgNameFromEMsg, BBuildAndAsyncSendFrame, RecvPkt.
//
struct SigOverride
{
	bool hasPattern = false;
	Pattern pattern;
	bool hasRva = false;
	uint64_t rva = 0;
};

class SigConfig
{
public:
	// Returns the number of problems found (they are also reported through `log`).
	int Parse( const std::string &text, const LocateLog &log );
	bool Load( const std::string &path, const LocateLog &log );

	const SigOverride *Find( const std::string &arch, const std::string &name ) const;
	size_t Count() const { return overrides_.size(); }

private:
	std::map<std::string, SigOverride> overrides_; // "x64.recvpkt"
};

// Commented template that is written next to the ini the first time NetHook2Two runs.
std::string DefaultSigConfigTemplate();


//
// Locating
//
struct SigCandidate
{
	const char *sig;  // C escapes, 0xCC = wildcard when mask has '?' there (legacy notation)
	const char *mask;
};

struct LocateRequest
{
	std::string name;   // "RecvPkt"
	std::string arch;   // "x64" / "x86"
	std::vector<SigCandidate> candidates;

	// Optional: reject matches that don't look like the function we want.
	std::function<bool( const ImageView &, size_t rva )> validate;

	// Optional: structural fallback returning candidate RVAs.
	std::function<std::vector<size_t>( const ImageView &, const LocateLog & )> fallback;
};

struct LocateResult
{
	bool ok = false;
	size_t rva = 0;
	std::string how; // "config signature", "signature #1", "string reference", ...
};

LocateResult Locate( const ImageView &image, const LocateRequest &request, const SigConfig &config, const LocateLog &log );

} // namespace nh2
