#include "locator.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <sstream>

namespace nh2
{

namespace
{

constexpr uint32_t kScnExecute = 0x20000000u;
constexpr uint32_t kScnCode = 0x00000020u;
constexpr uint32_t kScnDiscardable = 0x02000000u;

struct Section
{
	uint32_t rva = 0;
	uint32_t size = 0;
	uint32_t flags = 0;

	bool Executable() const { return ( flags & ( kScnExecute | kScnCode ) ) != 0; }
};

struct PeInfo
{
	bool ok = false;
	bool pe64 = false;
	std::vector<Section> sections;
	uint32_t excRva = 0;
	uint32_t excSize = 0;
};

bool Read16( const ImageView &img, size_t off, uint32_t &out )
{
	if ( off + 2 > img.size )
		return false;
	out = static_cast<uint32_t>( img.base[ off ] ) | ( static_cast<uint32_t>( img.base[ off + 1 ] ) << 8 );
	return true;
}

bool Read32( const ImageView &img, size_t off, uint32_t &out )
{
	if ( off + 4 > img.size )
		return false;
	out = static_cast<uint32_t>( img.base[ off ] ) | ( static_cast<uint32_t>( img.base[ off + 1 ] ) << 8 ) |
		( static_cast<uint32_t>( img.base[ off + 2 ] ) << 16 ) | ( static_cast<uint32_t>( img.base[ off + 3 ] ) << 24 );
	return true;
}

PeInfo ParsePe( const ImageView &img )
{
	PeInfo pe;
	if ( img.base == nullptr || img.size < 0x200 )
		return pe;

	uint32_t mz = 0, lfanew = 0, sig = 0;
	if ( !Read16( img, 0, mz ) || mz != 0x5A4D || !Read32( img, 0x3C, lfanew ) || !Read32( img, lfanew, sig ) || sig != 0x00004550 )
		return pe;

	uint32_t numSections = 0, optSize = 0, magic = 0;
	const size_t fileHeader = static_cast<size_t>( lfanew ) + 4;
	if ( !Read16( img, fileHeader + 2, numSections ) || !Read16( img, fileHeader + 16, optSize ) )
		return pe;

	const size_t opt = fileHeader + 20;
	if ( !Read16( img, opt, magic ) )
		return pe;

	pe.pe64 = magic == 0x20B;

	if ( pe.pe64 )
	{
		// DataDirectory[3] = exception table
		Read32( img, opt + 112 + 3 * 8, pe.excRva );
		Read32( img, opt + 112 + 3 * 8 + 4, pe.excSize );
	}

	const size_t sectionTable = opt + optSize;
	for ( uint32_t i = 0; i < numSections && i < 96; i++ )
	{
		const size_t s = sectionTable + static_cast<size_t>( i ) * 40;
		uint32_t virtualSize = 0, rva = 0, rawSize = 0, flags = 0;
		if ( !Read32( img, s + 8, virtualSize ) || !Read32( img, s + 12, rva ) || !Read32( img, s + 16, rawSize ) || !Read32( img, s + 36, flags ) )
			return pe;

		if ( ( flags & kScnDiscardable ) != 0 )
			continue;

		Section section;
		section.rva = rva;
		section.size = virtualSize != 0 ? virtualSize : rawSize;
		section.flags = flags;

		if ( section.rva >= img.size )
			continue;
		if ( static_cast<size_t>( section.rva ) + section.size > img.size )
			section.size = static_cast<uint32_t>( img.size - section.rva );

		pe.sections.push_back( section );
	}

	pe.ok = !pe.sections.empty();
	return pe;
}

std::string Trim( const std::string &s )
{
	const size_t b = s.find_first_not_of( " \t\r\n" );
	if ( b == std::string::npos )
		return std::string();
	const size_t e = s.find_last_not_of( " \t\r\n" );
	return s.substr( b, e - b + 1 );
}

std::string Lower( std::string s )
{
	std::transform( s.begin(), s.end(), s.begin(), []( unsigned char c ) { return static_cast<char>( std::tolower( c ) ); } );
	return s;
}

int HexValue( char c )
{
	if ( c >= '0' && c <= '9' ) return c - '0';
	if ( c >= 'a' && c <= 'f' ) return c - 'a' + 10;
	if ( c >= 'A' && c <= 'F' ) return c - 'A' + 10;
	return -1;
}

} // namespace


bool ReadableRva( const ImageView &image, size_t rva, size_t length )
{
	return image.base != nullptr && rva <= image.size && length <= image.size - rva;
}

bool IsExecutableRva( const ImageView &image, size_t rva )
{
	const PeInfo pe = ParsePe( image );
	for ( const Section &s : pe.sections )
	{
		if ( s.Executable() && rva >= s.rva && rva < static_cast<size_t>( s.rva ) + s.size )
			return true;
	}
	return false;
}


bool ParsePattern( const std::string &sigText, const std::string &maskText, Pattern &out, std::string &error )
{
	Pattern pattern;
	const std::string sig = Trim( sigText );
	const std::string mask = Trim( maskText );

	if ( sig.empty() )
	{
		error = "empty signature";
		return false;
	}

	const bool cStyle = sig.find( "\\x" ) != std::string::npos || sig.find( "\\X" ) != std::string::npos;

	if ( cStyle )
	{
		for ( size_t i = 0; i < sig.size(); )
		{
			if ( sig[ i ] == ' ' || sig[ i ] == '\t' )
			{
				i++;
				continue;
			}

			if ( sig[ i ] != '\\' || i + 3 >= sig.size() || ( sig[ i + 1 ] != 'x' && sig[ i + 1 ] != 'X' ) )
			{
				error = "expected \\xNN escapes only";
				return false;
			}

			const int hi = HexValue( sig[ i + 2 ] );
			const int lo = HexValue( sig[ i + 3 ] );
			if ( hi < 0 || lo < 0 )
			{
				error = "invalid \\x escape";
				return false;
			}

			pattern.bytes.push_back( static_cast<uint8_t>( hi * 16 + lo ) );
			pattern.mask.push_back( 'x' );
			i += 4;
		}

		if ( mask.empty() )
		{
			// legacy notation: 0xCC marks "don't care"
			for ( size_t i = 0; i < pattern.bytes.size(); i++ )
			{
				if ( pattern.bytes[ i ] == 0xCC )
					pattern.mask[ i ] = '?';
			}
		}
	}
	else
	{
		std::istringstream tokens( sig );
		std::string token;
		while ( tokens >> token )
		{
			if ( token == "?" || token == "??" || token == "*" || token == "**" )
			{
				pattern.bytes.push_back( 0 );
				pattern.mask.push_back( '?' );
				continue;
			}

			if ( token.size() > 2 && token[ 0 ] == '0' && ( token[ 1 ] == 'x' || token[ 1 ] == 'X' ) )
				token.erase( 0, 2 );

			int value = 0;
			if ( token.empty() || token.size() > 2 )
			{
				error = "invalid byte '" + token + "'";
				return false;
			}
			for ( char c : token )
			{
				const int h = HexValue( c );
				if ( h < 0 )
				{
					error = "invalid byte '" + token + "'";
					return false;
				}
				value = value * 16 + h;
			}

			pattern.bytes.push_back( static_cast<uint8_t>( value ) );
			pattern.mask.push_back( 'x' );
		}
	}

	if ( pattern.bytes.empty() )
	{
		error = "empty signature";
		return false;
	}

	if ( !mask.empty() )
	{
		if ( mask.size() != pattern.bytes.size() )
		{
			error = "mask has " + std::to_string( mask.size() ) + " characters but the signature has " + std::to_string( pattern.bytes.size() ) + " bytes";
			return false;
		}

		for ( size_t i = 0; i < mask.size(); i++ )
		{
			if ( mask[ i ] != 'x' && mask[ i ] != 'X' && mask[ i ] != '?' )
			{
				error = "mask may only contain 'x' and '?'";
				return false;
			}
			pattern.mask[ i ] = mask[ i ] == '?' ? '?' : 'x';
		}
	}

	// A pattern of only wildcards would match everything.
	if ( pattern.mask.find( 'x' ) == std::string::npos )
	{
		error = "signature contains no fixed bytes";
		return false;
	}

	out = std::move( pattern );
	return true;
}

std::string FormatPattern( const Pattern &pattern )
{
	std::string s;
	char buf[ 4 ];
	for ( size_t i = 0; i < pattern.bytes.size(); i++ )
	{
		if ( i )
			s += ' ';
		if ( pattern.mask[ i ] == '?' )
			s += "??";
		else
		{
			std::snprintf( buf, sizeof( buf ), "%02X", pattern.bytes[ i ] );
			s += buf;
		}
	}
	return s;
}


std::vector<size_t> FindPattern( const ImageView &image, const Pattern &pattern, size_t maxHits )
{
	std::vector<size_t> hits;
	const PeInfo pe = ParsePe( image );
	if ( !pe.ok || pattern.bytes.empty() )
		return hits;

	const size_t n = pattern.bytes.size();

	// Scan for the first fixed byte, verify the rest.
	size_t first = 0;
	while ( first < n && pattern.mask[ first ] != 'x' )
		first++;

	for ( const Section &s : pe.sections )
	{
		if ( !s.Executable() || s.size < n )
			continue;

		const uint8_t *begin = image.base + s.rva;
		const size_t last = s.size - n;

		for ( size_t i = 0; i <= last; i++ )
		{
			if ( begin[ i + first ] != pattern.bytes[ first ] )
				continue;

			size_t k = 0;
			for ( ; k < n; k++ )
			{
				if ( pattern.mask[ k ] == 'x' && begin[ i + k ] != pattern.bytes[ k ] )
					break;
			}

			if ( k == n )
			{
				hits.push_back( static_cast<size_t>( s.rva ) + i );
				if ( hits.size() >= maxHits )
					return hits;
			}
		}
	}

	return hits;
}


bool FunctionStartFromUnwindInfo( const ImageView &image, size_t rva, size_t &start )
{
	const PeInfo pe = ParsePe( image );
	if ( !pe.ok || !pe.pe64 || pe.excRva == 0 || pe.excSize < 12 )
		return false;

	const size_t count = pe.excSize / 12;
	if ( !ReadableRva( image, pe.excRva, count * 12 ) )
		return false;

	// binary search: last entry whose BeginAddress <= rva
	size_t lo = 0, hi = count;
	while ( lo < hi )
	{
		const size_t mid = lo + ( hi - lo ) / 2;
		uint32_t begin = 0;
		Read32( image, pe.excRva + mid * 12, begin );
		if ( begin <= rva )
			lo = mid + 1;
		else
			hi = mid;
	}

	if ( lo == 0 )
		return false;

	size_t entry = pe.excRva + ( lo - 1 ) * 12;

	uint32_t begin = 0, end = 0, unwind = 0;
	if ( !Read32( image, entry, begin ) || !Read32( image, entry + 4, end ) || rva >= end )
		return false;

	for ( int depth = 0; depth < 16; depth++ )
	{
		if ( !Read32( image, entry, begin ) || !Read32( image, entry + 4, end ) || !Read32( image, entry + 8, unwind ) )
			return false;

		if ( ( unwind & 1 ) != 0 )
		{
			// indirect: the unwind data is the RVA of another RUNTIME_FUNCTION
			entry = unwind & ~1u;
			continue;
		}

		if ( !ReadableRva( image, unwind, 4 ) )
			return false;

		const uint8_t header = image.base[ unwind ];
		const uint8_t flags = header >> 3;
		if ( ( flags & 4 ) == 0 ) // UNW_FLAG_CHAININFO
		{
			start = begin;
			return true;
		}

		const size_t codes = image.base[ unwind + 2 ];
		entry = static_cast<size_t>( unwind ) + 4 + ( ( codes + 1 ) & ~static_cast<size_t>( 1 ) ) * 2;
	}

	return false;
}


std::vector<size_t> FindFunctionsReferencingString( const ImageView &image, const std::string &text )
{
	std::vector<size_t> result;
	const PeInfo pe = ParsePe( image );
	if ( !pe.ok || !pe.pe64 || text.empty() )
		return result;

	// 1. the string itself (data sections), as a whole C string
	std::vector<size_t> stringRvas;
	const std::string needle = text + std::string( 1, '\0' );

	for ( const Section &s : pe.sections )
	{
		if ( s.Executable() || s.size < needle.size() )
			continue;

		const uint8_t *begin = image.base + s.rva;
		const size_t last = s.size - needle.size();
		for ( size_t i = 0; i <= last; i++ )
		{
			if ( begin[ i ] != static_cast<uint8_t>( needle[ 0 ] ) || std::memcmp( begin + i, needle.data(), needle.size() ) != 0 )
				continue;

			// not the tail of a longer string
			if ( i > 0 && begin[ i - 1 ] >= 0x20 && begin[ i - 1 ] < 0x7F )
				continue;

			stringRvas.push_back( static_cast<size_t>( s.rva ) + i );
		}
	}

	if ( stringRvas.empty() )
		return result;

	// 2. rip-relative "lea reg, [string]" in code
	std::set<size_t> starts;

	for ( const Section &s : pe.sections )
	{
		if ( !s.Executable() || s.size < 8 )
			continue;

		const uint8_t *b = image.base + s.rva;
		const size_t last = s.size - 7;

		for ( size_t i = 0; i < last; i++ )
		{
			if ( ( b[ i ] != 0x48 && b[ i ] != 0x4C ) || b[ i + 1 ] != 0x8D || ( b[ i + 2 ] & 0xC7 ) != 0x05 )
				continue;

			int32_t disp;
			std::memcpy( &disp, b + i + 3, 4 );
			const int64_t target = static_cast<int64_t>( s.rva ) + static_cast<int64_t>( i ) + 7 + disp;

			if ( target < 0 || std::find( stringRvas.begin(), stringRvas.end(), static_cast<size_t>( target ) ) == stringRvas.end() )
				continue;

			size_t start = 0;
			if ( FunctionStartFromUnwindInfo( image, static_cast<size_t>( s.rva ) + i, start ) )
				starts.insert( start );
		}
	}

	result.assign( starts.begin(), starts.end() );
	return result;
}


bool LooksLikeRecvPkt( const ImageView &image, size_t rva )
{
	size_t length = 0xC0;
	if ( rva >= image.size )
		return false;
	length = std::min( length, image.size - rva );
	if ( length < 32 )
		return false;

	const uint8_t *b = image.base + rva;

	for ( size_t i = 0; i + 16 < length; i++ )
	{
		if ( b[ i ] != 0xB2 || b[ i + 1 ] != 0x01 ) // mov dl, 1
			continue;

		// mov rcx, <reg> ; call rel32   within a few instructions
		for ( size_t j = 2; j <= 12 && i + j + 4 < length; j++ )
		{
			if ( b[ i + j ] == 0x48 && b[ i + j + 1 ] == 0x8B && ( b[ i + j + 2 ] & 0xF8 ) == 0xC8 && b[ i + j + 3 ] == 0xE8 )
				return true;
		}
	}

	return false;
}

std::vector<size_t> FindRecvPktByStringReference( const ImageView &image, const LocateLog &log )
{
	std::vector<size_t> candidates = FindFunctionsReferencingString( image, "CCMInterface::RecvPkt" );

	std::vector<size_t> valid;
	for ( size_t rva : candidates )
	{
		if ( LooksLikeRecvPkt( image, rva ) )
			valid.push_back( rva );
	}

	if ( log && candidates.size() != valid.size() )
		log( "  string reference: " + std::to_string( candidates.size() ) + " functions reference the name, " + std::to_string( valid.size() ) + " look like RecvPkt" );

	return valid;
}


//
// Config
//
namespace
{

struct PendingOverride
{
	std::string sig, mask;
	bool hasSig = false, hasMask = false;
	uint64_t rva = 0;
	bool hasRva = false;
	std::string where;
};

std::string StripComment( const std::string &value )
{
	std::string v = Trim( value );
	if ( !v.empty() && v[ 0 ] == '"' )
	{
		const size_t close = v.find( '"', 1 );
		return close == std::string::npos ? v.substr( 1 ) : v.substr( 1, close - 1 );
	}

	for ( size_t i = 0; i < v.size(); i++ )
	{
		if ( ( v[ i ] == ';' || v[ i ] == '#' ) && ( i == 0 || v[ i - 1 ] == ' ' || v[ i - 1 ] == '\t' ) )
			return Trim( v.substr( 0, i ) );
	}
	return v;
}

} // namespace

int SigConfig::Parse( const std::string &text, const LocateLog &log )
{
	overrides_.clear();
	general_.clear();
	int problems = 0;

	std::map<std::string, PendingOverride> pending;
	std::string section;

	std::istringstream in( text );
	std::string line;
	int lineNo = 0;

	auto complain = [ & ]( const std::string &message )
	{
		problems++;
		if ( log )
			log( "nethook2two_cfg.ini line " + std::to_string( lineNo ) + ": " + message );
	};

	while ( std::getline( in, line ) )
	{
		lineNo++;
		line = Trim( line );
		if ( line.empty() || line[ 0 ] == ';' || line[ 0 ] == '#' )
			continue;

		if ( line.front() == '[' )
		{
			const size_t close = line.find( ']' );
			if ( close == std::string::npos )
			{
				complain( "missing ']'" );
				continue;
			}
			section = Lower( Trim( line.substr( 1, close - 1 ) ) );
			continue;
		}

		const size_t eq = line.find( '=' );
		if ( eq == std::string::npos )
		{
			complain( "expected key = value" );
			continue;
		}

		const std::string key = Lower( Trim( line.substr( 0, eq ) ) );
		const std::string value = StripComment( line.substr( eq + 1 ) );

		if ( section == "general" )
		{
			general_[ key ] = value;
			continue;
		}

		const size_t dot = key.rfind( '.' );
		if ( dot == std::string::npos )
		{
			complain( "unknown key '" + key + "' (expected <Name>.sig / .mask / .rva)" );
			continue;
		}

		if ( section != "x64" && section != "x86" )
		{
			complain( "'" + key + "' is outside of an [x64] or [x86] section" );
			continue;
		}

		const std::string name = key.substr( 0, dot );
		const std::string field = key.substr( dot + 1 );
		PendingOverride &p = pending[ section + "." + name ];
		if ( p.where.empty() )
			p.where = "line " + std::to_string( lineNo );

		if ( field == "sig" || field == "signature" )
		{
			p.sig = value;
			p.hasSig = !value.empty();
		}
		else if ( field == "mask" )
		{
			p.mask = value;
			p.hasMask = !value.empty();
		}
		else if ( field == "rva" )
		{
			if ( value.empty() )
				continue;
			char *end = nullptr;
			const unsigned long long parsed = std::strtoull( value.c_str(), &end, 0 );
			if ( end == value.c_str() || *end != '\0' )
				complain( "invalid rva '" + value + "'" );
			else
			{
				p.rva = parsed;
				p.hasRva = true;
			}
		}
		else
			complain( "unknown key '" + key + "' (expected .sig / .mask / .rva)" );
	}

	for ( const auto &entry : pending )
	{
		const PendingOverride &p = entry.second;
		SigOverride o;

		if ( p.hasSig )
		{
			std::string error;
			if ( ParsePattern( p.sig, p.hasMask ? p.mask : std::string(), o.pattern, error ) )
				o.hasPattern = true;
			else
			{
				problems++;
				if ( log )
					log( "nethook2two_cfg.ini: " + entry.first + ".sig (" + p.where + "): " + error );
			}
		}
		else if ( p.hasMask )
		{
			problems++;
			if ( log )
				log( "nethook2two_cfg.ini: " + entry.first + ".mask without " + entry.first + ".sig is ignored" );
		}

		if ( p.hasRva )
		{
			o.hasRva = true;
			o.rva = p.rva;
		}

		if ( o.hasPattern || o.hasRva )
			overrides_[ entry.first ] = std::move( o );
	}

	return problems;
}

bool SigConfig::Load( const std::string &path, const LocateLog &log )
{
	FILE *f = std::fopen( path.c_str(), "rb" );
	if ( f == nullptr )
	{
		overrides_.clear();
		general_.clear();
		return false;
	}

	std::string text;
	char buffer[ 4096 ];
	size_t n;
	while ( ( n = std::fread( buffer, 1, sizeof( buffer ), f ) ) > 0 )
		text.append( buffer, n );
	std::fclose( f );

	if ( text.compare( 0, 3, "\xEF\xBB\xBF" ) == 0 )
		text.erase( 0, 3 );

	Parse( text, log );
	return true;
}

bool SigConfig::GetBool( const std::string &key, bool defaultValue ) const
{
	auto it = general_.find( Lower( key ) );
	if ( it == general_.end() )
		return defaultValue;

	const std::string v = Lower( it->second );
	if ( v == "1" || v == "true" || v == "yes" || v == "on" )
		return true;
	if ( v == "0" || v == "false" || v == "no" || v == "off" )
		return false;
	return defaultValue;
}

bool SetIniValue( const std::string &path, const std::string &section, const std::string &key, const std::string &value )
{
	std::string text;
	if ( FILE *f = std::fopen( path.c_str(), "rb" ) )
	{
		char buffer[ 4096 ];
		size_t n;
		while ( ( n = std::fread( buffer, 1, sizeof( buffer ), f ) ) > 0 )
			text.append( buffer, n );
		std::fclose( f );
	}

	const bool crlf = text.find( "\r\n" ) != std::string::npos || text.empty();
	std::vector<std::string> lines;
	{
		std::istringstream in( text );
		std::string line;
		while ( std::getline( in, line ) )
		{
			if ( !line.empty() && line.back() == '\r' )
				line.pop_back();
			lines.push_back( line );
		}
	}

	const std::string wantSection = Lower( section ), wantKey = Lower( key );
	const std::string newLine = key + " = " + value;

	int sectionStart = -1, sectionEnd = static_cast<int>( lines.size() ), keyLine = -1;
	std::string current;
	for ( size_t i = 0; i < lines.size(); i++ )
	{
		const std::string t = Trim( lines[ i ] );
		if ( !t.empty() && t[ 0 ] == '[' )
		{
			const size_t close = t.find( ']' );
			current = close == std::string::npos ? std::string() : Lower( Trim( t.substr( 1, close - 1 ) ) );
			if ( sectionStart >= 0 && sectionEnd == static_cast<int>( lines.size() ) )
				sectionEnd = static_cast<int>( i );
			if ( current == wantSection && sectionStart < 0 )
				sectionStart = static_cast<int>( i );
			continue;
		}

		if ( current == wantSection && sectionEnd == static_cast<int>( lines.size() ) && keyLine < 0 && !t.empty() && t[ 0 ] != ';' && t[ 0 ] != '#' )
		{
			const size_t eq = t.find( '=' );
			if ( eq != std::string::npos && Lower( Trim( t.substr( 0, eq ) ) ) == wantKey )
				keyLine = static_cast<int>( i );
		}
	}

	if ( keyLine >= 0 )
	{
		lines[ keyLine ] = newLine;
	}
	else if ( sectionStart >= 0 )
	{
		int at = sectionEnd;
		while ( at > sectionStart + 1 && Trim( lines[ at - 1 ] ).empty() )
			at--;
		lines.insert( lines.begin() + at, newLine );
	}
	else
	{
		if ( !lines.empty() && !Trim( lines.back() ).empty() )
			lines.push_back( std::string() );
		lines.push_back( "[" + section + "]" );
		lines.push_back( newLine );
	}

	std::string out;
	for ( const std::string &l : lines )
		out += l + ( crlf ? "\r\n" : "\n" );

	FILE *f = std::fopen( path.c_str(), "wb" );
	if ( f == nullptr )
		return false;
	const bool ok = std::fwrite( out.data(), 1, out.size(), f ) == out.size();
	std::fclose( f );
	return ok;
}

const SigOverride *SigConfig::Find( const std::string &arch, const std::string &name ) const
{
	auto it = overrides_.find( Lower( arch ) + "." + Lower( name ) );
	return it == overrides_.end() ? nullptr : &it->second;
}

std::string DefaultSigConfigTemplate()
{
	return
		"; NetHook2Two configuration.\r\n"
		";\r\n"
		"[general]\r\n"
		"; Also write the classic nethook\\<time>\\*.bin dump files (File > Also write dump files to disk).\r\n"
		"DumpToDisk = 1\r\n"
		"\r\n"
		";\r\n"
		"; NetHook2Two finds the functions it hooks in steamclient(64).dll with signatures, and for RecvPkt also by\r\n"
		"; looking at the code that uses its name. If a Steam update breaks one of them and a newer NetHook2Two isn't\r\n"
		"; available yet, put a working signature here. Remove the leading ';' of the lines you want to use.\r\n"
		";\r\n"
		"; Names:  SymmetricEncryptChosenIV, PchMsgNameFromEMsg, BBuildAndAsyncSendFrame, RecvPkt\r\n"
		"; .sig    hex bytes, \"??\" = any byte   (or C style: \\x48\\x8B\\xCC - 0xCC is a wildcard unless .mask is given)\r\n"
		"; .mask   optional, one character per byte: 'x' = must match, '?' = any byte\r\n"
		"; .rva    optional, offset of the function from the module base (wins over .sig)\r\n"
		"; The signature has to match exactly one place in the module. It must point at the first byte of the function.\r\n"
		";\r\n"
		"; [x64]\r\n"
		"; RecvPkt.sig = 48 8B C4 55 48 8D A8 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 48 89 58 08 48 8B DA\r\n"
		"; RecvPkt.mask =\r\n"
		"; BBuildAndAsyncSendFrame.sig = 48 8B C4 55 48 8D 68 ?? 48 81 EC ?? ?? ?? ?? 48 89 70 ?? 49 8B F0 48 89 78 ?? 4C 89 60\r\n"
		"; SymmetricEncryptChosenIV.sig = 48 83 EC 58 8B 84 24 ?? ?? ?? ?? C6 44 24\r\n"
		"; PchMsgNameFromEMsg.sig = 48 89 5C 24 ?? 57 48 83 EC 20 8B D9 E8\r\n"
		";\r\n"
		"; [x86]\r\n"
		"; RecvPkt.sig = 55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 56 8B F1 57\r\n";
}


//
// Locate
//
LocateResult Locate( const ImageView &image, const LocateRequest &request, const SigConfig &config, const LocateLog &log )
{
	LocateResult result;
	auto say = [ & ]( const std::string &s ) { if ( log ) log( s ); };

	if ( !ParsePe( image ).ok )
	{
		say( request.name + ": the module image could not be read" );
		return result;
	}

	// 1. config override
	if ( const SigOverride *o = config.Find( request.arch, request.name ) )
	{
		if ( o->hasRva )
		{
			if ( o->rva < image.size && IsExecutableRva( image, static_cast<size_t>( o->rva ) ) )
			{
				result.ok = true;
				result.rva = static_cast<size_t>( o->rva );
				result.how = "config rva";
				return result;
			}
			say( request.name + ": configured rva 0x" + std::to_string( o->rva ) + " is not inside the code of the module, ignoring it" );
		}

		if ( o->hasPattern )
		{
			const std::vector<size_t> hits = FindPattern( image, o->pattern, 2 );
			if ( !hits.empty() )
			{
				if ( hits.size() > 1 )
					say( request.name + ": the configured signature matches more than once, using the first match" );
				result.ok = true;
				result.rva = hits.front();
				result.how = "config signature";
				return result;
			}
			say( request.name + ": the configured signature was not found, trying the built-in ones" );
		}
	}

	// 2. built-in signatures
	int index = 0;
	for ( const SigCandidate &c : request.candidates )
	{
		index++;

		Pattern pattern;
		pattern.mask = c.mask;
		pattern.bytes.assign( reinterpret_cast<const uint8_t *>( c.sig ), reinterpret_cast<const uint8_t *>( c.sig ) + pattern.mask.size() );

		const std::vector<size_t> hits = FindPattern( image, pattern, 2 );
		if ( hits.empty() )
			continue;

		if ( hits.size() > 1 )
		{
			say( request.name + ": signature #" + std::to_string( index ) + " is ambiguous, skipping it" );
			continue;
		}

		if ( request.validate && !request.validate( image, hits.front() ) )
		{
			say( request.name + ": signature #" + std::to_string( index ) + " matched code that doesn't look right, skipping it" );
			continue;
		}

		result.ok = true;
		result.rva = hits.front();
		result.how = "signature #" + std::to_string( index );
		return result;
	}

	// 3. structural fallback
	if ( request.fallback )
	{
		say( request.name + ": no signature matched, searching by structure..." );
		const std::vector<size_t> found = request.fallback( image, log );

		if ( found.size() == 1 )
		{
			result.ok = true;
			result.rva = found.front();
			result.how = "code analysis";
			return result;
		}

		if ( found.size() > 1 )
			say( request.name + ": " + std::to_string( found.size() ) + " equally likely functions found, not hooking any of them" );
	}

	return result;
}

} // namespace nh2
