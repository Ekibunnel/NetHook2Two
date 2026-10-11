#include "protoscan.h"

#include <algorithm>
#include <cstring>
#include <fstream>

namespace nh2
{

namespace
{

bool ReadVarint( const uint8_t *data, size_t length, size_t &pos, uint64_t &value )
{
	value = 0;
	for ( int shift = 0; shift < 70 && pos < length; shift += 7 )
	{
		const uint8_t b = data[ pos++ ];
		if ( shift < 64 )
			value |= static_cast<uint64_t>( b & 0x7F ) << shift;

		if ( ( b & 0x80 ) == 0 )
			return true;
	}
	return false;
}

bool IsProtoNameChar( uint8_t c )
{
	return ( c >= 'a' && c <= 'z' ) || ( c >= 'A' && c <= 'Z' ) || ( c >= '0' && c <= '9' ) ||
		c == '_' || c == '\\' || c == '/' || c == '.';
}

// ^[a-zA-Z_0-9\\/.]+\.proto$   (case-insensitive extension, like the original)
bool IsValidProtoName( const uint8_t *name, size_t len )
{
	static const char ext[] = ".proto";
	const size_t extLen = sizeof( ext ) - 1;

	if ( len <= extLen )
		return false;

	for ( size_t i = 0; i < len; i++ )
	{
		if ( !IsProtoNameChar( name[ i ] ) )
			return false;
	}

	for ( size_t i = 0; i < extLen; i++ )
	{
		char c = static_cast<char>( name[ len - extLen + i ] );
		if ( c >= 'A' && c <= 'Z' )
			c = static_cast<char>( c - 'A' + 'a' );
		if ( c != ext[ i ] )
			return false;
	}

	return true;
}

} // namespace


namespace
{

// Serialized FileDescriptorProtos list their fields in ascending field number order (name = 1, package = 2,
// dependency = 3, message_type = 4 ... syntax = 12, edition = 14). Anything after the first field that breaks that
// order, or that isn't a FileDescriptorProto field at all, is not part of the descriptor.
constexpr uint64_t kMaxDescriptorField = 20;

size_t ConsumeFields( const uint8_t *data, size_t length, std::vector<size_t> *fieldEnds )
{
	uint64_t lastField = 0;
	size_t pos = 0;

	while ( pos < length )
	{
		const size_t positionBeforeField = pos;

		uint64_t tag = 0;
		if ( !ReadVarint( data, length, pos, tag ) )
			return positionBeforeField;

		const uint64_t fieldNumber = tag >> 3;
		const uint32_t wireType = static_cast<uint32_t>( tag & 7 );

		if ( fieldNumber == 0 || fieldNumber > kMaxDescriptorField || fieldNumber < lastField )
			return positionBeforeField;

		// Field 1 is the "name" field in FileDescriptorProto. Seeing it a second time means we've hit the next message.
		// (Covered by the ordering rule: 1 < anything that has been seen.) The first field must be the name.
		if ( lastField == 0 && fieldNumber != 1 )
			return positionBeforeField;

		lastField = fieldNumber;

		switch ( wireType )
		{
		case 0: // varint
		{
			uint64_t ignored;
			if ( !ReadVarint( data, length, pos, ignored ) )
				return positionBeforeField;
			break;
		}
		case 2: // length delimited
		{
			uint64_t len;
			if ( !ReadVarint( data, length, pos, len ) || len > length - pos )
				return positionBeforeField;
			pos += static_cast<size_t>( len );
			break;
		}
		default: // FileDescriptorProto has no fixed size or group fields
			return positionBeforeField;
		}

		if ( fieldEnds != nullptr )
			fieldEnds->push_back( pos );
	}

	return pos;
}

bool IsIdentifier( const std::string &s )
{
	if ( s.empty() )
		return false;

	for ( size_t i = 0; i < s.size(); i++ )
	{
		const char c = s[ i ];
		const bool alpha = ( c >= 'a' && c <= 'z' ) || ( c >= 'A' && c <= 'Z' ) || c == '_';
		const bool digit = c >= '0' && c <= '9';
		if ( !( alpha || ( digit && i > 0 ) ) )
			return false;
	}
	return true;
}

bool IsDottedIdentifier( const std::string &s )
{
	size_t start = 0;
	while ( start <= s.size() )
	{
		size_t dot = s.find( '.', start );
		if ( dot == std::string::npos )
			dot = s.size();
		if ( !IsIdentifier( s.substr( start, dot - start ) ) )
			return false;
		start = dot + 1;
		if ( dot == s.size() )
			break;
	}
	return true;
}

bool IsPlausibleMessage( const google::protobuf::DescriptorProto &m )
{
	if ( !IsIdentifier( m.name() ) )
		return false;

	for ( const auto &f : m.field() )
	{
		if ( !IsIdentifier( f.name() ) || f.number() <= 0 )
			return false;
	}
	for ( const auto &n : m.nested_type() )
	{
		if ( !IsPlausibleMessage( n ) )
			return false;
	}
	for ( const auto &e : m.enum_type() )
	{
		if ( !IsIdentifier( e.name() ) )
			return false;
		for ( const auto &v : e.value() )
		{
			if ( !IsIdentifier( v.name() ) )
				return false;
		}
	}
	return true;
}

// Guards against random bytes that happen to follow a real descriptor being mistaken for part of it.
bool IsPlausibleDescriptor( const google::protobuf::FileDescriptorProto &f )
{
	if ( !f.package().empty() && !IsDottedIdentifier( f.package() ) )
		return false;

	for ( const std::string &dep : f.dependency() )
	{
		if ( !IsValidProtoName( reinterpret_cast<const uint8_t *>( dep.data() ), dep.size() ) )
			return false;
	}
	for ( int idx : f.public_dependency() )
	{
		if ( idx < 0 || idx >= f.dependency_size() )
			return false;
	}
	for ( int idx : f.weak_dependency() )
	{
		if ( idx < 0 || idx >= f.dependency_size() )
			return false;
	}
	for ( const auto &m : f.message_type() )
	{
		if ( !IsPlausibleMessage( m ) )
			return false;
	}
	for ( const auto &e : f.enum_type() )
	{
		if ( !IsIdentifier( e.name() ) )
			return false;
		for ( const auto &v : e.value() )
		{
			if ( !IsIdentifier( v.name() ) )
				return false;
		}
	}
	for ( const auto &svc : f.service() )
	{
		if ( !IsIdentifier( svc.name() ) )
			return false;
		for ( const auto &method : svc.method() )
		{
			if ( !IsIdentifier( method.name() ) )
				return false;
		}
	}
	for ( const auto &x : f.extension() )
	{
		if ( !IsIdentifier( x.name() ) || x.number() <= 0 )
			return false;
	}
	return true;
}

} // namespace

size_t ConsumeOneDescriptor( const uint8_t *data, size_t length )
{
	return ConsumeFields( data, length, nullptr );
}


void ScanBufferForDescriptors(
	const uint8_t *data,
	size_t length,
	std::vector<google::protobuf::FileDescriptorProto> &out,
	std::set<std::string> &seen,
	ScanStats &stats )
{
	const uint8_t markerStart = 0x0A; // field 1, length delimited

	size_t i = 0;
	while ( length > 1 && i < length - 1 )
	{
		const void *hit = memchr( data + i, markerStart, length - i );
		if ( hit == nullptr )
			break;

		i = static_cast<size_t>( static_cast<const uint8_t *>( hit ) - data );
		if ( i >= length - 1 )
			break;

		// The name length is a varint, names of 128 characters or more take two bytes
		size_t expectedLength = data[ i + 1 ] & 0x7F;
		size_t markerLength = 2;

		if ( ( data[ i + 1 ] & 0x80 ) != 0 )
		{
			if ( i + 2 >= length || ( data[ i + 2 ] & 0x80 ) != 0 )
			{
				i++;
				continue;
			}

			expectedLength |= static_cast<size_t>( data[ i + 2 ] ) << 7;
			markerLength = 3;
		}

		if ( i + markerLength + expectedLength > length )
		{
			i++;
			continue;
		}

		const uint8_t *nameBytes = data + i + markerLength;
		if ( !IsValidProtoName( nameBytes, expectedLength ) )
		{
			i++;
			continue;
		}

		const std::string protoName( reinterpret_cast<const char *>( nameBytes ), expectedLength );
		if ( seen.count( protoName ) != 0 )
		{
			i++;
			continue;
		}

		stats.candidates++;

		std::vector<size_t> fieldEnds;
		const size_t consumed = ConsumeFields( data + i, length - i, &fieldEnds );

		// Normally the whole consumed range is the descriptor. If random bytes after it were swallowed, drop trailing
		// fields until what's left is a plausible descriptor.
		google::protobuf::FileDescriptorProto candidate;
		size_t used = 0;
		int attempts = 0;
		for ( size_t k = fieldEnds.size(); k > 0 && attempts < 24; k--, attempts++ )
		{
			const size_t end = fieldEnds[ k - 1 ];
			candidate.Clear();
			if ( candidate.ParseFromArray( data + i, static_cast<int>( end ) ) && candidate.name() == protoName && IsPlausibleDescriptor( candidate ) )
			{
				used = end;
				break;
			}
		}

		if ( used == 0 )
		{
			stats.invalid++;
			i += std::max<size_t>( 1, consumed );
			continue;
		}

		seen.insert( protoName );
		out.push_back( std::move( candidate ) );
		stats.accepted++;

		i += std::max<size_t>( 1, used );
		continue;
	}
}



bool ScanFileForDescriptors(
	const std::string &path,
	std::vector<google::protobuf::FileDescriptorProto> &out,
	std::set<std::string> &seen,
	ScanStats &stats,
	std::string &error )
{
	std::ifstream file( path, std::ios::binary | std::ios::ate );
	if ( !file )
	{
		error = "unable to open " + path;
		return false;
	}

	const std::streamoff size = file.tellg();
	if ( size <= 0 )
	{
		error = "file is empty: " + path;
		return false;
	}

	std::vector<uint8_t> buffer( static_cast<size_t>( size ) );
	file.seekg( 0, std::ios::beg );
	if ( !file.read( reinterpret_cast<char *>( buffer.data() ), size ) )
	{
		error = "unable to read " + path;
		return false;
	}

	ScanBufferForDescriptors( buffer.data(), buffer.size(), out, seen, stats );
	return true;
}

} // namespace nh2
