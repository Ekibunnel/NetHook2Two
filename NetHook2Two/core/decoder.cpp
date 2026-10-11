#include "decoder.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <sstream>

#include <google/protobuf/message.h>
#include <google/protobuf/unknown_field_set.h>

using namespace google::protobuf;

namespace nh2
{

namespace
{

// EMsgs that matter for decoding. Values are stable parts of the Steam protocol.
constexpr uint32_t k_EMsgMulti = 1;
constexpr uint32_t k_EMsgServiceMethod = 146;
constexpr uint32_t k_EMsgServiceMethodResponse = 147;
constexpr uint32_t k_EMsgServiceMethodCallFromClient = 151;
constexpr uint32_t k_EMsgServiceMethodSendToClient = 152;
constexpr uint32_t k_EMsgChannelEncryptRequest = 1303;
constexpr uint32_t k_EMsgChannelEncryptResponse = 1304;
constexpr uint32_t k_EMsgChannelEncryptResult = 1305;
constexpr uint32_t k_EMsgClientToGC = 5452;
constexpr uint32_t k_EMsgClientFromGC = 5453;
constexpr uint32_t k_EMsgClientServiceMethodLegacy = 5594;
constexpr uint32_t k_EMsgClientServiceMethodLegacyResponse = 5595;
constexpr uint32_t k_EMsgServiceMethodCallFromClientNonAuthed = 9804;

constexpr uint32_t kProtoMask = 0x80000000u;
constexpr size_t kMaxRepeatedShown = 2000;
constexpr int kMaxDepth = 40;

bool IsServiceMethodEMsg( uint32_t emsg )
{
	return emsg == k_EMsgServiceMethod || emsg == k_EMsgServiceMethodResponse || emsg == k_EMsgServiceMethodCallFromClient ||
		emsg == k_EMsgServiceMethodSendToClient || emsg == k_EMsgServiceMethodCallFromClientNonAuthed;
}

bool IsChannelEncryptEMsg( uint32_t emsg )
{
	return emsg == k_EMsgChannelEncryptRequest || emsg == k_EMsgChannelEncryptResponse || emsg == k_EMsgChannelEncryptResult;
}

uint32_t ReadU32( const uint8_t *p ) { uint32_t v; memcpy( &v, p, 4 ); return v; }
uint64_t ReadU64( const uint8_t *p ) { uint64_t v; memcpy( &v, p, 8 ); return v; }
uint16_t ReadU16( const uint8_t *p ) { uint16_t v; memcpy( &v, p, 2 ); return v; }

std::string Format( const char *fmt, ... )
{
	char buffer[ 512 ];
	va_list args;
	va_start( args, fmt );
	vsnprintf( buffer, sizeof( buffer ), fmt, args );
	va_end( args );
	return buffer;
}

std::string ToLower( std::string s )
{
	std::transform( s.begin(), s.end(), s.begin(), []( unsigned char c ) { return static_cast<char>( std::tolower( c ) ); } );
	return s;
}

std::string StripEMsgPrefix( const std::string &name )
{
	if ( name.rfind( "k_EMsg", 0 ) == 0 )
		return name.substr( 6 );
	if ( name.rfind( "k_", 0 ) == 0 )
		return name.substr( 2 );
	if ( name.rfind( "EMsg", 0 ) == 0 && name.size() > 4 )
		return name.substr( 4 );
	return name;
}

//
// Minimal protobuf wire reader (independent of any descriptors)
//
struct WireReader
{
	const uint8_t *data;
	size_t size;
	size_t pos = 0;

	WireReader( const uint8_t *d, size_t n ) : data( d ), size( n ) {}

	bool AtEnd() const { return pos >= size; }

	bool Varint( uint64_t &v )
	{
		v = 0;
		for ( int shift = 0; shift < 70 && pos < size; shift += 7 )
		{
			const uint8_t b = data[ pos++ ];
			if ( shift < 64 )
				v |= static_cast<uint64_t>( b & 0x7F ) << shift;
			if ( ( b & 0x80 ) == 0 )
				return true;
		}
		return false;
	}

	bool Skip( size_t n )
	{
		if ( n > size - pos )
			return false;
		pos += n;
		return true;
	}
};

struct RawField
{
	uint32_t number = 0;
	uint32_t wire = 0;
	uint64_t value = 0;           // varint / fixed
	const uint8_t *bytes = nullptr; // length delimited
	size_t length = 0;
};

// Strict parse: the whole buffer must be a sequence of valid fields.
bool ParseRaw( const uint8_t *data, size_t size, std::vector<RawField> &out )
{
	WireReader r( data, size );
	while ( !r.AtEnd() )
	{
		uint64_t tag;
		if ( !r.Varint( tag ) )
			return false;

		RawField f;
		f.number = static_cast<uint32_t>( tag >> 3 );
		f.wire = static_cast<uint32_t>( tag & 7 );
		if ( f.number == 0 || ( tag >> 3 ) > 536870911ull )
			return false;

		switch ( f.wire )
		{
		case 0:
			if ( !r.Varint( f.value ) )
				return false;
			break;
		case 1:
			if ( r.size - r.pos < 8 )
				return false;
			f.value = ReadU64( r.data + r.pos );
			r.pos += 8;
			break;
		case 2:
		{
			uint64_t len;
			if ( !r.Varint( len ) || len > r.size - r.pos )
				return false;
			f.bytes = r.data + r.pos;
			f.length = static_cast<size_t>( len );
			r.pos += f.length;
			break;
		}
		case 5:
			if ( r.size - r.pos < 4 )
				return false;
			f.value = ReadU32( r.data + r.pos );
			r.pos += 4;
			break;
		default:
			return false;
		}

		out.push_back( f );
		if ( out.size() > 100000 )
			return false;
	}

	return !out.empty();
}

//
// Header parsing without descriptors (CMsgProtoBufHeader field numbers are stable)
//
struct LiteHeader
{
	bool ok = false;
	uint64_t steamId = 0;
	uint64_t jobSource = ~0ull;
	uint64_t jobTarget = ~0ull;
	int32_t sessionId = 0;
	std::string targetJobName;
};

LiteHeader ParseLiteHeader( const uint8_t *data, size_t size )
{
	LiteHeader h;
	WireReader r( data, size );

	while ( !r.AtEnd() )
	{
		uint64_t tag;
		if ( !r.Varint( tag ) )
			return h;

		const uint32_t field = static_cast<uint32_t>( tag >> 3 );
		const uint32_t wire = static_cast<uint32_t>( tag & 7 );

		switch ( wire )
		{
		case 0:
		{
			uint64_t v;
			if ( !r.Varint( v ) )
				return h;
			if ( field == 2 )
				h.sessionId = static_cast<int32_t>( v );
			break;
		}
		case 1:
		{
			if ( r.size - r.pos < 8 )
				return h;
			const uint64_t v = ReadU64( r.data + r.pos );
			r.pos += 8;
			if ( field == 1 ) h.steamId = v;
			else if ( field == 10 ) h.jobSource = v;
			else if ( field == 11 ) h.jobTarget = v;
			break;
		}
		case 2:
		{
			uint64_t len;
			if ( !r.Varint( len ) || len > r.size - r.pos )
				return h;
			if ( field == 12 )
				h.targetJobName.assign( reinterpret_cast<const char *>( r.data + r.pos ), static_cast<size_t>( len ) );
			r.pos += static_cast<size_t>( len );
			break;
		}
		case 5:
			if ( !r.Skip( 4 ) )
				return h;
			break;
		default:
			return h;
		}
	}

	h.ok = true;
	return h;
}

// Reads the top level fields of CMsgGCClient / CMsgClientServiceMethodLegacy(Response) without descriptors.
struct LiteGCClient
{
	uint32_t appId = 0;
	uint32_t msgType = 0;
	bool hasMsgType = false;
	std::string methodName;
	const uint8_t *payload = nullptr;
	size_t payloadSize = 0;
};

LiteGCClient ParseLiteGCClient( const uint8_t *data, size_t size )
{
	LiteGCClient g;
	std::vector<RawField> fields;
	if ( !ParseRaw( data, size, fields ) )
		return g;

	for ( const RawField &f : fields )
	{
		if ( f.wire == 0 && f.number == 1 ) g.appId = static_cast<uint32_t>( f.value );
		else if ( f.wire == 0 && f.number == 2 ) { g.msgType = static_cast<uint32_t>( f.value ); g.hasMsgType = true; }
		else if ( f.wire == 2 && f.number == 3 ) { g.payload = f.bytes; g.payloadSize = f.length; }
	}
	return g;
}

bool IsValidUtf8( const uint8_t *s, size_t n )
{
	size_t i = 0;
	while ( i < n )
	{
		const uint8_t c = s[ i ];
		size_t extra;
		if ( c < 0x80 ) extra = 0;
		else if ( c >= 0xC2 && c <= 0xDF ) extra = 1;
		else if ( c >= 0xE0 && c <= 0xEF ) extra = 2;
		else if ( c >= 0xF0 && c <= 0xF4 ) extra = 3;
		else return false;

		if ( extra != 0 && i + extra >= n )
			return false;

		for ( size_t k = 1; k <= extra; k++ )
		{
			if ( ( s[ i + k ] & 0xC0 ) != 0x80 )
				return false;
		}
		i += extra + 1;
	}
	return true;
}

bool LooksLikeText( const uint8_t *s, size_t n )
{
	if ( n == 0 || !IsValidUtf8( s, n ) )
		return false;

	for ( size_t i = 0; i < n; i++ )
	{
		const uint8_t c = s[ i ];
		if ( c < 0x20 && c != '\t' && c != '\n' && c != '\r' )
			return false;
		if ( c == 0x7F )
			return false;
	}
	return true;
}

std::string Quote( const std::string &s, size_t maxLen = 400 )
{
	std::string out = "\"";
	size_t shown = 0;
	for ( unsigned char c : s )
	{
		if ( shown >= maxLen )
		{
			out += "...";
			break;
		}

		switch ( c )
		{
		case '\n': out += "\\n"; break;
		case '\r': out += "\\r"; break;
		case '\t': out += "\\t"; break;
		case '"': out += "\\\""; break;
		case '\\': out += "\\\\"; break;
		default:
			if ( c < 0x20 || c == 0x7F )
				out += Format( "\\x%02X", c );
			else
				out += static_cast<char>( c );
		}
		shown++;
	}
	out += "\"";
	return out;
}

std::string HexPreview( const uint8_t *d, size_t n, size_t maxBytes = 32 )
{
	static const char digits[] = "0123456789ABCDEF";
	std::string s;
	const size_t shown = std::min( n, maxBytes );
	s.reserve( shown * 3 + 24 );
	for ( size_t i = 0; i < shown; i++ )
	{
		if ( i ) s += ' ';
		s += digits[ d[ i ] >> 4 ];
		s += digits[ d[ i ] & 15 ];
	}
	if ( shown < n )
		s += " ...";
	return s;
}

std::string HexString( const uint8_t *d, size_t n )
{
	static const char digits[] = "0123456789ABCDEF";
	std::string s;
	s.reserve( n * 2 );
	for ( size_t i = 0; i < n; i++ )
	{
		s += digits[ d[ i ] >> 4 ];
		s += digits[ d[ i ] & 15 ];
	}
	return s;
}

Node MakeValue( const std::string &name, const std::string &type, const std::string &value, const std::string &note = std::string() )
{
	Node n;
	n.kind = Node::Kind::Value;
	n.name = name;
	n.type = type;
	n.value = value;
	n.copyText = value;
	n.note = note;
	return n;
}

Node MakeError( const std::string &name, const std::string &message )
{
	Node n;
	n.kind = Node::Kind::Error;
	n.name = name;
	n.value = message;
	n.copyText = message;
	return n;
}

Node MakeContainer( const std::string &name, const std::string &type, bool open = false )
{
	Node n;
	n.kind = Node::Kind::Container;
	n.name = name;
	n.type = type;
	n.open = open;
	return n;
}

// Builds the node for a blob. Text and nested protobuf interpretations become children.
Node MakeBytes( const std::string &name, const uint8_t *d, size_t n, int depth, const std::string &type = "bytes" )
{
	Node node;
	node.kind = Node::Kind::Bytes;
	node.name = name;
	node.type = type;
	node.data.assign( d, d + n );
	node.value = n == 0 ? std::string( "(empty)" ) : HexPreview( d, n ) + Format( "  (%zu bytes)", n );
	node.copyText = HexString( d, n );

	if ( n == 0 )
		return node;

	if ( LooksLikeText( d, n ) )
	{
		node.children.push_back( MakeValue( "as text", "string", Quote( std::string( reinterpret_cast<const char *>( d ), n ), 2000 ) ) );
		node.children.back().copyText.assign( reinterpret_cast<const char *>( d ), n );
	}

	return node;
}

Node RawFieldsToNode( const std::string &name, const uint8_t *d, size_t n, int depth, bool open );

Node RawFieldToNode( const RawField &f, int depth )
{
	const std::string name = "field " + std::to_string( f.number );

	switch ( f.wire )
	{
	case 0:
		return MakeValue( name, "varint", std::to_string( f.value ), f.value > 0x7FFFFFFFFFFFFFFFull ? "as signed: " + std::to_string( static_cast<int64_t>( f.value ) ) : std::string() );
	case 1:
	{
		double dbl;
		memcpy( &dbl, &f.value, 8 );
		return MakeValue( name, "fixed64", std::to_string( f.value ), std::isfinite( dbl ) && std::fabs( dbl ) > 1e-6 && std::fabs( dbl ) < 1e12 ? Format( "as double: %g", dbl ) : std::string() );
	}
	case 5:
	{
		float flt;
		const uint32_t v = static_cast<uint32_t>( f.value );
		memcpy( &flt, &v, 4 );
		return MakeValue( name, "fixed32", std::to_string( v ), std::isfinite( flt ) && std::fabs( flt ) > 1e-4f && std::fabs( flt ) < 1e9f ? Format( "as float: %g", flt ) : std::string() );
	}
	default:
		break;
	}

	// length delimited: string, nested message or blob
	if ( f.length == 0 )
		return MakeValue( name, "string/bytes", "(empty)" );

	if ( LooksLikeText( f.bytes, f.length ) )
	{
		Node n = MakeValue( name, "string", Quote( std::string( reinterpret_cast<const char *>( f.bytes ), f.length ) ) );
		n.copyText.assign( reinterpret_cast<const char *>( f.bytes ), f.length );
		return n;
	}

	if ( depth < 8 )
	{
		std::vector<RawField> nested;
		if ( ParseRaw( f.bytes, f.length, nested ) )
		{
			Node n = RawFieldsToNode( name, f.bytes, f.length, depth + 1, false );
			n.type = "message?";
			return n;
		}
	}

	return MakeBytes( name, f.bytes, f.length, depth );
}

Node RawFieldsToNode( const std::string &name, const uint8_t *d, size_t n, int depth, bool open )
{
	Node node = MakeContainer( name, "protobuf (schema unknown)", open );

	std::vector<RawField> fields;
	if ( !ParseRaw( d, n, fields ) )
	{
		Node bytes = MakeBytes( name, d, n, depth );
		bytes.note = "not a valid protobuf";
		return bytes;
	}

	for ( const RawField &f : fields )
		node.children.push_back( RawFieldToNode( f, depth ) );

	return node;
}

void AppendChildrenText( const Node &node, int indent, std::ostringstream &out )
{
	for ( const Node &child : node.children )
	{
		out << std::string( static_cast<size_t>( indent ) * 2, ' ' ) << child.name;
		if ( !child.type.empty() )
			out << " (" << child.type << ")";

		if ( child.kind != Node::Kind::Container )
			out << ": " << child.value;

		if ( !child.note.empty() )
			out << "  // " << child.note;

		if ( child.unset )
			out << "  [unset]";

		out << "\n";
		AppendChildrenText( child, indent + 1, out );
	}
}

} // namespace


//
// Formatting helpers
//
std::string FormatUnixTime( int64_t seconds )
{
	// civil_from_days (Howard Hinnant), so that we don't depend on the platform's gmtime
	int64_t days = seconds / 86400;
	int64_t rem = seconds % 86400;
	if ( rem < 0 ) { rem += 86400; days--; }

	days += 719468;
	const int64_t era = ( days >= 0 ? days : days - 146096 ) / 146097;
	const int64_t doe = days - era * 146097;
	const int64_t yoe = ( doe - doe / 1460 + doe / 36524 - doe / 146096 ) / 365;
	int64_t y = yoe + era * 400;
	const int64_t doy = doe - ( 365 * yoe + yoe / 4 - yoe / 100 );
	const int64_t mp = ( 5 * doy + 2 ) / 153;
	const int64_t d = doy - ( 153 * mp + 2 ) / 5 + 1;
	const int64_t m = mp < 10 ? mp + 3 : mp - 9;
	if ( m <= 2 ) y++;

	return Format( "%04lld-%02lld-%02lld %02lld:%02lld:%02lld UTC",
		static_cast<long long>( y ), static_cast<long long>( m ), static_cast<long long>( d ),
		static_cast<long long>( rem / 3600 ), static_cast<long long>( ( rem / 60 ) % 60 ), static_cast<long long>( rem % 60 ) );
}

std::string FormatSteamId( uint64_t id )
{
	const uint32_t account = static_cast<uint32_t>( id & 0xFFFFFFFFu );
	const uint32_t instance = static_cast<uint32_t>( ( id >> 32 ) & 0xFFFFFu );
	const uint32_t type = static_cast<uint32_t>( ( id >> 52 ) & 0xFu );
	const uint32_t universe = static_cast<uint32_t>( id >> 56 );

	if ( type == 0 && account == 0 )
		return "invalid";

	char letter = 'i';
	switch ( type )
	{
	case 1: letter = 'U'; break;
	case 2: letter = 'M'; break;
	case 3: letter = 'G'; break;
	case 4: letter = 'A'; break;
	case 5: letter = 'P'; break;
	case 6: letter = 'C'; break;
	case 7: letter = 'g'; break;
	case 8: letter = ( instance & 0x40000 ) ? 'L' : ( ( instance & 0x80000 ) ? 'c' : 'T' ); break;
	case 9: letter = 'I'; break;
	case 10: letter = 'a'; break;
	default: letter = 'i'; break;
	}

	std::string s = Format( "[%c:%u:%u", letter, universe, account );
	if ( type == 1 ? instance != 1 : ( instance != 0 && type != 7 ) )
		s += Format( ":%u", instance );
	s += "]";

	if ( type == 1 && universe <= 5 )
		s += Format( " (STEAM_%u:%u:%u)", universe == 1 ? 0u : universe, account & 1, account >> 1 );

	return s;
}

std::string HexDump( const uint8_t *data, size_t length, size_t bytesPerLine )
{
	static const char digits[] = "0123456789ABCDEF";
	std::string out;
	out.reserve( length * 4 + 64 );

	for ( size_t offset = 0; offset < length; offset += bytesPerLine )
	{
		out += Format( "%08zX  ", offset );
		for ( size_t i = 0; i < bytesPerLine; i++ )
		{
			if ( offset + i < length )
			{
				out += digits[ data[ offset + i ] >> 4 ];
				out += digits[ data[ offset + i ] & 15 ];
				out += ' ';
			}
			else
				out += "   ";

			if ( i == 7 )
				out += ' ';
		}

		out += " ";
		for ( size_t i = 0; i < bytesPerLine && offset + i < length; i++ )
		{
			const uint8_t c = data[ offset + i ];
			out += ( c >= 0x20 && c < 0x7F ) ? static_cast<char>( c ) : '.';
		}
		out += "\n";
	}
	return out;
}

std::string NodeToText( const Node &node )
{
	std::ostringstream out;
	out << node.name;
	if ( !node.type.empty() )
		out << " (" << node.type << ")";
	if ( node.kind != Node::Kind::Container )
		out << ": " << node.value;
	if ( !node.note.empty() )
		out << "  // " << node.note;
	out << "\n";
	AppendChildrenText( node, 1, out );
	return out.str();
}


//
// Decoder
//
namespace
{

class Builder
{
public:
	Builder( const DescriptorStore *store, const DecodeOptions &options, const std::string &hookName )
		: store_( store ), options_( options ), hookName_( hookName )
	{
	}

	Node BuildPacket( const uint8_t *data, size_t size );

private:
	Node FromMessage( const std::string &name, const Message &msg, int depth, bool open );
	Node FromBytesAsMessage( const std::string &name, const Descriptor *descriptor, const uint8_t *d, size_t n, bool open );
	Node FieldNode( const Message &msg, const Reflection *refl, const FieldDescriptor *fd, int index, bool isSet, int depth );
	Node RepeatedNode( const Message &msg, const Reflection *refl, const FieldDescriptor *fd, int depth );
	Node UnknownFieldsNode( const UnknownFieldSet &unknown, int depth );
	void Annotate( Node &node, const FieldDescriptor *fd, uint64_t value, bool isSigned );

	const Descriptor *FindDescriptor( const char *name ) const { return store_ ? store_->FindMessage( name ) : nullptr; }
	const MethodDescriptor *FindMethod( const std::string &jobName ) const;
	std::string ResolveEMsgName( uint32_t emsg ) const;

	void AddGameCoordinator( Node &root, const Message &body, int depth );
	void AddLegacyServiceMethod( Node &root, const Message &body, bool isResponse, int depth );

	const DescriptorStore *store_;
	DecodeOptions options_;
	std::string hookName_;
};

std::string Builder::ResolveEMsgName( uint32_t emsg ) const
{
	std::string name = StripEMsgPrefix( hookName_ );
	if ( !name.empty() && name != "UNKNOWN" && name != "Unknown" && name != "<unknown>" )
		return name;

	return store_ ? store_->EMsgName( emsg ) : std::string();
}

const MethodDescriptor *Builder::FindMethod( const std::string &jobName ) const
{
	if ( !store_ || jobName.empty() )
		return nullptr;

	const size_t dot = jobName.find( '.' );
	if ( dot == std::string::npos )
		return nullptr;

	const std::string serviceName = jobName.substr( 0, dot );
	std::string methodName = jobName.substr( dot + 1 );
	const size_t hash = methodName.find( '#' );
	if ( hash != std::string::npos )
		methodName.resize( hash );

	const ServiceDescriptor *service = store_->FindService( serviceName );
	return service ? service->FindMethodByName( methodName ) : nullptr;
}

void Builder::Annotate( Node &node, const FieldDescriptor *fd, uint64_t value, bool /*isSigned*/ )
{
	const std::string lower = ToLower( fd->name() );

	const bool is64 = fd->cpp_type() == FieldDescriptor::CPPTYPE_UINT64 || fd->cpp_type() == FieldDescriptor::CPPTYPE_INT64;

	if ( is64 && ( lower.find( "steamid" ) != std::string::npos || lower.find( "steam_id" ) != std::string::npos ) &&
		value != 0 && value != ~0ull )
	{
		node.note = FormatSteamId( value );
		return;
	}

	if ( is64 && value == ~0ull && ( lower.find( "jobid" ) != std::string::npos || lower.find( "messageid" ) != std::string::npos ) )
	{
		node.note = "none";
		return;
	}

	const bool isInt = is64 || fd->cpp_type() == FieldDescriptor::CPPTYPE_UINT32 || fd->cpp_type() == FieldDescriptor::CPPTYPE_INT32;
	if ( isInt && lower.find( "time" ) != std::string::npos )
	{
		// 2000-01-01 .. 2100-01-01
		if ( value >= 946684800ull && value <= 4102444800ull )
			node.note = FormatUnixTime( static_cast<int64_t>( value ) );
	}
}

Node Builder::FieldNode( const Message &msg, const Reflection *refl, const FieldDescriptor *fd, int index, bool isSet, int depth )
{
	const bool repeatedItem = index >= 0;
	const std::string name = repeatedItem ? "[" + std::to_string( index ) + "]" : ( fd->is_extension() ? "[" + fd->full_name() + "]" : fd->name() );

	Node node;

	switch ( fd->cpp_type() )
	{
	case FieldDescriptor::CPPTYPE_INT32:
	{
		const int32_t v = repeatedItem ? refl->GetRepeatedInt32( msg, fd, index ) : refl->GetInt32( msg, fd );
		node = MakeValue( name, fd->type_name(), std::to_string( v ) );
		Annotate( node, fd, static_cast<uint64_t>( static_cast<int64_t>( v ) ), true );
		break;
	}
	case FieldDescriptor::CPPTYPE_INT64:
	{
		const int64_t v = repeatedItem ? refl->GetRepeatedInt64( msg, fd, index ) : refl->GetInt64( msg, fd );
		node = MakeValue( name, fd->type_name(), std::to_string( static_cast<long long>( v ) ) );
		Annotate( node, fd, static_cast<uint64_t>( v ), true );
		break;
	}
	case FieldDescriptor::CPPTYPE_UINT32:
	{
		const uint32_t v = repeatedItem ? refl->GetRepeatedUInt32( msg, fd, index ) : refl->GetUInt32( msg, fd );
		node = MakeValue( name, fd->type_name(), std::to_string( v ) );
		Annotate( node, fd, v, false );
		break;
	}
	case FieldDescriptor::CPPTYPE_UINT64:
	{
		const uint64_t v = repeatedItem ? refl->GetRepeatedUInt64( msg, fd, index ) : refl->GetUInt64( msg, fd );
		node = MakeValue( name, fd->type_name(), std::to_string( static_cast<unsigned long long>( v ) ) );
		Annotate( node, fd, v, false );
		break;
	}
	case FieldDescriptor::CPPTYPE_DOUBLE:
	{
		const double v = repeatedItem ? refl->GetRepeatedDouble( msg, fd, index ) : refl->GetDouble( msg, fd );
		node = MakeValue( name, fd->type_name(), Format( "%.17g", v ) );
		break;
	}
	case FieldDescriptor::CPPTYPE_FLOAT:
	{
		const float v = repeatedItem ? refl->GetRepeatedFloat( msg, fd, index ) : refl->GetFloat( msg, fd );
		node = MakeValue( name, fd->type_name(), Format( "%.9g", static_cast<double>( v ) ) );
		break;
	}
	case FieldDescriptor::CPPTYPE_BOOL:
	{
		const bool v = repeatedItem ? refl->GetRepeatedBool( msg, fd, index ) : refl->GetBool( msg, fd );
		node = MakeValue( name, fd->type_name(), v ? "true" : "false" );
		break;
	}
	case FieldDescriptor::CPPTYPE_ENUM:
	{
		const EnumValueDescriptor *v = repeatedItem ? refl->GetRepeatedEnum( msg, fd, index ) : refl->GetEnum( msg, fd );
		node = MakeValue( name, fd->enum_type()->full_name(), v->name() + " (" + std::to_string( v->number() ) + ")" );
		node.copyText = v->name();
		break;
	}
	case FieldDescriptor::CPPTYPE_STRING:
	{
		const std::string v = repeatedItem ? refl->GetRepeatedString( msg, fd, index ) : refl->GetString( msg, fd );
		if ( fd->type() == FieldDescriptor::TYPE_BYTES )
		{
			node = MakeBytes( name, reinterpret_cast<const uint8_t *>( v.data() ), v.size(), depth );

			// Blobs are often nested protobuf messages (or contain one); offer that view when it's plausible.
			if ( v.size() > 1 && depth < 8 && node.children.empty() )
			{
				std::vector<RawField> nested;
				if ( ParseRaw( reinterpret_cast<const uint8_t *>( v.data() ), v.size(), nested ) )
				{
					Node asProto = RawFieldsToNode( "as protobuf?", reinterpret_cast<const uint8_t *>( v.data() ), v.size(), depth + 1, false );
					node.children.push_back( std::move( asProto ) );
				}
			}
		}
		else
		{
			node = MakeValue( name, "string", Quote( v ) );
			node.copyText = v;
		}
		break;
	}
	case FieldDescriptor::CPPTYPE_MESSAGE:
	{
		if ( !repeatedItem && !isSet )
		{
			node = MakeContainer( name, fd->message_type()->full_name() );
			break;
		}

		const Message &sub = repeatedItem ? refl->GetRepeatedMessage( msg, fd, index ) : refl->GetMessage( msg, fd );
		node = FromMessage( name, sub, depth + 1, false );
		break;
	}
	}

	node.unset = !isSet && !repeatedItem;
	return node;
}

Node Builder::RepeatedNode( const Message &msg, const Reflection *refl, const FieldDescriptor *fd, int depth )
{
	const int count = refl->FieldSize( msg, fd );

	std::string typeName = fd->cpp_type() == FieldDescriptor::CPPTYPE_MESSAGE ? fd->message_type()->full_name() :
		( fd->cpp_type() == FieldDescriptor::CPPTYPE_ENUM ? fd->enum_type()->full_name() : std::string( fd->type_name() ) );

	Node node = MakeContainer( fd->is_extension() ? "[" + fd->full_name() + "]" : fd->name(), "repeated " + typeName );
	node.note = std::to_string( count ) + ( count == 1 ? " item" : " items" );

	const int shown = static_cast<int>( std::min<size_t>( static_cast<size_t>( count ), kMaxRepeatedShown ) );
	for ( int i = 0; i < shown; i++ )
		node.children.push_back( FieldNode( msg, refl, fd, i, true, depth ) );

	if ( shown < count )
		node.children.push_back( MakeValue( "...", "", Format( "%d more items not shown", count - shown ) ) );

	return node;
}

Node Builder::UnknownFieldsNode( const UnknownFieldSet &unknown, int depth )
{
	Node node = MakeContainer( "unknown fields", "not in the protobuf definition" );
	node.note = std::to_string( unknown.field_count() ) + " fields";

	for ( int i = 0; i < unknown.field_count(); i++ )
	{
		const UnknownField &f = unknown.field( i );
		RawField raw;
		raw.number = static_cast<uint32_t>( f.number() );

		switch ( f.type() )
		{
		case UnknownField::TYPE_VARINT:
			raw.wire = 0;
			raw.value = f.varint();
			node.children.push_back( RawFieldToNode( raw, depth ) );
			break;
		case UnknownField::TYPE_FIXED32:
			raw.wire = 5;
			raw.value = f.fixed32();
			node.children.push_back( RawFieldToNode( raw, depth ) );
			break;
		case UnknownField::TYPE_FIXED64:
			raw.wire = 1;
			raw.value = f.fixed64();
			node.children.push_back( RawFieldToNode( raw, depth ) );
			break;
		case UnknownField::TYPE_LENGTH_DELIMITED:
		{
			const std::string &bytes = f.length_delimited();
			raw.wire = 2;
			raw.bytes = reinterpret_cast<const uint8_t *>( bytes.data() );
			raw.length = bytes.size();
			node.children.push_back( RawFieldToNode( raw, depth ) );
			break;
		}
		case UnknownField::TYPE_GROUP:
			node.children.push_back( MakeValue( "field " + std::to_string( f.number() ), "group", Format( "%d fields", f.group().field_count() ) ) );
			break;
		}
	}

	return node;
}

Node Builder::FromMessage( const std::string &name, const Message &msg, int depth, bool open )
{
	const Descriptor *descriptor = msg.GetDescriptor();
	Node node = MakeContainer( name, descriptor->full_name(), open );

	if ( depth > kMaxDepth )
	{
		node.children.push_back( MakeError( "...", "nesting too deep" ) );
		return node;
	}

	const Reflection *refl = msg.GetReflection();

	std::vector<const FieldDescriptor *> fields;
	refl->ListFields( msg, &fields );

	std::vector<const FieldDescriptor *> unsetFields;
	if ( options_.showUnsetFields )
	{
		for ( int i = 0; i < descriptor->field_count(); i++ )
		{
			const FieldDescriptor *fd = descriptor->field( i );
			if ( std::find( fields.begin(), fields.end(), fd ) == fields.end() )
				unsetFields.push_back( fd );
		}

		fields.insert( fields.end(), unsetFields.begin(), unsetFields.end() );
		std::stable_sort( fields.begin(), fields.end(), []( const FieldDescriptor *a, const FieldDescriptor *b ) { return a->number() < b->number(); } );
	}

	for ( const FieldDescriptor *fd : fields )
	{
		const bool isSet = std::find( unsetFields.begin(), unsetFields.end(), fd ) == unsetFields.end();

		if ( fd->is_repeated() )
		{
			Node rep = RepeatedNode( msg, refl, fd, depth );
			rep.unset = !isSet;
			node.children.push_back( std::move( rep ) );
		}
		else
		{
			node.children.push_back( FieldNode( msg, refl, fd, -1, isSet, depth ) );
		}
	}

	const UnknownFieldSet &unknown = refl->GetUnknownFields( msg );
	if ( unknown.field_count() > 0 )
		node.children.push_back( UnknownFieldsNode( unknown, depth ) );

	return node;
}

Node Builder::FromBytesAsMessage( const std::string &name, const Descriptor *descriptor, const uint8_t *d, size_t n, bool open )
{
	std::unique_ptr<Message> msg = store_ ? store_->NewMessage( descriptor ) : nullptr;
	if ( msg && msg->ParsePartialFromArray( d, static_cast<int>( n ) ) )
		return FromMessage( name, *msg, 0, open );

	Node fallback = RawFieldsToNode( name, d, n, 0, open );
	fallback.note = "could not be parsed as " + ( descriptor ? descriptor->full_name() : std::string( "known type" ) ) + ", showing raw fields";
	return fallback;
}

void Builder::AddLegacyServiceMethod( Node &root, const Message &body, bool isResponse, int depth )
{
	const Descriptor *d = body.GetDescriptor();
	const Reflection *refl = body.GetReflection();

	const FieldDescriptor *nameField = d->FindFieldByName( "method_name" );
	const FieldDescriptor *dataField = d->FindFieldByName( isResponse ? "serialized_method_response" : "serialized_method" );
	if ( nameField == nullptr || dataField == nullptr || !refl->HasField( body, dataField ) )
		return;

	const std::string methodName = refl->GetString( body, nameField );
	const std::string payload = refl->GetString( body, dataField );

	const MethodDescriptor *method = FindMethod( methodName );
	const Descriptor *type = method ? ( isResponse ? method->output_type() : method->input_type() ) : nullptr;

	const char *label = isResponse ? "Service Method Response" : "Service Method Request";
	const uint8_t *bytes = reinterpret_cast<const uint8_t *>( payload.data() );

	if ( type != nullptr )
		root.children.push_back( FromBytesAsMessage( label, type, bytes, payload.size(), true ) );
	else if ( !payload.empty() )
		root.children.push_back( RawFieldsToNode( label, bytes, payload.size(), 0, true ) );
}

void Builder::AddGameCoordinator( Node &root, const Message &body, int depth )
{
	const Descriptor *d = body.GetDescriptor();
	const Reflection *refl = body.GetReflection();

	const FieldDescriptor *appField = d->FindFieldByName( "appid" );
	const FieldDescriptor *typeField = d->FindFieldByName( "msgtype" );
	const FieldDescriptor *payloadField = d->FindFieldByName( "payload" );
	if ( !appField || !typeField || !payloadField || !refl->HasField( body, payloadField ) )
		return;

	const uint32_t appId = refl->GetUInt32( body, appField );
	const uint32_t rawType = refl->GetUInt32( body, typeField );
	const bool isProto = ( rawType & kProtoMask ) != 0;
	const uint32_t gcMsg = rawType & ~kProtoMask;

	const std::string payload = refl->GetString( body, payloadField );
	const uint8_t *p = reinterpret_cast<const uint8_t *>( payload.data() );
	const size_t n = payload.size();

	std::string label;
	if ( store_ )
	{
		const auto names = store_->GCMessageNames( gcMsg, appId );
		for ( size_t i = 0; i < names.size(); i++ )
			label += ( i ? " / " : "" ) + names[ i ];
	}
	if ( label.empty() )
		label = std::to_string( gcMsg );

	Node gc = MakeContainer( "Game Coordinator Message", "GC", true );
	gc.note = label + " (app " + std::to_string( appId ) + ")";
	gc.children.push_back( MakeValue( "appid", "uint32", std::to_string( appId ) ) );
	gc.children.push_back( MakeValue( "emsg", isProto ? "protobuf" : "struct", label + " (" + std::to_string( gcMsg ) + ")" ) );

	size_t bodyOffset = 0;
	if ( isProto )
	{
		if ( n >= 8 )
		{
			const uint32_t headerLength = ReadU32( p + 4 );
			if ( headerLength <= n - 8 )
			{
				const Descriptor *headerType = FindDescriptor( "CMsgProtoBufHeader" );
				gc.children.push_back( FromBytesAsMessage( "Header", headerType, p + 8, headerLength, false ) );
				bodyOffset = 8 + headerLength;
			}
			else
				gc.children.push_back( MakeError( "Header", "invalid GC header length" ) );
		}
	}
	else if ( n >= 18 )
	{
		Node header = MakeContainer( "Header", "MsgGCHdr" );
		header.children.push_back( MakeValue( "headerVersion", "uint16", std::to_string( ReadU16( p ) ) ) );
		header.children.push_back( MakeValue( "targetJobID", "uint64", std::to_string( static_cast<unsigned long long>( ReadU64( p + 2 ) ) ) ) );
		header.children.push_back( MakeValue( "sourceJobID", "uint64", std::to_string( static_cast<unsigned long long>( ReadU64( p + 10 ) ) ) ) );
		gc.children.push_back( std::move( header ) );
		bodyOffset = 18;
	}

	const uint8_t *bodyData = p + bodyOffset;
	const size_t bodySize = n - bodyOffset;

	if ( isProto && store_ )
	{
		// Several games share message ids, so try each candidate and prefer one that leaves no unknown fields.
		std::unique_ptr<Message> best;
		for ( const Descriptor *candidate : store_->GCBodyCandidates( gcMsg, appId ) )
		{
			std::unique_ptr<Message> msg = store_->NewMessage( candidate );
			if ( !msg || !msg->ParsePartialFromArray( bodyData, static_cast<int>( bodySize ) ) )
				continue;

			const bool clean = msg->GetReflection()->GetUnknownFields( *msg ).field_count() == 0;
			if ( !best || clean )
			{
				best = std::move( msg );
				if ( clean )
					break;
			}
		}

		if ( best )
		{
			const std::string source = store_->DefinitionSourceOf( best->GetDescriptor() );
			if ( !source.empty() )
				gc.note += ", definitions: " + source;

			gc.children.push_back( FromMessage( "Body", *best, 0, true ) );
			root.children.push_back( std::move( gc ) );
			return;
		}
	}

	if ( bodySize > 0 )
	{
		Node raw = isProto ? RawFieldsToNode( "Body", bodyData, bodySize, 0, true ) : MakeBytes( "Body", bodyData, bodySize, 0 );
		if ( isProto )
			raw.note = "no protobuf definition known for this message, showing raw fields";
		gc.children.push_back( std::move( raw ) );
	}

	root.children.push_back( std::move( gc ) );
}

Node Builder::BuildPacket( const uint8_t *data, size_t size )
{
	if ( size < 4 )
		return MakeError( "Packet", Format( "Packet is too short (%zu bytes)", size ) );

	const uint32_t rawEMsg = ReadU32( data );
	const bool isProto = ( rawEMsg & kProtoMask ) != 0;
	const uint32_t emsg = rawEMsg & ~kProtoMask;

	const std::string emsgName = ResolveEMsgName( emsg );

	std::string title = "EMsg " + ( emsgName.empty() ? std::string( "<unknown>" ) : emsgName ) + " (" + std::to_string( emsg ) + ")";
	if ( !isProto )
		title += " (Non-Protobuf)";

	Node root = MakeContainer( title, "packet", true );

	size_t bodyOffset = 0;
	LiteHeader lite;

	if ( isProto )
	{
		if ( size < 8 )
		{
			root.children.push_back( MakeError( "Header", "Packet is too short for a protobuf header" ) );
			return root;
		}

		const uint32_t headerLength = ReadU32( data + 4 );
		if ( headerLength > size - 8 )
		{
			root.children.push_back( MakeError( "Header", Format( "Invalid header length %u for a %zu byte packet", headerLength, size ) ) );
			root.children.push_back( MakeBytes( "Raw packet", data, size, 0 ) );
			return root;
		}

		lite = ParseLiteHeader( data + 8, headerLength );

		const Descriptor *headerType = FindDescriptor( "CMsgProtoBufHeader" );
		root.children.push_back( FromBytesAsMessage( "Header", headerType, data + 8, headerLength, false ) );
		bodyOffset = 8 + headerLength;
	}
	else if ( IsChannelEncryptEMsg( emsg ) )
	{
		Node header = MakeContainer( "Header", "MsgHdr" );
		if ( size >= 20 )
		{
			header.children.push_back( MakeValue( "msg", "EMsg", emsgName + " (" + std::to_string( emsg ) + ")" ) );
			header.children.push_back( MakeValue( "targetJobID", "uint64", std::to_string( static_cast<unsigned long long>( ReadU64( data + 4 ) ) ) ) );
			header.children.push_back( MakeValue( "sourceJobID", "uint64", std::to_string( static_cast<unsigned long long>( ReadU64( data + 12 ) ) ) ) );
			bodyOffset = 20;
		}
		else
			header.children.push_back( MakeError( "...", "too short" ) );
		root.children.push_back( std::move( header ) );
	}
	else
	{
		Node header = MakeContainer( "Header", "ExtendedClientMsgHdr" );
		if ( size >= 36 )
		{
			header.children.push_back( MakeValue( "msg", "EMsg", emsgName + " (" + std::to_string( emsg ) + ")" ) );
			header.children.push_back( MakeValue( "headerSize", "uint8", std::to_string( data[ 4 ] ) ) );
			header.children.push_back( MakeValue( "headerVersion", "uint16", std::to_string( ReadU16( data + 5 ) ) ) );
			header.children.push_back( MakeValue( "targetJobID", "uint64", std::to_string( static_cast<unsigned long long>( ReadU64( data + 7 ) ) ) ) );
			header.children.push_back( MakeValue( "sourceJobID", "uint64", std::to_string( static_cast<unsigned long long>( ReadU64( data + 15 ) ) ) ) );
			header.children.push_back( MakeValue( "headerCanary", "uint8", std::to_string( data[ 23 ] ) ) );
			const uint64_t steamId = ReadU64( data + 24 );
			header.children.push_back( MakeValue( "steamID", "uint64", std::to_string( static_cast<unsigned long long>( steamId ) ), FormatSteamId( steamId ) ) );
			header.children.push_back( MakeValue( "sessionID", "int32", std::to_string( static_cast<int32_t>( ReadU32( data + 32 ) ) ) ) );
			bodyOffset = std::max<size_t>( 36, std::min<size_t>( data[ 4 ], size ) );
		}
		else
			header.children.push_back( MakeError( "...", "too short for an extended client header" ) );
		root.children.push_back( std::move( header ) );
	}

	if ( bodyOffset > size )
		bodyOffset = size;

	const uint8_t *body = data + bodyOffset;
	const size_t bodySize = size - bodyOffset;

	if ( !isProto )
	{
		// Struct based messages. Their layouts are defined in SteamLanguage, not in protobufs.
		if ( bodySize > 0 )
		{
			Node raw = MakeBytes( "Body", body, bodySize, 0 );
			raw.note = "struct based message, no decoder available";
			root.children.push_back( std::move( raw ) );
		}
		return root;
	}

	// Pick the body type
	const Descriptor *bodyType = nullptr;
	const MethodDescriptor *method = nullptr;
	if ( IsServiceMethodEMsg( emsg ) && !lite.targetJobName.empty() )
	{
		method = FindMethod( lite.targetJobName );
		if ( method )
			bodyType = emsg == k_EMsgServiceMethodResponse ? method->output_type() : method->input_type();
	}
	else if ( store_ )
	{
		bodyType = store_->FindBodyForEMsg( emsg, emsgName );
	}

	std::unique_ptr<Message> bodyMessage;
	if ( bodyType && store_ )
	{
		bodyMessage = store_->NewMessage( bodyType );
		if ( bodyMessage && !bodyMessage->ParsePartialFromArray( body, static_cast<int>( bodySize ) ) )
			bodyMessage.reset();
	}

	if ( bodyMessage )
	{
		root.children.push_back( FromMessage( "Body", *bodyMessage, 0, true ) );

		const std::string &bodyName = bodyMessage->GetDescriptor()->name();
		if ( emsg == k_EMsgClientToGC || emsg == k_EMsgClientFromGC || bodyName == "CMsgGCClient" )
			AddGameCoordinator( root, *bodyMessage, 0 );
		else if ( emsg == k_EMsgClientServiceMethodLegacy || bodyName == "CMsgClientServiceMethodLegacy" )
			AddLegacyServiceMethod( root, *bodyMessage, false, 0 );
		else if ( emsg == k_EMsgClientServiceMethodLegacyResponse || bodyName == "CMsgClientServiceMethodLegacyResponse" )
			AddLegacyServiceMethod( root, *bodyMessage, true, 0 );
	}
	else if ( bodySize > 0 )
	{
		Node raw = RawFieldsToNode( "Body", body, bodySize, 0, true );
		if ( bodyType )
			raw.note = "could not be parsed as " + bodyType->full_name() + ", showing raw fields";
		else if ( IsServiceMethodEMsg( emsg ) && !lite.targetJobName.empty() )
			raw.note = "service method " + lite.targetJobName + " is not in the protobuf definitions, showing raw fields";
		else
			raw.note = "no protobuf definition known for this message, showing raw fields";
		root.children.push_back( std::move( raw ) );
	}

	return root;
}

} // namespace


PacketDecoder::PacketDecoder( std::shared_ptr<const DescriptorStore> store )
	: store_( std::move( store ) )
{
}

PacketSummary PacketDecoder::Summarize( const uint8_t *data, size_t length, const std::string &hookName ) const
{
	PacketSummary s;
	s.size = length;
	if ( length < 4 )
		return s;

	s.rawEMsg = ReadU32( data );
	s.isProto = ( s.rawEMsg & kProtoMask ) != 0;
	s.emsg = s.rawEMsg & ~kProtoMask;

	std::string name = StripEMsgPrefix( hookName );
	if ( name.empty() || name == "UNKNOWN" || name == "Unknown" || name == "<unknown>" )
		name = store_ ? store_->EMsgName( s.emsg ) : std::string();
	s.emsgName = name;

	size_t bodyOffset = 4;

	if ( s.isProto )
	{
		if ( length < 8 )
			return s;

		const uint32_t headerLength = ReadU32( data + 4 );
		if ( headerLength > length - 8 )
			return s;

		const LiteHeader h = ParseLiteHeader( data + 8, headerLength );
		s.steamId = h.steamId;
		s.jobIdSource = h.jobSource;
		s.jobIdTarget = h.jobTarget;
		s.sessionId = h.sessionId;
		bodyOffset = 8 + headerLength;

		if ( IsServiceMethodEMsg( s.emsg ) )
		{
			s.inner = h.targetJobName;
		}
		else if ( s.emsg == k_EMsgClientServiceMethodLegacy || s.emsg == k_EMsgClientServiceMethodLegacyResponse )
		{
			std::vector<RawField> fields;
			if ( ParseRaw( data + bodyOffset, length - bodyOffset, fields ) )
			{
				for ( const RawField &f : fields )
				{
					if ( f.wire == 2 && f.number == 1 )
						s.inner.assign( reinterpret_cast<const char *>( f.bytes ), f.length );
				}
			}
		}
		else if ( s.emsg == k_EMsgClientToGC || s.emsg == k_EMsgClientFromGC )
		{
			const LiteGCClient gc = ParseLiteGCClient( data + bodyOffset, length - bodyOffset );
			if ( gc.hasMsgType )
			{
				const uint32_t gcMsg = gc.msgType & ~kProtoMask;
				std::string gcName;
				if ( store_ )
				{
					const auto names = store_->GCMessageNames( gcMsg, gc.appId );
					if ( !names.empty() )
						gcName = names.front();
				}
				if ( gcName.empty() )
					gcName = std::to_string( gcMsg );

				s.inner = gcName + " (app " + std::to_string( gc.appId ) + ")";
			}
		}
	}
	else if ( IsChannelEncryptEMsg( s.emsg ) )
	{
		if ( length >= 20 )
		{
			s.jobIdTarget = ReadU64( data + 4 );
			s.jobIdSource = ReadU64( data + 12 );
		}
	}
	else if ( length >= 36 )
	{
		s.jobIdTarget = ReadU64( data + 7 );
		s.jobIdSource = ReadU64( data + 15 );
		s.steamId = ReadU64( data + 24 );
		s.sessionId = static_cast<int32_t>( ReadU32( data + 32 ) );
	}

	s.valid = true;
	return s;
}

Node PacketDecoder::Decode( const uint8_t *data, size_t length, const std::string &hookName, const DecodeOptions &options ) const
{
	Builder builder( store_.get(), options, hookName );
	return builder.BuildPacket( data, length );
}

} // namespace nh2
