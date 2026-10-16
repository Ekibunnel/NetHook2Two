#include "multi.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/message.h>
#include <google/protobuf/wire_format_lite.h>

namespace nh2
{

namespace
{

bool ParseWithDescriptor( const DescriptorStore &store, const uint8_t *data, size_t length, MultiMessage &out )
{
	using namespace google::protobuf;

	const Descriptor *type = store.FindMessage( "CMsgMulti" );
	if ( type == nullptr )
		return false;
	const FieldDescriptor *sizeField = type->FindFieldByName( "size_unzipped" );
	const FieldDescriptor *bodyField = type->FindFieldByName( "message_body" );
	if ( sizeField == nullptr || bodyField == nullptr ||
		sizeField->cpp_type() != FieldDescriptor::CPPTYPE_UINT32 || bodyField->cpp_type() != FieldDescriptor::CPPTYPE_STRING ||
		sizeField->is_repeated() || bodyField->is_repeated() )
		return false; // an unexpected shape: let the wire reader handle it

	std::unique_ptr<Message> message = store.NewMessage( type );
	if ( !message || !message->ParseFromArray( data, static_cast<int>( length ) ) )
		return false;

	const Reflection *reflection = message->GetReflection();
	out.sizeUnzipped = reflection->HasField( *message, sizeField ) ? reflection->GetUInt32( *message, sizeField ) : 0;
	out.body = reflection->HasField( *message, bodyField ) ? reflection->GetString( *message, bodyField ) : std::string();
	return true;
}

bool ParseFromWire( const uint8_t *data, size_t length, MultiMessage &out )
{
	using google::protobuf::io::CodedInputStream;

	CodedInputStream in( data, static_cast<int>( length ) );
	in.SetTotalBytesLimit( 0x7FFFFFFF );
	MultiMessage result;

	for ( ;; )
	{
		const uint32_t tag = in.ReadTag();
		if ( tag == 0 )
			break;

		const uint32_t field = tag >> 3;
		const uint32_t wireType = tag & 7;

		if ( field == 1 && wireType == 0 )
		{
			uint32_t value = 0;
			if ( !in.ReadVarint32( &value ) )
				return false;
			result.sizeUnzipped = value;
		}
		else if ( field == 2 && wireType == 2 )
		{
			uint32_t size = 0;
			if ( !in.ReadVarint32( &size ) || !in.ReadString( &result.body, static_cast<int>( size ) ) )
				return false;
		}
		else if ( !google::protobuf::internal::WireFormatLite::SkipField( &in, tag ) )
			return false;
	}

	out = std::move( result );
	return true;
}

} // namespace

bool ParseMulti( const DescriptorStore *store, const uint8_t *data, size_t length, MultiMessage &out )
{
	if ( length > 0x7FFFFFFF )
		return false;
	if ( store != nullptr && ParseWithDescriptor( *store, data, length, out ) )
		return true;
	return ParseFromWire( data, length, out );
}

} // namespace nh2
