// Display tree produced by the packet decoder and rendered by the UI.
// Plain data, no protobuf or Windows types.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace nh2
{

struct Node
{
	enum class Kind
	{
		Container, // has children (a message, a repeated field...)
		Value,     // a single value
		Bytes,     // binary blob, `data` holds all of it
		Error,     // something that couldn't be decoded
	};

	Kind kind = Kind::Value;

	std::string name;     // field name or label
	std::string type;     // protobuf type, e.g. "uint32", "CMsgProtoBufHeader"
	std::string value;    // text shown for leaf values (possibly shortened)
	std::string note;     // extra interpretation, e.g. a date for a timestamp or a Steam3 id
	std::string copyText; // complete, unshortened value for "copy"

	bool unset = false;   // field wasn't present in the message (shown greyed out)
	bool open = false;    // expand by default

	std::vector<uint8_t> data; // Kind::Bytes only
	std::vector<Node> children;
};

// Renders the tree as indented text (used for the text tab, copy and save).
std::string NodeToText( const Node &node );

} // namespace nh2
