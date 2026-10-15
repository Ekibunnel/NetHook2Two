
#define WIN32_LEAN_AND_MEAN
#include <windows.h>


#include "net.h"

#include "logger.h"
#include "csimplescan.h"
#include "steamclient.h"

#include <cstddef>
#include <cstring>

#ifndef X64BITS
// 32-bit builds still treat the argument as a plain CNetPacket.
static_assert(offsetof(CNetPacket, m_pubData) == 12, "Wrong offset of CNetPacket::m_pubData on 32-bit");
static_assert(offsetof(CNetPacket, m_cubData) == 16, "Wrong offset of CNetPacket::m_cubData on 32-bit");
#endif



#ifdef X64BITS
// Current 64-bit steamclient passes a ref-counted raw buffer object to
// CCMInterface::RecvPkt (which then wraps it in CProtoBufNetPacket /
// CStructNetPacket / CClientStructNetPacket). The buffer object is { ..., uint8 *data @+8, uint32 size @+0x10 } which holds the
// complete serialized packet (emsg + header + body):
//   CProtoBufNetPacket / CClientStructNetPacket : buffer object at +0x18
//   CStructNetPacket                            : buffer object at +0x10
// The concrete type is identified through its MSVC RTTI name, and every
// pointer is validated before use, so a layout change results in a logged
// failure instead of a crash.
namespace
{

bool ReadableRange(const void *p, size_t cb)
{
	if (!p || cb == 0)
		return false;

	MEMORY_BASIC_INFORMATION mbi;
	const uint8 *cur = (const uint8 *)p;
	const uint8 *end = cur + cb;

	while (cur < end)
	{
		if (!VirtualQuery(cur, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT)
			return false;
		if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
			return false;
		const uint8 *regionEnd = (const uint8 *)mbi.BaseAddress + mbi.RegionSize;
		if (regionEnd <= cur)
			return false;
		cur = regionEnd;
	}
	return true;
}

// Returns the RTTI class name (e.g. ".?AVCProtoBufNetPacket@@") or nullptr.
const char *RttiName(const void *obj)
{
	if (!ReadableRange(obj, sizeof(void *)))
		return nullptr;

	const void *const *vtbl = *(const void *const *const *)obj;
	if (!ReadableRange(vtbl - 1, sizeof(void *)))
		return nullptr;

	const uint8 *col = (const uint8 *)vtbl[-1];
	if (!ReadableRange(col, 24))
		return nullptr;

	const uint32 sig = *(const uint32 *)col;
	const int32 typeDescRva = *(const int32 *)(col + 12);
	const int32 selfRva = *(const int32 *)(col + 20);
	if (sig != 1)
		return nullptr;

	const uint8 *imageBase = col - selfRva;
	const char *name = (const char *)(imageBase + typeDescRva + 16);
	if (!ReadableRange(name, 8))
		return nullptr;
	if (name[0] != '.' || name[1] != '?' || name[2] != 'A')
		return nullptr;
	return name;
}

// Does this look like a Steam packet (emsg, and for protobuf messages a sane header length)?
bool LooksLikeSteamPacket(const uint8 *data, uint32 cb)
{
	uint32 rawEMsg;
	memcpy(&rawEMsg, data, sizeof(rawEMsg));

	const uint32 emsg = rawEMsg & 0x7FFFFFFFu;
	if (emsg == 0 || emsg > 0x10000u)
		return false;

	if ((rawEMsg & 0x80000000u) != 0)
	{
		if (cb < 8)
			return false;
		uint32 headerLength;
		memcpy(&headerLength, data + 4, sizeof(headerLength));
		return headerLength <= cb - 8 && headerLength <= 0x4000u;
	}

	return true;
}

// The raw buffer object is { vtable?, ..., uint8 *data, uint32 size } but the position of data/size moves from
// one Steam build to the next (+8/+0x10 in one, +0x10/+0x18 in the next). Instead of hard-coding it, look at the
// slots that can hold a data pointer and accept the first one that leads to something that looks like a packet.
// The slot that worked is remembered.
bool ReadBufferObject(const uint8 *buf, const uint8 **ppData, uint32 *pcbData)
{
	static const size_t kSlots[] = { 0x10, 0x08, 0x18, 0x20, 0x28, 0x30, 0x38 };
	static volatile LONG s_cachedSlot = -1;

	if (!ReadableRange(buf, 0x48))
		return false;

	auto tryRead = [&](size_t slot) -> bool
	{
		const uint8 *data = *(const uint8 *const *)(buf + slot);
		const uint32 cb = *(const uint32 *)(buf + slot + 8);

		// smallest packet is an emsg, largest is bounded by Steam's message limit
		if (cb < 4 || cb > 0x1000000u)
			return false;
		if (!ReadableRange(data, cb) || !LooksLikeSteamPacket(data, cb))
			return false;

		*ppData = data;
		*pcbData = cb;
		return true;
	};

	const LONG cached = s_cachedSlot;
	if (cached >= 0 && tryRead((size_t)cached))
		return true;

	for (size_t slot : kSlots)
	{
		if (tryRead(slot))
		{
			if (s_cachedSlot != (LONG)slot)
			{
				s_cachedSlot = (LONG)slot;
				g_pLogger->LogConsole("CCMInterface::RecvPkt: packet buffer found at +0x%X\n", (unsigned)slot);
			}
			return true;
		}
	}

	return false;
}

bool ExtractPacketBytes(const void *pPacket, const uint8 **ppData, uint32 *pcbData)
{
	// Verified against steamclient64.dll: RecvPkt's argument is the raw buffer
	// object itself (RecvPkt passes it straight to the packet factory that
	// creates the polymorphic packet).
	if (ReadBufferObject((const uint8 *)pPacket, ppData, pcbData))
		return true;

	// Fallback: argument is already a polymorphic packet object that wraps a buffer.
	if (!ReadableRange(pPacket, 0x20))
		return false;

	const char *name = RttiName(pPacket);
	const uint8 *obj = (const uint8 *)pPacket;

	if (name)
	{
		if (strstr(name, "ClientStructNetPacket") || strstr(name, "ProtoBufNetPacket"))
			return ReadBufferObject(*(const uint8 *const *)(obj + 0x18), ppData, pcbData);
		if (strstr(name, "StructNetPacket"))
			return ReadBufferObject(*(const uint8 *const *)(obj + 0x10), ppData, pcbData);
	}
	return false;
}

} // namespace
#endif

namespace NetHook
{


BBuildAndAsyncSendFrameFn BBuildAndAsyncSendFrame_Orig = nullptr;
RecvPktFn RecvPkt_Orig = nullptr;

CNet::CNet() noexcept
	: m_RecvPktDetour(nullptr),
	  m_BuildDetour(nullptr)
{
	CSimpleScan steamClientScan(STEAMCLIENT_DLL);

	BBuildAndAsyncSendFrameFn pBuildFunc = nullptr;
	nh2::LocateRequest buildRequest;
	buildRequest.name = "BBuildAndAsyncSendFrame";
	buildRequest.arch = NH_ARCH;
	buildRequest.candidates = {
#ifdef X64BITS
		{ "\x48\x8B\xC4\x55\x48\x8D\x68\x00\x48\x81\xEC\x00\x00\x00\x00\x48\x89\x70\x00\x49\x8B\xF0\x48\x89\x78\x00\x4C\x89\x60", "xxxxxxx?xxx????xxx?xxxxxx?xxx" },
#else
		{ "\x55\x8B\xEC\x83\xEC\xCC\xA1\xCC\xCC\xCC\xCC\x53\x8B\xD9\x89\x5D\xCC\x83\x38\xCC\x75\xCC\x33\xC0\xEB\xCC\x8D\x45\xCC\x50\x6A\xCC\x68\xCC\xCC\xCC\xCC\xFF\x15\xCC\xCC\xCC\xCC\x83\xC4\xCC\x83\x7B\xCC\x02", "xxxxx?x????xxxxx?xx?x?xxx?xx?xx?x????xx????xx?xx?x" },
#endif
	};
	const bool bFoundBuildFunc = steamClientScan.Locate( buildRequest, (void **)&pBuildFunc );

	BBuildAndAsyncSendFrame_Orig = pBuildFunc;

	g_pLogger->LogConsole("CWebSocketConnection::BBuildAndAsyncSendFrame = 0x%p\n", BBuildAndAsyncSendFrame_Orig);

	RecvPktFn pRecvPktFunc = nullptr;
	nh2::LocateRequest recvRequest;
	recvRequest.name = "RecvPkt";
	recvRequest.arch = NH_ARCH;
#ifdef X64BITS
	// Just the start of the prologue: the compiler reorders the register saves behind it from build to build.
	recvRequest.candidates = {
		{ "\x48\x8B\xC4\x55\x48\x8D\xA8\xCC\xCC\xCC\xCC\x48\x81\xEC\xCC\xCC\xCC\xCC\x48\x89\x58\x08\x48\x8B\xDA", "xxxxxxx????xxx????xxxxxxx" },
	};
	// Matches must pass a structural check, and when no signature works the function is found through the
	// "CCMInterface::RecvPkt" string it references and the PE exception table.
	recvRequest.validate = nh2::LooksLikeRecvPkt;
	recvRequest.fallback = nh2::FindRecvPktByStringReference;
#else
	recvRequest.candidates = {
		{ "\x55\x8B\xEC\x81\xEC\xCC\xCC\xCC\xCC\xA1\xCC\xCC\xCC\xCC\x56\x8B\xF1\x57", "xxxxx????x????xxxx" },
	};
#endif
	const bool bFoundRecvPktFunc = steamClientScan.Locate( recvRequest, (void **)&pRecvPktFunc );

	RecvPkt_Orig = pRecvPktFunc;

	g_pLogger->LogConsole("CCMInterface::RecvPkt = 0x%p\n", RecvPkt_Orig);


	if (bFoundBuildFunc)
	{
		BBuildAndAsyncSendFrameFn thisBuildFunc = (BBuildAndAsyncSendFrameFn)CNet::BBuildAndAsyncSendFrame;

		m_BuildDetour = new CSimpleDetour((void **)&BBuildAndAsyncSendFrame_Orig, (void *)thisBuildFunc);
		m_BuildDetour->Attach();

		g_pLogger->LogConsole("Detoured CWebSocketConnection::BBuildAndAsyncSendFrame!\n");
	}
	else
	{
		g_pLogger->LogConsole("Unable to hook CWebSocketConnection::BBuildAndAsyncSendFrame: func scan failed.\n");
	}

	if (bFoundRecvPktFunc)
	{
		RecvPktFn thisRecvPktFunc = (RecvPktFn)CNet::RecvPkt;

		m_RecvPktDetour = new CSimpleDetour((void **)&RecvPkt_Orig, (void *)thisRecvPktFunc);
		m_RecvPktDetour->Attach();

		g_pLogger->LogConsole("Detoured CCMInterface::RecvPkt!\n");
	}
	else
	{
		g_pLogger->LogConsole("Unable to hook CCMInterface::RecvPkt: func scan failed.\n");
	}

}

CNet::~CNet()
{
	if (m_RecvPktDetour)
	{
		m_RecvPktDetour->Detach();
		delete m_RecvPktDetour;
	}

	if (m_BuildDetour)
	{
		m_BuildDetour->Detach();
		delete m_BuildDetour;
	}
}


bool CNet::BBuildAndAsyncSendFrame(
	void *webSocketConnection,
#ifndef X64BITS
	void *,
#endif
	EWebSocketOpCode eWebSocketOpCode, 
	const uint8 *pubData, 
	uint32 cubData)
{
	if (eWebSocketOpCode == EWebSocketOpCode::k_eWebSocketOpCode_Binary)
	{
		g_pLogger->LogNetMessage(ENetDirection::k_eNetOutgoing, pubData, cubData);
	}
	else
	{
		g_pLogger->LogConsole("Sending websocket frame with opcode %d (%s), ignoring\n",
			eWebSocketOpCode, EWebSocketOpCodeToName(eWebSocketOpCode)
		);
	}

	return (*BBuildAndAsyncSendFrame_Orig)(webSocketConnection, eWebSocketOpCode, pubData, cubData);
}

void CNet::RecvPkt(
	void *cmConnection,
#ifndef X64BITS
	void *,
#endif
	CNetPacket *pPacket)
{
#ifdef X64BITS
	static bool s_bWarned = false;
	const uint8 *pubData = nullptr;
	uint32 cubData = 0;

	if (ExtractPacketBytes(pPacket, &pubData, &cubData))
	{
		g_pLogger->LogNetMessage(ENetDirection::k_eNetIncoming, pubData, cubData);
	}
	else if (!s_bWarned)
	{
		s_bWarned = true;
		const char *name = RttiName(pPacket);
		g_pLogger->LogConsole("CCMInterface::RecvPkt: unrecognized packet object (%s), incoming packets will not be shown\n",
			name ? name : "no RTTI");
	}
#else
	g_pLogger->LogNetMessage(ENetDirection::k_eNetIncoming, pPacket->m_pubData, pPacket->m_cubData);
#endif

	(*RecvPkt_Orig)(cmConnection, pPacket);
}


}
