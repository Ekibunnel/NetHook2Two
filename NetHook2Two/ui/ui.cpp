#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "ui.h"

#include <d3d11.h>
#include <dxgi.h>
#include <shellapi.h>

#include <algorithm>
#include <cctype>
#include <cfloat>
#include <filesystem>
#include <cstdio>
#include <cstring>
#include <deque>
#include <set>
#include <string>
#include <vector>

#include "imgui.h"
#include "imgui_internal.h"
#include "backends/imgui_impl_dx11.h"
#include "backends/imgui_impl_win32.h"

#include "../core/decoder.h"
#include "../core/locator.h"
#include "../logger.h"
#include "nh2_shared.h"
#include "protobuf_updater.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler( HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam );

namespace nh2win
{

namespace
{

//
// Direct3D 11 / Win32 plumbing
//
HWND g_hwnd = nullptr;
ATOM g_windowClass = 0;
ID3D11Device *g_device = nullptr;
ID3D11DeviceContext *g_context = nullptr;
IDXGISwapChain *g_swapChain = nullptr;
ID3D11RenderTargetView *g_rtv = nullptr;
UINT g_resizeWidth = 0, g_resizeHeight = 0;
bool g_imguiReady = false;
bool g_win32Ready = false;
bool g_dx11Ready = false;
std::string g_iniPath;

ImFont *g_fontMono = nullptr;
float g_dpi = 1.0f;
float g_appliedScale = 1.0f;

const char kWindowClassName[] = "NetHook2Two_ImGui_Window";

void CreateRenderTarget()
{
	ID3D11Texture2D *backBuffer = nullptr;
	if ( SUCCEEDED( g_swapChain->GetBuffer( 0, IID_PPV_ARGS( &backBuffer ) ) ) )
	{
		g_device->CreateRenderTargetView( backBuffer, nullptr, &g_rtv );
		backBuffer->Release();
	}
}

void CleanupRenderTarget()
{
	if ( g_rtv )
	{
		g_rtv->Release();
		g_rtv = nullptr;
	}
}

bool CreateDevice( HWND hwnd )
{
	DXGI_SWAP_CHAIN_DESC sd = {};
	sd.BufferCount = 2;
	sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	sd.BufferDesc.RefreshRate.Numerator = 60;
	sd.BufferDesc.RefreshRate.Denominator = 1;
	sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
	sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	sd.OutputWindow = hwnd;
	sd.SampleDesc.Count = 1;
	sd.Windowed = TRUE;
	sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

	const D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
	D3D_FEATURE_LEVEL got;

	HRESULT hr = D3D11CreateDeviceAndSwapChain( nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, 2, D3D11_SDK_VERSION, &sd, &g_swapChain, &g_device, &got, &g_context );
	if ( hr == DXGI_ERROR_UNSUPPORTED )
		hr = D3D11CreateDeviceAndSwapChain( nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, levels, 2, D3D11_SDK_VERSION, &sd, &g_swapChain, &g_device, &got, &g_context );

	if ( FAILED( hr ) )
		return false;

	CreateRenderTarget();
	return true;
}

void CleanupDevice()
{
	CleanupRenderTarget();
	if ( g_swapChain ) { g_swapChain->Release(); g_swapChain = nullptr; }
	if ( g_context ) { g_context->Release(); g_context = nullptr; }
	if ( g_device ) { g_device->Release(); g_device = nullptr; }
}

void RenderLive(); // draws one frame right now (defined next to UiRun); used while the window is being resized

LRESULT CALLBACK WndProc( HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam )
{
	if ( ImGui_ImplWin32_WndProcHandler( hwnd, msg, wParam, lParam ) )
		return TRUE;

	switch ( msg )
	{
	case WM_SIZE:
		if ( wParam != SIZE_MINIMIZED )
		{
			g_resizeWidth = LOWORD( lParam );
			g_resizeHeight = HIWORD( lParam );
			// Windows runs a modal loop while the border is dragged, so the main loop doesn't get to run:
			// render from here so the window keeps updating during the resize.
			RenderLive();
		}
		return 0;

	case WM_ERASEBKGND:
		return 1; // everything is drawn by Direct3D

	case WM_SYSCOMMAND:
		if ( ( wParam & 0xfff0 ) == SC_KEYMENU ) // no ALT application menu
			return 0;
		break;

	case WM_CLOSE:
		// Closing the window unloads NetHook2Two again. The actual teardown happens on the UI thread.
		RequestShutdown();
		return 0;
	}

	return DefWindowProcA( hwnd, msg, wParam, lParam );
}

//
// The viewer
//
struct Row
{
	uint64_t id = 0;
	uint64_t fileTime = 0;
	bool outgoing = false;
	std::string hookName;
	std::vector<uint8_t> data;
	nh2::PacketSummary summary;
	std::string search; // lower case text the filter matches against
	std::string timeText;
};

std::string ToLower( std::string s )
{
	std::transform( s.begin(), s.end(), s.begin(), []( unsigned char c ) { return static_cast<char>( std::tolower( c ) ); } );
	return s;
}

std::string FormatTime( uint64_t fileTime )
{
	FILETIME ft;
	ft.dwLowDateTime = static_cast<DWORD>( fileTime & 0xFFFFFFFFu );
	ft.dwHighDateTime = static_cast<DWORD>( fileTime >> 32 );

	FILETIME local;
	SYSTEMTIME st;
	if ( !FileTimeToLocalFileTime( &ft, &local ) || !FileTimeToSystemTime( &local, &st ) )
		return "?";

	char buffer[ 32 ];
	snprintf( buffer, sizeof( buffer ), "%02u:%02u:%02u.%03u", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds );
	return buffer;
}

// View menu settings. Saved in the same ini file as the window layout (nethook2two_ui.ini) through a custom
// settings handler, see UiCreate().
struct ViewSettings
{
	bool showUnset = false;
	bool autoScroll = true;
	float scale = 1.0f; // text scale; the font atlas is rebuilt at this size so text stays sharp
};

ViewSettings g_view;

class Viewer
{
public:
	explicit Viewer( ProtobufUpdater &updater ) : updater_( updater ) {}

	void Frame();
	void PumpPackets(); // call every loop iteration, also while minimized

private:
	// data
	void AddPacket( CapturedPacket &&packet );
	void Summarize( Row &row );
	bool Matches( const Row &row ) const;
	void RebuildVisible();
	void Clear();
	int FindRowIndex( uint64_t id ) const;
	void CheckStore();

	// drawing
	void DrawMenuBar();
	void DrawToolbar();
	void DrawPacketTable( float height );
	void DrawDetails();
	void DrawParsedTab( const Row &row );
	void DrawHexTab( const Row &row );
	void DrawTextTab();
	void DrawLogTab();
	void DrawNode( const nh2::Node &node );
	void DrawStatusBar();
	void DrawProtobufPopup();
	void DrawBindingsWindow();
	void ReloadBindingRows();
	void ApplyBindings();

	void SelectRow( uint64_t id );
	void RefreshDetails( const Row &row );

	ProtobufUpdater &updater_;

	std::deque<Row> rows_;          // oldest first
	std::vector<int> visible_;      // indices into rows_
	uint64_t trimmedRows_ = 0;

	std::shared_ptr<const nh2::DescriptorStore> store_;
	std::shared_ptr<nh2::PacketDecoder> decoder_;
	uint64_t storeVersion_ = 0;

	// view state
	bool paused_ = false;
	bool showIn_ = true, showOut_ = true;
	// View menu state that is persisted: see g_view
	bool lastShowUnset_ = false, lastAutoScroll_ = true;
	float lastScale_ = 1.0f;
	bool openProtobufPopup_ = false;

	// "GC protobuf folders" window: binds extra\<folder> to app ids
	struct BindingRow
	{
		std::string name;
		char text[ 160 ] = "";
		std::string defaults;
		bool valid = true;
		nh2::GameFolderInfo info;
	};
	bool showBindings_ = false;
	std::vector<BindingRow> bindingRows_;
	uint64_t bindingsStoreVersion_ = ~0ull;
	bool bindingsDirty_ = false;
	std::string bindingsMessage_;
	bool bindingsMessageIsError_ = false;
	char filterText_[ 256 ] = "";
	std::string appliedFilter_;
	std::set<uint32_t> hiddenEMsgs_;
	float splitRatio_ = 0.45f;
	uint64_t selectedId_ = 0;
	bool scrollToSelected_ = false;
	bool newRowsThisFrame_ = false;
	size_t maxRows_ = 100000;

	// details of the selected packet
	uint64_t detailKey_ = 0;       // selected id the cached details belong to
	uint64_t detailStoreVersion_ = 0;
	bool detailShowUnset_ = false;
	nh2::Node detailTree_;
	std::string detailText_;
	std::vector<std::string> detailHexLines_;
	bool detailHexTruncated_ = false;

	// counters
	size_t totalIn_ = 0, totalOut_ = 0;

	// log
	std::vector<std::string> logLines_;
	uint64_t logCounter_ = 0;
	bool logStick_ = true;
};

void Viewer::CheckStore()
{
	const uint64_t version = updater_.Version();
	if ( version == storeVersion_ )
		return;

	storeVersion_ = version;
	store_ = updater_.Current();
	decoder_ = std::make_shared<nh2::PacketDecoder>( store_ );

	// Names that depend on the definitions (service methods, GC messages) may have changed.
	for ( Row &row : rows_ )
		Summarize( row );

	RebuildVisible();
}

void Viewer::Summarize( Row &row )
{
	nh2::PacketDecoder fallback( nullptr );
	const nh2::PacketDecoder &decoder = decoder_ ? *decoder_ : fallback;

	row.summary = decoder.Summarize( row.data.data(), row.data.size(), row.hookName );

	row.search = ToLower( row.summary.emsgName + " " + std::to_string( row.summary.emsg ) + " " + row.summary.inner + ( row.outgoing ? " out" : " in" ) );
}

void Viewer::AddPacket( CapturedPacket &&packet )
{
	Row row;
	row.id = packet.id;
	row.fileTime = packet.fileTime;
	row.outgoing = packet.outgoing;
	row.hookName = std::move( packet.hookName );
	row.data = std::move( packet.data );
	row.timeText = FormatTime( row.fileTime );
	Summarize( row );

	( row.outgoing ? totalOut_ : totalIn_ )++;

	rows_.push_back( std::move( row ) );
	newRowsThisFrame_ = true;

	if ( !paused_ && Matches( rows_.back() ) )
		visible_.push_back( static_cast<int>( rows_.size() - 1 ) );
}

void Viewer::PumpPackets()
{
	std::vector<CapturedPacket> incoming;
	g_packetQueue.Drain( incoming );

	for ( CapturedPacket &p : incoming )
		AddPacket( std::move( p ) );

	if ( rows_.size() > maxRows_ )
	{
		const size_t drop = rows_.size() - maxRows_ + maxRows_ / 10;
		rows_.erase( rows_.begin(), rows_.begin() + static_cast<std::ptrdiff_t>( drop ) );
		trimmedRows_ += drop;
		RebuildVisible();
	}
}

bool Viewer::Matches( const Row &row ) const
{
	if ( row.outgoing ? !showOut_ : !showIn_ )
		return false;

	if ( hiddenEMsgs_.count( row.summary.emsg ) )
		return false;

	if ( appliedFilter_.empty() )
		return true;

	// space separated terms, all must match; a leading '-' excludes
	size_t pos = 0;
	while ( pos < appliedFilter_.size() )
	{
		size_t end = appliedFilter_.find( ' ', pos );
		if ( end == std::string::npos )
			end = appliedFilter_.size();

		std::string term = appliedFilter_.substr( pos, end - pos );
		pos = end + 1;

		if ( term.empty() )
			continue;

		const bool exclude = term[ 0 ] == '-' && term.size() > 1;
		if ( exclude )
			term.erase( 0, 1 );

		const bool found = row.search.find( term ) != std::string::npos;
		if ( found == exclude )
			return false;
	}

	return true;
}

void Viewer::RebuildVisible()
{
	visible_.clear();
	for ( size_t i = 0; i < rows_.size(); i++ )
	{
		if ( Matches( rows_[ i ] ) )
			visible_.push_back( static_cast<int>( i ) );
	}
}

void Viewer::Clear()
{
	rows_.clear();
	visible_.clear();
	selectedId_ = 0;
	detailKey_ = 0;
	totalIn_ = totalOut_ = 0;
}

int Viewer::FindRowIndex( uint64_t id ) const
{
	// ids ascend with row order
	auto it = std::lower_bound( rows_.begin(), rows_.end(), id, []( const Row &r, uint64_t value ) { return r.id < value; } );
	if ( it == rows_.end() || it->id != id )
		return -1;
	return static_cast<int>( it - rows_.begin() );
}

void Viewer::SelectRow( uint64_t id )
{
	selectedId_ = id;
}

void Viewer::RefreshDetails( const Row &row )
{
	if ( detailKey_ == row.id && detailStoreVersion_ == storeVersion_ && detailShowUnset_ == g_view.showUnset )
		return;

	detailKey_ = row.id;
	detailStoreVersion_ = storeVersion_;
	detailShowUnset_ = g_view.showUnset;

	nh2::PacketDecoder fallback( nullptr );
	const nh2::PacketDecoder &decoder = decoder_ ? *decoder_ : fallback;

	nh2::DecodeOptions options;
	options.showUnsetFields = g_view.showUnset;

	detailTree_ = decoder.Decode( row.data.data(), row.data.size(), row.hookName, options );
	detailText_ = nh2::NodeToText( detailTree_ );

	const size_t hexLimit = 1u << 20;
	detailHexTruncated_ = row.data.size() > hexLimit;
	const std::string dump = nh2::HexDump( row.data.data(), std::min( row.data.size(), hexLimit ) );

	detailHexLines_.clear();
	size_t start = 0;
	while ( start < dump.size() )
	{
		size_t end = dump.find( '\n', start );
		if ( end == std::string::npos )
			end = dump.size();
		detailHexLines_.push_back( dump.substr( start, end - start ) );
		start = end + 1;
	}
}

//
// Drawing
//
void Viewer::DrawMenuBar()
{
	if ( !ImGui::BeginMenuBar() )
		return;

	if ( ImGui::BeginMenu( "File" ) )
	{
		bool dump = g_dumpToDisk;
		if ( ImGui::MenuItem( "Also write dump files to disk", nullptr, &dump ) )
		{
			g_dumpToDisk = dump;
			if ( !g_cfgPath.empty() )
				nh2::SetIniValue( g_cfgPath, "general", "DumpToDisk", dump ? "1" : "0" );
		}

		ImGui::Separator();

		if ( ImGui::MenuItem( "Open dump folder" ) && g_pLogger )
			ShellExecuteA( nullptr, "open", ( g_pLogger->LogDirExists() ? g_pLogger->GetLogDir() : g_pLogger->GetRootDir() ).c_str(), nullptr, nullptr, SW_SHOWNORMAL );

		const int idx = selectedId_ ? FindRowIndex( selectedId_ ) : -1;
		if ( ImGui::MenuItem( "Save selected packet as .bin", nullptr, false, idx >= 0 && g_pLogger ) )
		{
			const Row &row = rows_[ static_cast<size_t>( idx ) ];
			char name[ 64 ];
			snprintf( name, sizeof( name ), "selected_%llu.bin", static_cast<unsigned long long>( row.id ) );
			const std::string path = g_pLogger->EnsureLogDir() + name;
			if ( FILE *f = fopen( path.c_str(), "wb" ) )
			{
				fwrite( row.data.data(), 1, row.data.size(), f );
				fclose( f );
				g_logBuffer.Add( "Saved " + path );
			}
		}

		ImGui::Separator();
		if ( ImGui::MenuItem( "Eject NetHook2Two and close" ) )
			RequestShutdown();

		ImGui::EndMenu();
	}

	if ( ImGui::BeginMenu( "View" ) )
	{
		if ( ImGui::MenuItem( "Show unset fields", nullptr, &g_view.showUnset ) ) {}
		ImGui::MenuItem( "Auto-scroll", nullptr, &g_view.autoScroll );
		ImGui::SliderFloat( "Scale", &g_view.scale, 0.7f, 2.0f, "%.2f" ); // applied when the slider is released
		ImGui::EndMenu();
	}

	if ( ImGui::BeginMenu( "Protobufs" ) )
	{
		if ( ImGui::MenuItem( "Status..." ) )
			openProtobufPopup_ = true;

		if ( ImGui::MenuItem( "Game folders / app ids (GC)..." ) )
			showBindings_ = true;

		if ( ImGui::MenuItem( "Reload extra .proto files", nullptr, false, !updater_.IsRunning() ) )
			updater_.Start( false );

		if ( ImGui::MenuItem( "Rescan Steam binaries now", nullptr, false, !updater_.IsRunning() ) )
			updater_.Start( true );

		if ( ImGui::MenuItem( "Open protobuf folder" ) )
			ShellExecuteA( nullptr, "open", updater_.CacheDir().c_str(), nullptr, nullptr, SW_SHOWNORMAL );

		ImGui::EndMenu();
	}

	ImGui::EndMenuBar();
}

void Viewer::DrawToolbar()
{
	if ( ImGui::Button( paused_ ? "Resume" : "Pause" ) )
	{
		paused_ = !paused_;
		if ( !paused_ )
			RebuildVisible();
	}

	ImGui::SameLine();
	if ( ImGui::Button( "Clear" ) )
		Clear();

	ImGui::SameLine();
	if ( ImGui::Checkbox( "In", &showIn_ ) ) RebuildVisible();
	ImGui::SameLine();
	if ( ImGui::Checkbox( "Out", &showOut_ ) ) RebuildVisible();
	ImGui::SameLine();
	ImGui::Checkbox( "Auto-scroll", &g_view.autoScroll );

	ImGui::SameLine();
	ImGui::SetNextItemWidth( ImGui::GetContentRegionAvail().x * 0.45f );
	if ( ImGui::InputTextWithHint( "##filter", "Filter: name, id or method; -term excludes", filterText_, sizeof( filterText_ ) ) )
	{
		appliedFilter_ = ToLower( filterText_ );
		RebuildVisible();
	}

	if ( !hiddenEMsgs_.empty() )
	{
		ImGui::SameLine();
		const std::string label = "Hidden EMsgs: " + std::to_string( hiddenEMsgs_.size() ) + " (click to show all)";
		if ( ImGui::SmallButton( label.c_str() ) )
		{
			hiddenEMsgs_.clear();
			RebuildVisible();
		}
	}
}

void Viewer::DrawPacketTable( float height )
{
	const ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV |
		ImGuiTableFlags_Resizable | ImGuiTableFlags_Hideable | ImGuiTableFlags_SizingFixedFit;

	if ( !ImGui::BeginTable( "packets", 7, flags, ImVec2( 0, height ) ) )
		return;

	ImGui::TableSetupScrollFreeze( 0, 1 );
	ImGui::TableSetupColumn( "#", ImGuiTableColumnFlags_WidthFixed, 60.f );
	ImGui::TableSetupColumn( "Time", ImGuiTableColumnFlags_WidthFixed, 95.f );
	ImGui::TableSetupColumn( "Dir", ImGuiTableColumnFlags_WidthFixed, 40.f );
	ImGui::TableSetupColumn( "EMsg", ImGuiTableColumnFlags_WidthFixed, 55.f );
	ImGui::TableSetupColumn( "Name", ImGuiTableColumnFlags_WidthFixed, 280.f );
	ImGui::TableSetupColumn( "Details", ImGuiTableColumnFlags_WidthStretch );
	ImGui::TableSetupColumn( "Size", ImGuiTableColumnFlags_WidthFixed, 70.f );
	ImGui::TableHeadersRow();

	const bool atBottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 2.0f;

	// keyboard navigation
	if ( ImGui::IsWindowFocused( ImGuiFocusedFlags_RootAndChildWindows ) && !visible_.empty() && !ImGui::GetIO().WantTextInput )
	{
		int delta = 0;
		if ( ImGui::IsKeyPressed( ImGuiKey_DownArrow ) ) delta = 1;
		if ( ImGui::IsKeyPressed( ImGuiKey_UpArrow ) ) delta = -1;
		if ( ImGui::IsKeyPressed( ImGuiKey_PageDown ) ) delta = 20;
		if ( ImGui::IsKeyPressed( ImGuiKey_PageUp ) ) delta = -20;

		if ( delta != 0 )
		{
			int current = -1;
			for ( size_t i = 0; i < visible_.size(); i++ )
			{
				if ( rows_[ static_cast<size_t>( visible_[ i ] ) ].id == selectedId_ )
				{
					current = static_cast<int>( i );
					break;
				}
			}

			const int next = std::max( 0, std::min( static_cast<int>( visible_.size() ) - 1, current < 0 ? 0 : current + delta ) );
			SelectRow( rows_[ static_cast<size_t>( visible_[ static_cast<size_t>( next ) ] ) ].id );
			scrollToSelected_ = true;
		}
	}

	ImGuiListClipper clipper;
	clipper.Begin( static_cast<int>( visible_.size() ) );
	if ( scrollToSelected_ && selectedId_ )
	{
		for ( size_t i = 0; i < visible_.size(); i++ )
		{
			if ( rows_[ static_cast<size_t>( visible_[ i ] ) ].id == selectedId_ )
			{
				clipper.IncludeItemByIndex( static_cast<int>( i ) );
				break;
			}
		}
	}

	while ( clipper.Step() )
	{
		for ( int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++ )
		{
			const Row &row = rows_[ static_cast<size_t>( visible_[ static_cast<size_t>( i ) ] ) ];
			const bool selected = row.id == selectedId_;

			ImGui::TableNextRow();
			ImGui::PushID( static_cast<int>( row.id & 0x7FFFFFFF ) );

			ImGui::TableSetColumnIndex( 0 );
			char idText[ 24 ];
			snprintf( idText, sizeof( idText ), "%llu", static_cast<unsigned long long>( row.id ) );
			if ( ImGui::Selectable( idText, selected, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap ) )
				SelectRow( row.id );

			if ( selected && scrollToSelected_ )
			{
				ImGui::SetScrollHereY();
				scrollToSelected_ = false;
			}

			if ( ImGui::BeginPopupContextItem( "rowmenu" ) )
			{
				SelectRow( row.id );
				if ( ImGui::MenuItem( "Hide this EMsg" ) )
				{
					hiddenEMsgs_.insert( row.summary.emsg );
					RebuildVisible();
				}
				if ( ImGui::MenuItem( "Only show this EMsg" ) )
				{
					const std::string name = row.summary.emsgName.empty() ? std::to_string( row.summary.emsg ) : row.summary.emsgName;
					snprintf( filterText_, sizeof( filterText_ ), "%s", name.c_str() );
					appliedFilter_ = ToLower( filterText_ );
					RebuildVisible();
				}
				if ( ImGui::MenuItem( "Copy raw bytes (hex)" ) )
				{
					std::string hex;
					static const char digits[] = "0123456789ABCDEF";
					for ( uint8_t b : row.data ) { hex += digits[ b >> 4 ]; hex += digits[ b & 15 ]; }
					ImGui::SetClipboardText( hex.c_str() );
				}
				ImGui::EndPopup();
			}

			ImGui::TableSetColumnIndex( 1 );
			ImGui::TextUnformatted( row.timeText.c_str() );

			ImGui::TableSetColumnIndex( 2 );
			ImGui::TextColored( row.outgoing ? ImVec4( 0.45f, 0.70f, 1.0f, 1.0f ) : ImVec4( 0.45f, 0.90f, 0.55f, 1.0f ), row.outgoing ? "Out" : "In" );

			ImGui::TableSetColumnIndex( 3 );
			ImGui::Text( "%u", row.summary.emsg );

			ImGui::TableSetColumnIndex( 4 );
			if ( row.summary.emsgName.empty() )
				ImGui::TextDisabled( "<unknown>" );
			else
				ImGui::TextUnformatted( row.summary.emsgName.c_str() );

			ImGui::TableSetColumnIndex( 5 );
			ImGui::TextUnformatted( row.summary.inner.c_str() );

			ImGui::TableSetColumnIndex( 6 );
			ImGui::Text( "%zu", row.data.size() );

			ImGui::PopID();
		}
	}

	if ( g_view.autoScroll && atBottom && newRowsThisFrame_ && !paused_ )
		ImGui::SetScrollHereY( 1.0f );

	ImGui::EndTable();
}

void Viewer::DrawNode( const nh2::Node &node )
{
	ImGui::PushID( &node );

	const bool container = !node.children.empty();
	ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_SpanAvailWidth | ImGuiTreeNodeFlags_OpenOnArrow | ImGuiTreeNodeFlags_OpenOnDoubleClick;
	if ( !container )
		flags |= ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;

	if ( node.open && container )
		ImGui::SetNextItemOpen( true, ImGuiCond_Once );

	if ( node.unset )
		ImGui::PushStyleColor( ImGuiCol_Text, ImGui::GetStyleColorVec4( ImGuiCol_TextDisabled ) );
	else if ( node.kind == nh2::Node::Kind::Error )
		ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 1.0f, 0.45f, 0.4f, 1.0f ) );
	else if ( node.kind == nh2::Node::Kind::Container )
		ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0.95f, 0.80f, 0.45f, 1.0f ) );

	const bool open = ImGui::TreeNodeEx( "##n", flags, "%s", node.name.c_str() );
	const bool coloured = node.unset || node.kind == nh2::Node::Kind::Error || node.kind == nh2::Node::Kind::Container;
	if ( coloured )
		ImGui::PopStyleColor();

	if ( ImGui::BeginPopupContextItem( "nodemenu" ) )
	{
		if ( ImGui::MenuItem( "Copy name" ) ) ImGui::SetClipboardText( node.name.c_str() );
		if ( ImGui::MenuItem( "Copy value", nullptr, false, node.kind != nh2::Node::Kind::Container ) ) ImGui::SetClipboardText( node.copyText.c_str() );
		if ( ImGui::MenuItem( "Copy name and value" ) )
		{
			const std::string both = node.name + ": " + ( node.kind == nh2::Node::Kind::Container ? node.type : node.copyText );
			ImGui::SetClipboardText( both.c_str() );
		}
		if ( ImGui::MenuItem( "Copy type", nullptr, false, !node.type.empty() ) ) ImGui::SetClipboardText( node.type.c_str() );
		if ( ImGui::MenuItem( "Copy subtree as text", nullptr, false, container ) ) ImGui::SetClipboardText( nh2::NodeToText( node ).c_str() );
		ImGui::EndPopup();
	}

	if ( !node.type.empty() )
	{
		ImGui::SameLine();
		ImGui::TextDisabled( "(%s)", node.type.c_str() );
	}

	if ( node.kind != nh2::Node::Kind::Container && !node.value.empty() )
	{
		ImGui::SameLine();
		if ( node.kind == nh2::Node::Kind::Error )
			ImGui::TextColored( ImVec4( 1.0f, 0.45f, 0.4f, 1.0f ), "%s", node.value.c_str() );
		else if ( node.unset )
			ImGui::TextDisabled( "%s", node.value.c_str() );
		else
			ImGui::TextUnformatted( node.value.c_str() );
	}

	if ( !node.note.empty() )
	{
		ImGui::SameLine();
		ImGui::TextColored( ImVec4( 0.55f, 0.75f, 0.95f, 1.0f ), "// %s", node.note.c_str() );
	}

	if ( open && container )
	{
		for ( const nh2::Node &child : node.children )
			DrawNode( child );
		ImGui::TreePop();
	}

	ImGui::PopID();
}

void Viewer::DrawParsedTab( const Row &row )
{
	ImGui::BeginChild( "parsed", ImVec2( 0, 0 ), ImGuiChildFlags_None );
	DrawNode( detailTree_ );
	ImGui::EndChild();
}

void Viewer::DrawHexTab( const Row &row )
{
	if ( ImGui::Button( "Copy hex dump" ) )
	{
		std::string all;
		for ( const std::string &line : detailHexLines_ ) { all += line; all += '\n'; }
		ImGui::SetClipboardText( all.c_str() );
	}
	if ( detailHexTruncated_ )
	{
		ImGui::SameLine();
		ImGui::TextDisabled( "(showing the first 1 MiB of %zu bytes)", row.data.size() );
	}

	ImGui::BeginChild( "hex", ImVec2( 0, 0 ), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar );
	if ( g_fontMono ) ImGui::PushFont( g_fontMono );

	ImGuiListClipper clipper;
	clipper.Begin( static_cast<int>( detailHexLines_.size() ) );
	while ( clipper.Step() )
	{
		for ( int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++ )
			ImGui::TextUnformatted( detailHexLines_[ static_cast<size_t>( i ) ].c_str() );
	}

	if ( g_fontMono ) ImGui::PopFont();
	ImGui::EndChild();
}

void Viewer::DrawTextTab()
{
	if ( g_fontMono ) ImGui::PushFont( g_fontMono );
	// read-only, so imgui never writes to the buffer
	ImGui::InputTextMultiline( "##text", const_cast<char *>( detailText_.c_str() ), detailText_.size() + 1, ImVec2( -1, -1 ), ImGuiInputTextFlags_ReadOnly );
	if ( g_fontMono ) ImGui::PopFont();
}

void Viewer::DrawLogTab()
{
	logCounter_ = g_logBuffer.CopyNew( logCounter_, logLines_ );
	if ( logLines_.size() > 3000 )
		logLines_.erase( logLines_.begin(), logLines_.end() - 3000 );

	if ( ImGui::Button( "Clear log" ) ) logLines_.clear();
	ImGui::SameLine();
	if ( ImGui::Button( "Copy log" ) )
	{
		std::string all;
		for ( const std::string &line : logLines_ ) { all += line; all += '\n'; }
		ImGui::SetClipboardText( all.c_str() );
	}

	ImGui::BeginChild( "log", ImVec2( 0, 0 ), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar );
	if ( g_fontMono ) ImGui::PushFont( g_fontMono );

	ImGuiListClipper clipper;
	clipper.Begin( static_cast<int>( logLines_.size() ) );
	while ( clipper.Step() )
	{
		for ( int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++ )
			ImGui::TextUnformatted( logLines_[ static_cast<size_t>( i ) ].c_str() );
	}

	if ( g_fontMono ) ImGui::PopFont();
	if ( logStick_ && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 2.0f )
		ImGui::SetScrollHereY( 1.0f );
	ImGui::EndChild();
}

void Viewer::DrawDetails()
{
	// Keep the log counter moving even when the tab isn't visible so the first view isn't a flood.
	const int idx = selectedId_ ? FindRowIndex( selectedId_ ) : -1;

	if ( !ImGui::BeginTabBar( "details" ) )
		return;

	if ( ImGui::BeginTabItem( "Parsed" ) )
	{
		if ( idx >= 0 )
		{
			const Row &row = rows_[ static_cast<size_t>( idx ) ];
			RefreshDetails( row );
			DrawParsedTab( row );
		}
		else
			ImGui::TextDisabled( "Select a packet to see its parsed contents." );
		ImGui::EndTabItem();
	}

	if ( ImGui::BeginTabItem( "Hex" ) )
	{
		if ( idx >= 0 )
		{
			const Row &row = rows_[ static_cast<size_t>( idx ) ];
			RefreshDetails( row );
			DrawHexTab( row );
		}
		else
			ImGui::TextDisabled( "Select a packet." );
		ImGui::EndTabItem();
	}

	if ( ImGui::BeginTabItem( "Text" ) )
	{
		if ( idx >= 0 )
		{
			RefreshDetails( rows_[ static_cast<size_t>( idx ) ] );
			DrawTextTab();
		}
		else
			ImGui::TextDisabled( "Select a packet." );
		ImGui::EndTabItem();
	}

	if ( ImGui::BeginTabItem( "Log" ) )
	{
		DrawLogTab();
		ImGui::EndTabItem();
	}

	ImGui::EndTabBar();
}

void Viewer::DrawProtobufPopup()
{
	if ( openProtobufPopup_ )
	{
		ImGui::OpenPopup( "Protobuf definitions" );
		openProtobufPopup_ = false;
	}

	ImGui::SetNextWindowSize( ImVec2( 720, 0 ), ImGuiCond_Appearing );
	if ( !ImGui::BeginPopupModal( "Protobuf definitions", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
		return;

	if ( updater_.IsRunning() )
		ImGui::TextUnformatted( "Scanning Steam binaries..." );
	else if ( store_ )
		ImGui::Text( "%s", store_->Summary().c_str() );
	else
		ImGui::TextUnformatted( "No definitions loaded." );

	ImGui::TextDisabled( "Cache: %s", updater_.CacheDir().c_str() );
	ImGui::Separator();

	if ( store_ )
	{
		for ( const nh2::TargetStatus &t : store_->Targets() )
		{
			ImGui::BulletText( "%s", t.path.c_str() );
			ImGui::Indent();
			ImGui::TextDisabled( "%s, %zu files, %.2fs %s", t.state.c_str(), t.files, t.seconds, t.detail.c_str() );
			ImGui::Unindent();
		}
	}

	ImGui::Separator();
	ImGui::TextWrapped( "Definitions are read from the Steam client that NetHook2Two is running in, and are re-scanned automatically whenever that binary changes. "
		"Game coordinator protobufs: put .proto files into nethook\\protobufs\\extra\\<game>\\ (for example extra\\csgo\\cstrike15_gcmessages.proto) "
		"and bind the folder to an app id with Protobufs > Game folders / app ids. Descriptor sets (.pb/.desc) and executables to scan can still be put "
		"directly into 'extra' or listed in nethook\\protobuf_targets.txt." );

	if ( ImGui::Button( "Rescan now", ImVec2( 120, 0 ) ) && !updater_.IsRunning() )
		updater_.Start( true );
	ImGui::SameLine();
	if ( ImGui::Button( "Close", ImVec2( 120, 0 ) ) )
		ImGui::CloseCurrentPopup();

	ImGui::EndPopup();
}

void Viewer::ReloadBindingRows()
{
	bindingRows_.clear();
	bindingsDirty_ = false;

	if ( !store_ )
		return;

	for ( const nh2::GameFolderInfo &info : store_->GameFolders() )
	{
		if ( info.shared )
			continue;

		BindingRow row;
		row.name = info.name;
		row.info = info;
		row.defaults = nh2::FormatAppIds( nh2::DefaultAppIdsForFolder( info.name ) );

		const std::string current = nh2::FormatAppIds( store_->EffectiveAppIds( info.name ) );
		snprintf( row.text, sizeof( row.text ), "%s", current.c_str() );
		bindingRows_.push_back( std::move( row ) );
	}
}

void Viewer::ApplyBindings()
{
	nh2::AppBindings bindings;

	// Keep entries for folders that currently aren't on disk, so they aren't lost.
	if ( store_ )
		bindings = store_->ExplicitAppBindings();

	for ( const BindingRow &row : bindingRows_ )
	{
		std::vector<uint32_t> ids;
		nh2::ParseAppIds( row.text, ids );

		std::string key = row.name;
		for ( char &c : key )
			c = static_cast<char>( tolower( static_cast<unsigned char>( c ) ) );
		bindings[ key ] = ids;
	}

	std::string error;
	if ( !updater_.SaveBindings( bindings, error ) )
	{
		bindingsMessage_ = error;
		bindingsMessageIsError_ = true;
		return;
	}

	bindingsMessage_ = "Saved to " + updater_.BindingsPath();
	bindingsMessageIsError_ = false;
	bindingsDirty_ = false;

	// GC message names / bodies depend on the bindings: refresh the list and the open details.
	for ( Row &row : rows_ )
		Summarize( row );
	RebuildVisible();
	detailStoreVersion_ = ~0ull;
}

void Viewer::DrawBindingsWindow()
{
	if ( !showBindings_ )
		return;

	if ( bindingsStoreVersion_ != storeVersion_ )
	{
		bindingsStoreVersion_ = storeVersion_;
		ReloadBindingRows();
	}

	ImGui::SetNextWindowSize( ImVec2( 760, 360 ), ImGuiCond_FirstUseEver );
	if ( !ImGui::Begin( "Game folders / app ids (GC protobufs)", &showBindings_ ) )
	{
		ImGui::End();
		return;
	}

	ImGui::TextWrapped( "Every sub folder of nethook\\protobufs\\extra holds the .proto files of one game. Game coordinator messages carry the app id of "
		"their game, so bind each folder to its app id and NetHook2Two decodes a message with the matching folder only, even if several games use "
		"the same message ids or the same file names. A folder without app id is tried for every app." );
	ImGui::TextDisabled( "Folder: %s", updater_.ExtraDir().c_str() );
	ImGui::Separator();

	bool allValid = true;

	if ( updater_.IsRunning() )
	{
		ImGui::TextUnformatted( "Loading protobuf definitions..." );
	}
	else if ( bindingRows_.empty() )
	{
		ImGui::TextUnformatted( "No game folders found. Create folders such as extra\\csgo or extra\\tf2 and put .proto files in them." );
	}
	else if ( ImGui::BeginTable( "bindings", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_ScrollY, ImVec2( 0, -ImGui::GetFrameHeightWithSpacing() * 3 ) ) )
	{
		ImGui::TableSetupScrollFreeze( 0, 1 );
		ImGui::TableSetupColumn( "Folder", ImGuiTableColumnFlags_WidthStretch, 1.0f );
		ImGui::TableSetupColumn( "App ids (comma separated)", ImGuiTableColumnFlags_WidthStretch, 1.4f );
		ImGui::TableSetupColumn( "Default", ImGuiTableColumnFlags_WidthFixed, 110.0f );
		ImGui::TableSetupColumn( "Loaded", ImGuiTableColumnFlags_WidthStretch, 1.6f );
		ImGui::TableHeadersRow();

		for ( size_t i = 0; i < bindingRows_.size(); i++ )
		{
			BindingRow &row = bindingRows_[ i ];
			ImGui::PushID( static_cast<int>( i ) );
			ImGui::TableNextRow();

			ImGui::TableNextColumn();
			ImGui::AlignTextToFramePadding();
			ImGui::Text( "/%s/", row.name.c_str() );

			ImGui::TableNextColumn();
			std::vector<uint32_t> ids;
			row.valid = nh2::ParseAppIds( row.text, ids );
			allValid = allValid && row.valid;

			ImGui::SetNextItemWidth( -FLT_MIN );
			if ( !row.valid )
				ImGui::PushStyleColor( ImGuiCol_FrameBg, ImVec4( 0.55f, 0.15f, 0.15f, 1.0f ) );
			if ( ImGui::InputTextWithHint( "##ids", "any app", row.text, sizeof( row.text ) ) )
				bindingsDirty_ = true;
			if ( !row.valid )
				ImGui::PopStyleColor();

			ImGui::TableNextColumn();
			ImGui::AlignTextToFramePadding();
			if ( row.defaults.empty() )
				ImGui::TextDisabled( "-" );
			else
			{
				ImGui::TextDisabled( "%s", row.defaults.c_str() );
				if ( ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked( 0 ) )
				{
					snprintf( row.text, sizeof( row.text ), "%s", row.defaults.c_str() );
					bindingsDirty_ = true;
				}
			}

			ImGui::TableNextColumn();
			ImGui::AlignTextToFramePadding();
			ImGui::Text( "%zu files, %zu messages, %zu GC ids", row.info.files, row.info.messages, row.info.gcMessages );
			if ( row.info.failed != 0 )
			{
				ImGui::SameLine();
				ImGui::TextColored( ImVec4( 1.0f, 0.75f, 0.3f, 1.0f ), "(%zu skipped)", row.info.failed );
				if ( ImGui::IsItemHovered() )
					ImGui::SetTooltip( "Files that could not be used, usually because another file of the folder defines the same symbol.\nFirst problem: %s\nThe Log tab lists all of them.", row.info.firstError.c_str() );
			}

			ImGui::PopID();
		}

		ImGui::EndTable();
	}

	if ( !bindingsMessage_.empty() )
		ImGui::TextColored( bindingsMessageIsError_ ? ImVec4( 1.0f, 0.4f, 0.4f, 1.0f ) : ImVec4( 0.5f, 0.9f, 0.5f, 1.0f ), "%s", bindingsMessage_.c_str() );
	else if ( !allValid )
		ImGui::TextColored( ImVec4( 1.0f, 0.4f, 0.4f, 1.0f ), "App ids must be numbers separated by commas." );
	else
		ImGui::TextDisabled( "Double click a default value to use it." );

	ImGui::BeginDisabled( !allValid || bindingRows_.empty() );
	if ( ImGui::Button( bindingsDirty_ ? "Apply and save *" : "Apply and save", ImVec2( 150, 0 ) ) )
		ApplyBindings();
	ImGui::EndDisabled();

	ImGui::SameLine();
	if ( ImGui::Button( "Revert", ImVec2( 100, 0 ) ) )
	{
		ReloadBindingRows();
		bindingsMessage_.clear();
	}

	ImGui::SameLine();
	if ( ImGui::Button( "Reload .proto files", ImVec2( 150, 0 ) ) && !updater_.IsRunning() )
		updater_.Start( false );

	ImGui::SameLine();
	if ( ImGui::Button( "Open folder", ImVec2( 110, 0 ) ) )
	{
		std::error_code ec;
		std::filesystem::create_directories( updater_.ExtraDir(), ec );
		ShellExecuteA( nullptr, "open", updater_.ExtraDir().c_str(), nullptr, nullptr, SW_SHOWNORMAL );
	}

	ImGui::End();
}

void Viewer::DrawStatusBar()
{
	ImGui::Separator();
	ImGui::Text( "%zu packets (%zu in, %zu out)  |  showing %zu%s", rows_.size() + static_cast<size_t>( trimmedRows_ ), totalIn_, totalOut_, visible_.size(), paused_ ? "  |  PAUSED" : "" );
	ImGui::SameLine();

	if ( updater_.IsRunning() )
		ImGui::TextDisabled( "  |  protobufs: updating..." );
	else if ( store_ && store_->HasSteamDefinitions() )
		ImGui::TextDisabled( "  |  protobufs: %zu files, %zu messages", store_->FileCount(), store_->MessageCount() );
	else
		ImGui::TextColored( ImVec4( 1.0f, 0.7f, 0.3f, 1.0f ), "  |  protobufs: using built-in fallback only (see Log)" );
}

void Viewer::Frame()
{
	CheckStore();

	if ( lastShowUnset_ != g_view.showUnset || lastAutoScroll_ != g_view.autoScroll || lastScale_ != g_view.scale )
	{
		lastShowUnset_ = g_view.showUnset;
		lastAutoScroll_ = g_view.autoScroll;
		lastScale_ = g_view.scale;
		ImGui::MarkIniSettingsDirty();
	}

	const ImGuiViewport *viewport = ImGui::GetMainViewport();
	ImGui::SetNextWindowPos( viewport->WorkPos );
	ImGui::SetNextWindowSize( viewport->WorkSize );

	const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
		ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;

	if ( ImGui::Begin( "NetHook2Two##main", nullptr, flags ) )
	{
		DrawMenuBar();
		DrawToolbar();

		const float statusHeight = ImGui::GetTextLineHeightWithSpacing() + ImGui::GetStyle().ItemSpacing.y * 2;
		const float splitterHeight = 8.0f;
		const float avail = std::max( 100.0f, ImGui::GetContentRegionAvail().y - statusHeight - splitterHeight - ImGui::GetStyle().ItemSpacing.y * 2 );
		const float tableHeight = avail * splitRatio_;

		DrawPacketTable( tableHeight );

		ImGui::Button( "##splitter", ImVec2( -1, splitterHeight ) );
		if ( ImGui::IsItemActive() )
			splitRatio_ = std::max( 0.1f, std::min( 0.9f, splitRatio_ + ImGui::GetIO().MouseDelta.y / avail ) );
		if ( ImGui::IsItemHovered() || ImGui::IsItemActive() )
			ImGui::SetMouseCursor( ImGuiMouseCursor_ResizeNS );

		ImGui::BeginChild( "detailsarea", ImVec2( 0, avail - tableHeight ), ImGuiChildFlags_None );
		DrawDetails();
		ImGui::EndChild();

		DrawStatusBar();
		DrawProtobufPopup();
	}
	ImGui::End();

	DrawBindingsWindow();

	newRowsThisFrame_ = false;
}

void LoadFonts( float dpiScale )
{
	ImGuiIO &io = ImGui::GetIO();

	auto exists = []( const char *path ) { return GetFileAttributesA( path ) != INVALID_FILE_ATTRIBUTES; };

	const float uiSize = 16.0f * dpiScale;
	const float monoSize = 15.0f * dpiScale;

	ImFont *ui = nullptr;
	if ( exists( "C:\\Windows\\Fonts\\segoeui.ttf" ) )
		ui = io.Fonts->AddFontFromFileTTF( "C:\\Windows\\Fonts\\segoeui.ttf", uiSize );
	if ( ui == nullptr )
	{
		ImFontConfig cfg;
		cfg.SizePixels = uiSize;
		ui = io.Fonts->AddFontDefault( &cfg );
	}

	g_fontMono = nullptr;
	if ( exists( "C:\\Windows\\Fonts\\consola.ttf" ) )
		g_fontMono = io.Fonts->AddFontFromFileTTF( "C:\\Windows\\Fonts\\consola.ttf", monoSize );

	io.FontDefault = ui;
}

Viewer *g_viewer = nullptr;

} // namespace


bool UiCreate( const char *windowTitle, const char *iniFilePath, char *errorOut, size_t errorOutSize )
{
	auto fail = [ & ]( const char *message )
	{
		snprintf( errorOut, errorOutSize, "%s", message );
		UiDestroy();
		return false;
	};

	HINSTANCE instance = GetModuleHandleA( nullptr );

	WNDCLASSEXA wc = {};
	wc.cbSize = sizeof( wc );
	wc.style = CS_CLASSDC;
	wc.lpfnWndProc = WndProc;
	wc.hInstance = instance;
	wc.hCursor = LoadCursorA( nullptr, IDC_ARROW );
	wc.lpszClassName = kWindowClassName;
	g_windowClass = RegisterClassExA( &wc );
	if ( g_windowClass == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS )
		return fail( "RegisterClassEx failed" );

	g_hwnd = CreateWindowExA( 0, kWindowClassName, windowTitle, WS_OVERLAPPEDWINDOW, 100, 100, 1360, 860, nullptr, nullptr, instance, nullptr );
	if ( g_hwnd == nullptr )
		return fail( "CreateWindow failed" );

	if ( !CreateDevice( g_hwnd ) )
		return fail( "Unable to create a Direct3D 11 device" );

	ShowWindow( g_hwnd, SW_SHOWDEFAULT );
	UpdateWindow( g_hwnd );

	IMGUI_CHECKVERSION();
	ImGui::CreateContext();
	g_imguiReady = true;

	g_iniPath = iniFilePath ? iniFilePath : "";
	ImGuiIO &io = ImGui::GetIO();
	io.IniFilename = g_iniPath.empty() ? nullptr : g_iniPath.c_str();
	io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

	// Persist the View menu in the same ini file: [NetHook2Two][View]
	{
		ImGuiSettingsHandler handler;
		handler.TypeName = "NetHook2Two";
		handler.TypeHash = ImHashStr( "NetHook2Two" );
		handler.ReadOpenFn = []( ImGuiContext *, ImGuiSettingsHandler *, const char *name ) -> void *
		{
			return strcmp( name, "View" ) == 0 ? static_cast<void *>( &g_view ) : nullptr;
		};
		handler.ReadLineFn = []( ImGuiContext *, ImGuiSettingsHandler *, void *, const char *line )
		{
			int i = 0;
			float f = 1.0f;
			if ( sscanf( line, "ShowUnset=%d", &i ) == 1 )
				g_view.showUnset = i != 0;
			else if ( sscanf( line, "AutoScroll=%d", &i ) == 1 )
				g_view.autoScroll = i != 0;
			else if ( sscanf( line, "Scale=%f", &f ) == 1 )
				g_view.scale = std::max( 0.7f, std::min( 2.0f, f ) );
		};
		handler.WriteAllFn = []( ImGuiContext *, ImGuiSettingsHandler *h, ImGuiTextBuffer *buf )
		{
			buf->appendf( "[%s][View]\n", h->TypeName );
			buf->appendf( "ShowUnset=%d\n", g_view.showUnset ? 1 : 0 );
			buf->appendf( "AutoScroll=%d\n", g_view.autoScroll ? 1 : 0 );
			buf->appendf( "Scale=%.2f\n\n", g_view.scale );
		};
		ImGui::AddSettingsHandler( &handler );
	}

	ImGui::StyleColorsDark();
	ImGui::GetStyle().WindowRounding = 0.0f;
	ImGui::GetStyle().FrameRounding = 3.0f;

	const float dpi = ImGui_ImplWin32_GetDpiScaleForHwnd( g_hwnd );
	g_dpi = dpi > 0 ? dpi : 1.0f;
	LoadFonts( g_dpi * g_view.scale );
	g_appliedScale = g_view.scale;

	if ( !ImGui_ImplWin32_Init( g_hwnd ) )
		return fail( "ImGui_ImplWin32_Init failed" );
	g_win32Ready = true;

	if ( !ImGui_ImplDX11_Init( g_device, g_context ) )
		return fail( "ImGui_ImplDX11_Init failed" );
	g_dx11Ready = true;

	return true;
}

namespace
{
Viewer *g_liveViewer = nullptr;
bool g_inRender = false;

void RenderFrame( Viewer &viewer )
{
	if ( g_inRender || !g_swapChain || IsIconic( g_hwnd ) )
		return;
	g_inRender = true;

	if ( g_resizeWidth != 0 && g_resizeHeight != 0 )
	{
		CleanupRenderTarget();
		g_swapChain->ResizeBuffers( 0, g_resizeWidth, g_resizeHeight, DXGI_FORMAT_UNKNOWN, 0 );
		g_resizeWidth = g_resizeHeight = 0;
		CreateRenderTarget();
	}

	// Text scale changed (slider released / settings loaded): rebuild the glyph atlas at the new pixel size instead of
	// stretching the old bitmap, so text stays sharp.
	if ( g_view.scale != g_appliedScale && !ImGui::IsMouseDown( ImGuiMouseButton_Left ) )
	{
		ImGui_ImplDX11_InvalidateDeviceObjects();
		ImGui::GetIO().Fonts->Clear();
		LoadFonts( g_dpi * g_view.scale );
		g_appliedScale = g_view.scale;
	}

	ImGui_ImplDX11_NewFrame();
	ImGui_ImplWin32_NewFrame();
	ImGui::NewFrame();

	viewer.Frame();

	ImGui::Render();

	const float color[ 4 ] = { 0.08f, 0.08f, 0.09f, 1.0f };
	g_context->OMSetRenderTargets( 1, &g_rtv, nullptr );
	g_context->ClearRenderTargetView( g_rtv, color );
	ImGui_ImplDX11_RenderDrawData( ImGui::GetDrawData() );

	const HRESULT hr = g_swapChain->Present( 1, 0 );
	if ( hr == DXGI_STATUS_OCCLUDED )
		Sleep( 20 );

	g_inRender = false;
}

void RenderLive()
{
	if ( g_liveViewer && g_imguiReady )
		RenderFrame( *g_liveViewer );
}
} // namespace

void UiRun( ProtobufUpdater &updater )
{
	Viewer viewer( updater );
	g_viewer = &viewer;
	g_liveViewer = &viewer;

	while ( !g_quitRequested )
	{
		MSG msg;
		while ( PeekMessageA( &msg, nullptr, 0U, 0U, PM_REMOVE ) )
		{
			TranslateMessage( &msg );
			DispatchMessageA( &msg );
		}

		if ( g_quitRequested )
			break;

		viewer.PumpPackets();

		if ( IsIconic( g_hwnd ) )
		{
			Sleep( 50 );
			continue;
		}

		RenderFrame( viewer );
	}

	g_liveViewer = nullptr;
	g_viewer = nullptr;
}

void UiDestroy()
{
	if ( g_dx11Ready ) { ImGui_ImplDX11_Shutdown(); g_dx11Ready = false; }
	if ( g_win32Ready ) { ImGui_ImplWin32_Shutdown(); g_win32Ready = false; }
	if ( g_imguiReady ) { ImGui::DestroyContext(); g_imguiReady = false; }

	CleanupDevice();

	if ( g_hwnd )
	{
		DestroyWindow( g_hwnd );
		g_hwnd = nullptr;
	}

	UnregisterClassA( kWindowClassName, GetModuleHandleA( nullptr ) );
	g_windowClass = 0;
}

} // namespace nh2win
