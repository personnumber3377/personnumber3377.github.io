
# Fuzzing the CSGO packet handler

This is my writeup for fuzzing the counter strike packet handler. This is inspired by this: https://phoenhex.re/2018-08-26/csgo-fuzzing-bsp  but instead of fuzzing BSP map files we are now fuzzing the network packet handler.

Now, the original blog post was done with the QEMU fuzzer. This is quite slow and also we do not really have access to the source code. Instead of trying to patch the binary such that we jump to the packet handler function, we also have this: https://github.com/SwagSoftware/Kisak-Strike . It is the leaked source code which can be compiled to the csgo binary.

We can add a longjmp call to the place where we want to jump to the packet handler function and in addition to this we can now use the __AFL_LOOP macro to use persistent mode in the fuzzing.

I actually already did something similar to this with the BSP file fuzzing, but now we just need to do it with the packet handler.


## Quick code overview

The main socket handling function in the counter strike source code is this function:


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

this code calls the NET_GetPacket function which gets a packet from the socket:

```
packet = NET_GetPacket ( sock, scratch.GetBuffer() )
```


The NET_GetPacket function is this:

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

the definition of the inpacket  object is here:

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

the definition of ProcessPacket is this:

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





and then finally ProcessMessages which calls _ProcessMessages internally:

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

one thing to note about this code is that wiresize isn't really used in the _ProcessMessages function so we really do not need to modify it accordingly and I think that we can safely ignore this field in the packet object.


## Plan of attack

So maybe the easiest way to accomplish this is to just do something similar with the bsp file thing, except that this time we should probably use the longjmp thing to jump instead of making a script which patches the compiled binary like I did previously.

This is what I did previously:


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

and then I just compiled this and ran it with the game shared libraries and it worked decently.

Now, instead of doing that I think that I should modify the original source to use longjmp instead. The thing is that I know absolute jack shit about this so this will probably take a long time until I get this right.

The original main.cpp in the dedicated_main thing is this:


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

According to this https://www.tutorialspoint.com/c_standard_library/c_function_longjmp.htm we should use the longjmp thing like so:


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



Now, one issue which I am facing is that the ProcessPacket is a function which is associated with a class. Now the thing is that classes are a bit funky, because we need to call the method of the object so we really can not just jump to the function itself.

Maybe this will work? :


First we add this to net_ws.cpp :
```
#include "../jumpbuf.h"
#include <setjmp.h>
```
and then later this:

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

actually I think that we need to do something like this:

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


and:

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

To use all of this stuff we need to include the header files:


```
#include "/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/public/engine/inetsupport.h"
#include "/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/net_chan.h"
```

Lets try to compile this and see what happens!

And we get a compiler error. Very surprising /s .

```


In file included from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/net_chan.h:23,
                 from /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated_main/main.cpp:26:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/common/netmessages.h:49:10: fatal error: netmessages.pb.h: No such file or directory
   49 | #include "netmessages.pb.h"
      |          ^~~~~~~~~~~~~~~~~~
compilation terminated.



```


After literally just removing that include from that thing we now get another error:

```
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated_main/main.cpp: In function ‘int main(int, char**)’:
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated_main/main.cpp:319:20: error: invalid conversion from ‘int’ to ‘INetChannel*’ [-fpermissive]
  319 |   fuzzing_function(return_value_thing);
      |                    ^~~~~~~~~~~~~~~~~~
      |                    |
      |                    int
/home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicat

```

This error was expected because the return type of the setjmp thing when returning with longjmp is an integer and we are trying to cast it to a INetChannel pointer (aka CNetChan pointer) .

Sure, this under normal circumstances would be dumb but now that our application does some unorthodox stuff, we actually need to be able to do this.

While higher level languages are in my opinion better than lower level languages, this is one of the few things lower level stuff is better at: Being able to do close to the metal stuff far easier. Yes, sure the higher level  langauges  protect you from yourself by preventing you from doing dumb shit, but it is at the expense of the understanding of the lower layers. Also the abstraction of course making higher level constructs easier, but the one in a blue moon occurence when you are forced to do "dumb shit" because there is 100% no other way to do it, then you need to come up with complete ugliness like this:

```
		thing = (INetChannel*)((int*)return_value_thing);
		fuzzing_function(thing);

```


And in situations like these, the developer grows uneasy and is more prone to making for example integer casting mistakes which would become obvious when working with assembly language.

Now the program is still compiling but my guess is that we are going to get yelled at by the linker about missing functions ... lets see.

Except lets not see because the compilation seems to take forever. See ya in a few hours.

Ok so after hours of compiling we actually didn't even get any linking errors. Quite surprising. I think that is because the external functions which we are calling are object methods, not plain functions but idk.

Lets see if it actually runs on the first try.

```
System (VMaterialSystem080) failed during stage CONNECTION
```

Uh oh. That does not sound good. Looking through the code we see that the code runs a lot of so called "factories" which add all the required components to the game such as the materialsystem and the filesystem thing and the shader stuff.

after a bit of debugging, I narrowed the problem down to this:


```
	g_pLauncherMgr = (ILauncherMgr *)factory( "SDLMgrInterface001", NULL );
	if ( !g_pLauncherMgr ) {
		Warning("g_pLauncherMgr == NULL\n");
		return false;
	}

```


g_pLauncherMgr is NULL for some reason.


We try to call FindSystem with "SDLMgrInterface001" as pSystemName



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

We never even initialize the sdlmgr interface in the first place so something is going wrong.

Lets just try recompiling with the -DUSE_SDL=ON flag .

Aaaannnddd that actually worked??? Huh.

Anyway, now we get an ASAN error when we try to run the server. I actually remember this:


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

Here is the code:

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


So just add -basedir to the command line parameters and we should be fine???

And it worked! Things are going surprisingly well.

After that we get another asan error:


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

So just do `export ASAN_OPTIONS=alloc_dealloc_mismatch=0` ?

Ok so now the server is running. Now we need to connect to it and see if the fuzzing code works.

After trying to connect to the server we get a segfault (very surprising. /s) .

Lets investigate the crash in a debugger.


Aaanndd the crash seems to happen in the longjmp thing in net_ws.cpp . So the jump back to the main function is not working properly. I think that we should first make a minimal example and then try to scale things up to the csgo binary.


Lets try this as the main binary:

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


and then jump.h :

```

#include <setjmp.h>

jmp_buf env_buffer;


```

to compile this just do:

```
gcc main.c -ldl -o main
```

then we need to program the "library" :


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

and this code now reproduces the issue which we had previously. That is quite bad since I do not know how to do this properly. Now a way in which we can go about this is to use the deferred forkserver method. The deferred forkserver allows us to have the __AFL_LOOP inside a shared library. We need to put the __AFL_HAVE_MANUAL_CONTROL thing or whatever with it to use it.

Instead of doing some longjmp bullshit lets just add this to net_ws.cpp :

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
and then add this line:

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


After fixing a couple of typos, we now get another crash:

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

This is because something goes wrong in the Seek thing.











