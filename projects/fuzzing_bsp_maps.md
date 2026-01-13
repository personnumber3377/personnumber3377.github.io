
# Fuzzing BSP map files in CSGO.

These are just my notes when fuzzing the CSGO BSP map files.


There is a very interesting issue where the AFL expects the child thread to return a certain signal through a pipe, but because the way csgo is coded, it tries to wait for the thread waiting for the signal so you get a hang:



This is the parent fuzzing process inside the binary:

{% raw %}
```

(gdb) where
#0  0x00007f1c4ba89c7f in __GI___wait4 (pid=19166, stat_loc=0x7ffe0193b6cc, options=2, usage=0x0)
    at ../sysdeps/unix/sysv/linux/wait4.c:27
#1  0x00007f1c4c202510 in __interceptor_waitpid (pid=<optimized out>, status=0x7ffe0193b6cc, options=<optimized out>)
    at ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:2382
#2  0x000055a13b8afc08 in __afl_start_forkserver () at instrumentation/afl-compiler-rt.o.c:1229
#3  __afl_manual_init () at instrumentation/afl-compiler-rt.o.c:1330
#4  0x00007f1c38ccf385 in CGameServer::fuzz_maps (this=this@entry=0x7f1c3cb34ac0 <sv>, 
    szModelName=szModelName@entry=0x7ffe0193b8d0 "maps/fuzz.bsp")
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sv_main.cpp:2937
#5  0x00007f1c38cd698e in CGameServer::SpawnServer (this=this@entry=0x7f1c3cb34ac0 <sv>, 
    mapname=mapname@entry=0x7f1c3cba0420 <g_HostState+32> "fuzz", 
    mapGroupName=mapGroupName@entry=0x7f1c3cba0520 <g_HostState+288> "", startspot=startspot@entry=0x0)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sv_main.cpp:3278
#6  0x00007f1c3955f17e in Host_NewGame (mapName=mapName@entry=0x7f1c3cba0420 <g_HostState+32> "fuzz", 
    mapGroupName=mapGroupName@entry=0x7f1c3cba0520 <g_HostState+288> "", loadGame=loadGame@entry=false, 
    bBackgroundLevel=<optimized out>, bSplitScreenConnect=<optimized out>, pszOldMap=pszOldMap@entry=0x0, 
    pszLandmark=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/host.cpp:6270
#7  0x00007f1c395bf330 in CHostState::State_NewGame (this=this@entry=0x7f1c3cba0400 <g_HostState>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/host_state.cpp:436
#8  0x00007f1c395c46a7 in CHostState::FrameUpdate (this=<optimized out>, time=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/host_state.cpp:788
#9  0x00007f1c39a8d4f2 in CEngine::Frame (this=0x7f1c3cbb3760 <g_Engine>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_engine.cpp:572
#10 0x00007f1c39a68ae8 in CEngineAPI::MainLoop (this=0x7f1c3cbb31c0 <s_EngineAPI>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_dll2.cpp:1161
#11 0x00007f1c39a696ef in CModAppSystemGroup::Main (this=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_dll2.cpp:2416
--Type <RET> for more, q to quit, c to continue without paging--
#12 0x00007f1c3b088625 in CAppSystemGroup::Run (this=this@entry=0x7ffe0193c790)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#13 0x00007f1c39a78ebe in CEngineAPI::RunListenServer (this=0x7f1c3cbb31c0 <s_EngineAPI>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_dll2.cpp:1437
#14 0x00007f1c4788c875 in ?? ()
#15 0x00007ffe0193c900 in ?? ()
#16 0x00007ffe0193ca10 in ?? ()
#17 0x00007f1c47a4eab0 in ?? ()
#18 0x00007f1c47a76000 in ?? ()
#19 0x00007f1c47a7bf5a in ?? ()
#20 0xffffffffffffff90 in ?? ()
#21 0x00007ffe0193c940 in ?? ()
#22 0x00007f1c4788c875 in ?? ()
#23 0x00007f1c47a76000 in ?? ()
#24 0xffffffffffffff90 in ?? ()
#25 0x0000000000000000 in ?? ()


```
{% endraw %}

This is the child process:

19166
{% raw %}
```

(gdb) where
#0  0x00007f1c4ba8423f in __GI___clock_nanosleep (clock_id=clock_id@entry=0, flags=flags@entry=0, 
    req=req@entry=0x7ffe01939c60, rem=rem@entry=0x0) at ../sysdeps/unix/sysv/linux/clock_nanosleep.c:78
#1  0x00007f1c4ba89ec7 in __GI___nanosleep (requested_time=requested_time@entry=0x7ffe01939c60, 
    remaining=remaining@entry=0x0) at nanosleep.c:27
#2  0x00007f1c4babc85f in usleep (useconds=useconds@entry=0) at ../sysdeps/posix/usleep.c:32
#3  0x00007f1c48c9023f in ThreadSleep (nMilliseconds=nMilliseconds@entry=0)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/tier0/threadtools.cpp:503
#4  0x00007f1c4692efb2 in CThreadPool::SuspendExecution (this=0x629000000200)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/vstdlib/jobthread.cpp:555
#5  0x00007f1c469441b2 in CThreadPool::ExecuteToPriority (this=<optimized out>, iToPriority=<optimized out>, 
    pfnFilter=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/vstdlib/jobthread.cpp:851
#6  0x00007f1c44efe300 in CBaseFileSystem::AsyncFinishAll (this=<optimized out>, iToPriority=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/filesystem/basefilesystemasync.cpp:127
#7  0x00007f1c44e93a5a in CBaseFileSystem::AddSearchPathInternal (this=<optimized out>, 
    pPath=0x7ffe0193b3e0 "maps/fuzz.bsp", pathID=0x7f1c3c25f8e0 "GAME", addType=<optimized out>, 
    bAddPackFiles=<optimized out>, iForceInsertIndex=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/filesystem/basefilesystem.cpp:2675
#8  0x00007f1c44e96541 in CBaseFileSystem::AddSearchPath (this=0x7f1c452df300 <g_FileSystem_Stdio>, 
    pPath=<optimized out>, pathID=<optimized out>, addType=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/filesystem/basefilesystem.cpp:2961
#9  0x00007f1c3891883e in CModelLoader::LoadModel (this=<optimized out>, mod=0x7f1c35f08c34, 
    pReferencetype=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/modelloader.cpp:4340
#10 0x00007f1c3891068d in CModelLoader::GetModelForName (this=0x7f1c3c9f2f60 <g_ModelLoader>, name=<optimized out>, 
    referencetype=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/modelloader.cpp:4167
#11 0x00007f1c38ccf54a in CGameServer::fuzz_maps (this=this@entry=0x7f1c3cb34ac0 <sv>, 
    szModelName=szModelName@entry=0x7ffe0193b8d0 "maps/fuzz.bsp")
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sv_main.cpp:2966
--Type <RET> for more, q to quit, c to continue without paging--
#12 0x00007f1c38cd698e in CGameServer::SpawnServer (this=this@entry=0x7f1c3cb34ac0 <sv>, 
    mapname=mapname@entry=0x7f1c3cba0420 <g_HostState+32> "fuzz", 
    mapGroupName=mapGroupName@entry=0x7f1c3cba0520 <g_HostState+288> "", startspot=startspot@entry=0x0)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sv_main.cpp:3278
#13 0x00007f1c3955f17e in Host_NewGame (mapName=mapName@entry=0x7f1c3cba0420 <g_HostState+32> "fuzz", 
    mapGroupName=mapGroupName@entry=0x7f1c3cba0520 <g_HostState+288> "", loadGame=loadGame@entry=false, 
    bBackgroundLevel=<optimized out>, bSplitScreenConnect=<optimized out>, pszOldMap=pszOldMap@entry=0x0, 
    pszLandmark=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/host.cpp:6270
#14 0x00007f1c395bf330 in CHostState::State_NewGame (this=this@entry=0x7f1c3cba0400 <g_HostState>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/host_state.cpp:436
#15 0x00007f1c395c46a7 in CHostState::FrameUpdate (this=<optimized out>, time=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/host_state.cpp:788
#16 0x00007f1c39a8d4f2 in CEngine::Frame (this=0x7f1c3cbb3760 <g_Engine>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_engine.cpp:572
#17 0x00007f1c39a68ae8 in CEngineAPI::MainLoop (this=0x7f1c3cbb31c0 <s_EngineAPI>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_dll2.cpp:1161
#18 0x00007f1c39a696ef in CModAppSystemGroup::Main (this=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_dll2.cpp:2416
#19 0x00007f1c3b088625 in CAppSystemGroup::Run (this=this@entry=0x7ffe0193c790)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#20 0x00007f1c39a78ebe in CEngineAPI::RunListenServer (this=0x7f1c3cbb31c0 <s_EngineAPI>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_dll2.cpp:1437
#21 0x00007f1c4788c875 in ?? ()
#22 0x00007ffe0193c900 in ?? ()
#23 0x00007ffe0193ca10 in ?? ()
#24 0x00007f1c47a4eab0 in ?? ()
#25 0x00007f1c47a76000 in ?? ()




```
{% endraw %}

See, the program expects that the upper thread is the main thread which tries to load the stuff, but instead it is a child process because of the way the forkserver does stuff, so instead of execution continuing like normal, we get a hang.




The hang occurs on this line in modelloader.cpp:

{% raw %}
```
			g_pFileSystem->AddSearchPath( szNameOnDisk, "GAME", PATH_ADD_TO_HEAD );
```
{% endraw %}


and:

{% raw %}
```

CThreadMutex g_AsyncFinishMutex;
void CBaseFileSystem::AsyncFinishAll( int iToPriority )
{
	// MYCHANGE Causes a hang.
	//return;
	//DevMsg("poopoothingrgerer\n");
	if ( m_pThreadPool)
	{
		DevMsg("poopoothingrgerer2\n");
		AUTO_LOCK( g_AsyncFinishMutex );
		DevMsg("poopoothingrgerer3\n");
		m_pThreadPool->ExecuteToPriority( ConvertPriority( iToPriority ) );
	}
}



```
{% endraw %}

and:


{% raw %}
```

#define THREADED_EXECUTETOPRIORITY 0 //  Not ready for general consumption [8/4/2010 tom]

int CThreadPool::ExecuteToPriority( JobPriority_t iToPriority, JobFilter_t pfnFilter )
{
	ConMsg("Called ExecuteToPriority.\n");

	if ( !THREADED_EXECUTETOPRIORITY || pfnFilter )
	{
		SuspendExecution();
		ConMsg("Suspended execution\n");
		CJob *pJob;
		int i;
		int nExecuted = 0;
		int nJobsTotal = GetJobCount();
		CUtlVector<CJob *> jobsToPutBack;

		for ( int iCurPriority = JP_NUM_PRIORITIES - 1; iCurPriority >= iToPriority; --iCurPriority )
		{
			for ( i = 0; i < m_Threads.Count(); i++ )
			{
				CJobQueue &queue = m_Threads[i]->AccessDirectQueue();
				while ( queue.Count( (JobPriority_t)iCurPriority ) )
				{
					queue.Pop( &pJob );
					if ( pfnFilter && !(*pfnFilter)( pJob ) )
					{
						if ( pJob->CanExecute() )
						{
							jobsToPutBack.EnsureCapacity( nJobsTotal );
							jobsToPutBack.AddToTail( pJob );
						}
						else
						{
							m_nJobs--;
							pJob->Release(); // an already serviced job in queue, may as well ditch it (as in, main thread probably force executed)
						}
						continue;
					}
					ServiceJobAndRelease( pJob );
					m_nJobs--;
					nExecuted++;
				}

			}

			ConMsg("After first for loop thing.\n");

			while ( m_SharedQueue.Count( (JobPriority_t)iCurPriority ) )
			{
				m_SharedQueue.Pop( &pJob );
				if ( pfnFilter && !(*pfnFilter)( pJob ) )
				{
					if ( pJob->CanExecute() )
					{
						jobsToPutBack.EnsureCapacity( nJobsTotal );
						jobsToPutBack.AddToTail( pJob );
					}
					else
					{
						m_nJobs--;
						pJob->Release(); // see above
					}
					continue;
				}

				ServiceJobAndRelease( pJob );
				m_nJobs--;
				nExecuted++;
			}
		}

		for ( i = 0; i < jobsToPutBack.Count(); i++ )
		{
			InsertJobInQueue( jobsToPutBack[i] );
			jobsToPutBack[i]->Release();
		}
		ConMsg("Resuming execution\n");
		ResumeExecution();
		ConMsg("Returning\n");
		return nExecuted;
	}
	else
	{
		JobPriority_t prevPriority = CJobQueue::GetMinPriority();

		CJobQueue::SetMinPriority( iToPriority );

		CUtlVectorFixedGrowable<CThreadEvent*, 64> handles;

		for ( int i = 0; i < m_Threads.Count(); i++ )
		{
			handles.AddToTail( &m_Threads[i]->GetIdleEvent() );
		}

		CJob *pJob = NULL;
		do
		{
			YieldWait( (CThreadEvent **)handles.Base(), handles.Count(), true, TT_INFINITE );
			if ( m_SharedQueue.Pop( &pJob ) )
			{
				ServiceJobAndRelease( pJob );
				m_nJobs--;
			}
		} while ( pJob );

		CJobQueue::SetMinPriority( prevPriority );

		return 1;
	}
}

//---------------

// ...


int CThreadPool::SuspendExecution()
{
	AUTO_LOCK( m_SuspendMutex );

	// If not already suspended
	if ( m_nSuspend == 0 )
	{
		int i;
		for ( i = 0; i < m_Threads.Count(); i++ )
		{
			m_Threads[i]->CallWorker( TPM_SUSPEND, 0 );
		}

		for ( i = 0; i < m_Threads.Count(); i++ )
		{
			m_Threads[i]->WaitForReply();
		}

		// Because worker must signal before suspending, we could reach
		// here with the thread not actually suspended
		for ( i = 0; i < m_Threads.Count(); i++ )
		{
			while ( !m_Threads[i]->IsSuspended() )
			{
				ThreadSleep();
			}   	
		}
	}

	return m_nSuspend++;
}



```
{% endraw %}

The THREADED_EXECUTETOPRIORITY seems interesting, because in the code which I referenced pfnFilter does not get defined so it is null so if we set THREADED_EXECUTETOPRIORITY to one it should work and it should not wait for other stuff maybe?


another idea is to look at the definition of this:


{% raw %}
```

class CJobThread : public CWorkerThread
{
public:
	CJobThread( CThreadPool *pOwner, int iThread ) : 
		m_SharedQueue( pOwner->m_SharedQueue ),
		m_pOwner( pOwner ),
		m_iThread( iThread )
	{
	}

	CThreadEvent &GetIdleEvent()
	{
		return m_IdleEvent;
	}

	CJobQueue &AccessDirectQueue()
	{ 
		return m_DirectQueue;
	}

private:
	unsigned Wait()
	{
		unsigned waitResult;
#ifdef WIN32
		enum Event_t
		{
			CALL_FROM_MASTER,
			SHARED_QUEUE,
			DIRECT_QUEUE,
			
			NUM_EVENTS
		};

		CThreadEvent *waitHandles[NUM_EVENTS];
		
		waitHandles[CALL_FROM_MASTER]	= &GetCallHandle();
		waitHandles[SHARED_QUEUE]		= &m_SharedQueue.GetEventHandle();
		waitHandles[DIRECT_QUEUE] 		= &m_DirectQueue.GetEventHandle();
		
#ifdef _DEBUG
		while ( ( waitResult = CThreadEvent::WaitForMultiple( ARRAYSIZE(waitHandles), waitHandles , FALSE, 10 ) ) == TW_TIMEOUT )
		{
			waitResult = waitResult; // break here
		}
#else
		waitResult = CThreadEvent::WaitForMultiple( ARRAYSIZE(waitHandles), waitHandles , FALSE, TT_INFINITE );
#endif
#else // !win32
		bool bSet = false;
		int nWaitTime = 100;
		
		while ( !bSet )
		{
			// jobs are typically enqueued to the shared job queue so wait on it
			bSet = m_SharedQueue.GetEventHandle().Wait( nWaitTime );
			if ( !bSet )
				bSet = m_DirectQueue.GetEventHandle().Wait( 0 );
			if ( !bSet )
				bSet = GetCallHandle().Wait( 0 );
		}
		
		if ( !bSet )
			waitResult = WAIT_TIMEOUT;
		else
			waitResult = WAIT_OBJECT_0;		
#endif
		return waitResult;
	}

	int Run()
	{
		// Wait for either a call from the master thread, or an item in the queue...
		unsigned waitResult;
		bool	 bExit = false;

		m_pOwner->m_nIdleThreads++;
		m_IdleEvent.Set();
		while ( !bExit && ( waitResult = Wait() ) != TW_FAILED )
		{
			if ( PeekCall() )
			{
				switch ( GetCallParam() )
				{
				case TPM_EXIT:
					Reply( true );
					bExit = TRUE;
					break;

				case TPM_SUSPEND:
					Reply( true );
					Suspend();
					break;

				default:
					AssertMsg( 0, "Unknown call to thread" );
					Reply( false );
					break;
				}
			}
			else
			{
				CJob *pJob;
				bool bTookJob = false;
				do
				{
					if ( !m_DirectQueue.Pop( &pJob) )
					{
						if ( !m_SharedQueue.Pop( &pJob ) )
						{
							// Nothing to process, return to wait state
							break;
						}
					}
					if ( !bTookJob )
					{
						m_IdleEvent.Reset();
						m_pOwner->m_nIdleThreads--;
						bTookJob = true;
					}
					ServiceJobAndRelease( pJob, m_iThread );
					m_pOwner->m_nJobs--;
				} while ( !PeekCall() );

				if ( bTookJob )
				{
					m_pOwner->m_nIdleThreads++;
					m_IdleEvent.Set();
				}
			}
		}
		m_pOwner->m_nIdleThreads--;
		m_IdleEvent.Reset();
		return 0;
	}

	CJobQueue			m_DirectQueue;
	CJobQueue &			m_SharedQueue;
	CThreadPool *		m_pOwner;
	CThreadManualEvent	m_IdleEvent;
	int					m_iThread;
};

```
{% endraw %}

There is the 

{% raw %}
```
	int					m_iThread;
```
{% endraw %}

line which seems to indicate that we can get the thread number






{% raw %}
```

(gdb) where
#0  0x00007f9bdf87e0b1 in __GI___pthread_mutex_lock (mutex=0x7f9be05da990 <_rtld_global+2352>)
    at ../nptl/pthread_mutex_lock.c:115
#1  0x00007f9bdf492291 in __GI___dl_iterate_phdr (callback=0x7f9bdf5375f0, data=0x7ffebec7c510)
    at dl-iteratephdr.c:40
#2  0x00007f9bdf5386c1 in _Unwind_Find_FDE () from /lib/x86_64-linux-gnu/libgcc_s.so.1
#3  0x00007f9bdf534868 in ?? () from /lib/x86_64-linux-gnu/libgcc_s.so.1
#4  0x00007f9bdf53677b in _Unwind_Backtrace () from /lib/x86_64-linux-gnu/libgcc_s.so.1
#5  0x00007f9bdfc7d668 in __sanitizer::BufferedStackTrace::SlowUnwindStack (this=0x7ffebec7c8f0, pc=140307450901520, 
    max_depth=<optimized out>) at ../../../../src/libsanitizer/sanitizer_common/sanitizer_unwind_linux_libcdep.cc:125
#6  0x00007f9bdfc534a2 in __asan::GetStackTrace (fast=false, context=0x0, bp=140732099187008, pc=140307450901520, 
    max_depth=30, stack=0x7ffebec7c8f0) at ../../../../src/libsanitizer/asan/asan_stack.h:45
#7  __interceptor_free (ptr=0x6020004982d0) at ../../../../src/libsanitizer/asan/asan_malloc_linux.cc:122
#8  0x00007f9bc55cec43 in FcConfigSubstituteWithPat () from /lib/x86_64-linux-gnu/libfontconfig.so.1
#9  0x00007f9bc5cb3d4c in FontMatch (type=<optimized out>, type=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/vgui2/vgui_surfacelib/linuxfont.cpp:210
#10 0x00007f9bc5cba967 in CLinuxFont::Create (this=this@entry=0x610000334340, 
    windowsFontName=windowsFontName@entry=0x60200005e910 "Tahoma", tall=tall@entry=36, weight=weight@entry=900, 
    blur=blur@entry=0, scanlines=scanlines@entry=0, flags=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/vgui2/vgui_surfacelib/linuxfont.cpp:275
#11 0x00007f9bc5c6e865 in CFontManager::CreateOrFindWin32Font (this=0x7f9bc61d12a0 <s_FontManager>, 
    windowsFontName=<optimized out>, tall=<optimized out>, weight=<optimized out>, blur=<optimized out>, 
    scanlines=<optimized out>, flags=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/vgui2/vgui_surfacelib/fontmanager.cpp:382
#12 0x00007f9bc5c6f3b5 in CFontManager::SetFontGlyphSet (this=0x7f9bc61d12a0 <s_FontManager>, font=<optimized out>, 
    windowsFontName=0x60200005e910 "Tahoma", tall=<optimized out>, weight=<optimized out>, blur=<optimized out>, 
    scanlines=<optimized out>, flags=<optimized out>, nRangeMin=<optimized out>, nRangeMax=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/vgui2/vgui_surfacelib/fontmanager.cpp:234
--Type <RET> for more, q to quit, c to continue without paging--
#13 0x00007f9bc528937a in CScheme::ReloadFontGlyphs (this=<optimized out>, inScreenTall=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/public/tier1/utlmemory.h:608
#14 0x00007f9bc5295cf6 in CScheme::LoadFonts (this=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/vgui2/src/Scheme.cpp:1159
#15 0x00007f9bc529726a in CScheme::LoadFromFile (this=0x6110002bce00, sizingPanel=<optimized out>, 
    pFilename=<optimized out>, inTag=<optimized out>, inKeys=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/vgui2/src/Scheme.cpp:962
#16 0x00007f9bc5298455 in CSchemeManager::LoadSchemeFromFileEx (this=<optimized out>, sizingPanel=<optimized out>, 
    pFilename=<optimized out>, tag=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/vgui2/src/Scheme.cpp:472
#17 0x00007f9bcdd27657 in CEngineVGui::Init (this=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/public/vgui_controls/Controls.h:58
#18 0x00007f9bccede862 in Host_Init (bDedicated=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/host.cpp:5671
#19 0x00007f9bcd3e066c in Sys_InitGame (appSystemFactory=<optimized out>, pBaseDir=pBaseDir@entry=0x7f9bdb35fdc0 "", 
    pwnd=<optimized out>, bIsDedicated=bIsDedicated@entry=0)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_dll.cpp:1150
#20 0x00007f9bcd410997 in CEngine::Load (this=<optimized out>, dedicated=<optimized out>, rootdir=0x7f9bdb35fdc0 "")
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_engine.cpp:245
#21 0x00007f9bcd3f360b in CModAppSystemGroup::Main (this=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_dll2.cpp:2411
#22 0x00007f9bcea12625 in CAppSystemGroup::Run (this=this@entry=0x7ffebec7e420)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#23 0x00007f9bcd402ebe in CEngineAPI::RunListenServer (this=0x7f9bd053d1c0 <s_EngineAPI>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_dll2.cpp:1437
#24 0x00007f9bdb18c875 in ?? ()
#25 0x00007ffebec7e590 in ?? ()
--Type <RET> for more, q to quit, c to continue without paging--c
#26 0x00007ffebec7e6a0 in ?? ()

```
{% endraw %}


Now after enabling the THREADED_EXECUTETOPRIORITY to one we get this segv:


{% raw %}
```

(gdb) where
#0  __memset_sse2_unaligned_erms () at ../sysdeps/x86_64/multiarch/memset-vec-unaligned-erms.S:200
#1  0x00007f9df7a47e4f in __interceptor_memset (dst=0x0, v=0, size=131072)
    at ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:762
#2  0x00007f9df7a4825d in __interceptor_memset (dst=dst@entry=0x0, v=v@entry=0, size=size@entry=131072)
    at ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:762
#3  0x00007f9ddc8d2366 in memset (__len=131072, __ch=0, __dest=0x0)
    at /usr/include/x86_64-linux-gnu/bits/string_fortified.h:71
#4  CMeshMgr::FillEmptyColorBuffer (this=<optimized out>, pEmptyColorBuffer=0x607006a41610, nCount=32768)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/materialsystem/shaderapidx9/meshdx8.cpp:5513
#5  0x00007f9ddc8d3c28 in CMeshMgr::CreateEmptyColorBuffer (this=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/materialsystem/shaderapidx9/meshdx8.cpp:5528
#6  0x00007f9ddc8db4e2 in CMeshMgr::Init (this=0x7f9ddd049280 <g_MeshMgr>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/materialsystem/shaderapidx9/meshdx8.cpp:5244
#7  0x00007f9ddca6be0a in CShaderDeviceDx8::ReacquireResourcesInternal (this=<optimized out>, 
    bResetState=<optimized out>, bForceReacquire=<optimized out>, pszForceReason=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/materialsystem/shaderapidx9/shaderdevicedx8.cpp:3444
#8  0x00007f9de03490cc in CMaterialSystem::EndRenderTargetAllocation (this=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/materialsystem/cmaterialsystem.cpp:5151
#9  0x00007f9de40a401a in InitWellKnownRenderTargets ()
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/matsys_interface.cpp:982
#10 0x00007f9de40c70e0 in EnableHDR (bEnable=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/modelloader.cpp:1174
#11 0x00007f9de40c8111 in Map_CheckForHDR (pModel=pModel@entry=0x7f9de172cc34, 
    pMapPathName=pMapPathName@entry=0x7f9de172cc3c "maps/fuzz.bsp")
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/modelloader.cpp:1265
#12 0x00007f9de413531e in CModelLoader::Map_LoadModelGuts (this=<optimized out>, mod=<optimized out>)
    at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/modelloader.cpp:5197
--Type <RET> for more, q to quit, c to continue without paging--c
#13 0x00007f9de41391e9 in CModelLoader::Map_LoadModel (this=this@entry=0x7f9de8216fe0 <g_ModelLoader>, mod=mod@entry=0x7f9de172cc34) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/modelloader.cpp:5178
#14 0x00007f9de413be06 in CModelLoader::LoadModel (this=<optimized out>, mod=0x7f9de172cc34, pReferencetype=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/modelloader.cpp:4394
#15 0x00007f9de413468d in CModelLoader::GetModelForName (this=0x7f9de8216fe0 <g_ModelLoader>, name=<optimized out>, referencetype=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/modelloader.cpp:4167
#16 0x00007f9de44f3570 in CGameServer::fuzz_maps (this=this@entry=0x7f9de8358b40 <sv>, szModelName=szModelName@entry=0x7ffda78e5a20 "maps/fuzz.bsp") at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sv_main.cpp:2970
#17 0x00007f9de44fa9ae in CGameServer::SpawnServer (this=this@entry=0x7f9de8358b40 <sv>, mapname=mapname@entry=0x7f9de83c44a0 <g_HostState+32> "fuzz", mapGroupName=mapGroupName@entry=0x7f9de83c45a0 <g_HostState+288> "", startspot=startspot@entry=0x0) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sv_main.cpp:3282
#18 0x00007f9de4d8319e in Host_NewGame (mapName=mapName@entry=0x7f9de83c44a0 <g_HostState+32> "fuzz", mapGroupName=mapGroupName@entry=0x7f9de83c45a0 <g_HostState+288> "", loadGame=loadGame@entry=false, bBackgroundLevel=<optimized out>, bSplitScreenConnect=<optimized out>, pszOldMap=pszOldMap@entry=0x0, pszLandmark=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/host.cpp:6270
#19 0x00007f9de4de3350 in CHostState::State_NewGame (this=this@entry=0x7f9de83c4480 <g_HostState>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/host_state.cpp:436
#20 0x00007f9de4de86c7 in CHostState::FrameUpdate (this=<optimized out>, time=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/host_state.cpp:788
#21 0x00007f9de52b1512 in CEngine::Frame (this=0x7f9de83d77e0 <g_Engine>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_engine.cpp:572
#22 0x00007f9de528cb08 in CEngineAPI::MainLoop (this=0x7f9de83d7240 <s_EngineAPI>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_dll2.cpp:1161
#23 0x00007f9de528d70f in CModAppSystemGroup::Main (this=<optimized out>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_dll2.cpp:2416
#24 0x00007f9de68ac645 in CAppSystemGroup::Run (this=this@entry=0x7ffda78e68e0) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/appframework/AppSystemGroup.cpp:775
#25 0x00007f9de529cede in CEngineAPI::RunListenServer (this=0x7f9de83d7240 <s_EngineAPI>) at /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_dll2.cpp:1437
#26 0x00007f9df308c875 in ?? ()
#27 0x00007ffda78e6a50 in ?? ()
#28 0x00007ffda78e6b60 in ?? ()
#29 0x00007f9df324eab0 in ?? ()
#30 0x00007f9df3276000 in ?? ()
#31 0x00007f9df327bf5a in ?? ()
#32 0xffffffffffffff90 in ?? ()
#33 0x00007ffda78e6a90 in ?? ()
#34 0x00007f9df308c875 in ?? ()
#35 0x00007f9df3276000 in ?? ()
#36 0xffffffffffffff90 in ?? ()
#37 0x0000000000000000 in ?? ()


```
{% endraw %}

And it is a null pointer dereference so that means that skipping the waiting stuff breaks something :( .

I think that this shit has something to do with the fact that we are fuzzing the client instead of the server. Aka for example in SV_FlushMemoryIfMarked :


{% raw %}
```

// ...

bool SV_FlushMemoryIfMarked()
{
    if ( g_bFlushMemoryOnNextServer )
    {
        g_bFlushMemoryOnNextServer = false;
        if ( IsGameConsole() )
        {
            g_pQueuedLoader->PurgeAll();
        }
        g_pDataCache->Flush();
        g_pMaterialSystem->CompactMemory();
        g_pFileSystem->AsyncFinishAll();
#if !defined( DEDICATED )
        extern CThreadMutex g_SndMutex;
        g_SndMutex.Lock();
        g_pFileSystem->AsyncSuspend();
        g_pThreadPool->SuspendExecution();
        g_pMemAlloc->CompactHeap();
        g_pThreadPool->ResumeExecution();
        g_pFileSystem->AsyncResume();
        g_SndMutex.Unlock();
#endif // DEDICATED

        return true;
    }
    else
    
    // ...

```
{% endraw %}

So I think that this has something to do with the client shit.

Lets take a look at InitWellKnownRenderTargets :


{% raw %}
```
void InitWellKnownRenderTargets( void )
{
#if !defined( DEDICATED )

	if ( mat_debugalttab.GetBool() )
	{
		Warning( "mat_debugalttab: InitWellKnownRenderTargets\n" );
	}

	// Begin block in which all render targets should be allocated
	materials->BeginRenderTargetAllocation();

	// Create the render targets upon which mods may rely

	if ( IsPC() )
	{
		// Create for all mods as vgui2 uses it for 3D painting
		g_PowerOfTwoFBTexture.Init( CreatePowerOfTwoFBTexture() );
	}

	// Create these for all mods because the engine references them
	if ( IsPC() && g_pMaterialSystemHardwareConfig->GetHDRType() == HDR_TYPE_FLOAT )
	{
		// Used for building HDR Cubemaps
		g_BuildCubemaps16BitTexture.Init( CreateBuildCubemaps16BitTexture() );
	}

	// Used in Bloom effects
	g_QuarterSizedFBTexture0.Init( CreateQuarterSizedFBTexture( 0, 0 ) );

	/*
	// Commenting out this texture aliasing because it breaks the paint screenspace effect in Portal 2.
	if( IsX360() )
	materials->AddTextureAlias( "_rt_SmallFB1", "_rt_SmallFB0" ); //an alias is good enough on the 360 since we don't have a texture lock problem during post processing
	else
	g_QuarterSizedFBTexture1.Init( CreateQuarterSizedFBTexture( 1, 0 ) );			
	*/
	g_QuarterSizedFBTexture1.Init( CreateQuarterSizedFBTexture( 1, 0 ) );
#if ! ( defined( LEFT4DEAD ) || defined( CSTRIKE15 ) )
	g_QuarterSizedFBTexture2.Init( CreateQuarterSizedFBTexture( 2, 0 ) );
	g_QuarterSizedFBTexture3.Init( CreateQuarterSizedFBTexture( 3, 0 ) );			
#endif


#if defined( _X360 )
	g_RtGlowTexture360.InitRenderTargetTexture( 8, 8, RT_SIZE_NO_CHANGE, IMAGE_FORMAT_ARGB8888, MATERIAL_RT_DEPTH_NONE, false, "_rt_Glows360" );

	// NOTE: The 360 requires render targets generated with 1xMSAA to be 80x16 aligned in EDRAM
	//       Using 1120x624 since this seems to be the largest surface we can fit in EDRAM next to the back buffer
	g_RtGlowTexture360.InitRenderTargetSurface( 1120, 624, IMAGE_FORMAT_ARGB8888, false );
#endif

	if ( IsPC() )
	{
		g_TeenyFBTexture0.Init( CreateTeenyFBTexture( 0 ) );
		g_TeenyFBTexture1.Init( CreateTeenyFBTexture( 1 ) );
		g_TeenyFBTexture2.Init( CreateTeenyFBTexture( 2 ) );
	}

#ifdef _PS3
	g_FullFrameRawBufferAliasPS3_BackBuffer.Init(
		materials->CreateNamedRenderTargetTextureEx2(
		"^PS3^BACKBUFFER",
		1, 1, RT_SIZE_FULL_FRAME_BUFFER,
		materials->GetBackBufferFormat(), 
		MATERIAL_RT_DEPTH_SHARED,
		TEXTUREFLAGS_CLAMPS | TEXTUREFLAGS_CLAMPT,
		CREATERENDERTARGETFLAGS_HDR ) );
	g_FullFrameRawBufferAliasPS3_DepthBuffer.Init(
		materials->CreateNamedRenderTargetTextureEx2(
		"^PS3^DEPTHBUFFER",
		1, 1, RT_SIZE_FULL_FRAME_BUFFER,
		g_pMaterialSystemHardwareConfig->GetShadowDepthTextureFormat(),
		MATERIAL_RT_DEPTH_NONE,
		TEXTUREFLAGS_CLAMPS | TEXTUREFLAGS_CLAMPT | TEXTUREFLAGS_POINTSAMPLE,
		CREATERENDERTARGETFLAGS_NOEDRAM ) );
#endif

	g_FullFrameFBTexture0.Init( CreateFullFrameFBTexture( 0 ) );

	// Since the tools may not draw the world, we don't want depth buffer effects
	if ( toolframework->InToolMode() )
	{
		mat_resolveFullFrameDepth.SetValue( 0 );
	}

#if defined( LEFT4DEAD )
	if ( IsPC() )	
	{
		g_FullFrameFBTexture1.Init( CreateFullFrameFBTexture( 1 ) );	// save some memory on the 360
	}
#else

	g_FullFrameFBTexture1.Init( CreateFullFrameFBTexture( 1, CREATERENDERTARGETFLAGS_TEMP ) );

#endif

#ifndef _PS3
	g_FullFrameDepth.Init( CreateFullFrameDepthTexture() );
#endif

	// Allow the client to init their own mod-specific render targets
	if ( g_pClientRenderTargets )
	{
		g_pClientRenderTargets->InitClientRenderTargets( materials, g_pMaterialSystemHardwareConfig );
	}
	else
	{
		// If this mod doesn't define the interface, fallback to initializing the standard render textures 
		// NOTE: these should match up with the 'Get' functions in cl_dll/rendertexture.h/cpp
		g_WaterReflectionTexture.Init( CreateWaterReflectionTexture() );
		g_WaterRefractionTexture.Init( CreateWaterRefractionTexture() );
		g_CameraTexture.Init( CreateCameraTexture() );
	}

	// End block in which all render targets should be allocated (kicking off an Alt-Tab type behavior)
	materials->EndRenderTargetAllocation();

	CMatRenderContextPtr pRenderContext( g_pMaterialSystem );
	pRenderContext->SetNonInteractiveTempFullscreenBuffer( g_FullFrameFBTexture0, MATERIAL_NON_INTERACTIVE_MODE_LEVEL_LOAD );
#endif
}

```
{% endraw %}

And look at that. There is a big ass check for DEDICATED . if !defined is if not defined so if not defined as a dedicated server then do all of this. So lets add the dedicated flag into the compiler flags and see what happens.

And that did the trick! After recompiling with -DDEDICATED=1 in the cmake options we now get a working map fuzzer! Fantastic!

------------

After a bit of fiddling around I now have a couple crashes.

Now I am going to start with the low hanging fruit. I am going to start with the stack buffer overflows and then go over the heap-buffer-overflows.

There are only one interesting stack based buffer overflow and I do not think that it is that important:



{% raw %}
```
[S_API] SteamAPI_Init(): Loaded '/home/cyberhacker/.local/share/Steam/linux64/steamclient.so' OK.
Setting breakpad minidump AppID = 730
SteamInternal_SetMinidumpSteamID:  Caching Steam ID:  76561198999137044 [API loaded no]
=================================================================
==10629==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fff77141c14 at pc 0x7f2f5c842b0a bp 0x7fff77141aa0 sp 0x7fff77141a90
READ of size 4 at 0x7fff77141c14 thread T0
    #0 0x7f2f5c842b09 in VectorCopy(Vector const&, Vector&) /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/public/mathlib/vector.h:813
    #1 0x7f2f5c842b09 in CCoreDispSurface::AdjustSurfPointData() /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/public/builddisp.cpp:401
    #2 0x7f2f5c9a7d42 in CollisionBSPData_LoadDispInfo(CCollisionBSPData*, texinfo_s*, int) /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/cmodel_bsp.cpp:1204
    #3 0x7f2f5c9ae3fa in CollisionBSPData_Load(char const*, CCollisionBSPData*, texinfo_s*, int) /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/cmodel_bsp.cpp:295
    #4 0x7f2f5c926f0f in CM_LoadMap(char const*, bool, texinfo_s*, int, unsigned int*) /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/cmodel.cpp:360
    #5 0x7f2f5c453012 in CModelLoader::Map_LoadModelGuts(model_t*) /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/modelloader.cpp:5232
    #6 0x7f2f5c45613c in CModelLoader::Map_LoadModel(model_t*) /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/modelloader.cpp:5187
    #7 0x7f2f5c458f35 in CModelLoader::LoadModel(model_t*, IModelLoader::REFERENCETYPE*) /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/modelloader.cpp:4402
    #8 0x7f2f5c45208c in CModelLoader::GetModelForName(char const*, IModelLoader::REFERENCETYPE) /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/modelloader.cpp:4170
    #9 0x7f2f5c5e6385 in CGameServer::SpawnServer(char*, char*, char*) /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sv_main.cpp:3349
    #10 0x7f2f5ce3c743 in Host_NewGame(char*, char*, bool, bool, bool, char const*, char const*) /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/host.cpp:6270
    #11 0x7f2f5ce8c3bf in CHostState::State_NewGame() /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/host_state.cpp:436
    #12 0x7f2f5ce91013 in CHostState::FrameUpdate(float) /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/host_state.cpp:788
    #13 0x7f2f5d2e1a59 in CEngine::Frame() /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_engine.cpp:572
    #14 0x7f2f5d2c324f in CDedicatedServerAPI::RunFrame() /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_dll2.cpp:2900
    #15 0x7f2f5f6d3da7 in RunServerIteration(bool) /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/dedicated/sys_ded.cpp:215
    #16 0x7f2f5f6d4153 in RunServer(bool) /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/dedicated/sys_ded.cpp:275
    #17 0x7f2f5f6cf50e in CDedicatedExports::RunServer() /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/dedicated/sys_common.cpp:198
    #18 0x7f2f5d2c3723 in CModAppSystemGroup::Main() /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_dll2.cpp:2399
    #19 0x7f2f5e08b2f4 in CAppSystemGroup::Run() /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #20 0x7f2f5d2cc7af in CDedicatedServerAPI::ModInit(ModInfo_t&) /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/engine/sys_dll2.cpp:2864
    #21 0x7f2f5f6d4a93 in CDedicatedAppSystemGroup::Main() /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/dedicated/sys_ded.cpp:447
    #22 0x7f2f5faaa564 in CAppSystemGroup::Run() /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #23 0x7f2f5faaa564 in CAppSystemGroup::Run() /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #24 0x7f2f5f69e59e in main /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/dedicated/sys_ded.cpp:652
    #25 0x55693c0acaac in main /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/dedicated_main/main.cpp:176
    #26 0x7f2f63785082 in __libc_start_main ../csu/libc-start.c:308
    #27 0x55693c0ad2cd in _start (/home/cyberhacker/Fuzzingnavfiles/game/srcds_linux+0x42cd)

Address 0x7fff77141c14 is located in stack of thread T0 at offset 116 in frame
    #0 0x7f2f5c83e94f in CCoreDispSurface::AdjustSurfPointData() /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/public/builddisp.cpp:374

  This frame has 7 object(s):
    [32, 48) 'tmpAlphas' (line 378)
    [64, 96) 'tmpTexCoords' (line 377)
    [128, 176) 'tmpPoints' (line 375) <== Memory access at offset 116 underflows this variable
    [208, 256) 'tmpNormals' (line 376)
    [288, 352) 'tmpMultiBlend' (line 379)
    [384, 448) 'tmpAlphaBlend' (line 380)
    [480, 672) 'tmpBlendColor' (line 381)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow /home/cyberhacker/Fuzzingnavfiles/Kisak-Strike/public/mathlib/vector.h:813 in VectorCopy(Vector const&, Vector&)
Shadow bytes around the buggy address:
  0x10006ee20330: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10006ee20340: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10006ee20350: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10006ee20360: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10006ee20370: 00 00 00 00 f1 f1 f1 f1 00 00 f2 f2 00 00 00 00
=>0x10006ee20380: f2 f2[f2]f2 00 00 00 00 00 00 f2 f2 f2 f2 00 00
  0x10006ee20390: 00 00 00 00 f2 f2 f2 f2 00 00 00 00 00 00 00 00
  0x10006ee203a0: f2 f2 f2 f2 00 00 00 00 00 00 00 00 f2 f2 f2 f2
  0x10006ee203b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10006ee203c0: 00 00 00 00 00 00 00 00 f3 f3 f3 f3 f3 f3 f3 f3
  0x10006ee203d0: 00 00 00 00 00 00 00 00 00 00 00 00 ca ca ca ca
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
==10629==ABORTING
id:000198,sig:06,src:000281,time:4389326,execs:156417,op:havoc,rep:16

```
{% endraw %}









{% raw %}
```
void CCoreDispSurface::AdjustSurfPointData( void )
{
	Vector		tmpPoints[4];
	Vector		tmpNormals[4];
	Vector2D	tmpTexCoords[4];
	float		tmpAlphas[4];
	Vector4D	tmpMultiBlend[ 4 ];
	Vector4D	tmpAlphaBlend[ 4 ];
	Vector		tmpBlendColor[ 4 ][ MAX_MULTIBLEND_CHANNELS ];

	int i;
	for( i = 0; i < QUAD_POINT_COUNT; i++ )
	{
		VectorCopy( m_Points[i], tmpPoints[i] );
		VectorCopy( m_Normals[i], tmpNormals[i] );
		Vector2DCopy( m_TexCoords[i], tmpTexCoords[i] );

		tmpAlphas[i] = m_Alphas[i];
		tmpMultiBlend[ i ] = m_MultiBlends[ i ];
		tmpAlphaBlend[ i ] = m_AlphaBlends[ i ];
		for( int j = 0; j < MAX_MULTIBLEND_CHANNELS; j++ )
		{
			tmpBlendColor[ i ][ j ] = m_vBlendColors[ i ][ j ];
		}
	}

	for( i = 0; i < QUAD_POINT_COUNT; i++ )
	{
		VectorCopy( tmpPoints[(i+m_PointStartIndex)%4], m_Points[i] );
		VectorCopy( tmpNormals[(i+m_PointStartIndex)%4], m_Normals[i] );
		Vector2DCopy( tmpTexCoords[(i+m_PointStartIndex)%4], m_TexCoords[i] );

		m_Alphas[i] = tmpAlphas[i];	// is this correct?
		m_MultiBlends[ i ] = tmpMultiBlend[ (i+m_PointStartIndex)%4 ];
		m_AlphaBlends[ i ] = tmpAlphaBlend[ (i+m_PointStartIndex)%4 ];
		for( int j = 0; j < MAX_MULTIBLEND_CHANNELS; j++ )
		{
			m_vBlendColors[ i ][ j ] = tmpBlendColor[ ( i + m_PointStartIndex ) % 4 ][ j ];
		}
	}
}


```
{% endraw %}

The VectorCopy functions first argument is the source and the second is the destination:

{% raw %}
```


#ifdef VECTOR_PARANOIA
#define CHECK_VALID( _v)	Assert( (_v).IsValid() )
#else
#ifdef GNUC
#define CHECK_VALID( _v)
#else
#define CHECK_VALID( _v)	0
#endif
#endif

// -- snip --



FORCEINLINE void VectorCopy( const Vector& src, Vector& dst )
{
	CHECK_VALID(src);
	dst.x = src.x;
	dst.y = src.y;
	dst.z = src.z;
}

```
{% endraw %}

The report mentions that this is a read issue, not a write issue, so we can not overflow the buffer with data which we control, but instead we must overflow the buffer with data from an out-of-bounds source.

I need to compile another version in which I can observe all of the things without interrupting the fuzzer. Also the reason why there are so many null dereferences is because the program crashes purposefully in the Sys_Error_Internal function:

{% raw %}
```
// ...
	fflush(stdout );
	
	int *p = 0;
	*p = 0xdeadbeef;
#elif defined( LINUX )
	// Doing this doesn't quite work the way we want because there is no "crashing" thread
	// and we see "No thread was identified as the cause of the crash; No signature could be created because we do not know which thread crashed" on the back end
	//SteamAPI_WriteMiniDump( 0, NULL, build_number() );
	int *p = 0;
	*p = 0xdeadbeef;
#else
//!!BUG!! "need minidump impl on sys_error"
#endif

// ...
```
{% endraw %}

So lets patch that shit out before continuing so we actually get the actual crashes.

In the meantime during fuzzing and compiling lets try to improve the mini_bsp thing here: https://github.com/niklasb/bspfuzz

The reason why I want to do this is because the corpus which I am now using consists of only one file roughly 16kb in size, which is quite large for fuzzing but tiny in terms of a game map. The bspfuzz mini_bsp script tries to simplify the file by taking out redundant lumps which are not really that interesting for example the PAK file lump and so on.

Even with all the removing enabled, we are still left with roughly a quarter of the file:

{% raw %}
```

cyberhacker@cyberhacker-h8-1131sc:~/Fuzzingnavfiles/bspfuzz/mini_bsp$ python mini_bsp.py de_dust2.bsp thing.bsp
51206100
0 2975348 124196
1 725520 644400
2 544856 8576
3 5400608 453300
4 1975904 999444
5 1850868 124512
6 1040 543816
7 6734876 874496
8 9350932 0
9 9350920 12
10 562820 125504
11 26857960 31232
12 5853908 357348
13 6211256 523620
14 1849428 1440
15 25512028 0
16 25288032 46900
17 688324 37194
18 1369920 76356
19 1446276 403152
20 1975380 128
21 1975508 396
22 26889192 3348
23 26892540 62464
24 0 0
25 0 0
26 5291664 108944
27 26955004 749784
28 9260696 90223
29 3099544 2192117
30 24132200 54360
31 24186560 154776
32 0 0
33 8483868 674620
34 25515128 1311600
35 27704788 145300
36 25334932 0
37 23996424 27970
38 24024396 0
39 24024396 107802
40 27850088 23356012
41 25510444 1584
42 25509852 592
43 553432 8313
44 561748 1072
45 25334932 161568
46 25502008 7844
47 26826728 31232
48 9158488 102208
49 0 0
50 25496500 0
51 24466840 15688
52 24451152 15688
53 9350932 14645492
54 25512028 3100
55 24482528 805504
56 24341336 109816
57 0 0
58 7609372 874496
59 1036 4
60 25496500 3672
61 25500172 1836
62 5291664 0
63 9260696 0
lump=29 size=2192117
lump=34 size=1311600
lump=4 size=999444
lump=58 size=874496
lump=55 size=805504
lump=27 size=749784
lump=33 size=674620
lump=1 size=644400
lump=6 size=543816
lump=19 size=403152
11234467
cyberhacker@cyberhacker-h8-1131sc:~/Fuzzingnavfiles/bspfuzz/mini_bsp$ ls -lh
total 71M
-rw-rw-r-- 1 cyberhacker cyberhacker  49M Jun 21 19:07 de_dust2.bsp
-rwxrwxr-x 1 cyberhacker cyberhacker 6,2K Jun 21 19:09 mini_bsp_modified.py
-rwxrwxr-x 1 cyberhacker cyberhacker 1,9K Jun 16 05:37 mini_bsp.py
-rw-rw-r-- 1 cyberhacker cyberhacker  11M Jun 21 19:08 out2.bsp
-rw-rw-r-- 1 cyberhacker cyberhacker  16K Jun 16 05:41 out.bsp
-rw-rw-r-- 1 cyberhacker cyberhacker 294K Jun 16 05:37 test.bsp
-rw-rw-r-- 1 cyberhacker cyberhacker 9,6K Jun 16 05:37 test_mini.bsp
-rw-rw-r-- 1 cyberhacker cyberhacker  11M Jun 21 19:50 thing.bsp


```
{% endraw %}

So we can not really fuzz using the minified de_dust2 file, because it is so big, however, when looking at the documentation for the BSP file: https://developer.valvesoftware.com/wiki/BSP_(Source_1) we see that we can see the size of each lump type in the file header, so lets make a simple script to parse that (there are existing ones but lets just for practice write up a new one):

One funny thing which I realized when doing the header thing is that when you highlight the lump names list aka LUMP_ENTITIES etc etc in the bspfile.h lines 280 onward you can see which lines they edited later because most of the lines have tabs but some of them have spaces instead of tabs between the equal sign and the variable name. This is just a funny thing which I realized. :) 


After programming my bsp header reader it seems that a lot of the lumps in de_dust2 are just way too large so in order for us to fuzz with them effectively. Instead I am going to download a lot of maps from the web and then try to reduce them. One lump which the minifier does not remove is the 


There is this check inside the modelloader.cpp file:


{% raw %}
```

	if ( s_MapHeader.m_nVersion >= 20 && CMapLoadHelper::LumpSize( LUMP_LEAF_AMBIENT_LIGHTING_HDR ) == 0 )
	{
		// This lump only exists in version 20 and greater, so don't bother checking for it on earlier versions.
		bHasHDR = false;
	}
	

```
{% endraw %}


So I think that it should be fine if we remove the LUMP_LEAF_AMBIENT_LIGHTING_HDR lump from the file. The modelloader should still consume it without complaints.

----

When compiling the other thing I get the fucking materialsystem error message: `#System (VMaterialSystem080) failed during stage CONNECTION` . So probably cleaning everything and recompiling will fix it? This is going to take a long time :( .

Ok I improved the minifier to get rid of the HDR stuff and now I have a file which is 200kb in size for our fuzzer, but which has more lumps in it. I think I can include this testcase.

One other possible strategy is to first download a map and then modify the lumps using ValveBSP for example: https://pysourcesdk.github.io/ValveBSP/ .

I think that I am going to try that next.

As it turns out I am too dumb to figure out how to use the valvebsp package to modify a map. So I think I am going to tackle this problem the way I described initially.

For some reason the compile still failed with the same materialsystem error as before. Maybe try deleting all of the build files (aka not just running make clean but just delete every object file and stuff and then try compiling again?).

---------

After a bit of fuzzing I have found some crashes but the vast majority of them seem to be non exploitable out-of-bounds reads only.



Maybe I should try measuring the amount of time which it takes to load the map and then adjust the timeout by that amount?

Actually I think that there is a bug in my fuzzer, because when I try to load the same map over and over again with the same logic I get this:

{% raw %}
```

LD_LIBRARY_PATH=/home/cyberhacker/Netpacketfuzzer/game/bin:/home/cyberhacker/Netpacketfuzzer/game/bin/linux64
#Module /home/cyberhacker/Netpacketfuzzer/game/bin/linux64/stdshader_dbg failed to load! Error: ((null))
#Module stdshader_dbg failed to load! Error: ((null))
#
#Console initialized.
#Loading VPK file hashes for pure server operation.
#Loading VPK file hashes for pure server operation.
#Loading VPK file hashes for pure server operation.
#Module /home/cyberhacker/Netpacketfuzzer/game/csgo/bin/matchmaking_ds_client.so failed to load! Error: ((null))
#Module /home/cyberhacker/Netpacketfuzzer/game/csgo/bin/server_valve failed to load! Error: ((null))
#Module /home/cyberhacker/Netpacketfuzzer/game/csgo/bin/linux64/server_valve failed to load! Error: ((null))
#Module /home/cyberhacker/Netpacketfuzzer/game/bin/csgo/bin/server_valve failed to load! Error: ((null))
#Module /home/cyberhacker/Netpacketfuzzer/game/bin/csgo/bin/linux64/server_valve failed to load! Error: ((null))
#Module server_valve failed to load! Error: ((null))
#Module /home/cyberhacker/Netpacketfuzzer/game/csgo/bin/server failed to load! Error: ((null))
#Game.dll loaded for "Counter-Strike: Global Offensive"
#CGameEventManager::AddListener: event 'server_pre_shutdown' unknown.
#CGameEventManager::AddListener: event 'game_newmap' unknown.
#CGameEventManager::AddListener: event 'finale_start' unknown.
#CGameEventManager::AddListener: event 'round_start' unknown.
#CGameEventManager::AddListener: event 'round_end' unknown.
#CGameEventManager::AddListener: event 'difficulty_changed' unknown.
#CGameEventManager::AddListener: event 'player_connect' unknown.
#CGameEventManager::AddListener: event 'player_disconnect' unknown.
#GameTypes: missing mapgroupsSP entry for game type/mode (custom/custom).
#GameTypes: missing mapgroupsSP entry for game type/mode (cooperative/cooperative).
#GameTypes: missing mapgroupsSP entry for game type/mode (cooperative/coopmission).
Failed to load gamerulescvars.txt, game rules cvars might not be reported to management tools.
Server is hibernating
[S_API] SteamAPI_Init(): Loaded '/home/cyberhacker/.local/share/Steam/linux64/steamclient.so' OK.
Setting breakpad minidump AppID = 730
SteamInternal_SetMinidumpSteamID:  Caching Steam ID:  76561198999137044 [API loaded no]
Particles: Missing 'particles/money_fx.pcf'
No web api auth key specified - workshop downloads will be disabled.
GameTypes: missing mapgroupsSP entry for game type/mode (custom/custom).
GameTypes: missing mapgroupsSP entry for game type/mode (cooperative/cooperative).
GameTypes: missing mapgroupsSP entry for game type/mode (cooperative/coopmission).
maxplayers set to 64
Unknown command "cl_bobamt_vert"
Unknown command "cl_bobamt_lat"
Unknown command "cl_bob_lower_amt"
Unknown command "cl_viewmodel_shift_left_amt"
Unknown command "cl_viewmodel_shift_right_amt"
Unknown command "cl_teamid_overhead"
Unknown command "cl_teamid_overhead_maxdist"
Unknown command "dev"
---- Host_NewGame ----
Now running benchmark.Loop counter: 0
Loop counter: 1
Loop counter: 2
Loop counter: 3
Loop counter: 4
Loop counter: 5
Loop counter: 6
Loop counter: 7
Loop counter: 8
Loop counter: 9
Loop counter: 10
Loop counter: 11
Loop counter: 12
Loop counter: 13
Engine hunk overflow!
Engine hunk overflow!

Engine hunk overflow!

AddressSanitizer:DEADLYSIGNAL
=================================================================
==3684214==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x7fae75183135 bp 0x7ffdc1b28dc0 sp 0x7ffdc1b28da0 T0)
==3684214==The signal is caused by a WRITE memory access.
==3684214==Hint: address points to the zero page.
    #0 0x7fae75183134 in Plat_ExitProcess /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/tier0/platform_posix.cpp:393
    #1 0x7fae6e8c1eff in Sys_Error_Internal(bool, char const*, __va_list_tag*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll.cpp:496
    #2 0x7fae6e8c2bae in Sys_Error(char const*, ...) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll.cpp:511
    #3 0x7fae6e8c93d8 in CEngineConsoleLoggingListener::Log(LoggingContext_t const*, char const*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll.cpp:992
    #4 0x7fae75171e75 in CLoggingSystem::LogDirect(int, LoggingSeverity_t, Color, char const*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/tier0/logging.cpp:415
    #5 0x7fae75161b4b in Error /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/tier0/dbg.cpp:282
    #6 0x7fae6e9fef98 in Hunk_AllocName(int, char const*, bool) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/zone.cpp:153
    #7 0x7fae6da11be0 in Mod_LoadVertNormalIndices() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/modelloader.cpp:1992
    #8 0x7fae6da619bc in CModelLoader::Map_LoadModelGuts(model_t*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/modelloader.cpp:5215
    #9 0x7fae6da63f6e in CModelLoader::Map_LoadModel(model_t*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/modelloader.cpp:5075
    #10 0x7fae6da66c52 in CModelLoader::LoadModel(model_t*, IModelLoader::REFERENCETYPE*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/modelloader.cpp:4293
    #11 0x7fae6da5febc in CModelLoader::GetModelForName(char const*, IModelLoader::REFERENCETYPE) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/modelloader.cpp:4067
    #12 0x7fae6dbe7b35 in CGameServer::benchmark() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sv_main.cpp:2911
    #13 0x7fae6dbed4d0 in CGameServer::SpawnServer(char*, char*, char*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sv_main.cpp:3164
    #14 0x7fae6e442363 in Host_NewGame(char*, char*, bool, bool, bool, char const*, char const*) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host.cpp:6273
    #15 0x7fae6e491fdf in CHostState::State_NewGame() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host_state.cpp:436
    #16 0x7fae6e496c33 in CHostState::FrameUpdate(float) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/host_state.cpp:790
    #17 0x7fae6e8e8e01 in CEngine::Frame() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_engine.cpp:572
    #18 0x7fae6e8ca61f in CDedicatedServerAPI::RunFrame() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2900
    #19 0x7fae70bd6c37 in RunServerIteration(bool) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:215
    #20 0x7fae70bd6fe3 in RunServer(bool) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:275
    #21 0x7fae70bd239e in CDedicatedExports::RunServer() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_common.cpp:198
    #22 0x7fae6e8caaf3 in CModAppSystemGroup::Main() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2399
    #23 0x7fae6f690d64 in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #24 0x7fae6e8d3b7f in CDedicatedServerAPI::ModInit(ModInfo_t&) /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/engine/sys_dll2.cpp:2864
    #25 0x7fae70bd7923 in CDedicatedAppSystemGroup::Main() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:447
    #26 0x7fae70fab714 in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #27 0x7fae70fab714 in CAppSystemGroup::Run() /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/appframework/AppSystemGroup.cpp:775
    #28 0x7fae70ba141e in main /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated/sys_ded.cpp:652
    #29 0x5572b5f7daac in main /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/dedicated_main/main.cpp:176
    #30 0x7fae74bed082 in __libc_start_main ../csu/libc-start.c:308
    #31 0x5572b5f7e2cd in _start (/home/cyberhacker/Netpacketfuzzer/game/srcds_linux+0x42cd)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /home/cyberhacker/Netpacketfuzzer/Kisak-Strike/tier0/platform_posix.cpp:393 in Plat_ExitProcess
==3684214==ABORTING


```
{% endraw %}

That is when loading the de_dust2.bsp map over and over again. I think we are not closing up all of the stuff before continuing with the next load?

Even after running shutdown and then init again on the fucking map we still get the same thing. My code currently is this:


{% raw %}
```

void CGameServer::benchmark( void ) {

    //     host_state.SetWorldModel( modelloader->GetModelForName( szModelName, IModelLoader::FMODELLOADER_SERVER ) );
    model_t* out;

    /*

    static CModelLoader g_ModelLoader;
IModelLoader *modelloader = ( IModelLoader * )&g_ModelLoader;
*/

    //static CModelLoader g_ModelLoader;
    //IModelLoader *modelloader = ( IModelLoader * )&g_ModelLoader;

    for (int i = 0; i < 1000; i++) {
        ConMsg("Loop counter: %d\n", i);

        modelloader->Shutdown();
        modelloader->Init();


        out = modelloader->GetModelForName("maps/bench.bsp", IModelLoader::FMODELLOADER_SERVER);

        if ( out != NULL ) {
            //ConMsg("Succesfully loaded the map!\n");
            //modelloader->UnloadModel(mdl);
            modelloader->UnreferenceAllModels(0x2ffff);
            modelloader->PurgeUnusedModels();

            // These fucks may have been the answer to our problem.
        }

        /*
            // Is a model loaded?
    virtual bool    IsLoaded( const model_t *mod );
        */

        if (modelloader->IsLoaded(out)) {
            ConMsg("Model is still loaded!\n");
        }

        ConMsg("poopoo\n");


    }

    return;
}



```
{% endraw %}

Maybe look at the SpawnServer function and see what it does before trying to load the map?


I am going to list interesting snippets here:

{% raw %}
```
// ...

    if ( IsGameConsole() && g_pQueuedLoader->IsMapLoading() )
    {
        Msg( "Spawning a new server - loading map %s. Forcing current map load to end.\n", mapname );
        g_pQueuedLoader->EndMapLoading( true );
    }

// ...












```
{% endraw %}


This here works prefectly fine, but it still has the memory allocated (if you observe in htop you can see the memory meter go up):


{% raw %}
```

void CGameServer::benchmark( void ) {

    //     host_state.SetWorldModel( modelloader->GetModelForName( szModelName, IModelLoader::FMODELLOADER_SERVER ) );
    model_t* out;

    /*

    static CModelLoader g_ModelLoader;
IModelLoader *modelloader = ( IModelLoader * )&g_ModelLoader;
*/

    //static CModelLoader g_ModelLoader;
    //IModelLoader *modelloader = ( IModelLoader * )&g_ModelLoader;

    for (int i = 0; i < 1000; i++) {
        ConMsg("Loop counter: %d\n", i);

        modelloader->Shutdown();
        materials->OnLevelShutdown();
        modelloader->Init();

        //ConMsg("Printing with DebugPrintDynamicModels\n");
        //modelloader->DebugPrintDynamicModels();

        ConMsg("Printing with Print()\n");

        modelloader->Print();

        ConMsg("Resetting memory with Hunk_OnMapStart:\n");
        Memory_Shutdown();
        Memory_Init();
        Hunk_OnMapStart(0);

        ConMsg("Printing Hunk_Print\n");

        Hunk_Print();

        // Memory_Init
        // Hunk_OnMapStart
        // Memory_Shutdown


        out = modelloader->GetModelForName("maps/bench.bsp", IModelLoader::FMODELLOADER_SERVER);

        
        Assert(out);
        if (out == NULL ) {

            ConMsg("Fuck!\n");

            int* p = 0;
            *p = 0xBADBEEF;
        }
        

        if ( out != NULL ) {
            //ConMsg("Succesfully loaded the map!\n");
            //modelloader->UnloadModel(mdl);
            modelloader->UnreferenceAllModels(0x2ffff);
            modelloader->PurgeUnusedModels();

            // These fucks may have been the answer to our problem.
        }

        




        /*
            // Is a model loaded?
    virtual bool    IsLoaded( const model_t *mod );
        */

        if (modelloader->IsLoaded(out)) {
            ConMsg("Model is still loaded!\n");
        }

        ConMsg("poopoo\n");


    }

    return;
}


```
{% endraw %}

Except I think I got it! There are the Hunk_LowMark and Hunk_FreeToLowMark functions. The Hunk_LowMark tells you how many "blocks" have been allocated and then the Hunk_FreeToLowMark function then frees until that block! So if we just do this I think we should be good:

{% raw %}
```

void CGameServer::benchmark( void ) {

    //     host_state.SetWorldModel( modelloader->GetModelForName( szModelName, IModelLoader::FMODELLOADER_SERVER ) );
    model_t* out;
    int mem_count_thing;
    /*

    static CModelLoader g_ModelLoader;
IModelLoader *modelloader = ( IModelLoader * )&g_ModelLoader;
*/

    //static CModelLoader g_ModelLoader;
    //IModelLoader *modelloader = ( IModelLoader * )&g_ModelLoader;

    for (int i = 0; i < 1000; i++) {
        ConMsg("Loop counter: %d\n", i);

        //modelloader->Shutdown();
        //materials->OnLevelShutdown();
        //modelloader->Init();

        //ConMsg("Printing with DebugPrintDynamicModels\n");
        //modelloader->DebugPrintDynamicModels();

        ConMsg("Printing with Print()\n");

        modelloader->Print();

        //ConMsg("Resetting memory with Hunk_OnMapStart:\n");
        //Memory_Shutdown();
        //Memory_Init();
        //Hunk_OnMapStart(0);

        ConMsg("Printing Hunk_Print\n");

        Hunk_Print();

        // Memory_Init
        // Hunk_OnMapStart
        // Memory_Shutdown
        mem_count_thing = Hunk_LowMark();

        out = modelloader->GetModelForName("maps/bench.bsp", IModelLoader::FMODELLOADER_SERVER);

        Hunk_FreeToLowMark(mem_count_thing);
        
        Assert(out);
        if (out == NULL ) {

            ConMsg("Fuck!\n");

            int* p = 0;
            *p = 0xBADBEEF;
        }
        

        if ( out != NULL ) {
            //ConMsg("Succesfully loaded the map!\n");
            //modelloader->UnloadModel(mdl);
            modelloader->UnreferenceAllModels(0x2ffff);
            modelloader->PurgeUnusedModels();

            // These fucks may have been the answer to our problem.
        }

        




        /*
            // Is a model loaded?
    virtual bool    IsLoaded( const model_t *mod );
        */

        if (modelloader->IsLoaded(out)) {
            ConMsg("Model is still loaded!\n");
        }

        ConMsg("poopoo\n");


    }

    return;
}


```
{% endraw %}

Except that the memory counter still goes up? What to do? There is also this here in host.cpp :

{% raw %}
```
void Host_FreeToLowMark( bool server )
{
	Assert( host_initialized );
	Assert( host_hunklevel );

	// If called by the client and we are running a listen server, just ignore
	if ( !server && ( sv.IsActive() || sv.IsLoading() ) )
		return;

	CM_FreeMap();

	if ( host_hunklevel )
	{
		// See if we are going to obliterate any malloc'd pointers
		Hunk_FreeToLowMark(host_hunklevel);
	}
}

```
{% endraw %}

and in cmodel.cpp : 

{% raw %}
```

void CM_FreeMap(void)
{
	// get the current collision bsp -- there is only one!
	CCollisionBSPData *pBSPData = GetCollisionBSPData();

	// free the collision bsp data
	CollisionBSPData_Destroy( pBSPData );
}


```
{% endraw %}

So I think that we need to call CM_FreeMap in addition to the other stuff? Lets try that.

and tada:

{% raw %}
```

void CGameServer::benchmark( void ) {

    //     host_state.SetWorldModel( modelloader->GetModelForName( szModelName, IModelLoader::FMODELLOADER_SERVER ) );
    model_t* out;
    int mem_count_thing;
    /*

    static CModelLoader g_ModelLoader;
IModelLoader *modelloader = ( IModelLoader * )&g_ModelLoader;
*/

    //static CModelLoader g_ModelLoader;
    //IModelLoader *modelloader = ( IModelLoader * )&g_ModelLoader;

    for (int i = 0; i < 1000; i++) {
        ConMsg("Loop counter: %d\n", i);

        //modelloader->Shutdown();
        //materials->OnLevelShutdown();
        //modelloader->Init();

        //ConMsg("Printing with DebugPrintDynamicModels\n");
        //modelloader->DebugPrintDynamicModels();

        ConMsg("Printing with Print()\n");

        modelloader->Print();

        //ConMsg("Resetting memory with Hunk_OnMapStart:\n");
        //Memory_Shutdown();
        //Memory_Init();
        //Hunk_OnMapStart(0);

        ConMsg("Printing Hunk_Print\n");

        Hunk_Print();

        // Memory_Init
        // Hunk_OnMapStart
        // Memory_Shutdown
        mem_count_thing = Hunk_LowMark();

        //CCollisionBSPData *pBSPData = GetCollisionBSPData();

        // free the collision bsp data
        //CollisionBSPData_Destroy( pBSPData );

        out = modelloader->GetModelForName("maps/bench.bsp", IModelLoader::FMODELLOADER_SERVER);
        CM_FreeMap();
        Hunk_FreeToLowMark(mem_count_thing);
        
        Assert(out);
        if (out == NULL ) {

            ConMsg("Fuck!\n");

            int* p = 0;
            *p = 0xBADBEEF;
        }
        

        if ( out != NULL ) {
            //ConMsg("Succesfully loaded the map!\n");
            //modelloader->UnloadModel(mdl);
            modelloader->UnreferenceAllModels(0x2ffff);
            modelloader->PurgeUnusedModels();

            // These fucks may have been the answer to our problem.
        }

        




        /*
            // Is a model loaded?
    virtual bool    IsLoaded( const model_t *mod );
        */

        if (modelloader->IsLoaded(out)) {
            ConMsg("Model is still loaded!\n");
        }

        ConMsg("poopoo\n");


    }

    return;
}


```
{% endraw %}

This works perfectly! No more memoryleak!

Lets add it to our fuzzer.

-----------------------------------------------

After fuzzing we now have exactly one promising crash. It is the same crash as described here: https://phoenhex.re/2018-08-26/csgo-fuzzing-bsp the heap-buffer-overflow .

The blog text mentions that this bug hasn't even been fixed yet for some reason. Idk .




















