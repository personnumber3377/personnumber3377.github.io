
# Hacking CS:GO

I decided to write this blog post to outline my (new) attempt to try to hack counter strike global offensive. I have tried this before, but I didn't find any interesting bugs, which were present in the release version of counter strike global offensive.

I saw this post: https://ctf.re/source-engine/exploitation/2021/05/01/source-engine-2/ and I decided to fuzz the entity parsing mechanism of this game. So I have coded this: https://github.com/personnumber3377/Csgoprotofuzz which fuzzes the protobuf messages when they are going through afl. I compiled a leaked version of counter strike called "Kisak-Strike", which is basically internally identical to the real deal. I compiled it with asan and added a fuzzing loop which fuzzes the packets in the packet handler.

I played the game for a bit and recorded some of the packets which went through the game and made a corpus out of them. Then I filtered the CSVCMsg_PacketEntities packets out of the corpus using the Csgoprotofuzz script which I programmed. (The protobuf messages are described here: https://github.com/SteamDatabase/GameTracking-CS2/blob/master/Protobufs/netmessages.proto) One quite a big fault of my fuzzer is that it doesn't take into account the state the game is in. It assumes that the game state is independent of the previous game states. This is of course not the case, but I think we can still discover shallow bugs with this technique. The source code of the source engine (which counter strike is based on) is a mess of pointer arithmetic which is highly vulnerable to human coder oversights (integer under- and overflows, buffer overflows etc etc.) . One thing which makes me annoyed is that the game requires steam to run in order to run. If we try to remove the steam api connection from the source code, we run into problems. Also another thing is that I actually let the fuzzer run for 300 network packets before starting fuzzing, because then we achieve a state which is interesting from a fuzzing point of view. (We are actually in the game.) Also because the source engine is the source engine, the code stability is absolute garbage, so don't expect to be able to minimize your corpus with this stability :D . Also also another thing is that asan is slow and starting the fuzzer on my machine can take around 20 minutes, before we even start fuzzing. The fuzzer has to first reach the state which is important from a fuzzing perspective.

When fuzzing with the Csgoprotofuzz script and with the PacketEntities packets, I don't get anything. After looking at the code I found this (inside ents_shared.h) :

```

enum UpdateType
{
	EnterPVS = 0,	// Entity came back into pvs, create new entity if one doesn't exist

	LeavePVS,		// Entity left pvs

	DeltaEnt,		// There is a delta for this entity.
	PreserveEnt,	// Entity stays alive but no delta ( could be LOD, or just unchanged )

	Finished,		// finished parsing entities successfully
	Failed,			// parsing error occured while reading entities
};

```

and this:

```

void CClientState::ReadPacketEntities( CEntityReadInfo &u )
{
	// Loop until there are no more entities to read

	bool bRecord = cl_entityreport.GetBool();

	int oldEntity = u.m_nOldEntity;
	oldEntity = u.GetNextOldEntity(u.m_nOldEntity);
	UpdateType updateType = u.m_UpdateType;

	while ( updateType < Finished )
	{
		u.m_nHeaderCount--;

		u.m_bIsEntity = ( u.m_nHeaderCount >= 0 ) ? true : false;

		if ( u.m_bIsEntity  )
		{
			CL_ParseDeltaHeader( u );
		}

		for ( updateType = PreserveEnt; updateType == PreserveEnt; )
		{
			// Figure out what kind of an update this is.
			updateType = DetermineUpdateType(u, oldEntity);
			switch( updateType )
			{
			case EnterPVS:	
				{
					int iClass = u.m_pBuf->ReadUBitLong( m_nServerClassBits );

					int iSerialNum = u.m_pBuf->ReadUBitLong( NUM_NETWORKED_EHANDLE_SERIAL_NUMBER_BITS );
					u.m_nOldEntity = oldEntity;
					CL_CopyNewEntity( u, iClass, iSerialNum );

					if ( u.m_nNewEntity == oldEntity ) // that was a recreate
					{
						oldEntity = u.GetNextOldEntity(oldEntity);
					}
				}
				break;

			case LeavePVS:
				{
					if ( !u.m_bAsDelta )
					{
						Assert(0); // GetBaseLocalClient().validsequence = 0;
						ConMsg( "WARNING: LeavePVS on full update" );
						updateType = Failed;	// break out
					}
					else
					{
						Assert( !u.m_pTo->transmit_entity.Get( oldEntity ) );

						if ( u.m_UpdateFlags & FHDR_DELETE )
						{
							CL_DeleteDLLEntity( oldEntity, "ReadLeavePVS" );
						}

						oldEntity = u.GetNextOldEntity(oldEntity);
					}
				}
				break;

			case DeltaEnt:
				{
					u.m_nOldEntity = oldEntity;
					CL_CopyExistingEntity( u );
					oldEntity = u.GetNextOldEntity(oldEntity);
				}
				break;

			case PreserveEnt:
				{
					if ( !u.m_bAsDelta )  // Should never happen on a full update.
					{
						updateType = Failed;	// break out
					}
					else
					{
						Assert( u.m_pFrom->transmit_entity.Get(oldEntity) );

						// copy one of the old entities over to the new packet unchanged
						if ( u.m_nNewEntity < 0 || u.m_nNewEntity >= MAX_EDICTS )
						{
							Host_Error ("CL_ReadPreserveEnt: u.m_nNewEntity == MAX_EDICTS");
						}

						u.m_pTo->last_entity = oldEntity;
						u.m_pTo->transmit_entity.Set( oldEntity );

						if ( bRecord )
						{
							CL_RecordEntityBits( oldEntity, 0 );
						}

						oldEntity = u.GetNextOldEntity(oldEntity);
					}
				}
				break;

			default:
				break;
			}
		}
	}
	u.m_nOldEntity = oldEntity;
	u.m_UpdateType = updateType;

	// Now process explicit deletes 
	if ( u.m_bAsDelta && u.m_UpdateType == Finished )
	{
		ReadDeletions( u );
	}

	// Something didn't parse...
	if ( u.m_pBuf->IsOverflowed() )							
	{	
		Host_Error ( "CL_ParsePacketEntities:  buffer read overflow\n" );
	}

	// If we get an uncompressed packet, then the server is waiting for us to ack the validsequence
	// that we got the uncompressed packet on. So we stop reading packets here and force ourselves to
	// send the clc_move on the next frame.

	if ( !u.m_bAsDelta )
	{
		m_flNextCmdTime = 0.0; // answer ASAP to confirm full update tick
	} 
}

```

So first our packet needs to pass this check `while ( updateType < Finished )` and then there is also a check for the update type which is calculated using this function:

```

inline static UpdateType DetermineUpdateType( CEntityReadInfo &u, int oldEntity )
{
	if ( !u.m_bIsEntity || ( u.m_nNewEntity > oldEntity ) )
	{
		// If we're at the last entity, preserve whatever entities followed it in the old packet.
		// If newnum > oldnum, then the server skipped sending entities that it wants to leave the state alone for.
		if ( !u.m_pFrom	 || ( oldEntity > u.m_pFrom->last_entity ) )
		{
			return Finished;
		}

		// Preserve entities until we reach newnum (ie: the server didn't send certain entities because
		// they haven't changed).
	}
	else
	{
		if( u.m_UpdateFlags & FHDR_ENTERPVS )
		{
			return EnterPVS;
		}
		else if( u.m_UpdateFlags & FHDR_LEAVEPVS )
		{
			return LeavePVS;
		}
		return DeltaEnt;
	}

	return PreserveEnt;
}



```

This could be a reason for poor coverage in our fuzzer. If we look at the `( !u.m_bIsEntity || ( u.m_nNewEntity > oldEntity ) )` and look where oldEntity gets updated...

After looking at some debug messages it seems that we do not even reach the ReadPacketEntities function. That is quite odd. Let's look at the calling function.

After adding a couple of debug messages, I now get this message:

`m_nDeltaTick == -1 . Returning straight away!` so we are actually failing in this part:

```

bool CClientState::SVCMsg_PacketEntities( const CSVCMsg_PacketEntities &msg )
{
	CL_PreprocessEntities(); // setup client prediction

	if ( !msg.is_delta() )
	{
		// Delta too old or is initial message
		// we can start recording now that we've received an uncompressed packet
		demorecorder->SetSignonState( SIGNONSTATE_FULL );

		// Tell prediction that we're recreating entities due to an uncompressed packet arriving
		if ( g_pClientSidePrediction  )
		{
			g_pClientSidePrediction->OnReceivedUncompressedPacket();
		}
	}
	else
	{
		if ( m_nDeltaTick == -1  )
		{
			// we requested a full update but still got a delta compressed packet. ignore it.
			write_debug3("m_nDeltaTick == -1 . Returning straight away!\n");
			return true;
		}
	}

```

The reason why the msg.is_delta thing always goes to the else case is that in the custom mutator, we don't even mutate the CSVCMsg_PacketEntities type of message. So the reason why our code coverage sucks is that because our mutator sucks! :D .

## Improving the mutator.

Ok, so let's add a special case for the CSVCMsg_PacketEntities case:

```

	'''
	message CSVCMsg_PacketEntities
	{
		optional int32 max_entries = 1;
		optional int32 updated_entries = 2;
		optional bool is_delta = 3;	
		optional bool update_baseline = 4;
		optional int32 baseline = 5;
		optional int32 delta_from = 6;
		optional bytes entity_data = 7;
	}
	'''

	if msg_type == "CSVCMsg_PacketEntities":
		msg, thing = stuff_thing(msg, field, [["max_entries", "int"],["updated_entries", "int"], ["is_delta", "bool"], ["update_baseline", "bool"], ["baseline", "int"],["delta_from", "int"], ["entity_data", "bytes"]])


```

After adding this special case to our packet fuzzer we should now get better coverage and we should actually find some crashes. :)

For some reason I am not getting better coverage even after the changes. I think I have to debug the mutator and see what it is doing.

-----------------------

## Increasing the timeout.

As it turns out, when the is_delta thing is false, then we go into this loop here:

```

		for ( int i=0; i <= entitylist->GetHighestEntityIndex(); i++ )
		{
			write_debug2("inside the for loop thing with deletedllentity stuff\n");
			CL_DeleteDLLEntity( i, "ProcessPacketEntities", true );
			write_debug2("after CL_DeleteDLLEntity\n");
		}

```

and that loop takes a long while to complete, so we need to increase the timeout when fuzzing this specific type of packet.

Maybe three seconds? No, it still times out. That for loop is really screwing us over. (Maybe thirty seconds?) No, ok so that loop is just a pain in the ass. Trying to delete all of the dll entities takes a lot of time

Look: `Here is entitylist->GetHighestEntityIndex(): 4294967295` ok so we are not going to go over all of the entities, because reasons.

Let's just comment out the for loop and see what happens?

In the mean time let's explore other possible exploitation routes. The source engine enables transfer of files with NETMsg_File. This 


```


bool CNetChan::NETMsg_File( const CNETMsg_File& msg )
{
	const char *string = msg.file_name().c_str();

	if ( !msg.deny() && IsValidFileForTransfer( string ) )
	{
		m_MessageHandler->FileRequested( string, msg.transfer_id(), msg.is_replay_demo_file() );
	}
	else
	{
		m_MessageHandler->FileDenied( string, msg.transfer_id(), msg.is_replay_demo_file() );
	}

	return true;
}


```

The IsValidFileForTransfer is a function which checks that the request doesn't try to read any of the players personal files etc etc.. So maybe there is something which the devs overlooked there?

```

bool CNetChan::IsValidFileForTransfer( const char *pszFilename )
{
	if ( !pszFilename || !pszFilename[0] )
		return false;

	// No absolute paths or weaseling up the tree with ".." allowed.
	if ( !COM_IsValidPath( pszFilename ) || V_IsAbsolutePath( pszFilename ) )
		return false;

	char szTemp[MAX_PATH];
	int l = V_strlen( pszFilename );
	if ( l >= sizeof(szTemp) )
		return false;
	V_strcpy_safe( szTemp, pszFilename );
	V_FixSlashes( szTemp, '/' );
	if ( szTemp[l-1] == '/' )
		return false;

	if (
		V_stristr( pszFilename, "lua/" )
		|| V_stristr( pszFilename, "gamemodes/" )
		|| V_stristr( pszFilename, "scripts/" )
		|| V_stristr( pszFilename, "addons/" )
		|| V_stristr( pszFilename, "cfg/" )
		|| V_stristr( pszFilename, "~/" )
		|| V_stristr( pszFilename, "gamemodes.txt" )
		)
		return false;

	// Allow only bsp and nav file transfers to not overwrite any assets in maps directory
	if ( V_stristr( pszFilename, "maps/" ) &&
		!V_stristr( pszFilename, ".bsp" ) &&
		!V_stristr( pszFilename, ".ain" ) &&
		!V_stristr( pszFilename, ".nav" ) )
		return false;

	const char *extension = V_strrchr( pszFilename, '.' );
	if ( !extension )
		return false;

	int baseLen = V_strlen( extension );
	if ( baseLen > 4 || baseLen < 3 )
		return false;

	// are there any spaces in the extension? (windows exploit)
	const char *pChar = extension;
	while ( *pChar )
	{
		if ( V_isspace( *pChar ) )
		{
			return false;
		}

		++pChar;
	}

	if ( !Q_strcasecmp( extension, ".cfg" ) ||
		!Q_strcasecmp( extension, ".lst" ) ||
		!Q_strcasecmp( extension, ".lmp" ) ||
		!Q_strcasecmp( extension, ".exe" ) ||
		!Q_strcasecmp( extension, ".vbs" ) ||
		!Q_strcasecmp( extension, ".com" ) ||
		!Q_strcasecmp( extension, ".bat" ) ||
		!Q_strcasecmp( extension, ".dll" ) ||
		!Q_strcasecmp( extension, ".ini" ) ||
		!Q_strcasecmp( extension, ".log" ) ||
		!Q_strcasecmp( extension, ".lua" ) ||
		!Q_strcasecmp( extension, ".nut" ) ||
		!Q_strcasecmp( extension, ".vdf" ) ||
		!Q_strcasecmp( extension, ".smx" ) ||
		!Q_strcasecmp( extension, ".gcf" ) ||
		!Q_strcasecmp( extension, ".sys" ) )
	{
		return false;
	}

	return true;
}


```

and here is COM_IsValidPath: 

```

bool COM_IsValidPath( const char *pszFilename )
{
	if ( !pszFilename )
	{
		return false;
	}

	if ( Q_strlen( pszFilename ) <= 0    ||
		Q_strstr( pszFilename, "\\\\" ) ||	// to protect network paths
		Q_strstr( pszFilename, ":" )    || // to protect absolute paths
		Q_strstr( pszFilename, ".." ) ||   // to protect relative paths
		Q_strstr( pszFilename, "\n" ) ||   // CFileSystem_Stdio::FS_fopen doesn't allow this
		Q_strstr( pszFilename, "\r" ) )    // CFileSystem_Stdio::FS_fopen doesn't allow this
	{
		return false;
	}

	return true;
}

```

So we need to figure out a way to get COM_IsValidPath to return true even though the path itself is an absolute path.

and here is the absolute path check:

```

bool V_IsAbsolutePath( const char *pStr )
{
	if ( !( pStr[0] && pStr[1] ) )
		return false;
	
#if defined( PLATFORM_WINDOWS )
	bool bIsAbsolute = ( pStr[0] && pStr[1] == ':' ) || 
	  ( ( pStr[0] == '/' || pStr[0] == '\\' ) && ( pStr[1] == '/' || pStr[1] == '\\' ) );
#else
	bool bIsAbsolute = ( pStr[0] && pStr[1] == ':' ) || pStr[0] == '/' || pStr[0] == '\\';
#endif

	if ( IsX360() && !bIsAbsolute )
	{
		bIsAbsolute = ( V_stristr( pStr, ":" ) != NULL );
	}
	
	return bIsAbsolute;
}


```

While browsing, I discovered this: https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats

and there is a quote: "All forward slashes (/) are converted into the standard Windows separator, the back slash (\\). If they are present, a series of slashes that follow the first two slashes are collapsed into a single slash."

Now, I think we need to learn about how the game actually internally loads the files.

```

bool CNetChan::SendFile(const char *filename, unsigned int transferID, bool bIsReplayDemoFile )
{
	// add file to waiting list
	if ( IsNull() )
		return true;

	if ( !filename )
		return false;

	const char *sendfile = filename;
	while( sendfile[0] && PATHSEPARATOR( sendfile[0] ) )
	{
		sendfile = sendfile + 1;
	}

	// Don't transfer exe, vbs, com, bat-type files.
	if ( !IsValidFileForTransfer( sendfile ) )
		return false;

	if ( !CreateFragmentsFromFile( sendfile, FRAG_FILE_STREAM, transferID, bIsReplayDemoFile ) )
	{
		DenyFile( sendfile, transferID, bIsReplayDemoFile ); // send host a deny message
		return false;
	}

	if ( net_showfragments.GetInt() == 2 )
	{
		DevMsg("SendFile: %s (ID %i)\n", sendfile, transferID );
	}

	return true;
}

```


So there is the `while( sendfile[0] && PATHSEPARATOR( sendfile[0] ) )` thing which seems a bit sus. That probably messes our exploit attempt, but I am going to try anyways.

Here is the definition of PATHSEPARATOR: `#define PATHSEPARATOR(c) ((c) == '\\' || (c) == '/')` (inside strtools.cpp). This means that even if we somehow get an absolute path here, we still get screwed over by this.

Notice that there is this line `Q_strstr( pszFilename, "\\\\" ) ||	// to protect network paths` . If the paths with "/" in the get replaced by "\", then we can put "//.\" and it would first get converted to `\\.\` and this is a network drive. But then the `( ( pStr[0] == '/' || pStr[0] == '\\' ) && ( pStr[1] == '/' || pStr[1] == '\\' ) );` line screws us over. Maybe trying to exfiltrate files isn't a useful tactic. Maybe instead we should explore other areas.


I found this quick writeup: https://neodyme.io/de/blog/csgo_from_zero_to_0day/ and it abuses some bad logic which enables the upload of a binary file which is then executed by the client.

Let's just keep exploring the entity parsing code to see if it has some interesting parts.

There is this piece of code:

```

void CL_PreserveExistingEntity( int nOldEntity )
{
	IClientNetworkable *pEnt = entitylist->GetClientNetworkable( nOldEntity );
	if ( !pEnt )
	{
		Host_Error( "CL_PreserveExistingEntity: missing client entity %d.\n", nOldEntity );
		return;
	}

	pEnt->OnDataUnchangedInPVS();
}


```

Which seeoms quite odd. Looking at the code there is absolutely no references to this function, so this may be a dead end. See, this blog post: https://ctf.re/source-engine/exploitation/2021/05/01/source-engine-2/ describes an exploit which uses the CL_CopyExistingEntity function because it takes an attacker controlled index, which is then used to access an OOB memory address and then a method is called on that address, which basically means RIP control.

One way we could probably find bugs is to look at the fixes for previous bugs and see if they are actually sufficient in fixing the bug. There are many cases, where the fix for a bug turned out to be an invalid fix and did not account for all exploitation scenarios. Looking at the decompiled version of the newest version of csgo, it looks like there are no references to CL_PreserveExistingEntity . This sucks.


Let's investigate the fix for the CL_CopyExistingEntity bug...

Here is the decompiled version (thanks ghidra)...


```

void FUN_003b01c0(long param_1)

{
  uint *puVar1;
  undefined8 uVar2;
  char cVar3;
  int iVar4;
  uint uVar5;
  long *plVar6;
  long *plVar7;
  long lVar8;
  undefined8 uVar9;
  long lVar10;
  undefined4 uVar11;
  long lVar12;
  undefined4 uVar13;
  undefined *puVar14;
  int iVar15;
  
  lVar8 = *(long *)(param_1 + 0x38);
  if (*(long *)(lVar8 + 0x30) == 0) {
    iVar15 = 0;
  }
  else {
    lVar12 = *(long *)(lVar8 + 0x20) - *(long *)(lVar8 + 0x30);
    lVar10 = lVar12 + 3;
    if (-1 < lVar12) {
      lVar10 = lVar12;
    }
    iVar15 = ((int)(lVar10 >> 2) * 0x20 - *(int *)(lVar8 + 0x1c)) +
             (*(uint *)(lVar8 + 0x10) & 3) * 8;
    if (*(int *)(lVar8 + 0xc) < iVar15) {
      iVar15 = *(int *)(lVar8 + 0xc);
    }
  }
  plVar6 = (long *)(**(code **)*DAT_00f11118)(DAT_00f11118,*(undefined4 *)(param_1 + 0x1c)); // IClientNetworkable *pEnt = entitylist->GetClientNetworkable( u.m_nNewEntity );
  if (plVar6 == (long *)0x0) { // !pEnt
    uVar13 = *(undefined4 *)(param_1 + 0x1c);
    puVar14 = &DAT_00a419e8;
  }

```

This fix doesn't really make sense, because this block here:

```

  lVar8 = *(long *)(param_1 + 0x38);
  if (*(long *)(lVar8 + 0x30) == 0) {
    iVar15 = 0;
  }
  else {
    lVar12 = *(long *)(lVar8 + 0x20) - *(long *)(lVar8 + 0x30);
    lVar10 = lVar12 + 3;
    if (-1 < lVar12) {
      lVar10 = lVar12;
    }
    iVar15 = ((int)(lVar10 >> 2) * 0x20 - *(int *)(lVar8 + 0x1c)) +
             (*(uint *)(lVar8 + 0x10) & 3) * 8;
    if (*(int *)(lVar8 + 0xc) < iVar15) {
      iVar15 = *(int *)(lVar8 + 0xc);
    }
  }

```

is somehow supposed to prevent exploitation? That is quite odd. That means that this vulnerability may exist in the game still. I am going to just assume that it got fixed and focus somewhere else first.

In very complex game engines, there are usually plenty of third party applications in use which we can also fuzz. Here: https://secret.club/2021/04/20/source-engine-rce-invite.html the exploiters abused a bug in XZip . 

Here is the comment at the top of XZip.cpp :

```
//========= Copyright 1996-2005, Valve Corporation, All rights reserved. ============//
//
// Purpose: 
//
// $NoKeywords: $
//
//=============================================================================//
// XZip.cpp  Version 1.1
//
// Authors:      Mark Adler et al. (see below)
//
// Modified by:  Lucian Wischik
//               lu@wischik.com
//
// Version 1.0   - Turned C files into just a single CPP file
//               - Made them compile cleanly as C++ files
//               - Gave them simpler APIs
//               - Added the ability to zip/unzip directly in memory without 
//                 any intermediate files
// 
// Modified by:  Hans Dietrich
//               hdietrich2@hotmail.com
//
// Version 1.1:  - Added Unicode support to CreateZip() and ZipAdd()
//               - Changed file names to avoid conflicts with Lucian's files
//
///////////////////////////////////////////////////////////////////////////////
//
// Lucian Wischik's comments:
// --------------------------
// THIS FILE is almost entirely based upon code by Info-ZIP.
// It has been modified by Lucian Wischik.
// The original code may be found at http://www.info-zip.org
// The original copyright text follows.
//
///////////////////////////////////////////////////////////////////////////////
//
// Original authors' comments:
// ---------------------------
// This is version 2002-Feb-16 of the Info-ZIP copyright and license. The 
// definitive version of this document should be available at 
// ftp://ftp.info-zip.org/pub/infozip/license.html indefinitely.
// 
// Copyright (c) 1990-2002 Info-ZIP.  All rights reserved.
//
// For the purposes of this copyright and license, "Info-ZIP" is defined as
// the following set of individuals:
//
//   Mark Adler, John Bush, Karl Davis, Harald Denker, Jean-Michel Dubois,
//   Jean-loup Gailly, Hunter Goatley, Ian Gorman, Chris Herborth, Dirk Haase,
//   Greg Hartwig, Robert Heath, Jonathan Hudson, Paul Kienitz, 
//   David Kirschbaum, Johnny Lee, Onno van der Linden, Igor Mandrichenko, 
//   Steve P. Miller, Sergio Monesi, Keith Owens, George Petrov, Greg Roelofs, 
//   Kai Uwe Rommel, Steve Salisbury, Dave Smith, Christian Spieler, 
//   Antoine Verheijen, Paul von Behren, Rich Wales, Mike White
//
// This software is provided "as is", without warranty of any kind, express
// or implied.  In no event shall Info-ZIP or its contributors be held liable
// for any direct, indirect, incidental, special or consequential damages
// arising out of the use of or inability to use this software.
//
// Permission is granted to anyone to use this software for any purpose,
// including commercial applications, and to alter it and redistribute it
// freely, subject to the following restrictions:
//
//    1. Redistributions of source code must retain the above copyright notice,
//       definition, disclaimer, and this list of conditions.
//
//    2. Redistributions in binary form (compiled executables) must reproduce 
//       the above copyright notice, definition, disclaimer, and this list of 
//       conditions in documentation and/or other materials provided with the 
//       distribution. The sole exception to this condition is redistribution 
//       of a standard UnZipSFX binary as part of a self-extracting archive; 
//       that is permitted without inclusion of this license, as long as the 
//       normal UnZipSFX banner has not been removed from the binary or disabled.
//
//    3. Altered versions--including, but not limited to, ports to new 
//       operating systems, existing ports with new graphical interfaces, and 
//       dynamic, shared, or static library versions--must be plainly marked 
//       as such and must not be misrepresented as being the original source.  
//       Such altered versions also must not be misrepresented as being 
//       Info-ZIP releases--including, but not limited to, labeling of the 
//       altered versions with the names "Info-ZIP" (or any variation thereof, 
//       including, but not limited to, different capitalizations), 
//       "Pocket UnZip", "WiZ" or "MacZip" without the explicit permission of 
//       Info-ZIP.  Such altered versions are further prohibited from 
//       misrepresentative use of the Zip-Bugs or Info-ZIP e-mail addresses or 
//       of the Info-ZIP URL(s).
//
//    4. Info-ZIP retains the right to use the names "Info-ZIP", "Zip", "UnZip",
//       "UnZipSFX", "WiZ", "Pocket UnZip", "Pocket Zip", and "MacZip" for its 
//       own source and binary releases.
//
///////////////////////////////////////////////////////////////////////////////
```

So the version is 1.1 for xunzip. There are also plenty of other third party libraries which have outdated versions, which could have exploits for them.

Looking at the newest version of csgo, it doesn't seem to have the screenshot functionality which is being mentioned in the writeup. Maybe the XZip is called somewhere else?

Yeah, the removed pretty much every reference to XZip from the code. Even if it get's called, it most likely gets called with data which we do not control easily, thus making exploitation hard. Instead there are plenty of references to SafeUncompress in lzss.cpp (for example there are plenty of references to SafeUncompress in net_ws.cpp for example so if we find a bug inside SafeUncompress, then we could exploit it).

One very nice thing is that lzss.cpp doesn't have that many external dependies, that means that we can basically just copy it to another file and it should compile without that many errors.

The lzss decompression is pretty much only used in net_ws.cpp in the decompression of network packets. Instead of just allocating a local memory area, they use some CUtlMemory stuff:

```


				MEM_ALLOC_CREDIT();
				CUtlMemoryFixedGrowable< byte, NET_COMPRESSION_STACKBUF_SIZE > memDecompressed( NET_COMPRESSION_STACKBUF_SIZE );
				memDecompressed.EnsureCapacity( actualSize );

				unsigned int uDecompressedSize = lzss.SafeUncompress( pCompressedData, memDecompressed.Base(), actualSize );
				if ( uDecompressedSize == 0 || ((unsigned int)actualSize) != uDecompressedSize )
				{
					return false;
				}

```

This isn't even that easy to exploit, even if we find a vuln in SafeUncompress. Let's keep looking.



























