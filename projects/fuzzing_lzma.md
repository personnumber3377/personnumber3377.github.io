
## Fuzzing lzma-sdk

Hi!

When fuzzing csgo, I encountered an lzma decoder in the counter strike source code. As it turns out it is a third party library which is ripped straight from the lzma-sdk software package.

The version of lzma which csgo uses is an old version of lzma-sdk From 2005! There is this code comment:

```
//========= Copyright © 1996-2007, Valve Corporation, All rights reserved. ============//
//
//	LZMA Codec.
//
//	LZMA SDK 4.43 Copyright (c) 1999-2006 Igor Pavlov (2006-05-01)
//	http://www.7-zip.org/
//
//=====================================================================================//
```

In the file lzmaDecoder.cpp . Just following the instructions provided you can easily compile the lzma binary.

So lets compile it with afl-g++-lto

Make modifications to the makefile:

Original:

```
PROG = lzma
CXX = g++ -O2 -Wall
CXX_C = gcc -O2 -Wall
LIB = -lm
RM = rm -f
CFLAGS = -c -I ../../../

```

new:

```
PROG = lzma
#CXX = g++ -O2 -Wall
#CXX_C = gcc -O2 -Wall

CXX = /home/cyberhacker/Asioita/newaflfuzz/AFLplusplus/afl-clang-lto++ -O2 -Wall
CXX_C = /home/cyberhacker/Asioita/newaflfuzz/AFLplusplus/afl-clang-lto -O2 -Wall

LIB = -lm
RM = rm -f
CFLAGS = -c -I ../../../

```






























