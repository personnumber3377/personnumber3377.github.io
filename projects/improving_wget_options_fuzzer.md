
# Improving the wget options fuzzer

Ok, so I actually fuzzed the wget command line stuff and as it turns out, the fuzzer doesn't work properly, because reasons. I actually reported a couple of bugs to a maintainer (Tim Ruhsen)

The time of writing this: Sun May 12 08:33:35 AM EEST 2024

After a couple of emails, he sent me this:

```

Hey :)

It's really appreciated if you spend some time on finding and fixing
those issues. My time actually is very limited, it reduces to 1-2 hours
on weekends.

I try to collect things from the tip of my mind that might be
interesting to you...

Our main collaboration space is on Gitlab.com
(https://gitlab.com/gnuwget/wget).

Last weekend, I looked into the fuzzer and amended it to work with `make
check` and `make check-valgrind`. With the latter I found and fixed a
bunch of issues, which you can find in branch
`rockdaboot-fix-options-fuzzer`. But the work needs to be finished...
maybe you can work on top of it?

The next step would be to fix the fuzzer itself, plus some local fuzzing
to find the most important bugs (something you started working on,
great). After that (or immediately), let's push the fix to master, so
that OSS-Fuzz can pick it up.

Wget fuzzer are on OSS-Fuzz, so you can clone or fork
https://github.com/google/oss-fuzz. In projects/wget you'll find the
details how to build the fuzzers. We currently have a build issue on
OSS-Fuzz - but that is due to
https://github.com/google/oss-fuzz/issues/11698 (need to fix that as well).

Building and running the fuzzer... please try with "Running the fuzzer
with clang". The AFL isn't tested since years, so may be broken atm
(feel free to fix the instructions, but that is low priority for me).

Regards, Tim

```

So I decided to give it a crack.

## Initial investigation

Let's just get a handle on the codebase and see what kind of infrastructure they have set up and see what we can do. Let's git clone the source code and checkout the rockdaboot-fix-options-fuzzer branch...

When I tried to follow these instructions here (the clang instructions): https://gitlab.com/gnuwget/wget/-/tree/master/fuzz?ref_type=heads#running-a-fuzzer-using-clang  . I got a linker error when the linker tried to find a "main" function when we are actually linking libfuzzer instead. These instructions has this line in them: `export LIB_FUZZING_ENGINE="-lFuzzer  -lstdc++"` the "Fuzzer" library is only found in oss-fuzz, because that is the fuzzer binary which the fuzzers get linked with. It doesn't usually exist on regular machines, so let's take it out. In addition, the instructions have the `-fsanitize=fuzzer-no-link` flag, but because we do not have the "Fuzzer" library, we want to use just `-fsanitize=fuzzer` instead.

Even with this as my configuration script:

```
#!/bin/sh

export CC=clang
export CFLAGS="-O3 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=undefined -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer"
export LIB_FUZZING_ENGINE=""
./configure --enable-fuzzing --without-metalink --without-zlib --disable-pcre --without-libuuid --enable-assert
make clean-recursive
make -j$(nproc)

```

the `-lFuzzer -lstdc++` flags still get added to the fuzz/Makefile file!??!?!?! That is quite odd.

However, if I try to run these commands:

```

export LIB_FUZZING_ENGINE=""
CC=afl-clang-fast ./configure --enable-fuzzing
make -j$(nproc) clean all

```

then we get the error that main is not found (this is because the program tries to link the fuzzer binaries without libfuzzer)????!!??!?

Grepping for `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` it only reveals that that variable is only used in a couple of bash scripts and nowhere else, so it can't be that.

Now after compiling with afl-clang-fast, then when I ran this:

```

#!/bin/sh

export CC=clang
export CFLAGS="-O3 -fno-omit-frame-pointer -gline-tables-only -fsanitize=undefined -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer"
export LIB_FUZZING_ENGINE=""
#./configure --enable-fuzzing --without-metalink --without-zlib --disable-pcre --without-libuuid --enable-assert

CC=clang ./configure --enable-fuzzing

make -j$(nproc) clean all


```

it tries to compile with afl-clang-fast again??? So therefore there is something leftover from the previous run, which fucks up our new configuration...

I tried to compile with these commands:

```

#!/bin/sh

export CC=clang
export CFLAGS="-O3 -fno-omit-frame-pointer -gline-tables-only -fsanitize=undefined -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link"
export LIB_FUZZING_ENGINE=""
#./configure --enable-fuzzing --without-metalink --without-zlib --disable-pcre --without-libuuid --enable-assert

./configure --enable-fuzzing

make -j$(nproc) clean all

#make clean-recursive
#make -j$(nproc)



```


and now I get this as a result:

```

../lib/stdio.h:1030:12: note: previous definition is here
#   define fopen rpl_fopen
           ^
In file included from url.c:31:
./wget.h:325:11: warning: 'fopen' macro redefined [-Wmacro-redefined]
#  define fopen(fp, mode) fopen_wget(fp, mode)
          ^
../lib/stdio.h:1030:12: note: previous definition is here
#   define fopen rpl_fopen
           ^
In file included from warc.c:44:
../lib/base32.h:58:13: warning: result of comparison of constant 256 with expression of type 'unsigned char' is always true [-Wtautological-constant-out-of-range-compare]
  return ch < sizeof base32_to_int && 0 <= base32_to_int[ch];
         ~~ ^ ~~~~~~~~~~~~~~~~~~~~
1 warning generated.
  CC       libunittest_a-utils.o
In file included from utils.c:31:
./wget.h:325:11: warning: 'fopen' macro redefined [-Wmacro-redefined]
#  define fopen(fp, mode) fopen_wget(fp, mode)
          ^
../lib/stdio.h:1030:12: note: previous definition is here
#   define fopen rpl_fopen
           ^
utils.c:133:1: warning: function declared 'noreturn' should not return [-Winvalid-noreturn]
}
^
1 warning generated.
  CC       libunittest_a-exits.o
In file included from exits.c:21:
./wget.h:325:11: warning: 'fopen' macro redefined [-Wmacro-redefined]
#  define fopen(fp, mode) fopen_wget(fp, mode)
          ^
../lib/stdio.h:1030:12: note: previous definition is here
#   define fopen rpl_fopen
           ^
1 warning generated.
  CC       libunittest_a-build_info.o
1 warning generated.
In file included from build_info.c:9:
./wget.h:325:11: warning: 'fopen' macro redefined [-Wmacro-redefined]
#  define fopen(fp, mode) fopen_wget(fp, mode)
          ^
../lib/stdio.h:1030:12: note: previous definition is here
#   define fopen rpl_fopen
           ^
  CC       libunittest_a-iri.o
1 warning generated.
  CC       libunittest_a-xattr.o
1 warning generated.
  CC       libunittest_a-ftp-opie.o
In file included from iri.c:31:
./wget.h:325:11: warning: 'fopen' macro redefined [-Wmacro-redefined]
#  define fopen(fp, mode) fopen_wget(fp, mode)
          ^
../lib/stdio.h:1030:12: note: previous definition is here
#   define fopen rpl_fopen
           ^
In file included from xattr.c:18:
./wget.h:325:11: warning: 'fopen' macro redefined [-Wmacro-redefined]
#  define fopen(fp, mode) fopen_wget(fp, mode)
          ^
../lib/stdio.h:1030:12: note: previous definition is here
#   define fopen rpl_fopen
           ^
2 warnings generated.
In file included from ftp-opie.c:31:
./wget.h:325:11: warning: 'fopen' macro redefined [-Wmacro-redefined]
#  define fopen(fp, mode) fopen_wget(fp, mode)
          ^
../lib/stdio.h:1030:12: note: previous definition is here
#   define fopen rpl_fopen
           ^
1 warning generated.
  CC       libunittest_a-http-ntlm.o
  CC       libunittest_a-gnutls.o
In file included from http-ntlm.c:32:
./wget.h:325:11: warning: 'fopen' macro redefined [-Wmacro-redefined]
#  define fopen(fp, mode) fopen_wget(fp, mode)
          ^
../lib/stdio.h:1030:12: note: previous definition is here
#   define fopen rpl_fopen
           ^
In file included from gnutls.c:31:
./wget.h:325:11: warning: 'fopen' macro redefined [-Wmacro-redefined]
#  define fopen(fp, mode) fopen_wget(fp, mode)
          ^
../lib/stdio.h:1030:12: note: previous definition is here
#   define fopen rpl_fopen
           ^
1 warning generated.
2 warnings generated.
1 warning generated.
1 warning generated.
1 warning generated.
1 warning generated.
2 warnings generated.
1 warning generated.
  AR       libunittest.a
make[3]: Leaving directory '/home/cyberhacker/Asioita/Hakkerointi/wget/src'
  CCLD     wget_cookie_fuzzer
  CCLD     wget_css_fuzzer
  CCLD     wget_ftpls_fuzzer
  CCLD     wget_html_fuzzer
  CCLD     wget_netrc_fuzzer
  CCLD     wget_options_fuzzer
  CCLD     wget_progress_fuzzer
  CCLD     wget_read_hunk_fuzzer
/usr/bin/ld: /lib/x86_64-linux-gnu/Scrt1.o: in function `_start':
(.text+0x1b): undefined reference to `main'
/usr/bin/ld/usr/bin/ld: /lib/x86_64-linux-gnu/Scrt1.o: in function `_start':
(.text+0x1b): undefined reference to `: /lib/x86_64-linux-gnu/Scrt1.omain'
/usr/bin/ld: /lib/x86_64-linux-gnu/Scrt1.o: in function `_start':
(.text+0x1b): undefined reference to `main'
: in function `_start':
(.text+0x1b): undefined reference to `main'
/usr/bin/ld: /lib/x86_64-linux-gnu/Scrt1.o: in function `_start':
(.text+0x1b): undefined reference to `main'
/usr/bin/ld: /lib/x86_64-linux-gnu/Scrt1.o: in function `_start':
(.text+0x1b): undefined reference to `main'
/usr/bin/ld: /lib/x86_64-linux-gnu/Scrt1.o: in function `_start':
(.text+0x1b): undefined reference to `main'
/usr/bin/ld: /lib/x86_64-linux-gnu/Scrt1.o: in function `_start':
(.text+0x1b): undefined reference to `main'
clang: error: linker command failed with exit code 1 (use -v to see invocation)
make[2]: *** [Makefile:2315: wget_cookie_fuzzer] Error 1
make[2]: *** Waiting for unfinished jobs....
clang: error: linker command failed with exit code 1 (use -v to see invocation)
make[2]: *** [Makefile:2323: wget_ftpls_fuzzer] Error 1
clang: error: linker command failed with exit code 1 (use -v to see invocation)
make[2]: *** [Makefile:2339: wget_options_fuzzer] Error 1
clang: error: linker command failed with exit code 1 (use -v to see invocation)
make[2]: *** [Makefile:2327: wget_html_fuzzer] Error 1
clang: error: linker command failed with exit code 1 (use -v to see invocation)
clang: error: linker command failed with exit code 1 (use -v to see invocation)
make[2]: *** [Makefile:2347: wget_read_hunk_fuzzer] Error 1
make[2]: *** [Makefile:2343: wget_progress_fuzzer] Error 1
clang: error: linker command failed with exit code 1 (use -v to see invocation)
make[2]: *** [Makefile:2319: wget_css_fuzzer] Error 1
clang: error: linker command failed with exit code 1 (use -v to see invocation)
make[2]: *** [Makefile:2331: wget_netrc_fuzzer] Error 1
make[2]: Leaving directory '/home/cyberhacker/Asioita/Hakkerointi/wget/fuzz'
make[1]: *** [Makefile:2019: all-recursive] Error 1
make[1]: Leaving directory '/home/cyberhacker/Asioita/Hakkerointi/wget'
make: *** [Makefile:1971: all] Error 2


```

this is good, because it means that we are on the right track atleast somewhat.

After modifying the link parameters in the fuzz/Makefile file here:

```
CFLAGS =    -I/usr/include/p11-kit-1 -DHAVE_LIBGNUTLS  -DNDEBUG -O3 -fno-omit-frame-pointer -gline-tables-only -fsanitize=undefined -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer #-fsanitize=fuzzer-no-link
```

(i changed `-fsanitize=fuzzer-no-link` to just `-fsanitize=fuzzer`)

and now it compiles the fuzzing binaries correctly.

## Why didn't it find the crash???

Previously I fuzzed the command line parameters, but the libfuzzer binaries didn't really seem to catch these bugs for some odd reason, now I think it is time to investigate why it didn't find it.

Try debugging with gdb first and see if the vulnerable function get's called???

I can't really tell you where the bug is, because it is yet to be disclosed to the public (it is not fixed yet) . 

Ok, so let's modify the source code, such that we can compile the fuzzer in the regular way (aka let's fix the Makefile.am in the fuzz directory).

After a bit of fiddling around, it looks like we do not even need to modify the Makefile.am file or anything, I just need to modify the parameters which we are compiling with:

```

export CC=clang
# address sanitizer:
#export CFLAGS="-O1 -g -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=undefined,integer,nullability -fsanitize=address -fsanitize-address-use-after-scope -fsanitize-coverage=trace-pc-guard,trace-cmp"
export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=undefined -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link"
# undefined sanitizer;
#export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=bool,array-bounds,float-divide-by-zero,function,integer-divide-by-zero,return,shift,signed-integer-overflow,vla-bound,vptr -fno-sanitize-recover=bool,array-bounds,float-divide-by-zero,function,integer-divide-by-zero,return,shift,signed-integer-overflow,vla-bound,vptr -fsanitize=fuzzer-no-link"
# export LIB_FUZZING_ENGINE=""

export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"

./configure --enable-fuzzing --without-metalink --without-zlib --disable-pcre --without-libuuid --enable-assert
#make clean
#make -j$(nproc)


```

that seems to compile the fuzzers all fine... and then if I seed the options fuzzer with a file which is close to a crashing input, then it finds the crash pretty quick.

## Making the fuzzer ignore memory leaks

Ok, so the fuzzing script (run-clang.sh) doesn't ignore memory leaks by default, so let's add command line options to ignore them. (Otherwise we will exit almost immediately, because there are some inconsequential memory leaks.)

Ok, so I forked the newer version of wget (wget2) here on github: https://gitlab.com/personnumber3377/wget2/-/commit/8a8ffc331f88e053ce1d0f7e8bb707e836115df9 and I made a couple of changes. I fixed some of the instructions such that now you can build the fuzzer locally without oss-fuzz.

Now that we have the fuzzer compiling fine on a local machine, let's investigate why the oss-fuzz build fails.

## Fixing the oss-fuzz build.

First of all I forked oss-fuzz to here: https://github.com/personnumber3377/oss-fuzz which has the fixes, such that we can build the fuzzers from the source code instead of the other stuff...

I remember that I had some trouble with the gnutls package and that is why it didn't compile properly. I found this: https://stackoverflow.com/questions/52722096/build-emacs-and-gnutls-not-found which basically said to just use this command: `sudo apt install libgnutls28-dev`

, but the Dockerfile has this command here:

`RUN git clone --depth=1 https://gitlab.com/gnutls/gnutls.git`

which seems to signify, that we want to build it from source???????!?!?!?!?!?!!?

I don't really understand, let's just try to compile the oss-fuzz fuzzer without any special modifications and see what it spits out...

Let's look up the documentation and usage of oss-fuzz from here: https://google.github.io/oss-fuzz/

This seems something we want: https://google.github.io/oss-fuzz/getting-started/new-project-guide/#testing-locally

Soooo just run these commands????

```
python infra/helper.py build_image wget
python infra/helper.py build_fuzzers --sanitizer address wget
```

and we should be good???

While those commands are running, I am going to go over some potential solutions...

First of all, we should use the `Find failures to fix by running the check_build command:` command aka:

```
python infra/helper.py check_build wget
```

but then if those fail, then another solution would be to just use the binary package version of gnutls instead of the compiled from source version. (aka just add `libgnutls28-dev` to the dockerfile packages instead of using the from source one.).

I noticed this in the log:

```

Step 8/13 : RUN git clone --depth=1 --recursive https://github.com/rockdaboot/libpsl.git
 ---> Running in 4bc10e16a219
Cloning into 'libpsl'...
fatal: unable to access 'https://github.com/rockdaboot/libpsl.git/': gnutls_handshake() failed: The TLS connection was non-properly terminated.
The command '/bin/sh -c git clone --depth=1 --recursive https://github.com/rockdaboot/libpsl.git' returned a non-zero code: 128
ERROR:__main__:Docker build failed.
INFO:__main__:Running: docker build -t gcr.io/oss-fu

```

If I try to git clone it locally on my own machine it works fine:

```
cyberhacker@cyberhacker-h8-1131sc:~/Asioita/Hakkerointi/fixwget$ git clone https://github.com/rockdaboot/libpsl.git
Cloning into 'libpsl'...
remote: Enumerating objects: 5102, done.
remote: Counting objects: 100% (602/602), done.
remote: Compressing objects: 100% (246/246), done.
remote: Total 5102 (delta 295), reused 545 (delta 275), pack-reused 4500
Receiving objects: 100% (5102/5102), 5.31 MiB | 1.38 MiB/s, done.
Resolving deltas: 100% (2590/2590), done.

```

so that is a bit weird. Let's just wait a bit more and see what happens.

Now it seems to be compiling something:

```

-lnettle  -o base64enc
clang -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -I/src/wget_deps/include -L/src/wget_deps/lib -ggdb3 -Wall -W -Wno-sign-compare   -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes   -Wpointer-arith -Wbad-function-cast -Wnested-externs -L.. -L/src/wget_deps/lib base64dec.o io.o \
-lnettle  -o base64dec
clang -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -I/src/wget_deps/include -L/src/wget_deps/lib -ggdb3 -Wall -W -Wno-sign-compare   -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes   -Wpointer-arith -Wbad-function-cast -Wnested-externs -L.. -L/src/wget_deps/lib rsa-keygen.o io.o ../getopt.o ../getopt1.o \
-lhogweed -lnettle  -o rsa-keygen
clang -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -I/src/wget_deps/include -L/src/wget_deps/lib -ggdb3 -Wall -W -Wno-sign-compare   -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes   -Wpointer-arith -Wbad-function-cast -Wnested-externs -L.. -L/src/wget_deps/lib rsa-sign.o io.o read_rsa_key.o \
-lhogweed -lnettle  -o rsa-sign
clang -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -I/src/wget_deps/include -L/src/wget_deps/lib -ggdb3 -Wall -W -Wno-sign-compare   -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes   -Wpointer-arith -Wbad-function-cast -Wnested-externs -L.. -L/src/wget_deps/lib rsa-verify.o io.o read_rsa_key.o \
-lhogweed -lnettle  -o rsa-verify
clang -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -I/src/wget_deps/include -L/src/wget_deps/lib -ggdb3 -Wall -W -Wno-sign-compare   -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes   -Wpointer-arith -Wbad-function-cast -Wnested-externs -L.. -L/src/wget_deps/lib rsa-encrypt.o io.o read_rsa_key.o \
../getopt.o ../getopt1.o \
-lhogweed -lnettle  -o rsa-encrypt
clang -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -I/src/wget_deps/include -L/src/wget_deps/lib -ggdb3 -Wall -W -Wno-sign-compare   -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes   -Wpointer-arith -Wbad-function-cast -Wnested-externs -L.. -L/src/wget_deps/lib rsa-decrypt.o io.o read_rsa_key.o \
-lhogweed -lnettle  -o rsa-decrypt
clang -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -I/src/wget_deps/include -L/src/wget_deps/lib -ggdb3 -Wall -W -Wno-sign-compare   -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes   -Wpointer-arith -Wbad-function-cast -Wnested-externs -L.. -L/src/wget_deps/lib random-prime.o io.o ../getopt.o ../getopt1.o \
-lhogweed -lnettle  -o random-prime
clang -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -I/src/wget_deps/include -L/src/wget_deps/lib -ggdb3 -Wall -W -Wno-sign-compare   -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes   -Wpointer-arith -Wbad-function-cast -Wnested-externs -L.. -L/src/wget_deps/lib ecc-benchmark.o timing.o -lhogweed -lnettle -lm  \
-o ecc-benchmark
clang -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -I/src/wget_deps/include -L/src/wget_deps/lib -ggdb3 -Wall -W -Wno-sign-compare   -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes   -Wpointer-arith -Wbad-function-cast -Wnested-externs -L.. -L/src/wget_deps/lib hogweed-benchmark.o timing.o \
-lhogweed -lnettle -lm   \
-o hogweed-benchmark
clang -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -I/src/wget_deps/include -L/src/wget_deps/lib -ggdb3 -Wall -W -Wno-sign-compare   -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes   -Wpointer-arith -Wbad-function-cast -Wnested-externs -L.. -L/src/wget_deps/lib nettle-benchmark.o nettle-openssl.o ../getopt.o ../getopt1.o ../non-nettle.o timing.o -lnettle -lm  -o nettle-benchmark


```

I remember that this compilation process errored when it was compiling some dependency, so let's see what happens...

Here is the end of the build log:

```

2024-05-13 08:48:42 URL:https://translationproject.org/latest/gnulib/vi.po [30022/30022] -> "./vi.po" [1]
2024-05-13 08:48:42 URL:https://translationproject.org/latest/gnulib/zh_CN.po [27092/27092] -> "./zh_CN.po" [1]
2024-05-13 08:48:43 URL:https://translationproject.org/latest/gnulib/zh_TW.po [30835/30835] -> "./zh_TW.po" [1]
FINISHED --2024-05-13 08:48:43--
Total wall clock time: 4.2s
Downloaded: 45 files, 1.1M in 0.5s (2.06 MB/s)
Creating gnulib_po/LINGUAS
Creating m4/gnulib-cache.m4
Creating m4/gnulib-comp.m4
Creating lib/gnulib.mk
Updating build-aux/.gitignore (backup in build-aux/.gitignore~)
Creating doc/.gitignore
Updating gnulib_po/.gitignore (backup in gnulib_po/.gitignore~)
Creating lib/.gitignore
Creating lib/glthread/.gitignore
Creating lib/malloc/.gitignore
Creating lib/unicase/.gitignore
Creating lib/unictype/.gitignore
Creating lib/uninorm/.gitignore
Creating lib/unistr/.gitignore
Creating lib/uniwidth/.gitignore
Updating m4/.gitignore (backup in m4/.gitignore~)
Finished.

You may need to add #include directives for the following .h files.
  #include <arpa/inet.h>
  #include <fcntl.h>
  #include <fnmatch.h>
  #include <getopt.h>
  #include <inttypes.h>
  #include <langinfo.h>
  #include <limits.h>
  #include <netdb.h>
  #include <regex.h>
  #include <signal.h>
  #include <spawn.h>
  #include <stdint.h>
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include <strings.h>
  #include <sys/file.h>
  #include <sys/ioctl.h>
  #include <sys/select.h>
  #include <sys/socket.h>
  #include <sys/stat.h>
  #include <sys/types.h>
  #include <time.h>
  #include <unistd.h>
  #include <utime.h>
  #include <wchar.h>
  #include "base32.h"
  #include "c-ctype.h"
  #include "c-strcase.h"
  #include "c-strcasestr.h"
  #include "dirname.h"
  #include "gettext.h"
  #include "intprops.h"
  #include "mbiter.h"
  #include "md2.h"
  #include "md4.h"
  #include "md5.h"
  #include "quote.h"
  #include "quotearg.h"
  #include "sha1.h"
  #include "sha256.h"
  #include "sha512.h"
  #include "spawn-pipe.h"
  #include "tmpdir.h"
  #include "unicase.h"
  #include "unistr.h"
  #include "unlocked-io.h"
  #include "utimens.h"
  #include "xmemdup0.h"
  #include "xstrndup.h"
  #if HAVE_ICONV
  # include <iconv.h>
  #endif
  #if HAVE_ICONV_H
  # include <iconv.h>
  #endif

You may need to use the following Makefile variables when linking.
Use them in <program>_LDADD when linking a program, or
in <library>_a_LDFLAGS or <library>_la_LDFLAGS when linking a library.
  $(CLOCK_TIME_LIB)
  $(GETADDRINFO_LIB)
  $(GETRANDOM_LIB)
  $(HARD_LOCALE_LIB)
  $(HOSTENT_LIB)
  $(INET_NTOP_LIB)
  $(LIBSOCKET)
  $(LIBTHREAD)
  $(LIB_CRYPTO)
  $(LTLIBC32CONV) when linking with libtool, $(LIBC32CONV) otherwise
  $(LTLIBICONV) when linking with libtool, $(LIBICONV) otherwise
  $(LTLIBINTL) when linking with libtool, $(LIBINTL) otherwise
  $(LTLIBUNISTRING) when linking with libtool, $(LIBUNISTRING) otherwise
  $(MBRTOWC_LIB)
  $(NANOSLEEP_LIB)
  $(POSIX_SPAWN_LIB)
  $(PTHREAD_SIGMASK_LIB)
  $(SELECT_LIB)
  $(SERVENT_LIB)
  $(SETLOCALE_NULL_LIB)

Don't forget to
  - "include gnulib.mk" from within "lib/Makefile.am",
  - add "gnulib_po/Makefile.in" to AC_CONFIG_FILES in ./configure.ac,
  - mention "gnulib_po" in SUBDIRS in Makefile.am,
  - mention "-I m4" in ACLOCAL_AMFLAGS in Makefile.am
    or add an AC_CONFIG_MACRO_DIRS([m4]) invocation in ./configure.ac,
  - mention "m4/gnulib-cache.m4" in EXTRA_DIST in Makefile.am,
  - invoke gl_EARLY in ./configure.ac, right after AC_PROG_CC,
  - invoke gl_INIT in ./configure.ac.
running: AUTOPOINT=true LIBTOOLIZE=true autoreconf --verbose --install --force -I m4  --no-recursive
autoreconf: Entering directory `.'
autoreconf: running: true --force
autoreconf: running: aclocal -I m4 --force -I m4
configure.ac:940: warning: macro 'AM_PATH_GPGME' not found in library
autoreconf: configure.ac: tracing
autoreconf: configure.ac: not using Libtool
autoreconf: running: /usr/bin/autoconf --include=m4 --force
autoreconf: running: /usr/bin/autoheader --include=m4 --force
autoreconf: running: automake --add-missing --copy --force-missing
configure.ac:62: installing 'build-aux/config.guess'
configure.ac:62: installing 'build-aux/config.sub'
configure.ac:54: installing 'build-aux/install-sh'
configure.ac:54: installing 'build-aux/missing'
Makefile.am: installing './INSTALL'
doc/Makefile.am:49: installing 'build-aux/mdate-sh'
doc/Makefile.am:49: installing 'build-aux/texinfo.tex'
fuzz/Makefile.am: installing 'build-aux/depcomp'
parallel-tests: installing 'build-aux/test-driver'
autoreconf: Leaving directory `.'
./bootstrap: ln -fs /src/gnulib/build-aux/install-sh build-aux/install-sh
./bootstrap: ln -fs /src/gnulib/build-aux/mdate-sh build-aux/mdate-sh
./bootstrap: ln -fs /src/gnulib/build-aux/texinfo.tex build-aux/texinfo.tex
./bootstrap: ln -fs /src/gnulib/build-aux/depcomp build-aux/depcomp
./bootstrap: ln -fs /src/gnulib/build-aux/config.guess build-aux/config.guess
./bootstrap: ln -fs /src/gnulib/build-aux/config.sub build-aux/config.sub
./bootstrap: ln -fs /src/gnulib/doc/INSTALL INSTALL
./bootstrap: Creating po/Makevars from po/Makevars.template ...
./bootstrap: done.  Now you can run './configure'.
+ autoreconf -fi
autopoint: using AM_GNU_GETTEXT_REQUIRE_VERSION instead of AM_GNU_GETTEXT_VERSION
Copying file build-aux/config.rpath
Copying file m4/codeset.m4
Copying file m4/extern-inline.m4
Copying file m4/fcntl-o.m4
Copying file m4/iconv.m4
Copying file m4/inttypes_h.m4
Copying file m4/lib-ld.m4
Copying file m4/lib-link.m4
Copying file m4/lib-prefix.m4
Copying file m4/lock.m4
Copying file m4/size_max.m4
Copying file m4/stdint_h.m4
Copying file m4/threadlib.m4
Copying file m4/visibility.m4
Copying file m4/wchar_t.m4
Copying file m4/wint_t.m4
Copying file m4/xsize.m4
Copying file gnulib_po/Makefile.in.in
Copying file po/Makevars.template
Copying file gnulib_po/remove-potcdate.sin
configure.ac:940: warning: macro 'AM_PATH_GPGME' not found in library
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/setlocale_null.m4:8: gl_FUNC_SETLOCALE_NULL is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/iswblank.m4:8: gl_FUNC_ISWBLANK is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/mbrtowc.m4:9: gl_FUNC_MBRTOWC is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/nl_langinfo.m4:8: gl_FUNC_NL_LANGINFO is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/setlocale_null.m4:8: gl_FUNC_SETLOCALE_NULL is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/iswblank.m4:8: gl_FUNC_ISWBLANK is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/mbrtowc.m4:9: gl_FUNC_MBRTOWC is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/nl_langinfo.m4:8: gl_FUNC_NL_LANGINFO is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/setlocale_null.m4:8: gl_FUNC_SETLOCALE_NULL is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/iswblank.m4:8: gl_FUNC_ISWBLANK is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/mbrtowc.m4:9: gl_FUNC_MBRTOWC is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/nl_langinfo.m4:8: gl_FUNC_NL_LANGINFO is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/setlocale_null.m4:8: gl_FUNC_SETLOCALE_NULL is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/iswblank.m4:8: gl_FUNC_ISWBLANK is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/mbrtowc.m4:9: gl_FUNC_MBRTOWC is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/nl_langinfo.m4:8: gl_FUNC_NL_LANGINFO is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure:22263: error: possibly undefined macro: gl_PTHREADLIB
      If this token and others are legitimate, please use m4_pattern_allow.
      See the Autoconf documentation.
configure:22375: error: possibly undefined macro: gl_WEAK_SYMBOLS
configure:23951: error: possibly undefined macro: gl_TYPE_WINT_T_PREREQ
autoreconf: /usr/bin/autoconf failed with exit status: 1
ERROR:__main__:Building fuzzers failed.


```

This is what happens when you try to fucking compile everything from the latest source code. Someone does a singular change and boom, your build no-longer works.

Here is some stuff from the log:

```

make[1]: Entering directory '/src/nettle/tools'
/usr/bin/mkdir -p /src/wget_deps/bin
for f in sexp-conv nettle-hash nettle-pbkdf2 nettle-lfib-stream pkcs1-conv ; do \
  /usr/bin/install -c $f /src/wget_deps/bin ; \
done
make[1]: Leaving directory '/src/nettle/tools'
Making install in testsuite
make[1]: Entering directory '/src/nettle/testsuite'
true
make[1]: Leaving directory '/src/nettle/testsuite'
Making install in examples
make[1]: Entering directory '/src/nettle/examples'
true
make[1]: Leaving directory '/src/nettle/examples'
+ test 0 '!=' 0
+ cd /src/gnutls
+ touch .submodule.stamp
+ ./bootstrap
Submodule 'tests/suite/tls-fuzzer/python-ecdsa' (https://github.com/warner/python-ecdsa) registered for path 'tests/suite/tls-fuzzer/python-ecdsa'
Cloning into '/src/gnutls/tests/suite/tls-fuzzer/python-ecdsa'...
Submodule path 'tests/suite/tls-fuzzer/python-ecdsa': checked out 'c8802e5c4f20557b674ef3d724985d40b5ff0537'
Submodule 'tests/suite/tls-fuzzer/tlsfuzzer' (https://github.com/tomato42/tlsfuzzer.git) registered for path 'tests/suite/tls-fuzzer/tlsfuzzer'
Cloning into '/src/gnutls/tests/suite/tls-fuzzer/tlsfuzzer'...
Submodule path 'tests/suite/tls-fuzzer/tlsfuzzer': checked out '4216d2ca4b017a893cc7681c2baa1635dbdf3f0f'
Submodule 'tests/suite/tls-fuzzer/tlslite-ng' (https://github.com/tomato42/tlslite-ng.git) registered for path 'tests/suite/tls-fuzzer/tlslite-ng'
Cloning into '/src/gnutls/tests/suite/tls-fuzzer/tlslite-ng'...
Submodule path 'tests/suite/tls-fuzzer/tlslite-ng': checked out '7b7a811901f9ddf2ad1ba2202814d1a188b0d717'
Submodule 'tests/suite/tls-interoperability' (https://gitlab.com/redhat-crypto/tests/interop.git) registered for path 'tests/suite/tls-interoperability'
Cloning into '/src/gnutls/tests/suite/tls-interoperability'...
Submodule path 'tests/suite/tls-interoperability': checked out 'd99d8486a3c7269f5a99fce5145365bdbbe1cab8'
Submodule 'devel/cligen' (https://gitlab.com/gnutls/cligen.git) registered for path 'cligen'
Cloning into '/src/gnutls/cligen'...
Submodule path 'cligen': checked out 'ed2ed7b19a5bcbc0f39505722058befc923eeeda'
Submodule 'devel/abi-dump' (https://gitlab.com/gnutls/abi-dump.git) registered for path 'devel/abi-dump'
Cloning into '/src/gnutls/devel/abi-dump'...
Submodule path 'devel/abi-dump': checked out 'd382be66407f887700dbdafc8d34a62e88afb8f4'
Submodule 'devel/nettle' (https://gitlab.com/gnutls/nettle.git) registered for path 'devel/nettle'
Cloning into '/src/gnutls/devel/nettle'...
Submodule path 'devel/nettle': checked out '236d79b8bc508ae089f63a75c16f87c7076babdf'
Submodule 'devel/openssl' (https://github.com/openssl/openssl.git) registered for path 'devel/openssl'
Cloning into '/src/gnutls/devel/openssl'...



```

here is some more stuff:

```

Copying file src/gl/windows-tls.h
Copying file src/gl/xalloc-die.c
Copying file src/gl/xalloc-oversized.h
Copying file src/gl/xalloc.h
Copying file src/gl/xmalloc.c
Copying file src/gl/xsize.c
Copying file src/gl/xsize.h
Creating src/gl/m4/gnulib-cache.m4
Creating src/gl/m4/gnulib-comp.m4
Creating src/gl/Makefile.am
Creating src/gl/tests/Makefile.am
Finished.

You may need to add #include directives for the following .h files.
  #include <alloca.h>
  #include <arpa/inet.h>
  #include <byteswap.h>
  #include <inttypes.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <stdint.h>
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include <strings.h>
  #include <sys/select.h>
  #include <sys/socket.h>
  #include <sys/stat.h>
  #include <sys/time.h>
  #include <sys/types.h>
  #include <time.h>
  #include <unistd.h>
  #include "attribute.h"
  #include "c-ctype.h"
  #include "c-strcase.h"
  #include "close-stream.h"
  #include "gettext.h"
  #include "gl_linked_list.h"
  #include "gl_linkedhash_list.h"
  #include "gl_xlist.h"
  #include "glthread/lock.h"
  #include "glthread/tls.h"
  #include "hash-pjw-bare.h"
  #include "hash.h"
  #include "intprops.h"
  #include "minmax.h"
  #include "parse-datetime.h"
  #include "pathmax.h"
  #include "progname.h"
  #include "read-file.h"
  #include "sockets.h"
  #include "verify.h"
  #include "xalloc-oversized.h"
  #include "xalloc.h"
  #include "xsize.h"
  #include <sys/types.h>
  #if HAVE_SYS_SOCKET_H
  # include <sys/socket.h>
  #elif HAVE_WS2TCPIP_H
  # include <ws2tcpip.h>
  #endif

You may need to use the following Makefile variables when linking.
Use them in <program>_LDADD when linking a program, or
in <library>_a_LDFLAGS or <library>_la_LDFLAGS when linking a library.
  $(CLOCK_TIME_LIB)
  $(GETADDRINFO_LIB)
  $(HOSTENT_LIB)
  $(INET_NTOP_LIB)
  $(INET_PTON_LIB)
  $(LIBSOCKET)
  $(LIBTHREAD)
  $(LTLIBINTL) when linking with libtool, $(LIBINTL) otherwise
  $(SELECT_LIB)
  $(SERVENT_LIB)

Don't forget to
  - add "src/gl/Makefile" to AC_CONFIG_FILES in ./configure.ac,
  - add "src/gl/tests/Makefile" to AC_CONFIG_FILES in ./configure.ac,
  - mention "gl" in SUBDIRS in src/Makefile.am,
  - mention "-I src/gl/m4" in ACLOCAL_AMFLAGS in Makefile.am
    or add an AC_CONFIG_MACRO_DIRS([src/gl/m4]) invocation in ./configure.ac,
  - replace AC_PROG_CC_C99 with AC_PROG_CC in ./configure.ac,
  - invoke ggl_EARLY in ./configure.ac, right after AC_PROG_CC_C99,
  - invoke ggl_INIT in ./configure.ac.
Copying file ./lib/nettle/backport/block-internal.h
Copying file ./lib/nettle/backport/bswap-internal.h
Copying file ./lib/nettle/backport/ctr-internal.h
Copying file ./lib/nettle/backport/ctr.h
Copying file ./lib/nettle/backport/ctr16.c
Copying file ./lib/nettle/backport/ghash-internal.h
Copying file ./lib/nettle/backport/ghash-set-key.c
Copying file ./lib/nettle/backport/ghash-update.c
Copying file ./lib/nettle/backport/gmp-glue.c
Copying file ./lib/nettle/backport/gmp-glue.h
Copying file ./lib/nettle/backport/oaep.c
Copying file ./lib/nettle/backport/oaep.h
Copying file ./lib/nettle/backport/pss-mgf1.h
Copying file ./lib/nettle/backport/pss-mgf1.c
Copying file ./lib/nettle/backport/rsa-internal.h
Copying file ./lib/nettle/backport/rsa-oaep-encrypt.c
Copying file ./lib/nettle/backport/rsa-oaep-decrypt.c
Copying file ./lib/nettle/backport/rsa-sec-compute-root.c
Copying file ./lib/nettle/backport/rsa-sign-tr.c
Copying file ./lib/nettle/backport/siv-gcm-aes128.c
Copying file ./lib/nettle/backport/siv-gcm-aes256.c
Copying file ./lib/nettle/backport/siv-gcm.c
Copying file ./lib/nettle/backport/siv-gcm.h
Copying file ./lib/nettle/backport/siv-ghash-set-key.c
Copying file ./lib/nettle/backport/siv-ghash-update.c
Copying file ./lib/minitasn1/coding.c
Copying file ./lib/minitasn1/decoding.c
Copying file ./lib/minitasn1/element.c
Copying file ./lib/minitasn1/element.h
Copying file ./lib/minitasn1/errors.c
Copying file ./lib/minitasn1/gstr.c
Copying file ./lib/minitasn1/gstr.h
Copying file ./lib/minitasn1/int.h
Copying file ./lib/minitasn1/parser_aux.c
Copying file ./lib/minitasn1/parser_aux.h
Copying file ./lib/minitasn1/structure.c
Copying file ./lib/minitasn1/structure.h
Copying file ./lib/minitasn1/version.c
Copying file ./lib/minitasn1/libtasn1.h
running: AUTOPOINT=true LIBTOOLIZE=true autoreconf --verbose --install --force -I m4  --no-recursive
autoreconf: Entering directory `.'
autoreconf: running: true --force
autoreconf: running: aclocal -I m4 --force -I m4 -I src/gl/m4 -I lib/unistring/m4 --install
aclocal: installing 'm4/gtk-doc.m4' from '/usr/share/aclocal/gtk-doc.m4'
aclocal: installing 'm4/pkg.m4' from '/usr/share/aclocal/pkg.m4'



```

Here is other stuff:

```

Copying file m4/mbrtowc.m4
Copying file m4/mbsinit.m4
Copying file m4/mbsrtowcs.m4
Copying file m4/mbstate_t.m4
Copying file m4/mbtowc.m4
Copying file m4/md4.m4
Copying file m4/md5.m4
Copying file m4/memchr.m4
Copying file m4/mempcpy.m4
Copying file m4/memrchr.m4
Copying file m4/minmax.m4
Copying file m4/mkdir.m4
Copying file m4/mkostemp.m4
Copying file m4/mkstemp.m4
Copying file m4/mktime.m4
Copying file m4/mmap-anon.m4
Copying file m4/mode_t.m4
Copying file m4/msvc-inval.m4
Copying file m4/msvc-nothrow.m4
Copying file m4/multiarch.m4
Copying file m4/musl.m4
Copying file m4/nanosleep.m4
Copying file m4/netdb_h.m4
Copying file m4/netinet_in_h.m4
Copying file m4/nl_langinfo.m4
Copying file m4/nocrash.m4
Copying file m4/off64_t.m4
Copying file m4/off_t.m4
Copying file m4/open-cloexec.m4
Copying file m4/open-slash.m4
Copying file m4/open.m4
Copying file m4/openat.m4
Copying file m4/opendir.m4
Copying file m4/pathmax.m4
Copying file m4/pid_t.m4
Copying file m4/pipe.m4
Copying file m4/pipe2.m4
Copying file m4/posix_spawn.m4
Copying file m4/posix_spawn_faction_addchdir.m4
Copying file m4/printf.m4
Copying file m4/pselect.m4
Copying file m4/pthread_rwlock_rdlock.m4
Copying file m4/pthread_sigmask.m4
Copying file m4/quote.m4
Copying file m4/quotearg.m4
Copying file m4/raise.m4
Copying file m4/rawmemchr.m4
Copying file m4/readdir.m4
Copying file m4/readlink.m4
Copying file m4/realloc.m4
Copying file m4/reallocarray.m4
Copying file m4/regex.m4
Copying file m4/rename.m4
Copying file m4/rewinddir.m4
Copying file m4/rmdir.m4
Copying file m4/save-cwd.m4
Copying file m4/sched_h.m4
Copying file m4/secure_getenv.m4
Copying file m4/select.m4
Copying file m4/servent.m4
Copying file m4/setlocale_null.m4
Copying file m4/sh-filename.m4
Copying file m4/sha1.m4
Copying file m4/sha256.m4
Copying file m4/sha512.m4
Copying file m4/sig_atomic_t.m4
Copying file m4/sigaction.m4
Copying file m4/signal_h.m4
Copying file m4/signalblocking.m4
Copying file m4/sigpipe.m4
Replacing file m4/size_max.m4 (non-gnulib code backed up in m4/size_max.m4~) !!
Copying file m4/snprintf.m4
Copying file m4/socketlib.m4
Copying file m4/sockets.m4
Copying file m4/socklen.m4
Copying file m4/sockpfaf.m4
Copying file m4/spawn-pipe.m4
Copying file m4/spawn_h.m4
Copying file m4/ssize_t.m4
Copying file m4/stat-time.m4
Copying file m4/stat.m4
Copying file m4/std-gnu11.m4
Copying file m4/stdalign.m4
Copying file m4/stddef_h.m4
Copying file m4/stdint.m4
Replacing file m4/stdint_h.m4 (non-gnulib code backed up in m4/stdint_h.m4~) !!
Copying file m4/stdio_h.m4
Copying file m4/stdlib_h.m4
Copying file m4/stpcpy.m4
Copying file m4/strcase.m4
Copying file m4/strchrnul.m4
Copying file m4/strdup.m4
Copying file m4/strerror.m4
Copying file m4/strerror_r.m4
Copying file m4/string_h.m4
Copying file m4/strings_h.m4
Copying file m4/strndup.m4
Copying file m4/strnlen.m4
Copying file m4/strpbrk.m4
Copying file m4/strptime.m4
Copying file m4/strtok_r.m4
Copying file m4/strtol.m4
Copying file m4/strtoll.m4
Copying file m4/symlink.m4
Copying file m4/sys_file_h.m4
Copying file m4/sys_ioctl_h.m4
Copying file m4/sys_random_h.m4
Copying file m4/sys_select_h.m4
Copying file m4/sys_socket_h.m4
Copying file m4/sys_stat_h.m4
Copying file m4/sys_time_h.m4
Copying file m4/sys_types_h.m4
Copying file m4/sys_uio_h.m4
Copying file m4/sys_wait_h.m4
Copying file m4/tcgetattr.m4
Copying file m4/tempname.m4
Replacing file m4/threadlib.m4 (non-gnulib code backed up in m4/threadlib.m4~) !!
Copying file m4/time_h.m4
Copying file m4/time_r.m4
Copying file m4/timegm.m4
Copying file m4/timespec.m4
Copying file m4/tm_gmtoff.m4
Copying file m4/tmpdir.m4
Copying file m4/uchar_h.m4
Copying file m4/ungetc.m4
Copying file m4/unicase_h.m4
Copying file m4/unictype_h.m4
Copying file m4/uninorm_h.m4
Copying file m4/unistd-safer.m4
Copying file m4/unistd_h.m4
Copying file m4/unlink.m4
Copying file m4/unlocked-io.m4
Copying file m4/utime.m4
Copying file m4/utime_h.m4
Copying file m4/utimens.m4
Copying file m4/utimes.m4
Copying file m4/vararrays.m4
Copying file m4/vasnprintf.m4
Copying file m4/vasprintf.m4
Replacing file m4/visibility.m4 (non-gnulib code backed up in m4/visibility.m4~) !!
Copying file m4/vsnprintf.m4
Copying file m4/wait-process.m4
Copying file m4/waitpid.m4
Copying file m4/warn-on-use.m4
Copying file m4/warnings.m4
Copying file m4/wchar_h.m4
Replacing file m4/wchar_t.m4 (non-gnulib code backed up in m4/wchar_t.m4~) !!
Copying file m4/wcrtomb.m4
Copying file m4/wctype.m4
Copying file m4/wctype_h.m4
Copying file m4/wcwidth.m4
Replacing file m4/wint_t.m4 (non-gnulib code backed up in m4/wint_t.m4~) !!
Copying file m4/wmemchr.m4
Copying file m4/wmempcpy.m4
Copying file m4/write.m4
Copying file m4/xalloc.m4
Replacing file m4/xsize.m4 (non-gnulib code backed up in m4/xsize.m4~) !!
Copying file m4/xstrndup.m4
Copying file m4/zzgnulib.m4
Copying file maint.mk
Updating gnulib_po/Makefile.in.in (backup in gnulib_po/Makefile.in.in~)
Updating gnulib_po/remove-potcdate.sin (backup in gnulib_po/remove-potcdate.sin~)
Creating gnulib_po/Makevars
Creating gnulib_po/POTFILES.in
Fetching gnulib PO files from https://translationproject.org/latest/
Last-modified header missing -- time-stamps turned off.
2024-05-13 09:18:26 URL:https://translationproject.org/latest/gnulib/ [8123] -> "./index.html.tmp" [1]
https://translationproject.org/robots.txt:
2024-05-13 09:18:26 ERROR 404: Not Found.
Last-modified header missing -- time-stamps turned off.
2024-05-13 09:18:26 URL:https://translationproject.org/latest/gnulib/?C=N;O=D [8123] -> "./index.html?C=N;O=D.tmp" [1]
Last-modified header missing -- time-stamps turned off.
2024-05-13 09:18:26 URL:https://translationproject.org/latest/gnulib/?C=M;O=A [8123] -> "./index.html?C=M;O=A.tmp" [1]
Last-modified header missing -- time-stamps turned off.
2024-05-13 09:18:26 URL:https://translationproject.org/latest/gnulib/?C=S;O=A [8123] -> "./index.html?C=S;O=A.tmp" [1]
Last-modified header missing -- time-stamps turned off.
2024-05-13 09:18:26 URL:https://translationproject.org/latest/gnulib/?C=D;O=A [8123] -> "./index.html?C=D;O=A.tmp" [1]
Last-modified header missing -- time-stamps turned off.
2024-05-13 09:18:26 URL:https://translationproject.org/latest/ [30430] -> "./index.html.tmp" [1]
2024-05-13 09:18:26 URL:https://translationproject.org/latest/gnulib/af.po [13766/13766] -> "./af.po" [1]
2024-05-13 09:18:27 URL:https://translationproject.org/latest/gnulib/be.po [13217/13217] -> "./be.po" [1]
2024-05-13 09:18:27 URL:https://translationproject.org/latest/gnulib/bg.po [37222/37222] -> "./bg.po" [1]
2024-05-13 09:18:27 URL:https://translationproject.org/latest/gnulib/ca.po [16781/16781] -> "./ca.po" [1]
2024-05-13 09:18:27 URL:https://translationproject.org/latest/gnulib/cs.po [28292/28292] -> "./cs.po" [1]
2024-05-13 09:18:27 URL:https://translationproject.org/latest/gnulib/da.po [27145/27145] -> "./da.po" [1]
2024-05-13 09:18:27 URL:https://translationproject.org/latest/gnulib/de.po [33485/33485] -> "./de.po" [1]
2024-05-13 09:18:27 URL:https://translationproject.org/latest/gnulib/el.po [27109/27109] -> "./el.po" [1]
2024-05-13 09:18:27 URL:https://translationproject.org/latest/gnulib/eo.po [30477/30477] -> "./eo.po" [1]
2024-05-13 09:18:27 URL:https://translationproject.org/latest/gnulib/es.po [34479/34479] -> "./es.po" [1]
2024-05-13 09:18:27 URL:https://translationproject.org/latest/gnulib/et.po [25425/25425] -> "./et.po" [1]
2024-05-13 09:18:27 URL:https://translationproject.org/latest/gnulib/eu.po [13065/13065] -> "./eu.po" [1]
2024-05-13 09:18:27 URL:https://translationproject.org/latest/gnulib/fi.po [30663/30663] -> "./fi.po" [1]
2024-05-13 09:18:27 URL:https://translationproject.org/latest/gnulib/fr.po [31287/31287] -> "./fr.po" [1]
2024-05-13 09:18:28 URL:https://translationproject.org/latest/gnulib/ga.po [24532/24532] -> "./ga.po" [1]
2024-05-13 09:18:28 URL:https://translationproject.org/latest/gnulib/gl.po [27316/27316] -> "./gl.po" [1]
2024-05-13 09:18:28 URL:https://translationproject.org/latest/gnulib/hu.po [28558/28558] -> "./hu.po" [1]
2024-05-13 09:18:28 URL:https://translationproject.org/latest/gnulib/it.po [33109/33109] -> "./it.po" [1]
2024-05-13 09:18:28 URL:https://translationproject.org/latest/gnulib/ja.po [31707/31707] -> "./ja.po" [1]
2024-05-13 09:18:28 URL:https://translationproject.org/latest/gnulib/ka.po [37117/37117] -> "./ka.po" [1]
2024-05-13 09:18:28 URL:https://translationproject.org/latest/gnulib/ko.po [11802/11802] -> "./ko.po" [1]
2024-05-13 09:18:28 URL:https://translationproject.org/latest/gnulib/ms.po [11306/11306] -> "./ms.po" [1]
2024-05-13 09:18:28 URL:https://translationproject.org/latest/gnulib/nb.po [11169/11169] -> "./nb.po" [1]
2024-05-13 09:18:28 URL:https://translationproject.org/latest/gnulib/nl.po [31806/31806] -> "./nl.po" [1]
2024-05-13 09:18:28 URL:https://translationproject.org/latest/gnulib/pl.po [30974/30974] -> "./pl.po" [1]
2024-05-13 09:18:29 URL:https://translationproject.org/latest/gnulib/pt.po [30184/30184] -> "./pt.po" [1]
2024-05-13 09:18:29 URL:https://translationproject.org/latest/gnulib/pt_BR.po [34497/34497] -> "./pt_BR.po" [1]
2024-05-13 09:18:29 URL:https://translationproject.org/latest/gnulib/ro.po [35569/35569] -> "./ro.po" [1]
2024-05-13 09:18:29 URL:https://translationproject.org/latest/gnulib/ru.po [37128/37128] -> "./ru.po" [1]
2024-05-13 09:18:29 URL:https://translationproject.org/latest/gnulib/rw.po [15799/15799] -> "./rw.po" [1]
2024-05-13 09:18:29 URL:https://translationproject.org/latest/gnulib/sk.po [11825/11825] -> "./sk.po" [1]
2024-05-13 09:18:29 URL:https://translationproject.org/latest/gnulib/sl.po [29126/29126] -> "./sl.po" [1]
2024-05-13 09:18:29 URL:https://translationproject.org/latest/gnulib/sr.po [36570/36570] -> "./sr.po" [1]
2024-05-13 09:18:29 URL:https://translationproject.org/latest/gnulib/sv.po [30233/30233] -> "./sv.po" [1]
2024-05-13 09:18:29 URL:https://translationproject.org/latest/gnulib/tr.po [14533/14533] -> "./tr.po" [1]
2024-05-13 09:18:29 URL:https://translationproject.org/latest/gnulib/uk.po [36864/36864] -> "./uk.po" [1]
2024-05-13 09:18:29 URL:https://translationproject.org/latest/gnulib/vi.po [30022/30022] -> "./vi.po" [1]
2024-05-13 09:18:29 URL:https://translationproject.org/latest/gnulib/zh_CN.po [27092/27092] -> "./zh_CN.po" [1]
2024-05-13 09:18:29 URL:https://translationproject.org/latest/gnulib/zh_TW.po [30835/30835] -> "./zh_TW.po" [1]
FINISHED --2024-05-13 09:18:29--
Total wall clock time: 4.3s
Downloaded: 45 files, 1.1M in 0.6s (1.72 MB/s)
Creating gnulib_po/LINGUAS
Creating m4/gnulib-cache.m4
Creating m4/gnulib-comp.m4
Creating lib/gnulib.mk
Updating build-aux/.gitignore (backup in build-aux/.gitignore~)
Creating doc/.gitignore
Updating gnulib_po/.gitignore (backup in gnulib_po/.gitignore~)
Creating lib/.gitignore
Creating lib/glthread/.gitignore
Creating lib/malloc/.gitignore
Creating lib/unicase/.gitignore
Creating lib/unictype/.gitignore
Creating lib/uninorm/.gitignore
Creating lib/unistr/.gitignore
Creating lib/uniwidth/.gitignore
Updating m4/.gitignore (backup in m4/.gitignore~)
Finished.

You may need to add #include directives for the following .h files.
  #include <arpa/inet.h>
  #include <fcntl.h>
  #include <fnmatch.h>
  #include <getopt.h>
  #include <inttypes.h>
  #include <langinfo.h>
  #include <limits.h>
  #include <netdb.h>
  #include <regex.h>
  #include <signal.h>
  #include <spawn.h>
  #include <stdint.h>
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include <strings.h>
  #include <sys/file.h>
  #include <sys/ioctl.h>
  #include <sys/select.h>
  #include <sys/socket.h>
  #include <sys/stat.h>
  #include <sys/types.h>
  #include <time.h>
  #include <unistd.h>
  #include <utime.h>
  #include <wchar.h>
  #include "base32.h"
  #include "c-ctype.h"
  #include "c-strcase.h"
  #include "c-strcasestr.h"
  #include "dirname.h"
  #include "gettext.h"
  #include "intprops.h"
  #include "mbiter.h"
  #include "md2.h"
  #include "md4.h"
  #include "md5.h"
  #include "quote.h"
  #include "quotearg.h"
  #include "sha1.h"
  #include "sha256.h"
  #include "sha512.h"
  #include "spawn-pipe.h"
  #include "tmpdir.h"
  #include "unicase.h"
  #include "unistr.h"
  #include "unlocked-io.h"
  #include "utimens.h"
  #include "xmemdup0.h"
  #include "xstrndup.h"
  #if HAVE_ICONV
  # include <iconv.h>
  #endif
  #if HAVE_ICONV_H
  # include <iconv.h>
  #endif

You may need to use the following Makefile variables when linking.
Use them in <program>_LDADD when linking a program, or
in <library>_a_LDFLAGS or <library>_la_LDFLAGS when linking a library.
  $(CLOCK_TIME_LIB)
  $(GETADDRINFO_LIB)
  $(GETRANDOM_LIB)
  $(HARD_LOCALE_LIB)
  $(HOSTENT_LIB)
  $(INET_NTOP_LIB)
  $(LIBSOCKET)
  $(LIBTHREAD)
  $(LIB_CRYPTO)
  $(LTLIBC32CONV) when linking with libtool, $(LIBC32CONV) otherwise
  $(LTLIBICONV) when linking with libtool, $(LIBICONV) otherwise
  $(LTLIBINTL) when linking with libtool, $(LIBINTL) otherwise
  $(LTLIBUNISTRING) when linking with libtool, $(LIBUNISTRING) otherwise
  $(MBRTOWC_LIB)
  $(NANOSLEEP_LIB)
  $(POSIX_SPAWN_LIB)
  $(PTHREAD_SIGMASK_LIB)
  $(SELECT_LIB)
  $(SERVENT_LIB)
  $(SETLOCALE_NULL_LIB)

Don't forget to
  - "include gnulib.mk" from within "lib/Makefile.am",
  - add "gnulib_po/Makefile.in" to AC_CONFIG_FILES in ./configure.ac,
  - mention "gnulib_po" in SUBDIRS in Makefile.am,
  - mention "-I m4" in ACLOCAL_AMFLAGS in Makefile.am
    or add an AC_CONFIG_MACRO_DIRS([m4]) invocation in ./configure.ac,
  - mention "m4/gnulib-cache.m4" in EXTRA_DIST in Makefile.am,
  - invoke gl_EARLY in ./configure.ac, right after AC_PROG_CC,
  - invoke gl_INIT in ./configure.ac.
running: AUTOPOINT=true LIBTOOLIZE=true autoreconf --verbose --install --force -I m4  --no-recursive
autoreconf: Entering directory `.'
autoreconf: running: true --force
autoreconf: running: aclocal -I m4 --force -I m4
configure.ac:940: warning: macro 'AM_PATH_GPGME' not found in library
autoreconf: configure.ac: tracing
autoreconf: configure.ac: not using Libtool
autoreconf: running: /usr/bin/autoconf --include=m4 --force
autoreconf: running: /usr/bin/autoheader --include=m4 --force
autoreconf: running: automake --add-missing --copy --force-missing
configure.ac:62: installing 'build-aux/config.guess'
configure.ac:62: installing 'build-aux/config.sub'
configure.ac:54: installing 'build-aux/install-sh'
configure.ac:54: installing 'build-aux/missing'
Makefile.am: installing './INSTALL'
doc/Makefile.am:49: installing 'build-aux/mdate-sh'
doc/Makefile.am:49: installing 'build-aux/texinfo.tex'
fuzz/Makefile.am: installing 'build-aux/depcomp'
parallel-tests: installing 'build-aux/test-driver'
autoreconf: Leaving directory `.'
./bootstrap: ln -fs /src/gnulib/build-aux/install-sh build-aux/install-sh
./bootstrap: ln -fs /src/gnulib/build-aux/mdate-sh build-aux/mdate-sh
./bootstrap: ln -fs /src/gnulib/build-aux/texinfo.tex build-aux/texinfo.tex
./bootstrap: ln -fs /src/gnulib/build-aux/depcomp build-aux/depcomp
./bootstrap: ln -fs /src/gnulib/build-aux/config.guess build-aux/config.guess
./bootstrap: ln -fs /src/gnulib/build-aux/config.sub build-aux/config.sub
./bootstrap: ln -fs /src/gnulib/doc/INSTALL INSTALL
./bootstrap: Creating po/Makevars from po/Makevars.template ...
./bootstrap: done.  Now you can run './configure'.
+ autoreconf -fi
autopoint: using AM_GNU_GETTEXT_REQUIRE_VERSION instead of AM_GNU_GETTEXT_VERSION
Copying file build-aux/config.rpath
Copying file m4/codeset.m4
Copying file m4/extern-inline.m4
Copying file m4/fcntl-o.m4
Copying file m4/iconv.m4
Copying file m4/inttypes_h.m4
Copying file m4/lib-ld.m4
Copying file m4/lib-link.m4
Copying file m4/lib-prefix.m4
Copying file m4/lock.m4
Copying file m4/size_max.m4
Copying file m4/stdint_h.m4
Copying file m4/threadlib.m4
Copying file m4/visibility.m4
Copying file m4/wchar_t.m4
Copying file m4/wint_t.m4
Copying file m4/xsize.m4
Copying file gnulib_po/Makefile.in.in
Copying file po/Makevars.template
Copying file gnulib_po/remove-potcdate.sin
configure.ac:940: warning: macro 'AM_PATH_GPGME' not found in library
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/setlocale_null.m4:8: gl_FUNC_SETLOCALE_NULL is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/iswblank.m4:8: gl_FUNC_ISWBLANK is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/mbrtowc.m4:9: gl_FUNC_MBRTOWC is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/nl_langinfo.m4:8: gl_FUNC_NL_LANGINFO is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/setlocale_null.m4:8: gl_FUNC_SETLOCALE_NULL is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/iswblank.m4:8: gl_FUNC_ISWBLANK is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/mbrtowc.m4:9: gl_FUNC_MBRTOWC is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/nl_langinfo.m4:8: gl_FUNC_NL_LANGINFO is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/setlocale_null.m4:8: gl_FUNC_SETLOCALE_NULL is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/iswblank.m4:8: gl_FUNC_ISWBLANK is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/mbrtowc.m4:9: gl_FUNC_MBRTOWC is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/nl_langinfo.m4:8: gl_FUNC_NL_LANGINFO is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/setlocale_null.m4:8: gl_FUNC_SETLOCALE_NULL is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/iswblank.m4:8: gl_FUNC_ISWBLANK is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/mbrtowc.m4:9: gl_FUNC_MBRTOWC is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/nl_langinfo.m4:8: gl_FUNC_NL_LANGINFO is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure:22263: error: possibly undefined macro: gl_PTHREADLIB
      If this token and others are legitimate, please use m4_pattern_allow.
      See the Autoconf documentation.
configure:22375: error: possibly undefined macro: gl_WEAK_SYMBOLS
configure:23951: error: possibly undefined macro: gl_TYPE_WINT_T_PREREQ
autoreconf: /usr/bin/autoconf failed with exit status: 1
ERROR:__main__:Building fuzzers failed.


```

This may also be a clue:

```

	    and start over
clangclang: : warning: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
ar: /src/libidn2/unistring/.libs/libunistring.a: No such file or directory
make[3]: *** [Makefile:2145: libunistring.la] Error 9
make[2]: *** [Makefile:1993: all] Error 2
make[1]: *** [Makefile:1857: all-recursive] Error 1
make: *** [Makefile:1765: all] Error 2
ar: /src/libidn2/unistring/.libs/libunistring.a: No such file or directory
make[3]: *** [Makefile:2145: libunistring.la] Error 9





+ export WGET_DEPS_PATH=/src/wget_deps
+ WGET_DEPS_PATH=/src/wget_deps
+ export PKG_CONFIG_PATH=/src/wget_deps/lib64/pkgconfig:/src/wget_deps/lib/pkgconfig
+ PKG_CONFIG_PATH=/src/wget_deps/lib64/pkgconfig:/src/wget_deps/lib/pkgconfig
+ export CPPFLAGS=-I/src/wget_deps/include
+ CPPFLAGS=-I/src/wget_deps/include
+ export 'CFLAGS=-O1 -fno-omit-frame-pointer -gline-tables-only -Wno-error=enum-constexpr-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -I/src/wget_deps/include -L/src/wget_deps/lib'
+ CFLAGS='-O1 -fno-omit-frame-pointer -gline-tables-only -Wno-error=enum-constexpr-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -I/src/wget_deps/include -L/src/wget_deps/lib'
+ export LDFLAGS=-L/src/wget_deps/lib
+ LDFLAGS=-L/src/wget_deps/lib
+ export GNULIB_SRCDIR=/src/gnulib
+ GNULIB_SRCDIR=/src/gnulib
+ export LLVM_PROFILE_FILE=/tmp/prof.test
+ LLVM_PROFILE_FILE=/tmp/prof.test
+ cd /src/libunistring
+ ./configure --enable-static --disable-shared --prefix=/src/wget_deps --cache-file ../config.cache
++ nproc
+ make -j8




Ubuntu clang version 14.0.0-1ubuntu1.1
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
Found candidate GCC installation: /usr/bin/../lib/gcc/x86_64-linux-gnu/11
Found candidate GCC installation: /usr/bin/../lib/gcc/x86_64-linux-gnu/12
Found candidate GCC installation: /usr/bin/../lib/gcc/x86_64-linux-gnu/9
Selected GCC installation: /usr/bin/../lib/gcc/x86_64-linux-gnu/12
Candidate multilib: .;@m64
Selected multilib: .;@m64
... rest of stderr output deleted ...
configure:7226: $? = 0
configure:7215: clang -V >&5
clang: error: argument to '-V' is missing (expected 1 value)
clang: error: no input files
configure:7226: $? = 1
configure:7215: clang -qversion >&5
clang: error: unknown argument '-qversion'; did you mean '--version'?
clang: error: no input files
configure:7226: $? = 1
configure:7215: clang -version >&5
clang: error: unknown argument '-version'; did you mean '--version'?
clang: error: no input files
configure:7226: $? = 1
configure:7246: checking whether the C compiler works
configure:7268: clang -O1 -fno-omit-frame-pointer -gline-tables-only -Wno-error=enum-constexpr-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int  -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -I/src/wget_deps/include -L/src/wget_deps/lib   conftest.c -lunistring >&5
warning: unknown warning option '-Werror=enum-constexpr-conversion' [-Wunknown-warning-option]
1 warning generated.
/usr/bin/ld: cannot find -lunistring: No such file or directory
clang: error: linker command failed with exit code 1 (use -v to see invocation)
configure:7272: $? = 1
configure:7312: result: no
configure: failed program was:
| /* confdefs.h */

```

This here compiles everything correctly in gnutls in the oss-fuzz build:

```

CC=clang CFLAGS='-O1 -fno-omit-frame-pointer -gline-tables-only -Wno-error=enum-constexpr-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int  -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -I/src/wget_deps/include -L/src/wget_deps/lib' ./configure --with-nettle-mini --enable-gcc-warnings --enable-static --disable-shared --with-included-libtasn1 --with-included-unistring --without-p11-kit --disable-doc --disable-tests --disable-tools --disable-cxx --disable-maintainer-mode --disable-libdane --disable-gcc-warnings --disable-full-test-suite --prefix=/src/wget_deps --disable-hardware-acceleration

```

notice, that the `LIBS=-lunistring` isn't there.


Wait that wasn't it. I don't understand why the wget shit won't compile. Maybe it has to do something with:

```

oof@oof-h8-1440eo:~/fuzz_wget/abc/wget$ autoreconf -fi^C
oof@oof-h8-1440eo:~/fuzz_wget/abc/wget$ export GNULIB_SRCDIR=/home/oof/fuzz_wget/abc/oof/gnulib
oof@oof-h8-1440eo:~/fuzz_wget/abc/wget$ autoreconf -fi
autopoint: using AM_GNU_GETTEXT_REQUIRE_VERSION instead of AM_GNU_GETTEXT_VERSION
Copying file build-aux/config.rpath
Copying file m4/host-cpu-c-abi.m4
Copying file m4/iconv.m4


```


No, the GNULIB_SRC environment variable has nothing to do with the compiler errors... fuck!!!!


```

autopoint: using AM_GNU_GETTEXT_REQUIRE_VERSION instead of AM_GNU_GETTEXT_VERSION
configure.ac:940: warning: macro 'AM_PATH_GPGME' not found in library
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/setlocale_null.m4:8: gl_FUNC_SETLOCALE_NULL is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/iswblank.m4:8: gl_FUNC_ISWBLANK is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/mbrtowc.m4:9: gl_FUNC_MBRTOWC is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/nl_langinfo.m4:8: gl_FUNC_NL_LANGINFO is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/setlocale_null.m4:8: gl_FUNC_SETLOCALE_NULL is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/iswblank.m4:8: gl_FUNC_ISWBLANK is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/mbrtowc.m4:9: gl_FUNC_MBRTOWC is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/nl_langinfo.m4:8: gl_FUNC_NL_LANGINFO is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/setlocale_null.m4:8: gl_FUNC_SETLOCALE_NULL is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/iswblank.m4:8: gl_FUNC_ISWBLANK is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/mbrtowc.m4:9: gl_FUNC_MBRTOWC is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/nl_langinfo.m4:8: gl_FUNC_NL_LANGINFO is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/setlocale_null.m4:8: gl_FUNC_SETLOCALE_NULL is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/iswblank.m4:8: gl_FUNC_ISWBLANK is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/mbrtowc.m4:9: gl_FUNC_MBRTOWC is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_PTHREADLIB is m4_require'd but not m4_defun'd
m4/nl_langinfo.m4:8: gl_FUNC_NL_LANGINFO is expanded from...
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure.ac:337: warning: gl_TYPE_WINT_T_PREREQ is m4_require'd but not m4_defun'd
m4/gnulib-comp.m4:461: gl_INIT is expanded from...
configure.ac:337: the top level
configure:22414: error: possibly undefined macro: gl_PTHREADLIB
      If this token and others are legitimate, please use m4_pattern_allow.
      See the Autoconf documentation.
configure:22526: error: possibly undefined macro: gl_WEAK_SYMBOLS
configure:24102: error: possibly undefined macro: gl_TYPE_WINT_T_PREREQ
autoreconf: /usr/bin/autoconf failed with exit status: 1
root@567d393065f8:/src/wget#


```

This almost works...

I get this error:

```

gnutls.c:805:13: warning: call to undeclared function 'gnutls_protocol_set_priority'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
  805 |       err = gnutls_protocol_set_priority (session, allowed_protocols);
      |             ^
1 warning generated.
1 warning generated.
  CCLD     wget
/usr/bin/ld: /src/wget_deps/lib/libhogweed.a(gmp-glue.o): in function `mpn_cnd_add_n':
/src/nettle/gmp-glue.c:46: multiple definition of `mpn_cnd_add_n'; /src/wget_deps/lib/libgnutls.a(gmp-glue.o):/src/gnutls/lib/nettle/backport/gmp-glue.c:46: first defined here
/usr/bin/ld: /src/wget_deps/lib/libhogweed.a(gmp-glue.o): in function `mpn_cnd_sub_n':
/src/nettle/gmp-glue.c:67: multiple definition of `mpn_cnd_sub_n'; /src/wget_deps/lib/libgnutls.a(gmp-glue.o):/src/gnutls/lib/nettle/backport/gmp-glue.c:67: first defined here
/usr/bin/ld: /src/wget_deps/lib/libhogweed.a(gmp-glue.o): in function `mpn_cnd_swap':
/src/nettle/gmp-glue.c:88: multiple definition of `mpn_cnd_swap'; /src/wget_deps/lib/libgnutls.a(gmp-glue.o):/src/gnutls/lib/nettle/backport/gmp-glue.c:88: first defined here
/usr/bin/ld: /src/wget_deps/lib/libhogweed.a(gmp-glue.o): in function `mpn_sec_tabselect':
/src/nettle/gmp-glue.c:107: multiple definition of `mpn_sec_tabselect'; /src/wget_deps/lib/libgnutls.a(gmp-glue.o):/src/gnutls/lib/nettle/backport/gmp-glue.c:107: first defined here
/usr/bin/ld: gnutls.o: in function `ssl_connect_wget':
/src/wget/src/gnutls.c:(.text.ssl_connect_wget[ssl_connect_wget]+0x543): undefined reference to `gnutls_protocol_set_priority'
clang: error: linker command failed with exit code 1 (use -v to see invocation)
make[3]: *** [Makefile:2225: wget] Error 1
make[3]: Leaving directory '/src/wget/src'
make[2]: *** [Makefile:2124: all] Error 2
make[2]: Leaving directory '/src/wget/src'
make[1]: *** [Makefile:2030: all-recursive] Error 1
make[1]: Leaving directory '/src/wget'
make: *** [Makefile:1982: all] Error 2
oof@oof-h8-1440eo:~/fuzz_wget/oss-fuzz$


```

fuck!!!!!!!!! This is quite bad!!!!

Let's focus on the multiple definition errors first. One quick and dirty way to deal with these is to just use this: https://stackoverflow.com/questions/69326932/multiple-definition-errors-during-gcc-linking-in-linux (aka. `--allow-multiple-definition`) . This (I think) is undefined behaviour, but I don't really care. Let's add `--allow-multiple-definition` to `CFLAGS` before compiling and see what happens.

Here is my current build.sh file:

```


#!/bin/bash -eu
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

export WGET_DEPS_PATH=$SRC/wget_deps
export PKG_CONFIG_PATH=$WGET_DEPS_PATH/lib64/pkgconfig:$WGET_DEPS_PATH/lib/pkgconfig
export CPPFLAGS="-I$WGET_DEPS_PATH/include"
export CFLAGS="$CFLAGS -I$WGET_DEPS_PATH/include -L$WGET_DEPS_PATH/lib"
export LDFLAGS="-L$WGET_DEPS_PATH/lib"
export GNULIB_SRCDIR=$SRC/gnulib
export LLVM_PROFILE_FILE=/tmp/prof.test

cd $SRC/libunistring
./configure --enable-static --disable-shared --prefix=$WGET_DEPS_PATH --cache-file ../config.cache
make -j$(nproc)
make install

cd $SRC/libidn2
./configure --enable-static --disable-shared --disable-doc --disable-gcc-warnings --prefix=$WGET_DEPS_PATH --cache-file ../config.cache
make -j$(nproc)
make install

cd $SRC/libpsl
./autogen.sh
./configure --enable-static --disable-shared --disable-gtk-doc --enable-runtime=libidn2 --enable-builtin=libidn2 --prefix=$WGET_DEPS_PATH --cache-file ../config.cache
make -j$(nproc)
make install

GNUTLS_CONFIGURE_FLAGS=""
NETTLE_CONFIGURE_FLAGS=""
if [[ $CFLAGS = *sanitize=memory* ]] || [[ $CFLAGS = *sanitize=address* ]] || [[ $CFLAGS = *sanitize=undefined* ]]; then
  GNUTLS_CONFIGURE_FLAGS="--disable-hardware-acceleration"
  NETTLE_CONFIGURE_FLAGS="--disable-assembler --disable-fat"
fi

# We could use GMP from git repository to avoid false positives in
# sanitizers, but GMP doesn't compile with clang. We use gmp-mini
# instead.
cd $SRC/nettle
git checkout 8be0d5c4cbb0a1f1939e314418af6c10d26da70d # This specific commit is needed, because reasons...
bash .bootstrap
./configure --enable-mini-gmp --enable-static --disable-shared --disable-documentation --disable-openssl --prefix=$WGET_DEPS_PATH $NETTLE_CONFIGURE_FLAGS --cache-file ../config.cache
( make -j$(nproc) || make -j$(nproc) ) && make install
if test $? != 0;then
        echo "Failed to compile nettle"
        exit 1
fi

cd $SRC/gnutls
touch .submodule.stamp
./bootstrap
GNUTLS_CFLAGS=`echo $CFLAGS|sed s/-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION//`

LIBS="-lunistring" \
CFLAGS="$GNUTLS_CFLAGS" \
./configure --with-nettle-mini --enable-gcc-warnings --enable-static --disable-shared --with-included-libtasn1 \
    --with-included-unistring --without-p11-kit --disable-doc --disable-tests --disable-tools --disable-cxx \
    --disable-maintainer-mode --disable-libdane --disable-gcc-warnings --disable-full-test-suite \
    --prefix=$WGET_DEPS_PATH $GNUTLS_CONFIGURE_FLAGS
make -j$(nproc)
make install


# avoid iconv() memleak on Ubuntu 16.04 image (breaks test suite)
export ASAN_OPTIONS=detect_leaks=0

# Ensure our libraries can be found
ln -s $WGET_DEPS_PATH/lib64/libhogweed.a $WGET_DEPS_PATH/lib/libhogweed.a
ln -s $WGET_DEPS_PATH/lib64/libnettle.a  $WGET_DEPS_PATH/lib/libnettle.a

cd $SRC/wget
./bootstrap --skip-po
#autoreconf -fi # This fucks shit up, so skip over this step. This doesn't seem to affect other things.

# We need to add "--allow-multiple-definition" to the compiler flags before compiling to avoid some errors.

ORIG_CFLAGS="$CFLAGS"

# build and run non-networking tests
CFLAGS="$ORIG_CFLAGS --allow-multiple-definition" \
LIBS="-lgnutls -lhogweed -lnettle -lidn2 -lunistring -lpsl -lz" \
./configure -C
make clean
make -j$(nproc)
make -j$(nproc) -C fuzz check

# build for fuzzing
LIBS="-lgnutls -lhogweed -lnettle -lidn2 -lunistring -lpsl -lz" \
./configure --enable-fuzzing -C
make clean
make -j$(nproc) -C lib
make -j$(nproc) -C src

# build fuzzers
cd fuzz
make -j$(nproc) ../src/libunittest.a
make oss-fuzz

find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer.options' -exec cp -v '{}' $OUT ';'

for dir in *_fuzzer.in; do
  fuzzer=$(basename $dir .in)
  zip -rj "$OUT/${fuzzer}_seed_corpus.zip" "${dir}/"
done


```

there is just the tiny problem, that clang doesn't have any option which corresponds to `--allow-multiple-definition` in gcc . Fuck!!!







Let's focus on this error first:

```
/src/wget/src/gnutls.c:(.text.ssl_connect_wget[ssl_connect_wget]+0x543): undefined reference to `gnutls_protocol_set_priority'
clang: error: linker command failed with exit code 1 (use -v to see invocation)
```

after a quick google search, I found this: https://lists.gnu.org/archive/html/bug-wget/2020-05/msg00023.html



```

CFLAGS="$ORIG_CFLAGS -Wall -Wl,--allow-multiple-definition" \
LIBS="-lgnutls -lhogweed -lnettle -lidn2 -lunistring -lpsl -lz" \
./configure -C

```



```

CFLAGS="$CFLAGS --allow-multiple-definition" \
LIBS="-lgnutls -lhogweed -lnettle -lidn2 -lunistring -lpsl -lz" \
./configure -C

```


While the other compilation is running, let's try to figure out the other thing...

We need to replace all instances of `gnutls_protocol_set_priority` with `gnutls_priority_set_direct`

looking at the newest code:

```


static int
set_prio_default (gnutls_session_t session)
{
  int err = -1;

#if HAVE_GNUTLS_PRIORITY_SET_DIRECT
  switch (opt.secure_protocol)
    {
    case secure_protocol_auto:
      err = gnutls_set_default_priority (session);
      gnutls_session_enable_compatibility_mode(session);
      break;

    case secure_protocol_sslv2:
    case secure_protocol_sslv3:
      err = gnutls_priority_set_direct (session, "NORMAL:-VERS-TLS-ALL:+VERS-SSL3.0", NULL);
      break;

    case secure_protocol_tlsv1:
      err = gnutls_priority_set_direct (session, "NORMAL:-VERS-SSL3.0", NULL);
      break;

    case secure_protocol_tlsv1_1:
      err = gnutls_priority_set_direct (session, "NORMAL:-VERS-SSL3.0:-VERS-TLS1.0", NULL);
      break;

    case secure_protocol_tlsv1_2:
      err = gnutls_priority_set_direct (session, "NORMAL:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1", NULL);
      break;

    case secure_protocol_tlsv1_3:
#if GNUTLS_VERSION_NUMBER >= 0x030603
      err = gnutls_priority_set_direct (session, "NORMAL:-VERS-SSL3.0:+VERS-TLS1.3:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-TLS1.2", NULL);
      break;
#else
      logprintf (LOG_NOTQUIET, _("Your GnuTLS version is too old to support TLS 1.3\n"));
      return -1;
#endif

    case secure_protocol_pfs:
      err = gnutls_priority_set_direct (session, "PFS:-VERS-SSL3.0", NULL);
      if (err != GNUTLS_E_SUCCESS)
        /* fallback if PFS is not available */
        err = gnutls_priority_set_direct (session, "NORMAL:-RSA:-VERS-SSL3.0", NULL);
      break;

    default:
      logprintf (LOG_NOTQUIET, _("GnuTLS: unimplemented 'secure-protocol' option value %u\n"),
                 (unsigned) opt.secure_protocol);
      logprintf (LOG_NOTQUIET, _("Please report this issue to bug-wget@gnu.org\n"));
      abort ();
    }
#else
  int allowed_protocols[4] = {0, 0, 0, 0};
  switch (opt.secure_protocol)
    {
    case secure_protocol_auto:
      err = gnutls_set_default_priority (session);
      break;

    case secure_protocol_sslv2:
    case secure_protocol_sslv3:
      allowed_protocols[0] = GNUTLS_SSL3;
      err = gnutls_protocol_set_priority (session, allowed_protocols);
      break;

    case secure_protocol_tlsv1:
      allowed_protocols[0] = GNUTLS_TLS1_0;
      allowed_protocols[1] = GNUTLS_TLS1_1;
      allowed_protocols[2] = GNUTLS_TLS1_2;
#if GNUTLS_VERSION_NUMBER >= 0x030603
      allowed_protocols[3] = GNUTLS_TLS1_3;
#endif
      err = gnutls_protocol_set_priority (session, allowed_protocols);
      break;

    case secure_protocol_tlsv1_1:
      allowed_protocols[0] = GNUTLS_TLS1_1;
      allowed_protocols[1] = GNUTLS_TLS1_2;
#if GNUTLS_VERSION_NUMBER >= 0x030603
      allowed_protocols[2] = GNUTLS_TLS1_3;
#endif
      err = gnutls_protocol_set_priority (session, allowed_protocols);
      break;

    case secure_protocol_tlsv1_2:
      allowed_protocols[0] = GNUTLS_TLS1_2;
#if GNUTLS_VERSION_NUMBER >= 0x030603
      allowed_protocols[1] = GNUTLS_TLS1_3;
#endif
      err = gnutls_protocol_set_priority (session, allowed_protocols);
      break;

    case secure_protocol_tlsv1_3:
#if GNUTLS_VERSION_NUMBER >= 0x030603
      allowed_protocols[0] = GNUTLS_TLS1_3;
      err = gnutls_protocol_set_priority (session, allowed_protocols);
      break;
#else
      logprintf (LOG_NOTQUIET, _("Your GnuTLS version is too old to support TLS 1.3\n"));
      return -1;
#endif

    default:
      logprintf (LOG_NOTQUIET, _("GnuTLS: unimplemented 'secure-protocol' option value %d\n"), opt.secure_protocol);
      logprintf (LOG_NOTQUIET, _("Please report this issue to bug-wget@gnu.org\n"));
      abort ();
    }
#endif

  return err;
}

```

why doesn't the `HAVE_GNUTLS_PRIORITY_SET_DIRECT` macro work????? Maybe that is the `autoreconf -fi` stuff solves. We removed that shit out of the build.sh script.

Here is the final part of the output when compiling:

```


clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       libgnu_a-quotearg.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       libgnu_a-same-inode.o
  CC       libgnu_a-save-cwd.o
  CC       libgnu_a-setlocale_null.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       libgnu_a-setlocale_null-unlocked.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       libgnu_a-sig-handler.o
  CC       libgnu_a-sockets.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       libgnu_a-spawn-pipe.o
  CC       libgnu_a-stat-time.o
  CC       libgnu_a-strnlen1.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       libgnu_a-sys_socket.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       libgnu_a-tempname.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       glthread/libgnu_a-threadlib.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       libgnu_a-timespec.o
  CC       libgnu_a-tmpdir.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       libgnu_a-u64.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       libgnu_a-unistd.o
  CC       libgnu_a-dup-safer.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       libgnu_a-fd-safer.o
  CC       libgnu_a-pipe-safer.o
  CC       libgnu_a-utimens.o
clangclang: : warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]warning:
-Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       libgnu_a-wait-process.o
  CC       libgnu_a-wctype-h.o
clangclang: warning: : warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]-Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]

clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       libgnu_a-xmalloc.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       libgnu_a-xalloc-die.o
  CC       libgnu_a-xmemdup0.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       libgnu_a-xsize.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       libgnu_a-xstrndup.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       fopen.o
  CC       mbsrtoc32s-state.o
  CC       mbsrtowcs-state.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       mktime.o
  CC       strerror_r.o
  CC       malloc/libgnu_a-dynarray_at_failure.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       malloc/libgnu_a-dynarray_emplace_enlarge.o
  CC       malloc/libgnu_a-dynarray_finalize.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       malloc/libgnu_a-dynarray_resize.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       malloc/libgnu_a-dynarray_resize_clear.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       malloc/libgnu_a-scratch_buffer_grow.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       malloc/libgnu_a-scratch_buffer_grow_preserve.o
  CC       malloc/libgnu_a-scratch_buffer_set_array_size.o
  CC       glthread/libgnu_a-lock.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       unicase/libgnu_a-cased.o
  CC       unicase/libgnu_a-ignorable.o
  CC       unicase/libgnu_a-special-casing.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]  CC       unicase/libgnu_a-u8-casemap.o

clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       uninorm/libgnu_a-decompose-internal.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  AR       libgnu.a
make[3]: Leaving directory '/src/wget/lib'
make[2]: Leaving directory '/src/wget/lib'
Making all in src
make[2]: Entering directory '/src/wget/src'
make  all-am
make[3]: Entering directory '/src/wget/src'
flex  -ocss.c css.l
  CC       connect.o
  CC       convert.o
  CC       cookies.o
  CC       ftp.o
  CC       css-url.o
  CC       ftp-basic.o
  CC       ftp-ls.o
css.l:161: warning, the character range [*-[] is ambiguous in a case-insensitive scanner
css.l:161: warning, the character range []-~] is ambiguous in a case-insensitive scanner
clangclang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]clang: warning:
argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
: warning: clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]clang
-Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]:
warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
-Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: clangargument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
: warning: clangargument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       hash.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       host.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       hsts.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       html-parse.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       html-url.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       http.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       init.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       log.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       main.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       netrc.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
init.c:1375:49: warning: implicit conversion from 'long' to 'double' changes value from 9223372036854775807 to 9223372036854775808 [-Wimplicit-const-int-float-conversion]
 1375 |       || byte_value < WGINT_MIN || byte_value > WGINT_MAX)
      |                                               ~ ^~~~~~~~~
./wget.h:145:19: note: expanded from macro 'WGINT_MAX'
  145 | #define WGINT_MAX INT64_MAX
      |                   ^~~~~~~~~
/usr/include/stdint.h:113:22: note: expanded from macro 'INT64_MAX'
  113 | # define INT64_MAX              (__INT64_C(9223372036854775807))
      |                                  ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/usr/include/stdint.h:95:24: note: expanded from macro '__INT64_C'
   95 | #  define __INT64_C(c)  c ## L
      |                         ^~~~~~
<scratch space>:16:1: note: expanded from here
   16 | 9223372036854775807L
      | ^~~~~~~~~~~~~~~~~~~~
  CC       progress.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       ptimer.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       recur.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       res.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       retr.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       spider.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
1 warning generated.
  CC       url.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       warc.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       utils.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       exits.o
if test -n ""; then cp "./build_info.c.in" .; fi
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       iri.o
/usr/bin/perl "../build-aux/build_info.pl" \
    "../src/build_info.c"
In file included from warc.c:44:
../lib/base32.h:58:13: warning: result of comparison of constant 256 with expression of type 'unsigned char' is always true [-Wtautological-constant-out-of-range-compare]
   58 |   return ch < sizeof base32_to_int && 0 <= base32_to_int[ch];
      |          ~~ ^ ~~~~~~~~~~~~~~~~~~~~
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
if test -n ""; then rm -f build_info.c.in; fi
  CC       xattr.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       ftp-opie.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
iri.c:134:20: warning: variable 'tooshort' set but not used [-Wunused-but-set-variable]
  134 |   int invalid = 0, tooshort = 0;
      |                    ^
  CC       http-ntlm.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
1 warning generated.
  CC       gnutls.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
echo '#include "wget.h"' > css_.c
cat css.c >> css_.c
  CC       build_info.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
echo '/* version.c */' > version.c
echo '/* Autogenerated by Makefile - DO NOT EDIT */' >> version.c
echo '' >> version.c
echo '#include "version.h"' >> version.c
echo 'const char *version_string = "1.24.5.7-ca10";' >> version.c
echo 'const char *compilation_string = "'clang -DHAVE_CONFIG_H -DSYSTEM_WGETRC=\"/usr/local/etc/wgetrc\" -DLOCALEDIR=\"/usr/local/share/locale\" -I.  -I../lib -I../lib  -I/src/wget_deps/include    -I/src/wget_deps/include -I/src/wget_deps/include -I/src/wget_deps/include -DHAVE_LIBGNUTLS  -I/src/wget_deps/include -DNDEBUG -O1 -fno-omit-frame-pointer -gline-tables-only -Wno-error=enum-constexpr-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -I/src/wget_deps/include -L/src/wget_deps/lib -Wall -Wl,--allow-multiple-definition'";' \
    | sed -e 's/[\\"]/\\&/g' -e 's/\\"/"/' -e 's/\\";$/";/' >> version.c
echo 'const char *link_string = "'clang    -I/src/wget_deps/include -I/src/wget_deps/include -I/src/wget_deps/include -DHAVE_LIBGNUTLS  -I/src/wget_deps/include -DNDEBUG -O1 -fno-omit-frame-pointer -gline-tables-only -Wno-error=enum-constexpr-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -I/src/wget_deps/include -L/src/wget_deps/lib -Wall -Wl,--allow-multiple-definition \
 -L/src/wget_deps/lib -L/src/wget_deps/lib -lidn2 -L/src/wget_deps/lib64 -lnettle -L/src/wget_deps/lib -lgnutls -lz -L/src/wget_deps/lib -lpsl -lgnutls -lhogweed -lnettle -lidn2 -lunistring -lpsl -lz   ../lib/libgnu.a             /src/wget_deps/lib/libunistring.a       '";' \
    | sed -e 's/[\\"]/\\&/g' -e 's/\\"/"/' -e 's/\\";$/";/' >> version.c
  CC       css_.o
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CC       version.o
1 warning generated.
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CCLD     wget
make[3]: Leaving directory '/src/wget/src'
make[2]: Leaving directory '/src/wget/src'
Making all in doc
make[2]: Entering directory '/src/wget/doc'
sed s/@/@@/g sample.wgetrc > sample.wgetrc.munged_for_texi_inclusion
Updating ./version.texi
./texi2pod.pl -D VERSION="1.24.5.7-ca10" ./wget.texi wget.pod
  MAKEINFO wget.info
/usr/bin/pod2man --center="GNU Wget" --release="GNU Wget 1.24.5.7-ca10" --utf8 wget.pod > wget.1 || \
/usr/bin/pod2man --center="GNU Wget" --release="GNU Wget 1.24.5.7-ca10" wget.pod > wget.1
make[2]: Leaving directory '/src/wget/doc'
Making all in po
make[2]: Entering directory '/src/wget/po'
make wget.pot-update
make[3]: Entering directory '/src/wget/po'
sed -e '/^#/d' remove-potcdate.sin > t-remove-potcdate.sed
mv t-remove-potcdate.sed remove-potcdate.sed
package_gnu="yes"; \
test -n "$package_gnu" || { \
  if { if (LC_ALL=C find --version) 2>/dev/null | grep GNU >/dev/null; then \
	 LC_ALL=C find -L .. -maxdepth 1 -type f \
		       -size -10000000c -exec grep 'GNU wget' \
		       /dev/null '{}' ';' 2>/dev/null; \
       else \
	 LC_ALL=C grep 'GNU wget' ../* 2>/dev/null; \
       fi; \
     } | grep -v 'libtool:' >/dev/null; then \
     package_gnu=yes; \
   else \
     package_gnu=no; \
   fi; \
}; \
if test "$package_gnu" = "yes"; then \
  package_prefix='GNU '; \
else \
  package_prefix=''; \
fi; \
if test -n 'bug-wget@gnu.org' || test 'bug-wget@gnu.org' = '@'PACKAGE_BUGREPORT'@'; then \
  msgid_bugs_address='bug-wget@gnu.org'; \
else \
  msgid_bugs_address='bug-wget@gnu.org'; \
fi; \
case `/usr/bin/xgettext --version | sed 1q | sed -e 's,^[^0-9]*,,'` in \
  '' | 0.[0-9] | 0.[0-9].* | 0.1[0-5] | 0.1[0-5].* | 0.16 | 0.16.[0-1]*) \
    /usr/bin/xgettext --default-domain=wget --directory=.. \
      --add-comments=TRANSLATORS: --keyword=_ --keyword=N_ --flag=_:1:pass-c-format --flag=N_:1:pass-c-format --flag=error:3:c-format --flag=error_at_line:5:c-format ${end_of_xgettext_options+}  --flag=error:3:c-format --flag=error_at_line:5:c-format --flag=asprintf:2:c-format --flag=vasprintf:2:c-format \
      --files-from=./POTFILES.in \
      --copyright-holder='Free Software Foundation, Inc.' \
      --msgid-bugs-address="$msgid_bugs_address" \
    ;; \
  *) \
    /usr/bin/xgettext --default-domain=wget --directory=.. \
      --add-comments=TRANSLATORS: --keyword=_ --keyword=N_ --flag=_:1:pass-c-format --flag=N_:1:pass-c-format --flag=error:3:c-format --flag=error_at_line:5:c-format ${end_of_xgettext_options+}  --flag=error:3:c-format --flag=error_at_line:5:c-format --flag=asprintf:2:c-format --flag=vasprintf:2:c-format \
      --files-from=./POTFILES.in \
      --copyright-holder='Free Software Foundation, Inc.' \
      --package-name="${package_prefix}wget" \
      --package-version='1.24.5.7-ca10' \
      --msgid-bugs-address="$msgid_bugs_address" \
    ;; \
esac
test ! -f wget.po || { \
  if test -f ./wget.pot-header; then \
    sed -e '1,/^#$/d' < wget.po > wget.1po && \
    cat ./wget.pot-header wget.1po > wget.po; \
    rm -f wget.1po; \
  fi; \
  if test -f ./wget.pot; then \
    sed -f remove-potcdate.sed < ./wget.pot > wget.1po && \
    sed -f remove-potcdate.sed < wget.po > wget.2po && \
    if cmp wget.1po wget.2po >/dev/null 2>&1; then \
      rm -f wget.1po wget.2po wget.po; \
    else \
      rm -f wget.1po wget.2po ./wget.pot && \
      mv wget.po ./wget.pot; \
    fi; \
  else \
    mv wget.po ./wget.pot; \
  fi; \
}
make[3]: Leaving directory '/src/wget/po'
test ! -f ./wget.pot || \
  test -z "" || make
touch stamp-po
make[2]: Leaving directory '/src/wget/po'
Making all in gnulib_po
make[2]: Entering directory '/src/wget/gnulib_po'
make wget-gnulib.pot-update
make[3]: Entering directory '/src/wget/gnulib_po'
sed -e '/^#/d' remove-potcdate.sin > t-remove-potcdate.sed
mv t-remove-potcdate.sed remove-potcdate.sed
package_gnu=""; \
test -n "$package_gnu" || { \
  if { if (LC_ALL=C find --version) 2>/dev/null | grep GNU >/dev/null; then \
         LC_ALL=C find -L .. -maxdepth 1 -type f -size -10000000c -exec grep -i 'GNU wget' /dev/null '{}' ';' 2>/dev/null; \
       else \
         LC_ALL=C grep -i 'GNU wget' ../* 2>/dev/null; \
       fi; \
     } | grep -v 'libtool:' >/dev/null; then \
     package_gnu=yes; \
   else \
     package_gnu=no; \
   fi; \
}; \
if test "$package_gnu" = "yes"; then \
  package_prefix='GNU '; \
else \
  package_prefix=''; \
fi; \
if test -n 'bug-gnulib@gnu.org' || test 'bug-wget@gnu.org' = '@'PACKAGE_BUGREPORT'@'; then \
  msgid_bugs_address='bug-gnulib@gnu.org'; \
else \
  msgid_bugs_address='bug-wget@gnu.org'; \
fi; \
case `/usr/bin/xgettext --version | sed 1q | sed -e 's,^[^0-9]*,,'` in \
  '' | 0.[0-9] | 0.[0-9].* | 0.1[0-5] | 0.1[0-5].* | 0.16 | 0.16.[0-1]*) \
    /usr/bin/xgettext --default-domain=wget-gnulib --directory=.. \
      --add-comments=TRANSLATORS: \
      --files-from=./POTFILES.in \
      --copyright-holder='Free Software Foundation, Inc.' \
      --msgid-bugs-address="$msgid_bugs_address" \
      --keyword=_ --flag=_:1:pass-c-format --keyword=N_ --flag=N_:1:pass-c-format --keyword='proper_name:1,"This is a proper name. See the gettext manual, section Names."' --keyword='proper_name_lite:1,"This is a proper name. See the gettext manual, section Names."' --keyword='proper_name_utf8:1,"This is a proper name. See the gettext manual, section Names."' --flag=error:3:c-format --flag=error_at_line:5:c-format  --flag=error:3:c-format --flag=error_at_line:5:c-format --flag=asprintf:2:c-format --flag=vasprintf:2:c-format \
    ;; \
  *) \
    /usr/bin/xgettext --default-domain=wget-gnulib --directory=.. \
      --add-comments=TRANSLATORS: \
      --files-from=./POTFILES.in \
      --copyright-holder='Free Software Foundation, Inc.' \
      --package-name="${package_prefix}wget" \
      --package-version='1.24.5.7-ca10' \
      --msgid-bugs-address="$msgid_bugs_address" \
      --keyword=_ --flag=_:1:pass-c-format --keyword=N_ --flag=N_:1:pass-c-format --keyword='proper_name:1,"This is a proper name. See the gettext manual, section Names."' --keyword='proper_name_lite:1,"This is a proper name. See the gettext manual, section Names."' --keyword='proper_name_utf8:1,"This is a proper name. See the gettext manual, section Names."' --flag=error:3:c-format --flag=error_at_line:5:c-format  --flag=error:3:c-format --flag=error_at_line:5:c-format --flag=asprintf:2:c-format --flag=vasprintf:2:c-format \
    ;; \
esac
/usr/bin/xgettext: warning: file 'lib/libunistring.valgrind' extension 'valgrind' is unknown; will try C
/usr/bin/xgettext: warning: file 'lib/memchr.valgrind' extension 'valgrind' is unknown; will try C
/usr/bin/xgettext: warning: file 'lib/rawmemchr.valgrind' extension 'valgrind' is unknown; will try C
/usr/bin/xgettext: warning: file 'lib/strchrnul.valgrind' extension 'valgrind' is unknown; will try C
/usr/bin/xgettext: warning: file 'lib/unicase/special-casing-table.gperf' extension 'gperf' is unknown; will try C
test ! -f wget-gnulib.po || { \
  if test -f ./wget-gnulib.pot-header; then \
    sed -e '1,/^#$/d' < wget-gnulib.po > wget-gnulib.1po && \
    cat ./wget-gnulib.pot-header wget-gnulib.1po > wget-gnulib.po && \
    rm -f wget-gnulib.1po \
    || exit 1; \
  fi; \
  if test -f ./wget-gnulib.pot; then \
    sed -f remove-potcdate.sed < ./wget-gnulib.pot > wget-gnulib.1po && \
    sed -f remove-potcdate.sed < wget-gnulib.po > wget-gnulib.2po && \
    if cmp wget-gnulib.1po wget-gnulib.2po >/dev/null 2>&1; then \
      rm -f wget-gnulib.1po wget-gnulib.2po wget-gnulib.po; \
    else \
      rm -f wget-gnulib.1po wget-gnulib.2po ./wget-gnulib.pot && \
      mv wget-gnulib.po ./wget-gnulib.pot; \
    fi; \
  else \
    mv wget-gnulib.po ./wget-gnulib.pot; \
  fi; \
}
make[3]: Leaving directory '/src/wget/gnulib_po'
*** error: gettext infrastructure mismatch: using a Makefile.in.in from gettext version 0.20 but the autoconf macros are from gettext version 0.19
make[2]: *** [Makefile:765: stamp-po] Error 1
make[2]: Leaving directory '/src/wget/gnulib_po'
make[1]: *** [Makefile:2030: all-recursive] Error 1
make[1]: Leaving directory '/src/wget'
make: *** [Makefile:1982: all] Error 2




```

we are actually linking `wget` succesfully!


See here:

```

1 warning generated.
clang: warning: -Wl,--allow-multiple-definition: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-L/src/wget_deps/lib' [-Wunused-command-line-argument]
  CCLD     wget
make[3]: Leaving directory '/src/wget/src'
make[2]: Leaving directory '/src/wget/src'

```



but then it fails in the building of the docs , we don't really need the docs for anything, so let's just skip those for now. We can add `--disable-doc` to the configuration flags and then try again...

After adding `--disable-doc` , I get these errors:

```

./bootstrap: done.  Now you can run './configure'.
+ ORIG_CFLAGS='-O1 -fno-omit-frame-pointer -gline-tables-only -Wno-error=enum-constexpr-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -I/src/wget_deps/include -L/src/wget_deps/lib'
+ CFLAGS='-O1 -fno-omit-frame-pointer -gline-tables-only -Wno-error=enum-constexpr-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -I/src/wget_deps/include -L/src/wget_deps/lib -Wall -Wl,--allow-multiple-definition'
+ LIBS='-lgnutls -lhogweed -lnettle -lidn2 -lunistring -lpsl -lz'
+ ./configure -C --disable-doc
configure: WARNING: unrecognized options: --disable-doc

```

Fuck!!!!!

Why does the differences in versions have to always fuck me up?

Here is all of the make targets in the wget source code:

```
Making all in lib
Making all in src
Making all in doc
Making all in po
Making all in gnulib_po
Making all in util
Making all in fuzz
Making all in tests
Making all in testenv
```

Ok, so here is the stuff:

```

touch stamp-po
make[2]: Leaving directory '/src/wget/po'
Making all in gnulib_po
make[2]: Entering directory '/src/wget/gnulib_po'
make wget-gnulib.pot-update
make[3]: Entering directory '/src/wget/gnulib_po'
sed -e '/^#/d' remove-potcdate.sin > t-remove-potcdate.sed
mv t-remove-potcdate.sed remove-potcdate.sed
package_gnu=""; \
test -n "$package_gnu" || { \
  if { if (LC_ALL=C find --version) 2>/dev/null | grep GNU >/dev/null; then \
         LC_ALL=C find -L .. -maxdepth 1 -type f -size -10000000c -exec grep -i 'GNU wget' /dev/null '{}' ';' 2>/dev/null; \
       else \
         LC_ALL=C grep -i 'GNU wget' ../* 2>/dev/null; \
       fi; \
     } | grep -v 'libtool:' >/dev/null; then \
     package_gnu=yes; \
   else \
     package_gnu=no; \
   fi; \
}; \
if test "$package_gnu" = "yes"; then \
  package_prefix='GNU '; \
else \
  package_prefix=''; \
fi; \
if test -n 'bug-gnulib@gnu.org' || test 'bug-wget@gnu.org' = '@'PACKAGE_BUGREPORT'@'; then \
  msgid_bugs_address='bug-gnulib@gnu.org'; \
else \
  msgid_bugs_address='bug-wget@gnu.org'; \
fi; \
case `/usr/bin/xgettext --version | sed 1q | sed -e 's,^[^0-9]*,,'` in \
  '' | 0.[0-9] | 0.[0-9].* | 0.1[0-5] | 0.1[0-5].* | 0.16 | 0.16.[0-1]*) \
    /usr/bin/xgettext --default-domain=wget-gnulib --directory=.. \
      --add-comments=TRANSLATORS: \
      --files-from=./POTFILES.in \
      --copyright-holder='Free Software Foundation, Inc.' \
      --msgid-bugs-address="$msgid_bugs_address" \
      --keyword=_ --flag=_:1:pass-c-format --keyword=N_ --flag=N_:1:pass-c-format --keyword='proper_name:1,"This is a proper name. See the gettext manual, section Names."' --keyword='proper_name_lite:1,"This is a proper name. See the gettext manual, section Names."' --keyword='proper_name_utf8:1,"This is a proper name. See the gettext manual, section Names."' --flag=error:3:c-format --flag=error_at_line:5:c-format  --flag=error:3:c-format --flag=error_at_line:5:c-format --flag=asprintf:2:c-format --flag=vasprintf:2:c-format \
    ;; \
  *) \
    /usr/bin/xgettext --default-domain=wget-gnulib --directory=.. \
      --add-comments=TRANSLATORS: \
      --files-from=./POTFILES.in \
      --copyright-holder='Free Software Foundation, Inc.' \
      --package-name="${package_prefix}wget" \
      --package-version='1.24.5.7-ca10' \
      --msgid-bugs-address="$msgid_bugs_address" \
      --keyword=_ --flag=_:1:pass-c-format --keyword=N_ --flag=N_:1:pass-c-format --keyword='proper_name:1,"This is a proper name. See the gettext manual, section Names."' --keyword='proper_name_lite:1,"This is a proper name. See the gettext manual, section Names."' --keyword='proper_name_utf8:1,"This is a proper name. See the gettext manual, section Names."' --flag=error:3:c-format --flag=error_at_line:5:c-format  --flag=error:3:c-format --flag=error_at_line:5:c-format --flag=asprintf:2:c-format --flag=vasprintf:2:c-format \
    ;; \
esac
/usr/bin/xgettext: warning: file 'lib/libunistring.valgrind' extension 'valgrind' is unknown; will try C
/usr/bin/xgettext: warning: file 'lib/memchr.valgrind' extension 'valgrind' is unknown; will try C
/usr/bin/xgettext: warning: file 'lib/rawmemchr.valgrind' extension 'valgrind' is unknown; will try C
/usr/bin/xgettext: warning: file 'lib/strchrnul.valgrind' extension 'valgrind' is unknown; will try C
/usr/bin/xgettext: warning: file 'lib/unicase/special-casing-table.gperf' extension 'gperf' is unknown; will try C
test ! -f wget-gnulib.po || { \
  if test -f ./wget-gnulib.pot-header; then \
    sed -e '1,/^#$/d' < wget-gnulib.po > wget-gnulib.1po && \
    cat ./wget-gnulib.pot-header wget-gnulib.1po > wget-gnulib.po && \
    rm -f wget-gnulib.1po \
    || exit 1; \
  fi; \
  if test -f ./wget-gnulib.pot; then \
    sed -f remove-potcdate.sed < ./wget-gnulib.pot > wget-gnulib.1po && \
    sed -f remove-potcdate.sed < wget-gnulib.po > wget-gnulib.2po && \
    if cmp wget-gnulib.1po wget-gnulib.2po >/dev/null 2>&1; then \
      rm -f wget-gnulib.1po wget-gnulib.2po wget-gnulib.po; \
    else \
      rm -f wget-gnulib.1po wget-gnulib.2po ./wget-gnulib.pot && \
      mv wget-gnulib.po ./wget-gnulib.pot; \
    fi; \
  else \
    mv wget-gnulib.po ./wget-gnulib.pot; \
  fi; \
}
make[3]: Leaving directory '/src/wget/gnulib_po'
test ! -f ./wget-gnulib.pot || \
  test -z "af.gmo be.gmo bg.gmo ca.gmo cs.gmo da.gmo de.gmo el.gmo eo.gmo es.gmo et.gmo eu.gmo fi.gmo fr.gmo ga.gmo gl.gmo hu.gmo it.gmo ja.gmo ka.gmo ko.gmo ms.gmo nb.gmo nl.gmo pl.gmo pt.gmo pt_BR.gmo ro.gmo ru.gmo rw.gmo sk.gmo sl.gmo sr.gmo sv.gmo tr.gmo uk.gmo vi.gmo zh_CN.gmo zh_TW.gmo" || make af.gmo be.gmo bg.gmo ca.gmo cs.gmo da.gmo de.gmo el.gmo eo.gmo es.gmo et.gmo eu.gmo fi.gmo fr.gmo ga.gmo gl.gmo hu.gmo it.gmo ja.gmo ka.gmo ko.gmo ms.gmo nb.gmo nl.gmo pl.gmo pt.gmo pt_BR.gmo ro.gmo ru.gmo rw.gmo sk.gmo sl.gmo sr.gmo sv.gmo tr.gmo uk.gmo vi.gmo zh_CN.gmo zh_TW.gmo
make[3]: Entering directory '/src/wget/gnulib_po'
/usr/bin/msgmerge --update  --lang=af --previous af.po wget-gnulib.pot
/usr/bin/msgmerge --update  --lang=be --previous be.po wget-gnulib.pot
/usr/bin/msgmerge --update  --lang=ca --previous ca.po wget-gnulib.pot
/usr/bin/msgmerge --update  --lang=bg --previous bg.po wget-gnulib.pot
/usr/bin/msgmerge --update  --lang=cs --previous cs.po wget-gnulib.pot
/usr/bin/msgmerge --update  --lang=de --previous de.po wget-gnulib.pot
/usr/bin/msgmerge --update  --lang=da --previous da.po wget-gnulib.pot
/usr/bin/msgmerge --update  --lang=el --previous el.po wget-gnulib.pot
................................................................... done.
........... done.
........ done.
...... done.
...... done.
............ done.
./usr/bin/msgmerge --update  --lang=eo --previous eo.po wget-gnulib.pot
/usr/bin/msgmerge --update  --lang=es --previous es.po wget-gnulib.pot
 done.
/usr/bin/msgmerge --update  --lang=et --previous et.po wget-gnulib.pot
........../usr/bin/msgmerge --update  --lang=eu --previous eu.po wget-gnulib.pot
...... done.
./usr/bin/msgmerge --update  --lang=fi --previous fi.po wget-gnulib.pot
......./usr/bin/msgmerge --update  --lang=fr --previous fr.po wget-gnulib.pot
/usr/bin/msgmerge --update  --lang=ga --previous ga.po wget-gnulib.pot
...... done.
/usr/bin/msgmerge --update  --lang=gl --previous gl.po wget-gnulib.pot
..................... done.
............. done.
............./usr/bin/msgmerge --update  --lang=hu --previous hu.po wget-gnulib.pot
.......... done.
 done.
........./usr/bin/msgmerge --update  --lang=it --previous it.po wget-gnulib.pot
/usr/bin/msgmerge --update  --lang=ja --previous ja.po wget-gnulib.pot
/usr/bin/msgmerge --update  --lang=ka --previous ka.po wget-gnulib.pot
........ done.
........................................... done.
../usr/bin/msgmerge --update  --lang=ko --previous ko.po wget-gnulib.pot
...... done.
............... done.
/usr/bin/msgmerge --update  --lang=ms --previous ms.po wget-gnulib.pot
............ done.
.......... done.
. done.
/usr/bin/msgmerge --update  --lang=nb --previous nb.po wget-gnulib.pot
/usr/bin/msgmerge --update  --lang=nl --previous nl.po wget-gnulib.pot
/usr/bin/msgmerge --update  --lang=pl --previous pl.po wget-gnulib.pot
............./usr/bin/msgmerge --update  --lang=pt_BR --previous pt_BR.po wget-gnulib.pot
/usr/bin/msgmerge --update  --lang=ro --previous ro.po wget-gnulib.pot
/usr/bin/msgmerge --update  --lang=pt --previous pt.po wget-gnulib.pot
........... done.
..................................... done.
 done.
............. done.
......./usr/bin/msgmerge --update  --lang=ru --previous ru.po wget-gnulib.pot
............................ done.
........ done.
/usr/bin/msgmerge --update  --lang=sk --previous sk.po wget-gnulib.pot
........ done.
/usr/bin/msgmerge --update  --lang=sl --previous sl.po wget-gnulib.pot
/usr/bin/msgmerge --update  --lang=rw --previous rw.po wget-gnulib.pot
../usr/bin/msgmerge --update  --lang=sr --previous sr.po wget-gnulib.pot
......... done.
....../usr/bin/msgmerge --update  --lang=sv --previous sv.po wget-gnulib.pot
 done.
/usr/bin/msgmerge --update  --lang=tr --previous tr.po wget-gnulib.pot
.........../usr/bin/msgmerge --update  --lang=uk --previous uk.po wget-gnulib.pot
............... done.
................. done.
........... done.
.........../usr/bin/msgmerge --update  --lang=vi --previous vi.po wget-gnulib.pot
......................... done.
 done.
 done.
/usr/bin/msgmerge --update  --lang=zh_CN --previous zh_CN.po wget-gnulib.pot
rm -f af.gmo && /usr/bin/msgmerge @MSGMERGE_FOR_MSGFMT_OPTION@ -o af.1po af.po wget-gnulib.pot && /usr/bin/msgfmt -c --statistics --verbose -o af.gmo af.1po && rm -f af.1po
/usr/bin/msgmerge --update  --lang=zh_TW --previous zh_TW.po wget-gnulib.pot
rm -f be.gmo && /usr/bin/msgmerge @MSGMERGE_FOR_MSGFMT_OPTION@ -o be.1po be.po wget-gnulib.pot && /usr/bin/msgfmt -c --statistics --verbose -o be.gmo be.1po && rm -f be.1po
........./usr/bin/msgmerge: exactly 2 input files required
Try '/usr/bin/msgmerge --help' for more information.
make[3]: *** [Makefile:725: be.gmo] Error 1
make[3]: *** Waiting for unfinished jobs....
.....rm -f bg.gmo && /usr/bin/msgmerge @MSGMERGE_FOR_MSGFMT_OPTION@ -o bg.1po bg.po wget-gnulib.pot && /usr/bin/msgfmt -c --statistics --verbose -o bg.gmo bg.1po && rm -f bg.1po
...rm -f ca.gmo && /usr/bin/msgmerge @MSGMERGE_FOR_MSGFMT_OPTION@ -o ca.1po ca.po wget-gnulib.pot && /usr/bin/msgfmt -c --statistics --verbose -o ca.gmo ca.1po && rm -f ca.1po
.................... done.
 done.
/usr/bin/msgmerge: /usr/bin/msgmerge: exactly 2 input files required
exactly 2 input files required
Try '/usr/bin/msgmerge --help' for more information.
Try '/usr/bin/msgmerge --help' for more information.
make[3]: *** [Makefile:725: ca.gmo] Error 1
make[3]: *** [Makefile:725: bg.gmo] Error 1
............ done.
/usr/bin/msgmerge: exactly 2 input files required
Try '/usr/bin/msgmerge --help' for more information.
make[3]: *** [Makefile:725: af.gmo] Error 1
.................. done.
make[3]: Leaving directory '/src/wget/gnulib_po'
make[2]: *** [Makefile:766: stamp-po] Error 2
make[2]: Leaving directory '/src/wget/gnulib_po'
make[1]: *** [Makefile:2030: all-recursive] Error 1
make[1]: Leaving directory '/src/wget'
make: *** [Makefile:1982: all] Error 2


```

What happens if we just ignore all of the errors which get produced during compilation??????!?!?!

Here is my current build.sh file:

```


#!/bin/bash -eu
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

export WGET_DEPS_PATH=$SRC/wget_deps
export PKG_CONFIG_PATH=$WGET_DEPS_PATH/lib64/pkgconfig:$WGET_DEPS_PATH/lib/pkgconfig
export CPPFLAGS="-I$WGET_DEPS_PATH/include"
export CFLAGS="$CFLAGS -I$WGET_DEPS_PATH/include -L$WGET_DEPS_PATH/lib"
export LDFLAGS="-L$WGET_DEPS_PATH/lib"
export GNULIB_SRCDIR=$SRC/gnulib
export LLVM_PROFILE_FILE=/tmp/prof.test

cd $SRC/libunistring
./configure --enable-static --disable-shared --prefix=$WGET_DEPS_PATH --cache-file ../config.cache
make -j$(nproc)
make install

cd $SRC/libidn2
./configure --enable-static --disable-shared --disable-doc --disable-gcc-warnings --prefix=$WGET_DEPS_PATH --cache-file ../config.cache
make -j$(nproc)
make install

cd $SRC/libpsl
./autogen.sh
./configure --enable-static --disable-shared --disable-gtk-doc --enable-runtime=libidn2 --enable-builtin=libidn2 --prefix=$WGET_DEPS_PATH --cache-file ../config.cache
make -j$(nproc)
make install

GNUTLS_CONFIGURE_FLAGS=""
NETTLE_CONFIGURE_FLAGS=""
if [[ $CFLAGS = *sanitize=memory* ]] || [[ $CFLAGS = *sanitize=address* ]] || [[ $CFLAGS = *sanitize=undefined* ]]; then
  GNUTLS_CONFIGURE_FLAGS="--disable-hardware-acceleration"
  NETTLE_CONFIGURE_FLAGS="--disable-assembler --disable-fat"
fi

# We could use GMP from git repository to avoid false positives in
# sanitizers, but GMP doesn't compile with clang. We use gmp-mini
# instead.
cd $SRC/nettle
git checkout 8be0d5c4cbb0a1f1939e314418af6c10d26da70d # This specific commit is needed, because reasons...
bash .bootstrap
./configure --enable-mini-gmp --enable-static --disable-shared --disable-documentation --disable-openssl --prefix=$WGET_DEPS_PATH $NETTLE_CONFIGURE_FLAGS --cache-file ../config.cache
( make -j$(nproc) || make -j$(nproc) ) && make install
if test $? != 0;then
        echo "Failed to compile nettle"
        exit 1
fi

cd $SRC/gnutls
touch .submodule.stamp
./bootstrap
GNUTLS_CFLAGS=`echo $CFLAGS|sed s/-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION//`

LIBS="-lunistring" \
CFLAGS="$GNUTLS_CFLAGS" \
./configure --with-nettle-mini --enable-gcc-warnings --enable-static --disable-shared --with-included-libtasn1 \
    --with-included-unistring --without-p11-kit --disable-doc --disable-tests --disable-tools --disable-cxx \
    --disable-maintainer-mode --disable-libdane --disable-gcc-warnings --disable-full-test-suite \
    --prefix=$WGET_DEPS_PATH $GNUTLS_CONFIGURE_FLAGS
make -j$(nproc)
make install


# avoid iconv() memleak on Ubuntu 16.04 image (breaks test suite)
export ASAN_OPTIONS=detect_leaks=0

# Ensure our libraries can be found
ln -s $WGET_DEPS_PATH/lib64/libhogweed.a $WGET_DEPS_PATH/lib/libhogweed.a
ln -s $WGET_DEPS_PATH/lib64/libnettle.a  $WGET_DEPS_PATH/lib/libnettle.a

cd $SRC/wget
./bootstrap --skip-po
#autoreconf -fi # This fucks shit up, so skip over this step. This doesn't seem to affect other things.

# We need to add "--allow-multiple-definition" to the compiler flags before compiling to avoid some errors.

ORIG_CFLAGS="$CFLAGS"

# These modifications are needed, because otherwise we get an error while building the documentation


echo "#A Makefile" > $SRC/wget/doc/Makefile.am
echo "Nothing:" >> $SRC/wget/doc/Makefile.am
echo "all:# twist again" >> $SRC/wget/doc/Makefile.am
echo ".SILENT:" >> $SRC/wget/doc/Makefile.am

# gnulib_po Makefile.in.in has the wrong gettext version. Just patch it out (for now)...

sed -i -e 's/GETTEXT_MACRO_VERSION = 0.20/GETTEXT_MACRO_VERSION = 0.19/g' $SRC/wget/gnulib_po/Makefile.in.in

# build and run non-networking tests
CFLAGS="$ORIG_CFLAGS -Wall -Wl,--allow-multiple-definition" \
LIBS="-lgnutls -lhogweed -lnettle -lidn2 -lunistring -lpsl -lz" \
./configure -C --disable-doc
make clean MAKEINFO=true
# make MAKEINFO=true we need to skip building the documentation, because those cause errors.
make -j$(nproc) MAKEINFO=true || true # ignore errors, which may be caused in gnulib_po
make -j$(nproc) -C fuzz check MAKEINFO=true || true # ignore errors, which may be caused in gnulib_po

# build for fuzzing
# We also need to "--allow-multiple-definition" stuff here too!
CFLAGS="$ORIG_CFLAGS -Wall -Wl,--allow-multiple-definition" \
LIBS="-lgnutls -lhogweed -lnettle -lidn2 -lunistring -lpsl -lz" \
./configure --enable-fuzzing -C --disable-doc
make clean
make -j$(nproc) -C lib MAKEINFO=true || true # ignore errors, which may be caused in gnulib_po
make -j$(nproc) -C src MAKEINFO=true || true # ignore errors, which may be caused in gnulib_po

# build fuzzers
cd fuzz
make -j$(nproc) ../src/libunittest.a MAKEINFO=true || true # ignore errors, which may be caused in gnulib_po
make oss-fuzz MAKEINFO=true || true # ignore errors, which may be caused in gnulib_po

find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer.options' -exec cp -v '{}' $OUT ';'

for dir in *_fuzzer.in; do
  fuzzer=$(basename $dir .in)
  zip -rj "$OUT/${fuzzer}_seed_corpus.zip" "${dir}/"
done


```

and it compiles the fuzzers correctly! Good!!

Now, the question is: Can you run them???

Let's try to run `python infra/helper.py run_fuzzer --corpus-dir=corpus/ wget wget_options_fuzzer`

it finds a memory leak.... it suggests to use `-detect_leaks=0` to the options to disable detection of memory leaks, but I can't really put that command line option in the running arguments, because the python script will whine about it, so therefore I had to modify the infra/helper.py file to add that option before running the fuzzer.

## Final thoughts

Ok, so there was quite a lot of debugging involved. Very little coding, but a lot of trial and error to get shit to work and now I have finally duct taped something together which works. Here is the very final diff:

```
diff --git a/infra/helper.py b/infra/helper.py
index 0d331791a..e83510790 100755
--- a/infra/helper.py
+++ b/infra/helper.py
@@ -1381,6 +1381,7 @@ def run_fuzzer(args):
       'SANITIZER=' + args.sanitizer,
       'RUN_FUZZER_MODE=interactive',
       'HELPER=True',
+      'ASAN_OPTIONS=detect_leaks=0:log_path=stdout:abort_on_error=1', # This here is to ignore memory leaks.
   ]

   if args.e:
diff --git a/projects/wget/build.sh b/projects/wget/build.sh
index 83e81b065..8260b1717 100755
--- a/projects/wget/build.sh
+++ b/projects/wget/build.sh
@@ -41,7 +41,7 @@ make install

 GNUTLS_CONFIGURE_FLAGS=""
 NETTLE_CONFIGURE_FLAGS=""
-if [[ $CFLAGS = *sanitize=memory* ]]; then
+if [[ $CFLAGS = *sanitize=memory* ]] || [[ $CFLAGS = *sanitize=address* ]] || [[ $CFLAGS = *sanitize=undefined* ]]; then
   GNUTLS_CONFIGURE_FLAGS="--disable-hardware-acceleration"
   NETTLE_CONFIGURE_FLAGS="--disable-assembler --disable-fat"
 fi
@@ -50,6 +50,7 @@ fi
 # sanitizers, but GMP doesn't compile with clang. We use gmp-mini
 # instead.
 cd $SRC/nettle
+#git checkout 8be0d5c4cbb0a1f1939e314418af6c10d26da70d # This specific commit is needed, because reasons...
 bash .bootstrap
 ./configure --enable-mini-gmp --enable-static --disable-shared --disable-documentation --disable-openssl --prefix=$WGET_DEPS_PATH $NETTLE_CONFIGURE_FLAGS --cache-file ../config.cache
 ( make -j$(nproc) || make -j$(nproc) ) && make install
@@ -62,6 +63,7 @@ cd $SRC/gnutls
 touch .submodule.stamp
 ./bootstrap
 GNUTLS_CFLAGS=`echo $CFLAGS|sed s/-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION//`
+
 LIBS="-lunistring" \
 CFLAGS="$GNUTLS_CFLAGS" \
 ./configure --with-nettle-mini --enable-gcc-warnings --enable-static --disable-shared --with-included-libtasn1 \
@@ -81,26 +83,46 @@ ln -s $WGET_DEPS_PATH/lib64/libnettle.a  $WGET_DEPS_PATH/lib/libnettle.a

 cd $SRC/wget
 ./bootstrap --skip-po
-autoreconf -fi
+#autoreconf -fi # This fucks shit up, so skip over this step. This doesn't seem to affect other things.
+
+# We need to add "--allow-multiple-definition" to the compiler flags before compiling to avoid some errors.
+
+ORIG_CFLAGS="$CFLAGS"
+
+# These modifications are needed, because otherwise we get an error while building the documentation
+
+
+echo "#A Makefile" > $SRC/wget/doc/Makefile.am
+echo "Nothing:" >> $SRC/wget/doc/Makefile.am
+echo "all:# twist again" >> $SRC/wget/doc/Makefile.am
+echo ".SILENT:" >> $SRC/wget/doc/Makefile.am
+
+# gnulib_po Makefile.in.in has the wrong gettext version. Just patch it out (for now)...
+
+sed -i -e 's/GETTEXT_MACRO_VERSION = 0.20/GETTEXT_MACRO_VERSION = 0.19/g' $SRC/wget/gnulib_po/Makefile.in.in

 # build and run non-networking tests
+CFLAGS="$ORIG_CFLAGS -Wall -Wl,--allow-multiple-definition" \
 LIBS="-lgnutls -lhogweed -lnettle -lidn2 -lunistring -lpsl -lz" \
-./configure -C
-make clean
-make -j$(nproc)
-make -j$(nproc) -C fuzz check
+./configure -C --disable-doc
+make clean MAKEINFO=true
+# make MAKEINFO=true we need to skip building the documentation, because those cause errors.
+make -j$(nproc) MAKEINFO=true || true # ignore errors, which may be caused in gnulib_po
+make -j$(nproc) -C fuzz check MAKEINFO=true || true # ignore errors, which may be caused in gnulib_po

 # build for fuzzing
+# We also need to "--allow-multiple-definition" stuff here too!
+CFLAGS="$ORIG_CFLAGS -Wall -Wl,--allow-multiple-definition" \
 LIBS="-lgnutls -lhogweed -lnettle -lidn2 -lunistring -lpsl -lz" \
-./configure --enable-fuzzing -C
+./configure --enable-fuzzing -C --disable-doc
 make clean
-make -j$(nproc) -C lib
-make -j$(nproc) -C src
+make -j$(nproc) -C lib MAKEINFO=true || true # ignore errors, which may be caused in gnulib_po
+make -j$(nproc) -C src MAKEINFO=true || true # ignore errors, which may be caused in gnulib_po

 # build fuzzers
 cd fuzz
-make -j$(nproc) ../src/libunittest.a
-make oss-fuzz
+make -j$(nproc) ../src/libunittest.a MAKEINFO=true || true # ignore errors, which may be caused in gnulib_po
+make oss-fuzz MAKEINFO=true || true # ignore errors, which may be caused in gnulib_po

 find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
 find . -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'

```

## Why doesn't the fuzzer crash on a crashing input?

Ok, so now after a bit of trial and error, the fuzzer doesn't seem to crash on a crashing input. I can not reveal which input crashes the program, because that bug hasn't yet been fixed.

I solved this problem

## Solving the coverage issue

Ok, so it is time to improve coverage.

Let's take a look at the dictionary file and see what we have.

Here is the current dictionary file:

```
"--"
"no-"
"on"
"off"
"="
"PEM"
"DER"
"ASN1"
"INF"
"INFINITY"
"1"
"1k"
"1m"
"1g"
"1t"
"1s"
"1m"
"1h"
"1d"
"hard"
"soft"
"none"
"ipv4"
"ipv6"
"bar"
"posix"
"pcre"
"bytes"
"bits"
"human"
"csv"
"json"
"accept="
"accept-regex="
"adjust-extension="
"append-output="
"ask-password="
"auth-no-challenge="
"backup-converted="
"backups="
"base="
"bind-address="
"ca-certificate="
"cache="
"ca-directory="
"certificate="
"certificate-type="
"check-certificate="
"check-hostname="
"chunk-size="
"clobber="
"config="
"connect-timeout="
"content-disposition="
"content-on-error="
"continue="
"convert-links="
"cookies="
"cookie-suffixes="
"crl-file="
"cut-dirs="
"cut-file-get-vars="
"cut-url-get-vars="
"debug="
"default-page="
"delete-after="
"directories="
"directory-prefix="
"dns-caching="
"dns-timeout="
"domains="
"egd-file="
"exclude-domains="
"execute="
"filter-mime-type="
"filter-urls="
"follow-tags="
"force-atom="
"force-css="
"force-directories="
"force-html="
"force-metalink="
"force-progress="
"force-rss="
"force-sitemap="
"fsync-policy="
"gnupg-homedir="
"gnutls-options="
"header="
"help="
"host-directories="
"hpkp="
"hpkp-file="
"hsts="
"hsts-file="
"html-extension="
"http2="
"http2-request-window="
"http-keep-alive="
"http-password="
"http-proxy="
"http-proxy-password="
"http-proxy-user="
"https-enforce="
"https-only="
"https-proxy="
"http-user="
"ignore-case="
"ignore-tags="
"inet4-only="
"inet6-only="
"input-encoding="
"input-file="
"iri="
"keep-session-cookies="
"level="
"list-plugins="
"load-cookies="
"local-db="
"local-encoding="
"local-plugin="
"max-redirect="
"max-threads="
"metalink="
"mirror="
"netrc="
"netrc-file="
"no-quiet="
"ocsp="
"ocsp-file="
"ocsp-stapling="
"output-document="
"output-file="
"page-requisites="
"parent="
"password="
"plugin="
"plugin-dirs="
"plugin-help="
"plugin-opt="
"post-data="
"post-file="
"prefer-family="
"private-key="
"private-key-type="
"progress="
"protocol-directories="
"proxy="
"quiet="
"quota="
"random-file="
"random-wait="
"read-timeout="
"recursive="
"referer="
"regex-type="
"reject="
"reject-regex="
"remote-encoding="
"report-speed="
"restrict-file-names="
"robots="
"save-cookies="
"save-headers="
"secure-protocol="
"server-response="
"signature-extension="
"span-hosts="
"spider="
"stats-all="
"stats-dns="
"stats-ocsp="
"stats-server="
"stats-site="
"stats-tls="
"strict-comments="
"tcp-fastopen="
"timeout="
"timestamping="
"tls-false-start="
"tls-resume="
"tls-session-file="
"tries="
"trust-server-names="
"use-askpass="
"user="
"user-agent="
"use-server-timestamps="
"verbose="
"verify-save-failed="
"verify-sig="
"version="
"wait="
"waitretry="
"xattr="
```

looks quite good on first glance, but it is actually missing some options.

Here is the help message from the newest version of wget:

```

Now trying to open: /home/oof/.wgetrc
GNU Wget 1.24.5, a non-interactive network retriever.

Mandatory arguments to long options are mandatory for short options too.

Startup:
  -V,  --version                   display the version of Wget and exit
  -h,  --help                      print this help
  -b,  --background                go to background after startup
  -e,  --execute=COMMAND           execute a `.wgetrc'-style command

Logging and input file:
  -o,  --output-file=FILE          log messages to FILE
  -a,  --append-output=FILE        append messages to FILE
  -d,  --debug                     print lots of debugging information
  -q,  --quiet                     quiet (no output)
  -v,  --verbose                   be verbose (this is the default)
  -nv, --no-verbose                turn off verboseness, without being quiet
       --report-speed=TYPE         output bandwidth as TYPE.  TYPE can be bits
  -i,  --input-file=FILE           download URLs found in local or external FILE
  -F,  --force-html                treat input file as HTML
  -B,  --base=URL                  resolves HTML input-file links (-i -F)
                                     relative to URL
       --config=FILE               specify config file to use
       --no-config                 do not read any config file
       --rejected-log=FILE         log reasons for URL rejection to FILE

Download:
  -t,  --tries=NUMBER              set number of retries to NUMBER (0 unlimits)
       --retry-connrefused         retry even if connection is refused
       --retry-on-host-error       consider host errors as non-fatal, transient errors
       --retry-on-http-error=ERRORS    comma-separated list of HTTP errors to retry
  -O,  --output-document=FILE      write documents to FILE
  -nc, --no-clobber                skip downloads that would download to
                                     existing files (overwriting them)
       --no-netrc                  don't try to obtain credentials from .netrc
  -c,  --continue                  resume getting a partially-downloaded file
       --start-pos=OFFSET          start downloading from zero-based position OFFSET
       --progress=TYPE             select progress gauge type
       --show-progress             display the progress bar in any verbosity mode
  -N,  --timestamping              don't re-retrieve files unless newer than
                                     local
       --no-if-modified-since      don't use conditional if-modified-since get
                                     requests in timestamping mode
       --no-use-server-timestamps  don't set the local file's timestamp by
                                     the one on the server
  -S,  --server-response           print server response
       --spider                    don't download anything
  -T,  --timeout=SECONDS           set all timeout values to SECONDS
       --dns-timeout=SECS          set the DNS lookup timeout to SECS
       --connect-timeout=SECS      set the connect timeout to SECS
       --read-timeout=SECS         set the read timeout to SECS
  -w,  --wait=SECONDS              wait SECONDS between retrievals
                                     (applies if more then 1 URL is to be retrieved)
       --waitretry=SECONDS         wait 1..SECONDS between retries of a retrieval
                                     (applies if more then 1 URL is to be retrieved)
       --random-wait               wait from 0.5*WAIT...1.5*WAIT secs between retrievals
                                     (applies if more then 1 URL is to be retrieved)
       --no-proxy                  explicitly turn off proxy
  -Q,  --quota=NUMBER              set retrieval quota to NUMBER
       --bind-address=ADDRESS      bind to ADDRESS (hostname or IP) on local host
       --limit-rate=RATE           limit download rate to RATE
       --no-dns-cache              disable caching DNS lookups
       --restrict-file-names=OS    restrict chars in file names to ones OS allows
       --ignore-case               ignore case when matching files/directories
  -4,  --inet4-only                connect only to IPv4 addresses
  -6,  --inet6-only                connect only to IPv6 addresses
       --prefer-family=FAMILY      connect first to addresses of specified family,
                                     one of IPv6, IPv4, or none
       --user=USER                 set both ftp and http user to USER
       --password=PASS             set both ftp and http password to PASS
       --ask-password              prompt for passwords
       --use-askpass=COMMAND       specify credential handler for requesting
                                     username and password.  If no COMMAND is
                                     specified the WGET_ASKPASS or the SSH_ASKPASS
                                     environment variable is used.
       --no-iri                    turn off IRI support
       --local-encoding=ENC        use ENC as the local encoding for IRIs
       --remote-encoding=ENC       use ENC as the default remote encoding
       --unlink                    remove file before clobber
       --xattr                     turn on storage of metadata in extended file attributes

Directories:
  -nd, --no-directories            don't create directories
  -x,  --force-directories         force creation of directories
  -nH, --no-host-directories       don't create host directories
       --protocol-directories      use protocol name in directories
  -P,  --directory-prefix=PREFIX   save files to PREFIX/..
       --cut-dirs=NUMBER           ignore NUMBER remote directory components

HTTP options:
       --http-user=USER            set http user to USER
       --http-password=PASS        set http password to PASS
       --no-cache                  disallow server-cached data
       --default-page=NAME         change the default page name (normally
                                     this is 'index.html'.)
  -E,  --adjust-extension          save HTML/CSS documents with proper extensions
       --ignore-length             ignore 'Content-Length' header field
       --header=STRING             insert STRING among the headers
       --compression=TYPE          choose compression, one of auto, gzip and none. (default: none)
       --max-redirect              maximum redirections allowed per page
       --proxy-user=USER           set USER as proxy username
       --proxy-password=PASS       set PASS as proxy password
       --referer=URL               include 'Referer: URL' header in HTTP request
       --save-headers              save the HTTP headers to file
  -U,  --user-agent=AGENT          identify as AGENT instead of Wget/VERSION
       --no-http-keep-alive        disable HTTP keep-alive (persistent connections)
       --no-cookies                don't use cookies
       --load-cookies=FILE         load cookies from FILE before session
       --save-cookies=FILE         save cookies to FILE after session
       --keep-session-cookies      load and save session (non-permanent) cookies
       --post-data=STRING          use the POST method; send STRING as the data
       --post-file=FILE            use the POST method; send contents of FILE
       --method=HTTPMethod         use method "HTTPMethod" in the request
       --body-data=STRING          send STRING as data. --method MUST be set
       --body-file=FILE            send contents of FILE. --method MUST be set
       --content-disposition       honor the Content-Disposition header when
                                     choosing local file names (EXPERIMENTAL)
       --content-on-error          output the received content on server errors
       --auth-no-challenge         send Basic HTTP authentication information
                                     without first waiting for the server's
                                     challenge

HTTPS (SSL/TLS) options:
       --secure-protocol=PR        choose secure protocol, one of auto, SSLv2,
                                     SSLv3, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3 and PFS
       --https-only                only follow secure HTTPS links
       --no-check-certificate      don't validate the server's certificate
       --certificate=FILE          client certificate file
       --certificate-type=TYPE     client certificate type, PEM or DER
       --private-key=FILE          private key file
       --private-key-type=TYPE     private key type, PEM or DER
       --ca-certificate=FILE       file with the bundle of CAs
       --ca-directory=DIR          directory where hash list of CAs is stored
       --crl-file=FILE             file with bundle of CRLs
       --pinnedpubkey=FILE/HASHES  Public key (PEM/DER) file, or any number
                                   of base64 encoded sha256 hashes preceded by
                                   'sha256//' and separated by ';', to verify
                                   peer against

       --ciphers=STR           Set the priority string (GnuTLS) or cipher list string (OpenSSL) directly.
                                   Use with care. This option overrides --secure-protocol.
                                   The format and syntax of this string depend on the specific SSL/TLS engine.
HSTS options:
       --no-hsts                   disable HSTS
       --hsts-file                 path of HSTS database (will override default)

FTP options:
       --ftp-user=USER             set ftp user to USER
       --ftp-password=PASS         set ftp password to PASS
       --no-remove-listing         don't remove '.listing' files
       --no-glob                   turn off FTP file name globbing
       --no-passive-ftp            disable the "passive" transfer mode
       --preserve-permissions      preserve remote file permissions
       --retr-symlinks             when recursing, get linked-to files (not dir)

FTPS options:
       --ftps-implicit                 use implicit FTPS (default port is 990)
       --ftps-resume-ssl               resume the SSL/TLS session started in the control connection when
                                         opening a data connection
       --ftps-clear-data-connection    cipher the control channel only; all the data will be in plaintext
       --ftps-fallback-to-ftp          fall back to FTP if FTPS is not supported in the target server
WARC options:
       --warc-file=FILENAME        save request/response data to a .warc.gz file
       --warc-header=STRING        insert STRING into the warcinfo record
       --warc-max-size=NUMBER      set maximum size of WARC files to NUMBER
       --warc-cdx                  write CDX index files
       --warc-dedup=FILENAME       do not store records listed in this CDX file
       --no-warc-compression       do not compress WARC files with GZIP
       --no-warc-digests           do not calculate SHA1 digests
       --no-warc-keep-log          do not store the log file in a WARC record
       --warc-tempdir=DIRECTORY    location for temporary files created by the
                                     WARC writer

Recursive download:
  -r,  --recursive                 specify recursive download
  -l,  --level=NUMBER              maximum recursion depth (inf or 0 for infinite)
       --delete-after              delete files locally after downloading them
  -k,  --convert-links             make links in downloaded HTML or CSS point to
                                     local files
       --convert-file-only         convert the file part of the URLs only (usually known as the basename)
       --backups=N                 before writing file X, rotate up to N backup files
  -K,  --backup-converted          before converting file X, back up as X.orig
  -m,  --mirror                    shortcut for -N -r -l inf --no-remove-listing
  -p,  --page-requisites           get all images, etc. needed to display HTML page
       --strict-comments           turn on strict (SGML) handling of HTML comments

Recursive accept/reject:
  -A,  --accept=LIST               comma-separated list of accepted extensions
  -R,  --reject=LIST               comma-separated list of rejected extensions
       --accept-regex=REGEX        regex matching accepted URLs
       --reject-regex=REGEX        regex matching rejected URLs
       --regex-type=TYPE           regex type (posix|pcre)
  -D,  --domains=LIST              comma-separated list of accepted domains
       --exclude-domains=LIST      comma-separated list of rejected domains
       --follow-ftp                follow FTP links from HTML documents
       --follow-tags=LIST          comma-separated list of followed HTML tags
       --ignore-tags=LIST          comma-separated list of ignored HTML tags
  -H,  --span-hosts                go to foreign hosts when recursive
  -L,  --relative                  follow relative links only
  -I,  --include-directories=LIST  list of allowed directories
       --trust-server-names        use the name specified by the redirection
                                     URL's last component
  -X,  --exclude-directories=LIST  list of excluded directories
  -np, --no-parent                 don't ascend to the parent directory

Email bug reports, questions, discussions to <bug-wget@gnu.org>
and/or open issues at https://savannah.gnu.org/bugs/?func=additem&group=wget.


```

Let's create a quick script to get the new options for wget and then add them to the dictionary if they aren't present.

Here is my quick implementation:

```

#!/bin/python3







fh = open("opts.txt", "r")

lines = fh.readlines()


fh.close()


# Read the already existing options stuff.

fh = open("wget_options_fuzzer.dict", "r")

options = fh.readlines()

fh.close()

help_opts = []

for line in lines:
	#print(line[1:-1])
	# Skip to the "--" part

	line = line[line.index("--"):]

	# Cut off at the next space character
	if " " in line:
		line = line[:line.index(" ")]

	# print(line)

	if line == "" or line =="\n": # Empty???
		continue

	# Skip the stuff after the "=" character.
	if "=" in line:
		line = line[:line.index("=")+1]

	# strip the two dashes from the start

	line = line[2:]

	#print(line)

	if line[-1] == "\n":
		line = line[:-1]
		if line[-1] == ".":
			line = line[:-1]
			#print("POOOPOO: "+str(line))

	help_opts.append(line)



new_opts = []

# Check if the option is already in the options file. If yes, then don't bother adding it to the list

for line in help_opts:

	if not any(line in x for x in options) and len(line) > 2: # It isn't in the list.
		print(line) # The option wasn't previously in the dictionary.



```

In addition to adding the other options to the dictionary, we should also add the stuff from here: https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Commands.html to the dictionary and see what happens.

This script here seems sufficient:

```

fh = open("wget_rc_stuff.txt", "r")

lines = fh.readlines()

fh.close()

for line in lines:
	if line.startswith("<dt>"): # We have found a thing.
		if line[-1] == "\n": # Get rid of newline at end.
			line = line[:-1]

		#print(line)
		# Search for " = "
		line = line[:line.index(" = ")+len(" = ")]
		#print(line)
		line = line[len("<dt>"):]
		print("\""+line+"\"") # print the string wrapped in double quotes.


```

(for the wget_rc_stuff.txt file I just ran `wget https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Commands.html` and then `cat Wgetrc-Commands.html | grep " = " > wget_rc_stuff.txt`)

Let's test out this new dictionary on the fuzzer! With the old dictionary we got 5355 corpus files.

With the new dictionary file, we went past 5355 in less than five minutes of fuzzing! Fantastic!!!!

Here is our new and improved dictionary file:

```

# These next options are taken from here: https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Commands.html

"accept/reject = "
"add_hostdir = "
"ask_password = "
"auth_no_challenge = "
"background = "
"backup_converted = "
"backups = "
"base = "
"bind_address = "
"ca_certificate = "
"ca_directory = "
"cache = "
"certificate = "
"certificate_type = "
"check_certificate = "
"connect_timeout = "
"content_disposition = "
"trust_server_names = "
"continue = "
"convert_links = "
"cookies = "
"cut_dirs = "
"debug = "
"default_page = "
"delete_after = "
"dir_prefix = "
"dirstruct = "
"dns_cache = "
"dns_timeout = "
"domains = "
"dot_bytes = "
"dot_spacing = "
"dots_in_line = "
"egd_file = "
"exclude_directories = "
"exclude_domains = "
"follow_ftp = "
"follow_tags = "
"force_html = "
"ftp_password = "
"ftp_proxy = "
"ftp_user = "
"glob = "
"header = "
"compression = "
"adjust_extension = "
"http_keep_alive = "
"http_password = "
"http_proxy = "
"http_user = "
"https_only = "
"https_proxy = "
"ignore_case = "
"ignore_length = "
"ignore_tags = "
"include_directories = "
"iri = "
"inet4_only = "
"inet6_only = "
"input = "
"keep_session_cookies = "
"limit_rate = "
"load_cookies = "
"local_encoding = "
"logfile = "
"max_redirect = "
"mirror = "
"netrc = "
"no_clobber = "
"no_parent = "
"no_proxy = "
"output_document = "
"page_requisites = "
"passive_ftp = "
"password = "
"post_data = "
"post_file = "
"prefer_family = "
"private_key = "
"private_key_type = "
"progress = "
"protocol_directories = "
"proxy_password = "
"proxy_user = "
"quiet = "
"quota = "
"random_file = "
"random_wait = "
"read_timeout = "
"reclevel = "
"recursive = "
"referer = "
"relative_only = "
"remote_encoding = "
"remove_listing = "
"restrict_file_names = "
"retr_symlinks = "
"retry_connrefused = "
"robots = "
"save_cookies = "
"save_headers = "
"secure_protocol = "
"server_response = "
"show_all_dns_entries = "
"span_hosts = "
"spider = "
"strict_comments = "
"timeout = "
"timestamping = "
"use_server_timestamps = "
"tries = "
"use_proxy = "
"user = "
"user_agent = "
"verbose = "
"wait = "
"wait_retry = "

# These were the new options taken from the latest version of wget (1.24.5)

"background"
"no-verbose"
"no-config"
"rejected-log="
"retry-connrefused"
"retry-on-host-error"
"retry-on-http-error="
"no-clobber"
"no-netrc"
"start-pos="
"show-progress"
"no-if-modified-since"
"no-use-server-timestamps"
"no-proxy"
"limit-rate="
"no-dns-cache"
"no-iri"
"unlink"
"no-directories"
"no-host-directories"
"no-cache"
"ignore-length"
"compression="
"no-http-keep-alive"
"no-cookies"
"method="
"body-data="
"body-file="
"no-check-certificate"
"pinnedpubkey="
"ciphers="
"no-hsts"
"ftp-user="
"ftp-password="
"no-remove-listing"
"no-glob"
"no-passive-ftp"
"preserve-permissions"
"retr-symlinks"
"ftps-implicit"
"ftps-resume-ssl"
"ftps-clear-data-connection"
"ftps-fallback-to-ftp"
"warc-file="
"warc-header="
"warc-max-size="
"warc-cdx"
"warc-dedup="
"no-warc-compression"
"no-warc-digests"
"no-warc-keep-log"
"warc-tempdir="
"convert-file-only"
"follow-ftp"
"relative"
"include-directories="
"exclude-directories="
"no-parent"

# And these were the original strings from the old wget_fuzz_options.dict file...

"--"
"no-"
"on"
"off"
"="
"PEM"
"DER"
"ASN1"
"INF"
"INFINITY"
"1"
"1k"
"1m"
"1g"
"1t"
"1s"
"1m"
"1h"
"1d"
"hard"
"soft"
"none"
"ipv4"
"ipv6"
"bar"
"posix"
"pcre"
"bytes"
"bits"
"human"
"csv"
"json"
"accept="
"accept-regex="
"adjust-extension="
"append-output="
"ask-password="
"auth-no-challenge="
"backup-converted="
"backups="
"base="
"bind-address="
"ca-certificate="
"cache="
"ca-directory="
"certificate="
"certificate-type="
"check-certificate="
"check-hostname="
"chunk-size="
"clobber="
"config="
"connect-timeout="
"content-disposition="
"content-on-error="
"continue="
"convert-links="
"cookies="
"cookie-suffixes="
"crl-file="
"cut-dirs="
"cut-file-get-vars="
"cut-url-get-vars="
"debug="
"default-page="
"delete-after="
"directories="
"directory-prefix="
"dns-caching="
"dns-timeout="
"domains="
"egd-file="
"exclude-domains="
"execute="
"filter-mime-type="
"filter-urls="
"follow-tags="
"force-atom="
"force-css="
"force-directories="
"force-html="
"force-metalink="
"force-progress="
"force-rss="
"force-sitemap="
"fsync-policy="
"gnupg-homedir="
"gnutls-options="
"header="
"help="
"host-directories="
"hpkp="
"hpkp-file="
"hsts="
"hsts-file="
"html-extension="
"http2="
"http2-request-window="
"http-keep-alive="
"http-password="
"http-proxy="
"http-proxy-password="
"http-proxy-user="
"https-enforce="
"https-only="
"https-proxy="
"http-user="
"ignore-case="
"ignore-tags="
"inet4-only="
"inet6-only="
"input-encoding="
"input-file="
"iri="
"keep-session-cookies="
"level="
"list-plugins="
"load-cookies="
"local-db="
"local-encoding="
"local-plugin="
"max-redirect="
"max-threads="
"metalink="
"mirror="
"netrc="
"netrc-file="
"no-quiet="
"ocsp="
"ocsp-file="
"ocsp-stapling="
"output-document="
"output-file="
"page-requisites="
"parent="
"password="
"plugin="
"plugin-dirs="
"plugin-help="
"plugin-opt="
"post-data="
"post-file="
"prefer-family="
"private-key="
"private-key-type="
"progress="
"protocol-directories="
"proxy="
"quiet="
"quota="
"random-file="
"random-wait="
"read-timeout="
"recursive="
"referer="
"regex-type="
"reject="
"reject-regex="
"remote-encoding="
"report-speed="
"restrict-file-names="
"robots="
"save-cookies="
"save-headers="
"secure-protocol="
"server-response="
"signature-extension="
"span-hosts="
"spider="
"stats-all="
"stats-dns="
"stats-ocsp="
"stats-server="
"stats-site="
"stats-tls="
"strict-comments="
"tcp-fastopen="
"timeout="
"timestamping="
"tls-false-start="
"tls-resume="
"tls-session-file="
"tries="
"trust-server-names="
"use-askpass="
"user="
"user-agent="
"use-server-timestamps="
"verbose="
"verify-save-failed="
"verify-sig="
"version="
"wait="
"waitretry="
"xattr="





```

After roughly half an hour of fuzzing, we have 9671 corpus files. That is quite decent.


## Any new crashes?????

I actually ran the fuzzer with the `-ignore_crashes=1` command line parameter, so to deduplicate the crashes, we need to write a quick python script which run's the crashes and stores every asan report in a file which we can then comb through with grep to get the individual crashes and throw out the duplicates.







## TODO for the future:

 * Fix the fuzzer compilation process (done)
 * Fix the oss-fuzz fuzzer compilation process. (now done after plenty of debugging)
 * Improve option fuzzing corpus code coverage.
 * Improve option fuzzing dictionary.
 * Fix the bugs found by the fuzzer.




