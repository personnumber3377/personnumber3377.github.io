
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






## TODO:

 * Fix the fuzzer compilation process (done)
 * Fix the oss-fuzz fuzzer compilation process.
 * Improve fuzzing corpus code coverage.
 * Fix the bugs found by the fuzzer.




