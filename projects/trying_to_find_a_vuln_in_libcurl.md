
# Trying to find a bug in libcurl

I was recently inspired by this recent hackerone report here: https://hackerone.com/reports/2559516 I decided my hand at trying to fuzz libcurl...

## Inspecting the fuzzers

libcurl is one of the most widely used software libraries in the world, therefore it has plenty of fuzzers and unittests in place to prevent security issues. These fuzzers along with their corpora are located here: https://github.com/curl/curl-fuzzer

Looking at the fuzzer source code, there doesn't appear to be any mentions of a hsts parser. The Curl_hsts_parse which parses hsts does not seem to have a fuzzer. The function is called in the source code, but it is only called in one place, so I don't think that it is worth fuzzing. I think there is a function called "curl_getdate" which parses a date string and returns a time_t value. This function isn't used anywhere in the curl codebase, and there isn't a fuzzer for this specific function, so maybe we can find bugs in it????

## Why no new coverage???

Ok, so there is some bullshit going on which causes there to be no coverage for some odd reason and this messes up stuff.

This is because we are linking against the system libcurl version, not the version with coverage... FUck!


```

   0x7ffff7f41ec8 <curl_getdate+24>:	mov    %rsp,%rsi
   0x7ffff7f41ecb <curl_getdate+27>:	movq   $0xffffffffffffffff,(%rsp)
   0x7ffff7f41ed3 <curl_getdate+35>:	call   0x7ffff7f71aa0
   0x7ffff7f41ed8 <curl_getdate+40>:	test   %eax,%eax
   0x7ffff7f41eda <curl_getdate+42>:	jne    0x7ffff7f41f00 <curl_getdate+80>
(gdb) break parsedate
Function "parsedate" not defined.
Make breakpoint pending on future shared library load? (y or [n]) c
Please answer y or [n].
Make breakpoint pending on future shared library load? (y or [n]) n
(gdb) cQuit
(gdb) break 0x7ffff7f41ed3
Function "0x7ffff7f41ed3" not defined.
Make breakpoint pending on future shared library load? (y or [n]) n
(gdb) break *0x7ffff7f41ed3
Breakpoint 2 at 0x7ffff7f41ed3
(gdb) c
Continuing.

Breakpoint 2, 0x00007ffff7f41ed3 in curl_getdate () from /lib/x86_64-linux-gnu/libcurl.so.4
(gdb) where
#0  0x00007ffff7f41ed3 in curl_getdate () from /lib/x86_64-linux-gnu/libcurl.so.4
#1  0x00000000004cf19b in test (URL=URL@entry=0x7fffffffe196 "fefef") at lib517.c:207
#2  0x00000000004d0051 in main (argc=<optimized out>, argv=0x7fffffffddd8) at first.c:178
(gdb)



```

After adding `LD_LIBRARY_PATH` to our environment variables which points to the libcurl.so library...

The date parsing didn't yield any results for fuzzing, so let's move on...

## Fuzzing urls

Ok, so the urls is actually the most heavily fuzzed part of libcurl for reasons..



























