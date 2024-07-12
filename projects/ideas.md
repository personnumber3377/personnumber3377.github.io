
# Ideas

This is a compilation of some of my ideas, which I could do sometime.

- Basic interpreter in python (WIP)
- Write a time based fuzzer in python, which tries to find inputs, which timeout. (This could be useful for fuzzing different kinds of python applications for DOS vulns, like django etc).
- HTTP request fuzzer (stateful with grammar), for example make a tool which could be used to find this bug:
- Fuzz apache httpd with libfuzzer (use the oss-fuzz stuff to fuzz instead of doing something janky). (This is under progress.)
- Try ruzzy (https://blog.trailofbits.com/2024/03/29/introducing-ruzzy-a-coverage-guided-ruby-fuzzer/) with the custom mutator which I made????

## Some interesting looking stuff..


```

# This is taken from https://libc-alpha.sourceware.narkive.com/1BhjzIpn/is-there-a-fuzzer-for-libc

Sure, one class of functions that aren't too hard to fuzz is functions
which take only integer and pointer-to-string arguments with no
constraints on them. However it still may be hard to hit the
meaningful cases. I think fuzzing gethostbyname would be pretty slow
since you'd end up waiting for the dns request to fail for nearly
every random string you generated.

Rich
Konstantin Serebryany10 years ago
PermalinkQuick update: I found regfuzz, a fuzzer for regular expressions.
https://code.google.com/p/regfuzz/
A short run revealed a least 3 somewhat scary situations in regcomp:
infinite loop, quick memory exhaustion and a memory leak:
I've submitted two bugs so far; if they are considered interesting and
get fixed I can file more :)
https://sourceware.org/bugzilla/show_bug.cgi?id=17069
https://sourceware.org/bugzilla/show_bug.cgi?id=17070

I also wrote a naive fuzzer for wildcards and it found a buffer
overflow in fnmatch:
https://sourceware.org/bugzilla/show_bug.cgi?id=17062 (already fixed).


```

https://sourceware.org/glibc/wiki/FuzzingLibc






