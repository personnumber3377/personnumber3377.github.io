
# Ideas

This is a compilation of some of my ideas, which I could do sometime.

- Basic interpreter in python (WIP)
- Write a time based fuzzer in python, which tries to find inputs, which timeout. (This could be useful for fuzzing different kinds of python applications for DOS vulns, like django etc). (Done!)
- HTTP request fuzzer (stateful with grammar), for example make a tool which could be used to find this bug:
- Fuzz apache httpd with libfuzzer (use the oss-fuzz stuff to fuzz instead of doing something janky). (This is under progress.)
- Try ruzzy (https://blog.trailofbits.com/2024/03/29/introducing-ruzzy-a-coverage-guided-ruby-fuzzer/) with the custom mutator which I made????
- Make a program which takes a C-code struct and then outputs a python program which reads said struct. (Probably exists already) (this is for the source engine mdl decompilation thing).
- Optimize my own graphics library.
- Try to make a perl exiftool fuzzer, potentially try to find interesting bugs in exiftool like DOS style bugs, because those are eligible for a big gitlab bounty.
- Try to fuzz nokogiri for DOS style bugs, because those too are eligible for gitlab bounty.
- Fuzz python markdown module.
- Fuzz python tomli module.
- Fuzz librsvg with my new custom mutator.
- Make an autodictionary tool, which creates a fuzzing dictionary out of the source code without even having to look at the code ourselves. I think clang already has this, but I think this should be used on other programming languages as well.
- Make a custom mutator for CLVM crypto virtual machine.
- Fuzz gitaly with golang fuzzer. (This is a part of the gitlab bug bounty.)
- Try to find some vulnerabilities in third party libraries used by django, because maybe you can get a bounty that way.
- Try to run my redos thing against python source code.
- Add a way to get the http response content in the python requests library (just as in burp suite for example). Also maybe do this for the requests too?? (You can get the raw request text before sending.)
- Make a custom mutator for APDU for rsk-powhsm stuff.
- Try to fuzz ffmpeg's http component:
- Try this tool here?? https://taesoo.kim/pubs/2020/park:die.pdf  seems like a fun little tool to play around with.
- Make a python script which generates a parser with a .h file which tells about some file format????
- Fuzz libmysofa.
- Explore some of this maybe? https://www.researchgate.net/publication/51911443_TRX_A_Formally_Verified_Parser_Interpreter
- Maybe explore mathematical modelling of computer programs????
- Add fuzz target for avfilter_graph_parse in ffmpeg???
- Make an autodictionary tool for webpages etc..
- Add ways to fuzz the parsers in ffmpeg individually. As it stands, all of the parsers are being fuzzed simultaneously and that isn't really good. The parsers.c file has some pointers as to how to do about doing this. My idea is to just write one file which serves as a template and then compile all of the fuzzers individually with a compiler flag signifying which parser to use... This way each of the formats that ffmpeg supports get's fuzzed individually. Jpeg-XL seems to have the most complex parsing by just looking at the file sizes.
- Fuzz OPX files in microsoft office.
- Fuzz GDIplus with winafl and other windows internals...
- Try to make a custom mutator for the EMF file format.
- Try to fuzz with this: https://github.com/fuzzitdev/jsfuzz/tree/master the standard library of nodejs or something like that maybe???
- Finish the microsoft office svg fuzzer...
- Try to fuzz django for SQL injection vulns.
- Maybe try to differential fuzz pitchfork which is made by shopify or some bullshit like that????
- Make a content farm for youtube and automatically upload "summary style" videos or shorts to youtube, like this one here: https://www.youtube.com/watch?v=j-3QuSfDuvI
- Fuzz windows LDAP (lsass.exe) and maybe http parsing (HTTP.sys) and mime parsing???
- Do a custom mutator for the program fuzzer in clvm in chia netowrk maybe????
- Fuzz python internals...
- Fuzz chromium svg stuff in blink maybe???
- Differential fuzz golang stdlib with other libraries like net/http...




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

Also maybe say about the thing about the regex.match(string, position) method which is undocumented.




