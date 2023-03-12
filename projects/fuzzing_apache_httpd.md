
# Fuzzing apache http server

I wanted to write this writeup as notes to myself and to share my story of fuzzing apache. Now at this point I have already setup a good fuzzing workflow, but as of writing this I haven't found any interesting crashes. Now I am going to try to remember my story from the start:


One day I came across this post: https://securitylab.github.com/research/fuzzing-apache-1/ . As a computer security enthusiast this caught my attention. As usual, I jumped in without doing any research.

I first tried to follow the instructions provided, but then I got a good idea: Let's use afl-clang-lto ! After compiling afl-fuzz with afl-clang-lto LLVM support I tried to compile apache. As usual, there were a mountain of errors, because we are now using afl-clang-lto. After fiddling a couple of days with the configuration options I finally came up with this:


```
CC=afl-clang-lto CXX=afl-clang-lto++ RANLIB=llvm-ranlib AR=llvm-ar CFLAGS="-std=c99 -g -ggdb -fsanitize=address,undefined -fno-sanitize-recover=all -O3" CXXFLAGS="-std=c99 -g -ggdb -O3 -fsanitize=address,undefined -fno-sanitize-recover=all" LDFLAGS="-std=c99 -fsanitize=address,undefined -fno-sanitize-recover=all -lm -fuse-ld=/home/cyberhacker/Asioita/newaflfuzz/shit/llvm-project-llvmorg-15.0.7/build/bin/ld.lld" ./configure --prefix='/home/cyberhacker/httpd-lto/install' --with-included-apr --enable-static-support --enable-mods-static=few --disable-shared --disable-pie --enable-debugger-mode --with-mpm=prefork  --enable-negotiation=static --enable-session=static --enable-auth-form=static --enable-request=static --enable-rewrite=static --enable-auth_digest=static --enable-deflate=static  --enable-crypto=static --with-crypto --with-openssl --enable-proxy_html=static --enable-xml2enc=static --enable-cache=static --enable-cache-disk=static --enable-data=static --enable-substitute=static --enable-ratelimit=static --enable-dav=static
```

In addition to this, I still got a couple of errors. After tracking down a build configuration file I wrote this script:

```
def patch_thing(filename, original, patch):
	with open(filename, "r") as f:
		haystack = f.read()
	if original not in haystack:
		print("Warning: File "+str(filename) + " already patched!")
		return
	result = haystack.replace(original, patch)
	with open(filename, "w") as f:
		f.write(result)
	print("File " + str(filename) + " patched.")
	return




if __name__=="__main__":

	config_vars = "build/config_vars.mk"

	to_be_replaced = "NOTEST_CFLAGS = -O0 -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wdeclaration-after-statement -Werror=declaration-after-statement -Wpointer-arith -Wformat -Wformat-security -Werror=format-security"


	replacement = "NOTEST_CFLAGS = -O0 -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wdeclaration-after-statement -Wpointer-arith -Wformat -Wformat-security"


	patch_thing(config_vars, to_be_replaced, replacement)

	makefile = "./Makefile"

	to_be_replaced = "= modules.c"

	replacement = "= modules.c server/fuzzing_aux.c"

	patch_thing(makefile, to_be_replaced, replacement)

	print("[+] Done")
```
The errors were caused by -Werror statements which I removed. It obviously still gives warnings, but I do not care about those. I just wanted to get something to work. This is methaphorically sweeping the dirt under the rug instead of cleaning it up. Also I added a couple of files and lines to the project in order to fuzz the server. You can find these changes in the diff file which I uploaded to my github and you can copy the modified source from my github too. I also uploaded the final binaries to my github along with all the configuration and other installation files. The installation files assume that the server root is at /home/cyberhacker/httpd-lto/install/ so if you want to try to fuzz on your own, then you need to change those or compile with --prefix=YOURPREFIXHERE . Now I finally got a fuzzing setup which atleast worked somewhat. I run the fuzzer with this:

```
# if(data->brute_level == 10)
# 10 means back_8bits

export BRUTE_LEVEL=40
BRUTE_LEVEL=40
export FUZZ_NUM=1000
FUZZ_NUM=1000
#export AFL_PRELOAD=/home/cyberhacker/httpd-lto/install/lib/tls/x86_64/x86_64/libm.so.6:/home/cyberhacker/httpd-lto/install/lib/tls/x86_64/libm.so.6:/home/cyberhacker/httpd-lto/install/lib/tls/x86_64/libm.so.6:/home/cyberhacker/httpd-lto/install/lib/tls/libm.so.6:/home/cyberhacker/httpd-lto/install/lib/x86_64/x86_64/libm.so.6:/home/cyberhacker/httpd-lto/install/lib/x86_64/libm.so.6:/home/cyberhacker/httpd-lto/install/lib/x86_64/libm.so.6:/home/cyberhacker/httpd-lto/install/lib/libm.so.6:/home/cyberhacker/httpd-lto/install/lib/libpcre2-8.so.0:/home/cyberhacker/httpd-lto/install/lib/libz.so.1:/home/cyberhacker/httpd-lto/install/lib/libxml2.so.2:/home/cyberhacker/httpd-lto/install/lib/libapr-2.so.0:/home/cyberhacker/httpd-lto/install/lib/libuuid.so.1:/home/cyberhacker/httpd-lto/install/lib/libpthread.so.0:/home/cyberhacker/httpd-lto/install/lib/libexpat.so.1:/home/cyberhacker/httpd-lto/install/lib/librt.so.1:/home/cyberhacker/httpd-lto/install/lib/libdl.so.2:/home/cyberhacker/httpd-lto/install/lib/libgcc_s.so.1:/home/cyberhacker/httpd-lto/install/lib/libc.so.6:/home/cyberhacker/httpd-lto/install/lib/apr-2/apr_crypto_openssl-2.so
#export AFL_CUSTOM_MUTATOR_LIBRARY=/home/cyberhacker/Asioita/Hakkerointi/anotherapache/new-mutator/bruteforcenew.so
#export AFL_CUSTOM_MUTATOR_LIBRARY=/home/cyberhacker/Asioita/Hakkerointi/anotherapache/new-mutator/lineswapping.so
#export AFL_CUSTOM_MUTATOR_ONLY=1
#AFL_CUSTOM_MUTATOR_ONLY=1
#export LD_LIBRARY_PATH=/home/cyberhacker/httpd-lto/install/lib
#export AFL_LLVM_DOCUMENT_IDS=/home/cyberhacker/httpd-lto/things/ids.bin
#AFL_LLVM_DOCUMENT_IDS=/home/cyberhacker/httpd-lto/things/ids.bin
#export AFL_DEBUG=1
#rm -r fuzzing_output/

export AFL_AUTORESUME=1

#AFL_PRELOAD=/home/cyberhacker/httpd-lto/install/lib/tls/x86_64/x86_64/libm.so.6:/home/cyberhacker/httpd-lto/install/lib/tls/x86_64/libm.so.6:/home/cyberhacker/httpd-lto/install/lib/tls/x86_64/libm.so.6:/home/cyberhacker/httpd-lto/install/lib/tls/libm.so.6:/home/cyberhacker/httpd-lto/install/lib/x86_64/x86_64/libm.so.6:/home/cyberhacker/httpd-lto/install/lib/x86_64/libm.so.6:/home/cyberhacker/httpd-lto/install/lib/x86_64/libm.so.6:/home/cyberhacker/httpd-lto/install/lib/libm.so.6:/home/cyberhacker/httpd-lto/install/lib/libpcre2-8.so.0:/home/cyberhacker/httpd-lto/install/lib/libz.so.1:/home/cyberhacker/httpd-lto/install/lib/libxml2.so.2:/home/cyberhacker/httpd-lto/install/lib/libapr-2.so.0:/home/cyberhacker/httpd-lto/install/lib/libuuid.so.1:/home/cyberhacker/httpd-lto/install/lib/libpthread.so.0:/home/cyberhacker/httpd-lto/install/lib/libexpat.so.1:/home/cyberhacker/httpd-lto/install/lib/librt.so.1:/home/cyberhacker/httpd-lto/install/lib/libdl.so.2:/home/cyberhacker/httpd-lto/install/lib/libgcc_s.so.1:/home/cyberhacker/httpd-lto/install/lib/libc.so.6:/home/cyberhacker/httpd-lto/install/lib/apr-2/apr_crypto_openssl-2.so
AFL_MAP_SIZE=256000 SHOW_HOOKS=1 ASAN_OPTIONS=detect_leaks=0,abort_on_error=1,symbolize=0,debug=true,check_initialization_order=true,detect_stack_use_after_return=true,strict_string_checks=true,detect_invalid_pointer_pairs=2,detect_odr_violation=0 AFL_DISABLE_TRIM=1 /home/cyberhacker/Asioita/newaflfuzz/AFLplusplus/afl-fuzz -s 123 -t 2000 -M master -m none -i '/home/cyberhacker/httpd-lto/AFL/afl_tmin_out/' -o '/home/cyberhacker/httpd-lto/fuzzing_output/' -- '/home/cyberhacker/httpd-lto/install/bin/httpd' -X -f /home/cyberhacker/httpd-lto/install/conf/httpd.conf @@


```

## Creating htdocs folder.

Now the original post said that they had created random content with short filenames in the htdocs, but once again, they were very kind and did not share this htdocs folder anywhere 🙃 . So once again I needed to somehow create my own and out comes this: https://github.com/personnumber3377/samplefilegenerator . It creates random files in a specified directory. One features which it is missing is that it does not create subdirectories, which would we good, although you can of course manually create subdirs and then run the script on that directory, but that is quite janky. The files which it creates are binary files, text files, random images, random pdf files and random html files which consist of just simple autogenerated `<p1>` tags. To create a htdocs folder similar to the original blog post just run the script with your htdocs directory as a command line argument.



## Better corpus



Now, the writer of the original post did not specify in great detail how he came up with the corpus which was used in the fuzzing, but something about https://github.com/AFLplusplus/Grammar-Mutator  was said. Well, I tried it and yes it created better inputs than what you would have gotten by just running with a single empty file as the corpus, but the coverage was really poor still. (see "poor_coverage" on my github page on httpdfuzzing) . Only around 19% of the lines got covered according to lcov .

Now looking at the autogenerated files, they look something like this:

```
UNLOCK dav://127.0.0.1:8080/ HTTP/3.0
1

```
and like this:

```
HEAD dav://127.0.0.1:8080/ HTTP/0.9
TE: 
Via: z


```

So these are kinda good requests, but not good enough. Looking around the web for a script which just creates random requests with random headers and random request body, so I actually wrote my own: https://github.com/personnumber3377/HTTP-request-generator . This script creates some random requests with random headers, but it is sort of intelligent in the sense that it opens your htdocs folder and then actually adds a valid filename to the request (eq if you have a file called foo.html, then it creates a request like GET /foo.html HTTP/1.1 ... ) . Now this tool creates requests like these:


```
POST /s?Ug=o HTTP/1.1
Host: U
Accept-Charset: iso-8859-5
Content-Encoding: deflate
Accept-Language: tk

FwFXjxjWwjSJihFewHDxeQKbvNVIdAVnnymqOALATwknnpDIyuEDwloRZptbJbscWKFNNFYhGjryiAxcFIVeg

```

Now this looks a lot better than the autogenerated requests with the Grammar-Mutator . I actually combined these autogenerated ones with those old files. I also found this: https://github.com/lpereira/lwan/tree/master/fuzz/corpus which had a lot of good requests to use as a corpus so I also added those in. The result is this: https://github.com/personnumber3377/HTTPcorpus/tree/main/corpus  after running afl-cmin and afl-tmin we get this: https://github.com/personnumber3377/HTTPcorpus/tree/main/corpus_minified 



## Custom mutators:

Now you may have realized that I actually used a custom fuzzer (actually i used a few custom fuzzers which are here https://github.com/personnumber3377/httpdfuzzing/tree/main/custom_fuzzer_stuff ) . Once again, the original post only contained fragments of the source code needed to compile these custom mutators (basically lineswapping and bruteforcing sequential bytes in the input file), but did not contain any script to compile them. Also the version of afl-fuzz which I use is a couple years newer so for example `queued_paths` does no longer exist and I had to replace it with the new attribute `queued_items` which does exist in the newest version. Also the "Other tests.c" file has a 16 bit bruteforce which actually does not even work properly. It bruteforces two bytes yes, but it forgets to add the bruteforced bytes to the actual input, so you get inputs which just look like `aabb` and then `aabc` and so on, so it does not even work. I did not have the patience to try to get this piece of shit to work (at this point I had already poured like couple weeks of my time on this project alread, even though I once again overestimated how easy it would be and originally intended this to be just a week long project) so I just completetly ignored and just used the working fuzzer instead. (the brute_level==10 one which just bruteforces each singular byte in the input file sequentially.) . 


## Investigating lcov report

After applying these better fuzzing strategies, I got over three thousand three hundred corpus count, whereas previously I only got roughly two thousand. Now while this is a good improvement, the line coverage only rose from roughly 19% to 21.4% . Now investigating the better_coverage coverage output I realise that many of the files have completely zero coverage.

![zero_coverage](/pictures/coverage/cov0.png)

![zero_coverage](/pictures/coverage/cov1.png)

![zero_coverage](/pictures/coverage/cov2.png)

![zero_coverage](/pictures/coverage/cov3.png)


Now, lets start with json. I couldn't find anything which told anything about how to use json in apache so what I did was i just added --enable-json=static to the configure options in hopes of this doing something. Also looking at my HTTP-request generatated corpus I can not really find any requests which has the json thing so it makes sense that the coverage of the json decoder is zero, because there were no requests which used text/json as the mime type *facepalm* . Also another thing is that at this point in time the HTTP-request-generator does not even create json http bodies, so I need to add it to it.

We also need to do the same with the xml thing.

For the dbm thing according to this: https://httpd.apache.org/docs/2.4/mod/mod_authn_dbm.html  we need to put --with-berkeley-db  on the configure settings to use this module.

Now this also requires us to use AuthBasicProvider  with the value dbm aka `AuthBasicProvider dbm` , but this breaks other stuff because right now we use the Basic authentication, so we really can't do anything about this right now.

The apr-util missing stuff is actually because I accidentally compiled the coverage version of the binary with the apr-util stuff when as I actually did not compile the fuzzing version with the apr-util stuff. Whoops. Also I did not compile the fuzzing version with ssl so that is why it shows zero there.

So the only things which I need to do are:

* Compile the coverage version without ssl and apr-util.
* Add json and xml body generation to the HTTP-request generator.


Now, the compilation without ssl and apr-util is easy, just remove --with-apr-util= ...  and --with-openssl from the configure command and you are pretty much done.

Adding the json and xml generation in the request generator is also relatively easy. (See https://github.com/personnumber3377/HTTP-request-generator/commit/4dec58031d6e1bd43c68672d7b3fe9d9206ecf6a)



## Compilation bullcrap

Now after trying to recompile the coverage binary, I realized that something went wrong. The coverage only shows the coverage for the crypto openssl module thing, so that means that I did something wrong and that is why that happens.


.... Aaaaanddd I accidentally deleted the actual fuzzing binaries instead of the coverage binaries which are in another directory. Welp, just recompile those I guess. Thankfully the recompilation went succesfully for the fuzzing binaries. Phew. That was close.


Back to the coverage thing. This is surprisingly stubborn. I have been wondering here for an hour as to where the bug could be hiding, but it is nowhere to be found. I tried to clean everything and then do a complete recompile, but that does not work. 

...

Aaannnddd I found the bug. Again, I accidentally mistyped the codedir parameter for the coverage command to point to anothercoverage directory instead of coverage directory. The "anothercoverage" directory was another test which I did and that is why it didn't work. I should really cleanup my working directories to avoid these types of situations and I should probably start naming stuff with more appropriate names other than like "stuff.txt" and "anotherstuff.txt" :) .

Now it works perfectly..... except that it doesn't. It uses the oldaprstuff directories for some reason in the coverage thing. Back to the drawing board.

Upon further investigation I realized that the coverage/ directory is actually the old test thing and the "anothercoverage/" directory is the one which we want to actually compile. Whoops.



## Rechecking coverage

Now that we have removed the unused code from the coverage binary, it should report the correct coverage for the code which was actually compiled in the fuzzing version. The coverage is now actually accurate.

## How to integrate new testcases to an already fuzzing thing?

Now, I have already fuzzed the server for around a day straight and I really wouldn't like to restart the fuzzing process, because I forgot to add the xml and json input files, so I found this: https://groups.google.com/g/afl-users/c/_jDHV7X2i_w . So it is completely possible to add testcases.

I programmed this quick script:

```


import os
import sys


if __name__=="__main__":

	if len(sys.argv) < 3:
		print("Usage: "+str(sys.argv[0]) + "ORIGINAL_FILES SYNCDIR")
		exit(1)

	original_dir = sys.argv[1]

	sync_dir = sys.argv[2]

	files = os.listdir(original_dir)

	if original_dir[-1] != "/":
		original_dir += "/"

	if sync_dir[-1] != "/":
		sync_dir += "/"

	id_count = 0

	for file in files:

		length = 6-len(str(id_count))
		filename = "id:"+str(length*"0")+str(id_count)+",stuffwhatever"

		print("Running: "+str("cp "+str(original_dir)+str(file) + " "+str(sync_dir)+filename))
		os.system("cp "+str(original_dir)+str(file) + " "+str(sync_dir)+filename)
		id_count += 1




```

I also made a slight update to the generator.py script so that in addition to specifying mandatory headers, you can also add mandatory values for those mandatory headers. This way you can generate only specific kinds of requests if you want to fuzz more narrowly.

I also got bored of specifying GCM_CREDENTIAL_STORE=cache every time I opened a new console, so I added this line to my .bashrc: `export GCM_CREDENTIAL_STORE=cache` .

Now we just need for the fuzzer to pick those testcases up and hope that it causes code coverage in the json and xml things.

After a while the fuzzer hasn't done a sync round yet, so we need to wait for a lot longer than I expected.

Now at this point after roughly an hour of the coverage thing we have only gone through around 600 of the 3000 corpus count files and we already have 22.1% line coverage. It looks like the original poster did not have the apr-util stuff enabled like I had previously and now I think it is correct. Too bad that the original poster of course did not upload their coverage report anywhere (or for that matter their original corpus which they used) 🙃 , so we can not really inspect which files the person originally included or did not include in the report, so we can not really accurately gauge our fuzzing method to theirs because we do not know how many lines their.... oh wait. The person included a screenshot which shows that their code had just a bit over 53 thousand lines of code. Sorry about that. Still, my point about the coverage report and not sharing the corpus still stands. My version has over 81 thousand lines, so no wonder our coverage is less in percentage, because we are still even after removing apr-util including way more code than the poster of that original blog. Because they did not share their report I can not really compare. As of now, we have processed around 900 cases and we have around 18021 lines of code and the original poster had 18400 lines of code, even though they included far less stuff than I, so we still have a ways to go.

It is quite fascinating how every now and then the coverage reports new line coverage when going through the corpus files. I find it fascinating how a relatively simple algorithm can find even the tiniest nooks and crannies of a program. There are of course pitfalls in this kind of fuzzing, but the benefits vastly outweigh the cons.

After a bit of waiting I am now realizing that the fuzzer actually hasn't picked up the xml and json test cases for some reason. Now I am starting to suspect that those requests don't even trigger to functionality in those files. I will try a json request with a debugger and see if the server jumps to the json decoding code.

Now looking at the code, the json decode function only gets called by other modules. Looking around you can't seem to enable it as a module itsel in the httpd.conf file, so I guess we need to just ignore it. I am going to be satisfied if I get a line coverage even somewhat similar to what they achieved in their fuzzing session.

Now I actually forgot to include the "If-Match" and "If-Modified-Since" etc etc headers in my http request generator. Now I added those and added files which have those headers in to the fuzzing session. Now surely it will pick those up. Right? well... we will see soon. Now again it is 3 am and I am going to sleep and lets see what happens over the night (morning?).


... Now it is actually around 7 pm in the evening of the next day, because i spent quite a lot of time studying the finnish language for my exam, but now I am taking a break from that for a bit so I decided to update this blog post.

And I was correct. The fuzzer did pick those files up which I added. (The ones with the If-Modified-Since headers etc etc). Now the coverage script has also caught up with the fuzzers and now we have a whopping `lines......: 23.7%` coverage. I uploaded them to my github to the folder called "even_better_coverage/" if you want to take a look. The coverage is looking now atleast somewhat decent. It seems like the xml and json stuff did not get triggered by the files which I put in manually, so I assume that they are both used by some other module instead of being used directly. Looking at the apr_uri.c file we only have two lines which we haven't hit atleast once and they are both probably something to do with some flags set which can not be changed by passing different requests. The lines are these ones:

```
        28 :                           ? ((flags & APR_URI_UNP_REVEALPASSWORD)
     109           0 :                               ? uptr->password : "XXXXXXXX")
```

and

```
    111          56 :                       ((uptr->user     && !(flags & APR_URI_UNP_OMITUSER)) ||
     112           0 :                        (uptr->password && !(flags & APR_URI_UNP_OMITPASSWORD)))
```


and yeah, they are to do with some flag, which I think has something to do with redacting the password and the other one I am not too sure about. Anyway. The point is that there really isn't any place which hasn't gotten covered by the fuzzer, so I think that we have achieved atleast somewhat good coverage. This statement is also supported by the fact that the fuzzer has only found around three new corpus count files in the last couple of hours,which suggests to me that the fuzzer is quite done. I am going to keep investigating the coverage report and if there are any gaping holes, then I manually add a couple test cases again to help the fuzzer along.

A lot of the function which are not getting hit are associated with the http2 module, which I should have probably enabled in retrospect. Oh well.. the guy in the original post also did not enable it so I think we are still going to atleast find something, but I think we could have gotten a lot broader attack surface if we enabled that.

One interesting file from a security perspective is apr_snprintf.c which holds a lot of string processing code. Looking at my coverage report I am not really hitting it all that much. For example the function apr_vformatter has only like half and half coverage. This function is used in apr_snprintf for example, which I think is a custom implementation of snprintf. Now this looks quite interesting, because custom code which implements parts of libc functions usually include a ton of bugs in them. For example I think that Valve used their own memory allocator instead of the standard c code malloc and free , and that caused gaping security holes. Looking at the server code this custom apr_snprintf gets used in apreq_cookie.c in the function apreq_cookie_serialize

Also I forgot to add that I had to remove the Content-Length memmem checks in the fuzzing harness code, because they caused false positive crashes, because it calculated the value in a way which caused a crash.

Back to the apr_snprintf function. In the apreq_cookie_serialize function it is used with a constant format called "format = "%s=%s"; ". This is the only place where this custom function is used in the server main code in any meaningful way.

The apr_snprintf function is used a lot more in the other modules for example it is used in the http module in the chunk filter file (ap_http_chunk_filter). Also it is used in the metadata thing in the make_cookie function too.

## Another coverage bug?

Wait... hold on.. Not all of the files for the metadata module are showing up for some reason..... we probably forgot to clean the modules directory when compiling the coverage version.

Actually wait a second... we actually did everything correctly. You just need to enable the mod_expires  in the configuration file, and we did not do that, so the compilation script didn't even compile that stuff. So my bad, we actually did everything correctly.

## Investigating some poor coverage stuff:


Here is an example from the metadata module (mod_headers.c):


```
     428       14990 : static APR_INLINE const char *header_inout_cmd(cmd_parms *cmd,
     429             :                                                void *indirconf,
     430             :                                                const char *action,
     431             :                                                const char *hdr,
     432             :                                                const char *value,
     433             :                                                const char *subs,
     434             :                                                const char *envclause)
     435             : {
     436       14990 :     headers_conf *dirconf = indirconf;
     437       14990 :     const char *condition_var = NULL;
     438             :     const char *colon;
     439             :     header_entry *new;
     440       14990 :     ap_expr_info_t *expr = NULL;
     441             : 
     442       14990 :     apr_array_header_t *fixup = (cmd->info == &hdr_in)
     443       14990 :         ? dirconf->fixup_in   : (cmd->info == &hdr_out_always)
     444           0 :         ? dirconf->fixup_err
     445           0 :         : dirconf->fixup_out;
     446             : 
     447       14990 :     new = (header_entry *) apr_array_push(fixup);
     448             : 
     449       14990 :     if (!strcasecmp(action, "set"))
     450           0 :         new->action = hdr_set;
     451       14990 :     else if (!strcasecmp(action, "setifempty"))
     452           0 :         new->action = hdr_setifempty;
     453       14990 :     else if (!strcasecmp(action, "add"))
     454           0 :         new->action = hdr_add;
     455       14990 :     else if (!strcasecmp(action, "append"))
     456           0 :         new->action = hdr_append;
     457       14990 :     else if (!strcasecmp(action, "merge"))
     458           0 :         new->action = hdr_merge;
     459       14990 :     else if (!strcasecmp(action, "unset"))
     460       14990 :         new->action = hdr_unset;
     461           0 :     else if (!strcasecmp(action, "echo"))
     462           0 :         new->action = hdr_echo;
     463           0 :     else if (!strcasecmp(action, "edit"))
     464           0 :         new->action = hdr_edit;
     465           0 :     else if (!strcasecmp(action, "edit*"))
     466           0 :         new->action = hdr_edit_r;
     467           0 :     else if (!strcasecmp(action, "note"))
     468           0 :         new->action = hdr_note;
     469             :     else
```

Then a bit later we make a call to parse_format_string:


```
14990 :     return parse_format_string(cmd, new, value);
```

Then inside parse_format_string :

```
     397       14990 :     if (hdr->action == hdr_unset || hdr->action == hdr_echo) {
     398       14990 :         return NULL;
     399             :     }

```
because hdr-action is set in every case as we can see in the upper lines, then we never reach these lines of code:


```

     400             :     /* Tags are in the replacement value for edit */
     401           0 :     else if (hdr->action == hdr_edit || hdr->action == hdr_edit_r ) {
     402           0 :         s = hdr->subs;
     403           0 :     }
     404             : 
     405           0 :     if (!strncmp(s, "expr=", 5)) { 
     406             :         const char *err;
     407           0 :         hdr->expr_out = ap_expr_parse_cmd(cmd, s+5, 
     408             :                                           AP_EXPR_FLAG_STRING_RESULT,
     409             :                                           &err, NULL);
     410           0 :         if (err) {
     411           0 :             return apr_pstrcat(cmd->pool,
     412           0 :                     "Can't parse value expression : ", err, NULL);
     413             :         }
     414           0 :         return NULL;
     415             :     }
     416             : 
     417           0 :     hdr->ta = apr_array_make(p, 10, sizeof(format_tag));
     418             : 
     419           0 :     while (*s) {
     420           0 :         if ((res = parse_format_tag(p, (format_tag *) apr_array_push(hdr->ta), &s))) {
     421           0 :             return res;
     422             :         }
     423             :     }
     424           0 :     return NULL;

```

So, the question is: How do we make new->action something other than hdr_unset or hdr_echo?


```
     428       14990 : static APR_INLINE const char *header_inout_cmd(cmd_parms *cmd,
     429             :                                                void *indirconf,
     430             :                                                const char *action,
     431             :                                                const char *hdr,
     432             :                                                const char *value,
     433             :                                                const char *subs,
     434             :                                                const char *envclause)
```

the action is simply passed as an argument to the function, so we need to search for references to header_inout_cmd and see how we can affect the arguments which are passed to it.

The only reference to the function is in the same file in the function header_cmd :

```
static const char *header_cmd(cmd_parms *cmd, void *indirconf,
                              const char *args)
{
    const char *action;
    const char *hdr;
    const char *val;
    const char *envclause;
    const char *subs;

    action = ap_getword_conf(cmd->temp_pool, &args);
    if (cmd->info == &hdr_out_onsuccess) {
        if (!strcasecmp(action, "always")) {
            cmd->info = &hdr_out_always;
            action = ap_getword_conf(cmd->temp_pool, &args);
        }
        else if (!strcasecmp(action, "onsuccess")) {
            action = ap_getword_conf(cmd->temp_pool, &args);
        }
    }
    hdr = ap_getword_conf(cmd->pool, &args);
    val = *args ? ap_getword_conf(cmd->pool, &args) : NULL;
    subs = *args ? ap_getword_conf(cmd->pool, &args) : NULL;
    envclause = *args ? ap_getword_conf(cmd->pool, &args) : NULL;

    if (*args) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           " has too many arguments", NULL);
    }

    return header_inout_cmd(cmd, indirconf, action, hdr, val, subs, envclause);
}

```

the only references to header_cmd are here:

```
static const command_rec headers_cmds[] =
{
    AP_INIT_RAW_ARGS("Header", header_cmd, &hdr_out_onsuccess, OR_FILEINFO,
                     "an optional condition, an action, header and value "
                     "followed by optional env clause"),
    AP_INIT_RAW_ARGS("RequestHeader", header_cmd, &hdr_in, OR_FILEINFO,
                     "an action, header and value followed by optional env "
                     "clause"),
    {NULL}
};

```


After doing some research, It looks like this mod_headers thing needs to be enabled in the configuration file to make the program flow differ, so this actually isn't something we can affect. :(  https://httpd.apache.org/docs/2.4/mod/mod_headers.html

Another area of interest is the session cookie stuff. In the session_cookie_save function we are not calling ap_cookie_write, because the session_rec *z is not encoded, apparently.

```
      68         176 :         if (z->encoded && z->encoded[0]) {
      69           0 :             ap_cookie_write(r, conf->name, z->encoded, conf->name_attrs,
      70           0 :                             maxage, r->err_headers_out,
      71             :                             NULL);
      72           0 :         }

```

the place in mod_session.c where we encode a possible cookie is at session_identity_encode `z->encoded = buffer;` . But looking at the report I can see that the line gets called numerous times, but that I think is for other stuff.

Here is a piece of code which I found in util_cookies.c :


```
            if (!strncmp(trim, name, len)) {
                if (v->encoded) {
                    if (strcmp(v->encoded, trim + len)) {
                        v->duplicated = 1;
                    }
                }
                v->encoded = apr_pstrdup(v->r->pool, trim + len);
                eat = 1;
            }
```

the strncmp call basically returns zero if the strings are equivalent.


Here in the coverage report we can see that we do not hit the code not even once.

```

     202        4768 :             if (!strncmp(trim, name, len)) {
     203           0 :                 if (v->encoded) {
     204           0 :                     if (strcmp(v->encoded, trim + len)) {
     205           0 :                         v->duplicated = 1;
     206           0 :                     }
     207           0 :                 }
     208           0 :                 v->encoded = apr_pstrdup(v->r->pool, trim + len);
     209           0 :                 eat = 1;
     210           0 :             }
```

the name value gets defined here:

```
const char *name = apr_pstrcat(v->r->pool, v->name ? v->name : "", "=", NULL);
```
v is defined previously:

```
ap_cookie_do *v = varg;
```
And v is passed an argument to the function. This function is called here:


```
AP_DECLARE(apr_status_t) ap_cookie_read(request_rec * r, const char *name, const char **val,
                                        int remove)
{

    ap_cookie_do v;
    v.r = r;
    v.encoded = NULL;
    v.new_cookies = apr_table_make(r->pool, 10);
    v.duplicated = 0;
    v.name = name;

    apr_table_do(extract_cookie_line, &v, r->headers_in,    // <---- here
                 "Cookie", "Cookie2", NULL);
```
There is a call to ap_cookie_read in session_cookie_load .

```
static apr_status_t session_cookie_load(request_rec * r, session_rec ** z)
{

    session_cookie_dir_conf *conf = ap_get_module_config(r->per_dir_config,
                                                    &session_cookie_module);

    session_rec *zz = NULL;
    const char *val = NULL;
    const char *note = NULL;
    const char *name = NULL;
    request_rec *m = r;

    /* find the first redirect */
    while (m->prev) {
        m = m->prev;
    }
    /* find the main request */
    while (m->main) {
        m = m->main;
    }

    /* is our session in a cookie? */
    if (conf->name2_set) {
        name = conf->name2;
    }
    else if (conf->name_set) {
        name = conf->name;
    }
    else {
        return DECLINED;
    }

    /* first look in the notes */
    note = apr_pstrcat(m->pool, MOD_SESSION_COOKIE, name, NULL);
    zz = (session_rec *)apr_table_get(m->notes, note);
    if (zz) {
        *z = zz;
        return OK;
    }

    /* otherwise, try parse the cookie */
    ap_cookie_read(r, name, &val, conf->remove);
```

Looking at the coverage report:

```
     134       56789 :     if (conf->name2_set) {
     135           0 :         name = conf->name2;
     136           0 :     }
     137       56789 :     else if (conf->name_set) {
     138        8183 :         name = conf->name;
     139        8183 :     }
     140             :     else {
     141       48606 :         return DECLINED;
     142             :     }
     143             : 
     144             :     /* first look in the notes */
     145        8183 :     note = apr_pstrcat(m->pool, MOD_SESSION_COOKIE, name, NULL);
     146        8183 :     zz = (session_rec *)apr_table_get(m->notes, note);
     147        8183 :     if (zz) {
     148        4867 :         *z = zz;
     149        4867 :         return OK;
     150             :     }
     151             : 
     152             :     /* otherwise, try parse the cookie */
     153        3316 :     ap_cookie_read(r, name, &val, conf->remove);
     154             : 

```



so we are hitting ap_cookie_read and we are actually setting the name variable. The important bit is:


```
    session_cookie_dir_conf *conf = ap_get_module_config(r->per_dir_config,
                                                    &session_cookie_module);
```

and here it is:


```
#define MOD_SESSION_COOKIE "mod_session_cookie"

module AP_MODULE_DECLARE_DATA session_cookie_module;

/**
 * Structure to carry the per-dir session config.
 */
typedef struct {
    const char *name;
    int name_set;
    const char *name_attrs;
    const char *name2;
    int name2_set;
    const char *name2_attrs;
    int remove;
    int remove_set;
    int maxage;
    int maxage_set;
} session_cookie_dir_conf;
```


so the name is set in the configuration file:

```
<Location "/x">
    AuthFormProvider file
    AuthUserFile "conf/passwd"
    AuthType form
    AuthName "/admin"
    AuthFormLoginRequiredLocation "http://example.com/login.html"

    Session On
    SessionCookieName session path=/

    Require valid-user
</Location>
```

.... aaaannndd the name of the session cookie is simply "session" 🙃 . So basically we need to just add A request which has tries to access /x on the server and has a "Cookie: session=whateverblabla" cookie in the request.

Lets use the HTTP-Request generator to generate a couple of these requests.

Ok, so I generated those requests and now lets see if the fuzzer picks those up.

Now, I think that I should create something like a debug build of the server where I can use gdb to step through any input through it and see which the values area, and I think that I am actually going to do that. I am going to make a new directory called ~/httpd-debugging/ which contains that build.... well maybe I will do that tomorrow.

Now after waiting around half an hour we see that if we run: `grep -iRl "Cookie: session=sessioncookie"` on the fuzzing_output directory we get:


```
thing/queue/id:000042,stuffwhatever
thing/queue/id:000044,stuffwhatever
thing/queue/id:000046,stuffwhatever
thing/queue/id:000041,stuffwhatever
thing/queue/id:000047,stuffwhatever
thing/queue/id:000048,stuffwhatever
thing/queue/id:000040,stuffwhatever
thing/queue/id:000049,stuffwhatever
thing/queue/id:000043,stuffwhatever
thing/queue/id:000045,stuffwhatever
slave2/queue/id:004105,sync:master,src:004126
slave2/queue/id:004104,sync:master,src:004125,+cov
slave2/queue/id:004197,src:004104,time:242090716,execs:361343267,op:havoc,rep:2
slave2/queue/id:004102,sync:master,src:004123
slave2/queue/id:004109,sync:master,src:004130
slave2/queue/id:004099,sync:master,src:004119,+cov
slave2/queue/id:004101,sync:master,src:004122,+cov
slave2/queue/id:004198,src:004104,time:242092365,execs:361346276,op:havoc,rep:4
slave2/queue/id:004108,sync:master,src:004129
slave3/queue/id:004063,sync:master,src:004125,+cov
slave3/queue/id:004067,sync:master,src:004129
slave3/queue/id:004068,sync:master,src:004130
slave3/queue/id:004060,sync:master,src:004122,+cov
slave3/queue/id:004061,sync:master,src:004123
slave3/queue/id:004155,src:004063,time:241485182,execs:363017922,op:havoc,rep:8
slave3/queue/id:004154,src:004063,time:241484974,execs:363017534,op:havoc,rep:4
slave3/queue/id:004057,sync:master,src:004119,+cov
slave3/queue/id:004064,sync:master,src:004126
master/queue/id:004129,src:004122,time:241654653,execs:239260945,op:havoc,rep:2
master/queue/id:004220,sync:slave2,src:004198
master/queue/id:004119,sync:thing,src:000040,+cov
master/queue/id:004219,sync:slave2,src:004197
master/queue/id:004126,src:004119,time:241641459,execs:239232492,op:havoc,rep:2
master/queue/id:004130,src:004122,time:241654712,execs:239261066,op:havoc,rep:8
master/queue/id:004125,src:004119,time:241641350,execs:239232275,op:havoc,rep:2,+cov
master/queue/id:004122,src:004119,time:241638960,execs:239226983,op:havoc,rep:4,+cov
master/queue/id:004123,src:004119,time:241639022,execs:239227107,op:havoc,rep:2
master/queue/id:004229,sync:slave3,src:004154

```
so we see that the fuzzer has picked those test cases up, so now we are hitting the previously uncovered code. Before we incorporated those test cases to the fuzzer, we had around 4110 edges. Now we have 4230 , so we have succesfully increased coverage by manual test case insertion! :) 











