
# Fuzzing apache http server

I wanted to write this writeup as notes to myself and to share my story of fuzzing apache. Now at this point I have already setup a good fuzzing workflow, but as of writing this I haven't found any interesting crashes. Now I am going to try to remember my story from the start:


One day I came across this post: https://securitylab.github.com/research/fuzzing-apache-1/ . As a computer security enthusiast this caught my attention. As usual, I jumped in without doing any research.

I first tried to follow the instructions provided, but then I got a good idea: Let's use afl-clang-lto ! After compiling afl-fuzz with afl-clang-lto LLVM support I tried to compile apache. As usual, there were a mountain of errors, because we are now using afl-clang-lto. After fiddling a couple of days with the configuration options I finally came up with this:


{% raw %}
```
CC=afl-clang-lto CXX=afl-clang-lto++ RANLIB=llvm-ranlib AR=llvm-ar CFLAGS="-std=c99 -g -ggdb -fsanitize=address,undefined -fno-sanitize-recover=all -O3" CXXFLAGS="-std=c99 -g -ggdb -O3 -fsanitize=address,undefined -fno-sanitize-recover=all" LDFLAGS="-std=c99 -fsanitize=address,undefined -fno-sanitize-recover=all -lm -fuse-ld=/home/cyberhacker/Asioita/newaflfuzz/shit/llvm-project-llvmorg-15.0.7/build/bin/ld.lld" ./configure --prefix='/home/cyberhacker/httpd-lto/install' --with-included-apr --enable-static-support --enable-mods-static=few --disable-shared --disable-pie --enable-debugger-mode --with-mpm=prefork  --enable-negotiation=static --enable-session=static --enable-auth-form=static --enable-request=static --enable-rewrite=static --enable-auth_digest=static --enable-deflate=static  --enable-crypto=static --with-crypto --with-openssl --enable-proxy_html=static --enable-xml2enc=static --enable-cache=static --enable-cache-disk=static --enable-data=static --enable-substitute=static --enable-ratelimit=static --enable-dav=static
```
{% endraw %}

In addition to this, I still got a couple of errors. After tracking down a build configuration file I wrote this script:

{% raw %}
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
{% endraw %}
The errors were caused by -Werror statements which I removed. It obviously still gives warnings, but I do not care about those. I just wanted to get something to work. This is methaphorically sweeping the dirt under the rug instead of cleaning it up. Also I added a couple of files and lines to the project in order to fuzz the server. You can find these changes in the diff file which I uploaded to my github and you can copy the modified source from my github too. I also uploaded the final binaries to my github along with all the configuration and other installation files. The installation files assume that the server root is at /home/cyberhacker/httpd-lto/install/ so if you want to try to fuzz on your own, then you need to change those or compile with --prefix=YOURPREFIXHERE . Now I finally got a fuzzing setup which atleast worked somewhat. I run the fuzzer with this:

{% raw %}
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
{% endraw %}

## Creating htdocs folder.

Now the original post said that they had created random content with short filenames in the htdocs, but once again, they were very kind and did not share this htdocs folder anywhere 🙃 . So once again I needed to somehow create my own and out comes this: https://github.com/personnumber3377/samplefilegenerator . It creates random files in a specified directory. One features which it is missing is that it does not create subdirectories, which would we good, although you can of course manually create subdirs and then run the script on that directory, but that is quite janky. The files which it creates are binary files, text files, random images, random pdf files and random html files which consist of just simple autogenerated `<p1>` tags. To create a htdocs folder similar to the original blog post just run the script with your htdocs directory as a command line argument.



## Better corpus



Now, the writer of the original post did not specify in great detail how he came up with the corpus which was used in the fuzzing, but something about https://github.com/AFLplusplus/Grammar-Mutator  was said. Well, I tried it and yes it created better inputs than what you would have gotten by just running with a single empty file as the corpus, but the coverage was really poor still. (see "poor_coverage" on my github page on httpdfuzzing) . Only around 19% of the lines got covered according to lcov .

Now looking at the autogenerated files, they look something like this:

{% raw %}
```
UNLOCK dav://127.0.0.1:8080/ HTTP/3.0
1

```
{% endraw %}
and like this:

{% raw %}
```
HEAD dav://127.0.0.1:8080/ HTTP/0.9
TE: 
Via: z


```
{% endraw %}

So these are kinda good requests, but not good enough. Looking around the web for a script which just creates random requests with random headers and random request body, so I actually wrote my own: https://github.com/personnumber3377/HTTP-request-generator . This script creates some random requests with random headers, but it is sort of intelligent in the sense that it opens your htdocs folder and then actually adds a valid filename to the request (eq if you have a file called foo.html, then it creates a request like GET /foo.html HTTP/1.1 ... ) . Now this tool creates requests like these:


{% raw %}
```
POST /s?Ug=o HTTP/1.1
Host: U
Accept-Charset: iso-8859-5
Content-Encoding: deflate
Accept-Language: tk

FwFXjxjWwjSJihFewHDxeQKbvNVIdAVnnymqOALATwknnpDIyuEDwloRZptbJbscWKFNNFYhGjryiAxcFIVeg

```
{% endraw %}

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

{% raw %}
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
{% endraw %}

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

{% raw %}
```
        28 :                           ? ((flags & APR_URI_UNP_REVEALPASSWORD)
     109           0 :                               ? uptr->password : "XXXXXXXX")
```
{% endraw %}

and

{% raw %}
```
    111          56 :                       ((uptr->user     && !(flags & APR_URI_UNP_OMITUSER)) ||
     112           0 :                        (uptr->password && !(flags & APR_URI_UNP_OMITPASSWORD)))
```
{% endraw %}


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


{% raw %}
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
{% endraw %}

Then a bit later we make a call to parse_format_string:


{% raw %}
```
14990 :     return parse_format_string(cmd, new, value);
```
{% endraw %}

Then inside parse_format_string :

{% raw %}
```
     397       14990 :     if (hdr->action == hdr_unset || hdr->action == hdr_echo) {
     398       14990 :         return NULL;
     399             :     }

```
{% endraw %}
because hdr-action is set in every case as we can see in the upper lines, then we never reach these lines of code:


{% raw %}
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
{% endraw %}

So, the question is: How do we make new->action something other than hdr_unset or hdr_echo?


{% raw %}
```
     428       14990 : static APR_INLINE const char *header_inout_cmd(cmd_parms *cmd,
     429             :                                                void *indirconf,
     430             :                                                const char *action,
     431             :                                                const char *hdr,
     432             :                                                const char *value,
     433             :                                                const char *subs,
     434             :                                                const char *envclause)
```
{% endraw %}

the action is simply passed as an argument to the function, so we need to search for references to header_inout_cmd and see how we can affect the arguments which are passed to it.

The only reference to the function is in the same file in the function header_cmd :

{% raw %}
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
{% endraw %}

the only references to header_cmd are here:

{% raw %}
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
{% endraw %}


After doing some research, It looks like this mod_headers thing needs to be enabled in the configuration file to make the program flow differ, so this actually isn't something we can affect. :(  https://httpd.apache.org/docs/2.4/mod/mod_headers.html

Another area of interest is the session cookie stuff. In the session_cookie_save function we are not calling ap_cookie_write, because the session_rec *z is not encoded, apparently.

{% raw %}
```
      68         176 :         if (z->encoded && z->encoded[0]) {
      69           0 :             ap_cookie_write(r, conf->name, z->encoded, conf->name_attrs,
      70           0 :                             maxage, r->err_headers_out,
      71             :                             NULL);
      72           0 :         }

```
{% endraw %}

the place in mod_session.c where we encode a possible cookie is at session_identity_encode `z->encoded = buffer;` . But looking at the report I can see that the line gets called numerous times, but that I think is for other stuff.

Here is a piece of code which I found in util_cookies.c :


{% raw %}
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
{% endraw %}

the strncmp call basically returns zero if the strings are equivalent.


Here in the coverage report we can see that we do not hit the code not even once.

{% raw %}
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
{% endraw %}

the name value gets defined here:

{% raw %}
```
const char *name = apr_pstrcat(v->r->pool, v->name ? v->name : "", "=", NULL);
```
{% endraw %}
v is defined previously:

{% raw %}
```
ap_cookie_do *v = varg;
```
{% endraw %}
And v is passed an argument to the function. This function is called here:


{% raw %}
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
{% endraw %}
There is a call to ap_cookie_read in session_cookie_load .

{% raw %}
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
{% endraw %}

Looking at the coverage report:

{% raw %}
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
{% endraw %}



so we are hitting ap_cookie_read and we are actually setting the name variable. The important bit is:


{% raw %}
```
    session_cookie_dir_conf *conf = ap_get_module_config(r->per_dir_config,
                                                    &session_cookie_module);
```
{% endraw %}

and here it is:


{% raw %}
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
{% endraw %}


so the name is set in the configuration file:

{% raw %}
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
{% endraw %}

.... aaaannndd the name of the session cookie is simply "session" 🙃 . So basically we need to just add A request which has tries to access /x on the server and has a "Cookie: session=whateverblabla" cookie in the request.

Lets use the HTTP-Request generator to generate a couple of these requests.

Ok, so I generated those requests and now lets see if the fuzzer picks those up.

Now, I think that I should create something like a debug build of the server where I can use gdb to step through any input through it and see which the values area, and I think that I am actually going to do that. I am going to make a new directory called ~/httpd-debugging/ which contains that build.... well maybe I will do that tomorrow.

Now after waiting around half an hour we see that if we run: `grep -iRl "Cookie: session=sessioncookie"` on the fuzzing_output directory we get:


{% raw %}
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
{% endraw %}
so we see that the fuzzer has picked those test cases up, so now we are hitting the previously uncovered code. Before we incorporated those test cases to the fuzzer, we had around 4110 edges. Now we have 4230 , so we have succesfully increased coverage by manual test case insertion! :) 

Now, after running the coverage script again we can see that the coverage is a lot better:

{% raw %}
```
     202        5341 :             if (!strncmp(trim, name, len)) {
     203         506 :                 if (v->encoded) {
     204         179 :                     if (strcmp(v->encoded, trim + len)) {
     205         102 :                         v->duplicated = 1;
     206         102 :                     }
     207         179 :                 }
     208         506 :                 v->encoded = apr_pstrdup(v->r->pool, trim + len);
     209         506 :                 eat = 1;
     210         506 :             }
```
{% endraw %}

except that when we look at the other piece of code:

{% raw %}
```
     428        8760 : static APR_INLINE const char *header_inout_cmd(cmd_parms *cmd,
     429             :                                                void *indirconf,
     430             :                                                const char *action,
     431             :                                                const char *hdr,
     432             :                                                const char *value,
     433             :                                                const char *subs,
     434             :                                                const char *envclause)
     435             : {
     436        8760 :     headers_conf *dirconf = indirconf;
     437        8760 :     const char *condition_var = NULL;
     438             :     const char *colon;
     439             :     header_entry *new;
     440        8760 :     ap_expr_info_t *expr = NULL;
     441             : 
     442        8760 :     apr_array_header_t *fixup = (cmd->info == &hdr_in)
     443        8760 :         ? dirconf->fixup_in   : (cmd->info == &hdr_out_always)
     444           0 :         ? dirconf->fixup_err
     445           0 :         : dirconf->fixup_out;
     446             : 
     447        8760 :     new = (header_entry *) apr_array_push(fixup);
     448             : 
     449        8760 :     if (!strcasecmp(action, "set"))
     450           0 :         new->action = hdr_set;
     451        8760 :     else if (!strcasecmp(action, "setifempty"))
     452           0 :         new->action = hdr_setifempty;
     453        8760 :     else if (!strcasecmp(action, "add"))
     454           0 :         new->action = hdr_add;
     455        8760 :     else if (!strcasecmp(action, "append"))
     456           0 :         new->action = hdr_append;
     457        8760 :     else if (!strcasecmp(action, "merge"))
     458           0 :         new->action = hdr_merge;
     459        8760 :     else if (!strcasecmp(action, "unset"))
     460        8760 :         new->action = hdr_unset;
     461           0 :     else if (!strcasecmp(action, "echo"))
```
{% endraw %}

We see that it still justs sets the action to hdr_unset .

{% raw %}
```
     572        8760 :     action = ap_getword_conf(cmd->temp_pool, &args);
     573        8760 :     if (cmd->info == &hdr_out_onsuccess) {
```
{% endraw %}

Now, when compiling the debugging build, it did not compile the apr_crypto_openssl-2.so file for some reason. After like an hour of debugging I found that I had accidentally typed `--enable-openssl` instead of `--with-openssl` . That was quite a dumb mistake, but thankfully I found it.


Now, trying to run the debugging build with one of the generated requests does not cause the header_cmd to be called. 

There is a comment before the function `/* Handle all (xxx)Header directives */` , now I do not even know what (xxx)Header directives even are.

I have no idea how to call this function even with a specific input. Maybe we should try actually reading the documentation: https://httpd.apache.org/docs/2.4/mod/mod_headers.html .


There are these lines in the configuration file:

{% raw %}
```
<IfModule headers_module>
    #
    # Avoid passing HTTP_PROXY environment to CGI's on this or any proxied
    # backend servers which have lingering "httpoxy" defects.
    # 'Proxy' request header is undefined by the IETF, not listed by IANA
    #
    RequestHeader unset Proxy early
</IfModule>
```
{% endraw %}
So the RequestHeader is I think one of these "(xxx)Header" directives which the code comment talks about so I think we need to append Proxy to the headers and then this will cause the code to be called. Lets see:

Now, yes the header_cmd gets called, but I think that it is actually for the configuration files instead of each request itself, so we wen't through a lot of effort for nothing. :) Well, we got a bit more of coverage accidentally since we added the Cookie: sessio=blablabla; thing to the requests. They even mention this in a code comment before parse_format_string : `Header add MyHeader "Free form text %D %t more text"` *facepalm* .

Now looking at the rest of the code we can see that we can not call parse_misc_string for example from anywhere else other than parsing the config file so we can not call the code by crafting a specific request, oh well.

According to the report we have zero coverage on apr_strnatcmp.c so I lets take a look at that next.

These are the files where the file gets called from:

{% raw %}
```
srclib/apr/dbd/apr_dbd_odbc.c
srclib/apr/test/teststrnatcmp.c
srclib/apr/strings/apr_strnatcmp.c
srclib/apr/exports.c
modules/http2/h2_push.c
modules/http2/h2_proxy_util.c
modules/http2/h2_alt_svc.c
modules/http2/h2_from_h1.c
modules/http2/h2_util.c
modules/md/md_curl.c
modules/md/mod_md_config.c
modules/md/md_util.c
modules/md/md_crypt.c
modules/md/md_acme.c
modules/md/md_acme_authz.c
modules/generators/mod_autoindex.c
server/exports.c

```
{% endraw %}

Again, we do not have http2 enabled. We also don't have md enabled, but we have mod_autoindex ! Now mod_autoindex just generates those "Index of ..." pages when you try to access a directory instead of a file. Now, the reason why we have't gotten this covered is because the directory structure of my server is just the root directory without any subdirs. Then when the fuzzer tries to access / , the server directs that to /index.html , so if we remove index.html, that should help the problem and yes, that does cause a call to output_directories , but that code is not really important to parsing the requests so I do not think that it is worth doing, since the code triggered is code, which doesn't even process the input requests, but lets just do that because more coverage = always better right?

I made a subdir called "/az/" in the htdocs folder and now lets see if the fuzzer picks it up and it does! I know that it really doesn't matter, since the code has basically nothing to do with parsing the http request, but still.

## Crashes?


Now, after all of that effort it is time to see if we actually got anything worth our time.

Looking at one of the crashes in the fuzzer binary with asan and stuff we get this:

{% raw %}
```
__GI_raise (sig=sig@entry=6) at ../sysdeps/unix/sysv/linux/raise.c:50
50	../sysdeps/unix/sysv/linux/raise.c: No such file or directory.
(gdb) where
#0  __GI_raise (sig=sig@entry=6) at ../sysdeps/unix/sysv/linux/raise.c:50
#1  0x00007ffff796e859 in __GI_abort () at abort.c:79
#2  0x00005555559dd90f in __sanitizer::Abort() ()
#3  0x00005555559db35c in __sanitizer::Die() ()
#4  0x00005555559f8fe9 in __ubsan_handle_nonnull_arg_abort ()
#5  0x0000555555f5edb3 in apr_brigade_flatten ()
#6  0x0000555555ae8e1a in deflate_in_filter ()
#7  0x0000555555b7687f in ap_discard_request_body ()
#8  0x0000555555e73647 in default_handler ()
#9  0x0000555555d31805 in ap_run_handler ()
#10 0x0000555555d345d1 in ap_invoke_handler ()
#11 0x0000555555b57b9c in ap_process_async_request ()
#12 0x0000555555b5847e in ap_process_request ()
#13 0x0000555555b3ce7c in ap_process_http_connection ()
#14 0x0000555555dbbef5 in ap_run_process_connection ()
#15 0x0000555555d2c142 in child_main ()
#16 0x0000555555d2a1a6 in make_child ()
#17 0x0000555555d29082 in prefork_run ()
#18 0x0000555555dcbec2 in ap_run_mpm ()
#19 0x0000555555d61fa4 in main ()

```
{% endraw %}
then looking at the asan log:

{% raw %}
```
buckets/apr_brigade.c:281:19: runtime error: null pointer passed as argument 2, which is declared to never be null
/usr/include/string.h:44:28: note: nonnull attribute specified here
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior buckets/apr_brigade.c:281:19 in 

```
{% endraw %}
So it is undefined behaviour because we are passing a null string as an argument to a function.

Looking at the rest of the crashes it seems that they are just copies of this same bug. This bug occurs here:

{% raw %}
```
        if (str_len + actual > *len) {
            str_len = *len - actual;
        }

        /* XXX: It appears that overflow of the final bucket
         * is DISCARDED without any warning to the caller.
         *
         * No, we only copy the data up to their requested size.  -- jre
         */
        memcpy(c, str, str_len);     <--------- HERE

        c += str_len;
        actual += str_len;

        /* This could probably be actual == *len, but be safe from stray
         * photons. */
        if (actual >= *len) {
            break;
        }
```
{% endraw %}


We can use our debugging build to further investigate this possible bug. This does not even cause a crash, because str is null, but str_len is also zero, so we can not even do a null reference. :( . And yeah, I am right. When the str is NULL the str_len also seems to be null even before the if check before the memcpy, so bypassing that check is not really going to do anything for us.


## Ditching the banlist.

Up until now i have compiled the binary with the banlist.txt which lists "unstable" functions, but I honestly have no idea why they are "unstable" so I am from now on not going to omit those functions.

Omitting these functions of course causes an immense "stability" drop, because now the fuzzer recognizes that instability, but it will help with coverage. Looking at the banlist.txt it contains a lot of string parsing functions which could be actually useful to find crashes.

As expected the fuzzer took a bit of a stability hit but I do not really care that much.

## More investigation of the code coverage report.

Looking at the code report there isn't anything that immediately jumps out for me, so I guess now we just sit back and wait until we actually find a useful crash, maybe we will have to use the byte bruteforce mutator after a while and see what it does, but hey, for now  I think that this is good setup and we will wait for a couple weeks to wait for actually useful crashes.

I actually patched the code such that the ubsan "crash" does no longer exist. I added a quick patch which check that if str==Null and str_len==0 then it simply continues instead of doing the memcpy.

Anyway. Now it is a waiting game. (for now)

## Update on the fuzzing.

It has been around a day and yeah, the patch which I added fixed the undefined behaviour crash. Now the fuzzer is still showing zero crashes, but hopefully that will change soon. The fuzzer is slowly getting slower at finding new corpus files so I am a bit concerned that we will not even find a single actually useful bug, but lets not give up yet. Also I am thinking of creating a sort of precision fuzzing framework for apache, which lets you choose like on function to fuzz, so that you can fuzz the critical request parsing functions thoroughly. For example we could make a custom fuzzer just to fuzz this function (util.c):

{% raw %}
```
static int unescape_url(char *url, const char *forbid, const char *reserved)
{
    int badesc, badpath;
    char *x, *y;

    badesc = 0;
    badpath = 0;

    if (url == NULL) {
        return OK;
    }
    /* Initial scan for first '%'. Don't bother writing values before
     * seeing a '%' */
    y = strchr(url, '%');
    if (y == NULL) {
        return OK;
    }
    for (x = y; *y; ++x, ++y) {
        if (*y != '%') {
            *x = *y;
        }
        else {
            if (!apr_isxdigit(*(y + 1)) || !apr_isxdigit(*(y + 2))) {
                badesc = 1;
                *x = '%';
            }
            else {
                char decoded;
                decoded = x2c(y + 1);
                if ((decoded == '\0')
                    || (forbid && ap_strchr_c(forbid, decoded))) {
                    badpath = 1;
                    *x = decoded;
                    y += 2;
                }
                else if (reserved && ap_strchr_c(reserved, decoded)) {
                    *x++ = *y++;
                    *x++ = *y++;
                    *x = *y;
                }
                else {
                    *x = decoded;
                    y += 2;
                }
            }
        }
    }
    *x = '\0';
    if (badesc) {
        return HTTP_BAD_REQUEST;
    }
    else if (badpath) {
        return HTTP_NOT_FOUND;
    }
    else {
        return OK;
    }
}
```
{% endraw %}


or we can make a custom fuzzer to fuzz this function:

{% raw %}
```
AP_CORE_DECLARE(void) ap_parse_uri(request_rec *r, const char *uri)
{
    int status = HTTP_OK;

    r->unparsed_uri = apr_pstrdup(r->pool, uri);

    /* http://issues.apache.org/bugzilla/show_bug.cgi?id=31875
     * http://issues.apache.org/bugzilla/show_bug.cgi?id=28450
     *
     * This is not in fact a URI, it's a path.  That matters in the
     * case of a leading double-slash.  We need to resolve the issue
     * by normalizing that out before treating it as a URI.
     */
    while ((uri[0] == '/') && (uri[1] == '/')) {
        ++uri ;
    }
    if (r->method_number == M_CONNECT) {
        status = apr_uri_parse_hostinfo(r->pool, uri, &r->parsed_uri);
    }
    else {
        status = apr_uri_parse(r->pool, uri, &r->parsed_uri);
    }

    if (status == APR_SUCCESS) {
        /* if it has a scheme we may need to do absoluteURI vhost stuff */
        if (r->parsed_uri.scheme
            && !ap_cstr_casecmp(r->parsed_uri.scheme, ap_http_scheme(r))) {
            r->hostname = r->parsed_uri.hostname;
        }
        else if (r->method_number == M_CONNECT) {
            r->hostname = r->parsed_uri.hostname;
        }

        r->args = r->parsed_uri.query;
        if (r->parsed_uri.path) {
            r->uri = r->parsed_uri.path;
        }
        else if (r->method_number == M_OPTIONS) {
            r->uri = apr_pstrdup(r->pool, "*");
        }
        else {
            r->uri = apr_pstrdup(r->pool, "/");
        }

#if defined(OS2) || defined(WIN32)
        /* Handle path translations for OS/2 and plug security hole.
         * This will prevent "http://www.wherever.com/..\..\/" from
         * returning a directory for the root drive.
         */
        {
            char *x;

            for (x = r->uri; (x = strchr(x, '\\')) != NULL; )
                *x = '/';
        }
#endif /* OS2 || WIN32 */
    }
    else {
        r->args = NULL;
        r->hostname = NULL;
        r->status = HTTP_BAD_REQUEST;             /* set error status */
        r->uri = apr_pstrdup(r->pool, uri);
    }
}

```
{% endraw %}


To accomplish this we could just write a wrapper, but maybe I will do that some other time. I do not really know why i even wrote this here but oh well.

Ok so now I compiled a fuzzer for the unescape_url function with arguments unescape_url(url, NULL, NULL) : (you can find it here: https://github.com/personnumber3377/unescape_url_fuzzing/tree/master)

{% raw %}
```
#include <ctype.h>
#include <stdio.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define apr_isxdigit(c) (isxdigit(((unsigned char)(c))))

static char x2c(const char *what)
{
    char digit;

#if !APR_CHARSET_EBCDIC
    digit = ((what[0] >= 'A') ? ((what[0] & 0xdf) - 'A') + 10
             : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10
              : (what[1] - '0'));
#else /*APR_CHARSET_EBCDIC*/
    char xstr[5];
    xstr[0]='0';
    xstr[1]='x';
    xstr[2]=what[0];
    xstr[3]=what[1];
    xstr[4]='\0';
    digit = apr_xlate_conv_byte(ap_hdrs_from_ascii,
                                0xFF & strtol(xstr, NULL, 16));
#endif /*APR_CHARSET_EBCDIC*/
    return (digit);
}


static int unescape_url(char *url, const char *forbid, const char *reserved)
{
    int badesc, badpath;
    char *x, *y;

    badesc = 0;
    badpath = 0;

    if (url == NULL) {
        //return OK;
        return 0;
    }
    /* Initial scan for first '%'. Don't bother writing values before
     * seeing a '%' */
    //printf("oooffff\n");
    y = strchr(url, '%');
    //printf("oooffff\n");
    if (y == NULL) {
        //return OK;
        return 0;
    }
    for (x = y; *y; ++x, ++y) {
        //printf("start of loop\n");
        if (*y != '%') {
            *x = *y;
        }
        else {
            if (!apr_isxdigit(*(y + 1)) || !apr_isxdigit(*(y + 2))) {
                badesc = 1;
                *x = '%';
            }
            else {
                char decoded;
                decoded = x2c(y + 1);
                //if ((decoded == '\0')
                //    || (forbid && strchr(forbid, decoded))) {
                if (decoded == '\0') {
                    badpath = 1;
                    *x = decoded;
                    y += 2;
                }
                //else if (reserved && strchr(reserved, decoded)) {
                //    *x++ = *y++;
                //    *x++ = *y++;
                //    *x = *y;
                //}
                else {
                    *x = decoded;
                    y += 2;
                }
            }
        }
    }
    *x = '\0';
    if (badesc) {
        //return HTTP_BAD_REQUEST;
        return 2;
    }
    else if (badpath) {
        //return HTTP_NOT_FOUND;
        return 1;
    }
    else {
        //return OK;
        return 0;
    }
}

/*
int main(int argc, char** argv) {

    char* input_url[1000];
    int return_val;
    fgets(input_url, 999, stdin);


    // static int unescape_url(char *url, const char *forbid, const char *reserved)

    return_val = unescape_url(input_url, NULL, NULL);
    printf("Return value: %d\n", return_val);

    printf("Decoded stuff: %s\n", input_url);

    return 0;
}
*/

int fuzzone(const uint8_t*data, size_t size) {
    int return_val;
    char stuff[100];
    if (size < 100) {
        memcpy(stuff, data, size);
    }
    else {
        memcpy(stuff, data, 99);
    }
    //memcpy(stuff, data, 999);

    return_val = unescape_url(stuff, NULL, NULL);
    return return_val;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  fuzzone(Data, Size);
  return 0;  // Values other than 0 and -1 are reserved for future use.
}

```
{% endraw %}

Now, this code was simple to write, because the unescape_url function did not have any outside references to non-standard functions, but I think that it will be a lot harder to do this for the ap_parse_uri function which seems a lot more interesting.

## Writing a fuzzer for ap_parse_uri.

Looking at the code ap_parse_uri is actually not the important function, but the interesting function is apr_uri_parse se we are going to fuzz that instead.

Now, my idea is to try to just statically compile everything to call the apr_uri_parse from the LLVMFuzzerTestOneInput function.

The arguments to the function are:



{% raw %}
```
APR_DECLARE(apr_status_t) apr_uri_parse(apr_pool_t *p, const char *uri,
                                        apr_uri_t *uptr)
```
{% endraw %}

The definition for the apr_pool_t is at ./apr/include/apr_pools.h which basically points to apr_pools.c :

{% raw %}
```
struct apr_pool_t {
    apr_pool_t           *parent;
    apr_pool_t           *child;
    apr_pool_t           *sibling;
    apr_pool_t          **ref;
    cleanup_t            *cleanups;
    cleanup_t            *free_cleanups;
    apr_allocator_t      *allocator;
    struct process_chain *subprocesses;
    apr_abortfunc_t       abort_fn;
    apr_hash_t           *user_data;
    const char           *tag;

#if !APR_POOL_DEBUG
    apr_memnode_t        *active;
    apr_memnode_t        *self; /* The node containing the pool itself */
    char                 *self_first_avail;

#else /* APR_POOL_DEBUG */
    apr_pool_t           *joined; /* the caller has guaranteed that this pool
                                   * will survive as long as ->joined */
    debug_node_t         *nodes;
    const char           *file_line;
    apr_uint32_t          creation_flags;
    unsigned int          stat_alloc;
    unsigned int          stat_total_alloc;
    unsigned int          stat_clear;
#if APR_HAS_THREADS
    apr_os_thread_t       owner;
    apr_thread_mutex_t   *mutex;
#endif /* APR_HAS_THREADS */
#endif /* APR_POOL_DEBUG */
#ifdef NETWARE
    apr_os_proc_t         owner_proc;
#endif /* defined(NETWARE) */
    cleanup_t            *pre_cleanups;
#if APR_POOL_CONCURRENCY_CHECK

#define                   IDLE        0
#define                   IN_USE      1
#define                   DESTROYED   2
    volatile apr_uint32_t in_use;
    apr_os_thread_t       in_use_by;
#endif /* APR_POOL_CONCURRENCY_CHECK */
};

```
{% endraw %}
in apr_hooks.h:

{% raw %}
```
#define apr_palloc(pool,size)   malloc(size)
```
{% endraw %}
in apr_strings.c:

{% raw %}
```
APR_DECLARE(char *) apr_pstrdup(apr_pool_t *a, const char *s)
{
    char *res;
    apr_size_t len;

    if (s == NULL) {
        return NULL;
    }
    len = strlen(s) + 1;
    res = apr_pmemdup(a, s, len);
    return res;
}


APR_DECLARE(char *) apr_pstrmemdup(apr_pool_t *a, const char *s, apr_size_t n)
{
    char *res;

    if (s == NULL) {
        return NULL;
    }
    res = apr_palloc(a, n + 1);
    memcpy(res, s, n);
    res[n] = '\0';
    return res;
}

APR_DECLARE(void *) apr_pmemdup(apr_pool_t *a, const void *m, apr_size_t n)
{
    void *res;

    if (m == NULL)
	return NULL;
    res = apr_palloc(a, n);
    memcpy(res, m, n);
    return res;
}

```
{% endraw %}

One thing which I do not understand is that there are lines like these: 

{% raw %}
```
uptr->fragment = apr_pstrdup(p, s1 + 1);
```
{% endraw %}


Oh wait, nevermind. I Understand what those are for. At first I didn't understand what the pool p was used for but then digging through the code:

{% raw %}
```
res = apr_palloc(a, n);
```
{% endraw %}
that is basically just a memalloc and the a parameter is basically ignored. I do not understand how the Makefile compiles the uri thing, but we actually can probably use the same trick which we used for the unescape_url function. We can just replace the problematic functions which referer to other files by the standard versions, because the only problematic function in that function is apr_uri_port_of_scheme which is defined as follows:

{% raw %}
```
static schemes_t schemes[] =
{
    {"http",     APR_URI_HTTP_DEFAULT_PORT},
    {"ftp",      APR_URI_FTP_DEFAULT_PORT},
    {"https",    APR_URI_HTTPS_DEFAULT_PORT},
    {"gopher",   APR_URI_GOPHER_DEFAULT_PORT},
    {"ldap",     APR_URI_LDAP_DEFAULT_PORT},
    {"nntp",     APR_URI_NNTP_DEFAULT_PORT},
    {"snews",    APR_URI_SNEWS_DEFAULT_PORT},
    {"imap",     APR_URI_IMAP_DEFAULT_PORT},
    {"pop",      APR_URI_POP_DEFAULT_PORT},
    {"sip",      APR_URI_SIP_DEFAULT_PORT},
    {"rtsp",     APR_URI_RTSP_DEFAULT_PORT},
    {"wais",     APR_URI_WAIS_DEFAULT_PORT},
    {"z39.50r",  APR_URI_WAIS_DEFAULT_PORT},
    {"z39.50s",  APR_URI_WAIS_DEFAULT_PORT},
    {"prospero", APR_URI_PROSPERO_DEFAULT_PORT},
    {"nfs",      APR_URI_NFS_DEFAULT_PORT},
    {"tip",      APR_URI_TIP_DEFAULT_PORT},
    {"acap",     APR_URI_ACAP_DEFAULT_PORT},
    {"telnet",   APR_URI_TELNET_DEFAULT_PORT},
    {"ssh",      APR_URI_SSH_DEFAULT_PORT},
    { NULL, 0xFFFF }     /* unknown port */
};


APR_DECLARE(apr_port_t) apr_uri_port_of_scheme(const char *scheme_str)
{
    schemes_t *scheme;

    if (scheme_str) {
        for (scheme = schemes; scheme->name != NULL; ++scheme) {
            if (strcasecmp(scheme_str, scheme->name) == 0) {
                return scheme->default_port;
            }
        }
    }
    return 0;
}

```
{% endraw %}

...

After a bit of coding I now have a fuzzer which fuzzes the apr_uri_parse function. Now I only need a corpus. I looked around the web and basically came up with these inputs to the parser:

{% raw %}
```
http://[1080::8:800:200c:417a]:8888/index.html?par=val#thing

http://user:pass@[1080::8:800:200c:417a]:8888/index.html?par=val#thing

http://user:pass@www.domain.com/page.html?param=value&param2=value2#subpage

http://www.domain.com/page.html?param=value&param2=value2#subpage

http://www.domain.com/../../subdir/page.html?param=value&param2=value2#subpage
```
{% endraw %}

In addition to these I found this: https://github.com/dvyukov/go-fuzz-corpus/tree/master/url/corpus  which contains a fuzzing corpus for URI:s , so I am going to stea... erm.. import those to my fuzzing session. :)

Now running the fuzzer on the apr_uri_parse function it works good, but no crashes of course haven't been found yet, but hopefully that will soon change., except we get an out of memory error. Huh. That is quite bad.

Yeah I forgot to free the malloced memory so that is why it ran out of memory.

I do not actually know how to free a struct. If i just try this:

{% raw %}
```
    return_val = apr_uri_parse(&anotherstuff, stuff, &output);
    //return_val = unescape_url(stuff, NULL, NULL);

    //free(&anotherstuff);
    free(&output);
```
{% endraw %}

It crashes with an invalid free pointer. (asan).

but then if i do something like this:

{% raw %}
```
            printf("%s\n\0", "poopooshit");
            free(uptr->port_str);
            return APR_EGENERAL;
```
{% endraw %}
inside the function itself, then we do not get any error or crash or anything. Even though uptr is literally just the input argument anotherstuff ??? I don't get this shit. Lets just do this:


{% raw %}
```
    if ((&output)->user != NULL) {
    	free((&output)->user);
    }
    

    if ((&output)->password != NULL) {
    	free((&output)->password);
    }
	
    
    if ((&output)->port_str != NULL) {
    	free((&output)->port_str);
    }

    if ((&output)->hostname != NULL) {
    	free((&output)->hostname);
    }

    if ((&output)->path != NULL) {
    	free((&output)->path);
    }

    if ((&output)->scheme != NULL) {
    	free((&output)->scheme);
    }

    if ((&output)->hostinfo != NULL) {
    	free((&output)->hostinfo);
    }

    if ((&output)->fragment != NULL) {
    	free((&output)->fragment);
    }
```
{% endraw %}

After that shit code, lets look if it crashes. We need to remember that the instance of the struct is not malloced, but the attributes of it are so we just need to free those and we should be fine.

Another idea which I have is to also use the apr_uri_unparse function and check if the output is the same, because it if it isn't then something went horribly wrong. No oom crash yet, so i think i succeeded.

After a but of fuzzing I got another out of memory but that is just because I forgot to free (&output)->query . Whoops. Now also I did a quick coverage report, we see that apr_uri_port_of_scheme is not properly getting covered:

{% raw %}
```
      74           3 : apr_port_t apr_uri_port_of_scheme(const char *scheme_str)
      75             : {
      76           3 :     schemes_t *scheme;
      77             : 
      78           3 :     if (scheme_str) {
      79           0 :         for (scheme = schemes; scheme->name != NULL; ++scheme) {
      80           0 :             if (strcasecmp(scheme_str, scheme->name) == 0) {
      81           0 :                 return scheme->default_port;
      82             :             }
      83             :         }
      84             :     }
      85             :     return 0;
      86             : }
      87             : 
      88             : 
```
{% endraw %}

So I added another test case which covers that stuff:

{% raw %}
```
ftp://ftp:
```
{% endraw %}



Anyway. Now I think that in addition to finding actual crashes, we should create a differential fuzzer with apr_uri_unparse which takes in the result of that other functions and then *should* return the original value. We can then of course compare this value to the actual original value and if they do not match, then something went wrong and we know there is a bug. Lets implement that next:



Another thing we have to take into account is that we should only report the testcase as invalid if the return value from the apr_uri_parse function was zero and then the output of the unparse function was something else other than what was originally entered. That way we can avoid false positives aka invalid uri:s being marked as inputs which makes the unparse function return differing output.



We also have to free the output from the unparse function, because that got malloc'ed .



Now, this produces results for example if you pass `http://http:/` in the parse function, then you will get `http://http/` from the unparse function. You can't really do anything with this, but oh well.


In the meantime the main fuzzing session with just plain afl hasn't yet found a usable crash, but again, hopefully that will soon change. The finding of new corpus files has slowed to an almost snails pace, so I think that I should probably switch to some other mutator soon, like the one-byte-bruteforce which bruteforces each byte individually. Maybe that will give us more coverage, but idk..



















