
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

![zero_coverage][/pictures/coverage/cov0.png]

![zero_coverage][/pictures/coverage/cov1.png]

![zero_coverage][/pictures/coverage/cov2.png]

![zero_coverage][/pictures/coverage/cov3.png]


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

# Rechecking coverage

Now that we have removed the unused code from the coverage binary, it should report the correct coverage.




















