
# Fuzzing ruby date formats.

Ok, so after seeing the big bounties people were getting payed on hackerone for ruby fuzzing (https://hackerone.com/ibb?type=team) I decided to fuzz ruby (again).

I have actually fuzzed ruby before, but I deleted the directory which had all of my work, when I needed to free some space. Soo, we need to compile everything again. *facepalm* .

First git clone https://github.com/ruby/ruby.git and then compile it with afl. This is partually inspired by this: https://medium.com/fuzzstation/breaking-rubys-unmarshal-with-afl-fuzz-6b5f72b581d5 , but the guy just used a ruby script to load the marshal thing. This is actually quite a shit choice in my opinion, because this adds a lot of overhead because you invoke the ruby interpreter on each execution cycle when parsing the ruby source code.

To circumvent this problem and improve performance drastically, I decided to use the ruby C api. There is the slight problem that I do not know how to use it. I remember setting it up was a pain in the ass back then. I had linking problems etc for some reason. Now, let's see what happens.

I am going to consult this guide here to compile ruby from source: https://docs.ruby-lang.org/en/master/contributing/building_ruby_md.html#label-Quick+start+guide

Let's try to first compile and use without the instrumentation to see if we can get something to work.

I ran `./autogen.sh` and then made a dir called `build/` then inside build I ran `../configure --prefix="MYINSTALLDIR"`. I tried this once before and I had problems linking the library to the c program which uses ruby. It didn't find ruby_init and some other of the symbols even though they were in the library.

Then I am going to just run `make -j8 install` to build and then install to the installation directory.

After that I then copied this example program from here: https://silverhammermba.github.io/emberb/embed/

Here it is:

```

#include <ruby.h>

int main(int argc, char* argv[])
{
	/* construct the VM */
	ruby_init();

	/* Ruby goes here */

	/* destruct the VM */
	return ruby_cleanup(0);
}

```

The compilation process is this: `gcc -I/usr/include/ruby-3.0.0 -I/usr/include/ruby-3.0.0/x86_64-linux -lruby`

Notice the `-lruby` ? This is basically `libruby.so` , but there isn't a library of that name in the installation directory. See, we need to add `--enable-shared` to our configure parameters. :D

After compiling again, we now have `libruby.so` ! Great!

```
cyberhacker@cyberhacker-h8-1131sc:~/Asioita/Hakkerointi/Rubydatetime/ruby/install$ find . | grep libruby
./lib/libruby.so.3.4
./lib/libruby.so
./lib/libruby.so.3.4.0

```


Now we just need to compile the actual program. Shouldn't be that hard right? :D

Here is my command:

```
gcc -Iinstall/include/ruby-3.4.0+0 -Iinstall/include/ruby-3.4.0+0/x86_64-linux -Linstall/lib/ -lruby ./oof.c -o oof
```

and here is the error which I get:

```
/usr/bin/ld: /tmp/cckUnrHf.o: in function `main':
oof.c:(.text+0x23): undefined reference to `ruby_init'
/usr/bin/ld: oof.c:(.text+0x2d): undefined reference to `ruby_cleanup'
collect2: error: ld returned 1 exit status

```

sooooo what gives?

After a bit of googling I found this: https://stackoverflow.com/questions/59674947/linking-ruby-interpreter-into-c-program . It says that I need to link libruby.so (duh), but I am already doing that.

Now my computer just decided to automatically update. Thanks linux mint. Now I can not install new packages with apt-get because of it. Now in the stackoverflow question I when running `pkg-config `

After doing `export PKG_CONFIG_PATH=$PWD` in the directory where I had the `.pc` file, I got this:

```
cyberhacker@cyberhacker-h8-1131sc:~/Asioita/Hakkerointi/Rubydatetime/ruby$ pkg-config --cflags --libs ruby-3.3
-I/home/cyberhacker/Asioita/Hakkerointi/Rubydatetime/ruby/install/include/ruby-3.3.0+0/x86_64-linux -I/home/cyberhacker/Asioita/Hakkerointi/Rubydatetime/ruby/install/include/ruby-3.3.0+0 -L/home/cyberhacker/Asioita/Hakkerointi/Rubydatetime/ruby/install/lib -Wl,--compress-debug-sections=zlib -Wl,-rpath,/home/cyberhacker/Asioita/Hakkerointi/Rubydatetime/ruby/install/lib -lruby -lm -lpthread
```

Ok so let's add this to the compile command? No. Fuck!

Ok so now it is the next day and someone answered (actually the author of the guide I am following!) my question on stackoverflow: https://stackoverflow.com/a/77970820/14577985

And holy shit I am retarded. As it turns out, the order of linking matters for some reason!

After running this instead: 

```

gcc -c -I/home/cyberhacker/Asioita/Hakkerointi/Rubydatetime/ruby/install/include/ruby-3.3.0+0/x86_64-linux -I/home/cyberhacker/Asioita/Hakkerointi/Rubydatetime/ruby/install/include/ruby-3.3.0+0 -L/home/cyberhacker/Asioita/Hakkerointi/Rubydatetime/ruby/install/lib -Wl,--compress-debug-sections=zlib -Wl,-rpath,/home/cyberhacker/Asioita/Hakkerointi/Rubydatetime/ruby/install/lib -lruby -lm -lpthread -Iinstall/include/ruby-3.3.0+0 -Iinstall/include/ruby-3.3.0+0/x86_64-linux -Linstall/lib/ -L.  ./oof.c -o oof.o



gcc ./oof.o -I/home/cyberhacker/Asioita/Hakkerointi/Rubydatetime/ruby/install/include/ruby-3.3.0+0/x86_64-linux -I/home/cyberhacker/Asioita/Hakkerointi/Rubydatetime/ruby/install/include/ruby-3.3.0+0 -L/home/cyberhacker/Asioita/Hakkerointi/Rubydatetime/ruby/install/lib -Wl,--compress-debug-sections=zlib -Wl,-rpath,/home/cyberhacker/Asioita/Hakkerointi/Rubydatetime/ruby/install/lib -lruby -lm -lpthread -Iinstall/include/ruby-3.3.0+0 -Iinstall/include/ruby-3.3.0+0/x86_64-linux -Linstall/lib/ -L. -o oof

```

it now links and we get an executable! Great!


Now it is time to make a program which takes input from stdin and then tries to use it as input to strftime.

Yeah, fuck that. Let's fuzz unmarshalling instead. After compiling I do not find any crashes, but let's instead use the vulnerable version and see what happens.

Ok, so I decided to check if the vulnerability is actually findable with afl, so I decided to compile the thing with the patch removed. Thankfully the guy also provided a crashing input, so let's see what happens:

```
# xxd marshal-overflow
0000000: 0408 3afc ffff ff7f 3030 3030 3030 3030  ..:.....00000000
0000010: 3030 3030
```

I am going to remove the patch and compile again and see if it crashes.

Here is the thing before:

```
void
rb_str_modify_expand(VALUE str, long expand)
{
    int termlen = TERM_LEN(str);
    long len = RSTRING_LEN(str);

    if (expand < 0) {
        rb_raise(rb_eArgError, "negative expanding string size");
    }
    if (expand >= LONG_MAX - len) {
        rb_raise(rb_eArgError, "string size too big");
    }

    if (!str_independent(str)) {
        str_make_independent_expand(str, len, expand, termlen);
    }
    else if (expand > 0) {
        RESIZE_CAPA_TERM(str, len + expand, termlen);
    }
    ENC_CODERANGE_CLEAR(str);
}
```

and here it is after:

```

void
rb_str_modify_expand(VALUE str, long expand)
{
    int termlen = TERM_LEN(str);
    long len = RSTRING_LEN(str);

    if (expand < 0) {
        rb_raise(rb_eArgError, "negative expanding string size");
    }

    if (!str_independent(str)) {
        str_make_independent_expand(str, len, expand, termlen);
    }
    else if (expand > 0) {
        RESIZE_CAPA_TERM(str, len + expand, termlen);
    }
    ENC_CODERANGE_CLEAR(str);
}

```

and let's see if it crashes with the input.

Compile with afl-clang-fast ......






source "$HOME/.cargo/env"

## Actually fuzzing ruby dateformats.

Ok, so after a long while of searching I finally found this: https://stackoverflow.com/questions/3222171/ruby-c-extension-using-singleton which tells how to call `DateTime` in ruby c api. Here is my current wrapper code:

```


#include "ruby.h"


// These are needed to load symbols from date_core.so ...

#include <stdio.h>
#include <dlfcn.h>


// static VALUE cDate, cDateTime;

// extern VALUE cDate, cDateTime;


/*

VALUE dangerous_func(VALUE buffer) {
	//rb_funcall(rb_mKernel, rb_intern("Rational"), 1, buffer);
	
	// rb_funcall(rb_mKernel, rb_intern("to_f"), 1, buffer); // Fuzz float parsing instead
	VALUE parsed_date; // This is the datetime object. We are going to call "strftime" on this object later on...
	VALUE formatted_date; // This is the result of parsed_date.strftime("someformat")
	//rb_funcall(rb_mKernel, rb_intern("Complex"), 1, buffer);
	// cDate,
	printf("Trying to call parse...\n");

	// parsed_date = rb_funcall(cDateTime, rb_intern("parse"), 1, rb_str_new_cstr("3rd Feb 2001 04:05:06+03:30")); // Just use some date.

	//printf("Here is the address of cDateTime: %lx\n", cDateTime);

	parsed_date = rb_funcall(cDateTime, rb_intern("now"), 0);

	// strftime
	printf("Calling strftime...\n");
	rb_funcall(parsed_date, rb_intern("strftime"), 1, buffer); // Try to format the dateobject.


	// Maybe print the result?????

	printf("Calling puts...\n");

	rb_funcallv(rb_mKernel, rb_intern("puts"), 1, &formatted_date);

	return Qnil; // Just return Qnil
}

*/




// This is needed for rb_rescue
VALUE error_func(VALUE stuff) {
	//printf("Called error_func...\n");
	return Qnil;
}


// Main fuzzing wrapper.

#define DATE_CORE_NAME "date_core.so"

#define LOOP_COUNT 100000

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
	printf("Hello world!\n");

	int state;
	//rb_protect(dangerous_func, dangerous_arg, &state);


	VALUE hello_world_str;

	VALUE date_module;


	

	//ruby_setup();

	ruby_sysinit(&argc, &argv);
	RUBY_INIT_STACK;
	ruby_init();
	ruby_init_loadpath();

	date_module = rb_require("date");


	// VALUE singletonmodule = rb_const_get(rb_cObject,rb_intern("Singleton"));

	VALUE singletonmodule = rb_const_get(rb_cObject,rb_intern("DateTime"));


	// Need to initialize the date library, which we are fuzzing.

	// Init_date_core();

	__AFL_INIT();

	unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

	while (__AFL_LOOP(LOOP_COUNT)) {

	//while (true) {

		int len = __AFL_FUZZ_TESTCASE_LEN;

		state = 0;

		//hello_world_str = rb_str_new_cstr(buf);

		hello_world_str = rb_str_new_cstr(buf);

		/*
	rb_rescue(VALUE (* b_proc)(VALUE), VALUE data1,
          VALUE (* r_proc)(VALUE, VALUE), VALUE data2)
		*/
		//printf("Calling the function...\n");
		printf("Calling Init_date_core();\n");

		

		// Now we need to load the shit from date_core.so

		void     *handle  = NULL;
		void*  func    = NULL;

		handle = dlopen(DATE_CORE_NAME, RTLD_NOW | RTLD_GLOBAL);

		// func = dlsym(handle, "library_function");

		if (handle == NULL)
	   {
	       fprintf(stderr, "Unable to open lib: %s\n", dlerror());
	       return -1;
	   }

	   printf("Here is the address of handle: %lx\n", handle);

		/*
		if (cDateTime == NULL) {
       fprintf(stderr, "Unable to get symbol\n");
      return -1;
   }

		*/


		//printf("Here is the address of cDateTime: %lx\n", cDateTime);

		//Init_date_core();
		
		//printf("Returned from Init_date_core();\n");

		// Loading date_core.so ...
		printf("Now calling rb_require...\n");

		//rb_require("date"); // aka require 'date'

		// Ok, so now the date object is date_module.

		printf("Address of date_module: %lx\n", date_module);

		//rb_funcall(date_module, rb_intern("now"), 0);


		printf("Now calling rb_require...\n");

		// rb_funcall(cDateTime, rb_intern("now"), 0);
		printf("Now trying to call now...\n");


		// rb_funcall(singletonmodule,rb_intern("included"),1,mouseclass);

		printf("Now calling \"now\"...\n");

		rb_funcall(singletonmodule,rb_intern("now"),0);
		printf("Done!\n");

		//printf("The address of cDateTime is this: %lx\n", cDateTime);


		// rb_funcall(cDateTime, rb_intern("now"), 0); // Maybe this works???

		printf("Fuck!\n");


		// rb_rescue(dangerous_func, hello_world_str, error_func, Qnil);

		//rb_funcall(rb_mKernel, rb_intern("Rational"), 1, hello_world_str);

		//free(hello_world_str); // Try to free the allocated memory.

		// rb_funcall(rb_mKernel, rb_intern("Rational"), 1, hello_world_str);

	}

	






	ruby_finalize();

	return 0;
}


```

that actually calls `DateTime.now` instead of the parsing function, but whatever.

Here is the actual parse function:

```


		VALUE date_string = rb_str_new_cstr("2001-02-03T04:05:06.123456789+07:00"); // input string.

		// rb_funcall(singletonmodule,rb_intern("now"),1, date_string);

		rb_funcall(singletonmodule,rb_intern("parse"), 1, date_string);

```







