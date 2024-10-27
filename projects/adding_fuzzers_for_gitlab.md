
# Adding fuzzers for the gitlab codebase

Now I am getting this bullshit error message:

```

WARNING: Active Record does not support composite primary key.

security_findings has composite primary key. Composite primary key is ignored.
<internal:/opt/gitlab/embedded/lib/ruby/site_ruby/3.2.0/rubygems/core_ext/kernel_require.rb>:37:in `require': cannot load such file -- ruzzy (LoadError)
	from <internal:/opt/gitlab/embedded/lib/ruby/site_ruby/3.2.0/rubygems/core_ext/kernel_require.rb>:37:in `require'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/zeitwerk-2.6.7/lib/zeitwerk/kernel.rb:38:in `require'
	from /home/oof/gitlab/ruzzy_tracer.rb:2:in `<top (required)>'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/railties-7.0.8.4/lib/rails/commands/runner/runner_command.rb:43:in `load'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/railties-7.0.8.4/lib/rails/commands/runner/runner_command.rb:43:in `perform'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/thor-1.3.1/lib/thor/command.rb:28:in `run'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/thor-1.3.1/lib/thor/invocation.rb:127:in `invoke_command'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/thor-1.3.1/lib/thor.rb:527:in `dispatch'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/railties-7.0.8.4/lib/rails/command/base.rb:87:in `perform'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/railties-7.0.8.4/lib/rails/command.rb:48:in `invoke'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/railties-7.0.8.4/lib/rails/commands.rb:18:in `<top (required)>'
	from <internal:/opt/gitlab/embedded/lib/ruby/site_ruby/3.2.0/rubygems/core_ext/kernel_require.rb>:37:in `require'
	from <internal:/opt/gitlab/embedded/lib/ruby/site_ruby/3.2.0/rubygems/core_ext/kernel_require.rb>:37:in `require'
	from bin/rails:4:in `<main>'
<internal:/opt/gitlab/embedded/lib/ruby/site_ruby/3.2.0/rubygems/core_ext/kernel_require.rb>:37:in `require': Interrupt
	from <internal:/opt/gitlab/embedded/lib/ruby/site_ruby/3.2.0/rubygems/core_ext/kernel_require.rb>:37:in `require'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/rubyzip-2.3.2/lib/zip.rb:10:in `<top (required)>'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/bundler-2.5.11/lib/bundler/runtime.rb:60:in `require'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/bundler-2.5.11/lib/bundler/runtime.rb:60:in `block (2 levels) in require'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/bundler-2.5.11/lib/bundler/runtime.rb:55:in `each'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/bundler-2.5.11/lib/bundler/runtime.rb:55:in `block in require'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/bundler-2.5.11/lib/bundler/runtime.rb:44:in `each'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/bundler-2.5.11/lib/bundler/runtime.rb:44:in `require'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/bundler-2.5.11/lib/bundler.rb:207:in `require'
	from /opt/gitlab/embedded/service/gitlab-rails/config/application.rb:18:in `<top (required)>'
	from <internal:/opt/gitlab/embedded/lib/ruby/site_ruby/3.2.0/rubygems/core_ext/kernel_require.rb>:37:in `require'
	from <internal:/opt/gitlab/embedded/lib/ruby/site_ruby/3.2.0/rubygems/core_ext/kernel_require.rb>:37:in `require'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/railties-7.0.8.4/lib/rails/command/actions.rb:22:in `require_application!'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/railties-7.0.8.4/lib/rails/command/actions.rb:14:in `require_application_and_environment!'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/railties-7.0.8.4/lib/rails/commands/runner/runner_command.rb:33:in `perform'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/thor-1.3.1/lib/thor/command.rb:28:in `run'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/thor-1.3.1/lib/thor/invocation.rb:127:in `invoke_command'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/thor-1.3.1/lib/thor.rb:527:in `dispatch'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/railties-7.0.8.4/lib/rails/command/base.rb:87:in `perform'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/railties-7.0.8.4/lib/rails/command.rb:48:in `invoke'
	from /opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/railties-7.0.8.4/lib/rails/commands.rb:18:in `<top (required)>'
	from <internal:/opt/gitlab/embedded/lib/ruby/site_ruby/3.2.0/rubygems/core_ext/kernel_require.rb>:37:in `require'
	from <internal:/opt/gitlab/embedded/lib/ruby/site_ruby/3.2.0/rubygems/core_ext/kernel_require.rb>:37:in `require'
	from bin/rails:4:in `<main>'


```

Ok, so I managed to resolve that error, now it is time to actually try to run the fuzzer...

## Installing ruzzy

To install ruzzy, I had to run this command here:

```

MAKE="make --environment-overrides V=1" \
CC="clang" \
CXX="clang++" \
LDSHARED="clang -shared" \
LDSHAREDXX="clang++ -shared" \
    /home/oof/.asdf/shims/gem install ruzzy


```

and then it installed ruzzy correctly for the tools that GDK uses.

## Trying to patch ruzzy, such that it works with our setup.

See, we need to try to run ruzzy like so:

```
#!/bin/sh

export LD_PRELOAD="/usr/lib/python3.10/config-3.10-x86_64-linux-gnu/libpython3.10.so" # Load the python stuff first.

while true; do
	bundle exec rails runner -e development /home/oof/gdk/gitlab-development-kit/gitlab/ruzzy_tracer.rb -max_len=100000 corpus/ 2>> fuzz_output.txt
done


```

We get errors from ruzzy complaining about unregognized command line options like `-e` this is because it thinks that the bundle exec arguments are for libfuzzer.

So we need to actually patch the ruby fuzzer (`ruzzy`) itself to update these command line arguments to something more reasonable. I created a fork of ruzzy here: https://github.com/personnumber3377/ruzzy which implements those changes.

What I did was I copied the compiled `cruzzy.so` to `/home/oof/.asdf/installs/ruby/3.2.4/lib/ruby/gems/3.2.0/gems/ruzzy-0.7.0/lib/cruzzy` (the place where the gitlab rails runner looks for the ruby libraries) and now if we pass something like this:

```

#!/bin/sh

export LD_PRELOAD="/usr/lib/python3.10/config-3.10-x86_64-linux-gnu/libpython3.10.so" # Load the python stuff first.

while true; do
	bundle exec rails runner -e development /home/oof/gdk/gitlab-development-kit/gitlab/ruzzy_tracer.rb --- somefile -max_len=100000 corpus/ 2>> fuzz_output.txt # The three dashes are on purpose.
done



```


We actually start fuzzing nicely!!!!

The three dashes separate the argv arguments we want to pass to the setup and the argv arguments we want to actually pass to libfuzzer. This way we sort of "fake" the command line arguments which are passed to libfuzzer.

The most important part of this code is here:

```
    char **args_ptr = &argv[0];
    // fprintf(stderr, "Error: Cannot find/call custom mutator function in"
    //                    " external Python module.\n");

    fprintf(stderr, "Checking for argv arguments...\n");

    fprintf(stderr, "Printing the argument shit before:\n");
    fprintf(stderr, "Printing the first thing before:\n");
    fprintf(stderr, "%s\n", args_ptr[0]);
    for(int i=0;i<args_len-1;i++) {
      fprintf(stderr, "%s\n",args_ptr[i]);
    }
    fprintf(stderr, "Done beforebeforebeforebeforebeforebefore!\n");

    for (int i = 0; i < args_len; i++) {
      // Now just check if the string is "---" or something like that...
      if (strcmp(argv[i], "---") != 0) {
        continue;
      } else {
        // We found the thing.
        fprintf(stderr, "Found the \"---\" string thing...\n");
        args_ptr = &argv[i+1];
        args_len = args_len - i - 1; // Just put the shit stuff.
        fprintf(stderr, "Here is the amount of arguments after the \"---\" string: %d\n", args_len); // Just print that shit..
        break; // Break out of the loop
      }
    }

    // Print out the arguments for debugging purposes:
    fprintf(stderr, "Printing the argument shit:\n");
    fprintf(stderr, "Printing the first thing:\n");
    fprintf(stderr, "%s\n", args_ptr[0]);
    for(int i=0;i<args_len-1;i++) {
      fprintf(stderr, "%s\n",args_ptr[i]);
    }
    fprintf(stderr, "Done!\n");

    // https://llvm.org/docs/LibFuzzer.html#using-libfuzzer-as-a-library
    int result = LLVMFuzzerRunDriver(&args_len, &args_ptr, proc_caller);

    return INT2FIX(result);
```


which modifies the command line arguments and the argument count before passing to `LLVMFuzzerRunDriver` such that we do not pass the arguments meant for bundle to libfuzzer which doesn't understand them...

## Trying it out:


Here is the contents of the `ruzzy_tracer.rb` file:

```
require 'ruzzy'

Ruzzy.trace('fuzz.rb')

```


and here is the contents of my fuzzer (`fuzz.rb`):

```


require 'timeout'

def target_function(data)
	Timeout::timeout 3 do
    # NOTE: Here you would put the part of gitlab which you would like to fuzz. Here I just print the username of the first user (should usually be root) and then if the length of the inputted data is 100, then print the string "The length is 100 characters!" . Normally here you would put some part of the gitlab code, which parses user input. The timeout is there to catch timeouts, which could be indicative of Denial Of Service vulnerabilities.

    # These two lines are actually from gitlab itself: https://docs.gitlab.com/ee/administration/operations/rails_console.html#using-the-rails-runner
    # This proves that we are actually fuzzing gitlab.
    user = User.first;
    puts user.username
    if data.length == 100
      puts "The length is 100 characters!"
    end


	rescue SystemStackError, ArgumentError, NoMethodError, RuntimeError, TypeError
		return
	end
end

test_one_input = lambda do |data|
	target_function(data) # Your fuzzing target would go here
	return 0
end

Ruzzy.fuzz(test_one_input)


```

and here is the glorious output:

Stdout:

```
# SNIP
root
root
root
root
The length is 100 characters!
root
root
The length is 100 characters!
The length is 100 characters!
root
root
root
root
# SNIP
```

Stderr:

```

Warning: No Python module specified, using the default libfuzzer mutator (for now).
Checking for argv arguments...
Printing the argument shit before:
Printing the first thing before:
bin/rails
bin/rails
-e
development
/home/oof/gdk/gitlab-development-kit/gitlab/ruzzy_tracer.rb
---
somefile
-max_len=100000
Done beforebeforebeforebeforebeforebefore!
Found the "---" string thing...
Here is the amount of arguments after the "---" string: 3
Printing the argument shit:
Printing the first thing:
somefile
somefile
-max_len=100000
Done!
WARNING: Failed to find function "__sanitizer_acquire_crash_state".
WARNING: Failed to find function "__sanitizer_print_stack_trace".
WARNING: Failed to find function "__sanitizer_set_death_callback".
INFO: found LLVMFuzzerCustomMutator (0x7f4781125980). Disabling -len_control by default.
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 355598280
INFO: Loaded 1 modules   (8192 inline 8-bit counters): 8192 [0x7f4781189850, 0x7f478118b850),
INFO: Loaded 1 PC tables (8192 PCs): 8192 [0x7f4781169850,0x7f4781189850),
INFO:        1 files found in corpus/
INFO: seed corpus: files: 1 min: 4b max: 4b total: 4b rss: 713Mb
#2	INITED cov: 1 ft: 1 corp: 1/4b exec/s: 0 rss: 713Mb
#4	REDUCE cov: 1 ft: 1 corp: 1/2b lim: 100000 exec/s: 0 rss: 713Mb L: 2/2 MS: 4 CrossOver-Custom-EraseBytes-Custom-
#61	REDUCE cov: 1 ft: 1 corp: 1/1b lim: 100000 exec/s: 0 rss: 717Mb L: 1/1 MS: 4 ChangeBinInt-Custom-EraseBytes-Custom-
#381	REDUCE cov: 2 ft: 2 corp: 2/101b lim: 100000 exec/s: 381 rss: 728Mb L: 100/100 MS: 6 InsertRepeatedBytes-Custom-ChangeByte-Custom-InsertByte-Custom-
#1024	pulse  cov: 2 ft: 2 corp: 2/101b lim: 100000 exec/s: 341 rss: 729Mb


```




