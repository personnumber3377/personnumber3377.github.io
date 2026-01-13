
# Fuzzing ruby command line options.

Ok, so command line arguments are often quite overlooked when fuzzing.

There is this line in ruby.c:

{% raw %}
```
if (FEATURE_SET_P(opt->features, rubyopt) && (s = getenv("RUBYOPT"))) {
```
{% endraw %}

which checks for the environment variable called RUBYOPT . Here it is said that it can only contain certain flags, but I think it is adequate for our purposes: `https://stackoverflow.com/a/59616442`

I actually had to put a check for an environment variable for the environment variable called "NOW_FUZZING" , because the compilation process actually runs the built binary itsefl, so we do not want to hang there when it expects fuzzing input..

## Fuzzing results

Crashes plzzzz...???? Ok, so I have fuzzed for half an hour and there are no crashes yet. Let's keep our hopes up.

## Compiling with address sanitizer

Ok, so with the normal thing I didn't get any crashes, so I decided to compile with address sanitizer.

There is a problem with ASAN and a lot of caveats: https://docs.ruby-lang.org/en/master/contributing/building_ruby_md.html#label-Building+with+Address+Sanitizer

'''
Please note, however, the following caveats!

ASAN will not work properly on any currently released version of Ruby; the necessary support is currently only present on Ruby’s master branch.

Due to this bug, Clang generates code for threadlocal variables which doesn’t work with M:N threading. Thus, it’s necessary to disable M:N threading support at build time for now.

Currently, ASAN will only work correctly when using a recent head build of LLVM/Clang - it requires this bugfix related to multithreaded fork, which is not yet in any released version. See here for instructions on how to build LLVM/Clang from source (note you will need at least the clang and compiler-rt projects enabled). Then, you will need to replace CC=clang in the instructions with an explicit path to your built Clang binary.

ASAN has only been tested so far with Clang on Linux. It may or may not work with other compilers or on other platforms - please file an issue on bugs.ruby-lang.org if you run into problems with such configurations (or, to report that they actually work properly!)

In particular, although I have not yet tried it, I have reason to believe ASAN will not work properly on macOS yet - the fix for the multithreaded fork issue was actually reverted for macOS (see here). Please open an issue on bugs.ruby-lang.org if this is a problem for you.
'''

so we need to copy the master branch and add it to that.

It is quite a shit situation that ruby binary get's ran when compiling, because I got an ASAN error on the older version. Let's see what happens in the newest master branch commit (3c4d0b13132f9ba3f07575f175d173b69f9bd6ef as of writing this).

Ok, so now I am compiling ruby with ASAN. Let's see if we get an ASAN error.

Ok, so I am quite surprised that I didn't get any ASAN errors. Now it is fuzzing the command line arguments.

## Now any crashes?

Ok, so the fuzzer has run a bit aaaannnnddd... no crashes. fuck!!!







