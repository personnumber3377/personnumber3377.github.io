
# Making a custom mutator for clvm-rs

I found that there is a bug bounty program for the chia cryptocurrency network: https://hackerone.com/chia_network and that there is a virtual machine written in rust for running programs: https://github.com/Chia-Network/clvm_rs/tree/main . There are fuzzer targets, but those targets have "dumb" fuzzers instead of a smart fuzzer. The program uses `cargo fuzz` to fuzz the virtual machine... I am best at python so let's try to see if there was a way to program custom mutators in python for `cargo fuzz` .

## Doing some reading...

Ok, so how do I call python code from rust??????

This seems interesting: https://docs.rs/libfuzzer-sys/latest/libfuzzer_sys/macro.fuzz_mutator.html

Ok, so the custom mutator stuff is actually here: https://github.com/rust-fuzz/libfuzzer . Let's use the mozilla fuzzing bridge to try to add the custom mutator support:

https://github.com/MozillaSecurity/libfuzzer-python-bridge


After a shitton of figuring stuff out, I finally can call a python custom mutator from libfuzzer.

## Programming the actual custom mutator...


Ok, so now that we can actually call the thing from rust stuff, let's try to program the custom mutator which mutates our CLVM program and then returns the mutated version.

Here is my mutator skeleton:

```


import sys



def custom_mutator(data, max_size, seed, native_mutator): # This is for ruzzyfork
	# The strategy is to first decode the program to a treelike structure and then mutate this tree and then serialize the program back into bytes...
	prog_tree = decode_tree(data) # Decode to treelike structure
	prog_tree = mutate_tree(prog_tree) # Mutate
	mutated_data = encode_tree(prog_tree) # Encode back to bytes
	return mutated_data



if __name__=="__main__":
	# This main function is just for testing. The fuzzer itself only calls "custom_mutator" with the data.


	if len(sys.argv) != 2:
		print("Usage: python3 "+str(sys.argv[0])+" INPUTDATA")
		exit(1)

	fh = open(sys.argv[1], "wb")
	data = fh.read()
	fh.close()

	databytes = bytearray(data) # Convert to bytearray as the fuzzer would pass the data to the "custom_mutator" as a bytearray...

	new_data = custom_mutator(databytes, 10000000, 100, None)

	print("Here is the mutated data: ")

	print(new_data)



	exit(0)



```

Let's read through the documentation here: https://chialisp.com/clvm/

it seems quite interesting...

## Writing the parser

Ok, so first up is the binary to tree formation...


Here is a quick example:

```

(venv) oof@oof-h8-1440eo:~/clvmshit$ cdv clsp disassemble ff11ffff108080
(- (+))


```

how does that get serialized????

the first byte is 0xff , so that means that the value thing is a pair.

Wait, this is completely retarded. There exists python bindings for Chia, which we can use to just do the stuff. This saves us plenty of time.



https://github.com/Chia-Network/clvm_rs/blob/main/wheel/python/clvm_rs/program.py


Nevermind... that shit doesn't really seem to be interesting to us, because that only enables us to run programs, but it doesn't provide a way to modify a program after being parsed from string. Fuck!!!





## Bugfixes

Ok, so I actually encountered a bug where when I changed the program, the serialized data didn't change after I serialized the mutated program back to a bytestring: https://github.com/Chia-Network/clvm_rs/issues/457

But after figuring out that bug, we are back on track...

## Actually writing the tree mutator

I am going to copy my previous SVG tree mutator and see what I can do with that code.








Here is the code from my svg mutator which is responsible for selecting a random node (which we basically want, because we want to mutate random nodes and leafs)






```


import sys
import xml.etree.ElementTree as ET # For parsing XML
import random

def get_all_paths_recursive(cur_node, current_path):
	out = [current_path]
	for i, child in enumerate(cur_node): # Loop over all child nodes...
		# print("current_path + [i] == "+str(current_path + [i]))
		# out.append(get_all_paths_recursive(child, current_path + [i]))
		out += get_all_paths_recursive(child, current_path + [i])
	return out


def get_all_paths(tree):
	return get_all_paths_recursive(tree, [])

def select_random_node_func(tree): # Select a random node with equal probability.
	all_paths = get_all_paths(tree)
	ran_path = random.choice(all_paths)
	parent = None # parent node.
	out = tree
	for ind in ran_path:
		parent = out
		out = out[ind] # Traverse the tree according to the randomly chosen path.
	return out, parent


```

We want to basically emulate this but with clvm.


Something like this?

```


def get_all_paths_recursive(cur_node, current_path):
	out = [current_path]
	for i, child in enumerate(cur_node.pair): # Loop over all child nodes... (new_prog.pair)
		# print("current_path + [i] == "+str(current_path + [i]))
		# out.append(get_all_paths_recursive(child, current_path + [i]))
		out += get_all_paths_recursive(child, current_path + [i])
	return out

def get_all_paths(program):
	return get_all_paths_recursive(program, [])


def select_random_node(program): # Select a random node from the program...
	# Thanks to https://www.geeksforgeeks.org/select-random-node-tree-equal-probability/
	all_paths = get_all_paths(program)
	rand_path = random.choice(all_paths)
	parent = None
	out = program
	for ind in rand_path:
		parent = out
		out = out.pair[ind]
	return out, parent
```

let's add test functions in a file called `tests.py`:

```

from main import *


def test_random_node():

	program_data = "ff32ff3c80" #  `(50 60)`
	#print("original data: "+str(program_data))
	new_prog = Program.fromhex(program_data)

	node, parent = select_random_node(new_prog)

	print("node == "+str(node))
	print("parent == "+str(parent))

	return


if __name__=="__main__":

	# First run the test for choosing a random node.

	test_random_node()

	exit(0)

```

uh oh:

```

  File "/home/oof/clvm_custom_mutator/main.py", line 34, in get_all_paths_recursive
    for i, child in enumerate(cur_node.pair): # Loop over all child nodes... (new_prog.pair)
TypeError: 'NoneType' object is not iterable


```

something like this instead:

```

def get_all_paths_recursive(cur_node, current_path):
	out = [current_path]
	if cur_node.pair:

		for i, child in enumerate(cur_node.pair): # Loop over all child nodes... (new_prog.pair)
			# print("current_path + [i] == "+str(current_path + [i]))
			# out.append(get_all_paths_recursive(child, current_path + [i]))
			out += get_all_paths_recursive(child, current_path + [i])
	else:
		print("Encountered atom: "+str(cur_node.atom))
		print("cur_node == "+str(cur_node))
		assert cur_node.atom
		return out
	return out

```

getting closer it seems:

```
  File "/home/oof/clvm_custom_mutator/main.py", line 44, in get_all_paths_recursive
    assert cur_node.atom
AssertionError
```

this is because the `0x80` atom is actually called "nil" and is a special value, if you look at the docs: https://chialisp.com/clvm/#nil . we need to program a special case for nil (I think maybe possibly...)

I am just going to take note that the node could be nil, and I am going to treat it normally (for now). If this causes us trouble, we should come back and change this behaviour:

```

def get_all_paths_recursive(cur_node, current_path):
	out = [current_path]
	if cur_node.pair:

		for i, child in enumerate(cur_node.pair): # Loop over all child nodes... (new_prog.pair)
			# print("current_path + [i] == "+str(current_path + [i]))
			# out.append(get_all_paths_recursive(child, current_path + [i]))
			out += get_all_paths_recursive(child, current_path + [i])
	else:
		print("Encountered atom: "+str(cur_node.atom))
		print("cur_node == "+str(cur_node))
		#assert cur_node.atom
		if not cur_node.atom: # 0x80 or "nil" https://chialisp.com/clvm/#nil
			# NOTE: This acts normally (for now) when the node is "nil" , but if this causes problems, change this behaviour to do something else in this "if not" case.
			return out
		return out
	return out

```

Now that we have a way to select a random node, we should then figure out if it is an atom (or a tuple like thing) or not and then choose our mutation strategy based on that.

I am going to program a quick little helper function called `isatom`, which as the name suggests returns a boolean value if the node is an atom...


```

def isatom(node): # Returns true, if node is an atom, otherwise returns false
	if not node.pair: # No pair... therefore atom
		return True
	return False # pair exists, therefore not atom

```

I think I am going to do a copy of my generic_mutator module to mutate the atom and stuff like that...


now let's try out our fuzzer:

```

warning: /home/oof/clvm_rs/fuzz/Cargo.toml: unused manifest key: dependencies.libfuzzer-sys.path
    Finished `release` profile [optimized + debuginfo] target(s) in 1.94s
warning: /home/oof/clvm_rs/fuzz/Cargo.toml: unused manifest key: dependencies.libfuzzer-sys.path
    Finished `release` profile [optimized + debuginfo] target(s) in 0.06s
     Running `/home/oof/clvm_rs/target/x86_64-unknown-linux-gnu/release/fuzz_run_program -artifact_prefix=/home/oof/clvm_rs/fuzz/artifacts/fuzz_run_program/ -rss_limit_mb=4096 -max_len=2000000 -timeout=1 /home/oof/clvm_rs/fuzz/corpus/fuzz_run_program -fork=8`
WARNING: Calling custom_mutator!
AttributeError: module 'main' has no attribute 'custom_crossover'
Warning: Python module does not implement crossover API, standard crossover will be used.
WARNING: Disabling -len_control . Assuming custom mutator!
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 510915728
INFO: Loaded 1 modules   (245390 inline 8-bit counters): 245390 [0x5610432aa4a0, 0x5610432e632e),
INFO: Loaded 1 PC tables (245390 PCs): 245390 [0x5610432e6330,0x5610436a4c10),
INFO: -fork=8: fuzzing in separate process(s)
INFO: -fork=8: 1355 seed inputs, starting to fuzz in /tmp/libFuzzerTemp.FuzzWithFork74846.dir
#0: cov: 13270 ft: 13270 corp: 1355 exec/s: 0 oom/timeout/crash: 0/0/0 time: 31s job: 8 dft_time: 0
INFO: log from the inner process:
WARNING: Calling custom_mutator!
AttributeError: module 'main' has no attribute 'custom_crossover'
Warning: Python module does not implement crossover API, standard crossover will be used.
WARNING: Disabling -len_control . Assuming custom mutator!
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1499667582
INFO: Loaded 1 modules   (245390 inline 8-bit counters): 245390 [0x558ec209a4a0, 0x558ec20d632e),
INFO: Loaded 1 PC tables (245390 PCs): 245390 [0x558ec20d6330,0x558ec2494c10),
INFO:        0 files found in /tmp/libFuzzerTemp.FuzzWithFork74846.dir/C8
INFO: seed corpus: files: 36 min: 3027b max: 43594b total: 514065b rss: 67Mb
#38	INITED cov: 1331 ft: 3964 corp: 36/502Kb exec/s: 0 rss: 92Mb
WARNING: Calling custom_mutator!
#39	NEW    cov: 1333 ft: 3966 corp: 37/527Kb lim: 2000000 exec/s: 0 rss: 95Mb L: 26181/43594 MS: 2 CrossOver-Custom-
WARNING: Calling custom_mutator!
Traceback (most recent call last):
  File "/home/oof/clvm_rs/fuzz/main.py", line 173, in custom_mutator
    mutate_program(new_prog)
  File "/home/oof/clvm_rs/fuzz/main.py", line 110, in mutate_program
    rand_node, _ = select_random_node(program) # Parent is left unused
  File "/home/oof/clvm_rs/fuzz/main.py", line 75, in select_random_node
    all_paths = get_all_paths(program)
  File "/home/oof/clvm_rs/fuzz/main.py", line 70, in get_all_paths
    return get_all_paths_recursive(program, [])
  File "/home/oof/clvm_rs/fuzz/main.py", line 55, in get_all_paths_recursive
    out += get_all_paths_recursive(child, current_path + [i])
  File "/home/oof/clvm_rs/fuzz/main.py", line 55, in get_all_paths_recursive
    out += get_all_paths_recursive(child, current_path + [i])
  File "/home/oof/clvm_rs/fuzz/main.py", line 55, in get_all_paths_recursive
    out += get_all_paths_recursive(child, current_path + [i])
  [Previous line repeated 982 more times]
  File "/home/oof/clvm_rs/fuzz/main.py", line 50, in get_all_paths_recursive
    if cur_node.pair:
  File "/home/oof/clvm_rs/wheel/python/clvm_rs/program.py", line 102, in pair
    self._pair = (self.wrap(pair[0]), self.wrap(pair[1]))
  File "/home/oof/clvm_rs/wheel/python/clvm_rs/program.py", line 111, in wrap
    if isinstance(v, Program):
  File "/usr/lib/python3.10/typing.py", line 1503, in __instancecheck__
    issubclass(instance.__class__, cls)):
  File "/usr/lib/python3.10/abc.py", line 123, in __subclasscheck__
    return _abc_subclasscheck(cls, subclass)
RecursionError: maximum recursion depth exceeded in comparison
Error: Call failed
The libFuzzer Python layer encountered a critical error.
Please fix the messages above and then restart fuzzing.
oof
INFO: exiting: 1 time: 32s
────────────────────────────────────────────────────────────────────────────────

Error: Fuzz target exited with exit status: 1



```

this is because of unbounded recursion. Let's stop that.

This here:

```

	try:
		mutate_program(new_prog)
	except:
		return data

```

should work fine!

## Optimizing the mutator.

Ok, so now the mutator works, but there are some problems with it.

Let's add a benchmark...

The benchark is actually quite good and the mutator is actually quite efficient. I was quite surprised by this.



## Adding a good fuzzing corpus.

Ok, so let's create a corpus of valid programs. Our mutator always returns the original program, if it can not parse it, so let's get a corpus of valid programs.

There is a file called `test_program.py` in the python tests in clvm_rs , so let's create a quick program to parse the program data from these tests:

```




if __name__=="__main__":

	fh = open("test_program.py", "r")
	lines = fh.readlines()

	fh.close()

	split_string = ".fromhex(\""

	thing = 0

	for line in lines:
		if split_string in line:
			line = line[line.index(split_string)+len(split_string):] # Cut out the stuff.
			#print(line)
			if "\")" in line:
				line = line[:line.index("\")")]
				#print(line)
				stuff = bytearray.fromhex(line)
				fh = open("out/"+str(thing), "wb")
				fh.write(stuff)
				fh.close()
				thing += 1
	exit(0)


```

clvm_rs comes with a corpus, so I think a good way to figure out how many percent of the inputs passed to our custom fuzzer are valid.

Let's mod our custom mutator:

```


TOTAL = 0
VALID = 0

def custom_mutator(data, max_size, seed, native_mutator): # This is for ruzzyfork
	# The strategy is to first decode the program to a treelike structure and then mutate this tree and then serialize the program back into bytes...
	assert isinstance(data, bytearray) # Sanity checking...

	global TOTAL
	global VALID

	TOTAL += 1

	if random.randrange(10) == 1:

		fh = open("oofstuff.txt","w")
		contents = fh.write(str(VALID/TOTAL))
		fh.close()


	program_data = data.hex() # Convert to hex representation

	try:
		new_prog = Program.fromhex(program_data)
	except:
		# Invalid program, just return the original data instead...
		#print("Invalid data!")

		# Invalid data, increment invalid counter...
		'''
		fh = open("invalid.txt","r")
		contents = fh.read()
		fh.close()


		invalid_int = int(contents)

		invalid_int += 1

		fh = open("invalid.txt","w")
		contents = fh.write(str(valid_int))
		fh.close()

		'''



		return data
	# Mutate program...
	try:
		mutate_program(new_prog)
	except:
		return data
	new_prog._cached_serialization = None # This is to get the new serialization, not the cached one.

	#print("type(new_prog) == "+str(type(new_prog)))

	stuff = bytes(new_prog)
	output = bytearray(stuff)

	# Hard cap...

	if len(output) >= max_size:
		output = output[:max_size]

	# Increment the valid count...

	'''
	fh = open("valid.txt","r")
	contents = fh.read()
	fh.close()

	valid_int = int(contents)

	valid_int += 1

	fh = open("valid.txt","w")
	contents = fh.write(str(valid_int))
	fh.close()
	'''


	VALID += 1



	return output # Return the mutated program as bytearray...



```

let's see the result...

```

oof@oof-h8-1440eo:~/clvm_rs/fuzz$ cat oofstuff.txt
0.5516989404457435

```

so just over half of these programs passed to the fuzzer are actually valid. That is quite good. Let's try to start with an entirely valid corpus which we extracted from the tests... that results in roughly 65 percent of the programs passed to the fuzzer to be valid. That is good enough.

## Adding some tiny modifications.

First of all, I think there should be a way to just select a small integer instead, so let's add that to our custom mutator:

```

	stuff = int.from_bytes(string, "big")
	#print("stuff == "+str(stuff))
	if stuff <= 500:
		if random.randrange(2) == 1: # Select a random integer from a range.
			random_shit = random.randrange(MAX_SMALL_INT)
			#print("returning this: "+str(random_shit))
			random_length = min_num_bytes(random_shit)
			#print("random_length this: "+str(random_length))
			bytes_val = random_shit.to_bytes(random_length, 'big')
			#assert isinstance(bytes_val, bytes)
			#print("returning this: "+str(bytes_val))
			return bytes_val


```

I think this is good enough

## Do you want to follow along?


Here is my patch file for clvm_rs.

```
diff --git a/Cargo.lock b/Cargo.lock
index 61eeb8c..9675ae0 100644
--- a/Cargo.lock
+++ b/Cargo.lock
@@ -859,12 +859,9 @@ checksum = "97b3888a4aecf77e811145cadf6eef5901f4782c53886191b2f693f24761847c"
 [[package]]
 name = "libfuzzer-sys"
 version = "0.4.7"
-source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "a96cfd5557eb82f2b83fed4955246c988d331975a002961b07c81584d107e7f7"
 dependencies = [
  "arbitrary",
  "cc",
- "once_cell",
 ]

 [[package]]
diff --git a/Cargo.toml b/Cargo.toml
index aafdda8..0bf32b0 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -54,7 +54,10 @@ wasm-bindgen = "0.2.92"
 wasm-bindgen-test = "0.3.42"
 js-sys = "0.3.69"
 getrandom = "0.2.15"
-libfuzzer-sys = "0.4.6"
+# libfuzzer-sys = "0.4.6"
+
+libfuzzer-sys = { path = "/home/oof/libfuzzer/" }
+
 rand = "0.8.5"
 sha1 = "0.10.6"
 linreg = "0.2.0"
diff --git a/fuzz/Cargo.toml b/fuzz/Cargo.toml
index f809b59..6fb1520 100644
--- a/fuzz/Cargo.toml
+++ b/fuzz/Cargo.toml
@@ -9,7 +9,10 @@ edition = "2021"
 cargo-fuzz = true

 [dependencies]
-libfuzzer-sys = { workspace = true }
+# libfuzzer-sys = { workspace = true }
+
+libfuzzer-sys = { path = "/home/oof/libfuzzer/", workspace = true } # Disable default features.
+
 clvmr = { workspace = true }

 [[bin]]
diff --git a/wheel/python/clvm_rs/program.py b/wheel/python/clvm_rs/program.py
index c3f6acf..f51d704 100644
--- a/wheel/python/clvm_rs/program.py
+++ b/wheel/python/clvm_rs/program.py
@@ -58,7 +58,12 @@ class Program(CLVMStorage):

     def __bytes__(self) -> bytes:
         if self._cached_serialization is None:
-            self._cached_serialization = sexp_to_bytes(self)
+            #print("Calling sexp_to_bytes")
+            #self._cached_serialization = sexp_to_bytes(self)
+            #print("Fuck"*100)
+            return bytes(sexp_to_bytes(self))
+        #else:
+        #    #print("Fuck"*10)
         if not isinstance(self._cached_serialization, bytes):
             self._cached_serialization = bytes(self._cached_serialization)
         return self._cached_serialization
diff --git a/wheel/python/clvm_rs/ser.py b/wheel/python/clvm_rs/ser.py
index 135b110..ff3d03e 100644
--- a/wheel/python/clvm_rs/ser.py
+++ b/wheel/python/clvm_rs/ser.py
@@ -31,10 +31,11 @@ def sexp_to_byte_iterator(sexp: CLVMStorage) -> Iterator[bytes]:
     todo_stack = [sexp]
     while todo_stack:
         sexp = todo_stack.pop()
-        r = getattr(sexp, "_cached_serialization", None)
-        if r is not None:
-            yield r
-            continue
+        # DO NOT USE CACHE!
+        #r = getattr(sexp, "_cached_serialization", None)
+        #if r is not None:
+        #    yield r
+        #    continue
         pair = sexp.pair
         if pair:
             yield bytes([CONS_BOX_MARKER])
@@ -42,6 +43,7 @@ def sexp_to_byte_iterator(sexp: CLVMStorage) -> Iterator[bytes]:
             todo_stack.append(pair[0])
         else:
             atom = sexp.atom
+            # print("atom == "+str(atom))
             assert atom is not None
             yield from atom_to_byte_iterator(atom)


```

(of course replace the modifications to the Cargo.toml with a path to your own libfuzzer)


then apply this patch to rust libfuzzer (aka https://github.com/rust-fuzz/libfuzzer):

```

diff --git a/build.rs b/build.rs
index e549e3f..1dc8479 100644
--- a/build.rs
+++ b/build.rs
@@ -21,6 +21,14 @@ fn build_and_link_libfuzzer() {
             Ok(s) => println!("cargo:rustc-link-lib={}", s),
         }
     } else {
+
+
+        println!("cargo:rustc-link-search=/usr/lib/x86_64-linux-gnu/");
+        println!("cargo:rustc-link-lib=m");
+        println!("cargo:rustc-link-lib=z");
+        println!("cargo:rustc-link-lib=expat");
+        println!("cargo:rustc-link-lib=python3.10");
+
         let mut build = cc::Build::new();
         let sources = ::std::fs::read_dir("libfuzzer")
             .expect("listable source directory")
@@ -31,9 +39,209 @@ fn build_and_link_libfuzzer() {
             println!("cargo:rerun-if-changed={}", source.display());
             build.file(source.to_str().unwrap());
         }
+
+
+
+
+
+
         build.flag("-std=c++17");
         build.flag("-fno-omit-frame-pointer");
         build.flag("-w");
+        build.flag("-l:libexpat.a");
+
+        build.flag("-I/usr/include/python3.10/");
+        //build.flag("-L/usr/lib/python3.10/config-3.10-x86_64-linux-gnu/"); // Needed for linking python3.10
+        build.flag("-L/usr/lib/x86_64-linux-gnu/");
+        //build.flag("-l:libpython3.10.a");
+        // /usr/lib/x86_64-linux-gnu/libpython3.10.a
+
+        // Libexpat:
+
+        build.object("/usr/lib/x86_64-linux-gnu/libexpat.a");
+        build.object("/usr/lib/x86_64-linux-gnu/libm.a");
+        build.object("/usr/lib/x86_64-linux-gnu/libz.a");
+
+        build.object("/home/oof/libfuzzer/fuck/hashtable.o");
+        build.object("/home/oof/libfuzzer/fuck/genericaliasobject.o");
+        build.object("/home/oof/libfuzzer/fuck/mathmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/listobject.o");
+        build.object("/home/oof/libfuzzer/fuck/codeobject.o");
+        build.object("/home/oof/libfuzzer/fuck/pyexpat.o");
+        build.object("/home/oof/libfuzzer/fuck/accu.o");
+        build.object("/home/oof/libfuzzer/fuck/_threadmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/_heapqmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/genobject.o");
+        build.object("/home/oof/libfuzzer/fuck/_iomodule.o");
+        build.object("/home/oof/libfuzzer/fuck/weakrefobject.o");
+        build.object("/home/oof/libfuzzer/fuck/_datetimemodule.o");
+        build.object("/home/oof/libfuzzer/fuck/_tracemalloc.o");
+        build.object("/home/oof/libfuzzer/fuck/getplatform.o");
+        build.object("/home/oof/libfuzzer/fuck/sha1module.o");
+        build.object("/home/oof/libfuzzer/fuck/pwdmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/_statisticsmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/bytearrayobject.o");
+        build.object("/home/oof/libfuzzer/fuck/main.o");
+        build.object("/home/oof/libfuzzer/fuck/capsule.o");
+        build.object("/home/oof/libfuzzer/fuck/md5module.o");
+        build.object("/home/oof/libfuzzer/fuck/sha256module.o");
+        build.object("/home/oof/libfuzzer/fuck/_collectionsmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/arraymodule.o");
+        build.object("/home/oof/libfuzzer/fuck/_bisectmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/getcompiler.o");
+        build.object("/home/oof/libfuzzer/fuck/ast_unparse.o");
+        build.object("/home/oof/libfuzzer/fuck/future.o");
+        build.object("/home/oof/libfuzzer/fuck/_struct.o");
+        build.object("/home/oof/libfuzzer/fuck/complexobject.o");
+        build.object("/home/oof/libfuzzer/fuck/iobase.o");
+        build.object("/home/oof/libfuzzer/fuck/blake2b_impl.o");
+        build.object("/home/oof/libfuzzer/fuck/pyctype.o");
+        build.object("/home/oof/libfuzzer/fuck/obmalloc.o");
+        build.object("/home/oof/libfuzzer/fuck/dynload_shlib.o");
+        build.object("/home/oof/libfuzzer/fuck/getcopyright.o");
+        build.object("/home/oof/libfuzzer/fuck/pymath.o");
+        build.object("/home/oof/libfuzzer/fuck/tokenizer.o");
+        build.object("/home/oof/libfuzzer/fuck/symtablemodule.o");
+        build.object("/home/oof/libfuzzer/fuck/pyarena.o");
+        build.object("/home/oof/libfuzzer/fuck/parser.o");
+        build.object("/home/oof/libfuzzer/fuck/fcntlmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/call.o");
+        build.object("/home/oof/libfuzzer/fuck/pythonrun.o");
+        build.object("/home/oof/libfuzzer/fuck/config.o");
+        build.object("/home/oof/libfuzzer/fuck/pystate.o");
+        build.object("/home/oof/libfuzzer/fuck/string_parser.o");
+        build.object("/home/oof/libfuzzer/fuck/frameobject.o");
+        build.object("/home/oof/libfuzzer/fuck/setobject.o");
+        build.object("/home/oof/libfuzzer/fuck/exceptions.o");
+        build.object("/home/oof/libfuzzer/fuck/moduleobject.o");
+        build.object("/home/oof/libfuzzer/fuck/pegen.o");
+        build.object("/home/oof/libfuzzer/fuck/fileio.o");
+        build.object("/home/oof/libfuzzer/fuck/_codecsmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/ast.o");
+        build.object("/home/oof/libfuzzer/fuck/methodobject.o");
+        build.object("/home/oof/libfuzzer/fuck/dictobject.o");
+        build.object("/home/oof/libfuzzer/fuck/pystrtod.o");
+        build.object("/home/oof/libfuzzer/fuck/selectmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/_abc.o");
+        build.object("/home/oof/libfuzzer/fuck/unicodedata.o");
+        build.object("/home/oof/libfuzzer/fuck/token.o");
+        build.object("/home/oof/libfuzzer/fuck/object.o");
+        build.object("/home/oof/libfuzzer/fuck/xxsubtype.o");
+        build.object("/home/oof/libfuzzer/fuck/bootstrap_hash.o");
+        build.object("/home/oof/libfuzzer/fuck/cmathmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/sysmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/cellobject.o");
+        build.object("/home/oof/libfuzzer/fuck/getopt.o");
+        build.object("/home/oof/libfuzzer/fuck/descrobject.o");
+        build.object("/home/oof/libfuzzer/fuck/bytes_methods.o");
+        build.object("/home/oof/libfuzzer/fuck/_pickle.o");
+        build.object("/home/oof/libfuzzer/fuck/initconfig.o");
+        build.object("/home/oof/libfuzzer/fuck/faulthandler.o");
+        build.object("/home/oof/libfuzzer/fuck/zlibmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/_localemodule.o");
+        build.object("/home/oof/libfuzzer/fuck/errnomodule.o");
+        build.object("/home/oof/libfuzzer/fuck/_functoolsmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/sliceobject.o");
+        build.object("/home/oof/libfuzzer/fuck/structseq.o");
+        build.object("/home/oof/libfuzzer/fuck/typeobject.o");
+        build.object("/home/oof/libfuzzer/fuck/libpython3.10.a");
+        build.object("/home/oof/libfuzzer/fuck/textio.o");
+        build.object("/home/oof/libfuzzer/fuck/fileutils.o");
+        build.object("/home/oof/libfuzzer/fuck/atexitmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/interpreteridobject.o");
+        build.object("/home/oof/libfuzzer/fuck/asdl.o");
+        build.object("/home/oof/libfuzzer/fuck/binascii.o");
+        build.object("/home/oof/libfuzzer/fuck/unionobject.o");
+        build.object("/home/oof/libfuzzer/fuck/funcobject.o");
+        build.object("/home/oof/libfuzzer/fuck/myreadline.o");
+        build.object("/home/oof/libfuzzer/fuck/traceback.o");
+        build.object("/home/oof/libfuzzer/fuck/ceval.o");
+        build.object("/home/oof/libfuzzer/fuck/sha3module.o");
+        build.object("/home/oof/libfuzzer/fuck/getbuildinfo.o");
+        build.object("/home/oof/libfuzzer/fuck/memoryobject.o");
+        build.object("/home/oof/libfuzzer/fuck/_randommodule.o");
+        build.object("/home/oof/libfuzzer/fuck/unicodectype.o");
+        build.object("/home/oof/libfuzzer/fuck/errors.o");
+        build.object("/home/oof/libfuzzer/fuck/sha512module.o");
+        build.object("/home/oof/libfuzzer/fuck/timemodule.o");
+        build.object("/home/oof/libfuzzer/fuck/blake2s_impl.o");
+        build.object("/home/oof/libfuzzer/fuck/picklebufobject.o");
+        build.object("/home/oof/libfuzzer/fuck/getargs.o");
+        build.object("/home/oof/libfuzzer/fuck/bytesio.o");
+        build.object("/home/oof/libfuzzer/fuck/gcmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/pyfpe.o");
+        build.object("/home/oof/libfuzzer/fuck/boolobject.o");
+        build.object("/home/oof/libfuzzer/fuck/marshal.o");
+        build.object("/home/oof/libfuzzer/fuck/fileobject.o");
+        build.object("/home/oof/libfuzzer/fuck/dtoa.o");
+        build.object("/home/oof/libfuzzer/fuck/importdl.o");
+        build.object("/home/oof/libfuzzer/fuck/floatobject.o");
+        build.object("/home/oof/libfuzzer/fuck/pylifecycle.o");
+        build.object("/home/oof/libfuzzer/fuck/posixmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/peg_api.o");
+        build.object("/home/oof/libfuzzer/fuck/modsupport.o");
+        build.object("/home/oof/libfuzzer/fuck/frozenmain.o");
+        build.object("/home/oof/libfuzzer/fuck/suggestions.o");
+        build.object("/home/oof/libfuzzer/fuck/_posixsubprocess.o");
+        build.object("/home/oof/libfuzzer/fuck/stringio.o");
+        build.object("/home/oof/libfuzzer/fuck/pydtrace.o");
+        build.object("/home/oof/libfuzzer/fuck/thread.o");
+        build.object("/home/oof/libfuzzer/fuck/Python-ast.o");
+        build.object("/home/oof/libfuzzer/fuck/import.o");
+        build.object("/home/oof/libfuzzer/fuck/pystrhex.o");
+        build.object("/home/oof/libfuzzer/fuck/pathconfig.o");
+        build.object("/home/oof/libfuzzer/fuck/grpmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/formatter_unicode.o");
+        build.object("/home/oof/libfuzzer/fuck/blake2module.o");
+        build.object("/home/oof/libfuzzer/fuck/pyhash.o");
+        build.object("/home/oof/libfuzzer/fuck/_csv.o");
+        build.object("/home/oof/libfuzzer/fuck/bufferedio.o");
+        build.object("/home/oof/libfuzzer/fuck/context.o");
+        build.object("/home/oof/libfuzzer/fuck/_warnings.o");
+        build.object("/home/oof/libfuzzer/fuck/odictobject.o");
+        build.object("/home/oof/libfuzzer/fuck/structmember.o");
+        build.object("/home/oof/libfuzzer/fuck/unicodeobject.o");
+        build.object("/home/oof/libfuzzer/fuck/hamt.o");
+        build.object("/home/oof/libfuzzer/fuck/longobject.o");
+        build.object("/home/oof/libfuzzer/fuck/codecs.o");
+        build.object("/home/oof/libfuzzer/fuck/mysnprintf.o");
+        build.object("/home/oof/libfuzzer/fuck/abstract.o");
+        build.object("/home/oof/libfuzzer/fuck/namespaceobject.o");
+        build.object("/home/oof/libfuzzer/fuck/syslogmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/rangeobject.o");
+        build.object("/home/oof/libfuzzer/fuck/frozen.o");
+        build.object("/home/oof/libfuzzer/fuck/getversion.o");
+        build.object("/home/oof/libfuzzer/fuck/_elementtree.o");
+        build.object("/home/oof/libfuzzer/fuck/_sre.o");
+        build.object("/home/oof/libfuzzer/fuck/ast_opt.o");
+        build.object("/home/oof/libfuzzer/fuck/bltinmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/_operator.o");
+        build.object("/home/oof/libfuzzer/fuck/classobject.o");
+        build.object("/home/oof/libfuzzer/fuck/spwdmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/itertoolsmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/compile.o");
+        build.object("/home/oof/libfuzzer/fuck/bytesobject.o");
+        build.object("/home/oof/libfuzzer/fuck/signalmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/mystrtoul.o");
+        build.object("/home/oof/libfuzzer/fuck/_stat.o");
+        build.object("/home/oof/libfuzzer/fuck/preconfig.o");
+        build.object("/home/oof/libfuzzer/fuck/getpath.o");
+        build.object("/home/oof/libfuzzer/fuck/socketmodule.o");
+        build.object("/home/oof/libfuzzer/fuck/_math.o");
+        build.object("/home/oof/libfuzzer/fuck/symtable.o");
+        build.object("/home/oof/libfuzzer/fuck/pytime.o");
+        build.object("/home/oof/libfuzzer/fuck/iterobject.o");
+        build.object("/home/oof/libfuzzer/fuck/pystrcmp.o");
+        build.object("/home/oof/libfuzzer/fuck/dynamic_annotations.o");
+        build.object("/home/oof/libfuzzer/fuck/_weakref.o");
+        build.object("/home/oof/libfuzzer/fuck/enumobject.o");
+        build.object("/home/oof/libfuzzer/fuck/tupleobject.o");
+        build.flag("-lexpat");
+
+
+
+        //build.object("")
+        //build.object("/usr/lib/python3.10/config-3.10-x86_64-linux-gnu/libpython3.10.so");
         build.cpp(true);
         build.compile("libfuzzer.a");
     }
diff --git a/libfuzzer/FuzzerDriver.cpp b/libfuzzer/FuzzerDriver.cpp
index 8674d78..9211f81 100644
--- a/libfuzzer/FuzzerDriver.cpp
+++ b/libfuzzer/FuzzerDriver.cpp
@@ -200,12 +200,20 @@ static void ParseFlags(const std::vector<std::string> &Args,
   }

   // Disable len_control by default, if LLVMFuzzerCustomMutator is used.
+  /*
+
   if (EF->LLVMFuzzerCustomMutator) {
     Flags.len_control = 0;
     Printf("INFO: found LLVMFuzzerCustomMutator (%p). "
            "Disabling -len_control by default.\n", EF->LLVMFuzzerCustomMutator);
   }

+  */
+
+  Printf("WARNING: Disabling -len_control . Assuming custom mutator!\n");
+
+  Flags.len_control = 0; // Just assume
+
   Inputs = new std::vector<std::string>;
   for (size_t A = 1; A < Args.size(); A++) {
     if (ParseOneFlag(Args[A].c_str())) {
@@ -646,8 +654,12 @@ int FuzzerDriver(int *argc, char ***argv, UserCallback Callback) {
   assert(argc && argv && "Argument pointers cannot be nullptr");
   std::string Argv0((*argv)[0]);
   EF = new ExternalFunctions();
-  if (EF->LLVMFuzzerInitialize)
-    EF->LLVMFuzzerInitialize(argc, argv);
+
+
+  //if (EF->LLVMFuzzerInitialize)
+  if (1) // Assume custom mutator.
+    LLVMFuzzerInitialize(argc, argv);
+
   if (EF->__msan_scoped_disable_interceptor_checks)
     EF->__msan_scoped_disable_interceptor_checks();
   const std::vector<std::string> Args(*argv, *argv + *argc);
@@ -931,3 +943,262 @@ LLVMFuzzerRunDriver(int *argc, char ***argv,
 ExternalFunctions *EF = nullptr;

 }  // namespace fuzzer
+
+
+
+
+
+
+
+
+
+
+
+
+
+/* This Source Code Form is subject to the terms of the Mozilla Public
+ * License, v. 2.0. If a copy of the MPL was not distributed with this
+ * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
+
+#include <Python.h>
+
+static void LLVMFuzzerFinalizePythonModule();
+static void LLVMFuzzerInitPythonModule();
+
+static PyObject* py_module = NULL;
+
+class LLVMFuzzerPyContext {
+  public:
+    LLVMFuzzerPyContext() {
+      if (!py_module) {
+        LLVMFuzzerInitPythonModule();
+      }
+    }
+    ~LLVMFuzzerPyContext() {
+      if (py_module) {
+        LLVMFuzzerFinalizePythonModule();
+      }
+    }
+};
+
+// This takes care of (de)initializing things properly
+LLVMFuzzerPyContext init;
+
+static void py_fatal_error() {
+  fprintf(stderr, "The libFuzzer Python layer encountered a critical error.\n");
+  fprintf(stderr, "Please fix the messages above and then restart fuzzing.\n");
+  exit(1);
+}
+
+enum {
+  /* 00 */ PY_FUNC_CUSTOM_MUTATOR,
+  /* 01 */ PY_FUNC_CUSTOM_CROSSOVER,
+  PY_FUNC_COUNT
+};
+
+static PyObject* py_functions[PY_FUNC_COUNT];
+
+// Forward-declare the libFuzzer's mutator callback.
+//extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
+size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
+
+
+// size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
+
+// This function unwraps the Python arguments passed, which must be
+//
+// 1) A bytearray containing the data to be mutated
+// 2) An int containing the maximum size of the new mutation
+//
+// The function will modify the bytearray in-place (and resize it accordingly)
+// if necessary. It returns None.
+PyObject* LLVMFuzzerMutatePyCallback(PyObject* data, PyObject* args) {
+  PyObject* py_value;
+
+  // Get MaxSize first, so we know how much memory we need to allocate
+  py_value = PyTuple_GetItem(args, 1);
+  if (!py_value) {
+    fprintf(stderr, "Error: Missing MaxSize argument to native callback.\n");
+    py_fatal_error();
+  }
+  size_t MaxSize = PyLong_AsSize_t(py_value);
+  if (MaxSize == (size_t)-1 && PyErr_Occurred()) {
+    PyErr_Print();
+    fprintf(stderr, "Error: Failed to convert MaxSize argument to size_t.\n");
+    py_fatal_error();
+  }
+
+  // Now get the ByteArray with our data and resize it appropriately
+  py_value = PyTuple_GetItem(args, 0);
+  size_t Size = (size_t)PyByteArray_Size(py_value);
+  if (PyByteArray_Resize(py_value, MaxSize) < 0) {
+    fprintf(stderr, "Error: Failed to resize ByteArray to MaxSize.\n");
+    py_fatal_error();
+  }
+
+  // Call libFuzzer's native mutator
+  size_t RetLen =
+    LLVMFuzzerMutate((uint8_t *)PyByteArray_AsString(py_value), Size, MaxSize);
+
+  if (PyByteArray_Resize(py_value, RetLen) < 0) {
+    fprintf(stderr, "Error: Failed to resize ByteArray to RetLen.\n");
+    py_fatal_error();
+  }
+
+  Py_RETURN_NONE;
+}
+
+static PyMethodDef LLVMFuzzerMutatePyMethodDef = {
+  "LLVMFuzzerMutate",
+  LLVMFuzzerMutatePyCallback,
+  METH_VARARGS | METH_STATIC,
+  NULL
+};
+
+static void LLVMFuzzerInitPythonModule() {
+  Py_Initialize();
+  char* module_name = getenv("LIBFUZZER_PYTHON_MODULE");
+
+  if (module_name) {
+    PyObject* py_name = PyUnicode_FromString(module_name);
+
+    py_module = PyImport_Import(py_name);
+    Py_DECREF(py_name);
+
+    //Printf("WARNING: Calling custom_mutator!\n");
+
+    //fprintf(stderr, "WARNING: Calling custom_mutator!\n");
+
+    if (py_module != NULL) {
+      py_functions[PY_FUNC_CUSTOM_MUTATOR] =
+        PyObject_GetAttrString(py_module, "custom_mutator");
+      py_functions[PY_FUNC_CUSTOM_CROSSOVER] =
+        PyObject_GetAttrString(py_module, "custom_crossover");
+
+      if (!py_functions[PY_FUNC_CUSTOM_MUTATOR]
+        || !PyCallable_Check(py_functions[PY_FUNC_CUSTOM_MUTATOR])) {
+        if (PyErr_Occurred())
+          PyErr_Print();
+        fprintf(stderr, "Error: Cannot find/call custom mutator function in"
+                        " external Python module.\n");
+        py_fatal_error();
+      }
+
+      if (!py_functions[PY_FUNC_CUSTOM_CROSSOVER]
+        || !PyCallable_Check(py_functions[PY_FUNC_CUSTOM_CROSSOVER])) {
+        if (PyErr_Occurred())
+          PyErr_Print();
+        fprintf(stderr, "Warning: Python module does not implement crossover"
+                        " API, standard crossover will be used.\n");
+        py_functions[PY_FUNC_CUSTOM_CROSSOVER] = NULL;
+      }
+    } else {
+      if (PyErr_Occurred())
+        PyErr_Print();
+      fprintf(stderr, "Error: Failed to load external Python module \"%s\"\n",
+        module_name);
+      py_fatal_error();
+    }
+  } else {
+    fprintf(stderr, "Warning: No Python module specified, using the default libfuzzer mutator (for now).\n");
+    // py_fatal_error();
+  }
+
+
+}
+
+static void LLVMFuzzerFinalizePythonModule() {
+  if (py_module != NULL) {
+    uint32_t i;
+    for (i = 0; i < PY_FUNC_COUNT; ++i)
+      Py_XDECREF(py_functions[i]);
+    Py_DECREF(py_module);
+  }
+  Py_Finalize();
+}
+
+extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
+                                          size_t MaxSize, unsigned int Seed) {
+  // First check if the custom python mutator is specified:
+  if (!py_module) { // No custom python mutator, so therefore just mutate regularly. (LLVMFuzzerMutate is the default mutator.)
+    return LLVMFuzzerMutate(Data, Size, MaxSize);
+  }
+  PyObject* py_args = PyTuple_New(4);
+
+  // Convert Data and Size to a ByteArray
+  PyObject* py_value = PyByteArray_FromStringAndSize((const char*)Data, Size);
+  if (!py_value) {
+    Py_DECREF(py_args);
+    fprintf(stderr, "Error: Failed to convert buffer.\n");
+    py_fatal_error();
+  }
+  PyTuple_SetItem(py_args, 0, py_value);
+
+  // Convert MaxSize to a PyLong
+  py_value = PyLong_FromSize_t(MaxSize);
+  if (!py_value) {
+    Py_DECREF(py_args);
+    fprintf(stderr, "Error: Failed to convert maximum size.\n");
+    py_fatal_error();
+  }
+  PyTuple_SetItem(py_args, 1, py_value);
+
+  // Convert Seed to a PyLong
+  py_value = PyLong_FromUnsignedLong((unsigned long)Seed);
+  if (!py_value) {
+    Py_DECREF(py_args);
+    fprintf(stderr, "Error: Failed to convert seed.\n");
+    py_fatal_error();
+  }
+  PyTuple_SetItem(py_args, 2, py_value);
+
+  PyObject* py_callback = PyCFunction_New(&LLVMFuzzerMutatePyMethodDef, NULL);
+  if (!py_callback) {
+    fprintf(stderr, "Failed to create native callback\n");
+    py_fatal_error();
+  }
+
+  // Pass the native callback
+  PyTuple_SetItem(py_args, 3, py_callback);
+
+  //fprintf(stderr, "WARNING: Calling custom_mutator!\n"); // Do not do the stuff.
+
+  py_value = PyObject_CallObject(py_functions[PY_FUNC_CUSTOM_MUTATOR], py_args);
+
+  Py_DECREF(py_args);
+  Py_DECREF(py_callback);
+
+  if (py_value != NULL) {
+    ssize_t ReturnedSize = PyByteArray_Size(py_value);
+    if (ReturnedSize > MaxSize) {
+      fprintf(stderr, "Warning: Python module returned buffer that exceeds "
+                      "the maximum size. Returning a truncated buffer.\n");
+      ReturnedSize = MaxSize;
+    }
+    memcpy(Data, PyByteArray_AsString(py_value), ReturnedSize);
+    Py_DECREF(py_value);
+    // return ReturnedSize; // Instead of returning the python custom mutator, we should also try to use the original custom mutator too (maybe).
+    if (getenv("FUZZ_ONLY_CUSTOM")) { // Only fuzz with the custom mutator
+      return ReturnedSize;
+    }
+
+
+    return LLVMFuzzerMutate(Data, ReturnedSize, MaxSize);
+
+  } else {
+    if (PyErr_Occurred())
+      PyErr_Print();
+    fprintf(stderr, "Error: Call failed\n");
+    py_fatal_error();
+  }
+  return 0;
+}
+
+
+
+
+
+
+
+
+
diff --git a/libfuzzer/FuzzerExtFunctions.def b/libfuzzer/FuzzerExtFunctions.def
index 51edf84..2e83af9 100644
--- a/libfuzzer/FuzzerExtFunctions.def
+++ b/libfuzzer/FuzzerExtFunctions.def
@@ -14,10 +14,15 @@
 //===----------------------------------------------------------------------===//

 // Optional user functions
-EXT_FUNC(LLVMFuzzerInitialize, int, (int *argc, char ***argv), false);
-EXT_FUNC(LLVMFuzzerCustomMutator, size_t,
-         (uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed),
-         false);
+
+// I commented these out, because we are going to define these ourselves.
+
+// EXT_FUNC(LLVMFuzzerInitialize, int, (int *argc, char ***argv), false);
+// EXT_FUNC(LLVMFuzzerCustomMutator, size_t,
+//          (uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed),
+//          false);
+
+
 EXT_FUNC(LLVMFuzzerCustomCrossOver, size_t,
          (const uint8_t *Data1, size_t Size1,
           const uint8_t *Data2, size_t Size2,
diff --git a/libfuzzer/FuzzerLoop.cpp b/libfuzzer/FuzzerLoop.cpp
index 935dd23..4781292 100644
--- a/libfuzzer/FuzzerLoop.cpp
+++ b/libfuzzer/FuzzerLoop.cpp
@@ -930,12 +930,15 @@ void Fuzzer::MinimizeCrashLoop(const Unit &U) {

 } // namespace fuzzer

-extern "C" {
+//extern "C" {

-ATTRIBUTE_INTERFACE size_t
-LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize) {
+//ATTRIBUTE_INTERFACE size_t
+size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize) {
   assert(fuzzer::F);
   return fuzzer::F->GetMD().DefaultMutate(Data, Size, MaxSize);
 }

-} // extern "C"
+//} // extern "C"
+
+
+
diff --git a/libfuzzer/FuzzerMutate.cpp b/libfuzzer/FuzzerMutate.cpp
index 1abce16..971b0f6 100644
--- a/libfuzzer/FuzzerMutate.cpp
+++ b/libfuzzer/FuzzerMutate.cpp
@@ -15,6 +15,9 @@
 #include "FuzzerOptions.h"
 #include "FuzzerTracePC.h"

+// For the custom shit.
+#include "FuzzerInterface.h"
+
 namespace fuzzer {

 const size_t Dictionary::kMaxDictSize;
@@ -50,7 +53,8 @@ MutationDispatcher::MutationDispatcher(Random &Rand,
     DefaultMutators.push_back(
         {&MutationDispatcher::Mutate_AddWordFromTORC, "CMP"});

-  if (EF->LLVMFuzzerCustomMutator)
+  //if (EF->LLVMFuzzerCustomMutator)
+  if (1) // Assume custom mutator
     Mutators.push_back({&MutationDispatcher::Mutate_Custom, "Custom"});
   else
     Mutators = DefaultMutators;
@@ -73,8 +77,14 @@ size_t MutationDispatcher::Mutate_Custom(uint8_t *Data, size_t Size,
     EF->__msan_unpoison(Data, Size);
   if (EF->__msan_unpoison_param)
     EF->__msan_unpoison_param(4);
+
+  /*
   return EF->LLVMFuzzerCustomMutator(Data, Size, MaxSize,
                                      Rand.Rand<unsigned int>());
+  */
+
+  return LLVMFuzzerCustomMutator(Data, Size, MaxSize,
+                                     Rand.Rand<unsigned int>());
 }

 size_t MutationDispatcher::Mutate_CustomCrossOver(uint8_t *Data, size_t Size,


```


(you need to unrar python into a directory and then do it that way. There is a more wise way to do it, but I discovered it only after I did that the dumb way and was too dumb to change it back...)

then you can use this fuzzing script here:

```

#!/bin/sh




export LD_PRELOAD="/usr/lib/python3.10/config-3.10-x86_64-linux-gnu/libpython3.10.so"


export LIBFUZZER_PYTHON_MODULE="main"

export ASAN_OPTIONS="allocator_may_return_null=1:detect_leaks=0:use_sigaltstack=0"

export PYTHONPATH="."



# CUSTOM_LIBFUZZER_PATH


# /home/oof/shitoof/libfuzzer/target/release/build/libfuzzer-sys-fbb203b4e9f25ffe/out

# export CUSTOM_LIBFUZZER_PATH="/home/oof/libfuzzer/target/release/build/libfuzzer-sys-fbb203b4e9f25ffe/out/libfuzzer.a"


# "/home/oof/shitoof/libfuzzer/target/release/build/libfuzzer-sys-fbb203b4e9f25ffe/out"


#export CUSTOM_LIBFUZZER_PATH="/home/oof/shitoof/libfuzzer/target/release/build/libfuzzer-sys-fbb203b4e9f25ffe/out/libfuzzer.a"


#while true
#do
  # loop infinitely
  # cargo fuzz run fuzz_run_program --jobs=1 -- -rss_limit_mb=4096 -max_len=2000000 -timeout=1 2>> fuzz_output.txt || true # Fuzz continuously

  # cargo fuzz run fuzz_run_program --jobs=1 -- -rss_limit_mb=4096 -max_len=2000 -timeout=1 2>> fuzz_output.txt || true # Fuzz continuously

  # 4096

  # cargo fuzz run fuzz_run_program --jobs=1 -- -rss_limit_mb=4096 -max_len=4096 -timeout=1 2>> fuzz_output.txt || true # Fuzz continuously

  # cargo fuzz run fuzz_run_program --jobs=8 -- -rss_limit_mb=4096 -max_len=4096 -timeout=1

#done



cargo fuzz run fuzz_run_program --jobs=8 -- -rss_limit_mb=4096 -max_len=4096 -timeout=1



```

to start fuzzing!

## Results.

I will come back and report with results after a while. I am going to let the fuzzer run for a bit to see if it discovers anything major.

























