
# Fuzzing ruby Kernel#Rational method

Hi!

Inspired by many writeups on hacker.one on ruby inbuilt functions, I decided to try my hand at fuzzing some ruby internals. I have done this a couple of times before and I didn't find any bugs then. However, let's see what I can find in Kernel#Rational .

## The usual setup

Just compile the newest ruby main branch with asan and ubsan. Here is my fuzzing wrapper:

{% raw %}
```


#include "ruby.h"




VALUE dangerous_func(VALUE buffer) {
	rb_funcall(rb_mKernel, rb_intern("Rational"), 1, buffer);
	return Qnil; // Just return Qnil
}


// This is needed for rb_rescue
VALUE error_func(VALUE stuff) {
	//printf("Called error_func...\n");
	return Qnil;
}


// Main fuzzing wrapper.

#define LOOP_COUNT 100000

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
	printf("Hello world!\n");

	int state;
	//rb_protect(dangerous_func, dangerous_arg, &state);


	VALUE hello_world_str;


	//ruby_setup();

	ruby_sysinit(&argc, &argv);
	RUBY_INIT_STACK;
	ruby_init();
	ruby_init_loadpath();

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
		rb_rescue(dangerous_func, hello_world_str, error_func, Qnil);

		//rb_funcall(rb_mKernel, rb_intern("Rational"), 1, hello_world_str);

		//free(hello_world_str); // Try to free the allocated memory.

		// rb_funcall(rb_mKernel, rb_intern("Rational"), 1, hello_world_str);

	}

	






	ruby_finalize();

	return 0;
}


```
{% endraw %}

I had a bit of trouble with non-existent crashes. This was caused, because I didn't properly setup the ruby environment and I only called ruby_init and not all of those functions. Big thanks to this: https://stackoverflow.com/a/36388918/14577985 !!!!

## Generating testcases.

Luckily for us, there is a file called `spec/ruby/language/numbers_spec.rb` in the ruby source code, which has plenty of testcases.

To extract these testcases, I created this quick script:

{% raw %}
```







def main() -> int:

	fh = open("numbers_spec.rb", "r")

	lines = fh.readlines()

	fh.close()

	# Extract testcases from each line if the "eval" string is in the line.

	for i, line in enumerate(lines):
		if "eval" in line:
			rest_of_line = line[line.index("eval(")+len("eval("):]
			# print(rest_of_line)
			testcase_with_quotes = rest_of_line[:rest_of_line.index(")")]

			#print(testcase_with_quotes)

			testcase_without_quotes = testcase_with_quotes[1:-1] # remove " or '

			print(testcase_without_quotes)

			fh = open("out/"+str(i), "w")
			fh.write(testcase_without_quotes)
			fh.close()

	return 0

if __name__=="__main__":
	exit(main())


```
{% endraw %}
















