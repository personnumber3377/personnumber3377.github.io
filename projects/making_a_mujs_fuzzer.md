# Fuzzing MUJS

Ok, so our target is this here: https://github.com/ccxvii/mujs looking at the issues, it appears that there are plenty of heap issues: https://github.com/ccxvii/mujs/issues/209 . I am thinking of trying to fuzz the regex engine because that seems interesting...

## Making a fuzzing corpus...

Something like this maybe???

{% raw %}
```
#!/bin/sh

CC=clang CXX=clang++ CFLAGS="-fsanitize=address,undefined,fuzzer-no-link" CXXFLAGS="-fsanitize=address,undefined,fuzzer-no-link" make -j$(nproc) release
```
{% endraw %}

that doesn't work, since the Makefile doesn't respect CFLAGS: `CFLAGS = -std=c99 -pedantic -Wall -Wextra -Wno-unused-parameter` so we need to modify the makefile itself. Maybe something like this here: `CFLAGS = -fsanitize=address,undefined,fuzzer-no-link -std=c99 -pedantic -Wall -Wextra -Wno-unused-parameter` and that seemed to work.

Now it is time to actually make the fuzzer:

{% raw %}
```

// regex_fuzzer.c
#include "mujs.h" // Include mujs header

// Global variables...

js_State *J;


/*
js_State *J;

J = js_newstate(NULL, NULL, strict ? JS_STRICT : 0);
	if (!J) {
		fprintf(stderr, "Could not initialize MuJS.\n");
		exit(1);
	}



void js_newregexp(js_State *J, const char *pattern, int flags)
{
	js_newregexpx(J, pattern, flags, 0);
}


*/

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	// Setup mujs...
	J = js_newstate(NULL, NULL, 0); // Javascript environment.

}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	// Main fuzzer
	if size < 2 {
		return 0;
	}
	int flags = (int)(*data); // Get the first character as flags...
	js_newregexp(J, data, flags);
	return 0;
}


```
{% endraw %}

Ok, so I modified my fuzzer a bit and I now have this here:

{% raw %}
```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "mujs.h"  // Your regex header
#include "regexp.h"

#define SPLITTER "--FUZZ--"  // must not appear in random regex input


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        if (size < 3)
                return 0;

        uint8_t compile_flags = data[0];
        uint8_t exec_flags = data[1];
        const char *input = (const char *)&data[2];
        size_t input_len = size - 2;

        // Null-terminate safely
        char *input_copy = (char *)malloc(input_len + 1);
        if (!input_copy) return 0;
        memcpy(input_copy, input, input_len);
        input_copy[input_len] = '\0';

        // Find splitter
        char *split = strstr(input_copy, SPLITTER);
        if (!split) {
                free(input_copy);
                return 0;
        }

        // Separate regex and string
        *split = '\0';
        const char *regex = input_copy;
        const char *subject = split + strlen(SPLITTER);

        const char *error;
        Reprog *prog = regcomp(regex, compile_flags, &error);
        if (!prog) {
                free(input_copy);
                return 0;
        }

        Resub m;
        if (!regexec(prog, subject, &m, exec_flags)) {
                for (int i = 0; i < m.nsub; ++i) {
                        if (m.sub[i].sp && m.sub[i].ep && m.sub[i].ep > m.sub[i].sp) {
                                volatile int len = m.sub[i].ep - m.sub[i].sp;
                                volatile char sink = m.sub[i].sp[0];  // prevent optimizing out
                                (void)sink;
                        }
                }
        }

        regfree(prog);
        free(input_copy);
        return 0;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
        // Optional: set up logging, flags, etc.
        return 0;
}
```
{% endraw %}

Which seems to fuzz nicely. I am going to update you on the results a bit later on...
















