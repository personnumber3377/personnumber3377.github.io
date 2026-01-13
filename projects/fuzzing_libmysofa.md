# Fuzzing libmysofa

libmysofa is a library which is used in ffmpeg: https://github.com/FFmpeg/FFmpeg/blob/master/libavfilter/af_sofalizer.c

Looking through the library source code: https://github.com/hoene/libmysofa there doesn't appear to be fuzzers in place, so let's try to do that. I made my own fork here: https://github.com/personnumber3377/libmysofa

Looking at CMakeLists.txt there appears to be a variable called BUILD_STATIC_LIBS which determines if we should build a static library. Let's add an option to compile a fuzzer too:

Let's add this fuzzer.c source code: (this is based on the code found in ffmpeg)

{% raw %}
```


#include "../hrtf/mysofa.h"
#include "../hrtf/tools.h"
// #include "json.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	// Main fuzzer

	struct MYSOFA_HRTF *mysofa;
	struct MYSOFA_LOOKUP *lookup;
	char *license;
	int ret;




	mysofa = mysofa_load_data(Data, Size, &ret);
	//s->sofa.hrtf = mysofa;
	if (ret || !mysofa) {
		return 0;
		//av_log(ctx, AV_LOG_ERROR, "Can't find SOFA-file '%s'\n", filename);
		//return AVERROR(EINVAL);
	}

	ret = mysofa_check(mysofa);
	if (ret != MYSOFA_OK) {
		//av_log(ctx, AV_LOG_ERROR, "Selected SOFA file is invalid. Please select valid SOFA file.\n");
		return 0; // ret;
	}

	//if (s->normalize)
	mysofa_loudness(mysofa);

	//if (s->minphase)
	mysofa_minphase(mysofa, 0.01f);

	mysofa_tocartesian(mysofa);

	lookup = mysofa_lookup_init(mysofa);
	if (lookup == NULL)
	    return 0;

	//if (s->interpolate)
	// s->sofa.neighborhood = mysofa_neighborhood_init_withstepdefine(s->sofa.hrtf, s->sofa.lookup, s->anglestep, s->radstep);

	mysofa_neighborhood_init_withstepdefine(mysofa, lookup, 0.1f, 0.1f); // Maybe do something like this???
	// float neighbor_angle_step, float neighbor_radius_step

	license = mysofa_getAttribute(mysofa->attributes, (char *)"License");


	return 0;  // Values other than 0 and -1 are reserved for future use.
}



```
{% endraw %}

it tries to somewhat mimic the functionality found in ffmpeg for fuzzing purposes. Now let's add the modifications to CMakeLists.txt

{% raw %}
```



```
{% endraw %}



here:

{% raw %}
```

export ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer
export ASAN_OPTIONS=symbolize=1
cmake -DCMAKE_BUILD_TYPE=Debug -DADDRESS_SANITIZE=ON -DVDEBUG=1 ..
make all test

```
{% endraw %}

That actually seems to compile the fuzzer! After a couple of fixes I am now in commit 5a45c42f8185aa70a1d4d80ce270dbb4a51fc7c2 ! Thanks for reading!

Anyway, you can take a look at the final source code here: https://github.com/personnumber3377/libmysofa
