
# Adding graph fuzzers for chainlink

I noticed that there is a bug bounty program for some crypto stuff here: https://hackerone.com/chainlink/policy_scopes . So it is basically some crypto stuff that I don't understand but looking at the code base, there actually exists a fuzzer for graphs at https://github.com/smartcontractkit/chainlink/blob/develop/core/services/pipeline/graph_fuzz_test.go , however it uses the crap inbuilt fuzz library. We want speed and coverage guided fuzzing with libfuzzer.

## Programming the corpus.

Ok, so I think this suffices:

{% raw %}
```

package pipeline

import (
	"strings"
	"github.com/smartcontractkit/chainlink/v2/core/services/pipeline"
)

func Fuzz(data []byte) int {
	pipeline.Parse(string(data[:])) // Just try to parse the bullshit...
	return 0
}


```
{% endraw %}

and maybe compile it with this????

{% raw %}
```


export PATH=/usr/local/bin/:/home/oof/go/bin/:$PATH

go-fuzz-build -libfuzzer -o graph_fuzzer.a ./core/services/pipeline/
clang -fsanitize=fuzzer graph_fuzzer.a -o graph_fuzzer

```
{% endraw %}

