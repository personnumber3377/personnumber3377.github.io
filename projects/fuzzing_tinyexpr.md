
## Fuzzing tinyexpr

I found this tiny math library called tinyexpr on github: https://github.com/codeplea/tinyexpr .



The example code on their website is this:

{% raw %}
```
#include "tinyexpr.h"
#include <stdio.h>

int main(int argc, char *argv[])
{
    const char *expression = "sqrt(3^2+4^2)";
    printf("Result: %f\n", te_interp(expression, 0));
    return 0;
}


```
{% endraw %}


