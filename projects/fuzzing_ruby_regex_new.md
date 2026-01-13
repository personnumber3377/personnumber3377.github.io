# Fuzzing ruby regexes part 2

Ok, so I already fuzzed ruby regexes before a bit, but didn't find anything good. I then read up on this blog post here: https://secret.club/2024/06/30/ring-around-the-regex-1.html There seems to be some quite interesting bugs maybe yet to be found in regular expression parsers maybe, so therefore I decided to try again. I have already fuzzed regular expressions in ruby, but this didn't yield any results.

I just asked chatgpt to make me a custom mutator for regular expressions and it decided to use lark to accomplish that:

{% raw %}
```

from lark import Lark, Transformer
import random

regex_grammar = """
    start: union
    union: concat | concat "|" union
    concat: quantified | quantified concat
    quantified: atom | atom quantifier
    quantifier: "*" | "+" | "?" | "{" NUMBER ("," NUMBER)? "}"
    atom: CHAR | "." | group | character_class
    group: "(" start ")" | "(?:" start ")" | "(?<NAME>" start ")"
    character_class: "[" char_class_content "]"
    char_class_content: CHAR | CHAR "-" CHAR | char_class_content char_class_content
    CHAR: /[a-zA-Z0-9]/
    NAME: /[a-zA-Z]+/
    NUMBER: /[0-9]+/
    %ignore " "
"""

class RandomRegexGenerator(Transformer):
    def start(self, items):
        return "".join(items)

    def union(self, items):
        if len(items) == 1:
            return items[0]
        return f"{items[0]}|{items[2]}"

    def concat(self, items):
        return "".join(items)

    def quantified(self, items):
        if len(items) == 1:
            return items[0]
        return f"{items[0]}{items[1]}"

    def quantifier(self, items):
        return random.choice(["*", "+", "?", "{1,3}", "{0,5}"])

    def atom(self, items):
        return items[0]

    def group(self, items):
        return f"({items[1]})"

    def character_class(self, items):
        return f"[{items[1]}]"

    def char_class_content(self, items):
        return "".join(items)

    def CHAR(self, token):
        return token.value

    def NAME(self, token):
        return token.value

    def NUMBER(self, token):
        return token.value

# Parse the grammar
parser = Lark(regex_grammar, start="start", parser="earley")


```
{% endraw %}

seems kinda fine. Let's put the grammar to a separate file maybe??



