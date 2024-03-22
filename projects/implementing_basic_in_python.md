
# Basic interpreter in python

Ok, so this is the obligatory "making my own programming language" project that every person probably has on their github. I decided to do this, because I thought that doing this will probably be quite fun and that I learn a lot.

## Lexer

Ok, so just as 99.99999% of all blog articles describing creating a programming language, I am going to start with the lexer. Now, the syntax is what everyone automatically focuses on when creating their programming language, but then they usually do not think about their language internals, do they want the programming language to be functional or object oriented, what kind of language builtins it has etc etc.. So I think that the lexer part of creating your own programming language is a bit overrated, because the language syntax is only a tiny part. Because I am writing an interpreter for an existing programming language, the syntax is basically out there already.

The main structure of a line in the basic program goes like this:

`<LINENUM> KEYWORD ARGUMENT`

there are actually a couple of exceptions, but that is how it roughly works.

Let's plan out stuff a bit before diving in.

I am going to implement a "program" class, which has methods called "parse" and "run", which *drumroll* parse and run the program!

I think that having a dictionary with the line number as key and the program line as string as value. Then the main loop will loop through these lines.

Here is my very initial attempt:

```


from util import * # needed for the fail function.

# Implements the main program class

class BasicProgram:
	def __init__(self):
		self.lines = {} # line num as key and the program line as value.
		self.linenums = [] # List of valid program line numbers.
	def load(self, filename) -> None:
		# Loads program from file
		fh = open(filename, "r")
		lines = fh.readlines()
		fh.close()
		self.parse_lines(lines)
	def parse_lines(self, lines) -> None: # Parses all of the program lines.
		for line in lines:
			# Split on spaces
			tokens = line.split(" ")
			linenum = tokens[0]
			program_line = ''.join(tokens[1:])
			# The line number should actually be a number
			if not linenum.isnumeric():
				fail("The line number must actually be number: "+str(line))
			linenum = int(linenum)

```

Ok, so now it is `Fri Mar 22 04:10:09 AM EET 2024` (UTC+2) and let's continue.

First optimization is to just convert the linenums thing into a set.

I think that I will use the line number set to check if a line number where we jump with `GOTO` is actually valid, but that is in the future.

I think the first step is to identify the keyword and then I think that having a dictionary where the key is the keyword and value is the handler.

The smart way of going about these "keyword handlers" is to implement them in a separate file, but I would want these handlers to be methods of the BasicProgram class, because then we have access to all of the variables and stuff like that. Sooo, I think that I have to add methods dynamically maybe??? To stackoverflow we go! https://stackoverflow.com/questions/13079299/dynamically-adding-methods-to-a-class . Thanks to this: https://stackoverflow.com/a/65571141/14577985 .

## Implementing keyword handlers.

I am going to create a new file called keywords.py and then add all of the functions which handle all of the different keywords there.




























