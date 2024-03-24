
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

The print function can take a comma or a semi-half colon separated list of arguments. For example, this is a valid program:

```
10 LET X = 10
20 PRINT "VALUE OF X: "; X
```

I think that I should add a function called "split_args" which tries to parse the arguments to the print command.

I am going to implement that function in util.py

I am using this as a reference: https://stigc.dk/c64/basic/

Ok, so apparently all of the characters between the stuff are completely ignored.

The result of this program:

```
10 LET X = 10
20 PRINT "value:"     ee ef"oof"X
```

is this: `VALUE: 0 OOF 10` ??? That is weird.

I think I am just going to just roll with it for now and separate on the "," and ";" characters. Also another thing is that you can evaluate expressions when calling "PRINT" such as 1+1 . This is actually quite complicated. I am just going to continue with the separated value list.

This was my very first attempt to create a parsing function:

```

def parse_args(string: str) -> list: # Parses the string to tokens and variables. (This is used by the PRINT function in keywords.py)

	out_list = [] # A list of tuples. the first value in each tuple is if it is a variable (1 means it is a variable) and the second value is the actual value.
	currently_in_string = False # If we are inside a string statement.
	currently_in_variable_name = False
	string_start_index = None
	var_start_index = None
	skip = None # Skip forward by this amount of characters

	for i, char in enumerate(string):
		# Check if we are currently skipping characters
		if skip:
			skip -= 1
			continue

		if char == STRING_DEF_CHAR: # Start or end of string found.
			if currently_in_string:
				# We closed a string. append this string to the list
				out_list.append(string[string_start_index:i])
				
				# The character after the string must be "," or ";"

				if string[i+1] not in ARG_SEP_CHARS:
					fail("Must separate arguments with \",\" or \";\" !")

				skip = 1 # Skip atleast the next character. ("," or ";")
				# Count the whitespaces after the "," or ";" character.

				while string[skip+i+1] == " ": # Skip whitespace
					skip += 1
				# We are no longer in string
				currently_in_string = False
				continue
			else:
				# Start of string.
				string_start_index = i+1 # The current character is a double quote character, skip over it.
				continue


		if currently_in_string: # Just a part of string.
			continue

		if char == " ":
			if currently_in_variable_name:
				# End of variable without "," or ";" character. Invalid.
				fail("Must separate arguments with \",\" or \";\" !")
			# Skip over whitespace
			continue

		# Part of variable name.

		if not currently_in_variable_name: # Start of new variable.
			var_start_index = i
			continue
		else:
			# end of variable name
			if char in ARG_SEP_CHARS:
				variable_name = string[var_start_index:i]
				out_list.append(variable_name)
				skip = 0
				while string[i+1+skip] == " " # Skip over whitespace
					skip += 1

	# String wasn't closed properly
	if currently_in_string:
		fail("Unclosed string!")

	return out_list
```

Create a test for this function maybe??? Here:

```
def test_argument_parser() -> None:
	example_string = "\"VALUE OF X: \"; X" # Example program line: PRINT "VALUE OF X: "; X
	res = parse_args(example_string)
	print(res)
	return

def main() -> int:
	# Run tests.
	test_argument_parser()
	print("All tests passed!")
	return 0

if __name__=="__main__":
	exit(main())
```

Uh oh...

```
[]
All tests passed!
```

The list is empty for some reason.

## Debugging the argument parsing function

Ok, so after a bit of debugging my function currently looks like this:

```

def parse_args(string: str) -> list: # Parses the string to tokens and variables. (This is used by the PRINT function in keywords.py)

	out_list = [] # A list of tuples. the first value in each tuple is if it is a variable (1 means it is a variable) and the second value is the actual value.
	currently_in_string = False # If we are inside a string statement.
	currently_in_variable_name = False
	string_start_index = None
	var_start_index = None
	skip = None # Skip forward by this amount of characters

	for i, char in enumerate(string):
		# Check if we are currently skipping characters
		if skip:
			skip -= 1
			continue

		if char == STRING_DEF_CHAR: # Start or end of string found.
			if currently_in_string:
				# We closed a string. append this string to the list
				out_list.append((0, string[string_start_index:i])) # zero means that the the value is a string literal
				
				# The character after the string must be "," or ";"

				if string[i+1] not in ARG_SEP_CHARS:
					fail("Must separate arguments with \",\" or \";\" !")

				skip = 1 # Skip atleast the next character. ("," or ";")
				# Count the whitespaces after the "," or ";" character.

				while string[skip+i+1] == " ": # Skip whitespace
					skip += 1
				# We are no longer in string
				currently_in_string = False
				continue
			else:
				# Start of string.
				currently_in_string = True
				string_start_index = i+1 # The current character is a double quote character, skip over it.
				continue

		if currently_in_string: # Just a part of string.
			continue

		if char == " ":
			if currently_in_variable_name:
				# End of variable without "," or ";" character. Invalid.
				fail("Must separate arguments with \",\" or \";\" !")
			# Skip over whitespace
			continue

		# Part of variable name.
		if not currently_in_variable_name: # Start of new variable.
			var_start_index = i
			currently_in_variable_name = True
			continue
		else:
			# end of variable name (also check for end of line)
			if char in ARG_SEP_CHARS or i == len(string)-1:
				currently_in_variable_name = False
				variable_name = string[var_start_index:i]
				out_list.append((1, variable_name)) # 1 means variable name
				skip = 0
				while string[i+1+skip] == " ": # Skip over whitespace
					skip += 1
	# Check for end of variable too.
	if currently_in_variable_name:
		out_list.append((1, string[var_start_index:]))
	# String wasn't closed properly
	if currently_in_string:
		fail("Unclosed string!")
	return out_list

```

which seems to work fine.

These tests pass ok:

```

def test_argument_parser() -> None:
	example_string = "\"VALUE OF X: \"; X" # Example program line: PRINT "VALUE OF X: "; X
	res = parse_args(example_string)
	assert res == [(0, "VALUE OF X: "), (1, "X")] # Tokens.
	example_string = "X; Y; Z" # Test multiple variables in a row.
	res = parse_args(example_string)
	assert res == [(1, "X"), (1, "Y"), (1, "Z")]
	print("test_argument_parser passed!")
	return
```

## Variables.

Ok, so when calling PRINT , we want to resolve these variables too. We of course wan't the string representation of these variables. By default if you have `10 LET X = 2` , the variable `X` is actually stored as a float (not as an integer). Integer operations are actually slower than operations with integers according to this: https://www.infinite-loop.at/Power64/Documentation/Power64-ReadMe/AA-C64_BASIC.html .

Here is my current code for the print function:

```

def PRINT(self, tokens):

	argument_string = " ".join(tokens)
	# Parse the arguments to this function.
	print("Here is the argument string: "+str(argument_string))
	arguments = parse_args(argument_string)
	# Print the values.
	for arg in arguments:
		if arg[0]: # Variable
			if arg[1] not in self.variables:
				# Undefined variable
				fail("Undefined variable: "+str(arg))
			# Get variable value and stringify it.
			str_value = stringify(self.variables[arg[1]])
			# Actually print it.
			print(str_value, end="")
		else: # Just a raw string.
			print(arg[1], end="")
	# Print newline.
	print("\n", end="")
	return

```

## Fixing a tiny bug.

Ok, so I added this testcase:

```
	example_string = "\"SAMPLETEXT\""
	res = parse_args(example_string)
	assert res == [(0, "SAMPLETEXT")]
```

and I get this error:

```
    if string[i+1] not in ARG_SEP_CHARS:
       ~~~~~~^^^^^
IndexError: string index out of range

```

This can be solved by just checking if we are at the end of the string before trying to access by index.

Like so:

```
				if i == len(string)-1: # The line ends in a double quote character
					currently_in_string = False
					continue
```

Commit... now I am in the 2b896fefb49d932dbd9153602698a245355bcce9 commit.

I have this tiny program:

```
10 PRINT "HELLO WORLD"
```

and here is the output:

```
Now executing this line: PRINT "HELLO WORLD"
Here is the argument string: "HELLO WORLD"
HELLO WORLD
Executed program succesfully!
```

Ok, so I think that is enough for this day. Tomorrow I think I am going to implement some if else, goto and some comparisons and maybe some type checking.

## Implementing goto









































