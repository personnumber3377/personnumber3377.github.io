
# Day 1

https://adventofcode.com/2023/day/1

Ok so I am actually a bit late since today as of writing this it is the third of december 2023, so let's quickly catch up!

## Part 1

Ok so the puzzle is basically get the first and last digit in an input, then concatenate those two together and you should get an integer. Do this for all of the input lines and then sum the integers together.

Instead of going through the entire string, I think it is advantageous to traverse the string first from the start to get the first number and after it has been obtained, then traverse the string from the end. That way we do not need to traverse the stuff in the middle, because that is completely irrevelant.

Here is my first attempt:

```


import sys

def parse_lines() -> list:
	lines = sys.stdin.read().split("\n")
	return lines

def get_int(line: str) -> int:
	numbers = set("0123456789")
	for i, char in enumerate(line):
		if char in numbers:
			first_num = char
			#line = line[i+1:]
			break
	for i in range(len(line)-1,-1,-1):
		if line[i] in numbers:
			last_num = line[i]
			break
	integer = int(first_num+last_num)
	return integer

def solve(lines: list) -> int:
	res = 0
	for line in line:
		res += get_int(line)
	return res
def main() -> int:
	lines = parse_lines()
	solution = solve(lines)
	return 0

if __name__=="__main__":
	exit(main())

```

and it works for the toy input. What about the actual input? No.

```
    integer = int(first_num+last_num)
                  ^^^^^^^^^
UnboundLocalError: cannot access local variable 'first_num' where it is not associated with a value
```

so we have a string which doesn't contain numbers?

Wait, nevermind. I forgot to paste the input into the file. *facepalm*

Yeah, it works.

## Part 2

Ok so now in addition to checking if our number is a digit, we also have to check if we have a typed out number as in "eight" for example. One thing which makes this a bit hard is that the typed out numbers are of different lengths, so we need to account for that. I have an idea of how to do this, but it may be slow. Let's see...

```


import sys

def parse_lines() -> list:
	lines = sys.stdin.read().split("\n")
	return lines

def get_int(line: str) -> int:
	numbers = set("0123456789")
	typed_out_numbers = ["one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]
	#print("line == "+str(line))
	for i, char in enumerate(line):
		if char in numbers:
			first_num = char
			#line = line[i+1:]
			break
		for j,string in enumerate(typed_out_numbers):
			#print("line[i:i+len(string)] == "+str(line[i:i+len(string)]))
			#print("string == "+str(string))
			if line[i:i+len(string)] == string:
				#print("Breaking")
				last_num = j
				break

	for i in range(len(line)-1,-1,-1):
		if line[i] in numbers:
			last_num = line[i]
			break
		# not in numbers
		for j,string in enumerate(typed_out_numbers):
			if line[i:i+len(string)] == string:
				last_num = j
				break


	integer = int(first_num+last_num)
	return integer

def solve(lines: list) -> int:
	res = 0
	for line in lines:
		res += get_int(line)
	return res
def main() -> int:
	lines = parse_lines()
	solution = solve(lines)
	print(solution)
	return 0

if __name__=="__main__":
	exit(main())


```

This doesn't work. This is because I have two nested loops and I need to break out both of them. And there actually was a feature suggestion, but it was rejected: https://stackoverflow.com/questions/653509/breaking-out-of-nested-loops . And to be honest I think it is good, because I should wrap this stuff into another function.

Ok so I refactored the code a bit and here it is:

```

import sys

def parse_lines() -> list:
	lines = sys.stdin.read().split("\n")
	return lines

def check_num(string: str, index: int) -> bool:
	char = string[index]
	#print("char == "+str(char))
	numbers = set("0123456789")
	typed_out_numbers = ["one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]
	#for i, char in enumerate(string):
	if char in numbers:
		return char
		#line = line[i+1:]
		#break
	for j,string in enumerate(typed_out_numbers):
		#print("line[i:i+len(string)] == "+str(line[i:i+len(string)]))
		#print("string == "+str(string))
		#print(" string[index:index+len(string)] == "+str( string[index:index+len(string)]))
		if string[index:index+len(string)] == string:
			#print("Breaking")
			last_num = str(j)
			return last_num
	return False

def get_int(line: str) -> int:
	
	#print("line == "+str(line))
	for i in range(len(line)):
		val = check_num(line, i)
		print("val == "+str(val))
		if val:
			first_num = val
			break

	for i in range(len(line)-1,-1,-1):
		val = check_num(line, i)
		if val:
			last_num = val
			break

		#if line[i] in numbers:
		#	last_num = line[i]
		#	break
		## not in numbers
		#for j,string in enumerate(typed_out_numbers):
		#	if line[i:i+len(string)] == string:
		#		last_num = j
		#		break


	integer = int(first_num+last_num)
	return integer

def solve(lines: list) -> int:
	res = 0
	for line in lines:
		res += get_int(line)
	return res
def main() -> int:
	lines = parse_lines()
	solution = solve(lines)
	print(solution)
	return 0

if __name__=="__main__":
	exit(main())

```

There is a problem in it. Can you spot it?

**SPOILER ALERT**

Here it is:

```

# ...
last_num = str(j)
# ...

```

Now, j is the index in the typed_out_numbers list, but the there is no "zero" inside of it, the first element is "one" , but it is at the zeroeth index, so we need to add one to j before converting to a string.

Also there is a variable naming conflict between the argument string and the loop string, so rename the argument to string to something else and it should now work. Right?

Aaaand it works! Great!

## Making it faster

Ok, so let's compare our solution to someone else's. Let's compare to this https://www.reddit.com/r/adventofcode/comments/1883ibu/comment/kbigj6k/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button

wait, my code is actually faster? Well, that is good enough for me.







































