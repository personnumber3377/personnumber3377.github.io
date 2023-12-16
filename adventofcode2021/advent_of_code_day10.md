
# Day 10

# Part 1

Ok so this is basically just a syntax check problem.

Ok so my first thought is to make a "call stack" which basically just keeps track of what order we should close the markers, and then if the next closing thing is not the expected last seen closer marker, then it is invalid. If we reach the end of the string without encountering such a mismatch, then it is valid. I think I can explain this more thoroughly through an example:

```

If we have a string {[}] , then first the "call stack " is initially a list which has the first character of the string in it. We take the second character and see if it is an opening marker (aka "{", "[", "(" or "<") then we can just append it to the list. We can see that the second character is "[" so therefore we add it to the list. Now the marker list is ["{", "["] , this means that if we are to encounter a closing marker next, then it should be "]" for the expression to be valid. This code does not take into account strings which are incomplete. (as the mission stated). We can see that the next character after the second character (aka third character) is "}" and it is not "[" so the expression is invalid. Now, if we put "[[{}<>]()]" instead, then it should return as true. 

```

Here is the final code for part one:

```

import sys

def check_valid(lines: list) -> int:
	# Set the result counter to zero initially:
	res = 0
	'''
	): 3 points.
	]: 57 points.
	}: 1197 points.
	>: 25137 points.
	'''
	points = {")":3,"]":57,"}":1197,">":25137} # score lookup

	correct_tags = {"<":">","(":")","[":"]","{":"}"} # these are what the closers should be

	for line in lines:
		assert line[0] not in points.keys() # assume first char is not closing tag

		cur_call_stack = [line[0]] # get first character from string
		for char in line[1:]:
			if char in points.keys():
				# we are closing
				if char != correct_tags[cur_call_stack[-1]]:
					# fail
					res += points[char]
					#print("char == "+str(char))
					break
				else:
					# we closed correctly so just pop the last thing:
					cur_call_stack.pop(-1)
			else:
				# not a closing character, so append it to the call stack
				cur_call_stack.append(char)

	return res # placeholder

def parse_input() -> list:

	input_str = sys.stdin.read()
	lines = input_str.split("\n")
	return lines

def main() -> int:
	input_lines = parse_input()
	res = check_valid(input_lines)
	print(res)
	return 0

if __name__=="__main__":
	exit(main())


```

That was quite easy. There are obvious optimizations such as instead of calling points.keys() twice, we can just assign that to a variable instead, but let's first solve part two and then try to optimize this.


# Part 2

Ok so just correct the string? First we need to get rid of the invalid strings, we can either just remove the invalid strings while we iterate over the list or we can append the valid lines into another list. Due to the way python works (it stores pointers to strings, not the actual strings) I think it is more efficient to just copy the strings to another list (append the pointers to the strings). Then after we are done getting the incomplete strings out of the input, we can then just get the score for each completion string and then after that we just sort the list of the scores and get the middle one. Though it may actually be faster to insert the scores in their right places initially, and not sort it afterwards. I don't know if that is actually faster, anyway here is the final code:

```


import sys


PART = 2

def part1(lines: list) -> int:
	# Set the result counter to zero initially:
	res = 0
	'''
	): 3 points.
	]: 57 points.
	}: 1197 points.
	>: 25137 points.
	'''
	points = {")":3,"]":57,"}":1197,">":25137} # score lookup

	correct_tags = {"<":">","(":")","[":"]","{":"}"} # these are what the closers should be
	#incomplete_strings = []
	for line in lines:
		assert line[0] not in points.keys() # assume first char is not closing tag
		#invalid = False
		cur_call_stack = [line[0]] # get first character from string
		for char in line[1:]:
			if char in points.keys():
				# we are closing
				if char != correct_tags[cur_call_stack[-1]]:
					# fail
					res += points[char]
					#print("char == "+str(char))
					#invalid = True
					break
				else:
					# we closed correctly so just pop the last thing:
					cur_call_stack.pop(-1)
			else:
				# not a closing character, so append it to the call stack
				cur_call_stack.append(char)
		#if not invalid:
		#	incomplete_strings.append(tuple((line, cur_call_stack)))

	# Now we have gotten rid of the invalid strings.


	return res # placeholder


def get_score_part2(char_list: list) -> int:
	res = 0
	print("char_list == "+str(char_list))
	points = {")":1,"]":2,"}":3,">":4}
	multiplier = 5
	for char in char_list:
		res *= multiplier
		res += points[char]
	print(res)
	return res


def part2(lines: list) -> int:
	# Set the result counter to zero initially:
	res = 0
	'''
	): 3 points.
	]: 57 points.
	}: 1197 points.
	>: 25137 points.
	'''
	points = {")":3,"]":57,"}":1197,">":25137} # score lookup

	correct_tags = {"<":">","(":")","[":"]","{":"}"} # these are what the closers should be
	#correct_tags_closing = {">":"<","(":")","[":"]","{":"}"}
	incomplete_strings = []
	for line in lines:
		assert line[0] not in points.keys() # assume first char is not closing tag
		invalid = False
		cur_call_stack = [line[0]] # get first character from string
		for char in line[1:]:
			if char in points.keys():
				# we are closing
				if char != correct_tags[cur_call_stack[-1]]:
					# fail
					#res += points[char]
					#print("char == "+str(char))
					invalid = True
					break
				else:
					# we closed correctly so just pop the last thing:
					cur_call_stack.pop(-1)
			else:
				# not a closing character, so append it to the call stack
				cur_call_stack.append(char)
		if not invalid:
			incomplete_strings.append(tuple((line, cur_call_stack)))

	# Now we have gotten rid of the invalid strings and we need to fix them. This is done by just checking the correct 
	point_list = []
	for incomplete in incomplete_strings:
		line = incomplete[0]
		call_stack = incomplete[1]


		call_stack.reverse() # we need to go from the end to the start, because that way we close them correctly
		completion_string = [correct_tags[x] for x in call_stack]
		print("completion_string: "+str(completion_string))
		res = get_score_part2(completion_string)
		point_list.append(res)

	point_list = sorted(point_list)
	assert len(point_list) % 2 == 1 # it must be odd length


	return point_list[len(point_list)//2]
	#return res # placeholder






def parse_input() -> list:

	input_str = sys.stdin.read()
	lines = input_str.split("\n")
	return lines

def main() -> int:
	input_lines = parse_input()
	if PART == 1:

		res = part1(input_lines)
	elif PART == 2:
		res = part2(input_lines)
	else:
		print("Invalid puzzle part number: "+str(PART))
		exit(1)
	print(res)
	return 0

if __name__=="__main__":
	exit(main())


```

# Making it faster

Yeah I know that making fast programs python is a horrible tool for, but the basic programming principles apply to every language, so I am still going to do some optimizations for this (or atleast try).

Here is the cprofile output sorted by total time:

```

3969823589
         14398 function calls in 0.015 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        1    0.012    0.012    0.014    0.014 main.py:60(part2)
     7146    0.001    0.000    0.001    0.000 {method 'keys' of 'dict' objects}
     4144    0.001    0.000    0.001    0.000 {method 'append' of 'list' objects}
     2957    0.000    0.000    0.000    0.000 {method 'pop' of 'list' objects}
       45    0.000    0.000    0.000    0.000 main.py:48(get_score_part2)
       45    0.000    0.000    0.000    0.000 main.py:104(<listcomp>)
        1    0.000    0.000    0.000    0.000 {built-in method builtins.print}
        1    0.000    0.000    0.015    0.015 main.py:1(<module>)
        1    0.000    0.000    0.000    0.000 {method 'read' of '_io.TextIOWrapper' objects}
        1    0.000    0.000    0.015    0.015 main.py:127(main)
        1    0.000    0.000    0.000    0.000 {method 'split' of 'str' objects}
        1    0.000    0.000    0.000    0.000 {built-in method builtins.sorted}
       45    0.000    0.000    0.000    0.000 {method 'reverse' of 'list' objects}
        1    0.000    0.000    0.000    0.000 <frozen _sitebuiltins>:19(__call__)
        1    0.000    0.000    0.000    0.000 <frozen codecs>:319(decode)
        1    0.000    0.000    0.000    0.000 {method 'close' of '_io.TextIOWrapper' objects}
        1    0.000    0.000    0.000    0.000 main.py:121(parse_input)
        1    0.000    0.000    0.015    0.015 {built-in method builtins.exec}
        1    0.000    0.000    0.000    0.000 {built-in method _codecs.utf_8_decode}
        1    0.000    0.000    0.000    0.000 {method 'disable' of '_lsprof.Profiler' objects}
        2    0.000    0.000    0.000    0.000 {built-in method builtins.len}


```

and as you can see the part2 function takes quite a lot, so there is some space for optimizations. Removing the asserts we can speed it by a bit, but not that much.

removing the ".keys()" call from the program and actually assigning to a variable instead of just calling .keys each time we can speed it up by quite a bit:

```

3969823589
         7252 function calls in 0.007 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        1    0.005    0.005    0.007    0.007 main.py:60(part2)
     4144    0.000    0.000    0.000    0.000 {method 'append' of 'list' objects}
     2957    0.000    0.000    0.000    0.000 {method 'pop' of 'list' objects}
       45    0.000    0.000    0.000    0.000 main.py:48(get_score_part2)
       45    0.000    0.000    0.000    0.000 main.py:106(<listcomp>)
        1    0.000    0.000    0.000    0.000 {built-in method builtins.print}
        1    0.000    0.000    0.007    0.007 main.py:1(<module>)
        1    0.000    0.000    0.000    0.000 {method 'read' of '_io.TextIOWrapper' objects}
        1    0.000    0.000    0.007    0.007 main.py:129(main)
        1    0.000    0.000    0.000    0.000 {method 'split' of 'str' objects}
        1    0.000    0.000    0.000    0.000 <frozen codecs>:319(decode)
        1    0.000    0.000    0.000    0.000 <frozen _sitebuiltins>:19(__call__)
       45    0.000    0.000    0.000    0.000 {method 'reverse' of 'list' objects}
        1    0.000    0.000    0.000    0.000 {built-in method builtins.sorted}
        1    0.000    0.000    0.000    0.000 main.py:123(parse_input)
        1    0.000    0.000    0.000    0.000 {method 'close' of '_io.TextIOWrapper' objects}
        1    0.000    0.000    0.007    0.007 {built-in method builtins.exec}
        1    0.000    0.000    0.000    0.000 {built-in method _codecs.utf_8_decode}
        1    0.000    0.000    0.000    0.000 {method 'disable' of '_lsprof.Profiler' objects}
        1    0.000    0.000    0.000    0.000 {built-in method builtins.len}
        1    0.000    0.000    0.000    0.000 {method 'keys' of 'dict' objects}


```

another thing is that we do not even need to include the line in the tuple thing. Then another thing is to simplify the looping mechanism. Currently our code looks like this:


```

import sys


PART = 2

def part1(lines: list) -> int:
	# Set the result counter to zero initially:
	res = 0
	'''
	): 3 points.
	]: 57 points.
	}: 1197 points.
	>: 25137 points.
	'''
	points = {")":3,"]":57,"}":1197,">":25137} # score lookup

	correct_tags = {"<":">","(":")","[":"]","{":"}"} # these are what the closers should be
	#incomplete_strings = []
	for line in lines:
		assert line[0] not in points.keys() # assume first char is not closing tag
		#invalid = False
		cur_call_stack = [line[0]] # get first character from string
		for char in line[1:]:
			if char in points.keys():
				# we are closing
				if char != correct_tags[cur_call_stack[-1]]:
					# fail
					res += points[char]
					#print("char == "+str(char))
					#invalid = True
					break
				else:
					# we closed correctly so just pop the last thing:
					cur_call_stack.pop(-1)
			else:
				# not a closing character, so append it to the call stack
				cur_call_stack.append(char)
		#if not invalid:
		#	incomplete_strings.append(tuple((line, cur_call_stack)))

	# Now we have gotten rid of the invalid strings.


	return res # placeholder


def get_score_part2(char_list: list) -> int:
	res = 0
	#print("char_list == "+str(char_list))
	points = {")":1,"]":2,"}":3,">":4}
	multiplier = 5
	for char in char_list:
		res *= multiplier
		res += points[char]
	#print(res)
	return res


def part2(lines: list) -> int:
	# Set the result counter to zero initially:
	res = 0
	'''
	): 3 points.
	]: 57 points.
	}: 1197 points.
	>: 25137 points.
	'''
	points = {")":3,"]":57,"}":1197,">":25137} # score lookup

	correct_tags = {"<":">","(":")","[":"]","{":"}"} # these are what the closers should be
	#correct_tags_closing = {">":"<","(":")","[":"]","{":"}"}
	points_keys = points.keys()
	incomplete_strings = []
	for line in lines:
		#assert line[0] not in points.keys() # assume first char is not closing tag
		invalid = False
		#cur_call_stack = [line[0]] # get first character from string
		cur_call_stack = []
		for char in line:
			if char in points_keys:
				# we are closing
				if char != correct_tags[cur_call_stack[-1]]:
					# fail
					#res += points[char]
					#print("char == "+str(char))
					invalid = True
					break
				else:
					# we closed correctly so just pop the last thing:
					cur_call_stack.pop(-1)
			else:
				# not a closing character, so append it to the call stack
				cur_call_stack.append(char)
		if not invalid:
			incomplete_strings.append(cur_call_stack)

	# Now we have gotten rid of the invalid strings and we need to fix them. This is done by just checking the correct 
	
	point_list = []

	for call_stack in incomplete_strings:



		call_stack.reverse() # we need to go from the end to the start, because that way we close them correctly
		completion_string = [correct_tags[x] for x in call_stack]
		#print("completion_string: "+str(completion_string))
		res = get_score_part2(completion_string)
		point_list.append(res)

	point_list = sorted(point_list)
	#assert len(point_list) % 2 == 1 # it must be odd length


	return point_list[len(point_list)//2]
	#return res # placeholder






def parse_input() -> list:

	input_str = sys.stdin.read()
	lines = input_str.split("\n")
	return lines

def main() -> int:
	input_lines = parse_input()
	if PART == 1:

		res = part1(input_lines)
	elif PART == 2:
		res = part2(input_lines)
	else:
		print("Invalid puzzle part number: "+str(PART))
		exit(1)
	print(res)
	return 0

if __name__=="__main__":
	exit(main())


```

and our cProfile report looks like this:

```

3969823589
         7342 function calls in 0.004 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        1    0.003    0.003    0.003    0.003 main.py:60(part2)
     4234    0.000    0.000    0.000    0.000 {method 'append' of 'list' objects}
     2957    0.000    0.000    0.000    0.000 {method 'pop' of 'list' objects}
       45    0.000    0.000    0.000    0.000 main.py:48(get_score_part2)
       45    0.000    0.000    0.000    0.000 main.py:107(<listcomp>)
        1    0.000    0.000    0.000    0.000 {built-in method builtins.print}
        1    0.000    0.000    0.000    0.000 {method 'close' of '_io.TextIOWrapper' objects}
        1    0.000    0.000    0.000    0.000 {method 'split' of 'str' objects}
        1    0.000    0.000    0.000    0.000 {method 'read' of '_io.TextIOWrapper' objects}
        1    0.000    0.000    0.004    0.004 main.py:1(<module>)
        1    0.000    0.000    0.004    0.004 main.py:130(main)
        1    0.000    0.000    0.000    0.000 {built-in method builtins.sorted}
        1    0.000    0.000    0.000    0.000 main.py:124(parse_input)
        1    0.000    0.000    0.000    0.000 <frozen codecs>:319(decode)
        1    0.000    0.000    0.000    0.000 <frozen _sitebuiltins>:19(__call__)
       45    0.000    0.000    0.000    0.000 {method 'reverse' of 'list' objects}
        1    0.000    0.000    0.004    0.004 {built-in method builtins.exec}
        1    0.000    0.000    0.000    0.000 {built-in method _codecs.utf_8_decode}
        1    0.000    0.000    0.000    0.000 {method 'disable' of '_lsprof.Profiler' objects}
        1    0.000    0.000    0.000    0.000 {built-in method builtins.len}
        1    0.000    0.000    0.000    0.000 {method 'keys' of 'dict' objects}


```

Let's compare our solution to other peoples solutions: https://www.reddit.com/r/adventofcode/comments/rd0s54/comment/hohtmda/?utm_source=share&utm_medium=web2x&context=3 this seems to be quite a fast solution, lets see how it fares on my machine:

```

         4045 function calls (3982 primitive calls) in 0.006 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
       62    0.001    0.000    0.002    0.000 <frozen importlib._bootstrap_external>:1676(find_spec)
        4    0.000    0.000    0.000    0.000 {built-in method marshal.loads}
       24    0.000    0.000    0.000    0.000 {built-in method builtins.__build_class__}
       76    0.000    0.000    0.000    0.000 {built-in method posix.stat}
      311    0.000    0.000    0.001    0.000 <frozen importlib._bootstrap_external>:126(_path_join)
      311    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:128(<listcomp>)
        3    0.000    0.000    0.000    0.000 {built-in method builtins.eval}
        3    0.000    0.000    0.000    0.000 __init__.py:348(namedtuple)
        1    0.000    0.000    0.002    0.002 parse.py:1(<module>)
       11    0.000    0.000    0.002    0.000 <frozen importlib._bootstrap_external>:1538(_get_spec)
        1    0.000    0.000    0.000    0.000 {built-in method _imp.create_dynamic}
       12    0.000    0.000    0.002    0.000 <frozen importlib._bootstrap>:1183(_find_spec)
      314    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:403(_verbose_message)
      6/1    0.000    0.000    0.006    0.006 {built-in method builtins.exec}
     12/1    0.000    0.000    0.006    0.006 <frozen importlib._bootstrap>:1294(_find_and_load)
      630    0.000    0.000    0.000    0.000 {method 'rstrip' of 'str' objects}
      325    0.000    0.000    0.000    0.000 {method 'join' of 'str' objects}
        1    0.000    0.000    0.005    0.005 pathlib.py:1(<module>)
        4    0.000    0.000    0.000    0.000 {built-in method io.open_code}
       74    0.000    0.000    0.000    0.000 {built-in method builtins.getattr}
       12    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:216(acquire)
       12    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:338(_get_module_lock)
:


```

and it fares slightly worse, but there is a lot of other shit going on in that for some reason. Now it is actually getting quite hard to tell which one is faster, so I think we may actually have to write a tool which generates inputs for us. I am quite pissed that the adventofcode website does not offer the programs which supply the inputs themselves, because I think by increasing the input size to the program you can figure out how fast your program actually is.





```


import random

PREFERRED_LENGTH = 1000
CLOSE_CHANCE = 0.2

OPEN_BRACKETS = ["<", "{", "[", "("]
CLOSE_BRACKETS = {"<":">", "{":"}", "[":"]", "(":")"}

def generate_line(length: int) -> str:
	# This generates one test case

	complete_string = ""
	call_stack = []

	while len(complete_string) != length:

		# Check if we should open or close
		if random.random() < CLOSE_CHANCE and complete_string != "" and call_stack != []: # Can not close if the very first thing
			# Close.
			complete_string += call_stack[-1]
			call_stack.pop(-1)
		else:
			# Open new bracket
			thing = random.choice(list(CLOSE_BRACKETS.keys()))
			complete_string += thing
			call_stack.append(CLOSE_BRACKETS[thing])

	#print(complete_string)
	return complete_string


def main() -> int:
	count = 10000
	for _ in range(count):
		print(generate_line(PREFERRED_LENGTH))
	return 0


if __name__=="__main__":

	exit(main())


```

This program generates test files. When running with a generated file, we can see that our implementation takes around six seconds to complete, when as the plagiarized version takes around ten seconds.



Here is an even more simplified plagiarized one:

```

from collections import deque
import fileinput

pairs = {"(": ")", "[": "]", "{": "}", "<": ">"}
points = {")": 3, "]": 57, "}": 1197, ">": 25137}
part1, part2 = 0, []

for line in fileinput.input():
    stack = deque()
    for c in line.strip():
        if c in "([{<":
            stack.appendleft(pairs[c])
        elif c != stack.popleft():
            part1 += points[c]
            break
    else:
        score = 0
        for c in stack:
            score = score * 5 + ")]}>".index(c) + 1
        part2.append(score)

print(part1)
print(sorted(part2)[len(part2) // 2])

```
This actually gets the wrong answer for some reason, but it is still slower, so I think my code won.






















