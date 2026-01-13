
# Day 3

# Part 1

This puzzle is quite interesting in my humble opinion. There are two ways to go about this. We can either check the neighbours of the numbers, or we can check the neighbours of the special characters and see if there is a number there. Both ways should identify all of the numbers which are near a special character, but I think one of these ways will be faster than the other. I am going to guess that checking the neighbours of the numbers is faster. I think which is faster depends on the ratio of special characters which have a number nearby to the amount of special characters which don't have a number nearby. I am still going to check the neighbours of a number.

Here was my initial attempt:

{% raw %}
```


import sys

def parse_input() -> list:
	# -1 means a special character
	lines = sys.stdin.read().split("\n")
	out_matrix = []
	not_special_chars = ".0123456789"
	#for line in lines:
	#	cur_out_line = []
	#	for char in line:
	#		if char not in not_special_chars:
	#			# Special character
	#			cur_out_line.append(-1)
	return lines


def check_neighbours(input_matrix: list, x: int, y: int) -> bool:
	max_x = len(input_matrix[0]) - 1
	max_y = len(input_matrix) - 1
	not_special_chars = ".0123456789"
	neighbours = [[x,y-1], [x,y+1], [x+1,y], [x-1,y]]
	#for i, neig in enumerate(neighbours):
	i = 0
	while i < len(neighbours):
		neig = neighbours[i]
		if neig[0] > max_x:
			neighbours.pop(i)
			i -= 1
		elif neig[0] < 0:
			neighbours.pop(i)
			i -= 1

		if neig[1] > max_y:
			neighbours.pop(i)
			i -= 1
		elif neig[1] < 0:
			neighbours.pop(i)
			i -= 1
		i += 1

	# Now actually check for special chars.
	for neig in neighbours:
		char = input_matrix[neig[1]][neig[0]]
		if char not in not_special_chars:
			return True # This place has a neighbour which is a special character

	return False

def get_nums(input_matrix: list) -> int:
	# Now check all of the characters and check if they are a special character.
	tot = 0
	numbers = "0123456789"
	for y in range(len(input_matrix)):
		num_index = None
		for x in range(len(input_matrix[0])):
			cur_char = input_matrix[y][x]
			if cur_char in numbers:
				num_index = x # Mark the start of the number
				# We encountered a number, check the neighbours.
				if check_neighbours(input_matrix, x, y):
					# We have a special character, so convert the number to an integer and add it to the total
					num_thing = input_matrix[y][num_index:]
					if "." in num_thing:
						num_thing = int(num_thing[:num_thing.index(".")]) # Cut off the integer.
					else:
						# We are at the end of the line, so there isn't a "." character so convert the rest of the string to an integer.
						num_thing = int(num_thing)
					tot += num_thing
	return tot
def main() -> int:
	input_matrix = parse_input()
	solution = get_nums(input_matrix)
	return 0

if __name__=="__main__":
	exit(main())


```
{% endraw %}

Except that it doesn't work:

{% raw %}
```
    num_thing = int(num_thing[:num_thing.index(".")]) # Cut off the integer.
                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
ValueError: invalid literal for int() with base 10: '7*'
```
{% endraw %}

This occurs, because my code converts integers by checking where the "." character is, so when there is a special character, then it fails.

Here is my initial attempt to fix this bug:

{% raw %}
```
				if check_neighbours(input_matrix, x, y):
					# We have a special character, so convert the number to an integer and add it to the total
					num_thing = input_matrix[y][num_index:]
					if "." in num_thing:
						print("num_thing == "+str(num_thing))
						for i, char in enumerate(num_thing):
							print("char == "+str(char))
							if char not in numbers:
								end_index = i
						num_thing = int(num_thing[:end_index]) # Cut off the integer.
					else:
						# We are at the end of the line, so there isn't a "." character so convert the rest of the string to an integer.
						num_thing = int(num_thing)
					tot += num_thing
```
{% endraw %}

Except that it doesn't work. The reason for that is because I am not breaking out of the for loop. *facepalm*

After adding the "break" line to it, now the code runs, but it produces the wrong output. The reason for that is `num_index = x`. The num_index variable is supposed to be the start of the current number, but we are resetting it. After doing a couple of changes:

{% raw %}
```
				if num_index == None:

					num_index = x # Mark the start of the number
```
{% endraw %}

the code now still produces a wrong answer, but it is less wrong. The reason for why it is wrong, is because I only get the neighbours which aren't diagonally. Let's fix that... Now after fixing that, we still get the wrong result. This is because when we encounter a number, we do not skip over that thing. Here is the fixed version:

{% raw %}
```

import sys

def parse_input() -> list:
	# -1 means a special character
	lines = sys.stdin.read().split("\n")
	out_matrix = []
	not_special_chars = ".0123456789"
	#for line in lines:
	#	cur_out_line = []
	#	for char in line:
	#		if char not in not_special_chars:
	#			# Special character
	#			cur_out_line.append(-1)
	return lines


def check_neighbours(input_matrix: list, x: int, y: int) -> bool:
	max_x = len(input_matrix[0]) - 1
	max_y = len(input_matrix) - 1
	not_special_chars = ".0123456789"
	neighbours = [[x,y-1], [x,y+1], [x+1,y], [x-1,y], [x-1,y-1], [x-1,y+1], [x+1,y+1], [x+1,y-1]]
	#for i, neig in enumerate(neighbours):
	i = 0
	while i < len(neighbours):
		neig = neighbours[i]
		if neig[0] > max_x:
			neighbours.pop(i)
			i -= 1
		elif neig[0] < 0:
			neighbours.pop(i)
			i -= 1

		if neig[1] > max_y:
			neighbours.pop(i)
			i -= 1
		elif neig[1] < 0:
			neighbours.pop(i)
			i -= 1
		i += 1

	# Now actually check for special chars.
	for neig in neighbours:
		char = input_matrix[neig[1]][neig[0]]
		if char not in not_special_chars:
			return True # This place has a neighbour which is a special character

	return False

def get_nums(input_matrix: list) -> int:
	# Now check all of the characters and check if they are a special character.
	tot = 0
	numbers = "0123456789"
	for y in range(len(input_matrix)):
		num_index = None
		#for x in range(len(input_matrix[0])):
		x = 0
		while x != len(input_matrix[0]):
			cur_char = input_matrix[y][x]
			#print("cur_char == "+str(cur_char))
			if cur_char in numbers:
				if num_index == None:

					num_index = x # Mark the start of the number
				# We encountered a number, check the neighbours.
				if check_neighbours(input_matrix, x, y):
					# We have a special character, so convert the number to an integer and add it to the total
					num_thing = input_matrix[y][num_index:]
					if "." in num_thing:
						#print("num_thing == "+str(num_thing))
						for i, char in enumerate(num_thing):
							#print("char == "+str(char))
							if char not in numbers:
								end_index = i
								break
						oof = num_thing[:end_index]
						x = end_index+num_index
						num_thing = int(oof) # Cut off the integer.
					else:
						# We are at the end of the line, so there isn't a "." character so convert the rest of the string to an integer.
						x = len(input_matrix[0])-1
						num_thing = int(num_thing)
					num_index = None
					#print("Number: "+str(num_thing))
					tot += num_thing
			else:
				num_index = None
			#print("x == "+str(x))

			x += 1
	return tot
def main() -> int:
	input_matrix = parse_input()
	solution = get_nums(input_matrix)
	print("solution: "+str(solution))
	return 0

if __name__=="__main__":
	exit(main())

```
{% endraw %}

and it works!

## Part 2

Ok, so we want to search for very specific characters ("*") , I think it is easier to just throw the way I was doing stuff away, and now search for the "special" characters instead of searching for numbers.

This is actually surprisingly difficult, because we got to make sure we are not counting the same number as multiple neighbours.

Here is something I quickly hacked together:

{% raw %}
```


import sys

def parse_input() -> list:
	# -1 means a special character
	lines = sys.stdin.read().split("\n")
	out_matrix = []
	not_special_chars = ".0123456789"
	#for line in lines:
	#	cur_out_line = []
	#	for char in line:
	#		if char not in not_special_chars:
	#			# Special character
	#			cur_out_line.append(-1)
	return lines


def get_neighbours(input_matrix: list, x: int, y: int) -> list:

	max_x = len(input_matrix[0]) - 1
	max_y = len(input_matrix) - 1
	not_special_chars = ".0123456789"
	neighbours = [[x,y-1], [x,y+1], [x+1,y], [x-1,y], [x-1,y-1], [x-1,y+1], [x+1,y+1], [x+1,y-1]]
	#for i, neig in enumerate(neighbours):
	i = 0
	while i < len(neighbours):
		neig = neighbours[i]
		if neig[0] > max_x:
			neighbours.pop(i)
			i -= 1
		elif neig[0] < 0:
			neighbours.pop(i)
			i -= 1

		if neig[1] > max_y:
			neighbours.pop(i)
			i -= 1
		elif neig[1] < 0:
			neighbours.pop(i)
			i -= 1
		i += 1
	return neighbours


def check_neighbours(input_matrix: list, x: int, y: int) -> bool:
	max_x = len(input_matrix[0]) - 1
	max_y = len(input_matrix) - 1
	not_special_chars = ".0123456789"
	neighbours = [[x,y-1], [x,y+1], [x+1,y], [x-1,y], [x-1,y-1], [x-1,y+1], [x+1,y+1], [x+1,y-1]]
	#for i, neig in enumerate(neighbours):
	i = 0
	while i < len(neighbours):
		neig = neighbours[i]
		if neig[0] > max_x:
			neighbours.pop(i)
			i -= 1
		elif neig[0] < 0:
			neighbours.pop(i)
			i -= 1

		if neig[1] > max_y:
			neighbours.pop(i)
			i -= 1
		elif neig[1] < 0:
			neighbours.pop(i)
			i -= 1
		i += 1

	# Now actually check for special chars.
	for neig in neighbours:
		char = input_matrix[neig[1]][neig[0]]
		if char not in not_special_chars:
			return True # This place has a neighbour which is a special character

	return False


def check_neighbours_nums(input_matrix: list, x: int, y: int) -> bool:
	# Counts the number of numbers near x,y .
	neighbours = get_neighbours(input_matrix, x, y)
	# Now check for the numbers.
	out = []
	already_checked = [] # These are the spots which we have already checked. This is used to prevent reading numbers which we have already read.
	numbers = "0123456789"
	for neig in neighbours:
		if neig in already_checked:
			continue
		if input_matrix[neig[1]][neig[0]] in numbers: # We are adjacent to a number.
			#out.append(neig)
			x_diff = 0
			while input_matrix[neig[1]][neig[0] - x_diff] in numbers: # Check if the number continues.
				x_diff += 1
				already_checked.append([neig[0] - x_diff, neig[1]])
			num_min_x = neig[0] - x_diff + 1
			helper_string = input_matrix[neig[1]][num_min_x:]
			x_diff = 0
			while helper_string[x_diff] in numbers: # Check if the number continues.
				x_diff += 1
				already_checked.append([neig[0] + x_diff, neig[1]])

			final_num = helper_string[:x_diff]
			print("Final num: "+str(final_num))
			out.append(int(final_num))
			if len(out) > 2:
				return []

	return out



def get_nums(input_matrix: list) -> int:
	# Now check all of the characters and check if they are a special character.
	tot = 0



	for y in range(len(input_matrix)):
		for x in range(len(input_matrix[0])):
			# Now, search for "*"
			char = input_matrix[y][x]
			if char == "*": # We have a gear.
				# Now search for adjacent numbers.
				adjacent_numbers = check_neighbours_nums(input_matrix, x, y)
				if len(adjacent_numbers) == 2:
					tot += adjacent_numbers[0] * adjacent_numbers[1]



	'''
	for y in range(len(input_matrix)):
		num_index = None
		#for x in range(len(input_matrix[0])):
		x = 0
		while x != len(input_matrix[0]):
			cur_char = input_matrix[y][x]
			#print("cur_char == "+str(cur_char))
			if cur_char in numbers:
				if num_index == None:

					num_index = x # Mark the start of the number
				# We encountered a number, check the neighbours.
				if check_neighbours(input_matrix, x, y):
					# We have a special character, so convert the number to an integer and add it to the total
					num_thing = input_matrix[y][num_index:]
					if "." in num_thing:
						#print("num_thing == "+str(num_thing))
						for i, char in enumerate(num_thing):
							#print("char == "+str(char))
							if char not in numbers:
								end_index = i
								break
						oof = num_thing[:end_index]
						x = end_index+num_index
						num_thing = int(oof) # Cut off the integer.
					else:
						# We are at the end of the line, so there isn't a "." character so convert the rest of the string to an integer.
						x = len(input_matrix[0])-1
						num_thing = int(num_thing)
					num_index = None
					#print("Number: "+str(num_thing))
					tot += num_thing
			else:
				num_index = None
			#print("x == "+str(x))

			x += 1
	'''

	return tot
def main() -> int:
	input_matrix = parse_input()
	solution = get_nums(input_matrix)
	print("solution: "+str(solution))
	return 0

if __name__=="__main__":
	exit(main())


```
{% endraw %}

Now, obviously it needs plenty of refactoring, but atleast it works. There are probably implementations which are orders of magnitude faster than my implementation, but hey, it works! :D Does it work for the actual output though? 

Uh oh..

{% raw %}
```
   while helper_string[x_diff] in numbers: # Check if the number continues.
          ~~~~~~~~~~~~~^^^^^^^^
IndexError: string index out of range
```
{% endraw %}

That is because I forgot to add the safety checking such that we do not read past the end of the string. 76644078

Here is the sort of fixed version:

{% raw %}
```

import sys

def parse_input() -> list:
	# -1 means a special character
	lines = sys.stdin.read().split("\n")
	out_matrix = []
	not_special_chars = ".0123456789"
	#for line in lines:
	#	cur_out_line = []
	#	for char in line:
	#		if char not in not_special_chars:
	#			# Special character
	#			cur_out_line.append(-1)
	return lines


def get_neighbours(input_matrix: list, x: int, y: int) -> list:

	max_x = len(input_matrix[0]) - 1
	max_y = len(input_matrix) - 1
	not_special_chars = ".0123456789"
	neighbours = [[x,y-1], [x,y+1], [x+1,y], [x-1,y], [x-1,y-1], [x-1,y+1], [x+1,y+1], [x+1,y-1]]
	#for i, neig in enumerate(neighbours):
	i = 0
	while i < len(neighbours):
		neig = neighbours[i]
		if neig[0] > max_x:
			neighbours.pop(i)
			i -= 1
		elif neig[0] < 0:
			neighbours.pop(i)
			i -= 1

		if neig[1] > max_y:
			neighbours.pop(i)
			i -= 1
		elif neig[1] < 0:
			neighbours.pop(i)
			i -= 1
		i += 1
	return neighbours


def check_neighbours(input_matrix: list, x: int, y: int) -> bool:
	max_x = len(input_matrix[0]) - 1
	max_y = len(input_matrix) - 1
	not_special_chars = ".0123456789"
	neighbours = [[x,y-1], [x,y+1], [x+1,y], [x-1,y], [x-1,y-1], [x-1,y+1], [x+1,y+1], [x+1,y-1]]
	#for i, neig in enumerate(neighbours):
	i = 0
	while i < len(neighbours):
		neig = neighbours[i]
		if neig[0] > max_x:
			neighbours.pop(i)
			i -= 1
		elif neig[0] < 0:
			neighbours.pop(i)
			i -= 1

		if neig[1] > max_y:
			neighbours.pop(i)
			i -= 1
		elif neig[1] < 0:
			neighbours.pop(i)
			i -= 1
		i += 1

	# Now actually check for special chars.
	for neig in neighbours:
		char = input_matrix[neig[1]][neig[0]]
		if char not in not_special_chars:
			return True # This place has a neighbour which is a special character

	return False


def check_neighbours_nums(input_matrix: list, x: int, y: int) -> bool:
	# Counts the number of numbers near x,y .
	neighbours = get_neighbours(input_matrix, x, y)
	# Now check for the numbers.
	out = []
	already_checked = [] # These are the spots which we have already checked. This is used to prevent reading numbers which we have already read.
	numbers = "0123456789"
	for neig in neighbours:
		if neig in already_checked:
			continue
		if input_matrix[neig[1]][neig[0]] in numbers: # We are adjacent to a number.
			#out.append(neig)
			x_diff = 0

			while input_matrix[neig[1]][neig[0] - x_diff] in numbers and neig[0] - x_diff != len(input_matrix[neig[1]]): # Check if the number continues.
				x_diff += 1
				already_checked.append([neig[0] - x_diff, neig[1]])

			num_min_x = neig[0] - x_diff + 1
			helper_string = input_matrix[neig[1]][num_min_x:]
			x_diff = 0


			while x_diff != len(helper_string) and helper_string[x_diff] in numbers: # Check if the number continues.
				#x_diff += 1
				already_checked.append([neig[0] + x_diff, neig[1]])
				x_diff += 1

			final_num = helper_string[:x_diff]
			#print("Final num: "+str(final_num))
			out.append(int(final_num))
			if len(out) > 2:
				return []

	return out



def get_nums(input_matrix: list) -> int:
	# Now check all of the characters and check if they are a special character.
	tot = 0



	for y in range(len(input_matrix)):
		for x in range(len(input_matrix[0])):
			# Now, search for "*"
			char = input_matrix[y][x]
			if char == "*": # We have a gear.
				# Now search for adjacent numbers.
				adjacent_numbers = check_neighbours_nums(input_matrix, x, y)
				if len(adjacent_numbers) == 2:
					tot += adjacent_numbers[0] * adjacent_numbers[1]



	'''
	for y in range(len(input_matrix)):
		num_index = None
		#for x in range(len(input_matrix[0])):
		x = 0
		while x != len(input_matrix[0]):
			cur_char = input_matrix[y][x]
			#print("cur_char == "+str(cur_char))
			if cur_char in numbers:
				if num_index == None:

					num_index = x # Mark the start of the number
				# We encountered a number, check the neighbours.
				if check_neighbours(input_matrix, x, y):
					# We have a special character, so convert the number to an integer and add it to the total
					num_thing = input_matrix[y][num_index:]
					if "." in num_thing:
						#print("num_thing == "+str(num_thing))
						for i, char in enumerate(num_thing):
							#print("char == "+str(char))
							if char not in numbers:
								end_index = i
								break
						oof = num_thing[:end_index]
						x = end_index+num_index
						num_thing = int(oof) # Cut off the integer.
					else:
						# We are at the end of the line, so there isn't a "." character so convert the rest of the string to an integer.
						x = len(input_matrix[0])-1
						num_thing = int(num_thing)
					num_index = None
					#print("Number: "+str(num_thing))
					tot += num_thing
			else:
				num_index = None
			#print("x == "+str(x))

			x += 1
	'''

	return tot
def main() -> int:
	input_matrix = parse_input()
	solution = get_nums(input_matrix)
	print("solution: "+str(solution))
	return 0

if __name__=="__main__":
	exit(main())

```
{% endraw %}

It runs, but it produces the wrong output. Let's plagiarize someone elses and see what the actual solution is. Let's compare our solution to this: https://www.reddit.com/r/adventofcode/comments/189m3qw/comment/kc0ppxx/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button

And our solution is a bit off.

## Fixing our code

Let's first print all of the numbers which we spot. There appears to be quite a mismatch.

Here is a minimal testcase where shit goes haywire:

{% raw %}
```
................................
...*.....24.../.........544.436.
.391..............*565.....*....
................................
```
{% endraw %}

let's add a couple of debug statements:

{% raw %}
```

def check_neighbours_nums(input_matrix: list, x: int, y: int) -> bool:
	# Counts the number of numbers near x,y .
	print("="*20)
	print("Called check_neighbours_nums")
	global all_nums
	neighbours = get_neighbours(input_matrix, x, y)
	# Now check for the numbers.
	out = []
	already_checked = [] # These are the spots which we have already checked. This is used to prevent reading numbers which we have already read.
	numbers = "0123456789"
	for neig in neighbours:
		print("already_checked: "+str(already_checked))
		print("neig: "+str(neig))
		if neig in already_checked:
			continue
		if input_matrix[neig[1]][neig[0]] in numbers: # We are adjacent to a number.
			#out.append(neig)
			x_diff = 0

			while input_matrix[neig[1]][neig[0] - x_diff] in numbers and neig[0] - x_diff != len(input_matrix[neig[1]]): # Check if the number continues.
				x_diff += 1
				already_checked.append([neig[0] - x_diff, neig[1]])

			num_min_x = neig[0] - x_diff + 1
			helper_string = input_matrix[neig[1]][num_min_x:]
			x_diff = 0


			while x_diff != len(helper_string) and helper_string[x_diff] in numbers: # Check if the number continues.
				#x_diff += 1
				already_checked.append([neig[0] + x_diff, neig[1]])
				x_diff += 1

			final_num = helper_string[:x_diff]
			#print("Final num: "+str(final_num))
			all_nums.add(int(final_num))
			out.append(int(final_num))
			if len(out) > 2:
				return []

	return out
```
{% endraw %}

Now I get this output:
{% raw %}
```
====================
Called check_neighbours_nums
already_checked: []
neig: [3, 0]
already_checked: []
neig: [3, 2]
already_checked: [[2, 2], [1, 2], [0, 2], [3, 2], [4, 2], [5, 2]]
neig: [4, 1]
already_checked: [[2, 2], [1, 2], [0, 2], [3, 2], [4, 2], [5, 2]]
neig: [2, 1]
already_checked: [[2, 2], [1, 2], [0, 2], [3, 2], [4, 2], [5, 2]]
neig: [2, 0]
already_checked: [[2, 2], [1, 2], [0, 2], [3, 2], [4, 2], [5, 2]]
neig: [2, 2]
already_checked: [[2, 2], [1, 2], [0, 2], [3, 2], [4, 2], [5, 2]]
neig: [4, 2]
already_checked: [[2, 2], [1, 2], [0, 2], [3, 2], [4, 2], [5, 2]]
neig: [4, 0]
adjacent_numbers == [391]
====================
Called check_neighbours_nums
already_checked: []
neig: [18, 1]
already_checked: []
neig: [18, 3]
already_checked: []
neig: [19, 2]
already_checked: [[18, 2], [19, 2], [20, 2], [21, 2]]
neig: [17, 2]
already_checked: [[18, 2], [19, 2], [20, 2], [21, 2]]
neig: [17, 1]
already_checked: [[18, 2], [19, 2], [20, 2], [21, 2]]
neig: [17, 3]
already_checked: [[18, 2], [19, 2], [20, 2], [21, 2]]
neig: [19, 3]
already_checked: [[18, 2], [19, 2], [20, 2], [21, 2]]
neig: [19, 1]
adjacent_numbers == [565]
====================
Called check_neighbours_nums
already_checked: []
neig: [27, 1]
already_checked: []
neig: [27, 3]
already_checked: []
neig: [28, 2]
already_checked: []
neig: [26, 2]
already_checked: []
neig: [26, 1]
already_checked: [[25, 1], [24, 1], [23, 1], [26, 1], [27, 1], [28, 1]]
neig: [26, 3]
already_checked: [[25, 1], [24, 1], [23, 1], [26, 1], [27, 1], [28, 1]]
neig: [28, 3]
already_checked: [[25, 1], [24, 1], [23, 1], [26, 1], [27, 1], [28, 1]]
neig: [28, 1]
adjacent_numbers == [544]
solution: 0
all_nums == {544, 565, 391}
531 in all_nums: False

```
{% endraw %}

The most important bit is this:

{% raw %}
```
Called check_neighbours_nums
already_checked: []
neig: [27, 1]
already_checked: []
neig: [27, 3]
already_checked: []
neig: [28, 2]
already_checked: []
neig: [26, 2]
already_checked: []
neig: [26, 1]
already_checked: [[25, 1], [24, 1], [23, 1], [26, 1], [27, 1], [28, 1]]
neig: [26, 3]
already_checked: [[25, 1], [24, 1], [23, 1], [26, 1], [27, 1], [28, 1]]
neig: [28, 3]
already_checked: [[25, 1], [24, 1], [23, 1], [26, 1], [27, 1], [28, 1]]
neig: [28, 1]
adjacent_numbers == [544]
```
{% endraw %}

Here are some fixes:

{% raw %}
```
			while x_diff != len(helper_string) and helper_string[x_diff] in numbers: # Check if the number continues.
				#x_diff += 1
				print("[neig[0] + x_diff, neig[1]] == "+str([neig[0] + x_diff, neig[1]]))
				print("input_matrix[neig[1]][num_min_x + x_diff] == "+str(input_matrix[neig[1]][num_min_x + x_diff]))
				already_checked.append([num_min_x + x_diff, neig[1]])
				x_diff += 1
```
{% endraw %}

Now the result is a bit closer to the actual which we want.

I actually made this comparison script, which compares all of the numbers which were matched and here is the current output:

{% raw %}
```
202 is not in our numbers.
235 is not in our numbers.
239 is not in our numbers.
321 is not in our numbers.
322 is not in our numbers.
436 is not in our numbers.
441 is not in our numbers.
833 is not in our numbers.
850 is not in our numbers.
858 is not in our numbers.
868 is not in our numbers.
```
{% endraw %}

ok, so let's look at where those numbers occur in the input.

...

After a bit of debugging I managed to minify an input.

Here:

{% raw %}
```
...................
....413.....42.....
104*....461*....240
...................
```
{% endraw %}

This input produces different answers. Let's look at the debug output, when running with our code..

Here is the debug output:

{% raw %}
```
(0, 0)
(1, 0)
(2, 0)
(3, 0)
(4, 0)
(5, 0)
(6, 0)
(7, 0)
(8, 0)
(9, 0)
(10, 0)
(11, 0)
(12, 0)
(13, 0)
(14, 0)
(15, 0)
(16, 0)
(17, 0)
(18, 0)
(0, 1)
(1, 1)
(2, 1)
(3, 1)
(4, 1)
(5, 1)
(6, 1)
(7, 1)
(8, 1)
(9, 1)
(10, 1)
(11, 1)
(12, 1)
(13, 1)
(14, 1)
(15, 1)
(16, 1)
(17, 1)
(18, 1)
(0, 2)
(1, 2)
(2, 2)
(3, 2)
====================
Called check_neighbours_nums
already_checked: []
neig: [3, 1]
already_checked: []
neig: [3, 3]
already_checked: []
neig: [4, 2]
already_checked: []
neig: [2, 2]
poopoo already_checked == [[1, 2], [0, 2], [-1, 2], [-2, 2], [-3, 2], [-4, 2]]
helper_string == 240
helper_string[x_diff] == 2
[neig[0] + x_diff, neig[1]] == [2, 2]
input_matrix[neig[1]][num_min_x + x_diff] == 2
[neig[0] + x_diff, neig[1]] == [3, 2]
input_matrix[neig[1]][num_min_x + x_diff] == 4
[neig[0] + x_diff, neig[1]] == [4, 2]
input_matrix[neig[1]][num_min_x + x_diff] == 0
Final num: 240
already_checked: [[1, 2], [0, 2], [-1, 2], [-2, 2], [-3, 2], [-4, 2], [-3, 2], [-2, 2], [-1, 2]]
neig: [2, 1]
already_checked: [[1, 2], [0, 2], [-1, 2], [-2, 2], [-3, 2], [-4, 2], [-3, 2], [-2, 2], [-1, 2]]
neig: [2, 3]
already_checked: [[1, 2], [0, 2], [-1, 2], [-2, 2], [-3, 2], [-4, 2], [-3, 2], [-2, 2], [-1, 2]]
neig: [4, 3]
already_checked: [[1, 2], [0, 2], [-1, 2], [-2, 2], [-3, 2], [-4, 2], [-3, 2], [-2, 2], [-1, 2]]
neig: [4, 1]
poopoo already_checked == [[1, 2], [0, 2], [-1, 2], [-2, 2], [-3, 2], [-4, 2], [-3, 2], [-2, 2], [-1, 2], [3, 1]]
helper_string == 413.....42.....
helper_string[x_diff] == 4
[neig[0] + x_diff, neig[1]] == [4, 1]
input_matrix[neig[1]][num_min_x + x_diff] == 4
[neig[0] + x_diff, neig[1]] == [5, 1]
input_matrix[neig[1]][num_min_x + x_diff] == 1
[neig[0] + x_diff, neig[1]] == [6, 1]
input_matrix[neig[1]][num_min_x + x_diff] == 3
Final num: 413
adjacent_numbers == [240, 413]
(4, 2)
(5, 2)
(6, 2)
(7, 2)
(8, 2)
(9, 2)
(10, 2)
(11, 2)
====================
Called check_neighbours_nums
already_checked: []
neig: [11, 1]
already_checked: []
neig: [11, 3]
already_checked: []
neig: [12, 2]
already_checked: []
neig: [10, 2]
poopoo already_checked == [[9, 2], [8, 2], [7, 2]]
helper_string == 461*....240
helper_string[x_diff] == 4
[neig[0] + x_diff, neig[1]] == [10, 2]
input_matrix[neig[1]][num_min_x + x_diff] == 4
[neig[0] + x_diff, neig[1]] == [11, 2]
input_matrix[neig[1]][num_min_x + x_diff] == 6
[neig[0] + x_diff, neig[1]] == [12, 2]
input_matrix[neig[1]][num_min_x + x_diff] == 1
Final num: 461
already_checked: [[9, 2], [8, 2], [7, 2], [8, 2], [9, 2], [10, 2]]
neig: [10, 1]
already_checked: [[9, 2], [8, 2], [7, 2], [8, 2], [9, 2], [10, 2]]
neig: [10, 3]
already_checked: [[9, 2], [8, 2], [7, 2], [8, 2], [9, 2], [10, 2]]
neig: [12, 3]
already_checked: [[9, 2], [8, 2], [7, 2], [8, 2], [9, 2], [10, 2]]
neig: [12, 1]
poopoo already_checked == [[9, 2], [8, 2], [7, 2], [8, 2], [9, 2], [10, 2], [11, 1]]
helper_string == 42.....
helper_string[x_diff] == 4
[neig[0] + x_diff, neig[1]] == [12, 1]
input_matrix[neig[1]][num_min_x + x_diff] == 4
[neig[0] + x_diff, neig[1]] == [13, 1]
input_matrix[neig[1]][num_min_x + x_diff] == 2
Final num: 42
adjacent_numbers == [461, 42]
(12, 2)
(13, 2)
(14, 2)
(15, 2)
(16, 2)
(17, 2)
(18, 2)
(0, 3)
(1, 3)
(2, 3)
(3, 3)
(4, 3)
(5, 3)
(6, 3)
(7, 3)
(8, 3)
(9, 3)
(10, 3)
(11, 3)
(12, 3)
(13, 3)
(14, 3)
(15, 3)
(16, 3)
(17, 3)
(18, 3)
solution: 118482
all_nums == {240, 461, 42, 413}
531 in all_nums: False

```
{% endraw %}

The most important part is this:

{% raw %}
```

poopoo already_checked == [[1, 2], [0, 2], [-1, 2], [-2, 2], [-3, 2], [-4, 2]]
helper_string == 240
helper_string[x_diff] == 2
[neig[0] + x_diff, neig[1]] == [2, 2]
input_matrix[neig[1]][num_min_x + x_diff] == 2
[neig[0] + x_diff, neig[1]] == [3, 2]
input_matrix[neig[1]][num_min_x + x_diff] == 4
[neig[0] + x_diff, neig[1]] == [4, 2]
input_matrix[neig[1]][num_min_x + x_diff] == 0
Final num: 240
already_checked: [[1, 2], [0, 2], [-1, 2], [-2, 2], [-3, 2], [-4, 2], [-3, 2], [-2, 2], [-1, 2]]
neig: [2, 1]
already_checked: [[1, 2], [0, 2], [-1, 2], [-2, 2], [-3, 2], [-4, 2], [-3, 2], [-2, 2], [-1, 2]]
neig: [2, 3]
already_checked: [[1, 2], [0, 2], [-1, 2], [-2, 2], [-3, 2], [-4, 2], [-3, 2], [-2, 2], [-1, 2]]
neig: [4, 3]
already_checked: [[1, 2], [0, 2], [-1, 2], [-2, 2], [-3, 2], [-4, 2], [-3, 2], [-2, 2], [-1, 2]]
neig: [4, 1]
poopoo already_checked == [[1, 2], [0, 2], [-1, 2], [-2, 2], [-3, 2], [-4, 2], [-3, 2], [-2, 2], [-1, 2], [3, 1]]
helper_string == 413.....42.....
helper_string[x_diff] == 4
[neig[0] + x_diff, neig[1]] == [4, 1]
input_matrix[neig[1]][num_min_x + x_diff] == 4
[neig[0] + x_diff, neig[1]] == [5, 1]
input_matrix[neig[1]][num_min_x + x_diff] == 1
[neig[0] + x_diff, neig[1]] == [6, 1]
input_matrix[neig[1]][num_min_x + x_diff] == 3
Final num: 413
adjacent_numbers == [240, 413]

```
{% endraw %}

So that's the reason my code didn't work. We go into the negative numbers when parsing the numbers. After adding a check such that we do not go into the negative numbers, now our code works!

## Making it faster.

(This was written on 5.12.2023)

I will probably return to this and make this faster, but for now I am going to go forward to the next day.























