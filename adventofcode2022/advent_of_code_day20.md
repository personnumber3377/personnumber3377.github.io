
# Day 20

https://adventofcode.com/2022/day/20

This is quite a fun challenge with modular arithmetic.

Here is the skeleton for this puzzle:

{% raw %}
```

import sys

def parse_input() -> list:
	return [int(x) for x in sys.stdin.read().split("\n")]

def solve_puzzle(puzzle_input: list) -> int:

	print("puzzle_input == "+str(puzzle_input))

	return 0
	

def main() -> int:
	puzzle_input = parse_input()
	result = solve_puzzle(puzzle_input)
	print("Solution: "+str(result))
	return 0

if __name__=="__main__":

	exit(main())

```
{% endraw %}

I am going to program a helper function called `swap` which as the name suggests swaps two elements in a list by index.

{% raw %}
```


def swap(in_list:list, ind_a: int, ind_b: int) -> None:
	a,b = in_list[ind_a], in_list[ind_b]
	in_list[ind_a], in_list[ind_b] = b, a
	return

```
{% endraw %}

The tricky part of this is that we need to move the numbers in the order they originally appeared, that is that the mixing of the numbers do not affect the order in which we mix them around. Looking at the input and it looks like all of the numbers only occur once in the input, so that way we can just get the index of it, but it is still quite slow I think.

Again, I have misunderstood the prompt. It does not swap the numbers, it places the number in that location. Here is the place location:

{% raw %}
```

def place(in_list: list, ind_a: int, ind_b: int) -> None:
	#elem = in_list.pop(ind_a)
	elem = in_list[ind_a]
	# if the index where we put the element is larger than ind_a, then the index where we want to put this element is decremented by one, because the elements shifted one to the left during the pop.
	#print("elem == "+str(elem))
	print("list before: "+str(in_list))
	print("ind_a == "+str(ind_a))
	print("ind_b == "+str(ind_b))
	'''
	if ind_a < ind_b:

		in_list.insert(ind_b, elem)

	else:

		# if the index is less, then just do it the typical way.

		in_list.insert(ind_b, elem)
	'''

	if ind_b == 0:
		ind_b = len(in_list)-1
	print("in_list[:ind_b+1] == "+str(in_list[:ind_b+1]))
	print("in_list[ind_b+1:] == "+str(in_list[ind_b+1:]))
	print("elem == "+str(elem))
	in_list = in_list[:ind_b+1]+[elem]+in_list[ind_b+1:]

	if ind_b > ind_a:
		# The index where we placed the element is larger than the place where we took it from so we can safely remove the original index
		assert in_list[ind_a] == elem
		print("in_list 3333 == "+str(in_list))
		print("ind_a == "+str(ind_a))
		in_list.pop(ind_a)
	else:
		assert in_list[ind_a+1] == elem
		in_list.pop(ind_a+1)

	print("list after: "+str(in_list))

	return in_list


```
{% endraw %}

As usual I had a bit of trouble to make it work, but I managed to do it in the end. Here is the code:

{% raw %}
```


import sys
import copy
'''
def swap(in_list:list, ind_a: int, ind_b: int) -> None:
	a,b = in_list[ind_a], in_list[ind_b]
	in_list[ind_a], in_list[ind_b] = b, a
	return
'''
def place(in_list: list, ind_a: int, ind_b: int) -> None:
	#elem = in_list.pop(ind_a)
	elem = in_list[ind_a]
	# if the index where we put the element is larger than ind_a, then the index where we want to put this element is decremented by one, because the elements shifted one to the left during the pop.
	#print("elem == "+str(elem))
	print("list before: "+str(in_list))
	print("ind_a == "+str(ind_a))
	print("ind_b == "+str(ind_b))
	'''
	if ind_a < ind_b:

		in_list.insert(ind_b, elem)

	else:

		# if the index is less, then just do it the typical way.

		in_list.insert(ind_b, elem)
	'''

	if ind_b == 0:
		ind_b = len(in_list)-1
	print("in_list[:ind_b+1] == "+str(in_list[:ind_b+1]))
	print("in_list[ind_b+1:] == "+str(in_list[ind_b+1:]))
	print("elem == "+str(elem))
	in_list = in_list[:ind_b+1]+[elem]+in_list[ind_b+1:]

	if ind_b > ind_a:
		# The index where we placed the element is larger than the place where we took it from so we can safely remove the original index
		assert in_list[ind_a] == elem
		print("in_list 3333 == "+str(in_list))
		print("ind_a == "+str(ind_a))
		in_list.pop(ind_a)
	else:
		assert in_list[ind_a+1] == elem
		in_list.pop(ind_a+1)

	print("list after: "+str(in_list))

	return in_list



def parse_input() -> list:
	return [int(x) for x in sys.stdin.read().split("\n")]

def solve_puzzle(puzzle_input: list) -> int:



	print("puzzle_input == "+str(puzzle_input))

	if len(puzzle_input) == len(set(puzzle_input)):
		print("The numbers only appear once!!!")

	orig_numbers = copy.deepcopy(puzzle_input)
	numbers = puzzle_input
	length = len(orig_numbers)
	for i, num in enumerate(orig_numbers):

		if numbers[i] != num:
			a_index = numbers.index(num)
		else:
			a_index = i # assume that the element is not moved.

		b_index = (a_index + num) % (length - 1)

		# swap

		numbers = place(numbers, a_index, b_index)



		print("The numbers array after mixing: "+str(numbers))

	return 0
	

def main() -> int:
	puzzle_input = parse_input()
	result = solve_puzzle(puzzle_input)
	print("Solution: "+str(result))
	return 0

if __name__=="__main__":

	exit(main())


```
{% endraw %}

## Bug

The bug occurs, because of the wraparound, because the last element is also the first elements, because it wraps around. Now, we need to check if we wrap around (I think).

Now I have been stuck on this problem for hours and I still haven't found a solution to this. We need to implement a circular array to be able to solve this problem. aand the solution I think is this:

I think we need to actually take the modulo of the length of the list - 1 because the last element is also the first element. This should make our problem disappear. Ok so it kinda worked, but then we also need to check that if the destination index is zero, then we need to actually put it at the very end.

...

Now I have been at this for a couple of hours and I wrote a program which compares the output of the correct program to our program and here is the results:

{% raw %}
```

==================================================
FAIL!
correct output: [2, 1, 0]
our output: [1, 0, 2]
input_list: [1, 2, 0]
==================================================


```
{% endraw %}

I fixed one thing and added more messages:

{% raw %}
```

The numbers only appear once!!!
Here are the numbers before mixing: [1, 0, 3, 2]
ind_a == 0
ind_b == 1
Here are the numbers after mixing: [0, 1, 3, 2]
Here are the numbers before mixing: [0, 1, 3, 2]
ind_a == 0
ind_b == 0
Here are the numbers after mixing: [0, 1, 3, 2]

Here are the numbers before mixing: [0, 1, 3, 2]
ind_a == 2
ind_b == 5
Here are the numbers after mixing: [0, 1, 3, 2]


Here are the numbers before mixing: [0, 1, 3, 2]
ind_a == 3
ind_b == 5
Here are the numbers after mixing: [1, 3, 0, 2]



result == 0
==================================================
FAIL!
correct output: [3, 0, 1, 2]
our output: [1, 3, 0, 2]
input_list: [1, 0, 3, 2]
==================================================


```
{% endraw %}

After doing some stuff now i get this:

{% raw %}
```


Here are the numbers before mixing: [1, 3, 0, 2]
ind_a == 0
ind_b == 1
Here are the numbers after mixing: [3, 1, 0, 2]
Here are the numbers before mixing: [3, 1, 0, 2]
ind_a == 0
ind_b == 3
Here are the numbers after mixing: [3, 1, 0, 2]
Here are the numbers before mixing: [3, 1, 0, 2]
ind_a == 2
ind_b == 2
Here are the numbers after mixing: [3, 1, 0, 2]
Here are the numbers before mixing: [3, 1, 0, 2]
ind_a == 3
ind_b == 5
Here are the numbers after mixing: [3, 1, 2, 0]
result == 0
==================================================
FAIL!
correct output: [0, 3, 1, 2]
our output: [3, 1, 2, 0]
input_list: [1, 3, 0, 2]
==================================================




```
{% endraw %}

Ok, so after a bit of fiddling around I realized that there are duplicate numbers in the input. 🤦 Now this is the reason why our code sucks. So instead let's make the numbers array actually a list of tuples where the first element is the original index and the second index is the value.

Here is our new input parsing function:

{% raw %}
```

def parse_input() -> list:
	return [(i, int(x)) for i, x in enumerate(sys.stdin.read().split("\n"))]

```
{% endraw %}

The after searching the numbers list for the correct index, instead of the correct value:

{% raw %}
```
# snip

	orig_numbers = copy.deepcopy(puzzle_input)
	numbers = puzzle_input

	for i, ind_num_pair in enumerate(orig_numbers):

		wanted_index = i

		a_index = [x[0] for x in numbers].index(wanted_index) # get the numbers index

		num = numbers[a_index][1] # the actual value
		#if numbers[i] != num:

		#a_index = numbers.index(num)

		#else:
		#	a_index = i # assume that the element is not moved.

		b_index = a_index + num
# snip
```
{% endraw %}

Now our code works correctly.

# Part 2

One curiousity of this is that I think I should test if the "mixing" of the list ten times is the same as mixing the list one time,but the movements are multiplied by ten. I assume not, but it is worth a shot I think.

I think that is not the case, so just do a for loop?

Fuck! Our code does not work.

{% raw %}
```


import sys
import copy
import pickle

TEST = True

COUNTER = 0

DEC_KEY = 811589153




'''
shit = """
2, 1, -3, 3, -2, 0, 4
1, -3, 2, 3, -2, 0, 4
1, 2, 3, -2, -3, 0, 4
1, 2, -2, -3, 0, 3, 4
1, 2, -3, 0, 3, 4, -2
1, 2, -3, 0, 3, 4, -2
1, 2, -3, 4, 0, 3, -2
"""
'''

shit = '''
811589153, 1623178306, -2434767459, 2434767459, -1623178306, 0, 3246356612
0, -2434767459, 3246356612, -1623178306, 2434767459, 1623178306, 811589153
0, 2434767459, 1623178306, 3246356612, -2434767459, -1623178306, 811589153
0, 811589153, 2434767459, 3246356612, 1623178306, -1623178306, -2434767459
0, 1623178306, -2434767459, 811589153, 2434767459, 3246356612, -1623178306
0, 811589153, -1623178306, 1623178306, -2434767459, 3246356612, 2434767459
0, 811589153, -1623178306, 3246356612, -2434767459, 1623178306, 2434767459
0, -2434767459, 2434767459, 1623178306, -1623178306, 811589153, 3246356612
0, 1623178306, 3246356612, 811589153, -2434767459, 2434767459, -1623178306
0, 811589153, 1623178306, -2434767459, 3246356612, 2434767459, -1623178306
'''


out_thing = shit.split("\n")

poopoo = []

for thing in out_thing:
	poopoo.append([int(x) if x != "" else "" for x in thing.split(", ")])

test_out = poopoo
print("fgewgreg")
print(test_out)



'''
def swap(in_list:list, ind_a: int, ind_b: int) -> None:
	a,b = in_list[ind_a], in_list[ind_b]
	in_list[ind_a], in_list[ind_b] = b, a
	return
'''
def place(in_list: list, ind_a: int, ind_b) -> None: # numbers = place(numbers, a_index, b_index, quotient, num)
	global COUNTER
	global test_out
	# This is here to take care of the loop-around.
	#if in_list[ind_a] == 0:
	#	return in_list
	#print("in_list before: "+str([x[1] for x in in_list]))
	#print("ind_a before == "+str(ind_a))
	#print("ind_b before == "+str(ind_b))
	ind_a = ind_a % (len(in_list) - 1)
	
	#elif ind_b == len(in_list) - 1:
	#	ind_b = 0

	element = in_list.pop(ind_a) # get the element

	ind_b = ind_b % (len(in_list))
	if ind_b == 0:
		ind_b = len(in_list)
	#if ind_b == len(in_list) - 1:
	#	ind_b = 0
	#if ind_b > ind_a: # if the target index is larger than the index where it took it from, then we need to decrement the target index, because the elements shift.
	#	ind_b -= 1

	#if ind_b < 0:
	#	exit(1)
	in_list.insert(ind_b,element)

	#print(str(in_list)[1:-1])
	#print("ind_a == "+str(ind_a))
	#print("ind_b == "+str(ind_b))
	#print("in_list after: "+str([x[1] for x in in_list]))

	#if TEST:
	#	if [x[1] for x in in_list] != test_out[COUNTER+1]:
	#		print("fuck!")
	#		print("test_out[COUNTER] == "+str(", ".join([str(x) for x in test_out[COUNTER+1]])))
	#		print("[x[1] for x in in_list] == "+str([x[1] for x in in_list]))
	#		exit(1)

	COUNTER += 1
	#print("in_list == "+str(in_list))
	return in_list



def parse_input() -> list:
	return [(i, int(x)*DEC_KEY) for i, x in enumerate(sys.stdin.read().split("\n"))]
	#return [(i, int(x)) for i, x in enumerate(sys.stdin.read().split("\n"))]

def get_numbers(numbers: list):
	number_vals = [x[1] for x in numbers]
	assert isinstance(numbers, list)

	index_zero = [x[1] for x in numbers].index(0) # get index of zero
	#print("index_zero == "+str(index_zero))
	res = 0
	for i in range(1,4):
		#print("i == "+str(i))
		#print("numbers[(1000*i) % (len(numbers))] == "+str(numbers[(1000*i+index_zero) % (len(numbers))]))
		print("number_vals[(1000*i+index_zero) % (len(numbers))] == "+str(number_vals[(1000*i+index_zero) % (len(numbers))]))
		res += number_vals[(1000*i+index_zero) % (len(numbers))]
	return res



def mix(puzzle_input: list, orig_numbers: list) -> list:

	# mixes, but does not take the integers.

	if len(puzzle_input) == len(set(puzzle_input)):
		print("The numbers only appear once!!!")
	else:
		print("poop")
		print("len(puzzle_input) == "+str(len(puzzle_input)))
		print("len(set(puzzle_input)) == "+str(len(set(puzzle_input))))
		exit(1)

	#orig_numbers = copy.deepcopy(puzzle_input)
	numbers = puzzle_input

	for i, ind_num_pair in enumerate(orig_numbers):

		wanted_index = i

		a_index = [x[0] for x in numbers].index(wanted_index) # get the numbers index

		num = numbers[a_index][1] # the actual value
		#if numbers[i] != num:

		#a_index = numbers.index(num)

		#else:
		#	a_index = i # assume that the element is not moved.

		b_index = a_index + num

		# swap


		numbers = place(numbers, a_index, b_index)

	return numbers


def solve_puzzle(puzzle_input: list) -> int:



	#print("puzzle_input == "+str(puzzle_input))
	orig_numbers = copy.deepcopy(puzzle_input)
	for i in range(10):
		print([x[1] for x in puzzle_input])
		if TEST:
			print("Testing!")
			if [x[1] for x in puzzle_input] != test_out[i+1]:
				print("Fuck!")
				print("correct: "+str(test_out[i+1]))
				print("our: "+str([x[1] for x in puzzle_input]))
				exit(1)
			else:
				print("Passed!")
				print("correct: "+str(test_out[i+1]))
				print("our: "+str([x[1] for x in puzzle_input]))
		puzzle_input = mix(puzzle_input, orig_numbers)
		


	result = get_numbers(puzzle_input)

	print("result == "+str(result))

	return 0
	

def main() -> int:
	puzzle_input = parse_input()
	result = solve_puzzle(puzzle_input)
	print("Solution: "+str(result))
	return 0

if __name__=="__main__":

	exit(main())


```
{% endraw %}

This is weapons grade bullshit.

After doing *SOME* debugging, I think I found the problem. It is an off-by-one error,because of course it is.

{% raw %}
```


import sys
import copy
import pickle

TEST = True

COUNTER = 0

DEC_KEY = 811589153


'''


shit = """
1, 2, -3, 3, -2, 0, 4
2, 1, -3, 3, -2, 0, 4
1, -3, 2, 3, -2, 0, 4
1, 2, 3, -2, -3, 0, 4
1, 2, -2, -3, 0, 3, 4
1, 2, -3, 0, 3, 4, -2
1, 2, -3, 0, 3, 4, -2
1, 2, -3, 4, 0, 3, -2
"""
'''



shit = '''
811589153, 1623178306, -2434767459, 2434767459, -1623178306, 0, 3246356612
0, -2434767459, 3246356612, -1623178306, 2434767459, 1623178306, 811589153
0, 2434767459, 1623178306, 3246356612, -2434767459, -1623178306, 811589153
0, 811589153, 2434767459, 3246356612, 1623178306, -1623178306, -2434767459
0, 1623178306, -2434767459, 811589153, 2434767459, 3246356612, -1623178306
0, 811589153, -1623178306, 1623178306, -2434767459, 3246356612, 2434767459
0, 811589153, -1623178306, 3246356612, -2434767459, 1623178306, 2434767459
0, -2434767459, 2434767459, 1623178306, -1623178306, 811589153, 3246356612
0, 1623178306, 3246356612, 811589153, -2434767459, 2434767459, -1623178306
0, 811589153, 1623178306, -2434767459, 3246356612, 2434767459, -1623178306
'''


out_thing = shit.split("\n")

poopoo = []

for thing in out_thing:
	poopoo.append([int(x) if x != "" else "" for x in thing.split(", ")])

test_out = poopoo
print("fgewgreg")
print(test_out)



'''
def swap(in_list:list, ind_a: int, ind_b: int) -> None:
	a,b = in_list[ind_a], in_list[ind_b]
	in_list[ind_a], in_list[ind_b] = b, a
	return
'''
def place(in_list: list, ind_a: int, ind_b) -> None: # numbers = place(numbers, a_index, b_index, quotient, num)
	global COUNTER
	global test_out
	# This is here to take care of the loop-around.
	#if in_list[ind_a] == 0:
	#	return in_list
	#print("in_list before: "+str([x[1] for x in in_list]))
	#print("ind_a before == "+str(ind_a))
	#print("ind_b before == "+str(ind_b))
	ind_a = ind_a % (len(in_list))
	
	#elif ind_b == len(in_list) - 1:
	#	ind_b = 0
	print("in_list[ind_a][1] == "+str(in_list[ind_a][1]))
	if in_list[ind_a][1] == 0:

		COUNTER += 1
		print("poop!")
		print("poop in_list[ind_a][1] == "+str(in_list[ind_a][1]))
		return in_list
	#print("in_list[ind_a] == "+str(in_list[ind_a]))
	element = in_list.pop(ind_a) # get the element

	ind_b = ind_b % (len(in_list))
	if ind_b == 0:
		ind_b = len(in_list)

	#if ind_b == len(in_list):
	#	ind_b = 0
	#if ind_b > ind_a: # if the target index is larger than the index where it took it from, then we need to decrement the target index, because the elements shift.
	#	ind_b -= 1

	#if ind_b < 0:
	#	exit(1)
	in_list.insert(ind_b,element)

	#print(str(in_list)[1:-1])
	#print("ind_a == "+str(ind_a))
	#print("ind_b == "+str(ind_b))
	#print("in_list after: "+str([x[1] for x in in_list]))

	#if TEST:
	#	if [x[1] for x in in_list] != test_out[COUNTER+1]:
	#		print("fuck!")
	#		print("test_out[COUNTER] == "+str(", ".join([str(x) for x in test_out[COUNTER+1]])))
	#		print("[x[1] for x in in_list] == "+str([x[1] for x in in_list]))
	#		exit(1)

	COUNTER += 1
	#print("in_list == "+str(in_list))
	print("in_list == "+str([int(x[1]) for x in in_list]))
	return in_list



def parse_input() -> list:
	return [(i, int(x)*DEC_KEY) for i, x in enumerate(sys.stdin.read().split("\n"))]
	#return [(i, int(x)) for i, x in enumerate(sys.stdin.read().split("\n"))]

def get_numbers(numbers: list):
	number_vals = [x[1] for x in numbers]
	assert isinstance(numbers, list)

	index_zero = [x[1] for x in numbers].index(0) # get index of zero
	#print("index_zero == "+str(index_zero))
	res = 0
	for i in range(1,4):
		#print("i == "+str(i))
		#print("numbers[(1000*i) % (len(numbers))] == "+str(numbers[(1000*i+index_zero) % (len(numbers))]))
		print("number_vals[(1000*i+index_zero) % (len(numbers))] == "+str(number_vals[(1000*i+index_zero) % (len(numbers))]))
		res += number_vals[(1000*i+index_zero) % (len(numbers))]
	return res



def mix(puzzle_input: list, orig_numbers: list) -> list:

	# mixes, but does not take the integers.

	if len(puzzle_input) == len(set(puzzle_input)):
		print("The numbers only appear once!!!")
	else:
		print("poop")
		print("len(puzzle_input) == "+str(len(puzzle_input)))
		print("len(set(puzzle_input)) == "+str(len(set(puzzle_input))))
		exit(1)

	#orig_numbers = copy.deepcopy(puzzle_input)
	numbers = puzzle_input

	for i, ind_num_pair in enumerate(orig_numbers):

		wanted_index = i

		a_index = [x[0] for x in numbers].index(wanted_index) # get the numbers index
		print("[x[0] for x in numbers] == "+str([x[0] for x in numbers]))
		print("wanted_index == "+str(wanted_index))
		num = numbers[a_index][1] # the actual value
		print("Mixing number: "+str(num))
		#if numbers[i] != num:

		#a_index = numbers.index(num)

		#else:
		#	a_index = i # assume that the element is not moved.

		b_index = a_index + num

		# swap


		numbers = place(numbers, a_index, b_index)

	return numbers


def solve_puzzle(puzzle_input: list) -> int:



	#print("puzzle_input == "+str(puzzle_input))
	orig_numbers = copy.deepcopy(puzzle_input)
	for i in range(10):
		print([x[1] for x in puzzle_input])
		if TEST:
			print("Testing!")
			if [x[1] for x in puzzle_input] != test_out[i+1]:
				print("Fuck!")
				print("correct: "+str(test_out[i+1]))
				print("our: "+str([x[1] for x in puzzle_input]))
				exit(1)
			else:
				print("Passed!")
				print("correct: "+str(test_out[i+1]))
				print("our: "+str([x[1] for x in puzzle_input]))
		puzzle_input = mix(puzzle_input, orig_numbers)
		


	result = get_numbers(puzzle_input)

	print("result == "+str(result))

	return 0
	

def main() -> int:
	puzzle_input = parse_input()
	result = solve_puzzle(puzzle_input)
	print("Solution: "+str(result))
	return 0

if __name__=="__main__":

	exit(main())


```
{% endraw %}

Here is the fixed code I think.

The only difference is that the `	ind_a = ind_a % (len(in_list) - 1)` got turned into the `	ind_a = ind_a % (len(in_list))` the reason for why this is needed, is that if the very last element is supposed to be moved, then we mistakenly move the very first element instead, this caused erroneous output.

Now we get the correct output!

# Making it faster

Now, even though we have completed the challence, let's try to make it faster just for the fun of it. Something about cprofile blah blah blah...


{% raw %}
```

result == 4275451658004
Solution: 0
         442229 function calls (427198 primitive calls) in 17.084 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
    50000   14.646    0.000   14.646    0.000 part2.py:157(<listcomp>)
    50001    1.537    0.000    1.537    0.000 {method 'index' of 'list' objects}
       10    0.627    0.063   17.033    1.703 part2.py:138(mix)
    50000    0.090    0.000    0.223    0.000 part2.py:63(place)
    49990    0.072    0.000    0.072    0.000 {method 'insert' of 'list' objects}
    49995    0.051    0.000    0.051    0.000 {method 'pop' of 'list' objects}
  15001/1    0.019    0.000    0.042    0.042 copy.py:118(deepcopy)
     5000    0.011    0.000    0.031    0.000 copy.py:200(_deepcopy_tuple)
100091/100089    0.010    0.000    0.010    0.000 {built-in method builtins.len}
     5000    0.004    0.000    0.019    0.000 copy.py:201(<listcomp>)
        1    0.003    0.003    0.003    0.003 part2.py:119(<listcomp>)
    30018    0.003    0.000    0.003    0.000 {method 'get' of 'dict' objects}
        1    0.002    0.002    0.042    0.042 copy.py:191(_deepcopy_list)
    20004    0.002    0.000    0.002    0.000 {built-in method builtins.id}
    10000    0.001    0.000    0.001    0.000 copy.py:172(_deepcopy_atomic)
        3    0.000    0.000    0.000    0.000 {built-in method marshal.loads}
     5065    0.000    0.000    0.000    0.000 {method 'append' of 'list' objects}
        1    0.000    0.000    0.000    0.000 part2.py:123(<listcomp>)
        1    0.000    0.000    0.000    0.000 part2.py:126(<listcomp>)
        2    0.000    0.000    0.000    0.000 {built-in method _imp.create_dynamic}

```
{% endraw %}

So we spend a lot of time in list comprehensions and accessing lists by index. This is obvious, because when we pop and insert an element into a list, it takes a lot of time to move the elements.

This singular line takes up most of the time:

{% raw %}
```

		a_index = [x[0] for x in numbers].index(wanted_index) # get the numbers index

```
{% endraw %}

So I think the obvious optimization is to just separate the numbers and the indexes alltogether, such that we do not need to do such bullshit.

Now currently my code looks like this:

{% raw %}
```


import sys
import copy
import pickle

TEST = False

COUNTER = 0

DEC_KEY = 811589153


'''


shit = """
1, 2, -3, 3, -2, 0, 4
2, 1, -3, 3, -2, 0, 4
1, -3, 2, 3, -2, 0, 4
1, 2, 3, -2, -3, 0, 4
1, 2, -2, -3, 0, 3, 4
1, 2, -3, 0, 3, 4, -2
1, 2, -3, 0, 3, 4, -2
1, 2, -3, 4, 0, 3, -2
"""
'''



shit = '''
811589153, 1623178306, -2434767459, 2434767459, -1623178306, 0, 3246356612
0, -2434767459, 3246356612, -1623178306, 2434767459, 1623178306, 811589153
0, 2434767459, 1623178306, 3246356612, -2434767459, -1623178306, 811589153
0, 811589153, 2434767459, 3246356612, 1623178306, -1623178306, -2434767459
0, 1623178306, -2434767459, 811589153, 2434767459, 3246356612, -1623178306
0, 811589153, -1623178306, 1623178306, -2434767459, 3246356612, 2434767459
0, 811589153, -1623178306, 3246356612, -2434767459, 1623178306, 2434767459
0, -2434767459, 2434767459, 1623178306, -1623178306, 811589153, 3246356612
0, 1623178306, 3246356612, 811589153, -2434767459, 2434767459, -1623178306
0, 811589153, 1623178306, -2434767459, 3246356612, 2434767459, -1623178306
'''


out_thing = shit.split("\n")

poopoo = []

for thing in out_thing:
	poopoo.append([int(x) if x != "" else "" for x in thing.split(", ")])

test_out = poopoo
print("fgewgreg")
print(test_out)



'''
def swap(in_list:list, ind_a: int, ind_b: int) -> None:
	a,b = in_list[ind_a], in_list[ind_b]
	in_list[ind_a], in_list[ind_b] = b, a
	return
'''
def place(in_list: list, ind_a: int, ind_b) -> None: # numbers = place(numbers, a_index, b_index, quotient, num)
	global COUNTER
	global test_out
	# This is here to take care of the loop-around.
	#if in_list[ind_a] == 0:
	#	return in_list
	#print("in_list before: "+str([x[1] for x in in_list]))
	#print("ind_a before == "+str(ind_a))
	#print("ind_b before == "+str(ind_b))
	ind_a = ind_a % (len(in_list))
	
	#elif ind_b == len(in_list) - 1:
	#	ind_b = 0
	#print("in_list[ind_a][1] == "+str(in_list[ind_a][1]))
	if in_list[ind_a] == 0:

		COUNTER += 1
		#print("poop!")
		#print("poop in_list[ind_a][1] == "+str(in_list[ind_a][1]))
		return in_list
	#print("in_list[ind_a] == "+str(in_list[ind_a]))
	element = in_list.pop(ind_a) # get the element

	ind_b = ind_b % (len(in_list))
	if ind_b == 0:
		ind_b = len(in_list)

	#if ind_b == len(in_list):
	#	ind_b = 0
	#if ind_b > ind_a: # if the target index is larger than the index where it took it from, then we need to decrement the target index, because the elements shift.
	#	ind_b -= 1

	#if ind_b < 0:
	#	exit(1)
	in_list.insert(ind_b,element)

	#print(str(in_list)[1:-1])
	#print("ind_a == "+str(ind_a))
	#print("ind_b == "+str(ind_b))
	#print("in_list after: "+str([x[1] for x in in_list]))

	#if TEST:
	#	if [x[1] for x in in_list] != test_out[COUNTER+1]:
	#		print("fuck!")
	#		print("test_out[COUNTER] == "+str(", ".join([str(x) for x in test_out[COUNTER+1]])))
	#		print("[x[1] for x in in_list] == "+str([x[1] for x in in_list]))
	#		exit(1)

	COUNTER += 1
	#print("in_list == "+str(in_list))
	#print("in_list == "+str([int(x[1]) for x in in_list]))
	return in_list



def parse_input() -> list:
	return [(i, int(x)*DEC_KEY) for i, x in enumerate(sys.stdin.read().split("\n"))]
	#return [(i, int(x)) for i, x in enumerate(sys.stdin.read().split("\n"))]

def get_numbers(numbers: list):
	number_vals = [x[1] for x in numbers]
	assert isinstance(numbers, list)

	index_zero = [x[1] for x in numbers].index(0) # get index of zero
	#print("index_zero == "+str(index_zero))
	res = 0
	for i in range(1,4):
		#print("i == "+str(i))
		#print("numbers[(1000*i) % (len(numbers))] == "+str(numbers[(1000*i+index_zero) % (len(numbers))]))
		print("number_vals[(1000*i+index_zero) % (len(numbers))] == "+str(number_vals[(1000*i+index_zero) % (len(numbers))]))
		res += number_vals[(1000*i+index_zero) % (len(numbers))]
	return res



def mix(puzzle_input: list, orig_numbers: list) -> list:

	# mixes, but does not take the integers.

	#if len(puzzle_input) == len(set(puzzle_input)):
	#	#print("The numbers only appear once!!!")
	#else:
	#	print("poop")
	#	print("len(puzzle_input) == "+str(len(puzzle_input)))
	#	print("len(set(puzzle_input)) == "+str(len(set(puzzle_input))))
	#	exit(1)

	#orig_numbers = copy.deepcopy(puzzle_input)
	orig_numbers = copy.deepcopy(puzzle_input)
	numbers = puzzle_input


	nums = [numbers[i][1] for i in range(len(numbers))]

	indexes = [x[0] for x in numbers]
	#print("1 in indexes == "+str(1 in indexes))

	for i, ind_num_pair in enumerate(orig_numbers):

		wanted_index = i
		print("tag == "+str(wanted_index))


		a_index = indexes.index(wanted_index) # get the numbers index

		#num = numbers[a_index][1] # the actual value
		num = nums[i]
		#print("indexes == "+str(indexes))
		#print("nums == "+str(nums))
		print("n == "+str(num))
		#if numbers[i] != num:

		#a_index = numbers.index(num)

		#else:
		#	a_index = i # assume that the element is not moved.

		b_index = a_index + num

		# swap


		#numbers = place(numbers, a_index, b_index)
		indexes = place(indexes, a_index, b_index)
		# swap

		#print("Checking!")

		list_thing = [nums[x] for x in indexes]
		#print("list_thing == "+str(list_thing))

		#numbers = place(numbers, a_index, b_index)

	return numbers


def solve_puzzle(puzzle_input: list) -> int:



	#print("puzzle_input == "+str(puzzle_input))
	orig_numbers = copy.deepcopy(puzzle_input)
	for i in range(10):
		#print([x[1] for x in puzzle_input])
		if TEST:
			print("Testing!")
			if [x[1] for x in puzzle_input] != test_out[i+1]:
				print("Fuck!")
				print("correct: "+str(test_out[i+1]))
				print("our: "+str([x[1] for x in puzzle_input]))
				exit(1)
			else:
				print("Passed!")
				print("correct: "+str(test_out[i+1]))
				print("our: "+str([x[1] for x in puzzle_input]))
		puzzle_input = mix(puzzle_input, orig_numbers)
		

	print()
	result = get_numbers(puzzle_input)

	print("result == "+str(result))

	return 0
	

def main() -> int:
	puzzle_input = parse_input()
	result = solve_puzzle(puzzle_input)
	print("Solution: "+str(result))
	return 0

if __name__=="__main__":

	exit(main())




```
{% endraw %}

Now it has some quite obvious bugs, because we are returning the numbers, not the indexes.


Now after some fiddling around I came up with this:

{% raw %}
```


import sys
import copy
import pickle

TEST = True

COUNTER = 0

DEC_KEY = 811589153


'''


shit = """
1, 2, -3, 3, -2, 0, 4
2, 1, -3, 3, -2, 0, 4
1, -3, 2, 3, -2, 0, 4
1, 2, 3, -2, -3, 0, 4
1, 2, -2, -3, 0, 3, 4
1, 2, -3, 0, 3, 4, -2
1, 2, -3, 0, 3, 4, -2
1, 2, -3, 4, 0, 3, -2
"""
'''



shit = '''
811589153, 1623178306, -2434767459, 2434767459, -1623178306, 0, 3246356612
0, -2434767459, 3246356612, -1623178306, 2434767459, 1623178306, 811589153
0, 2434767459, 1623178306, 3246356612, -2434767459, -1623178306, 811589153
0, 811589153, 2434767459, 3246356612, 1623178306, -1623178306, -2434767459
0, 1623178306, -2434767459, 811589153, 2434767459, 3246356612, -1623178306
0, 811589153, -1623178306, 1623178306, -2434767459, 3246356612, 2434767459
0, 811589153, -1623178306, 3246356612, -2434767459, 1623178306, 2434767459
0, -2434767459, 2434767459, 1623178306, -1623178306, 811589153, 3246356612
0, 1623178306, 3246356612, 811589153, -2434767459, 2434767459, -1623178306
0, 811589153, 1623178306, -2434767459, 3246356612, 2434767459, -1623178306
'''


out_thing = shit.split("\n")

poopoo = []

for thing in out_thing:
	poopoo.append([int(x) if x != "" else "" for x in thing.split(", ")])

test_out = poopoo
print("fgewgreg")
print(test_out)



'''
def swap(in_list:list, ind_a: int, ind_b: int) -> None:
	a,b = in_list[ind_a], in_list[ind_b]
	in_list[ind_a], in_list[ind_b] = b, a
	return
'''
def place(in_list: list, ind_a: int, ind_b) -> None: # numbers = place(numbers, a_index, b_index, quotient, num)
	global COUNTER
	global test_out
	# This is here to take care of the loop-around.
	#if in_list[ind_a] == 0:
	#	return in_list
	#print("in_list before: "+str([x[1] for x in in_list]))
	#print("ind_a before == "+str(ind_a))
	#print("ind_b before == "+str(ind_b))
	ind_a = ind_a % (len(in_list))
	
	#elif ind_b == len(in_list) - 1:
	#	ind_b = 0
	#print("in_list[ind_a][1] == "+str(in_list[ind_a][1]))
	if in_list[ind_a] == 0:

		COUNTER += 1
		#print("poop!")
		#print("poop in_list[ind_a][1] == "+str(in_list[ind_a][1]))
		return in_list
	#print("in_list[ind_a] == "+str(in_list[ind_a]))
	element = in_list.pop(ind_a) # get the element

	ind_b = ind_b % (len(in_list))
	if ind_b == 0:
		ind_b = len(in_list)
	print("b_index == "+str(ind_b))

	#if ind_b == len(in_list):
	#	ind_b = 0
	#if ind_b > ind_a: # if the target index is larger than the index where it took it from, then we need to decrement the target index, because the elements shift.
	#	ind_b -= 1

	#if ind_b < 0:
	#	exit(1)
	in_list.insert(ind_b,element)

	#print(str(in_list)[1:-1])
	#print("ind_a == "+str(ind_a))
	#print("ind_b == "+str(ind_b))
	#print("in_list after: "+str([x[1] for x in in_list]))

	#if TEST:
	#	if [x[1] for x in in_list] != test_out[COUNTER+1]:
	#		print("fuck!")
	#		print("test_out[COUNTER] == "+str(", ".join([str(x) for x in test_out[COUNTER+1]])))
	#		print("[x[1] for x in in_list] == "+str([x[1] for x in in_list]))
	#		exit(1)

	COUNTER += 1
	#print("in_list == "+str(in_list))
	#print("in_list == "+str([int(x[1]) for x in in_list]))
	return in_list



def parse_input() -> list:
	return [(i, int(x)*DEC_KEY) for i, x in enumerate(sys.stdin.read().split("\n"))]
	#return [(i, int(x)) for i, x in enumerate(sys.stdin.read().split("\n"))]

def get_numbers(numbers: list):
	#number_vals = [x[1] for x in numbers]
	assert isinstance(numbers, list)

	index_zero = numbers.index(0) # get index of zero
	#print("index_zero == "+str(index_zero))
	res = 0
	for i in range(1,4):
		#print("i == "+str(i))
		#print("numbers[(1000*i) % (len(numbers))] == "+str(numbers[(1000*i+index_zero) % (len(numbers))]))
		print("numbers[(1000*i+index_zero) % (len(numbers))] == "+str(numbers[(1000*i+index_zero) % (len(numbers))]))
		res += numbers[(1000*i+index_zero) % (len(numbers))]
	return res



def mix(indexes: list, orig_numbers: list) -> list:

	# mixes, but does not take the integers.

	#if len(puzzle_input) == len(set(puzzle_input)):
	#	#print("The numbers only appear once!!!")
	#else:
	#	print("poop")
	#	print("len(puzzle_input) == "+str(len(puzzle_input)))
	#	print("len(set(puzzle_input)) == "+str(len(set(puzzle_input))))
	#	exit(1)

	#orig_numbers = copy.deepcopy(puzzle_input)
	#orig_numbers = copy.deepcopy(puzzle_input)
	#numbers = puzzle_input


	#nums = [numbers[i][1] for i in range(len(numbers))]
	nums = orig_numbers

	#indexes = [x[0] for x in numbers]
	
	#print("1 in indexes == "+str(1 in indexes))
	print("indexes == "+str(indexes))
	for i, ind_num_pair in enumerate(orig_numbers):

		wanted_index = i
		print("tag == "+str(wanted_index))


		a_index = indexes.index(wanted_index) # get the numbers index
		num = nums[i]
		print("n == "+str(num))
		print("a_index == "+str(a_index))
		print("indexes == "+str(indexes))
		b_index = a_index + num

		indexes = place(indexes, a_index, b_index)


	return indexes


def solve_puzzle(puzzle_input: list) -> int:



	#print("puzzle_input == "+str(puzzle_input))
	orig_numbers = [x[1] for x in puzzle_input] # copy.deepcopy(puzzle_input)
	indexes = [x[0] for x in puzzle_input]
	for i in range(10):
		#print([x[1] for x in puzzle_input])
		if TEST:
			print("Testing!")
			if [orig_numbers[x] for x in indexes] != test_out[i+1]:
				print("Fuck!")
				print("correct: "+str(test_out[i+1]))
				#print("our: "+str([x[1] for x in puzzle_input]))
				print("our: "+str([orig_numbers[x] for x in indexes]))
				exit(1)

		indexes = mix(indexes, orig_numbers)
		

	#print()
	numbers_list = [orig_numbers[x] for x in indexes]
	print("numbers list final: "+str(numbers_list))
	result = get_numbers(numbers_list)

	print("result == "+str(result))

	return 0
	

def main() -> int:
	puzzle_input = parse_input()
	result = solve_puzzle(puzzle_input)
	print("Solution: "+str(result))
	return 0

if __name__=="__main__":

	exit(main())



```
{% endraw %}

Except that it has a bug. The bug is that 

{% raw %}
```
	if in_list[ind_a] == 0:
```
{% endraw %}

we are now checking if the index is zero, not the actual value, because previously this check was:

{% raw %}
```
	if in_list[ind_a][1] == 0:
```
{% endraw %}

which compares the number, so we actually need to pass in the number instead.

When we pass the num parameter to the place function:

{% raw %}
```

import sys
import copy
import pickle

TEST = True

COUNTER = 0

DEC_KEY = 811589153


'''


shit = """
1, 2, -3, 3, -2, 0, 4
2, 1, -3, 3, -2, 0, 4
1, -3, 2, 3, -2, 0, 4
1, 2, 3, -2, -3, 0, 4
1, 2, -2, -3, 0, 3, 4
1, 2, -3, 0, 3, 4, -2
1, 2, -3, 0, 3, 4, -2
1, 2, -3, 4, 0, 3, -2
"""
'''



shit = '''
811589153, 1623178306, -2434767459, 2434767459, -1623178306, 0, 3246356612
0, -2434767459, 3246356612, -1623178306, 2434767459, 1623178306, 811589153
0, 2434767459, 1623178306, 3246356612, -2434767459, -1623178306, 811589153
0, 811589153, 2434767459, 3246356612, 1623178306, -1623178306, -2434767459
0, 1623178306, -2434767459, 811589153, 2434767459, 3246356612, -1623178306
0, 811589153, -1623178306, 1623178306, -2434767459, 3246356612, 2434767459
0, 811589153, -1623178306, 3246356612, -2434767459, 1623178306, 2434767459
0, -2434767459, 2434767459, 1623178306, -1623178306, 811589153, 3246356612
0, 1623178306, 3246356612, 811589153, -2434767459, 2434767459, -1623178306
0, 811589153, 1623178306, -2434767459, 3246356612, 2434767459, -1623178306
'''


out_thing = shit.split("\n")

poopoo = []

for thing in out_thing:
	poopoo.append([int(x) if x != "" else "" for x in thing.split(", ")])

test_out = poopoo
print("fgewgreg")
print(test_out)



'''
def swap(in_list:list, ind_a: int, ind_b: int) -> None:
	a,b = in_list[ind_a], in_list[ind_b]
	in_list[ind_a], in_list[ind_b] = b, a
	return
'''
def place(in_list: list, ind_a: int, ind_b, num) -> None: # numbers = place(numbers, a_index, b_index, quotient, num)
	global COUNTER
	global test_out
	# This is here to take care of the loop-around.
	#if in_list[ind_a] == 0:
	#	return in_list
	#print("in_list before: "+str([x[1] for x in in_list]))
	#print("ind_a before == "+str(ind_a))
	#print("ind_b before == "+str(ind_b))
	ind_a = ind_a % (len(in_list))
	
	#elif ind_b == len(in_list) - 1:
	#	ind_b = 0
	#print("in_list[ind_a][1] == "+str(in_list[ind_a][1]))
	if num == 0:

		COUNTER += 1
		#print("poop!")
		#print("poop in_list[ind_a][1] == "+str(in_list[ind_a][1]))
		return in_list
	#print("in_list[ind_a] == "+str(in_list[ind_a]))
	element = in_list.pop(ind_a) # get the element

	ind_b = ind_b % (len(in_list))
	if ind_b == 0:
		ind_b = len(in_list)
	print("b_index == "+str(ind_b))

	#if ind_b == len(in_list):
	#	ind_b = 0
	#if ind_b > ind_a: # if the target index is larger than the index where it took it from, then we need to decrement the target index, because the elements shift.
	#	ind_b -= 1

	#if ind_b < 0:
	#	exit(1)
	in_list.insert(ind_b,element)

	#print(str(in_list)[1:-1])
	#print("ind_a == "+str(ind_a))
	#print("ind_b == "+str(ind_b))
	#print("in_list after: "+str([x[1] for x in in_list]))

	#if TEST:
	#	if [x[1] for x in in_list] != test_out[COUNTER+1]:
	#		print("fuck!")
	#		print("test_out[COUNTER] == "+str(", ".join([str(x) for x in test_out[COUNTER+1]])))
	#		print("[x[1] for x in in_list] == "+str([x[1] for x in in_list]))
	#		exit(1)

	COUNTER += 1
	#print("in_list == "+str(in_list))
	#print("in_list == "+str([int(x[1]) for x in in_list]))
	return in_list



def parse_input() -> list:
	return [(i, int(x)*DEC_KEY) for i, x in enumerate(sys.stdin.read().split("\n"))]
	#return [(i, int(x)) for i, x in enumerate(sys.stdin.read().split("\n"))]

def get_numbers(numbers: list):
	#number_vals = [x[1] for x in numbers]
	assert isinstance(numbers, list)

	index_zero = numbers.index(0) # get index of zero
	#print("index_zero == "+str(index_zero))
	res = 0
	for i in range(1,4):
		#print("i == "+str(i))
		#print("numbers[(1000*i) % (len(numbers))] == "+str(numbers[(1000*i+index_zero) % (len(numbers))]))
		print("numbers[(1000*i+index_zero) % (len(numbers))] == "+str(numbers[(1000*i+index_zero) % (len(numbers))]))
		res += numbers[(1000*i+index_zero) % (len(numbers))]
	return res



def mix(indexes: list, orig_numbers: list) -> list:

	# mixes, but does not take the integers.

	#if len(puzzle_input) == len(set(puzzle_input)):
	#	#print("The numbers only appear once!!!")
	#else:
	#	print("poop")
	#	print("len(puzzle_input) == "+str(len(puzzle_input)))
	#	print("len(set(puzzle_input)) == "+str(len(set(puzzle_input))))
	#	exit(1)

	#orig_numbers = copy.deepcopy(puzzle_input)
	#orig_numbers = copy.deepcopy(puzzle_input)
	#numbers = puzzle_input


	#nums = [numbers[i][1] for i in range(len(numbers))]
	nums = orig_numbers

	#indexes = [x[0] for x in numbers]
	
	#print("1 in indexes == "+str(1 in indexes))
	print("indexes == "+str(indexes))
	for i, ind_num_pair in enumerate(orig_numbers):

		wanted_index = i
		print("tag == "+str(wanted_index))


		a_index = indexes.index(wanted_index) # get the numbers index
		num = nums[i]
		print("n == "+str(num))
		print("a_index == "+str(a_index))
		print("indexes == "+str(indexes))
		b_index = a_index + num

		indexes = place(indexes, a_index, b_index, num)


	return indexes


def solve_puzzle(puzzle_input: list) -> int:



	#print("puzzle_input == "+str(puzzle_input))
	orig_numbers = [x[1] for x in puzzle_input] # copy.deepcopy(puzzle_input)
	indexes = [x[0] for x in puzzle_input]
	for i in range(10):
		#print([x[1] for x in puzzle_input])
		if TEST:
			print("Testing!")
			if [orig_numbers[x] for x in indexes] != test_out[i+1]:
				print("Fuck!")
				print("correct: "+str(test_out[i+1]))
				#print("our: "+str([x[1] for x in puzzle_input]))
				print("our: "+str([orig_numbers[x] for x in indexes]))
				exit(1)

		indexes = mix(indexes, orig_numbers)
		

	#print()
	numbers_list = [orig_numbers[x] for x in indexes]
	print("numbers list final: "+str(numbers_list))
	result = get_numbers(numbers_list)

	print("result == "+str(result))

	return 0
	

def main() -> int:
	puzzle_input = parse_input()
	result = solve_puzzle(puzzle_input)
	print("Solution: "+str(result))
	return 0

if __name__=="__main__":

	exit(main())

```
{% endraw %}


It now works. And it is a lot faster !

Now, I am wondering if the zero check is actually useless. I think there is a way to circumvent it but idk.


Now the cprofile output looks like this:

{% raw %}
```

Solution: 4275451658004
         302164 function calls (302133 primitive calls) in 1.767 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
    50001    1.516    0.000    1.516    0.000 {method 'index' of 'list' objects}
    49990    0.072    0.000    0.072    0.000 {method 'insert' of 'list' objects}
    50000    0.069    0.000    0.190    0.000 oofshit.py:63(place)
       10    0.054    0.005    1.759    0.176 oofshit.py:139(mix)
    49995    0.042    0.000    0.042    0.000 {method 'pop' of 'list' objects}
100068/100066    0.008    0.000    0.008    0.000 {built-in method builtins.len}
        1    0.003    0.003    0.003    0.003 oofshit.py:120(<listcomp>)
        3    0.000    0.000    0.000    0.000 {built-in method marshal.loads}
        1    0.000    0.000    0.000    0.000 oofshit.py:204(<listcomp>)
        1    0.000    0.000    0.000    0.000 oofshit.py:188(<listcomp>)
        1    0.000    0.000    0.000    0.000 oofshit.py:187(<listcomp>)
       14    0.000    0.000    0.000    0.000 {method 'split' of 'str' objects}


```
{% endraw %}

So the vast amount of time is in the insert method. I am comparing my performance to this script: (thanks to https://www.reddit.com/r/adventofcode/comments/zqezkn/comment/j10rp2g/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button)

{% raw %}
```
import itertools
lut = {tag: n * 811589153 for tag, n in enumerate(int(l) for l in open("input.txt"))}
tags = list(lut.keys())
for _, (tag, n) in itertools.product(range(10), lut.items()):
    #print("tag == "+str(tag))
    #print("n == "+str(n))
    #print("indexes == "+str(tags))
    tags.pop(idx := tags.index(tag))
    #print("a_index == "+str(idx))
    #print("b_index == "+str((idx + n) % len(tags)))
    tags.insert((idx + n) % len(tags), tag)
nums = [lut[t] for t in tags]
#print("numbers list final: "+str(nums))
print(sum(nums[(nums.index(0) + o) % len(nums)] for o in [1000, 2000, 3000]))

```
{% endraw %}

which does it faster. Here is the output of that:

{% raw %}
```

4275451658004
         205035 function calls in 1.675 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
    50003    1.478    0.000    1.478    0.000 {method 'index' of 'list' objects}
        1    0.077    0.077    1.675    1.675 oof.py:1(<module>)
    50000    0.071    0.000    0.071    0.000 {method 'insert' of 'list' objects}
    50000    0.041    0.000    0.041    0.000 {method 'pop' of 'list' objects}
    50003    0.004    0.000    0.004    0.000 {built-in method builtins.len}
     5001    0.002    0.000    0.002    0.000 oof.py:2(<genexpr>)
        1    0.002    0.002    0.004    0.004 oof.py:2(<dictcomp>)
        1    0.001    0.001    0.001    0.001 oof.py:12(<listcomp>)
        1    0.000    0.000    0.000    0.000 {built-in method builtins.print}
        1    0.000    0.000    0.000    0.000 {built-in method io.open}
        6    0.000    0.000    0.000    0.000 <frozen codecs>:319(decode)
        6    0.000    0.000    0.000    0.000 {built-in method _codecs.utf_8_decode}
        1    0.000    0.000    1.675    1.675 {built-in method builtins.exec}
        1    0.000    0.000    0.000    0.000 {built-in method builtins.sum}
        4    0.000    0.000    0.000    0.000 oof.py:14(<genexpr>)
        1    0.000    0.000    0.000    0.000 <frozen codecs>:309(__init__)
        1    0.000    0.000    0.000    0.000 <frozen codecs>:260(__init__)
        1    0.000    0.000    0.000    0.000 {method 'disable' of '_lsprof.Profiler' objects}
        1    0.000    0.000    0.000    0.000 {method 'keys' of 'dict' objects}
        1    0.000    0.000    0.000    0.000 {method 'items' of 'dict' objects}


```
{% endraw %}

My implementation is still 50-100 ms slower, because of all of the other stuff I have inside my implementation. Anyway, I think this is good enough for my taste. I could remove redundant code and stuff to make it just as fast, but I can't be bothered to.


