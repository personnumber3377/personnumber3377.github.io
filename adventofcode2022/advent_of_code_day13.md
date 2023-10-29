
# Writeup of https://adventofcode.com/2022/day/13


## Part one.

I think that I am allowed to post a writeup since the advent of code event has already ended a long time ago.

The puzzle input is a list of a pair of lists or something like that like this:


```
[1,1,3,1,1]
[1,1,5,1,1]

[[1],[2,3,4]]
[[1],4]

[9]
[[8,7,6]]

[[4,4],4,4]
[[4,4],4,4,4]

[7,7,7,7]
[7,7,7]

[]
[3]

[[[]]]
[[]]

[1,[2,[3,[4,[5,6,7]]]],8,9]
[1,[2,[3,[4,[5,6,0]]]],8,9]


```

The puzzle describes the conditions which need to be met for each of the lists to be in order.

```

If both values are integers, the lower integer should come first. If the left integer is lower than the right integer, the inputs are in the right order. If the left integer is higher than the right integer, the inputs are not in the right order. Otherwise, the inputs are the same integer; continue checking the next part of the input.
If both values are lists, compare the first value of each list, then the second value, and so on. If the left list runs out of items first, the inputs are in the right order. If the right list runs out of items first, the inputs are not in the right order. If the lists are the same length and no comparison makes a decision about the order, continue checking the next part of the input.
If exactly one value is an integer, convert the integer to a list which contains that integer as its only value, then retry the comparison. For example, if comparing [0,0,0] and 2, convert the right value to [2] (a list containing 2); the result is then found by instead comparing [0,0,0] and [2].

```

I am going to quickly make up a naive solution first and then try figuring out some logic which may increase the performance.



I programmed this by simply converting the logic described in english into logical statements.


```
import sys
from colorist import Color
import ast

# Do you want to enable debug mode?

DEBUG = True

def good(string):
	print(f"{Color.GREEN}[+] {string}{Color.OFF}")

def fatal(string, exit_code=1):
	print(f"{Color.RED}[!] {string}{Color.OFF}")
	exit(exit_code)

def info(string):
	print(f"{Color.BLUE}[*] {string}{Color.OFF}")
	

def debug(string):
	if DEBUG:
		print(f"{Color.YELLOW}[?] {string}{Color.OFF}")


def handle_input():

	# sys.stdin.readlines() reads all lines supplied to stdin to a singular string.

	lines = sys.stdin.readlines()

	# sanity check. every third line should be an empty line (aka just a newline)

	assert len(lines) % 3 == 2 # last newline does not exist therefore this is two


	while "\n" in lines:
		lines.remove("\n")

	assert "\n" not in lines # empty lines should not be in lines

	return_list = []

	assert len(lines) % 2 == 0


	for i in range(len(lines)//2):

		new_list = [ast.literal_eval(lines[i*2]), ast.literal_eval(lines[i*2+1])]
		return_list.append(new_list)

	debug("return_list == "+str(return_list))

	return return_list



def in_order(pair):

	# If both values are integers, the lower integer should come first. If the left integer is lower than the right integer, the inputs are in the right order. If the left integer is higher than the right integer, the inputs are not in the right order. Otherwise, the inputs are the same integer; continue checking the next part of the input.
	
	l1 = pair[0]
	l2 = pair[1]

	if isinstance(l1, int) and isinstance(l2, int):
		debug("int, int")
		if l1 < l2: # If the left integer is lower than the right integer, the inputs are in the right order.
			return True
		elif l1 > l2:
			return False
		else:
			return None # continue

	'''
	If both values are lists, compare the first value of each list, then the second value, and so on. If the left list runs out of items first, the inputs are in the right order. If the right list runs out of items first, the inputs are not in the right order. If the lists are the same length and no comparison makes a decision about the order, continue checking the next part of the input.
	'''

	debug("l1 == "+str(l1))
	debug("l2 == "+str(l2))

	if isinstance(l1, list) and isinstance(l2, list):
		debug("list, list")
		if len(l2) < len(l1):
			for i in range(len(l2)):
				result = in_order([l1[i], l2[i]])
				if result != None:
					return result
			return False # automatically out of order. No need to even compare. "If the right list runs out of items first, the inputs are not in the right order."
		
		elif len(l1) < len(l2):
			# "If the left list runs out of items first, the inputs are in the right order."
			for i in range(len(l1)):
				result = in_order([l1[i], l2[i]])
				if result != None:
					return result
			return True

		else:
			# If the lists are the same length and no comparison makes a decision about the order, continue checking the next part of the input.
			for i in range(len(l1)):
				result = in_order([l1[i], l2[i]])
				if result != None:
					return result
			return None

	# If exactly one value is an integer, convert the integer to a list which contains that integer as its only value, then retry the comparison. For example, if comparing [0,0,0] and 2, convert the right value to [2] (a list containing 2); the result is then found by instead comparing [0,0,0] and [2].

	if isinstance(l1, list) and isinstance(l2, int):
		debug("list, int")
		return in_order([l1, [l2]])

	if isinstance(l1, int) and isinstance(l2, list):
		debug("int, list")
		return in_order([[l1], l2])

	fatal("Does not match any case!")

def solve(list_pairs):
	x = 0
	for index, pair in enumerate(list_pairs):
		if in_order(pair):
			debug("Index "+str(index+1)+" is in order.")
			x += index+1
	return x

def solve_puzzle():
	
	list_stuff = handle_input()

	good("Handled input succesfully!")

	answer = solve(list_stuff)

	return answer

if __name__=="__main__":
	#print(solve_puzzle())
	good("Solution to puzzle is: "+str(solve_puzzle())+" !")

	exit(0)


```

This actually works for the supplied input!

One critique of this challenge is that the wording "If the right list runs out of items first, the inputs are not in the right order." is quite bad, because I think it should have been worded better as "If the elements up to now are yet to yield a result and If the right list runs out of items first, the inputs are not in the right order." . You do not simply look at the lengths of the lists. You first compare them and then after reaching the end without a result, then you look at the lengths of the lists.

## Part two.

Ok in this part I slightly cheated, because I could not figure out how to sort a list by a certain function as the "comparison" operator so I looked it up and came upon this: https://github.com/orfeasa/advent-of-code-2022/blob/main/day_13/main.py .

```


from functools import cmp_to_key, reduce



def part_two(filename: str) -> int:
    lines = parse_input(filename)
    keys = [[[2]], [[6]]]
    flat_lines = keys + [item for sublist in lines for item in sublist]
    flat_lines.sort(key=cmp_to_key(cmp_values), reverse=True)
    return reduce(
        operator.mul, [ind for ind, x in enumerate(flat_lines, 1) if x in keys]
    )


```
As it turns out you can pass a function to the key, here is the internal source code for cmp_to_key : 

```

def cmp_to_key(mycmp):
    """Convert a cmp= function into a key= function"""
    class K(object):
        __slots__ = ['obj']
        def __init__(self, obj):
            self.obj = obj
        def __lt__(self, other):
            return mycmp(self.obj, other.obj) < 0
        def __gt__(self, other):
            return mycmp(self.obj, other.obj) > 0
        def __eq__(self, other):
            return mycmp(self.obj, other.obj) == 0
        def __le__(self, other):
            return mycmp(self.obj, other.obj) <= 0
        def __ge__(self, other):
            return mycmp(self.obj, other.obj) >= 0
        __hash__ = None
    return K

```
So basically it is a way to wrap a function and make it implement the greater than stuff.

I was initially a bit confused as to why my code did not work with this:

```


def in_order_wrapper(x1,x2):
	res = in_order([x1,x2])
	if res == None:
		fatal("in_order somehow returned None?")
	if res == True:
		return 1
	elif res == False:
		return 0
	return res
```


and with:

```

def solve2(list_thing):
	#list_thing.sort()
	
	list_thing += [[[2]], [[6]]]

	debug("List thing before: "+str(list_thing))

	orig_list = copy.deepcopy(list_thing)

	list_thing.sort(key=cmp_to_key(in_order_wrapper), reverse=True)
	if not check_sorted(list_thing):
		fatal("List thing not sorted after sorting!")
	x = 1
	for i, k in enumerate(list_thing):
		if k == [[2]] or k == [[6]]:
			debug("Index "+str(i+1)+" is marker!")
			x *= i+1


	debug("List thing after: "+str(list_thing))

	if list_thing == orig_list:
		fatal("Original list is somehow same as sorted list!")


	return x

```

, but the problem was that the 0 in the wrapper needed to be replaced by -1 and then it works. The cmp_to_key return value zero means equal to, 1 means greater than and -1 means less than (i think) .

Thank you for reading!








