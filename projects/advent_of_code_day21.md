
# Day 21

This is basically building a calculator. The monkey names are variables and the stuff they say are expressions (numbers or operations.).

I think that building a hashmap with the monkey names as keys and the expression as a value is the best way to go here. Hashmap in python is basically a dictionary.

Let's program the initial parse function:

```
def parse_monkeys() -> dict:
	stdin_input = sys.stdin.read()
	lines = stdin_input.split("\n")
	# Each line represents one monkey.
	# Each monkey name is four characters long. The line is of the format aaaa: bbbb + cccc

	out_dict = {}

	for line in lines:

		monkey_name = line[:4]
		expression = line[6:]
		out_dict[monkey_name] = expression

	return out_dict
```

Then in the actual evaluation function, we recursively call itself, if there is another name in the expression and we just return an integer if it represents a number.

Here it is :

```

def evaluate_monkeys(monkeys: dict, cur_monkey: str) -> int:

	expression = monkeys[cur_monkey]

	# get tokens
	tokens = expression.split(" ")
	print("tokens == "+str(tokens))
	# check if expression represents a single number or other monkey

	if len(tokens) == 1:
		
		token = tokens[0]
		
		if token.isnumeric():

			return int(token) # plain number

		else:

			# assume monkey name

			return evaluate_monkeys(monkeys, token)

	else:
		# assume three tokens
		assert len(tokens) == 3

		# Judging by the input, it appears that each expression only has monkeys names as parameters, not constants, so we do not need to worry about the other operand being an immediate value. :)

		print("tokens[0] == "+str(tokens[0]))
		print("tokens[1] == "+str(tokens[1]))
		val_1 = evaluate_monkeys(monkeys, tokens[0])
		val_2 = evaluate_monkeys(monkeys, tokens[2])

		op_string = tokens[1]

		match op_string:
			case "+":
				return val_1 + val_2
			case "-":
				return val_1 - val_2
			case "*":
				return val_1 * val_2
			case "/":
				return (val_1 // val_2)
			case _:
				print("Invalid operation for monkey "+str(monkey_name)+" : "+str(op_string))
				exit(1)


```

Here is the final code:

```

import sys

def parse_monkeys() -> dict:
	stdin_input = sys.stdin.read()
	lines = stdin_input.split("\n")
	# Each line represents one monkey.
	# Each monkey name is four characters long. The line is of the format aaaa: bbbb + cccc

	out_dict = {}

	for line in lines:

		monkey_name = line[:4]
		expression = line[6:]
		out_dict[monkey_name] = expression

	return out_dict

def evaluate_monkeys(monkeys: dict, cur_monkey: str) -> int:

	expression = monkeys[cur_monkey]

	# get tokens
	tokens = expression.split(" ")
	print("tokens == "+str(tokens))
	# check if expression represents a single number or other monkey

	if len(tokens) == 1:
		
		token = tokens[0]
		
		if token.isnumeric():

			return int(token) # plain number

		else:

			# assume monkey name

			return evaluate_monkeys(monkeys, token)

	else:
		# assume three tokens
		assert len(tokens) == 3

		# Judging by the input, it appears that each expression only has monkeys names as parameters, not constants, so we do not need to worry about the other operand being an immediate value. :)

		print("tokens[0] == "+str(tokens[0]))
		print("tokens[1] == "+str(tokens[1]))
		val_1 = evaluate_monkeys(monkeys, tokens[0])
		val_2 = evaluate_monkeys(monkeys, tokens[2])

		op_string = tokens[1]

		match op_string:
			case "+":
				return val_1 + val_2
			case "-":
				return val_1 - val_2
			case "*":
				return val_1 * val_2
			case "/":
				return (val_1 // val_2)
			case _:
				print("Invalid operation for monkey "+str(monkey_name)+" : "+str(op_string))
				exit(1)









def main() -> int:

	monkeys = parse_monkeys()

	result = evaluate_monkeys(monkeys, "root") # find value of root.
	print(result)
	return 0

if __name__=="__main__":
	exit(main())

```

Part two of this challenge is really difficult. My first thought is to just bruteforce the correct number, but that is probably not the intended route. Also I think that using a solver such as sympy is cheating too like in this solution: https://github.com/orfeasa/advent-of-code-2022/blob/main/day_21/main.py .

One thing I should try is to just do all of the operations in reverse order, and when we traverse down the tree we record all of the operations in a list. I am going to make the assumption that the humn leaf only occurs once in the entire tree. This way there we do not need to deal with nonlinear equations which could screw us up, like this next example would not be allowed, since it has the humn leaf in two places:


```
root: aaaa = bbbb
bbbb: 100
aaaa: humn * cccc
cccc: humn + 2
```

This would basically simplify to the equation `100 = x*(x+2) = x**2 + 2*x` . When creating a binary tree out of this said group of monkeys with root as the top we get this:




This is not allowed, because the humn leaf is a leaf in two different places at once. I think that the puzzle input is structured in such a way that this does not happen.

Therefore we can traverse the binary tree backwards. We just find the route to the humn leaf and then traverse upwards.

Here is my code:

```

def traverse_backwards(monkeys, route, value):

	# This function traverses the binary tree backwards to get the appropriate value for humn.

	# First get the monkey names which we traverse along to get to humn.

	cur_name = "root"
	monkey_names = ["root"]

	for move in route:
		cur_name = get_monkey_name(monkeys, cur_name, move)
		monkey_names.append(cur_name)

	print("Monkey names which we traverse to get to humn: "+str(monkey_names))

	# reverse route and the monkey names along that route

	#monkey_names.reverse()
	#route.reverse()

	cur_name = "root"
	counter = 0
	monkey_names.pop(0)
	route.pop(0)
	print("monkey_names == "+str(monkey_names))
	print("Initial value: "+str(value))
	while cur_name != "humn":
		cur_name = monkey_names[counter]
		# value is lhs
		#
		if cur_name == "humn":
			break
		if route[counter] == 1:
			# humn thing is on the right, so calculate left.
			cor_index = 0
		else:
			# humn is on the left so calculate right
			cor_index = 2

		print("cur_name == "+str(cur_name))

		tokens = monkeys[cur_name].split(" ")
		print("tokens == "+str(tokens))
		other_monkey_name = tokens[cor_index]
		# get the value of the other monkey:

		val_2 = evaluate_monkeys(monkeys, other_monkey_name)

		# Now apply the reverse operation to the left hand side

		print("tokens[1] == "+str(tokens[1]))
		print("value == "+str(value))
		match tokens[1]: # Match operator and apply the reverse operator
			case "+":
				value = value - val_2
			case "-":
				value = value + val_2
			case "*":
				# sanity check
				if value % val_2 != 0:
					print("value % val_2 != 0")
					exit(1)
				value = value // val_2
			case "/":
				value = (value * val_2)
			case _:
				print("Invalid operation for monkey "+str(monkey_name)+" : "+str(op_string))
				exit(1)
		counter += 1

	return value

```

I actually had the wrong mindset, because we actually need to traverse from the top down, because of course. if we had an equation like `5*(x+2) == 10`, we first divide both sides by five, not subtract two.

Here is the code which works for the tiny input:

```

def traverse_backwards(monkeys, route, value):

	# This function traverses the binary tree backwards to get the appropriate value for humn.

	# First get the monkey names which we traverse along to get to humn.

	cur_name = "root"
	monkey_names = ["root"]

	for move in route:
		cur_name = get_monkey_name(monkeys, cur_name, move)
		monkey_names.append(cur_name)

	print("Monkey names which we traverse to get to humn: "+str(monkey_names))

	# reverse route and the monkey names along that route

	#monkey_names.reverse()
	#route.reverse()

	cur_name = "root"
	counter = 0
	monkey_names.pop(0)
	route.pop(0)
	print("monkey_names == "+str(monkey_names))
	print("Initial value: "+str(value))
	while cur_name != "humn":
		cur_name = monkey_names[counter]
		# value is lhs
		#
		if cur_name == "humn":
			break
		if route[counter] == 1:
			# humn thing is on the right, so calculate left.
			cor_index = 0
		else:
			# humn is on the left so calculate right
			cor_index = 2

		print("cur_name == "+str(cur_name))

		tokens = monkeys[cur_name].split(" ")
		print("tokens == "+str(tokens))
		other_monkey_name = tokens[cor_index]
		# get the value of the other monkey:

		val_2 = evaluate_monkeys(monkeys, other_monkey_name)

		# Now apply the reverse operation to the left hand side

		print("tokens[1] == "+str(tokens[1]))
		print("value == "+str(value))
		match tokens[1]: # Match operator and apply the reverse operator
			case "+":
				value = value - val_2
			case "-":
				value = value + val_2
			case "*":
				# sanity check
				if value % val_2 != 0:
					print("value % val_2 != 0")
					exit(1)
				value = value // val_2
			case "/":
				value = (value * val_2)
			case _:
				print("Invalid operation for monkey "+str(monkey_name)+" : "+str(op_string))
				exit(1)
		counter += 1

	return value

```

When using the script for the big input, I ran into a problem. The lookup function for the route to get to the humn leaf takes forever.

```

def get_route(monkeys: dict, wanted_monkey: str, moves: list, cur_monkey: str):

	# this is a recursive function which tries to find the route from the root of the tree to a certain node / leaf of the tree.

	# first check if this is the wanted leaf

	if cur_monkey == wanted_monkey:
		return moves # Return the current route which we took to get here.

	expression = monkeys[cur_monkey]
	tokens = expression.split(" ")
	# Check if current leaf is a terminal leaf (aka a number)

	if tokens[0].isnumeric():
		return None # No path found yet
	else:
		assert len(tokens) == 3
		# first check if the left branch (the left operand so to speak) has the wanted leaf.

		left_monkey = tokens[0]
		right_monkey = tokens[2]
		#print("wanted_monkey == "+str(wanted_monkey))
		#print("tokens == "+str(tokens))

		print("moves == "+str(moves))

		#if str(tokens) in all_things:
		#	print("oof")
		#	exit(1)
		all_things[str(tokens)] = 1
		if get_route(monkeys, wanted_monkey, moves, left_monkey) != None:
			#print("(monkeys, wanted_monkey, moves, left_monkey) == "+str((monkeys, wanted_monkey, moves, left_monkey)))
			# We found it in the left branch. Return the current moves list with left appended at the end.
			return get_route(monkeys, wanted_monkey, moves+[0], left_monkey)+[0] # Zero means left
		elif get_route(monkeys, wanted_monkey, moves, right_monkey) != None:
			return get_route(monkeys, wanted_monkey, moves+[1], right_monkey)+[1] # One means right
		else:
			#print("Wanted monkey not found in the binary tree!")
			#exit(1)

			return None

```

This is because it basically bruteforces the route by going through all of the possible routes (aka combinations of left and right in the binary tree). Instead of that we can just lookup the humn leaf and see where it gets mentioned and get the name of that node and see where that gets mentioned etc etc and we arrive at the root node. Basically going through the path backwards.

Let's implement that!

After a bit of fiddling I came up with this:

```
def get_route(monkeys: dict, wanted_monkey: str, moves: list, cur_monkey: str):

	if cur_monkey == wanted_monkey:
		print("Returning moves")
		return moves
	print("start")
	for monkey in monkeys.keys():

		expression = monkeys[monkey]
		print("wanted_monkey == "+str(wanted_monkey))
		print("expression == "+str(expression))
		print("cur_monkey == "+str(cur_monkey))
		print("monkey == "+str(monkey))

		# 
		tokens = expression.split(" ")
		if cur_monkey in expression:
			print("poopooooo")
			#tokens = expression.split(" ")
			if cur_monkey == tokens[0]:
				print("left")
				return get_route(monkeys, wanted_monkey, [0]+moves, monkey)
			elif cur_monkey == tokens[2]:
				return get_route(monkeys, wanted_monkey, [1]+moves, monkey)
				print("shit")
			else:
				print("Fuck!")
				print("wanted_monkey == "+str(wanted_monkey))
				exit(1)
				#return None
	print("end")
	return None
```

This gets the route, but now I am faced with the error `value % val_2 != 0` with this next following code:


```


import sys

PART2 = True

def parse_monkeys() -> dict:
	stdin_input = sys.stdin.read()
	lines = stdin_input.split("\n")
	# Each line represents one monkey.
	# Each monkey name is four characters long. The line is of the format aaaa: bbbb + cccc

	out_dict = {}

	for line in lines:

		monkey_name = line[:4]
		expression = line[6:]
		out_dict[monkey_name] = expression

	return out_dict

def evaluate_monkeys(monkeys: dict, cur_monkey: str) -> int:
	if cur_monkey == "humn" and PART2:
		print("Error!")
		exit(1)
	expression = monkeys[cur_monkey]

	# get tokens
	tokens = expression.split(" ")
	print("tokens == "+str(tokens))
	# check if expression represents a single number or other monkey

	if len(tokens) == 1:
		
		token = tokens[0]
		
		if token.isnumeric():

			return int(token) # plain number

		else:

			# assume monkey name

			return evaluate_monkeys(monkeys, token)

	else:
		# assume three tokens
		assert len(tokens) == 3

		# Judging by the input, it appears that each expression only has monkeys names as parameters, not constants, so we do not need to worry about the other operand being an immediate value. :)

		print("tokens[0] == "+str(tokens[0]))
		print("tokens[1] == "+str(tokens[1]))
		val_1 = evaluate_monkeys(monkeys, tokens[0])
		val_2 = evaluate_monkeys(monkeys, tokens[2])

		op_string = tokens[1]

		match op_string:
			case "+":
				return val_1 + val_2
			case "-":
				return val_1 - val_2
			case "*":
				return val_1 * val_2
			case "/":
				return (val_1 // val_2)
			case _:
				print("Invalid operation for monkey "+str(monkey_name)+" : "+str(op_string))
				exit(1)


all_things = {}

def get_route(monkeys: dict, wanted_monkey: str, moves: list, cur_monkey: str):

	if cur_monkey == wanted_monkey:
		print("Returning moves")
		return moves
	print("start")
	for monkey in monkeys.keys():

		expression = monkeys[monkey]
		print("wanted_monkey == "+str(wanted_monkey))
		print("expression == "+str(expression))
		print("cur_monkey == "+str(cur_monkey))
		print("monkey == "+str(monkey))

		# 
		tokens = expression.split(" ")
		if cur_monkey in expression:
			print("poopooooo")
			#tokens = expression.split(" ")
			if cur_monkey == tokens[0]:
				print("left")
				return get_route(monkeys, wanted_monkey, [0]+moves, monkey)
			elif cur_monkey == tokens[2]:
				return get_route(monkeys, wanted_monkey, [1]+moves, monkey)
				print("shit")
			else:
				print("Fuck!")
				print("wanted_monkey == "+str(wanted_monkey))
				exit(1)
				#return None
	print("end")
	return None

'''
def get_route(monkeys: dict, wanted_monkey: str, moves: list, cur_monkey: str):

	# this is a recursive function which tries to find the route from the root of the tree to a certain node / leaf of the tree.

	# first check if this is the wanted leaf

	if cur_monkey == wanted_monkey:
		return moves # Return the current route which we took to get here.

	expression = monkeys[cur_monkey]
	tokens = expression.split(" ")
	# Check if current leaf is a terminal leaf (aka a number)

	if tokens[0].isnumeric():
		return None # No path found yet
	else:
		assert len(tokens) == 3
		# first check if the left branch (the left operand so to speak) has the wanted leaf.

		left_monkey = tokens[0]
		right_monkey = tokens[2]
		#print("wanted_monkey == "+str(wanted_monkey))
		#print("tokens == "+str(tokens))

		print("moves == "+str(moves))

		#if str(tokens) in all_things:
		#	print("oof")
		#	exit(1)
		all_things[str(tokens)] = 1
		if get_route(monkeys, wanted_monkey, moves, left_monkey) != None:
			#print("(monkeys, wanted_monkey, moves, left_monkey) == "+str((monkeys, wanted_monkey, moves, left_monkey)))
			# We found it in the left branch. Return the current moves list with left appended at the end.
			return get_route(monkeys, wanted_monkey, moves+[0], left_monkey)+[0] # Zero means left
		elif get_route(monkeys, wanted_monkey, moves, right_monkey) != None:
			return get_route(monkeys, wanted_monkey, moves+[1], right_monkey)+[1] # One means right
		else:
			#print("Wanted monkey not found in the binary tree!")
			#exit(1)

			return None
'''

def get_value(monkeys: dict, route: list):
	if route[0] == 0:
		# The humn leaf is on the left so the other value is on the right side.
		value_monkey = monkeys["root"].split(" ")[2]
	else:
		# The humn leaf is on the right side, so the other value is on the left side
		value_monkey = monkeys["root"].split(" ")[0]

	# Calculate lhs

	# def evaluate_monkeys(monkeys: dict, cur_monkey: str) -> int:

	lhs = evaluate_monkeys(monkeys, value_monkey)

	return lhs


def get_monkey_name(monkeys: dict, name: str, move:int):
	expression = monkeys[name]
	if move == 0:
		return expression.split(" ")[0] # left
	else:
		return expression.split(" ")[2] # right

def traverse_backwards(monkeys, route, value):

	# This function traverses the binary tree backwards to get the appropriate value for humn.

	# First get the monkey names which we traverse along to get to humn.

	cur_name = "root"
	monkey_names = ["root"]

	for move in route:
		cur_name = get_monkey_name(monkeys, cur_name, move)
		monkey_names.append(cur_name)

	print("Monkey names which we traverse to get to humn: "+str(monkey_names))

	# reverse route and the monkey names along that route

	#monkey_names.reverse()
	#route.reverse()

	cur_name = "root"
	counter = 0
	monkey_names.pop(0)
	print("monkey_names == "+str(monkey_names))
	route.pop(0)
	print("monkey_names == "+str(monkey_names))
	print("Initial value: "+str(value))
	while cur_name != "humn":
		cur_name = monkey_names[counter]
		# value is lhs
		#
		if cur_name == "humn":
			print("qqqqqqqqqqqq")
			break
		if route[counter] == 1:
			# humn thing is on the right, so calculate left.
			cor_index = 0
		else:
			# humn is on the left so calculate right
			cor_index = 2

		print("cur_name == "+str(cur_name))

		tokens = monkeys[cur_name].split(" ")
		print("tokens == "+str(tokens))
		other_monkey_name = tokens[cor_index]
		# get the value of the other monkey:
		assert other_monkey_name not in monkey_names
		val_2 = evaluate_monkeys(monkeys, other_monkey_name)

		# Now apply the reverse operation to the left hand side

		print("tokens[1] == "+str(tokens[1]))
		print("value == "+str(value))
		match tokens[1]: # Match operator and apply the reverse operator
			case "+":
				value = value - val_2
			case "-":
				value = value + val_2
			case "*":
				# sanity check
				if value % val_2 != 0:
					print("counter == "+str(counter))
					print("value % val_2 != 0")
					exit(1)
				value = value // val_2
			case "/":
				value = (value * val_2)
			case _:
				print("Invalid operation for monkey "+str(monkey_name)+" : "+str(op_string))
				exit(1)
		counter += 1

	return value






'''

cur_name = "root"
	monkey_names = ["root"]

	for move in route:
		cur_name = get_monkey_name(monkeys, cur_name, move)
		monkey_names.append(cur_name)

'''

def get_monkey_names(monkeys: dict, route: list):

	cur_name = "root"
	monkey_names = ["root"]

	for move in route:
		cur_name = get_monkey_name(monkeys, cur_name, move)
		monkey_names.append(cur_name)
	return monkey_names


def solve_equation(monkeys: dict) -> int:
	# First get the route to the humn monkey and reverse it.

	route = get_route(monkeys, "root", [], "humn")
	print("route == "+str(route))
	monkey_names = get_monkey_names(monkeys, route)
	#route.reverse()
	print("="*30)
	print("All of the monkeys: ")
	print(str(monkey_names))
	print("="*30)


	value = get_value(monkeys, route)

	humn_value = traverse_backwards(monkeys, route, value)
	print("humn_value == "+str(humn_value))
	return route

def main() -> int:

	monkeys = parse_monkeys()
	result = solve_equation(monkeys)
	#result = evaluate_monkeys(monkeys, "root") # find value of root.
	print(result)
	return 0

if __name__=="__main__":
	exit(main())


```

## Logic bug


It works with the smaller output, but not with the actual output.

I am going to cheat a little and see if my lhs is the same as with an actually working output. Big thanks to https://github.com/KyleGBC/advent-of-code-2022/tree/master !

With the actual working rust version I get 49160133593649 as the constant number and 15610303684582 as the lhs in my own version, so there obviously a discrepency. This is because there is a include_str marco in the rust version which takes the input! Of course it does not work. After supplying our own input we now get the correct value of 15610303684582 which our script also gets. So the problem is in traversing the thing for the humn leaf. Let's just print all of the values of h in the copied version and compare them to our program. Actually there is no need for that, because my logic is flawed.

See, multiplication and addition are commutative operations, which means that a + b == b + a and a * b == b * a . Division and subtraction are not commutative, so when we are traversing up the tree, we need to see if the human monkey is on the left or the right and then decide on that information what to do.

Let's implement that fix:

```

def traverse_backwards(monkeys, route, value):

	# This function traverses the binary tree backwards to get the appropriate value for humn.

	# First get the monkey names which we traverse along to get to humn.

	cur_name = "root"
	monkey_names = ["root"]

	for move in route:
		cur_name = get_monkey_name(monkeys, cur_name, move)
		monkey_names.append(cur_name)

	print("Monkey names which we traverse to get to humn: "+str(monkey_names))

	# reverse route and the monkey names along that route

	#monkey_names.reverse()
	#route.reverse()

	cur_name = "root"
	counter = 0
	monkey_names.pop(0)
	print("monkey_names == "+str(monkey_names))
	route.pop(0)
	print("monkey_names == "+str(monkey_names))
	print("Initial value: "+str(value))
	while cur_name != "humn":
		cur_name = monkey_names[counter]
		# value is lhs
		#
		if cur_name == "humn":
			print("qqqqqqqqqqqq")
			break
		if route[counter] == 1:
			# humn thing is on the right, so calculate left.
			cor_index = 0
		else:
			# humn is on the left so calculate right
			cor_index = 2

		print("cur_name == "+str(cur_name))

		tokens = monkeys[cur_name].split(" ")
		print("tokens == "+str(tokens))
		other_monkey_name = tokens[cor_index]
		# get the value of the other monkey:
		assert other_monkey_name not in monkey_names
		val_2 = evaluate_monkeys(monkeys, other_monkey_name)

		# Now apply the reverse operation to the left hand side

		print("tokens[1] == "+str(tokens[1]))
		print("value == "+str(value))
		match tokens[1]: # Match operator and apply the reverse operator
			case "+":
				value = value - val_2
			case "-":
				# Same as with division:

				if cor_index == 0:

					# Humn thing is on the right aka value = aaaa - humn => humn = aaaa - value
					value = val_2 - value
				else:
					# Humn thing is on the left, so value = humn - aaaa => humn = value + aaaa

					value = value + val_2
				
			case "*":
				# sanity check
				if value % val_2 != 0:
					print("counter == "+str(counter))
					print("value % val_2 != 0")
					exit(1)
				value = value // val_2
			case "/":

				if cor_index == 0:
					# Left is constant, so the divisor is actually the human thing. value = x / humn => humn = value / x
					value = value / val_2
				else:
					# Right is constant, so just multiply by val_2
					value = (value * val_2)
			case _:
				print("Invalid operation for monkey "+str(monkey_name)+" : "+str(op_string))
				exit(1)
		counter += 1

	return value

```

## Making it faster

Now, it takes plenty of time to run, so let's just as an exercise try to make it faster.

First run with cProfile (with -s time ):

```

         493687 function calls (491054 primitive calls) in 2.520 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
   387147    2.095    0.000    2.095    0.000 {built-in method builtins.print}
     70/1    0.373    0.005    2.471    2.471 part2.py:76(get_route)
    98210    0.037    0.000    0.037    0.000 {method 'split' of 'str' objects}
  2633/69    0.013    0.000    0.046    0.001 part2.py:22(evaluate_monkeys)
        1    0.001    0.001    0.001    0.001 part2.py:6(parse_monkeys)
        1    0.001    0.001    0.038    0.038 part2.py:177(traverse_backwards)
     3915    0.000    0.000    0.000    0.000 {built-in method builtins.len}
     1351    0.000    0.000    0.000    0.000 {method 'isnumeric' of 'str' objects}
      138    0.000    0.000    0.000    0.000 part2.py:170(get_monkey_name)
        1    0.000    0.000    2.520    2.520 part2.py:1(<module>)
        1    0.000    0.000    2.519    2.519 part2.py:295(solve_equation)
        1    0.000    0.000    0.000    0.000 part2.py:284(get_monkey_names)
        1    0.000    0.000    2.520    2.520 part2.py:314(main)
       69    0.000    0.000    0.000    0.000 {method 'keys' of 'dict' objects}
        1    0.000    0.000    0.000    0.000 {method 'read' of '_io.TextIOWrapper' objects}
      138    0.000    0.000    0.000    0.000 {method 'append' of 'list' objects}
        1    0.000    0.000    0.000    0.000 <frozen _sitebuiltins>:19(__call__)
        1    0.000    0.000    0.000    0.000 {method 'close' of '_io.TextIOWrapper' objects}
        1    0.000    0.000    0.010    0.010 part2.py:153(get_value)
        1    0.000    0.000    2.520    2.520 {built-in method builtins.exec}
        1    0.000    0.000    0.000    0.000 <frozen codecs>:319(decode)
        1    0.000    0.000    0.000    0.000 {built-in method _codecs.utf_8_decode}
        2    0.000    0.000    0.000    0.000 {method 'pop' of 'list' objects}
        1    0.000    0.000    0.000    0.000 {method 'disable' of '_lsprof.Profiler' objects}


```

Let's just first get rid of the print statements. IO is slow as hell!

```
         105260 function calls (102627 primitive calls) in 0.054 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
     70/1    0.034    0.000    0.046    0.046 part2.py:76(get_route)
    98210    0.013    0.000    0.013    0.000 {method 'split' of 'str' objects}
  2633/69    0.005    0.000    0.006    0.000 part2.py:22(evaluate_monkeys)
        1    0.001    0.001    0.001    0.001 part2.py:6(parse_monkeys)
     2633    0.000    0.000    0.000    0.000 {built-in method builtins.len}
        1    0.000    0.000    0.006    0.006 part2.py:177(traverse_backwards)
     1351    0.000    0.000    0.000    0.000 {method 'isnumeric' of 'str' objects}
      138    0.000    0.000    0.000    0.000 part2.py:170(get_monkey_name)
        1    0.000    0.000    0.054    0.054 part2.py:1(<module>)
        2    0.000    0.000    0.000    0.000 {built-in method builtins.print}
        1    0.000    0.000    0.000    0.000 part2.py:284(get_monkey_names)
        1    0.000    0.000    0.054    0.054 part2.py:314(main)
        1    0.000    0.000    0.000    0.000 {method 'read' of '_io.TextIOWrapper' objects}
        1    0.000    0.000    0.053    0.053 part2.py:295(solve_equation)
      138    0.000    0.000    0.000    0.000 {method 'append' of 'list' objects}
        1    0.000    0.000    0.000    0.000 <frozen codecs>:319(decode)
        1    0.000    0.000    0.000    0.000 <frozen _sitebuiltins>:19(__call__)
       69    0.000    0.000    0.000    0.000 {method 'keys' of 'dict' objects}
        1    0.000    0.000    0.000    0.000 {method 'close' of '_io.TextIOWrapper' objects}
        1    0.000    0.000    0.000    0.000 {built-in method _codecs.utf_8_decode}
        1    0.000    0.000    0.054    0.054 {built-in method builtins.exec}
        1    0.000    0.000    0.001    0.001 part2.py:153(get_value)
        2    0.000    0.000    0.000    0.000 {method 'pop' of 'list' objects}
        1    0.000    0.000    0.000    0.000 {method 'disable' of '_lsprof.Profiler' objects}

```

That looks a lot more promising! Let's get rid of all the split calls by storing the tokens as a list in the dictionary, and not as a string, so we do not have to split it every time we use it.

Here are the results of doing that:

```

         9754 function calls (7121 primitive calls) in 0.022 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
     70/1    0.016    0.000    0.016    0.016 part2.py:76(get_route)
  2633/69    0.003    0.000    0.003    0.000 part2.py:22(evaluate_monkeys)
        1    0.002    0.002    0.002    0.002 part2.py:6(parse_monkeys)
     2704    0.001    0.000    0.001    0.000 {method 'split' of 'str' objects}
     2633    0.000    0.000    0.000    0.000 {built-in method builtins.len}
        1    0.000    0.000    0.022    0.022 part2.py:1(<module>)
        1    0.000    0.000    0.003    0.003 part2.py:182(traverse_backwards)
     1351    0.000    0.000    0.000    0.000 {method 'isnumeric' of 'str' objects}
      138    0.000    0.000    0.000    0.000 part2.py:172(get_monkey_name)
        1    0.000    0.000    0.000    0.000 part2.py:289(get_monkey_names)
        2    0.000    0.000    0.000    0.000 {built-in method builtins.print}
        1    0.000    0.000    0.022    0.022 part2.py:319(main)
        1    0.000    0.000    0.000    0.000 {method 'read' of '_io.TextIOWrapper' objects}
        1    0.000    0.000    0.020    0.020 part2.py:300(solve_equation)
      138    0.000    0.000    0.000    0.000 {method 'append' of 'list' objects}
       69    0.000    0.000    0.000    0.000 {method 'keys' of 'dict' objects}
        1    0.000    0.000    0.000    0.000 <frozen _sitebuiltins>:19(__call__)
        1    0.000    0.000    0.000    0.000 <frozen codecs>:319(decode)
        1    0.000    0.000    0.000    0.000 {built-in method _codecs.utf_8_decode}
        1    0.000    0.000    0.022    0.022 {built-in method builtins.exec}
        1    0.000    0.000    0.000    0.000 {method 'close' of '_io.TextIOWrapper' objects}
        1    0.000    0.000    0.000    0.000 part2.py:153(get_value)
        2    0.000    0.000    0.000    0.000 {method 'pop' of 'list' objects}
        1    0.000    0.000    0.000    0.000 {method 'disable' of '_lsprof.Profiler' objects}

        
```

We know that the monkey names are always four characters long, so the split statement in the parse_monkeys function can be replaced. This is the current version:

```
def parse_monkeys() -> dict:
	stdin_input = sys.stdin.read()
	lines = stdin_input.split("\n")
	# Each line represents one monkey.
	# Each monkey name is four characters long. The line is of the format aaaa: bbbb + cccc

	out_dict = {}

	for line in lines:

		monkey_name = line[:4]
		expression = line[6:]
		out_dict[monkey_name] = expression.split(" ")

	return out_dict
```

and here is the new version:

```
def parse_monkeys() -> dict:
	stdin_input = sys.stdin.read()
	lines = stdin_input.split("\n")
	# Each line represents one monkey.
	# Each monkey name is four characters long. The line is of the format aaaa: bbbb + cccc

	out_dict = {}

	for line in lines:

		monkey_name = line[:4]
		expression = line[6:]
		#out_dict[monkey_name] = expression.split(" ")
		#print("expression == "+str(expression))
		if expression.isnumeric():
			out_dict[monkey_name] = [expression]
			continue
		out_dict[monkey_name] = [expression[0:4], expression[5], expression[7:]]

	return out_dict


```

Except that this is actually the exact same speed, we could do a generator function which generates valid input files and then compare, but I digress.

One way to get the program to run faster is to actually instead of looking up the monkeys in the dictionary, we should construct an actual binary tree object instead. The issue with this is that we only basically search the tree once to find the humn leaf. I do not think it is advantageous, because constructing the object takes more time than we actually even use it. 

There is an obvious optimization in this part:

```

		if cur_monkey in expression:
			#print("poopooooo")
			#tokens = expression.split(" ")
			if cur_monkey == tokens[0]:
				#print("left")
				return get_route(monkeys, wanted_monkey, [0]+moves, monkey)
			elif cur_monkey == tokens[2]:
				return get_route(monkeys, wanted_monkey, [1]+moves, monkey)
				#print("shit")
			else:
				print("Fuck!")
				print("wanted_monkey == "+str(wanted_monkey))
				exit(1)

```

We can replace the elif with else and get rid of the current else, because it was just there for debugging reasons. We need more precise debugging so I made a script which takes one hundred runs and then takes the average:

```


import subprocess

RUN_COUNT = 100

def run_once() -> float:

	output = subprocess.check_output("./cprof.sh", stderr=subprocess.STDOUT, shell=True)

	lines = output.split(b"\n")

	count = 0

	for line in lines:
		if b"ncalls" in line:
			break
		count += 1

	count += 1
	
	out_time = 0.0
	
	for line in lines[count:]:
		#print("line == "+str(line))
		#print("line.split(b\" \") == "+str(line.split(b" ")))
		thing_count = 0
		poopoo = line.split(b" ")
		if poopoo == [b'']:
			break
		while poopoo[thing_count] == b'':
			thing_count += 1
		thing_count += 1

		out_time += float(line.split(b" ")[thing_count])
	print("This run took "+str(out_time)+" seconds.")
	return out_time


def main() -> int:
	# ./cprof.sh
	tot_time = 0.0

	for _ in range(RUN_COUNT):

		tot_time += run_once()

	return tot_time / RUN_COUNT


if __name__=="__main__":
	exit(main())


```

After running the current version a thousand times, the average time was 0.02303634697400002 seconds.

I made a modification to the actual python program, which loops over the solving function over a thousand times and takes the average of that. This gets rid of the setup overhead, so we do not have to take that into account.

Here it is:

```


import sys
import pstats
import time
#def f8_alt(x):
#    return "%14.12f" % x
#pstats.f8 = f8_alt
#PART2 = True
RUN_COUNT = 1000
glob_input = None
def parse_monkeys() -> dict:
	global glob_input
	if glob_input == None:

		glob_input = sys.stdin.read()
	
	lines = glob_input.split("\n")
	# Each line represents one monkey.
	# Each monkey name is four characters long. The line is of the format aaaa: bbbb + cccc

	out_dict = {}

	for line in lines:
		#print("line == "+str(line))
		monkey_name = line[:4]
		expression = line[6:]
		#out_dict[monkey_name] = expression.split(" ")
		#print("expression == "+str(expression))
		if expression.isnumeric():
			out_dict[monkey_name] = [expression]
			continue
		out_dict[monkey_name] = [expression[0:4], expression[5], expression[7:]]

	return out_dict


'''
def parse_monkeys() -> dict:
	stdin_input = sys.stdin.read()
	lines = stdin_input.split("\n")
	# Each line represents one monkey.
	# Each monkey name is four characters long. The line is of the format aaaa: bbbb + cccc

	out_dict = {}

	for line in lines:

		monkey_name = line[:4]
		expression = line[6:]
		out_dict[monkey_name] = expression.split(" ")

	return out_dict
'''


def evaluate_monkeys(monkeys: dict, cur_monkey: str) -> int:
	#if cur_monkey == "humn" and PART2:
	#	print("Error!")
	#	exit(1)
	tokens = monkeys[cur_monkey]
	if len(tokens) == 1:
		token = tokens[0]
		if token.isnumeric():
			return int(token) # plain number
		else:
			return evaluate_monkeys(monkeys, token)
	else:
		val_1 = evaluate_monkeys(monkeys, tokens[0])
		val_2 = evaluate_monkeys(monkeys, tokens[2])
		op_string = tokens[1]
		match op_string:
			case "+":
				return val_1 + val_2
			case "-":
				return val_1 - val_2
			case "*":
				return val_1 * val_2
			case "/":
				return (val_1 // val_2)
			case _:
				print("Invalid operation for monkey "+str(monkey_name)+" : "+str(op_string))
				exit(1)


all_things = {}

def get_route(monkeys: dict, wanted_monkey: str, moves: list, cur_monkey: str):

	if cur_monkey == wanted_monkey:
		#print("Returning moves")
		return moves
	#print("start")
	for monkey in monkeys.keys():

		expression = monkeys[monkey]

		tokens = expression
		if cur_monkey in expression:

			if cur_monkey == tokens[0]:
				#print("left")
				return get_route(monkeys, wanted_monkey, [0]+moves, monkey)
			else:
				return get_route(monkeys, wanted_monkey, [1]+moves, monkey)
	#print("end")
	return None

def get_value(monkeys: dict, route: list):
	if route[0] == 0:
		# The humn leaf is on the left so the other value is on the right side.
		#value_monkey = monkeys["root"].split(" ")[2]

		value_monkey = monkeys["root"][2]
	else:
		# The humn leaf is on the right side, so the other value is on the left side
		#value_monkey = monkeys["root"].split(" ")[0]
		value_monkey = monkeys["root"][0]
	# Calculate lhs

	# def evaluate_monkeys(monkeys: dict, cur_monkey: str) -> int:

	lhs = evaluate_monkeys(monkeys, value_monkey)

	return lhs


def get_monkey_name(monkeys: dict, name: str, move:int):
	expression = monkeys[name]
	if move == 0:
		#return expression.split(" ")[0] # left
		return expression[0]
	else:
		#return expression.split(" ")[2] # right
		return expression[2]


def traverse_backwards(monkeys, route, value):

	# This function traverses the binary tree backwards to get the appropriate value for humn.

	# First get the monkey names which we traverse along to get to humn.

	cur_name = "root"
	monkey_names = ["root"]

	for move in route:
		cur_name = get_monkey_name(monkeys, cur_name, move)
		monkey_names.append(cur_name)

	#print("Monkey names which we traverse to get to humn: "+str(monkey_names))

	# reverse route and the monkey names along that route

	#monkey_names.reverse()
	#route.reverse()

	cur_name = "root"
	counter = 0
	monkey_names.pop(0)
	#print("monkey_names == "+str(monkey_names))
	route.pop(0)
	#print("monkey_names == "+str(monkey_names))
	#print("Initial value: "+str(value))
	while cur_name != "humn":
		cur_name = monkey_names[counter]
		# value is lhs
		#
		if cur_name == "humn":
			#print("qqqqqqqqqqqq")
			break
		if route[counter] == 1:
			# humn thing is on the right, so calculate left.
			cor_index = 0
		else:
			# humn is on the left so calculate right
			cor_index = 2
		tokens = monkeys[cur_name]
		other_monkey_name = tokens[cor_index]

		val_2 = evaluate_monkeys(monkeys, other_monkey_name)

		match tokens[1]: # Match operator and apply the reverse operator
			case "+":
				value = value - val_2
			case "-":
				# Same as with division:
				if cor_index == 0:
					# Humn thing is on the right aka value = aaaa - humn => humn = aaaa - value
					value = val_2 - value
				else:
					# Humn thing is on the left, so value = humn - aaaa => humn = value + aaaa
					value = value + val_2
			case "*":
				# sanity check
				if value % val_2 != 0:
					print("counter == "+str(counter))
					print("value % val_2 != 0")
					exit(1)
				value = value // val_2
			case "/":
				if cor_index == 0:
					# Left is constant, so the divisor is actually the human thing. value = x / humn => humn = value / x
					value = value / val_2
				else:
					# Right is constant, so just multiply by val_2
					value = (value * val_2)
			case _:
				print("Invalid operation for monkey "+str(monkey_name)+" : "+str(op_string))
				exit(1)
		counter += 1
	return value


def get_monkey_names(monkeys: dict, route: list):

	cur_name = "root"
	monkey_names = ["root"]

	for move in route:
		cur_name = get_monkey_name(monkeys, cur_name, move)
		monkey_names.append(cur_name)
	return monkey_names


def solve_equation(monkeys: dict) -> int:
	# First get the route to the humn monkey and reverse it.

	route = get_route(monkeys, "root", [], "humn")
	monkey_names = get_monkey_names(monkeys, route)

	value = get_value(monkeys, route)

	humn_value = traverse_backwards(monkeys, route, value)
	#print("humn_value == "+str(humn_value))
	return humn_value

def main() -> int:
	start_time = time.time()
	for _ in range(RUN_COUNT):

		monkeys = parse_monkeys()
		result = solve_equation(monkeys)
		#result = evaluate_monkeys(monkeys, "root") # find value of root.
		#print(result)
	end_time = time.time()
	tot_time = end_time - start_time
	print(str(RUN_COUNT)+" runs tooks "+str(tot_time)+ " seconds.")
	print("Average run time was "+str(tot_time / RUN_COUNT)+" seconds.")
	return 0

if __name__=="__main__":
	exit(main())


```


and then `python3 -m cProfile -s time prof.py < input.txt` .

Here are the results:

```
1000 runs tooks 25.104990482330322 seconds.
Average run time was 0.025104990482330322 seconds.
         9743013 function calls (7110013 primitive calls) in 25.105 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
70000/1000   18.186    0.000   18.197    0.018 prof.py:87(get_route)
2633000/69000    3.394    0.000    3.761    0.000 prof.py:56(evaluate_monkeys)
     1000    2.416    0.002    2.723    0.003 prof.py:11(parse_monkeys)
  4054000    0.293    0.000    0.293    0.000 {method 'isnumeric' of 'str' objects}
  2633000    0.265    0.000    0.265    0.000 {built-in method builtins.len}
        1    0.175    0.175   25.105   25.105 prof.py:237(main)
     1000    0.140    0.000    3.487    0.003 prof.py:137(traverse_backwards)
     1000    0.115    0.000    0.115    0.000 {method 'split' of 'str' objects}
   138000    0.053    0.000    0.053    0.000 prof.py:127(get_monkey_name)
     1000    0.038    0.000    0.072    0.000 prof.py:214(get_monkey_names)
   138000    0.011    0.000    0.011    0.000 {method 'append' of 'list' objects}
    69000    0.011    0.000    0.011    0.000 {method 'keys' of 'dict' objects}
     1000    0.005    0.000   22.207    0.022 prof.py:225(solve_equation)
     1000    0.001    0.000    0.446    0.000 prof.py:108(get_value)
     2000    0.001    0.000    0.001    0.000 {method 'pop' of 'list' objects}
        1    0.000    0.000   25.105   25.105 prof.py:1(<module>)
        2    0.000    0.000    0.000    0.000 {built-in method builtins.print}
        1    0.000    0.000    0.000    0.000 {method 'read' of '_io.TextIOWrapper' objects}
        1    0.000    0.000    0.000    0.000 <frozen _sitebuiltins>:19(__call__)
        1    0.000    0.000    0.000    0.000 {method 'close' of '_io.TextIOWrapper' objects}
        1    0.000    0.000   25.105   25.105 {built-in method builtins.exec}
        1    0.000    0.000    0.000    0.000 <frozen codecs>:319(decode)
        1    0.000    0.000    0.000    0.000 {built-in method _codecs.utf_8_decode}
        2    0.000    0.000    0.000    0.000 {built-in method time.time}
        1    0.000    0.000    0.000    0.000 {method 'disable' of '_lsprof.Profiler' objects}

```

So just getting the path to humn takes a lot of time.

I found this: https://github.com/bozdoz/advent-of-code-2022/blob/main/21/monkeymath.go which links the monkeys together by using just references, but I think this is the same as just looking them up in a dictionary, so I do not think that we will get a performance increase from this. One way we can optimize the get_route function is to not store the operator in the tokens, so that the "in" check is faster, but idk.

Ok so apparently this is actually slower:

```
def get_route(monkeys: dict, wanted_monkey: str, moves: list, cur_monkey: str):

	if cur_monkey == wanted_monkey:
		#print("Returning moves")
		return moves
	#print("start")
	for monkey in monkeys:

		expression = monkeys[monkey]
		if len(expression) == 1:
			continue
		#tokens = expression
		
		if cur_monkey == expression[0]:
			#print("left")
			return get_route(monkeys, wanted_monkey, [0]+moves, monkey)
		elif cur_monkey == expression[2]:
			return get_route(monkeys, wanted_monkey, [1]+moves, monkey)
```

for some reason. Let's take a look!

```

1000 runs tooks 42.495182275772095 seconds.
Average run time was 0.04249518227577209 seconds.
         105043013 function calls (102410013 primitive calls) in 42.495 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
70000/1000   30.691    0.000   36.515    0.037 prof.py:107(get_route)
 98002000    6.018    0.000    6.018    0.000 {built-in method builtins.len}
2633000/69000    2.950    0.000    3.260    0.000 prof.py:56(evaluate_monkeys)
     1000    2.098    0.002    2.363    0.002 prof.py:11(parse_monkeys)
  4054000    0.285    0.000    0.285    0.000 {method 'isnumeric' of 'str' objects}
        1    0.146    0.146   42.495   42.495 prof.py:261(main)
     1000    0.123    0.000    3.018    0.003 prof.py:161(traverse_backwards)
     1000    0.095    0.000    0.095    0.000 {method 'split' of 'str' objects}
   138000    0.040    0.000    0.040    0.000 prof.py:151(get_monkey_name)
     1000    0.034    0.000    0.060    0.000 prof.py:238(get_monkey_names)
   138000    0.010    0.000    0.010    0.000 {method 'append' of 'list' objects}
     1000    0.003    0.000   39.986    0.040 prof.py:249(solve_equation)
     1000    0.001    0.000    0.390    0.000 prof.py:132(get_value)
     2000    0.000    0.000    0.000    0.000 {method 'pop' of 'list' objects}
        1    0.000    0.000   42.495   42.495 prof.py:1(<module>)
        2    0.000    0.000    0.000    0.000 {built-in method builtins.print}
        1    0.000    0.000    0.000    0.000 {method 'read' of '_io.TextIOWrapper' objects}
        1    0.000    0.000    0.000    0.000 <frozen _sitebuiltins>:19(__call__)
        1    0.000    0.000    0.000    0.000 {method 'close' of '_io.TextIOWrapper' objects}
        1    0.000    0.000   42.495   42.495 {built-in method builtins.exec}
        1    0.000    0.000    0.000    0.000 {built-in method _codecs.utf_8_decode}
        1    0.000    0.000    0.000    0.000 <frozen codecs>:319(decode)
        2    0.000    0.000    0.000    0.000 {built-in method time.time}
        1    0.000    0.000    0.000    0.000 {method 'disable' of '_lsprof.Profiler' objects}


```

So apparently taking the length of a list takes a surprisingly long time. In python taking the length of a list I think is O(1), because the length is stored alongside the array. https://www.geeksforgeeks.org/internal-working-of-the-len-function-in-python/ so why the fuck is it taking so long? I don't know. Maybe we should make a dictionary of types of the expressions (aka mark which ones are expr and which ones are integers)?

Apparently this:

```
def get_route(monkeys: dict, wanted_monkey: str, moves: list, cur_monkey: str, types: dict):

	if cur_monkey == wanted_monkey:
		#print("Returning moves")
		return moves
	#print("start")
	for monkey in monkeys:
		if types[monkey]:
			continue
		expression = monkeys[monkey]
		#tokens = expression
		#if cur_monkey in expression: # No need to check this anymore.

		if cur_monkey == expression[0]:
			#print("left")
			return get_route(monkeys, wanted_monkey, [0]+moves, monkey, types)
		elif cur_monkey == expression[2]:
			return get_route(monkeys, wanted_monkey, [1]+moves, monkey, types)
```

is slower than this:

```

def get_route(monkeys: dict, wanted_monkey: str, moves: list, cur_monkey: str, types: dict):

	if cur_monkey == wanted_monkey:
		#print("Returning moves")
		return moves
	#print("start")
	for monkey in monkeys:
		if types[monkey]:
			continue
		expression = monkeys[monkey]
		#tokens = expression
		#if cur_monkey in expression: # No need to check this anymore.
		if cur_monkey in expression:

			if cur_monkey == expression[0]:
				#print("left")
				return get_route(monkeys, wanted_monkey, [0]+moves, monkey, types)
			else:
				return get_route(monkeys, wanted_monkey, [1]+moves, monkey, types)

```

The first piece of code does in the worst case two comparisons (the if and elif thing), while the second code does in the worst case 3 comparisons (first the if cur_monkey in expression, because the expression also has the operation token in it with the monkey names and then in the condition is true then there is the if check with `expression[0]`) . Yeah whatever. I am done with this anyway. Maybe I will come back to this and optimize it further, but this I think is good enough. The rust version runs in about 12 milliseconds, when as ours runs in 20 milliseconds.

Final script (for now):

```


import sys
import pstats
import time
#def f8_alt(x):
#    return "%14.12f" % x
#pstats.f8 = f8_alt
#PART2 = True
RUN_COUNT = 1000
glob_input = None
def parse_monkeys() -> dict:
	global glob_input
	if glob_input == None:

		glob_input = sys.stdin.read()
	
	lines = glob_input.split("\n")
	# Each line represents one monkey.
	# Each monkey name is four characters long. The line is of the format aaaa: bbbb + cccc

	out_dict = {}
	types = {}

	for line in lines:
		#print("line == "+str(line))
		monkey_name = line[:4]
		expression = line[6:]
		#out_dict[monkey_name] = expression.split(" ")
		#print("expression == "+str(expression))
		if expression.isnumeric():
			out_dict[monkey_name] = [expression]
			types[monkey_name] = 1 # one means number, zero means other expression
			continue
		types[monkey_name] = 0
		out_dict[monkey_name] = [expression[0:4], expression[5], expression[7:]]

	return out_dict, types


'''
def parse_monkeys() -> dict:
	stdin_input = sys.stdin.read()
	lines = stdin_input.split("\n")
	# Each line represents one monkey.
	# Each monkey name is four characters long. The line is of the format aaaa: bbbb + cccc

	out_dict = {}

	for line in lines:

		monkey_name = line[:4]
		expression = line[6:]
		out_dict[monkey_name] = expression.split(" ")

	return out_dict
'''


def evaluate_monkeys(monkeys: dict, cur_monkey: str) -> int:
	#if cur_monkey == "humn" and PART2:
	#	print("Error!")
	#	exit(1)
	tokens = monkeys[cur_monkey]
	if len(tokens) == 1:
		token = tokens[0]
		if token.isnumeric():
			return int(token) # plain number
		else:
			return evaluate_monkeys(monkeys, token)
	else:
		val_1 = evaluate_monkeys(monkeys, tokens[0])
		val_2 = evaluate_monkeys(monkeys, tokens[2])
		op_string = tokens[1]
		match op_string:
			case "+":
				return val_1 + val_2
			case "-":
				return val_1 - val_2
			case "*":
				return val_1 * val_2
			case "/":
				return (val_1 // val_2)
			case _:
				print("Invalid operation for monkey "+str(monkey_name)+" : "+str(op_string))
				exit(1)

'''
def get_route(monkeys: dict, wanted_monkey: str, moves: list, cur_monkey: str):

	if cur_monkey == wanted_monkey:
		#print("Returning moves")
		return moves
	#print("start")
	for monkey in monkeys.keys():

		expression = monkeys[monkey]

		tokens = expression
		if cur_monkey in expression:

			if cur_monkey == tokens[0]:
				#print("left")
				return get_route(monkeys, wanted_monkey, [0]+moves, monkey)
			else:
				return get_route(monkeys, wanted_monkey, [1]+moves, monkey)
	#print("end")
	return None
'''

def get_route(monkeys: dict, wanted_monkey: str, moves: list, cur_monkey: str, types: dict):

	if cur_monkey == wanted_monkey:
		#print("Returning moves")
		return moves
	#print("start")
	for monkey in monkeys:
		if types[monkey]:
			continue
		expression = monkeys[monkey]
		#tokens = expression
		#if cur_monkey in expression: # No need to check this anymore.
		if cur_monkey in expression:

			if cur_monkey == expression[0]:
				#print("left")
				return get_route(monkeys, wanted_monkey, [0]+moves, monkey, types)
			else:
				return get_route(monkeys, wanted_monkey, [1]+moves, monkey, types)


def get_value(monkeys: dict, route: list):
	if route[0] == 0:
		# The humn leaf is on the left so the other value is on the right side.
		#value_monkey = monkeys["root"].split(" ")[2]

		value_monkey = monkeys["root"][2]
	else:
		# The humn leaf is on the right side, so the other value is on the left side
		#value_monkey = monkeys["root"].split(" ")[0]
		value_monkey = monkeys["root"][0]
	# Calculate lhs

	# def evaluate_monkeys(monkeys: dict, cur_monkey: str) -> int:

	lhs = evaluate_monkeys(monkeys, value_monkey)

	return lhs


def get_monkey_name(monkeys: dict, name: str, move:int):
	expression = monkeys[name]
	if move == 0:
		#return expression.split(" ")[0] # left
		return expression[0]
	else:
		#return expression.split(" ")[2] # right
		return expression[2]


def traverse_backwards(monkeys, route, value):

	# This function traverses the binary tree backwards to get the appropriate value for humn.

	# First get the monkey names which we traverse along to get to humn.

	cur_name = "root"
	monkey_names = ["root"]

	for move in route:
		cur_name = get_monkey_name(monkeys, cur_name, move)
		monkey_names.append(cur_name)

	#print("Monkey names which we traverse to get to humn: "+str(monkey_names))

	# reverse route and the monkey names along that route

	#monkey_names.reverse()
	#route.reverse()

	cur_name = "root"
	counter = 0
	monkey_names.pop(0)
	#print("monkey_names == "+str(monkey_names))
	route.pop(0)
	#print("monkey_names == "+str(monkey_names))
	#print("Initial value: "+str(value))
	while cur_name != "humn":
		cur_name = monkey_names[counter]
		# value is lhs
		#
		if cur_name == "humn":
			#print("qqqqqqqqqqqq")
			break
		if route[counter] == 1:
			# humn thing is on the right, so calculate left.
			cor_index = 0
		else:
			# humn is on the left so calculate right
			cor_index = 2
		tokens = monkeys[cur_name]
		other_monkey_name = tokens[cor_index]

		val_2 = evaluate_monkeys(monkeys, other_monkey_name)

		match tokens[1]: # Match operator and apply the reverse operator
			case "+":
				value = value - val_2
			case "-":
				# Same as with division:
				if cor_index == 0:
					# Humn thing is on the right aka value = aaaa - humn => humn = aaaa - value
					value = val_2 - value
				else:
					# Humn thing is on the left, so value = humn - aaaa => humn = value + aaaa
					value = value + val_2
			case "*":
				# sanity check
				#if value % val_2 != 0:
				#	print("counter == "+str(counter))
				#	print("value % val_2 != 0")
				#	exit(1)
				value = value // val_2
			case "/":
				if cor_index == 0:
					# Left is constant, so the divisor is actually the human thing. value = x / humn => humn = value / x
					value = value / val_2
				else:
					# Right is constant, so just multiply by val_2
					value = (value * val_2)
			case _:
				print("Invalid operation for monkey "+str(monkey_name)+" : "+str(op_string))
				exit(1)
		counter += 1
	return value


def get_monkey_names(monkeys: dict, route: list):

	cur_name = "root"
	monkey_names = ["root"]

	for move in route:
		cur_name = get_monkey_name(monkeys, cur_name, move)
		monkey_names.append(cur_name)
	return monkey_names


def solve_equation(monkeys: dict, types: dict) -> int:
	# First get the route to the humn monkey and reverse it.

	route = get_route(monkeys, "root", [], "humn", types)
	monkey_names = get_monkey_names(monkeys, route)

	value = get_value(monkeys, route)

	humn_value = traverse_backwards(monkeys, route, value)
	#print("humn_value == "+str(humn_value))
	return humn_value

def main() -> int:
	start_time = time.time()
	for _ in range(RUN_COUNT):

		monkeys, types = parse_monkeys()
		result = solve_equation(monkeys, types)
		#result = evaluate_monkeys(monkeys, "root") # find value of root.
		#print(result)
	end_time = time.time()
	tot_time = end_time - start_time
	print(str(RUN_COUNT)+" runs tooks "+str(tot_time)+ " seconds.")
	print("Average run time was "+str(tot_time / RUN_COUNT)+" seconds.")
	return 0

if __name__=="__main__":
	exit(main())


```


I couldn't let this be. I put up a question on stack overflow: https://stackoverflow.com/questions/77294215/why-is-in-list-faster-than-checking-individual-elements and the answer was because the "in" operator calls the CONTAINS_OP when as the slower version does not call that. Also taking the element by index is slow. Putting the monkeys first in the list and the operator last speeds up the program by a tiny bit:

```
def parse_monkeys() -> dict:
	global glob_input
	if glob_input == None:

		glob_input = sys.stdin.read()
	
	lines = glob_input.split("\n")
	# Each line represents one monkey.
	# Each monkey name is four characters long. The line is of the format aaaa: bbbb + cccc

	out_dict = {}
	types = {}
	#child_monkey_dict = {}
	for line in lines:
		#print("line == "+str(line))
		monkey_name = line[:4]
		expression = line[6:]
		#out_dict[monkey_name] = expression.split(" ")
		#print("expression == "+str(expression))
		if expression.isnumeric():
			out_dict[monkey_name] = [expression]
			types[monkey_name] = 1 # one means number, zero means other expression
			continue
		types[monkey_name] = 0
		#out_dict[monkey_name] = [expression[0:4], expression[5], expression[7:]]
		out_dict[monkey_name] = [expression[0:4], expression[7:], expression[5]]

		#child_monkey_dict[monkey_name] = [expression[0:4], expression[7:]]

	return out_dict, types#, child_monkey_dict
```

Anyway, now I think I am done.






