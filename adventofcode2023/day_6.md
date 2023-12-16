
# Day 6

## Part 1

Ok so we basically need to count all of the ways to finish the race while going farther than the current record holder.

Let's program a skeleton solver without the meat:

```
import sys

def parse_input() -> list:
	stdin_lines = sys.stdin.read().split("\n")
	# Thanks to https://stackoverflow.com/a/4289557
	times = [int(s) for s in stdin_lines[0].split() if s.isdigit()]
	distances = [int(s) for s in stdin_lines[1].split() if s.isdigit()]
	return times, distances

def get_possible_charge_times(times: list, distances: list) -> tuple:
	# Dummy
	return 0, 0

def main() -> None:
	times, distances = parse_input()
	min_charge, max_charge = get_possible_charge_times(times, distances)

if __name__=="__main__":
	exit(main())
```
Instead of going straight to the naive method, let's first try to model this problem with math. Our total time which we actually go forward is `t - c` where t is the total time and c is the charging time. Our velocity increases by one unit for every unit of time we charge, so our velocity is simply `c` units. Because distance is time times speed, we therefore go forward `c * (t - c)` units. Now, we want the intersection points between this graph and a horizontal line where `y=distance` where distance is the distance from our puzzle input, therefore we have an equation: `c * (t - c) = distance` and we need to solve this with respect to c (the charging time) and then get the highestand lowest bounds using math.ceil() and math.floor() to get the amount of integer solutions. Let's solve this using wolframalpha.

![](pictures/wolframalpha.png)

There you go!

Here was my first implementation of this:

```
import sys
import math

def parse_input() -> list:
	stdin_lines = sys.stdin.read().split("\n")
	# Thanks to https://stackoverflow.com/a/4289557
	times = [int(s) for s in stdin_lines[0].split() if s.isdigit()]
	distances = [int(s) for s in stdin_lines[1].split() if s.isdigit()]
	return times, distances

def get_sols(distance: int, time: int) -> tuple:
	sol1 = 1/2*(time - math.sqrt(time**2 - 4*distance)) # see https://www.wolframalpha.com/input?i=solve+c+*+%28t+-+c%29+%3D+d+for+c
	sol2 = 1/2*(time + math.sqrt(time**2 - 4*distance))
	return math.ceil(sol1), math.floor(sol2)

def get_possible_charge_times(times: list, distances: list) -> tuple:
	# Dummy
	out = 1
	for time, distance in zip(times, distances):
		# Get min time and max time.
		min_time, max_time = get_sols(distance, time)
		# Now multiply the output, by the amount of integer solutions.
		print("amount of solutions: "+str(max_time - min_time + 1))
		out *= max_time - min_time + 1

	return out
		

def main() -> None:
	times, distances = parse_input()
	solution = get_possible_charge_times(times, distances)
	print(solution)
	return 0
if __name__=="__main__":
	exit(main())
```

Except that it doesn't work, because in the very last case, we have 10.0 and 20.0 as solutions to the equation, and since those are integers represented as a float, the math.ceil and math.floor do not do anything to them, so we actually count cases where we tie the best distance, not exceed it. That is why my answer was wrong. After adding a couple of checks:

```

def get_sols(distance: int, time: int) -> tuple:
	sol1 = 1/2*(time - math.sqrt(time**2 - 4*distance)) # see https://www.wolframalpha.com/input?i=solve+c+*+%28t+-+c%29+%3D+d+for+c
	sol2 = 1/2*(time + math.sqrt(time**2 - 4*distance))
	print("sol1 == "+str(sol1))
	print("sol2 == "+str(sol2))
	if sol1.is_integer():
		sol1 += 1
	if sol2.is_integer():
		sol2 -= 1
	return math.ceil(sol1), math.floor(sol2)

```

Now our code works perfectly. Though there may exist a more efficient way to handle this edge case.

## Part 2

Ok, so I guess the challenge expected you to solve part 1 the naive way and then do part 2 the optimized way, but I did the optimized way first, so the only things we need to do for part 2 is to modify the integer concatenation and we should be good.

Here is the modified version, which ignores the spaces in the input:
```
import sys
import math

PART = 2

def parse_input() -> list:
	if PART == 1:

		stdin_lines = sys.stdin.read().split("\n")
		# Thanks to https://stackoverflow.com/a/4289557
		times = [int(s) for s in stdin_lines[0].split() if s.isdigit()]
		distances = [int(s) for s in stdin_lines[1].split() if s.isdigit()]
	elif PART == 2:
		nums = "0123456789"
		stdin_lines = sys.stdin.read().split("\n")
		time_string = [x for x in stdin_lines[0] if x in nums]
		distance_string = [x for x in stdin_lines[1] if x in nums]
		return [int(''.join(time_string))], [int(''.join(distance_string))]
	else:
		print("Invalid puzzle part number: "+str(PART)+"!")
		exit(1)

	return times, distances

def get_sols(distance: int, time: int) -> tuple:
	sol1 = 1/2*(time - math.sqrt(time**2 - 4*distance)) # see https://www.wolframalpha.com/input?i=solve+c+*+%28t+-+c%29+%3D+d+for+c
	sol2 = 1/2*(time + math.sqrt(time**2 - 4*distance))
	print("sol1 == "+str(sol1))
	print("sol2 == "+str(sol2))
	if sol1.is_integer():
		sol1 += 1
	if sol2.is_integer():
		sol2 -= 1
	return math.ceil(sol1), math.floor(sol2)

def get_possible_charge_times(times: list, distances: list) -> tuple:
	# Dummy
	out = 1
	for time, distance in zip(times, distances):
		# Get min time and max time.
		min_time, max_time = get_sols(distance, time)
		# Now multiply the output, by the amount of integer solutions.
		print("amount of solutions: "+str(max_time - min_time + 1))
		out *= max_time - min_time + 1

	return out
		

def main() -> None:
	times, distances = parse_input()
	solution = get_possible_charge_times(times, distances)
	print(solution)
	return 0
if __name__=="__main__":
	exit(main())
```

and it works, but I think we can actually make this faster, by making the nums a set instead of a string.

Like so:

```
import sys
import math

PART = 2

def parse_input() -> list:
	if PART == 1:

		stdin_lines = sys.stdin.read().split("\n")
		# Thanks to https://stackoverflow.com/a/4289557
		times = [int(s) for s in stdin_lines[0].split() if s.isdigit()]
		distances = [int(s) for s in stdin_lines[1].split() if s.isdigit()]
	elif PART == 2:
		nums = set("0123456789")
		stdin_lines = sys.stdin.read().split("\n")
		time_string = [x for x in stdin_lines[0] if x in nums]
		distance_string = [x for x in stdin_lines[1] if x in nums]
		return [int(''.join(time_string))], [int(''.join(distance_string))]
	else:
		print("Invalid puzzle part number: "+str(PART)+"!")
		exit(1)

	return times, distances

def get_sols(distance: int, time: int) -> tuple:
	sol1 = 1/2*(time - math.sqrt(time**2 - 4*distance)) # see https://www.wolframalpha.com/input?i=solve+c+*+%28t+-+c%29+%3D+d+for+c
	sol2 = 1/2*(time + math.sqrt(time**2 - 4*distance))
	print("sol1 == "+str(sol1))
	print("sol2 == "+str(sol2))
	if sol1.is_integer():
		sol1 += 1
	if sol2.is_integer():
		sol2 -= 1
	return math.ceil(sol1), math.floor(sol2)

def get_possible_charge_times(times: list, distances: list) -> tuple:
	# Dummy
	out = 1
	for time, distance in zip(times, distances):
		# Get min time and max time.
		min_time, max_time = get_sols(distance, time)
		# Now multiply the output, by the amount of integer solutions.
		print("amount of solutions: "+str(max_time - min_time + 1))
		out *= max_time - min_time + 1

	return out
		

def main() -> None:
	times, distances = parse_input()
	solution = get_possible_charge_times(times, distances)
	print(solution)
	return 0
if __name__=="__main__":
	exit(main())
```

## Comparing with other solutions

Ok, so let's see how my solution fairs with other solutions out there.

This seems like a neat solution: https://www.reddit.com/r/adventofcode/comments/18bwe6t/comment/kccr53u/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button

And it seems that my solution and that solution execute in roughly the same time. Great!






