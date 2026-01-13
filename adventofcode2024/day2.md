# Day 2

Ok, so I have already written up this code here:

{% raw %}
```



'''

def check_conditions(l1):
	if len(l1) < 2:  # A single-element list is trivially valid
		return True

	increasing = decreasing = True

	for i in range(1, len(l1)):
		diff = l1[i] - l1[i - 1]

		# Check differences
		if not (1 <= abs(diff) <= 3):
			return False  # Invalid difference, exit early

		# Check monotonicity
		if diff < 0:
			increasing = False
		if diff > 0:
			decreasing = False

		# If neither increasing nor decreasing, exit early
		if not (increasing or decreasing):
			return False

	return True  # Both conditions hold

'''


def check_conditions(l1):
	if len(l1) < 2:  # A single-element list is trivially valid
		return True

	increasing = decreasing = True

	for i in range(1, len(l1)):
		diff = l1[i] - l1[i - 1]

		# Check differences
		if not (1 <= abs(diff) <= 3):
			return False  # Invalid difference, exit early

		# Check monotonicity
		if diff < 0:
			increasing = False
		elif diff > 0:
			decreasing = False
		else:
			return False # The list has two consecutive elements of the same value. This is invalid.
		# If neither increasing nor decreasing, exit early
		if not (increasing or decreasing):
			return False

	return True  # Both conditions hold


def solve(lines: list[str]) -> int: # Solve function.

	return sum([1 if check_conditions(list(map(lambda x: int(x), line.split(" ")))) else 0 for line in lines])



if __name__=="__main__":

	fh = open("input.txt", "r")
	lines = fh.readlines()
	fh.close()

	res = solve(lines)

	print("Result: "+str(res))


	exit(0)


```
{% endraw %}

which seems to work for part1

## Part 2

Ok, so maybe just have a variable which signifies if the "one mistake" has already been used????

I think there is a problem with this approach, because reasons.

Here is my bruteforce solve:

{% raw %}
```

def check_conditions_skip_one(l1):
	valid = check_conditions(l1)
	if valid:
		return True

	# Not valid. Try removing that one element and try again.
	#print(valid)
	#print(fault_index)
	#print("feffefefe")

	#if fault_index is not None:
	for i in range(len(l1)):
		# Remove the current fault-causing element
		if check_conditions(l1[:i] + l1[i+1:]):
			return True
	return False


```
{% endraw %}


which basically does a bruteforce solve which is fucking stupid. There was a way better way of solving this here:


