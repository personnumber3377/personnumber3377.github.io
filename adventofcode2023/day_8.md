
# Day 8

## Part 1

Ok so this puzzle is basically just a binary tree searching problem. I am going to first program the way to parse the input and then a function which constructs a binary tree and then a function which traverses it.

Here is the input parsing part:

```
import sys

def parse_input() -> dict:
	# The output dictionary has the keys as the node and the values as a list of children. This way we can traverse the tree efficiently.
	lines = sys.stdin.read().split("\n")
	path = lines[0]
	tree = lines[2:] # There is an empty line in between.
	tree_dict = {}
	for line in tree:
		key = line[:3]
		value = line[7:-1].split(", ")
		tree_dict[key] = value
	return tree_dict, route
def main() -> int:
	tree, route = parse_input()
	
	return 0

if __name__=="__main__":
	exit(main())
```

Now just traverse the tree:

```
def traverse_tree(tree: dict, route: str) -> int: # returns the amount of steps required to reach "ZZZ"
	step_count = 0
	route_count = 0
	cur_element = "AAA"
	while cur_element != "ZZZ": # While we haven't reached the end.
		if route_count == len(route):
			route_count = 0 # Loop back to the start of the route instructions
		children = tree[cur_element]
		if route[route_count] == "L": # Go left
			cur_element = children[0]
		else: # Assume right
			cur_element = children[1]
		route_count += 1
		step_count += 1
	return step_count

def main() -> int:
	tree, route = parse_input()
	sol = traverse_tree(tree, route)
	print("Solution: "+str(sol))
	return 0
```

and it works! Great! Let's move on to part 2.

## Part 2













































