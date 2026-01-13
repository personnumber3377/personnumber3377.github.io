# Day 21

## Part 1

Ok, so I don't really understand this at first, so I think there are multiple keypads and you need to like chain together multiple of these to reach the initial keypad????????

First ideas: I think the best way to go about this is to just precompute the fastest way to move from spot to spot on each of the keypads (I think this is called memoizing) and then just do the thing???

Another idea is to just program an "inverse function" which takes the current position and the position where we want to go to and outputs the button presses which are required to complete that action? Then just do this recursively a couple times??????

I think the inverse function way is the way to go...

Let's program a toy example first...

## Toy example

Let's just program the keypad shit first.

Ok, so I asked ChatGPT and it said that my idea is shit and memory inefficient and it gave this answer:

{% raw %}
```

from collections import deque

# Define the numpad as a grid
NUMPAD = {
    0: (3, 1),
    1: (0, 0), 2: (0, 1), 3: (0, 2),
    4: (1, 0), 5: (1, 1), 6: (1, 2),
    7: (2, 0), 8: (2, 1), 9: (2, 2)
}

# Possible moves and their offsets
MOVES = {
    "up": (-1, 0),
    "down": (1, 0),
    "left": (0, -1),
    "right": (0, 1),
    "enter": (0, 0)
}

# Reverse lookup for moves
MOVE_KEYS = {v: k for k, v in MOVES.items()}


def shortest_path(start, target):
    """
    Calculate the shortest path on the numpad between two keys.
    Returns a list of moves (up, down, left, right, enter).
    """
    start_pos = NUMPAD[start]
    target_pos = NUMPAD[target]

    queue = deque([(start_pos, [])])
    visited = set()

    while queue:
        current_pos, path = queue.popleft()

        if current_pos == target_pos:
            return path + ["enter"]

        if current_pos in visited:
            continue

        visited.add(current_pos)

        for move, offset in MOVES.items():
            if move == "enter":
                continue

            new_pos = (current_pos[0] + offset[0], current_pos[1] + offset[1])

            if new_pos in NUMPAD.values():
                queue.append((new_pos, path + [move]))

    return []


def translate_to_robot_actions(path):
    """
    Translate a path of numpad moves into actions for a robot to press those keys.
    """
    robot_actions = []
    current_pos = (2, 2)  # Assume the robot starts centered on its arrow keys

    for move in path:
        target_pos = (current_pos[0] + MOVES[move][0], current_pos[1] + MOVES[move][1])
        if target_pos != current_pos:
            robot_actions.append(MOVE_KEYS[(target_pos[0] - current_pos[0], target_pos[1] - current_pos[1])])
        robot_actions.append("enter")
        current_pos = target_pos

    return robot_actions


def solve_multilevel_numpad(sequence):
    """
    Given a sequence of digits, determine the shortest sequence of actions
    for the outermost robot to type them.
    """
    outer_robot_actions = []
    current_numpad_pos = 5  # Assume the numpad starts at '5'

    for digit in sequence:
        # Step 1: Calculate shortest path on the numpad
        numpad_path = shortest_path(current_numpad_pos, digit)
        current_numpad_pos = digit

        # Step 2: Translate the numpad path into actions for the robot
        robot_actions = translate_to_robot_actions(numpad_path)

        # Step 3: Add these actions to the outermost robot actions
        outer_robot_actions.extend(robot_actions)

    return outer_robot_actions


# Example Usage
if __name__ == "__main__":
    sequence = [5, 8, 2]  # Example sequence to type
    actions = solve_multilevel_numpad(sequence)
    print("Actions for the outermost robot:", actions)


```
{% endraw %}

let's try to understand how it works... except it doesn't because it assumes that the numpad is starts always at (2,2) fuck.

## Banging my head against the wall

Ok, so this legit actually has me stumped. Let's try atleast something. My thinking is to generate all possible paths which encode the button presses and then memoize that shit in a huge lookup table which get's filled in dynamically as the codes are being typed. I am going to assume that the shortest possible typing shit is which is also the shortest path on the numpad.

Ok, so now I have a table for the initial numpad for the shortest bullshit:

{% raw %}
```



from collections import deque
from main import *

def is_valid(x, y, grid, visited):
    """Check if a position is valid for movement."""
    rows, cols = len(grid), len(grid[0])
    return 0 <= x < rows and 0 <= y < cols and grid[x][y] == 0 and (x, y) not in visited

def bfs_shortest_paths(grid, start, end):
    """Find all shortest paths from start to end on a 2D grid."""
    moves = [(1, 0), (0, 1), (-1, 0), (0, -1)]  # Right, Down, Left, Up
    queue = deque([(start, [start])])  # (current_position, path_so_far)
    visited = set()
    shortest_distance = float('inf')
    all_paths = []

    while queue:
        (x, y), path = queue.popleft()

        # Stop exploring if we go beyond the shortest known distance
        if len(path) > shortest_distance:
            continue

        # Reached the destination
        if (x, y) == end:
            if len(path) < shortest_distance:
                shortest_distance = len(path)
                all_paths = [path]  # Reset paths for a new shorter distance
            elif len(path) == shortest_distance:
                all_paths.append(path)
            continue

        # Mark as visited
        visited.add((x, y))

        # Explore neighbors
        for dx, dy in moves:
            nx, ny = x + dx, y + dy
            if is_valid(nx, ny, grid, visited):
                queue.append(((nx, ny), path + [(nx, ny)]))

    return all_paths

def path_to_string(path) -> str: # This bullshit returns the string which corresponds to the bullshit thing...
    start = path[0]
    path.pop(0)
    out = ""
    for elem in path:
        move_shit = (elem[0] - start[0], elem[1] - start[1])
        start = elem
        assert move_shit in MOVE_KEYS
        thing = MOVE_KEYS[move_shit]
        assert isinstance(thing, str)
        out += thing
    return out

def generate_shortest_paths_numpad():
    grid = [
        [0, 0, 0],
        [0, 0, 0],
        [0, 0, 0],
        [1, 0, 0]
    ]

    output = dict()
    banned = (0,3) # This is the banned space
    for x1 in range(0,3):
        for y1 in range(0,4):
            # (x,y) is the start
            start = (x1,y1)
            for x2 in range(0,3):
                for y2 in range(0,4):
                    end = (x2,y2)
                    if start == end:
                        continue
                    if start == banned or end == banned:
                        continue
                    paths = [path_to_string(x) for x in bfs_shortest_paths(grid, start, end)]
                    assert (x1,y1,x2,y2) not in output
                    output[(x1,y1,x2,y2)] = paths # Just add it like this?????

    return output



# Example Usage
if __name__ == "__main__":
    # Define a grid (0 = open, 1 = occupied)
    grid = [
        [0, 0, 0, 1],
        [0, 1, 0, 0],
        [0, 0, 0, 0],
        [1, 0, 1, 0]
    ]
    start = (0, 0)
    end = (2, 3)
    paths = bfs_shortest_paths(grid, start, end)
    print("All shortest paths:")
    for path in paths:
        print(path)

```
{% endraw %}

and here is the test program:

{% raw %}
```


from shortest_grids import *
from main import *



def test_shortest_numpad():
	res = generate_shortest_paths_numpad()
	print(res)
	# Now let's check the shortest paths from "A" to "7"
	start = NUMPAD["A"]
	end = NUMPAD[7]
	# Now check the result:
	print("Shortest paths from A to 7: "+str(res[(start[0], start[1], end[0], end[1])]))
	return

if __name__=="__main__":

	test_shortest_numpad()

	exit(0)


```
{% endraw %}

and here is the output:

{% raw %}
```

Shortest paths from A to 7: ['^<<^^', '^<^<^', '^<^^<', '^^<<^', '^^<^<', '^^^<<']

```
{% endraw %}

which seems correct. Note that the initialization of these tables is a one time cost only, so we don't really need to be concerned about performance all that much.

Ok, so let's add a couple of more helper functions to instead use the key symbols instead of coordinates.

Done!

Ok so now we know the shortest distances from any place in the keypad and the control keyboards to any other place in the boards. Now what?

My idea is to just iterate over the possible shortest paths in the the keypad and then figure out the shortest in the first robot panel?????

Let's do something like that. I honestly have no idea what I am doing but let's try it anyway...

Now actually reading this challenge closely I noticed that there is a very important thing which makes this atleast somewhat easier: "All robots will initially aim at the keypad's A key, wherever it is." now when we type a code, the last character of the code should always be "A" and since we press it we are pointing at the A on the other panels too, this basically means that we do not need to worry about state changes accross codes. This simplifies a lot. I have this feeling that this will change in part2 but that is a problem for then. This also means that we do not need to even figure out the changes between the different characters of the code, because we always go to the same state when we press.

## Looking up a solution

Ok, so now it is already december 28th after AOC, so it is time to finish this atleast...

This is my current code:

{% raw %}
```


# Dictionary which maps the moves and initial positions to end positions, if the move is not in this dictionary, then it is invalid: "In particular, if a robot arm is ever aimed at a gap where no button is present on the keypad, even for an instant, the robot will panic unrecoverably."

# KEYPAD_MOVES = {}

from shortest_grids import *
from constants import *

SHORTEST_PATHS_NUMPAD = generate_shortest_paths_numpad()
SHORTEST_PATHS_ARROWPAD = generate_shortest_paths_arrowpad()



# Now these functions are used to get the shortest paths from a position to another.

def generate_shortest_paths_arrowpad_keys():

	out = dict() # Generate the dictionary

	all_keys = ARROWPAD.keys() # Get the keys.
	for start_key in all_keys:
		for end_key in all_keys:
			if start_key == end_key:
				continue
			start_pos = ARROWPAD[start_key]
			end_pos = ARROWPAD[end_key]
			# res[(start[0], start[1], end[0], end[1])]
			out[(start_key, end_key)] = SHORTEST_PATHS_ARROWPAD[(start_pos[0], start_pos[1], end_pos[0], end_pos[1])]
	return out

def generate_shortest_paths_numpad_keys():
	out = dict() # Generate the dictionary

	all_keys = NUMPAD.keys() # Get the keys.
	for start_key in all_keys:
		for end_key in all_keys:
			if start_key == end_key:
				continue
			start_pos = NUMPAD[start_key]
			end_pos = NUMPAD[end_key]
			# res[(start[0], start[1], end[0], end[1])]
			out[(start_key, end_key)] = SHORTEST_PATHS_NUMPAD[(start_pos[0], start_pos[1], end_pos[0], end_pos[1])]
	return out






SHORTEST_PATHS_NUMPAD_KEYS = generate_shortest_paths_numpad_keys()
SHORTEST_PATHS_ARROWPAD_KEYS = generate_shortest_paths_arrowpad_keys()




def check_valid_numpad(x,y):
	# Checks if the position is valid in
	return


# Just do the thing...

'''

+---+---+---+
| 7 | 8 | 9 |
+---+---+---+
| 4 | 5 | 6 |
+---+---+---+
| 1 | 2 | 3 |
+---+---+---+
    | 0 | A |
    +---+---+

'''





def keypad_forward(actions, init_pos): # Init pos is the tuple
	assert actions[-1] == "A" # No point in moving if we don't press A, this means that there is a bug somewhere.
	# Applies the actions "actions" to the nine digit display and returns the results...

	# First split on the A button presses.

	press_actions = actions.split("A")


	# This is the location of the "A" character in the numpad.
	x = 2
	y = 3

	for action_seq in press_actions:
		for c in action_seq:
			match c:
				case "<":
					x -= 1
				case ">":
					x += 1

def get_shortest_path(code) -> str: # Generates the shortest path which types this code.
	cache = dict() # This is to memoieze the shortest shit such that we do not need to compute it every time.
	# Initialize the positions of every "pointer"
	keypad_pos = (2,3) # Pointing at "A"
	# Both of the arrowpads
	arrowpad1_pos = (2,0)
	arrowpad2_pos = (2,0)

	# Now generate all of the code changes.

	cur_shortest_path = "" # Current shortest path
	cur_shortest_path_len = 10**9 # Some very big number such that we initialize on the first loop iteration.
	for i in range(len(code)-1):
		start_key = code[i]
		end_key = code[i+1]
		# First generate all of the shortest paths in the initial keypad.
		numpad_paths = SHORTEST_PATHS_NUMPAD_KEYS[(start_key, end_key)]
		# Now iterate over those paths...
		for path in numpad_paths:



def solve(lines: list[str]) -> int: # Solve function.
	'''

	The length of the shortest sequence of button presses you need to type on your directional keypad in order to cause the code to be typed on the numeric keypad; for 029A, this would be 68.
	The numeric part of the code (ignoring leading zeroes); for 029A, this would be 29.

	'''

	output = 0
	for code in lines:
		assert code[-1] == "A"

		shortest_path = get_shortest_path(code)
		# Now just convert the numeric thing and then multiply with the length
		numeric_part_of_code = code[:-1] # Cut out "A"
		numeric_part_of_code = int(numeric_part_of_code)
		# Now just multiply and add to total.
		output += len(shortest_path)*numeric_part_of_code
	return output


if __name__=="__main__":

	fh = open("input.txt", "r")
	lines = fh.readlines()
	fh.close()

	res = solve(lines)

	print("Result: "+str(res))


	exit(0)


```
{% endraw %}

Now we need to iterate over the shortest paths in the numpad paths.

Actually fuck that. Let's just generate all of the shortest paths in the initial keypad and then iterate over them. This way we can go "one layer at a time".

Ok so here is what I have so far:

{% raw %}
```


def get_shortest_path(code) -> str: # Generates the shortest path which types this code.
	cache = dict() # This is to memoieze the shortest shit such that we do not need to compute it every time.
	# Initialize the positions of every "pointer"
	keypad_pos = (2,3) # Pointing at "A"
	# Both of the arrowpads
	arrowpad1_pos = (2,0)
	arrowpad2_pos = (2,0)

	# Now generate all of the code changes.

	cur_shortest_path = "" # Current shortest path
	cur_shortest_path_len = 10**9 # Some very big number such that we initialize on the first loop iteration.
	code = "A"+code # We need to start from "A", therefore do this...

	# This variable stores all of the things...

	numpad_path_stuff = []

	for i in range(len(code)-1):
		start_key = code[i]
		end_key = code[i+1]
		if start_key != "A":
			start_key = int(start_key)
		if end_key != "A":
			end_key = int(end_key)
		print("from : to == "+str(start_key)+", "+str(end_key))
		# First generate all of the shortest paths in the initial keypad.
		assert (start_key, end_key) in SHORTEST_PATHS_NUMPAD_KEYS
		numpad_paths = SHORTEST_PATHS_NUMPAD_KEYS[(start_key, end_key)]
		numpad_path_stuff.append(numpad_paths)
		print("numpad_paths == "+str(numpad_paths))
	print(numpad_path_stuff)
	# Now numpad_path_stuff has all of the possible path stuffs

	exit(1)

```
{% endraw %}

The numpad_path_stuff is a variable which holds all of the shortest path segments in the original keypad. For 029A it produces this:

{% raw %}
```
from : to == A, 0
numpad_paths == ['<']
from : to == 0, 2
numpad_paths == ['^']
from : to == 2, 9
numpad_paths == ['>^^', '^>^', '^^>']
from : to == 9, A
numpad_paths == ['vvv']
[['<'], ['^'], ['>^^', '^>^', '^^>'], ['vvv']]
```
{% endraw %}

which seems correct. Now we want to iterate over this list and all of the combinations of this. How do we do that? Well let's ask chatgpt. "I have a lis"
{% raw %}
```
I have a list of lists of strings. Some of these only contain one element while others contain many elements. It is guaranteed that all of the lists are nonempty and that the main list is also nonempty. How to loop over all of the permutations of these strings? For example given a list like so: [["a", "b"], ["c", "d"]] how to iterate over the strings "ac", "ad", "bc", and "bd"?
```
{% endraw %}
ok so the answer is just:

{% raw %}
```
for combination in itertools.product(*lists):
    # Join the elements of each combination into a string
    print(''.join(combination))
```
{% endraw %}

Here is my current function:

{% raw %}
```

def get_shortest_path(code) -> str: # Generates the shortest path which types this code.
	cache = dict() # This is to memoieze the shortest shit such that we do not need to compute it every time.
	# Initialize the positions of every "pointer"
	keypad_pos = (2,3) # Pointing at "A"
	# Both of the arrowpads
	arrowpad1_pos = (2,0)
	arrowpad2_pos = (2,0)

	# Now generate all of the code changes.

	cur_shortest_path = "" # Current shortest path
	cur_shortest_path_len = 10**9 # Some very big number such that we initialize on the first loop iteration.
	code = "A"+code # We need to start from "A", therefore do this...

	# This variable stores all of the things...

	numpad_path_stuff = []

	for i in range(len(code)-1):
		start_key = code[i]
		end_key = code[i+1]
		if start_key != "A":
			start_key = int(start_key)
		if end_key != "A":
			end_key = int(end_key)
		print("from : to == "+str(start_key)+", "+str(end_key))
		# First generate all of the shortest paths in the initial keypad.
		assert (start_key, end_key) in SHORTEST_PATHS_NUMPAD_KEYS
		numpad_paths = SHORTEST_PATHS_NUMPAD_KEYS[(start_key, end_key)]
		numpad_path_stuff.append(numpad_paths)
		print("numpad_paths == "+str(numpad_paths))
	print(numpad_path_stuff)
	# Now numpad_path_stuff has all of the possible path stuffs
	# Now iterate over all of the shit.
	print("Here are all of the paths on the keypad:")
	for combination in itertools.product(*numpad_path_stuff):
		# Join the elements of each combination into a string
		path = 'A'.join(combination)
		print("Path: "+str(path))

	exit(1)


```
{% endraw %}

and here is the output:

{% raw %}
```

Here are all of the paths on the keypad:
Path: <A^A>^^Avvv
Path: <A^A^>^Avvv
Path: <A^A^^>Avvv

```
{% endraw %}

which seems correct.

## Trying to figure out the arrowpad shit

Ok, so now that we have all of the shit in the initial keypad, let's try to figure out the rest of the bullshit...

One thing to note is that when we go one layer "up" we put the "A" character between each character to enter them. This can be seen by the amount of A characters when you go one layer up. The amount of A characters in the layer above is the same as the length of the entire string in the level below obviously.

Here is my current code:

{% raw %}
```
def get_shortest_path(code) -> str: # Generates the shortest path which types this code.
	cache = dict() # This is to memoieze the shortest shit such that we do not need to compute it every time.
	# Initialize the positions of every "pointer"
	keypad_pos = (2,3) # Pointing at "A"
	# Both of the arrowpads
	arrowpad1_pos = (2,0)
	arrowpad2_pos = (2,0)

	# Now generate all of the code changes.

	cur_shortest_path = "" # Current shortest path
	cur_shortest_path_len = 10**9 # Some very big number such that we initialize on the first loop iteration.
	code = "A"+code # We need to start from "A", therefore do this...

	# This variable stores all of the things...

	numpad_path_stuff = []

	for i in range(len(code)-1):
		start_key = code[i]
		end_key = code[i+1]
		if start_key != "A":
			start_key = int(start_key)
		if end_key != "A":
			end_key = int(end_key)
		print("from : to == "+str(start_key)+", "+str(end_key))
		# First generate all of the shortest paths in the initial keypad.
		assert (start_key, end_key) in SHORTEST_PATHS_NUMPAD_KEYS
		numpad_paths = SHORTEST_PATHS_NUMPAD_KEYS[(start_key, end_key)]
		numpad_path_stuff.append(numpad_paths)
		print("numpad_paths == "+str(numpad_paths))

	print(numpad_path_stuff)
	# Now numpad_path_stuff has all of the possible path stuffs
	# Now iterate over all of the shit.
	print("Here are all of the paths on the keypad:")
	for combination in itertools.product(*numpad_path_stuff):
		# Join the elements of each combination into a string
		path = 'A'.join(combination)
		print("Path: "+str(path))

		# So now we need to find out the thing...

		path_one_layer_up = "A".join(list(path))
		path_one_layer_up = "A"+path_one_layer_up # This must be done because the very first character is "A"
		print(path_one_layer_up)

		# Ok, so now the thing is done bullshit.

		# Now just run the same algorithm as above but for the new shit...
		arrowpad_paths_stuff = []
		for j in range(len(path_one_layer_up)-1):

			start_key = path_one_layer_up[j]
			end_key = path_one_layer_up[j+1]

			if start_key == end_key:
				#arrowpad_paths_stuff.append([])
				continue

			#if start_key != "A":
			#	start_key = int(start_key)
			#if end_key != "A":
			#	end_key = int(end_key)
			print("from : to == "+str(start_key)+", "+str(end_key))
			# First generate all of the shortest paths in the initial keypad.
			assert (start_key, end_key) in SHORTEST_PATHS_ARROWPAD_KEYS
			arrowpad_paths = SHORTEST_PATHS_ARROWPAD_KEYS[(start_key, end_key)]
			arrowpad_paths_stuff.append(arrowpad_paths)
			print("arrowpad_paths == "+str(arrowpad_paths))
		print("arrowpad_paths_stuff == "+str(arrowpad_paths_stuff))
		for combination2 in itertools.product(*arrowpad_paths_stuff):
			# Join the elements of each combination into a string
			path2 = 'A'.join(combination2)
			print("Here is another possible path: "+str(path2))

	exit(1)
```
{% endraw %}

here is a part of the output:

{% raw %}
```

Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^Av<A>^Av<A>^Av<
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^Av<A>^Av<A>^A<v
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^Av<A>^Av<A^>Av<
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^Av<A>^Av<A^>A<v
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^Av<A>^A<vA>^Av<
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^Av<A>^A<vA>^A<v
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^Av<A>^A<vA^>Av<
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^Av<A>^A<vA^>A<v
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^Av<A^>Av<A>^Av<
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^Av<A^>Av<A>^A<v
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^Av<A^>Av<A^>Av<
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^Av<A^>Av<A^>A<v
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^Av<A^>A<vA>^Av<
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^Av<A^>A<vA>^A<v
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^Av<A^>A<vA^>Av<
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^Av<A^>A<vA^>A<v
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^A<vA>^Av<A>^Av<
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^A<vA>^Av<A>^A<v
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^A<vA>^Av<A^>Av<
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^A<vA>^Av<A^>A<v
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^A<vA>^A<vA>^Av<
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^A<vA>^A<vA>^A<v
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^A<vA>^A<vA^>Av<
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^A<vA>^A<vA^>A<v
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^A<vA^>Av<A>^Av<
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^A<vA^>Av<A>^A<v
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^A<vA^>Av<A^>Av<
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^A<vA^>Av<A^>A<v
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^A<vA^>A<vA>^Av<
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^A<vA^>A<vA>^A<v
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^A<vA^>A<vA^>Av<
Here is another possible path: v<<A>>^A<A>A<A>A<A>AvA^A<vA^>A<vA^>A<v
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^Av<A>^Av<A>^Av<
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^Av<A>^Av<A>^A<v
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^Av<A>^Av<A^>Av<
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^Av<A>^Av<A^>A<v
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^Av<A>^A<vA>^Av<
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^Av<A>^A<vA>^A<v
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^Av<A>^A<vA^>Av<
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^Av<A>^A<vA^>A<v
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^Av<A^>Av<A>^Av<
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^Av<A^>Av<A>^A<v
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^Av<A^>Av<A^>Av<
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^Av<A^>Av<A^>A<v
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^Av<A^>A<vA>^Av<
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^Av<A^>A<vA>^A<v
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^Av<A^>A<vA^>Av<
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^Av<A^>A<vA^>A<v
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^A<vA>^Av<A>^Av<
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^A<vA>^Av<A>^A<v
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^A<vA>^Av<A^>Av<
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^A<vA>^Av<A^>A<v
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^A<vA>^A<vA>^Av<
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^A<vA>^A<vA>^A<v
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^A<vA>^A<vA^>Av<
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^A<vA>^A<vA^>A<v
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^A<vA^>Av<A>^Av<
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^A<vA^>Av<A>^A<v
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^A<vA^>Av<A^>Av<
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^A<vA^>Av<A^>A<v
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^A<vA^>A<vA>^Av<
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^A<vA^>A<vA>^A<v
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^A<vA^>A<vA^>Av<
Here is another possible path: v<<A>^>A<A>A<A>A<A>AvA^A<vA^>A<vA^>A<v
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^Av<A>^Av<A>^Av<
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^Av<A>^Av<A>^A<v
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^Av<A>^Av<A^>Av<
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^Av<A>^Av<A^>A<v
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^Av<A>^A<vA>^Av<
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^Av<A>^A<vA>^A<v
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^Av<A>^A<vA^>Av<
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^Av<A>^A<vA^>A<v
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^Av<A^>Av<A>^Av<
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^Av<A^>Av<A>^A<v
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^Av<A^>Av<A^>Av<
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^Av<A^>Av<A^>A<v
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^Av<A^>A<vA>^Av<
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^Av<A^>A<vA>^A<v
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^Av<A^>A<vA^>Av<
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^Av<A^>A<vA^>A<v
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^A<vA>^Av<A>^Av<
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^A<vA>^Av<A>^A<v
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^A<vA>^Av<A^>Av<
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^A<vA>^Av<A^>A<v
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^A<vA>^A<vA>^Av<
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^A<vA>^A<vA>^A<v
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^A<vA>^A<vA^>Av<
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^A<vA>^A<vA^>A<v
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^A<vA^>Av<A>^Av<
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^A<vA^>Av<A>^A<v
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^A<vA^>Av<A^>Av<
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^A<vA^>Av<A^>A<v
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^A<vA^>A<vA>^Av<
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^A<vA^>A<vA>^A<v
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^A<vA^>A<vA^>Av<
Here is another possible path: <v<A>>^A<A>A<A>A<A>AvA^A<vA^>A<vA^>A<v
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^Av<A>^Av<A>^Av<
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^Av<A>^Av<A>^A<v
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^Av<A>^Av<A^>Av<
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^Av<A>^Av<A^>A<v
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^Av<A>^A<vA>^Av<
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^Av<A>^A<vA>^A<v
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^Av<A>^A<vA^>Av<
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^Av<A>^A<vA^>A<v
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^Av<A^>Av<A>^Av<
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^Av<A^>Av<A>^A<v
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^Av<A^>Av<A^>Av<
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^Av<A^>Av<A^>A<v
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^Av<A^>A<vA>^Av<
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^Av<A^>A<vA>^A<v
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^Av<A^>A<vA^>Av<
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^Av<A^>A<vA^>A<v
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^A<vA>^Av<A>^Av<
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^A<vA>^Av<A>^A<v
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^A<vA>^Av<A^>Av<
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^A<vA>^Av<A^>A<v
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^A<vA>^A<vA>^Av<
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^A<vA>^A<vA>^A<v
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^A<vA>^A<vA^>Av<
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^A<vA>^A<vA^>A<v
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^A<vA^>Av<A>^Av<
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^A<vA^>Av<A>^A<v
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^A<vA^>Av<A^>Av<
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^A<vA^>Av<A^>A<v
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^A<vA^>A<vA>^Av<
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^A<vA^>A<vA>^A<v
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^A<vA^>A<vA^>Av<
Here is another possible path: <v<A>^>A<A>A<A>A<A>AvA^A<vA^>A<vA^>A<v

```
{% endraw %}


in some cases it starts off nice:

{% raw %}
```

Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>Av<A>^Av<A>^Av<
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>Av<A>^Av<A>^A<v
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>Av<A>^Av<A^>Av<
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>Av<A>^Av<A^>A<v
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>Av<A>^A<vA>^Av<
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>Av<A>^A<vA>^A<v
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>Av<A>^A<vA^>Av<
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>Av<A>^A<vA^>A<v
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>Av<A^>Av<A>^Av<
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>Av<A^>Av<A>^A<v
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>Av<A^>Av<A^>Av<
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>Av<A^>Av<A^>A<v
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>Av<A^>A<vA>^Av<
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>Av<A^>A<vA>^A<v
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>Av<A^>A<vA^>Av<
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>Av<A^>A<vA^>A<v
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>A<vA>^Av<A>^Av<
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>A<vA>^Av<A>^A<v
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>A<vA>^Av<A^>Av<
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>A<vA>^Av<A^>A<v
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>A<vA>^A<vA>^Av<
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>A<vA>^A<vA>^A<v
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>A<vA>^A<vA^>Av<
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>A<vA>^A<vA^>A<v
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>A<vA^>Av<A>^Av<
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>A<vA^>Av<A>^A<v
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>A<vA^>Av<A^>Av<
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>A<vA^>Av<A^>A<v
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>A<vA^>A<vA>^Av<
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>A<vA^>A<vA>^A<v
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>A<vA^>A<vA^>Av<
Here is another possible path: v<<A>>^A<A>AvA^A<A>A<A>A<vA^>A<vA^>A<v
oof@elskun-lppri:~/newadventofcode/adventofcode2024/day21$ python3 main.py | grep "v<<A>>\^A<A>AvA<"

```
{% endraw %}

but then something goes wrong and it produces the wrong answer. It starts off being correct but then it goes wrong somehow.

Let's just draw this on paper and see what is happening:

Ok, so the problem is because I am missing the A from the end:

Here is my current code:

{% raw %}
```

def get_shortest_path(code) -> str: # Generates the shortest path which types this code.
	cache = dict() # This is to memoieze the shortest shit such that we do not need to compute it every time.
	# Initialize the positions of every "pointer"
	keypad_pos = (2,3) # Pointing at "A"
	# Both of the arrowpads
	arrowpad1_pos = (2,0)
	arrowpad2_pos = (2,0)

	# Now generate all of the code changes.

	cur_shortest_path = "" # Current shortest path
	cur_shortest_path_len = 10**9 # Some very big number such that we initialize on the first loop iteration.
	code = "A"+code # We need to start from "A", therefore do this...

	# This variable stores all of the things...

	numpad_path_stuff = []

	for i in range(len(code)-1):
		start_key = code[i]
		end_key = code[i+1]
		if start_key != "A":
			start_key = int(start_key)
		if end_key != "A":
			end_key = int(end_key)
		print("from : to == "+str(start_key)+", "+str(end_key))
		# First generate all of the shortest paths in the initial keypad.
		assert (start_key, end_key) in SHORTEST_PATHS_NUMPAD_KEYS
		numpad_paths = SHORTEST_PATHS_NUMPAD_KEYS[(start_key, end_key)]
		numpad_path_stuff.append(numpad_paths)
		print("numpad_paths == "+str(numpad_paths))

	print(numpad_path_stuff)
	# Now numpad_path_stuff has all of the possible path stuffs
	# Now iterate over all of the shit.
	print("Here are all of the paths on the keypad:")
	for combination in itertools.product(*numpad_path_stuff):
		# Join the elements of each combination into a string
		path = 'A'.join(combination)
		print("Path: "+str(path))

		# So now we need to find out the thing...

		# path_one_layer_up = "A".join(list(path))
		path_one_layer_up = "".join(list(path))

		path_one_layer_up = "A"+path_one_layer_up+"A" # This must be done because the very first character is "A"
		print("Processing this path: "+str(path_one_layer_up))

		# Ok, so now the thing is done bullshit.

		# Now just run the same algorithm as above but for the new shit...
		arrowpad_paths_stuff = []
		for j in range(len(path_one_layer_up)-1):

			start_key = path_one_layer_up[j]
			end_key = path_one_layer_up[j+1]

			if start_key == end_key:
				# arrowpad_paths_stuff.append(["A"])
				arrowpad_paths_stuff.append(["A"])
				continue

			#if start_key != "A":
			#	start_key = int(start_key)
			#if end_key != "A":
			#	end_key = int(end_key)
			print("from : to == "+str(start_key)+", "+str(end_key))
			# First generate all of the shortest paths in the initial keypad.
			assert (start_key, end_key) in SHORTEST_PATHS_ARROWPAD_KEYS
			arrowpad_paths = SHORTEST_PATHS_ARROWPAD_KEYS[(start_key, end_key)]
			arrowpad_paths_stuff.append(arrowpad_paths)
			print("arrowpad_paths == "+str(arrowpad_paths))

		print("arrowpad_paths_stuff == "+str(arrowpad_paths_stuff))
		for combination2 in itertools.product(*arrowpad_paths_stuff):
			# Join the elements of each combination into a string
			path2 = ''.join(combination2)
			print("Here is another possible path: "+str(path2))

	exit(1)

```
{% endraw %}

This program produces such answers:

{% raw %}
```

v<<>>^<>v<^A>v<AA>^

```
{% endraw %}

now if I join each part with the character "A" I get this:

{% raw %}
```
path2 = 'A'.join(combination2)
path2 = path2 + "A" # Add the final enter.
```
{% endraw %}

I get this:

{% raw %}
```

v<<A>>^A<A>AvA<^AAA>Av<AAAAA>^A

```
{% endraw %}

which is almost correct. The issue is that when the previous character thing ends with A or the next thing starts with A, then we actually put an extra A character. We want a conditional join which checks for this. Let's ask chatgpt:

{% raw %}
```
I have a list of strings some of which contains the character 'A'. How do I conditionally join with the character A when the preceding string does not end with A and the next string does not start with A and otherwise join with the empty string?
```
{% endraw %}

here is the answer it gave:

{% raw %}
```

def conditional_join(strings):
    result = []
    for i, s in enumerate(strings):
        # Determine if 'A' should be used as the join character
        if ('A' in s and
            (i == 0 or not strings[i-1].endswith('A')) and
            (i == len(strings)-1 or not strings[i+1].startswith('A'))):
            result.append('A' + s)
        else:
            result.append(s)
    return ''.join(result)

# Example usage
strings = ['foo', 'barA', 'baz', 'Aqux', 'zooA']
joined = conditional_join(strings)
print(joined)

```
{% endraw %}

fuck

{% raw %}
```
v<<A>>^A<A>AvA<^AAA>Av<AAAAA>^A

v<<A>>^A<A>AvA<^AA>Av<AAA>^A


```
{% endraw %}

Let's just go over this manually on paper:

{% raw %}
```


our:

A v<<A >>^A <A >A  2 here i think    v<^A>v<AA>^A

correct:

v<<A >>^A <A >A  vA<^AA>A<vAAA>^A


```
{% endraw %}


I think there is the missing A because here:

{% raw %}
```
combination2 == ('v<<', '>>^', '<', '>', 'v', '<^', 'A', '>', 'v<', 'A', 'A', '>^')
Here is another possible path: Av<<A>>^A<A>Av<^A>v<AA>^A

```
{% endraw %}

so the bug is in the conditional_join logic.

Ok, so here is the fixed version:

{% raw %}
```


def conditional_join(strings):
	result = []
	for i, s in enumerate(strings):
		# Determine if 'A' should be used as the join character
		#if ('A' in s and
		if not i == 0:

			print("strings[i-1] == "+str(strings[i-1]))
		if not i == len(strings)-1:
			print("strings[i] == "+str(strings[i]))

		if		((i == 0 or not strings[i].endswith('A')) and
				(not strings[i].startswith('A'))):
			result.append('A' + s)
		else:
			result.append(s)
	return ''.join(result)

```
{% endraw %}

let's clean it up a bit:

{% raw %}
```

def conditional_join(strings):
	result = []
	for i, s in enumerate(strings):
		if ((i == 0 or not strings[i].endswith('A')) and (not strings[i].startswith('A'))):
			result.append('A' + s)
		else:
			result.append(s)
	return ''.join(result)

```
{% endraw %}

ok so here is my current code which produces the correct path for layer one:

{% raw %}
```


# Dictionary which maps the moves and initial positions to end positions, if the move is not in this dictionary, then it is invalid: "In particular, if a robot arm is ever aimed at a gap where no button is present on the keypad, even for an instant, the robot will panic unrecoverably."

# KEYPAD_MOVES = {}

from shortest_grids import *
from constants import *
import itertools

SHORTEST_PATHS_NUMPAD = generate_shortest_paths_numpad()
SHORTEST_PATHS_ARROWPAD = generate_shortest_paths_arrowpad()



# Now these functions are used to get the shortest paths from a position to another.

def generate_shortest_paths_arrowpad_keys():

	out = dict() # Generate the dictionary

	all_keys = ARROWPAD.keys() # Get the keys.
	for start_key in all_keys:
		for end_key in all_keys:
			if start_key == end_key:
				continue
			start_pos = ARROWPAD[start_key]
			end_pos = ARROWPAD[end_key]
			# res[(start[0], start[1], end[0], end[1])]
			out[(start_key, end_key)] = SHORTEST_PATHS_ARROWPAD[(start_pos[0], start_pos[1], end_pos[0], end_pos[1])]
	return out

def generate_shortest_paths_numpad_keys():
	out = dict() # Generate the dictionary

	all_keys = NUMPAD.keys() # Get the keys.
	for start_key in all_keys:
		for end_key in all_keys:
			if start_key == end_key:
				continue
			start_pos = NUMPAD[start_key]
			end_pos = NUMPAD[end_key]
			# res[(start[0], start[1], end[0], end[1])]
			out[(start_key, end_key)] = SHORTEST_PATHS_NUMPAD[(start_pos[0], start_pos[1], end_pos[0], end_pos[1])]
	return out






SHORTEST_PATHS_NUMPAD_KEYS = generate_shortest_paths_numpad_keys()
SHORTEST_PATHS_ARROWPAD_KEYS = generate_shortest_paths_arrowpad_keys()




def check_valid_numpad(x,y):
	# Checks if the position is valid in
	return


# Just do the thing...

'''

+---+---+---+
| 7 | 8 | 9 |
+---+---+---+
| 4 | 5 | 6 |
+---+---+---+
| 1 | 2 | 3 |
+---+---+---+
	 | 0 | A |
	 +---+---+

'''


# SHORTEST_PATHS_ARROWPAD_INPUT_KEYS
# These are basically the shortest ways to input a character to the second arrowpad from the first. The key is the wanted character and the value is the input into the original arrowpad:

SHORTEST_PATHS_ARROWPAD_INPUT_KEYS =	{"<": "<v<A",
										"^": "<A",
										"v": "<vA",
										">": "vA"}


'''

	 +---+---+
	 | ^ | A |
+---+---+---+
| < | v | > |
+---+---+---+

'''


def keypad_forward(actions, init_pos): # Init pos is the tuple
	assert actions[-1] == "A" # No point in moving if we don't press A, this means that there is a bug somewhere.
	# Applies the actions "actions" to the nine digit display and returns the results...

	# First split on the A button presses.

	press_actions = actions.split("A")


	# This is the location of the "A" character in the numpad.
	x = 2
	y = 3

	for action_seq in press_actions:
		for c in action_seq:
			match c:
				case "<":
					x -= 1
				case ">":
					x += 1

'''

def conditional_join(strings):
	result = []
	for i, s in enumerate(strings):
		# Determine if 'A' should be used as the join character
		if ('A' not in s and
				(i == 0 or not strings[i-1].endswith('A')) and
				(i == len(strings)-1 or not strings[i+1].startswith('A'))):
			result.append('A' + s)
		else:
			result.append(s)
	return ''.join(result)
'''



def conditional_join(strings):
	result = []
	for i, s in enumerate(strings):
		if ((not i == 0 and not strings[i].endswith('A')) and (not strings[i].startswith('A'))):
			result.append('A' + s)
		else:
			result.append(s)
	return ''.join(result)

'''
def conditional_join(strings):
	result = []
	for i, s in enumerate(strings):
		# Determine if 'A' should be used as the join character
		# if ('A' in s and
		if ((i == 0 or not strings[i-1].endswith('A')) and
				(i == len(strings)-1 or not strings[i+1].startswith('A'))):
			result.append('A' + s)
		else:
			result.append(s)
	return ''.join(result)
'''


# Example usage
#strings = ['foo', 'barA', 'baz', 'Aqux', 'zooA']
#joined = conditional_join(strings)
#print(joined)


def get_shortest_path(code) -> str: # Generates the shortest path which types this code.
	cache = dict() # This is to memoieze the shortest shit such that we do not need to compute it every time.
	# Initialize the positions of every "pointer"
	keypad_pos = (2,3) # Pointing at "A"
	# Both of the arrowpads
	arrowpad1_pos = (2,0)
	arrowpad2_pos = (2,0)

	# Now generate all of the code changes.

	cur_shortest_path = "" # Current shortest path
	cur_shortest_path_len = 10**9 # Some very big number such that we initialize on the first loop iteration.
	code = "A"+code # We need to start from "A", therefore do this...

	# This variable stores all of the things...

	numpad_path_stuff = []

	for i in range(len(code)-1):
		start_key = code[i]
		end_key = code[i+1]
		if start_key != "A":
			start_key = int(start_key)
		if end_key != "A":
			end_key = int(end_key)
		print("from : to == "+str(start_key)+", "+str(end_key))
		# First generate all of the shortest paths in the initial keypad.
		assert (start_key, end_key) in SHORTEST_PATHS_NUMPAD_KEYS
		numpad_paths = SHORTEST_PATHS_NUMPAD_KEYS[(start_key, end_key)]
		numpad_path_stuff.append(numpad_paths)
		print("numpad_paths == "+str(numpad_paths))

	print(numpad_path_stuff)
	# Now numpad_path_stuff has all of the possible path stuffs
	# Now iterate over all of the shit.
	print("Here are all of the paths on the keypad:")
	for combination in itertools.product(*numpad_path_stuff):
		# Join the elements of each combination into a string
		path = 'A'.join(combination)
		#print("Path: "+str(path))

		# So now we need to find out the thing...

		# path_one_layer_up = "A".join(list(path))
		path_one_layer_up = "".join(list(path))

		path_one_layer_up = "A"+path_one_layer_up+"A" # This must be done because the very first character is "A"
		#print("Processing this path: "+str(path_one_layer_up))

		# Ok, so now the thing is done bullshit.

		# Now just run the same algorithm as above but for the new shit...
		arrowpad_paths_stuff = []
		for j in range(len(path_one_layer_up)-1):

			start_key = path_one_layer_up[j]
			end_key = path_one_layer_up[j+1]

			if start_key == end_key:
				if start_key != "A":

					# arrowpad_paths_stuff.append(["A"])
					arrowpad_paths_stuff.append(["A"])
					continue
				else:
					continue

			#if start_key != "A":
			#	start_key = int(start_key)
			#if end_key != "A":
			#	end_key = int(end_key)
			#print("from : to == "+str(start_key)+", "+str(end_key))
			# First generate all of the shortest paths in the initial keypad.
			assert (start_key, end_key) in SHORTEST_PATHS_ARROWPAD_KEYS
			arrowpad_paths = SHORTEST_PATHS_ARROWPAD_KEYS[(start_key, end_key)]
			arrowpad_paths_stuff.append(arrowpad_paths)
			#print("arrowpad_paths == "+str(arrowpad_paths))

		#print("arrowpad_paths_stuff == "+str(arrowpad_paths_stuff))
		for combination2 in itertools.product(*arrowpad_paths_stuff):
			#print("combination2 == "+str(combination2))
			# Join the elements of each combination into a string
			#path2 = 'A'.join(combination2)
			path2 = conditional_join(combination2)
			#path2 = 'A'.join(combination2)
			#path2 = path2[1:] + "A" # Add the final enter.
			path2 = path2+"A"
			print("Here is another possible path: "+str(path2))

	exit(1)


def solve(lines: list[str]) -> int: # Solve function.
	'''

	The length of the shortest sequence of button presses you need to type on your directional keypad in order to cause the code to be typed on the numeric keypad; for 029A, this would be 68.
	The numeric part of the code (ignoring leading zeroes); for 029A, this would be 29.

	'''

	output = 0
	for code in lines:
		print("code == "+str(code))
		code = code[:-1]
		assert code[-1] == "A"

		shortest_path = get_shortest_path(code)
		# Now just convert the numeric thing and then multiply with the length
		numeric_part_of_code = code[:-1] # Cut out "A"
		numeric_part_of_code = int(numeric_part_of_code)
		# Now just multiply and add to total.
		output += len(shortest_path)*numeric_part_of_code
	return output


if __name__=="__main__":

	fh = open("input.txt", "r")
	lines = fh.readlines()
	fh.close()

	res = solve(lines)

	print("Result: "+str(res))


	exit(0)


```
{% endraw %}

git commit e79b7b2fda0057d326a388fdb32cd85a11bafb3a

Now we just need to basically do one more pass and we should be good maybe??????

Ok, so this is the correct answer:

{% raw %}
```

# Dictionary which maps the moves and initial positions to end positions, if the move is not in this dictionary, then it is invalid: "In particular, if a robot arm is ever aimed at a gap where no button is present on the keypad, even for an instant, the robot will panic unrecoverably."

# KEYPAD_MOVES = {}

from shortest_grids import *
from constants import *
import itertools

SHORTEST_PATHS_NUMPAD = generate_shortest_paths_numpad()
SHORTEST_PATHS_ARROWPAD = generate_shortest_paths_arrowpad()



# Now these functions are used to get the shortest paths from a position to another.

def generate_shortest_paths_arrowpad_keys():

	out = dict() # Generate the dictionary

	all_keys = ARROWPAD.keys() # Get the keys.
	for start_key in all_keys:
		for end_key in all_keys:
			if start_key == end_key:
				continue
			start_pos = ARROWPAD[start_key]
			end_pos = ARROWPAD[end_key]
			# res[(start[0], start[1], end[0], end[1])]
			out[(start_key, end_key)] = SHORTEST_PATHS_ARROWPAD[(start_pos[0], start_pos[1], end_pos[0], end_pos[1])]
	return out

def generate_shortest_paths_numpad_keys():
	out = dict() # Generate the dictionary

	all_keys = NUMPAD.keys() # Get the keys.
	for start_key in all_keys:
		for end_key in all_keys:
			if start_key == end_key:
				continue
			start_pos = NUMPAD[start_key]
			end_pos = NUMPAD[end_key]
			# res[(start[0], start[1], end[0], end[1])]
			out[(start_key, end_key)] = SHORTEST_PATHS_NUMPAD[(start_pos[0], start_pos[1], end_pos[0], end_pos[1])]
	return out






SHORTEST_PATHS_NUMPAD_KEYS = generate_shortest_paths_numpad_keys()
SHORTEST_PATHS_ARROWPAD_KEYS = generate_shortest_paths_arrowpad_keys()




def check_valid_numpad(x,y):
	# Checks if the position is valid in
	return


# Just do the thing...

'''

+---+---+---+
| 7 | 8 | 9 |
+---+---+---+
| 4 | 5 | 6 |
+---+---+---+
| 1 | 2 | 3 |
+---+---+---+
	 | 0 | A |
	 +---+---+

'''


# SHORTEST_PATHS_ARROWPAD_INPUT_KEYS
# These are basically the shortest ways to input a character to the second arrowpad from the first. The key is the wanted character and the value is the input into the original arrowpad:

SHORTEST_PATHS_ARROWPAD_INPUT_KEYS =	{"<": "<v<A",
										"^": "<A",
										"v": "<vA",
										">": "vA"}


'''

	 +---+---+
	 | ^ | A |
+---+---+---+
| < | v | > |
+---+---+---+

'''


def keypad_forward(actions, init_pos): # Init pos is the tuple
	assert actions[-1] == "A" # No point in moving if we don't press A, this means that there is a bug somewhere.
	# Applies the actions "actions" to the nine digit display and returns the results...

	# First split on the A button presses.

	press_actions = actions.split("A")


	# This is the location of the "A" character in the numpad.
	x = 2
	y = 3

	for action_seq in press_actions:
		for c in action_seq:
			match c:
				case "<":
					x -= 1
				case ">":
					x += 1

'''

def conditional_join(strings):
	result = []
	for i, s in enumerate(strings):
		# Determine if 'A' should be used as the join character
		if ('A' not in s and
				(i == 0 or not strings[i-1].endswith('A')) and
				(i == len(strings)-1 or not strings[i+1].startswith('A'))):
			result.append('A' + s)
		else:
			result.append(s)
	return ''.join(result)
'''



def conditional_join(strings):
	result = []
	for i, s in enumerate(strings):
		if ((not i == 0 and not strings[i].endswith('A')) and (not strings[i].startswith('A'))):
			result.append('A' + s)
		else:
			result.append(s)
	return ''.join(result)

'''
def conditional_join(strings):
	result = []
	for i, s in enumerate(strings):
		# Determine if 'A' should be used as the join character
		# if ('A' in s and
		if ((i == 0 or not strings[i-1].endswith('A')) and
				(i == len(strings)-1 or not strings[i+1].startswith('A'))):
			result.append('A' + s)
		else:
			result.append(s)
	return ''.join(result)
'''


# Example usage
#strings = ['foo', 'barA', 'baz', 'Aqux', 'zooA']
#joined = conditional_join(strings)
#print(joined)


def get_shortest_path(code) -> str: # Generates the shortest path which types this code.
	cache = dict() # This is to memoieze the shortest shit such that we do not need to compute it every time.
	# Initialize the positions of every "pointer"
	keypad_pos = (2,3) # Pointing at "A"
	# Both of the arrowpads
	arrowpad1_pos = (2,0)
	arrowpad2_pos = (2,0)

	# Now generate all of the code changes.

	cur_shortest_path = "" # Current shortest path
	cur_shortest_path_len = 10**9 # Some very big number such that we initialize on the first loop iteration.
	code = "A"+code # We need to start from "A", therefore do this...

	# This variable stores all of the things...

	numpad_path_stuff = []

	for i in range(len(code)-1):
		start_key = code[i]
		end_key = code[i+1]
		if start_key != "A":
			start_key = int(start_key)
		if end_key != "A":
			end_key = int(end_key)
		print("from : to == "+str(start_key)+", "+str(end_key))
		# First generate all of the shortest paths in the initial keypad.
		assert (start_key, end_key) in SHORTEST_PATHS_NUMPAD_KEYS
		numpad_paths = SHORTEST_PATHS_NUMPAD_KEYS[(start_key, end_key)]
		numpad_path_stuff.append(numpad_paths)
		print("numpad_paths == "+str(numpad_paths))

	print(numpad_path_stuff)
	# Now numpad_path_stuff has all of the possible path stuffs
	# Now iterate over all of the shit.
	print("Here are all of the paths on the keypad:")
	for combination in itertools.product(*numpad_path_stuff):
		# Join the elements of each combination into a string
		path = 'A'.join(combination)
		#print("Path: "+str(path))

		# So now we need to find out the thing...

		# path_one_layer_up = "A".join(list(path))
		path_one_layer_up = "".join(list(path))

		path_one_layer_up = "A"+path_one_layer_up+"A" # This must be done because the very first character is "A"
		#print("Processing this path: "+str(path_one_layer_up))

		# Ok, so now the thing is done bullshit.

		# Now just run the same algorithm as above but for the new shit...
		arrowpad_paths_stuff = []
		for j in range(len(path_one_layer_up)-1):

			start_key = path_one_layer_up[j]
			end_key = path_one_layer_up[j+1]

			if start_key == end_key:
				if start_key != "A":

					# arrowpad_paths_stuff.append(["A"])
					arrowpad_paths_stuff.append(["A"])
					continue
				else:
					continue

			#if start_key != "A":
			#	start_key = int(start_key)
			#if end_key != "A":
			#	end_key = int(end_key)
			#print("from : to == "+str(start_key)+", "+str(end_key))
			# First generate all of the shortest paths in the initial keypad.
			assert (start_key, end_key) in SHORTEST_PATHS_ARROWPAD_KEYS
			arrowpad_paths = SHORTEST_PATHS_ARROWPAD_KEYS[(start_key, end_key)]
			arrowpad_paths_stuff.append(arrowpad_paths)
			#print("arrowpad_paths == "+str(arrowpad_paths))

		#print("arrowpad_paths_stuff == "+str(arrowpad_paths_stuff))
		for combination2 in itertools.product(*arrowpad_paths_stuff):
			#print("combination2 == "+str(combination2))
			# Join the elements of each combination into a string
			#path2 = 'A'.join(combination2)
			path2 = conditional_join(combination2)
			#path2 = 'A'.join(combination2)
			#path2 = path2[1:] + "A" # Add the final enter.
			path2 = path2+"A"
			print("Here is another possible path2: "+str(path2))
			path2 = "A"+path2














			'''

			for combination in itertools.product(*numpad_path_stuff):
			# Join the elements of each combination into a string
			path = 'A'.join(combination)
			#print("Path: "+str(path))

			# So now we need to find out the thing...

			# path_one_layer_up = "A".join(list(path))
			path_one_layer_up = "".join(list(path))



			path_one_layer_up = "A"+path_one_layer_up+"A" # This must be done because the very first character is "A"
			#print("Processing this path: "+str(path_one_layer_up))

			'''


			# Ok, so now the thing is done bullshit.

			# Now just run the same algorithm as above but for the new shit...
			arrowpad_paths_stuff2 = []
			for k in range(len(path2)-1):

				start_key2 = path2[k]
				end_key2 = path2[k+1]

				if start_key2 == end_key2:
					arrowpad_paths_stuff2.append(["A"])
					continue
					assert False
					if start_key2 != "A":

						# arrowpad_paths_stuff.append(["A"])
						arrowpad_paths_stuff2.append(["A"])
						continue
					else:
						continue

				#if start_key != "A":
				#	start_key = int(start_key)
				#if end_key != "A":
				#	end_key = int(end_key)
				#print("from : to == "+str(start_key)+", "+str(end_key))
				# First generate all of the shortest paths in the initial keypad.
				assert (start_key2, end_key2) in SHORTEST_PATHS_ARROWPAD_KEYS
				arrowpad_paths_shit = SHORTEST_PATHS_ARROWPAD_KEYS[(start_key2, end_key2)]
				arrowpad_paths_stuff2.append(arrowpad_paths_shit)
				#print("arrowpad_paths == "+str(arrowpad_paths))





			#print("arrowpad_paths_stuff == "+str(arrowpad_paths_stuff))
			for combination3 in itertools.product(*arrowpad_paths_stuff2):
				path3 = conditional_join(combination3)
				#path3 = "A".join(combination3)
				#path2 = 'A'.join(combination2)
				#path2 = path2[1:] + "A" # Add the final enter.
				path3 = path3+"A"

				#print("path3: "+str(path3))
				# Now check for the shortest path bullshit
				if len(path3) < cur_shortest_path_len:
					cur_shortest_path_len = len(path3)
					cur_shortest_path = path3

	print("Shortest path: "+str(cur_shortest_path))
	exit(1)


def solve(lines: list[str]) -> int: # Solve function.
	'''

	The length of the shortest sequence of button presses you need to type on your directional keypad in order to cause the code to be typed on the numeric keypad; for 029A, this would be 68.
	The numeric part of the code (ignoring leading zeroes); for 029A, this would be 29.

	'''

	output = 0
	for code in lines:
		print("code == "+str(code))
		code = code[:-1]
		assert code[-1] == "A"

		shortest_path = get_shortest_path(code)
		# Now just convert the numeric thing and then multiply with the length
		numeric_part_of_code = code[:-1] # Cut out "A"
		numeric_part_of_code = int(numeric_part_of_code)
		# Now just multiply and add to total.
		output += len(shortest_path)*numeric_part_of_code
	return output


if __name__=="__main__":

	fh = open("input.txt", "r")
	lines = fh.readlines()
	fh.close()

	res = solve(lines)

	print("Result: "+str(res))


	exit(0)

```
{% endraw %}


it works, but obviously it is inefficient as hell.

## Optimizing the code

Ok, so now let's try to atleast get it down to say 100ms .

I asked chatgpt to try to optimize it and let's see what it returned:

{% raw %}
```

def get_shortest_path(code: str) -> str:
    """Generates the shortest path which types this code."""
    # Initialize the shortest path and its length
    cur_shortest_path = ""
    cur_shortest_path_len = float("inf")

    # Add a starting "A" to the code
    code = "A" + code

    # Generate numpad paths
    numpad_path_options = [
        SHORTEST_PATHS_NUMPAD_KEYS[
            (int(code[i]) if code[i] != "A" else "A",
             int(code[i + 1]) if code[i + 1] != "A" else "A")
        ]
        for i in range(len(code) - 1)
    ]

    # Iterate through combinations of numpad paths
    for numpad_combination in itertools.product(*numpad_path_options):
        path = "A" + "".join("A".join(numpad_combination)) + "A"
        arrowpad_path_options = _generate_arrowpad_paths(path)

        for arrowpad_combination in itertools.product(*arrowpad_path_options):
            arrowpad_path = "A" + conditional_join(arrowpad_combination) + "A"
            final_arrowpad_path_options = _generate_arrowpad_paths(arrowpad_path)

            for final_arrowpad_combination in itertools.product(*final_arrowpad_path_options):
                final_path = "A" + conditional_join(final_arrowpad_combination) + "A"
                if len(final_path) < cur_shortest_path_len:
                    cur_shortest_path_len = len(final_path)
                    cur_shortest_path = final_path

    print("Shortest path:", cur_shortest_path)
    return cur_shortest_path

def _generate_arrowpad_paths(path: str):
    """Helper to generate arrowpad paths for a given path."""
    arrowpad_path_options = []
    for i in range(len(path) - 1):
        start_key = path[i]
        end_key = path[i + 1]

        if start_key == end_key:
            arrowpad_path_options.append(["A"])  # Add a single "A" for repeated keys
            continue

        # Assert validity and fetch paths
        assert (start_key, end_key) in SHORTEST_PATHS_ARROWPAD_KEYS
        arrowpad_path_options.append(SHORTEST_PATHS_ARROWPAD_KEYS[(start_key, end_key)])

    return arrowpad_path_options

```
{% endraw %}

let's see...

Here is my current code:

{% raw %}
```

# Dictionary which maps the moves and initial positions to end positions, if the move is not in this dictionary, then it is invalid: "In particular, if a robot arm is ever aimed at a gap where no button is present on the keypad, even for an instant, the robot will panic unrecoverably."

# KEYPAD_MOVES = {}

from shortest_grids import *
from constants import *
import itertools

SHORTEST_PATHS_NUMPAD = generate_shortest_paths_numpad()
SHORTEST_PATHS_ARROWPAD = generate_shortest_paths_arrowpad()



# Now these functions are used to get the shortest paths from a position to another.

def generate_shortest_paths_arrowpad_keys():

	out = dict() # Generate the dictionary

	all_keys = ARROWPAD.keys() # Get the keys.
	for start_key in all_keys:
		for end_key in all_keys:
			if start_key == end_key:
				continue
			start_pos = ARROWPAD[start_key]
			end_pos = ARROWPAD[end_key]
			# res[(start[0], start[1], end[0], end[1])]
			out[(start_key, end_key)] = SHORTEST_PATHS_ARROWPAD[(start_pos[0], start_pos[1], end_pos[0], end_pos[1])]
	return out

def generate_shortest_paths_numpad_keys():
	out = dict() # Generate the dictionary

	all_keys = NUMPAD.keys() # Get the keys.
	for start_key in all_keys:
		for end_key in all_keys:
			if start_key == end_key:
				continue
			start_pos = NUMPAD[start_key]
			end_pos = NUMPAD[end_key]
			# res[(start[0], start[1], end[0], end[1])]
			out[(start_key, end_key)] = SHORTEST_PATHS_NUMPAD[(start_pos[0], start_pos[1], end_pos[0], end_pos[1])]
	return out






SHORTEST_PATHS_NUMPAD_KEYS = generate_shortest_paths_numpad_keys()
SHORTEST_PATHS_ARROWPAD_KEYS = generate_shortest_paths_arrowpad_keys()




def check_valid_numpad(x,y):
	# Checks if the position is valid in
	return


# Just do the thing...

'''

+---+---+---+
| 7 | 8 | 9 |
+---+---+---+
| 4 | 5 | 6 |
+---+---+---+
| 1 | 2 | 3 |
+---+---+---+
	 | 0 | A |
	 +---+---+

'''


# SHORTEST_PATHS_ARROWPAD_INPUT_KEYS
# These are basically the shortest ways to input a character to the second arrowpad from the first. The key is the wanted character and the value is the input into the original arrowpad:

SHORTEST_PATHS_ARROWPAD_INPUT_KEYS =	{"<": "<v<A",
										"^": "<A",
										"v": "<vA",
										">": "vA"}


'''

	 +---+---+
	 | ^ | A |
+---+---+---+
| < | v | > |
+---+---+---+

'''


def keypad_forward(actions, init_pos): # Init pos is the tuple
	assert actions[-1] == "A" # No point in moving if we don't press A, this means that there is a bug somewhere.
	# Applies the actions "actions" to the nine digit display and returns the results...

	# First split on the A button presses.

	press_actions = actions.split("A")


	# This is the location of the "A" character in the numpad.
	x = 2
	y = 3

	for action_seq in press_actions:
		for c in action_seq:
			match c:
				case "<":
					x -= 1
				case ">":
					x += 1

'''

def conditional_join(strings):
	result = []
	for i, s in enumerate(strings):
		# Determine if 'A' should be used as the join character
		if ('A' not in s and
				(i == 0 or not strings[i-1].endswith('A')) and
				(i == len(strings)-1 or not strings[i+1].startswith('A'))):
			result.append('A' + s)
		else:
			result.append(s)
	return ''.join(result)
'''



def conditional_join(strings):
	result = []
	for i, s in enumerate(strings):
		if ((not i == 0 and not strings[i].endswith('A')) and (not strings[i].startswith('A'))):
			result.append('A' + s)
		else:
			result.append(s)
	return ''.join(result)

'''
def conditional_join(strings):
	result = []
	for i, s in enumerate(strings):
		# Determine if 'A' should be used as the join character
		# if ('A' in s and
		if ((i == 0 or not strings[i-1].endswith('A')) and
				(i == len(strings)-1 or not strings[i+1].startswith('A'))):
			result.append('A' + s)
		else:
			result.append(s)
	return ''.join(result)
'''


# Example usage
#strings = ['foo', 'barA', 'baz', 'Aqux', 'zooA']
#joined = conditional_join(strings)
#print(joined)



'''
def get_shortest_path(code) -> str: # Generates the shortest path which types this code.
	# Now generate all of the code changes.

	cur_shortest_path = "" # Current shortest path
	cur_shortest_path_len = 10**9 # Some very big number such that we initialize on the first loop iteration.
	code = "A"+code # We need to start from "A", therefore do this...
	numpad_path_stuff = []

	for i in range(len(code)-1):
		start_key = code[i]
		end_key = code[i+1]
		if start_key != "A":
			start_key = int(start_key)
		if end_key != "A":
			end_key = int(end_key)
		# First generate all of the shortest paths in the initial keypad.
		assert (start_key, end_key) in SHORTEST_PATHS_NUMPAD_KEYS
		numpad_paths = SHORTEST_PATHS_NUMPAD_KEYS[(start_key, end_key)]
		numpad_path_stuff.append(numpad_paths)

	for combination in itertools.product(*numpad_path_stuff):
		# Join the elements of each combination into a string
		path = 'A'.join(combination)
		path_one_layer_up = "".join(list(path))
		path_one_layer_up = "A"+path_one_layer_up+"A" # This must be done because the very first character is "A"
		arrowpad_paths_stuff = []
		for j in range(len(path_one_layer_up)-1):
			start_key = path_one_layer_up[j]
			end_key = path_one_layer_up[j+1]
			if start_key == end_key:
				if start_key != "A":
					# arrowpad_paths_stuff.append(["A"])
					arrowpad_paths_stuff.append(["A"])
					continue
				else:
					continue
			assert (start_key, end_key) in SHORTEST_PATHS_ARROWPAD_KEYS
			arrowpad_paths = SHORTEST_PATHS_ARROWPAD_KEYS[(start_key, end_key)]
			arrowpad_paths_stuff.append(arrowpad_paths)
		for combination2 in itertools.product(*arrowpad_paths_stuff):
			path2 = conditional_join(combination2)
			path2 = path2+"A"
			print("Here is another possible path2: "+str(path2))
			path2 = "A"+path2

			# Now just run the same algorithm as above but for the new shit...
			arrowpad_paths_stuff2 = []
			for k in range(len(path2)-1):
				start_key2 = path2[k]
				end_key2 = path2[k+1]
				if start_key2 == end_key2:
					arrowpad_paths_stuff2.append(["A"])
					continue
					assert False
					if start_key2 != "A":
						arrowpad_paths_stuff2.append(["A"])
						continue
					else:
						continue
				# First generate all of the shortest paths in the initial keypad.
				assert (start_key2, end_key2) in SHORTEST_PATHS_ARROWPAD_KEYS
				arrowpad_paths_shit = SHORTEST_PATHS_ARROWPAD_KEYS[(start_key2, end_key2)]
				arrowpad_paths_stuff2.append(arrowpad_paths_shit)

			for combination3 in itertools.product(*arrowpad_paths_stuff2):
				path3 = conditional_join(combination3)
				path3 = path3+"A"
				if len(path3) < cur_shortest_path_len:
					cur_shortest_path_len = len(path3)
					cur_shortest_path = path3

	print("Shortest path: "+str(cur_shortest_path))
	exit(1)
'''


def get_shortest_path(code: str) -> str:
	"""Generates the shortest path which types this code."""
	# Initialize the shortest path and its length
	cur_shortest_path = ""
	cur_shortest_path_len = float("inf")

	# Add a starting "A" to the code
	code = "A" + code

	# Generate numpad paths
	numpad_path_options = [
		SHORTEST_PATHS_NUMPAD_KEYS[
			(int(code[i]) if code[i] != "A" else "A",
			 int(code[i + 1]) if code[i + 1] != "A" else "A")
		]
		for i in range(len(code) - 1)
	]

	# Iterate through combinations of numpad paths
	for numpad_combination in itertools.product(*numpad_path_options):
		path = "A" + "".join("A".join(numpad_combination)) + "A"
		arrowpad_path_options = _generate_arrowpad_paths(path)

		for arrowpad_combination in itertools.product(*arrowpad_path_options):
			arrowpad_path = "A" + conditional_join(arrowpad_combination) + "A"
			final_arrowpad_path_options = _generate_arrowpad_paths(arrowpad_path)

			for final_arrowpad_combination in itertools.product(*final_arrowpad_path_options):
				final_path = "A" + conditional_join(final_arrowpad_combination) + "A"
				if len(final_path) < cur_shortest_path_len:
					cur_shortest_path_len = len(final_path)
					cur_shortest_path = final_path
	cur_shortest_path = cur_shortest_path[1:] # Cut out the "A"
	print("Shortest path:", cur_shortest_path)
	return cur_shortest_path

def _generate_arrowpad_paths(path: str):
	"""Helper to generate arrowpad paths for a given path."""
	arrowpad_path_options = []
	for i in range(len(path) - 1):
		start_key = path[i]
		end_key = path[i + 1]

		if start_key == end_key:
			arrowpad_path_options.append(["A"])  # Add a single "A" for repeated keys
			continue

		# Assert validity and fetch paths
		assert (start_key, end_key) in SHORTEST_PATHS_ARROWPAD_KEYS
		arrowpad_path_options.append(SHORTEST_PATHS_ARROWPAD_KEYS[(start_key, end_key)])

	return arrowpad_path_options



def solve(lines: list[str]) -> int: # Solve function.
	'''

	The length of the shortest sequence of button presses you need to type on your directional keypad in order to cause the code to be typed on the numeric keypad; for 029A, this would be 68.
	The numeric part of the code (ignoring leading zeroes); for 029A, this would be 29.

	'''

	output = 0
	for code in lines:
		print("code == "+str(code))
		code = code[:-1]
		assert code[-1] == "A"

		shortest_path = get_shortest_path(code)
		# Now just convert the numeric thing and then multiply with the length
		numeric_part_of_code = code[:-1] # Cut out "A"
		numeric_part_of_code = int(numeric_part_of_code)
		# Now just multiply and add to total.
		output += len(shortest_path)*numeric_part_of_code
	return output


if __name__=="__main__":

	fh = open("input.txt", "r")
	lines = fh.readlines()
	fh.close()

	res = solve(lines)

	print("Result: "+str(res))


	exit(0)

```
{% endraw %}

maybe we should add a verify function which verifies if this solution makes sense by just simulating the shit?

Also maybe program a visualizing function which shows the positions of all of these things?????

Also the code is still slow as hell, let's improve it further.

Let's take a look at the cProfile shit:

{% raw %}
```


   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
      3/1    0.000    0.000   13.594   13.594 {built-in method builtins.exec}
        1    0.000    0.000   13.594   13.594 maincleaned.py:1(<module>)
        1    0.000    0.000   13.588   13.588 maincleaned.py:308(solve)
        1    0.411    0.411   13.588   13.588 maincleaned.py:245(get_shortest_path)
   589952    7.077    0.000   13.113    0.000 maincleaned.py:137(conditional_join)
 16713090    2.252    0.000    2.252    0.000 {method 'endswith' of 'str' objects}
 14844994    1.952    0.000    1.952    0.000 {method 'startswith' of 'str' objects}
 17306922    1.640    0.000    1.640    0.000 {method 'append' of 'list' objects}
   589974    0.193    0.000    0.193    0.000 {method 'join' of 'str' objects}
   600688    0.052    0.000    0.052    0.000 {built-in method builtins.len}
      131    0.003    0.000    0.013    0.000 maincleaned.py:283(_generate_arrowpad_paths)
      134    0.010    0.000    0.010    0.000 {built-in method builtins.print}
        1    0.000    0.000    0.004    0.004 shortest_grids.py:61(generate_shortest_paths_numpad)
      130    0.002    0.000    0.004    0.000 shortest_grids.py:13(bfs_shortest_paths)
     4232    0.001    0.000    0.002    0.000 shortest_grids.py:8(is_valid)
      2/1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:1349(_find_and_load)
      2/1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:1304(_find_and_load_unlocked)
      260    0.000    0.000    0.000    0.000 shortest_grids.py:48(path_to_string)
        1    0.000    0.000    0.000    0.000 shortest_grids.py:91(generate_shortest_paths_arrowpad)
      2/1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:911(_load_unlocked)
      2/1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:989(exec_module)
      4/2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:480(_call_with_frames_removed)
        1    0.000    0.000    0.000    0.000 shortest_grids.py:1(<module>)
     1602    0.000    0.000    0.000    0.000 {method 'append' of 'collections.deque' objects}
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1062(get_code)
     1732    0.000    0.000    0.000    0.000 {method 'popleft' of 'collections.deque' objects}
     1058    0.000    0.000    0.000    0.000 {method 'add' of 'set' objects}
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:1240(_find_spec)
        1    0.000    0.000    0.000    0.000 maincleaned.py:32(generate_shortest_paths_numpad_keys)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1520(find_spec)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1491(_get_spec)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1183(get_data)
        1    0.000    0.000    0.000    0.000 {method 'disable' of '_lsprof.Profiler' objects}
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1593(find_spec)
      729    0.000    0.000    0.000    0.000 {built-in method builtins.isinstance}
        2    0.000    0.000    0.000    0.000 {built-in method _io.open_code}
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:416(__enter__)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:806(module_from_spec)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:733(_init_module_attrs)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:304(acquire)
      262    0.000    0.000    0.000    0.000 {method 'pop' of 'list' objects}
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:751(_compile_bytecode)
        4    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:482(cache_from_source)
        1    0.000    0.000    0.000    0.000 <frozen _sitebuiltins>:19(__call__)
        2    0.000    0.000    0.000    0.000 {built-in method marshal.loads}
        4    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:632(cached)
        1    0.000    0.000    0.000    0.000 {built-in method _io.open}
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:611(_get_cached)
        6    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:140(_path_stat)
        2    0.000    0.000    0.000    0.000 {method 'close' of '_io.TextIOWrapper' objects}
        6    0.000    0.000    0.000    0.000 {built-in method posix.stat}
       12    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:126(_path_join)
        1    0.000    0.000    0.000    0.000 {method 'readlines' of '_io._IOBase' objects}
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:162(__enter__)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1588(_get_spec)
        2    0.000    0.000    0.000    0.000 {method 'read' of '_io.BufferedReader' objects}
        4    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:132(_path_split)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:426(_get_module_lock)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:124(setdefault)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:159(_path_isfile)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:802(spec_from_file_location)
        2    0.000    0.000    0.000    0.000 __init__.py:89(find_spec)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:150(_path_is_mode_type)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:420(__exit__)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:666(_classify_pyc)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1202(path_stats)
        4    0.000    0.000    0.000    0.000 {built-in method builtins.max}
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1469(_path_importer_cache)
        1    0.000    0.000    0.000    0.000 maincleaned.py:17(generate_shortest_paths_arrowpad_keys)
        2    0.000    0.000    0.000    0.000 {method '__exit__' of '_io._IOBase' objects}
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:372(release)
        6    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:84(_unpack_uint32)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:1128(find_spec)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:699(_validate_timestamp_pyc)
        1    0.000    0.000    0.000    0.000 constants.py:1(<module>)
        2    0.000    0.000    0.000    0.000 {built-in method posix.getcwd}
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:74(__new__)
        8    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:134(<genexpr>)
        2    0.000    0.000    0.000    0.000 <frozen codecs>:319(decode)
       28    0.000    0.000    0.000    0.000 {method 'rstrip' of 'str' objects}
       14    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:491(_verbose_message)
        8    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:1226(__exit__)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:185(_path_abspath)
        8    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:1222(__enter__)
       14    0.000    0.000    0.000    0.000 {built-in method builtins.getattr}
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:445(cb)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:232(__init__)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:82(remove)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:982(find_spec)
       10    0.000    0.000    0.000    0.000 {method 'rpartition' of 'str' objects}
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:180(_path_isabs)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:643(_check_name_wrapper)
        1    0.000    0.000    0.000    0.000 <frozen codecs>:309(__init__)
       12    0.000    0.000    0.000    0.000 {built-in method _imp.acquire_lock}
        2    0.000    0.000    0.000    0.000 {built-in method builtins.locals}
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:173(__exit__)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:48(_new_module)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:79(__init__)
       12    0.000    0.000    0.000    0.000 {built-in method _imp.release_lock}
        2    0.000    0.000    0.000    0.000 {method 'format' of 'str' objects}
        6    0.000    0.000    0.000    0.000 {method 'get' of 'dict' objects}
        1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:1390(_handle_fromlist)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:645(parent)
        4    0.000    0.000    0.000    0.000 {method 'rfind' of 'str' objects}
        2    0.000    0.000    0.000    0.000 {built-in method _imp.is_builtin}
        5    0.000    0.000    0.000    0.000 {built-in method builtins.hasattr}
        6    0.000    0.000    0.000    0.000 {built-in method from_bytes}
        2    0.000    0.000    0.000    0.000 {built-in method _imp.find_frozen}
        4    0.000    0.000    0.000    0.000 {method '__exit__' of '_thread.RLock' objects}
        6    0.000    0.000    0.000    0.000 {built-in method posix.fspath}
        2    0.000    0.000    0.000    0.000 {built-in method _codecs.utf_8_decode}
        4    0.000    0.000    0.000    0.000 {built-in method _thread.get_ident}
        2    0.000    0.000    0.000    0.000 {built-in method __new__ of type object at 0xa43b40}
        2    0.000    0.000    0.000    0.000 {method 'pop' of 'dict' objects}
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:599(__init__)
        2    0.000    0.000    0.000    0.000 {built-in method _imp._fix_co_filename}
        2    0.000    0.000    0.000    0.000 {built-in method _weakref._remove_dead_weakref}
        2    0.000    0.000    0.000    0.000 {built-in method _thread.allocate_lock}
        2    0.000    0.000    0.000    0.000 {method 'remove' of 'list' objects}
        2    0.000    0.000    0.000    0.000 {method 'keys' of 'dict' objects}
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:412(__init__)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1153(__init__)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:158(__init__)
        1    0.000    0.000    0.000    0.000 {method 'items' of 'dict' objects}
        2    0.000    0.000    0.000    0.000 __init__.py:96(<lambda>)
        1    0.000    0.000    0.000    0.000 <frozen codecs>:260(__init__)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:653(has_location)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1178(get_filename)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:986(create_module)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:71(_relax_case)

```
{% endraw %}

so the conditional_join function is the obvious bottleneck

Here is the original version:

{% raw %}
```

def conditional_join(strings):
	result = []
	for i, s in enumerate(strings):
		if ((not i == 0 and not strings[i].endswith('A')) and (not strings[i].startswith('A'))):
			result.append('A' + s)
		else:
			result.append(s)
	return ''.join(result)

```
{% endraw %}

actually this code seems to work just fine:

{% raw %}
```



```
{% endraw %}










