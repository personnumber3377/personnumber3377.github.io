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

let's try to understand how it works... except it doesn't because it assumes that the numpad is starts always at (2,2) fuck.

## Banging my head against the wall

Ok, so this legit actually has me stumped. Let's try atleast something. My thinking is to generate all possible paths which encode the button presses and then memoize that shit in a huge lookup table which get's filled in dynamically as the codes are being typed. I am going to assume that the shortest possible typing shit is which is also the shortest path on the numpad.

Ok, so now I have a table for the initial numpad for the shortest bullshit:

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

and here is the test program:

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

and here is the output:

```

Shortest paths from A to 7: ['^<<^^', '^<^<^', '^<^^<', '^^<<^', '^^<^<', '^^^<<']

```

which seems correct. Note that the initialization of these tables is a one time cost only, so we don't really need to be concerned about performance all that much.

Ok, so let's add a couple of more helper functions to instead use the key symbols instead of coordinates.

Done!

Ok so now we know the shortest distances from any place in the keypad and the control keyboards to any other place in the boards. Now what?

My idea is to just iterate over the possible shortest paths in the the keypad and then figure out the shortest in the first robot panel?????

Let's do something like that. I honestly have no idea what I am doing but let's try it anyway...

Now actually reading this challenge closely I noticed that there is a very important thing which makes this atleast somewhat easier: "All robots will initially aim at the keypad's A key, wherever it is." now when we type a code, the last character of the code should always be "A" and since we press it we are pointing at the A on the other panels too, this basically means that we do not need to worry about state changes accross codes. This simplifies a lot. I have this feeling that this will change in part2 but that is a problem for then. This also means that we do not need to even figure out the changes between the different characters of the code, because we always go to the same state when we press.


















