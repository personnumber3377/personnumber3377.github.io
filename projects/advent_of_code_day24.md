
# Day 24

This problem is basically a path finding puzzle, but with extra constraints. Instead of us washing over the entire grid, now this so called "grid" changes layout on each timestep with the blizzards. My first thought to have a list of positions and the step counters and for each position in these positions create five more positions for each move, aka bruteforce each possible path. Then to improve performance we can check these positions against the blizzards to see if we have collided with a blizzard. Then if yes, we remove this position from the list.

Now my first try was to use a list of lists for the blizzards, but then that is very slow for collision checking, so instead of that, I used dictionaries. The problem with dicts is obvious collisions, when multiple blizzards are at the same spot and we use the coordinates as keys into the dict, we get collisions. One way to circumvent is to make the values contained in the dictionary as a list of directions of each of the blizzards at that spot.

Now, the logic to check for the multiple blizzards in one spot is actually quite tricky, because you can not move the blizzards, because you are moving a spot at a time and then you will move the same blizzard many times. Instead of that maybe I should implement a counter also associated with every blizzard to see if it has already been moved or not. This is not efficient but maybe I will improve this logic later.

---------------------

When implementing the logic with dictionaries I ran into this peculiar problem when trying to modify a dict in a loop:

```

def update_blizzards(blizzards: dict, counter: int) -> list:
	# update blizzards according to the rules.

	#for coords in blizzards: # I hope there is a more pythonic way to modify each element in a list. if you try to do for bliz in blizzards: ... then you are not actually modifying the original list, but copies of the objects or something like that.


	# NOTE: If we tried the above, then we would get a "RuntimeError: dictionary changed size during iteration" error.


	#for coords in tuple(blizzards.keys()):
	for coords in blizzards:
		#move = blizzards[i][1]

		
		#move = blizzards[coords]
		moves = blizzards[coords]


		# Can not do this because we can have multiple blizzards at the same spot.

		# <comment>
		'''
		offset = OFFSETS[move]


		# move blizzard. here we do not need to do collision checking, because two blizzards or more blizzards can be at the same spot.

		#blizzards[i][0][0] += offset[0]
		#blizzards[i][0][1] += offset[1]

		# instead of using a list of lists, lets just use a dictionary with the coordinates as keys. it is a lot faster

		new_coords = [coords[0]+offset[0], coords[1]+offset[1]]

		del blizzards[coords] # delete old position.

		blizzards[new_coords] = move 
		'''

		# </comment>

		#new_stuff = []

		for ind, move in enumerate(moves):
			actual_move = move[0]

			count = move[1]

			if count != counter:


				offset = OFFSETS[actual_move]

				new_coords = [coords[0]+offset[0], coords[1]+offset[1]]

				if new_coords not in blizzards:
					blizzards[new_coords] = [[actual_move, counter]]
				else:
					blizzards[new_coords] += [[actual_move, counter]]



				#new_stuff.append([new_coords, actual_move])

			blizzards[coords].pop(ind) # delete it from the list

		# check if there are any blizzards left at that spot:

		if len(blizzards[coords]) == 0:

			del blizzards[coords]


	return blizzards



```

This returns this error:

```

RuntimeError: dictionary changed size during iteration


```

Now, I know that dictionaries are basically hashmaps internally where the object is first hashed by a hashing function and then the object is placed into memory at an index indicated by the hash, but I do not really understand why I can not modify the dictionary like that. If I use `for coords in tuple(blizzards.keys()):` instead, then it works. I think the for x in dictionary: loop accesses the keys of the dictionary as a reference and not as a value and that screws things up. I think that this is also less efficient because I need to generate copies of the keys of the dictionary each time I run this loop, but oh well. I guess I will figure that out later.

Now, I also wrote a quick test function to test the function to move the blizzards:

```

from naive_part1 import update_blizzards

# def update_blizzards(blizzards: dict, counter: int) -> list:

'''

DIRS = {UP_SYM: 0, LEFT_SYM: 1, DOWN_SYM: 2, RIGHT_SYM: 3}

UP = 0
LEFT = 1
DOWN = 2
RIGHT = 3

OFFSETS = {UP: [0,1], LEFT: [-1,0], DOWN: [0,-1], RIGHT:[1,0]}

'''












if __name__=="__main__":

	test_bliz = {(3, 6): [[0,0]], (4, 10): [[3,0]], (0,1): [[2,0]]}
	print("Before: "+str(test_bliz))
	update_blizzards(test_bliz, 0)

	print("After: "+str(test_bliz))



	exit(0)



```

And it now returns this:

```

Before: {(3, 6): [[0, 0]], (4, 10): [[3, 0]], (0, 1): [[2, 0]]}
After: {}


```

So obviously something is going wrong. As it turns out the test function should be called like so: `update_blizzards(test_bliz, 1)` and then also I forgot to indent the `blizzards[coords].pop(ind)` line.

Now that I have actually parsed the input, it is time to actually get into the meat and potatoes of the problem aka solving the fastest route to the end.

-------------------------------


After a bit of fiddling around I came up with this as the method to find the route:

```


import sys
import copy



PART = 1
DEBUG = False


EXAMPLE_ONE = False

#EXAMPLE_PATH = ["placeholder", [0,0], ] # This is the shortest path which the elf takes in the example. The point of this is to check that these positions appear in the steps taken.
#EXAMPLE_PATH = ["placeholder", [0, 0], [0, 1], [0, 2], [0, 2], [0, 1], [1, 1], [2, 1], [2, 2], [1, 2], [1, 1], [2, 1], [2, 1], [2, 2], [2, 3], [3, 3], [4, 3], [5, 3], [5, 4], [5, 5]]

#EXAMPLE_PATH = ["placeholder", [0, 0], [0, 1], [0, 1], [0, 0], [1, 0], [2, 0], [2, 1], [1, 1], [1, 0], [2, 0], [2, 0], [2, 1], [2, 2], [3, 2], [4, 2], [5, 2], [5, 3], [5, 4]]
EXAMPLE_PATH = ["placeholder", [0, 0], [0, 1], [0, 1], [0, 0], [1, 0], [2, 0], [2, 1], [1, 1], [1, 0], [2, 0], [2, 0], [2, 1], [2, 2], [3, 2], [4, 2], [5, 2], [5, 3], [5, 4]]
'''
UP_SYM = "^"
DOWN_SYM = "v"
LEFT_SYM = "<"
RIGHT_SYM = ">"
'''


#EXAMPLE_BLIZZARDS = [{(0, 1), (1, 3), (4, 0), (4, 3), (3, 1), (5, 3), (0, 3), (0, 2), (1, 0), (4, 1)}, {(1, 3), (1, 2), (4, 3), (1, 1), (2, 0), (5, 1), (4, 2), (4, 1), (5, 2)}, {(1, 2), (2, 1), (0, 0), (2, 0), (2, 3), (0, 2), (3, 3), (1, 0), (3, 2)}, {(0, 1), (4, 3), (3, 1), (1, 1), (4, 2), (0, 2), (1, 0), (3, 2), (1, 3)}, {(0, 1), (4, 0), (1, 2), (2, 1), (2, 0), (5, 1), (5, 0), (2, 2), (3, 2)}, {(2, 1), (0, 0), (3, 1), (0, 3), (5, 1), (3, 0), (0, 2), (5, 0), (5, 3), (3, 2), (5, 2)}, {(0, 1), (1, 2), (3, 1), (1, 1), (0, 3), (4, 2), (3, 0), (0, 2), (2, 2), (5, 3), (3, 2)}, {(4, 0), (2, 1), (3, 1), (2, 0), (5, 1), (2, 3), (3, 3), (1, 0), (5, 2)}, {(1, 3), (4, 0), (2, 1), (0, 0), (4, 3), (1, 1), (4, 2), (3, 0), (2, 3), (0, 2), (3, 3), (2, 2), (4, 1)}, {(0, 1), (4, 0), (1, 2), (2, 1), (2, 3), (0, 2), (3, 3), (3, 2), (4, 1)}, {(0, 1), (1, 3), (2, 1), (4, 3), (1, 1), (5, 1), (4, 2), (3, 0), (5, 0), (1, 0), (4, 1)}, {(4, 0), (4, 3), (5, 1), (0, 2), (1, 0), (1, 3), (4, 2), (3, 0), (3, 3), (5, 0), (5, 3), (1, 2), (3, 2), (4, 1), (5, 2), (0, 0), (1, 1), (0, 3), (2, 3)}, {(0, 1), (1, 3), (4, 0), (4, 3), (3, 1), (5, 3), (0, 3), (0, 2), (1, 0), (4, 1)}, {(1, 3), (1, 2), (4, 3), (1, 1), (2, 0), (5, 1), (4, 2), (4, 1), (5, 2)}, {(1, 2), (2, 1), (0, 0), (2, 0), (2, 3), (0, 2), (3, 3), (1, 0), (3, 2)}, {(0, 1), (4, 3), (3, 1), (1, 1), (4, 2), (0, 2), (1, 0), (3, 2), (1, 3)}, {(0, 1), (4, 0), (1, 2), (2, 1), (2, 0), (5, 1), (5, 0), (2, 2), (3, 2)}, {(2, 1), (0, 0), (3, 1), (0, 3), (5, 1), (3, 0), (0, 2), (5, 0), (5, 3), (3, 2), (5, 2)}]

EXAMPLE_BLIZZARDS = [{(4, 0), (4, 3), (5, 1), (0, 2), (1, 0), (1, 3), (4, 2), (3, 0), (3, 3), (5, 0), (5, 3), (1, 2), (3, 2), (4, 1), (5, 2), (0, 0), (1, 1), (0, 3), (2, 3)}, {(0, 1), (1, 3), (4, 0), (1, 2), (4, 3), (3, 1), (5, 3), (0, 3), (2, 0), (4, 2), (0, 2), (1, 0), (3, 2), (4, 1)}, {(1, 3), (1, 2), (2, 1), (4, 3), (3, 1), (1, 1), (2, 0), (5, 1), (4, 2), (3, 0), (2, 2), (1, 0), (4, 1), (5, 2)}, {(4, 0), (1, 2), (2, 1), (0, 0), (1, 1), (2, 0), (3, 0), (2, 3), (0, 2), (3, 3), (2, 2), (1, 0), (3, 2), (4, 1)}, {(0, 1), (4, 0), (1, 2), (4, 3), (3, 1), (1, 1), (4, 2), (2, 3), (0, 2), (3, 3), (5, 0), (1, 0), (3, 2), (1, 3)}, {(0, 1), (4, 0), (1, 2), (2, 1), (0, 0), (4, 3), (2, 0), (5, 1), (4, 2), (5, 0), (2, 2), (3, 2), (1, 3), (5, 2)}, {(2, 1), (0, 0), (3, 1), (1, 1), (0, 3), (5, 3), (5, 1), (4, 2), (3, 0), (0, 2), (5, 0), (1, 0), (3, 2), (4, 1), (5, 2)}, {(0, 1), (4, 0), (1, 2), (3, 1), (1, 1), (0, 3), (2, 0), (5, 3), (4, 2), (3, 0), (0, 2), (2, 2), (1, 0), (3, 2), (4, 1)}, {(4, 0), (1, 2), (2, 1), (4, 3), (3, 1), (2, 0), (5, 1), (3, 0), (2, 3), (3, 3), (2, 2), (1, 0), (1, 3), (5, 2)}, {(1, 3), (4, 0), (1, 2), (2, 1), (0, 0), (4, 3), (1, 1), (2, 0), (4, 2), (3, 0), (2, 3), (0, 2), (3, 3), (2, 2), (3, 2), (4, 1)}, {(0, 1), (4, 0), (1, 2), (2, 1), (3, 1), (1, 1), (4, 2), (2, 3), (0, 2), (3, 3), (5, 0), (1, 0), (3, 2), (4, 1)}, {(0, 1), (1, 3), (4, 0), (2, 1), (0, 0), (4, 3), (1, 1), (5, 1), (4, 2), (3, 0), (5, 0), (2, 2), (1, 0), (4, 1), (5, 2)}, {(4, 0), (4, 3), (5, 1), (0, 2), (1, 0), (1, 3), (4, 2), (3, 0), (3, 3), (5, 0), (5, 3), (1, 2), (3, 2), (4, 1), (5, 2), (0, 0), (1, 1), (0, 3), (2, 3)}, {(0, 1), (1, 3), (4, 0), (1, 2), (4, 3), (3, 1), (5, 3), (0, 3), (2, 0), (4, 2), (0, 2), (1, 0), (3, 2), (4, 1)}, {(1, 3), (1, 2), (2, 1), (4, 3), (3, 1), (1, 1), (2, 0), (5, 1), (4, 2), (3, 0), (2, 2), (1, 0), (4, 1), (5, 2)}, {(4, 0), (1, 2), (2, 1), (0, 0), (1, 1), (2, 0), (3, 0), (2, 3), (0, 2), (3, 3), (2, 2), (1, 0), (3, 2), (4, 1)}, {(0, 1), (4, 0), (1, 2), (4, 3), (3, 1), (1, 1), (4, 2), (2, 3), (0, 2), (3, 3), (5, 0), (1, 0), (3, 2), (1, 3)}, {(0, 1), (4, 0), (1, 2), (2, 1), (0, 0), (4, 3), (2, 0), (5, 1), (4, 2), (5, 0), (2, 2), (3, 2), (1, 3), (5, 2)}, {(2, 1), (0, 0), (3, 1), (1, 1), (0, 3), (5, 3), (5, 1), (4, 2), (3, 0), (0, 2), (5, 0), (1, 0), (3, 2), (4, 1), (5, 2)}]

# {(1, 3), (1, 2), (4, 3), (1, 1), (2, 0), (5, 1), (4, 2), (4, 1), (5, 2)}, {(1, 2), (2, 1), (0, 0), (2, 0), (2, 3), (0, 2), (3, 3), (1, 0), (3, 2)}

UP_SYM = ord("^")
DOWN_SYM = ord("v")
LEFT_SYM = ord("<")
RIGHT_SYM = ord(">")


DIRS = {UP_SYM: 0, LEFT_SYM: 1, DOWN_SYM: 2, RIGHT_SYM: 3}

UP = 0
LEFT = 1
DOWN = 2
RIGHT = 3

OFFSETS = {UP: [0,-1], LEFT: [-1,0], DOWN: [0,1], RIGHT:[1,0]}

#OFFSETS = {UP: [0,-1], LEFT: [-1,0], DOWN: [0,1], RIGHT:[1,0]}


def fail(msg: str) -> None:
	print("[FAIL] "+str(msg))
	exit(1)

def debug(msg: str) -> None:
	if DEBUG:
		print("[DEBUG] "+str(msg))
	return






def parse_1():

	debug("Parsing input.")

	raw_in = sys.stdin.buffer.read()

	lines = raw_in.split(b"\n")

	debug("Lines: "+str(lines))
	width = len(lines[0]) - 2 # - 2 because first and last are walls.

	height = len(lines) - 2

	#blizzards = []  # a list of lists. first element in sublist is the coordinates as a tuple and the second element is the direction

	blizzards = {} # change of plan. Implement blizzards as a dictionary with the coordinates as key and the move direction as val.


	for y, line in enumerate(lines[1:-1]): # skip first and last lines

		debug("Line: "+str(line))

		for x, spot in enumerate(line[1:-1]): # skip first and last spot which are walls.

			debug("Spot: "+str(spot))

			if spot in DIRS:
				debug("Spot: "+str(spot))
				result = [[x,y],DIRS[spot]]

				blizzards[tuple((x,y))] = [[DIRS[spot],0]] # first the direction and then the counter.

	return width, height, blizzards





def parse_input():
	if PART == 1:
		return parse_1()



#def update_blizzards(blizzards: dict, width: int, height: int, counter: int) -> list:
def update_blizzards(blizzards: dict, counter: int, width: int, height: int) -> list:
	# update blizzards according to the rules.

	#for coords in blizzards: # I hope there is a more pythonic way to modify each element in a list. if you try to do for bliz in blizzards: ... then you are not actually modifying the original list, but copies of the objects or something like that.
	debug("counter: "+str(counter))
	debug("width: "+str(width))
	debug("height: "+str(height))

	# NOTE: If we tried the above, then we would get a "RuntimeError: dictionary changed size during iteration" error.


	#for coords in tuple(blizzards.keys()):
	#for coords in blizzards:

	for coords in tuple(blizzards.keys()):

		#move = blizzards[i][1]

		
		#move = blizzards[coords]
		moves = blizzards[coords]

		new_list = copy.deepcopy(moves)


		# Can not do this because we can have multiple blizzards at the same spot.

		# <comment>
		'''
		offset = OFFSETS[move]


		# move blizzard. here we do not need to do collision checking, because two blizzards or more blizzards can be at the same spot.

		#blizzards[i][0][0] += offset[0]
		#blizzards[i][0][1] += offset[1]

		# instead of using a list of lists, lets just use a dictionary with the coordinates as keys. it is a lot faster

		new_coords = [coords[0]+offset[0], coords[1]+offset[1]]

		del blizzards[coords] # delete old position.

		blizzards[new_coords] = move 
		'''

		# </comment>

		#new_stuff = []

		for ind, move in enumerate(moves):
			actual_move = move[0]

			count = move[1]

			if count != counter:


				offset = OFFSETS[actual_move]

				#new_coords = (coords[0]+offset[0], coords[1]+offset[1])
				new_coords = [coords[0]+offset[0], coords[1]+offset[1]]
				# check for loop around.

				if new_coords[0] < 0:
					
					assert new_coords[0] == -1
					new_coords[0] = width - 1 # going left so spawn on the right

				elif new_coords[0] == width:
					
					new_coords[0] = 0 # loop around going to the right and spawn on the left
				
				elif new_coords[1] < 0:
					
					assert new_coords[1] == -1
					new_coords[1] = height - 1
				
				elif new_coords[1] == height:

					new_coords[1] = 0

				new_coords = tuple(new_coords)

				if new_coords not in blizzards:
					blizzards[new_coords] = [[actual_move, counter]]
				else:
					blizzards[new_coords] += [[actual_move, counter]]



				#new_stuff.append([new_coords, actual_move])

				#blizzards[coords].pop(ind) # delete it from the list # another note: we can not do this because it messes up the loop i think

				#blizzards[coords].remove(move)
				new_list.remove(move)
		blizzards[coords] = new_list
		# check if there are any blizzards left at that spot:

		if len(blizzards[coords]) == 0:

			del blizzards[coords]


	return blizzards


def generate_new_positions(prev_pos: list) -> list:

	# Generates all of the possible positions based on the previous possible positions.

	#new_pos = []

	new_pos = set()

	for pos in prev_pos:
		'''
		new_pos.append((pos[0],pos[1])) # stay in place
		new_pos.append((pos[0],pos[1]+1)) # up
		new_pos.append((pos[0],pos[1]-1)) # down
		new_pos.append((pos[0]-1,pos[1])) # left
		new_pos.append((pos[0]+1,pos[1])) # right
		'''

		new_pos.add((pos[0],pos[1])) # stay in place
		new_pos.add((pos[0],pos[1]+1)) # up
		new_pos.add((pos[0],pos[1]-1)) # down
		new_pos.add((pos[0]-1,pos[1])) # left
		new_pos.add((pos[0]+1,pos[1])) # right


	# Delete the previous position list to improve memory performance

	del prev_pos

	return new_pos

import numpy as np
from PIL import Image



def render_mat(mat):

	qr_matrix = np.invert(mat.astype(bool), dtype=bool).T
	print(qr_matrix.astype(int))
	qr_matrix = qr_matrix.astype(np.uint8)
	im = Image.fromarray(qr_matrix * 255)
	im.show()

def render_stuff(things, size):
	#return

	matrix = np.zeros((size,size))

	for thing in things:

		matrix[thing[0],thing[1]] = 1

	render_mat(matrix)

	return


# all_possible_positions = cut_blizzards(all_possible_positions, blizzards)

def cut_blizzards(positions: list, blizzards: list) -> list:

	#assert isinstance(positions, list)
	debug("Type of \"positions\" == "+str(type(positions)))

	for pos in list(positions):
		if pos in blizzards:
			positions.remove(pos)
	return positions



def bounds_check(positions: list, width: int, height: int) -> list:

	for pos in list(positions):
		if pos[0] < 0:
			positions.remove(pos)
		elif pos[0] > width - 1:
			positions.remove(pos)
		elif pos[1] < 0:
			positions.remove(pos)
		elif pos[1] > height - 1:
			positions.remove(pos)

	return positions



def check_bliz(correct_blizzards, blizzards):

	f = False
	debug("="*30)
	debug("Correct blizzards: "+str(correct_blizzards))
	debug("Our blizzards: "+str(blizzards))
	for bliz in blizzards:
		if bliz not in correct_blizzards:

			f = True

			debug("Blizzard "+str(bliz)+" is in blizzards, but should not be!")

	for bliz in correct_blizzards:
		if bliz not in blizzards:
			debug("Blizzard "+str(bliz)+" not in blizzards, when it should be!")

	if f:
		debug("="*30)
		fail("Blizzard check failed!")



	debug("="*30)
	debug("Blizzard check passed!")

	return

def solve_part_one() -> int:

	# init vars

	n = 0
	
	blizzards = {}

	width, height, blizzards = parse_input()



	# Skip forward until very first tile is available in the top left.
	debug("Blizzards: "+str(blizzards)+" .")
	debug("Showing blizzards.")

	#render_stuff(blizzards, 10)

	debug("Skipping forward:")
	while True:

		if (0,0) not in blizzards:
			break
		n += 1
		update_blizzards(blizzards, n, width, height)

	debug("Skipped "+str(n)+" steps!")

	# Now that the very first space is empty, we can actually start.

	all_possible_positions = [(0,0)]

	end = tuple((width-1, height-1))

	
	# Solve path


	while True: # continue until end has been reached.

		#return
		debug("n == "+str(n))
		# First generate all the possible positions from the all of the previous possible positions. (Aka the number of previous positions multiplied by 5).

		all_possible_positions = generate_new_positions(all_possible_positions)

		debug("All possible steps: "+str(all_possible_positions))

		# Check for done

		if end in all_possible_positions:
			break

		# Update blizzards

		blizzards = update_blizzards(blizzards, n, width, height)
		#render_stuff(blizzards, 10)
		# Cut out unwanted positions

		# First take out positions which are now in blizzards

		all_possible_positions = cut_blizzards(all_possible_positions, blizzards)
		debug("After blizzards: "+str(all_possible_positions))
		debug("Blizzards: "+str(blizzards))
		# Take out positions which are out of bounds.

		all_possible_positions = bounds_check(all_possible_positions, width, height)

		

		# Check example path.
		if EXAMPLE_ONE:

			debug("Testing blizzards")


			correct_blizzards = EXAMPLE_BLIZZARDS[n]

			check_bliz(correct_blizzards, blizzards)


			debug("poopoo")
			if n >= len(EXAMPLE_PATH) - 1:
				continue
			correct_move = EXAMPLE_PATH[n]
			debug("Correct thing: "+str(correct_move))
			if tuple(correct_move) not in all_possible_positions:
				debug("Correct move: "+str(correct_move))
				print("All possible positions: "+str(all_possible_positions))
				fail("OOF!")
			debug("Passed move test!")
		n += 1

		

	return n + 1 # +1 because we need to account for the final step.

def solve_part_two() -> int:
	# placeholder
	return 0



def solve_puzzle() -> int:
	if PART==1:
		return solve_part_one()
	elif PART==2:
		return solve_part_two()
	else:
		fail("Invalid puzzle part number ("+str(PART)+") .")



if __name__=="__main__":

	print("Solution to puzzle: "+str(solve_puzzle()))



```


This works for the small example, but the efficiency is donkey shit. I had problems in the update_blizzards function with updating the dictionary, because you can not update elements in the lists in the dictionary when you are iterating over it. You can see my frustration through the commented out code.

Time to make it faster for the actual input!

Start with cProfile as usual.

The program hangs when trying to process the big input, so I capped it to 1000 cycles and here it the report:

```

Solution to puzzle: 1001
         103254779 function calls (88503338 primitive calls) in 38.447 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
12993163/1931317   12.947    0.000   29.198    0.000 copy.py:128(deepcopy)
     1000    6.877    0.007   36.786    0.037 naive_part1.py:109(update_blizzards)
5618599/1931317    6.064    0.000   24.748    0.000 copy.py:200(_deepcopy_list)
  5618599    3.346    0.000    4.456    0.000 copy.py:242(_keep_alive)
 25986915    2.431    0.000    2.431    0.000 {method 'get' of 'dict' objects}
 26161696    2.427    0.000    2.427    0.000 {built-in method builtins.id}
        1    1.506    1.506   38.304   38.304 naive_part1.py:332(solve_part_one)
 14752958    1.333    0.000    1.333    0.000 {method 'append' of 'list' objects}
  7374564    0.650    0.000    0.650    0.000 copy.py:182(_deepcopy_atomic)
  2704301    0.512    0.000    0.512    0.000 {method 'remove' of 'list' objects}
1936896/1936726    0.199    0.000    0.199    0.000 {built-in method builtins.len}
      147    0.015    0.000    0.015    0.000 {built-in method marshal.loads}
       21    0.012    0.001    0.014    0.001 {built-in method _imp.create_dynamic}
  338/337    0.006    0.000    0.019    0.000 {built-in method builtins.__build_class__}
       13    0.005    0.000    0.007    0.001 enum.py:157(__new__)
      814    0.004    0.000    0.004    0.000 {built-in method posix.stat}
      399    0.004    0.000    0.016    0.000 <frozen importlib._bootstrap_external>:1498(find_spec)
        1    0.004    0.004    0.005    0.005 naive_part1.py:64(parse_1)
      999    0.003    0.000    0.004    0.000 naive_part1.py:276(cut_blizzards)
      147    0.003    0.000    0.003    0.000 {built-in method io.open_code}
      614    0.003    0.000    0.003    0.000 _inspect.py:65(getargs)
      148    0.002    0.000    0.002    0.000 {method 'read' of '_io.BufferedReader' objects}
     4364    0.002    0.000    0.002    0.000 {built-in method builtins.getattr}
     2078    0.002    0.000    0.005    0.000 <frozen importlib._bootstrap_external>:121(_path_join)
      328    0.002    0.000    0.003    0.000 functools.py:34(update_wrapper)
     2078    0.002    0.000    0.002    0.000 <frozen importlib._bootstrap_external>:123(<listcomp>)
     2010    0.002    0.000    0.002    0.000 {built-in method builtins.print}



```

There is quite an obvious optimization in the solve_part_one function when checking for the end. We should use another dictionary instead of a list instead. After that we have to optimize the function which moves the blizzards:

```

def update_blizzards(blizzards: dict, counter: int, width: int, height: int) -> list:
	# update blizzards according to the rules.

	#for coords in blizzards: # I hope there is a more pythonic way to modify each element in a list. if you try to do for bliz in blizzards: ... then you are not actually modifying the original list, but copies of the objects or something like that.
	#debug("counter: "+str(counter))
	#debug("width: "+str(width))
	#debug("height: "+str(height))

	# NOTE: If we tried the above, then we would get a "RuntimeError: dictionary changed size during iteration" error.

	OFFSETS = {UP: [0,-1], LEFT: [-1,0], DOWN: [0,1], RIGHT:[1,0]}
	#OFFSETS = [[0,-1], [-1,0], [0,1], [1,0]]


	#for coords in tuple(blizzards.keys()):
	#for coords in blizzards:

	for coords in tuple(blizzards.keys()):

		#move = blizzards[i][1]

		
		#move = blizzards[coords]
		moves = blizzards[coords]
		pop_list = []
		#new_list = copy.deepcopy(moves)
		#new_list = moves

		# Can not do this because we can have multiple blizzards at the same spot.

		# <comment>
		'''
		offset = OFFSETS[move]


		# move blizzard. here we do not need to do collision checking, because two blizzards or more blizzards can be at the same spot.

		#blizzards[i][0][0] += offset[0]
		#blizzards[i][0][1] += offset[1]

		# instead of using a list of lists, lets just use a dictionary with the coordinates as keys. it is a lot faster

		new_coords = [coords[0]+offset[0], coords[1]+offset[1]]

		del blizzards[coords] # delete old position.

		blizzards[new_coords] = move 
		'''

		# </comment>

		#new_stuff = []

		for ind, move in enumerate(moves):
			actual_move = move[0]

			count = move[1]

			if count != counter:


				offset = OFFSETS[actual_move]

				#new_coords = (coords[0]+offset[0], coords[1]+offset[1])
				new_coords = [coords[0]+offset[0], coords[1]+offset[1]]
				# check for loop around.

				if new_coords[0] < 0:
					
					assert new_coords[0] == -1
					new_coords[0] = width - 1 # going left so spawn on the right

				elif new_coords[0] == width:
					
					new_coords[0] = 0 # loop around going to the right and spawn on the left
				
				elif new_coords[1] < 0:
					
					assert new_coords[1] == -1
					new_coords[1] = height - 1
				
				elif new_coords[1] == height:

					new_coords[1] = 0

				new_coords = tuple(new_coords)

				if new_coords not in blizzards:
					blizzards[new_coords] = [[actual_move, counter]]
				else:
					blizzards[new_coords] += [[actual_move, counter]]



				#new_stuff.append([new_coords, actual_move])

				#blizzards[coords].pop(ind) # delete it from the list # another note: we can not do this because it messes up the loop i think
				pop_list.append(ind)
				#blizzards[coords].remove(move)
				#new_list.remove(move)
		offset = 0
		for pop_ind in pop_list:

			blizzards[coords].pop(pop_ind - offset)

			offset += 1
		
		# check if there are any blizzards left at that spot:

		if len(blizzards[coords]) == 0:

			del blizzards[coords]

	return blizzards


```


Now looking at this, I think we we could just use a three dimensional matrix instead of a dictionary, because our map is relatively small in size.
















