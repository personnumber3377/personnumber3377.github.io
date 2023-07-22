
# Advent of code 2022 day 17 writeup.

This is my quick writeup of the day 17 puzzle.

Basically the puzzle is a simplified version of tetris and the puzzle answer is the height of the stack of blocks when 2022 blocks have been placed.

So just get cracking I guess? I think that the binary and operation is a great way to check for intersection between block.

Also one optimization which I already got in my head is that if we just keep track of the height of the stack then we do not need to check for the intersection between the block and the placed blocks for the first x amount of steps because it is impossible for us to intersect with a block in that time, because we haven't reached to top of the block stack yet. But that is in the future. Let us just first program a working example.

I am going to program this just as a game would be programmed with a mainloop and stuff. (Maybe)

After a bit of fiddling around I came up with this:


```


import sys
import numpy as np
from PIL import Image
import copy

MAX_BLOCK_COUNT = 2022

MAP_WIDTH = 7

#MAP_HEIGHT = 10
MAP_HEIGHT = 10000
SHAPE_1 = np.array([[1,1,1,1]])

SHAPE_2 = np.array([[0,1,0],[1,1,1],[0,1,0]])

#SHAPE_3 = np.array([[0,0,1],[0,0,1],[1,1,1]])

SHAPE_3 = np.array([[1,1,1],[0,0,1],[0,0,1]])

SHAPE_4 = np.array([[1],[1],[1],[1]])

SHAPE_5 = np.array([[1,1],[1,1]])

shapes = [SHAPE_1, SHAPE_2, SHAPE_3, SHAPE_4, SHAPE_5]

AMOUNT_SHAPES = len(shapes)

dx_for_moves = {"<": -1, ">": 1}

shape_widths = [4,3,3,1,2]

heights = [1,3,3,4,2]


def render_mat(mat):

	qr_matrix = np.invert(mat.astype(bool), dtype=bool)
	print(qr_matrix.astype(int))
	qr_matrix = qr_matrix.astype(np.uint8)
	im = Image.fromarray(qr_matrix * 255)
	im.show()
	#input()





def check_col(shape, x_coord, y_coord, game_map):

	shape_shape = shape.shape
	x_diff = shape_shape[1]
	y_diff = shape_shape[0]
	thing = shape.astype("float64")
	#print("x_diff: "+str(x_diff))
	#print("y_diff: "+str(y_diff))

	#game_map_section = game_map[y_coord:y_coord+y_diff,x_coord:x_coord+x_diff]
	#game_map_section = game_map[x_coord:x_coord+x_diff,y_coord:y_coord+y_diff]

	#game_map_section = game_map[x_coord:x_coord+x_diff,y_coord:y_coord+y_diff]


	#game_map_section = game_map[y_coord:y_coord+y_diff,x_coord:x_coord+x_diff]

	game_map_section = game_map[x_coord:x_coord+x_diff,y_coord:y_coord+y_diff]


	# check with binary and operation for intersection.

	#print("type(game_map) == "+str(type(game_map)))
	#print("type(thing) == "+str(type(thing)))
	#print("type(game_map_section) == "+str(type(game_map_section)))
	
	#print("game_map_section == "+str(game_map_section))
	#print("thing == "+str(thing))

	intersect = (game_map_section.astype("bool") & thing.astype("bool").T)

	# if all are zeroes, then an intersection did not occur so when np.all(intersect == 0) returns false then we must return true and vice versa.

	return not np.all(intersect == 0)


def place_block(shape, x_coord, y_coord, game_map):
	print("Placed block!")
	shape_shape = shape.shape
	x_diff = shape_shape[1]
	y_diff = shape_shape[0]
	thing = shape.astype("bool")
	print("Placed block at y coord: "+str(y_coord))
	print("Placed block at x coord: "+str(x_coord))

	print("x_diff: "+str(x_diff))
	print("y_diff: "+str(y_diff))
	game_map[x_coord:x_coord+x_diff,y_coord:y_coord+y_diff] |= thing.T
	#game_map[y_coord:y_coord+y_diff,x_coord:x_coord+x_diff] = thing.T
	return game_map




# Check the actual height of the block tower.
# actual_height = check_height(game_map)


def check_height(game_map):
	h = 0

	shitoof = copy.deepcopy(game_map)
	shitoof = shitoof.T
	oof = shitoof[h]
	while not np.all(oof == 0):

		h += 1
		oof = shitoof[h]
		#print("Game map:"+str(shitoof))
	print("Returned height: "+str(h))
	return h




def main_loop(game_map,moves):

	n = 0

	loop_counter = 0
	tower_height = 0

	rendering = False
	render_oof = True

	while n < MAX_BLOCK_COUNT:

		print("tower_height == "+str(tower_height))
		x_coord = 2
		x_coord_prev = 2
		print("n == "+str(n))
		cur_height = heights[n % AMOUNT_SHAPES]

		y_coord = tower_height + 3# + heights[n % AMOUNT_SHAPES]

		#shape = shapes[n % AMOUNT_SHAPES] # get the shape for this block placement.
		shape = copy.deepcopy(shapes[n % AMOUNT_SHAPES]) # get the shape for this block placement.
		print("loop_counter == "+str(loop_counter))
		print("moves: "+str(moves))
		if n == 8:
			rendering = True
			print("poopoo")
			#render_oof = True
			#render_mat(game_map)
		else:
			if rendering:
				rendering = False


		while True:
			if loop_counter == len(moves):
				loop_counter = 0
			# This is a loop to place the blocks.
			print("x_coord at the start of the loop: "+str(x_coord))
			print("y_coord: "+str(y_coord))
			# Get move
			print("loop_countergregrege == "+str(loop_counter))
			cur_move = moves[loop_counter]

			# Apply move.
			print("cur_move == "+str(cur_move))
			dx = dx_for_moves[cur_move]
			print("dx: "+str(dx))
			x_coord += dx
			blocked = False
			if x_coord < 0:
				#x_coord = 0
				x_coord -= dx
				blocked = True
				#loop_counter -= 1
			print("shit")
			print("x_coord: "+str(x_coord))
			print("shape_widths[n % AMOUNT_SHAPES] == "+str(shape_widths[loop_counter % AMOUNT_SHAPES]))

			print("n % AMOUNT_SHAPES == "+str(n % AMOUNT_SHAPES))
			print("MAP_WIDTH == "+str(MAP_WIDTH))
			
			if x_coord + shape_widths[n % AMOUNT_SHAPES] > MAP_WIDTH:
				#x_coord = MAP_WIDTH-1
				print("Move blocked.")
				#loop_counter -= 1
				if not blocked:

					x_coord -= dx
					blocked = True

			
			# check collision against already placed blocks.

			if check_col(shape, x_coord, y_coord, game_map):


				if not blocked:

					x_coord -= dx
					blocked = True
				#x_coord -= dx # go back.
				#loop_counter -= 1
				#blocked = True

			# fall
			
			if rendering and render_oof:
				poopooshit = copy.deepcopy(game_map)
				poopooshit = place_block(shape, x_coord, y_coord, poopooshit)
				render_mat(poopooshit)
				print("Rendering")
				#render_oof = False


			if cur_move == "<":
				assert x_coord <= x_coord_prev

			if cur_move == ">":
				assert x_coord >= x_coord_prev

			x_coord_prev = x_coord

			y_coord -= 1
			print("y_coord after decrement: "+str(y_coord))
			# check collision

			# dx = dx_for_moves[cur_move]

			# check collision against floor:
			loop_counter = (loop_counter + 1) % len(moves)

			if y_coord == -1:

				y_coord += 1

				# Place block
				#if not blocked:
				#	x_coord -= dx
				game_map = place_block(shape, x_coord, y_coord, game_map)

				# increment placed block counter

				n += 1

				# update tower height
				print("Y coord in checking:"+str(y_coord))
				if y_coord+cur_height > tower_height: # no need to check for ones in the shape matrix because the first line always contains atleast one "1" .
					tower_height = y_coord+cur_height

				# Start new block loop.

				break

			if check_col(shape, x_coord, y_coord, game_map):

				# Go back up one space.

				y_coord += 1

				# Place block
				#if not blocked:
				#	x_coord -= dx
				game_map = place_block(shape, x_coord, y_coord, game_map)

				# increment placed block counter

				n += 1

				# update tower height
				print("Y coord in checking:"+str(y_coord))
				if y_coord+cur_height > tower_height: # no need to check for ones in the shape matrix because the first line always contains atleast one "1" .
					tower_height = y_coord+cur_height

				# Start new block loop.

				break
			
	render_mat(game_map)

	# sanity check

	actual_height = check_height(game_map)

	print("check_height output: "+str(actual_height))

	assert actual_height == tower_height

	return tower_height





def parse_input():

	return sys.stdin.buffer.read().decode('ascii')


def solve_puzzle():

	moves = parse_input()

	game_map = np.zeros((MAP_WIDTH, MAP_HEIGHT)).astype("bool")



	height = main_loop(game_map,moves)

	#result = get_height(game_map)

	return height






if __name__=="__main__":
	print("Solution to puzzle: "+str(solve_puzzle()))
	exit(0)


```


One annoying bug which I had to fix in this which stumped me for a while was that the loop_counter variable was incremented in a weird way that it skipped the very last move in the sequence before looping and that is why I got the incorrect result. I forgot what code configuration caused that bug but that works now.


This code works for the part 1 but is way too slow for the part two thing. One peculiar thing when examining the output with the render_mat function is that the block pattern basically just repeats when the moves loop back around. So I think we can just find the height of one of these and then divide the block counter by the amount of blocks in one of these patterns and then multiply that by the height which it gave to the tower.

I am going to try to solve this part without looking it up. Lets see how it goes.

Nevermind. I am too lazy to figure it out myself.

I looked this up: https://fasterthanli.me/series/advent-of-code-2022/part-17 and this seems to be quite a good writeup.

The writeup used states and then checked if the state was in the previously encountered states and if yes then just skip ahead that much.

I think this is some sort of memoization: https://en.wikipedia.org/wiki/Memoization

After just straight up copying all of the stuff I came up with this:


```


states = {}

loop_found = False


# ...


def main_loop(game_map,moves):

	n = 0

	loop_counter = 0
	tower_height = 0

	rendering = False
	render_oof = True
	
	loop_found = False

	print_count = 1000

	while n < MAX_BLOCK_COUNT:
		if n % print_count == 0:
			print(n)
		print(n)
		#print("tower_height == "+str(tower_height))
		x_coord = 2
		x_coord_prev = 2
		#print("n == "+str(n))
		cur_height = heights[n % AMOUNT_SHAPES]

		y_coord = tower_height + 3# + heights[n % AMOUNT_SHAPES]

		#shape = shapes[n % AMOUNT_SHAPES] # get the shape for this block placement.
		shape = copy.deepcopy(shapes[n % AMOUNT_SHAPES]) # get the shape for this block placement.
		#print("loop_counter == "+str(loop_counter))
		#print("moves: "+str(moves))
		if n == 8:
			rendering = True
			#print("poopoo")
			#render_oof = True
			#render_mat(game_map)
		else:
			if rendering:
				rendering = False


		while True:
			if loop_counter == len(moves):
				loop_counter = 0
			# This is a loop to place the blocks.
			#print("x_coord at the start of the loop: "+str(x_coord))
			#print("y_coord: "+str(y_coord))
			# Get move
			#print("loop_countergregrege == "+str(loop_counter))
			cur_move = moves[loop_counter]

			# Apply move.
			#print("cur_move == "+str(cur_move))
			dx = dx_for_moves[cur_move]
			#print("dx: "+str(dx))
			x_coord += dx
			blocked = False
			if x_coord < 0:
				#x_coord = 0
				x_coord -= dx
				blocked = True
				#loop_counter -= 1
			#print("shit")
			#print("x_coord: "+str(x_coord))
			#print("shape_widths[n % AMOUNT_SHAPES] == "+str(shape_widths[loop_counter % AMOUNT_SHAPES]))

			#print("n % AMOUNT_SHAPES == "+str(n % AMOUNT_SHAPES))
			#print("MAP_WIDTH == "+str(MAP_WIDTH))
			
			if x_coord + shape_widths[n % AMOUNT_SHAPES] > MAP_WIDTH:
				#x_coord = MAP_WIDTH-1
				#print("Move blocked.")
				#loop_counter -= 1
				if not blocked:

					x_coord -= dx
					blocked = True

			
			# check collision against already placed blocks.

			if check_col(shape, x_coord, y_coord, game_map):


				if not blocked:

					x_coord -= dx
					blocked = True
				#x_coord -= dx # go back.
				#loop_counter -= 1
				#blocked = True

			# fall
			
			if rendering and render_oof:
				poopooshit = copy.deepcopy(game_map)
				poopooshit = place_block(shape, x_coord, y_coord, poopooshit)
				render_mat(poopooshit)
				#print("Rendering")
				#render_oof = False


			if cur_move == "<":
				assert x_coord <= x_coord_prev

			if cur_move == ">":
				assert x_coord >= x_coord_prev

			x_coord_prev = x_coord

			y_coord -= 1
			#print("y_coord after decrement: "+str(y_coord))
			# check collision

			# dx = dx_for_moves[cur_move]

			# check collision against floor:
			loop_counter = (loop_counter + 1) % len(moves)

			if y_coord == -1:

				y_coord += 1

				# Place block
				#if not blocked:
				#	x_coord -= dx
				game_map = place_block(shape, x_coord, y_coord, game_map)

				# increment placed block counter

				n += 1

				# update tower height
				#print("Y coord in checking:"+str(y_coord))
				if y_coord+cur_height > tower_height: # no need to check for ones in the shape matrix because the first line always contains atleast one "1" .
					tower_height = y_coord+cur_height

				# Start new block loop.

				break

			if check_col(shape, x_coord, y_coord, game_map):

				# Go back up one space.

				y_coord += 1

				# Place block
				#if not blocked:
				#	x_coord -= dx
				game_map = place_block(shape, x_coord, y_coord, game_map)

				# increment placed block counter

				n += 1

				# update tower height
				#print("Y coord in checking:"+str(y_coord))
				if y_coord+cur_height > tower_height: # no need to check for ones in the shape matrix because the first line always contains atleast one "1" .
					tower_height = y_coord+cur_height

				# Start new block loop.

				break

		# Placed a block so now add a state to states 

		# Check for looped elements.

		print("Saving state")

		if not loop_found:

			new_state = []

			# Get the height at each point.


			print("Sorting shit.")

			for i in range(MAP_WIDTH):

				# Now just go through all the shit.

				h = 0

				for j in range(MAP_HEIGHT):
					if game_map[i][j] == 1:
						h = j

				new_state.append(h)

			lowest = min(new_state)

			print("Finished sorting shit.")

			state = [x - lowest for x in new_state] # The difference between shit.
			# n % AMOUNT_SHAPES
			state += [(n-1)%AMOUNT_SHAPES, loop_counter] # current 

			state = tuple(state)

			if state in states:

				height_gain = tower_height - states[state][0]

				rock_num = n - states[state][1]

				skipped = (MAX_BLOCK_COUNT - n) // rock_num

				n += skipped * rock_num

				loop_found = True
			else:
				states[state] = [tower_height, n]



	render_mat(game_map)

	# sanity check

	actual_height = check_height(game_map)

	#print("check_height output: "+str(actual_height))
	#print("tower_height: "+str(tower_height))
	#assert actual_height == tower_height
	if not loop_found:

		return tower_height
	else:

		return tower_height + (skipped * height_gain)


```

This gives the right answer for part two, but it takes a while. Now, the process takes the most in the:


```

			for i in range(MAP_WIDTH):

				# Now just go through all the shit.

				h = 0

				for j in range(MAP_HEIGHT):
					if game_map[i][j] == 1:
						h = j

				new_state.append(h)

			lowest = min(new_state)

```

Lines. To improve this algorithm I think I need to keep track of the maximum height on each of the "columns" on the fly so it doesn't need to be searched through here.

After adding this instead:

```

				h = 0

				#for j in range(MAP_HEIGHT):
				#	if game_map[i][j] == 1:
				#		h = j

				#new_state.append(h)
				new_state.append(col_heights[i])


```

and update_col_heights :

```

def update_col_heights(shape_num, x_coord, y_coord):

	# This updates the column heights so we do not need to check them later.
	# block_col_heights
	print("x_coord: "+str(x_coord))
	print("shape_num: "+str(shape_num))

	print("shapes[shape_num]: "+str(shapes[shape_num]))
	print("shapes[shape_num].shape[1]+x_coord: "+str(shapes[shape_num].shape[1]+x_coord))
	print("shapes[shape_num].shape[1] == "+str(shapes[shape_num].shape[1]))
	for i in range(x_coord, shapes[shape_num].shape[1]+x_coord):
		# Get the blocks height at that column.
		
		h = block_col_heights[shape_num][i-x_coord]

		if col_heights[i] < h + y_coord-1:
			col_heights[i] = h + y_coord-1

```

This spedup the execution by a lot, but it still takes quite a few seconds to complete.

After taking out the unused functions and the render_mat function I can speed up the program to 

```

cyberhacker@cyberhacker-h8-1131sc:~/Asioita/Ohjelmointi/adventofcode2022/chapter_17$ time python3.8 tetrisfinal.py < actual.txt > out.txt

real	0m1,364s
user	0m1,428s
sys	0m0,448s



```

Around one and a half seconds. The blog post got an execution speed of only around two milliseconds. One optimization which I can do is in the check_col function. We do not need to bitwise and every element of the matrixes, but instead go through them one by one and then break if one intersection is found because it does not matter what the others are. Another optimization is to just skip ahead three steps without collision detection with the game map itself, because it is impossible to hit anything because the block spawns three units above the block stack.

The output of the profiling is this:

```

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
    40420    0.415    0.000    0.923    0.000 tetrisfinal.py:61(check_col)
    84286    0.302    0.000    0.302    0.000 {method 'astype' of 'numpy.ndarray' objects}
    40420    0.162    0.000    0.162    0.000 {method 'reduce' of 'numpy.ufunc' objects}
        1    0.073    0.073    1.045    1.045 tetrisfinal.py:159(main_loop)
    40420    0.066    0.000    0.251    0.000 fromnumeric.py:69(_wrapreduction)
    40420    0.045    0.000    0.296    0.000 fromnumeric.py:2432(all)
    40420    0.033    0.000    0.365    0.000 <__array_function__ internals>:177(all)
    40422    0.029    0.000    0.325    0.000 {built-in method numpy.core._multiarray_umath.implement_array_function}
     3445    0.023    0.000    0.031    0.000 tetrisfinal.py:98(place_block)
    40420    0.018    0.000    0.018    0.000 fromnumeric.py:70(<dictcomp>)
      147    0.016    0.000    0.016    0.000 {built-in method marshal.loads}
       21    0.012    0.001    0.013    0.001 {built-in method _imp.create_dynamic}
46000/45830    0.009    0.000    0.009    0.000 {built-in method builtins.len}
    40420    0.008    0.000    0.008    0.000 fromnumeric.py:2427(_all_dispatcher)
     3445    0.008    0.000    0.008    0.000 tetrisfinal.py:116(update_col_heights)
    40843    0.006    0.000    0.006    0.000 {method 'items' of 'dict' objects}
  338/337    0.006    0.000    0.020    0.000 {built-in method builtins.__build_class__}

```

The function which checks collision against the already placed blocks takes up most of the time. Now, lets try to implement the optimization which I described previously.

After doing the skip thing which always skips the three first collision detections with the placed blocks, now it looks like this:


```
         495128 function calls (492808 primitive calls) in 1.073 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
    30085    0.299    0.000    0.664    0.000 tetrisfinal.py:61(check_col)
    63616    0.261    0.000    0.261    0.000 {method 'astype' of 'numpy.ndarray' objects}
    30085    0.117    0.000    0.117    0.000 {method 'reduce' of 'numpy.ufunc' objects}
        1    0.065    0.065    0.776    0.776 tetrisfinal.py:159(main_loop)
    30085    0.047    0.000    0.180    0.000 fromnumeric.py:69(_wrapreduction)
    30085    0.031    0.000    0.211    0.000 fromnumeric.py:2432(all)
    30085    0.024    0.000    0.263    0.000 <__array_function__ internals>:177(all)

```

Now, the time spent inside check_col is much less. 

After implementing the collision thing where we do not check each element separately:

```

         224363 function calls (222043 primitive calls) in 0.951 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
    30085    0.494    0.000    0.551    0.000 tetrisfinal.py:61(check_col)
    33531    0.216    0.000    0.216    0.000 {method 'astype' of 'numpy.ndarray' objects}
        1    0.060    0.060    0.652    0.652 tetrisfinal.py:176(main_loop)
     3445    0.021    0.000    0.026    0.000 tetrisfinal.py:115(place_block)
      147    0.016    0.000    0.016    0.000 {built-in method marshal.loads}
       21    0.013    0.001    0.015    0.001 {built-in method _imp.create_dynamic}
     3445    0.007    0.000    0.007    0.000 tetrisfinal.py:133(update_col_heights)

```

Now another optimization is to remove the astype methods which take up a lot of computing power.

This is now check_col :


```

def check_col(shape, x_coord, y_coord, game_map):

	shape_shape = shape.shape
	x_diff = shape_shape[1]
	y_diff = shape_shape[0]
	#thing = shape.astype("float64")
	#thing = shape.astype("bool")
	###print("x_diff: "+str(x_diff))
	###print("y_diff: "+str(y_diff))

	#game_map_section = game_map[y_coord:y_coord+y_diff,x_coord:x_coord+x_diff]
	#game_map_section = game_map[x_coord:x_coord+x_diff,y_coord:y_coord+y_diff]

	#game_map_section = game_map[x_coord:x_coord+x_diff,y_coord:y_coord+y_diff]


	#game_map_section = game_map[y_coord:y_coord+y_diff,x_coord:x_coord+x_diff]

	game_map_section = game_map[x_coord:x_coord+x_diff,y_coord:y_coord+y_diff]


	# check with binary and operation for intersection.

	###print("type(game_map) == "+str(type(game_map)))
	###print("type(thing) == "+str(type(thing)))
	###print("type(game_map_section) == "+str(type(game_map_section)))
	
	###print("game_map_section == "+str(game_map_section))
	###print("thing == "+str(thing))

	# This method is inefficient because it does more operations than strictly necessary.

	#intersect = (game_map_section.astype("bool") & thing.T)


	# Go through each of the elements and then break if an intersection is found.

	#for i in range(game_map_section.shape[0]):
	for i in range(x_diff):
		
		#for j in range(game_map_section.shape[1]):
		for j in range(y_diff):
			if game_map_section[i,j] == 1 and shape[j,i]:

				return True

	return False




```

After improving the program by getting rid of the "astype" statements and improving some other stuff I got this:

```

         190832 function calls (188512 primitive calls) in 0.695 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
    30085    0.466    0.000    0.466    0.000 tetrisfinal.py:61(check_col)
        1    0.052    0.052    0.549    0.549 tetrisfinal.py:183(main_loop)
     3445    0.018    0.000    0.018    0.000 tetrisfinal.py:116(place_block)
      147    0.017    0.000    0.017    0.000 {built-in method marshal.loads}
       21    0.012    0.001    0.013    0.001 {built-in method _imp.create_dynamic}
     3445    0.007    0.000    0.007    0.000 tetrisfinal.py:140(update_col_heights)

```

This is getting relatively fast for python standards.

I am figuring out a way to check the collision faster.

One way to improve this would be to make a similar thing what we did with the collision map thing We get the top left and bottom right corner of each new block when it is falling and then we can check if those coordinates are inside the "plausable collision" zone, so we treat every piece as if it was a square block and then map a range and we should be done.

----------------------

I was initially suspicious about this optimization, but as it turns out, it speeds up the program.

I did a simple benchmark script which takes the average output of the cProfile output:

```

import sys
import os

if __name__=="__main__":
	if len(sys.argv) < 2:
		print("Usage: python3.8 "+str(sys.argv[0])+" PYTHONSCRIPT")
		print("Example: python3.8 "+str(sys.argv[0])+" tetriswithrangedetection.py")
		exit(1)
	command = "python3.8 -m cProfile "+str(sys.argv[1])+" < actual.txt > profile.txt"

	n = 20
	tot_time = 0
	for i in range(n):
		print("i == "+str(i))
		os.system(command)

		fh = open("profile.txt", "r")

		lines = fh.readlines()

		fh.close()

		speed_line = lines[1] # second line in file has the time which it took to complete execution

		things = speed_line.split(" ")

		speed = float(things[-2])



		tot_time += speed

	print("Average time took "+str(tot_time/n)+" seconds.")
	exit(0)

```

The output for this with the square things is this:

Average time took 0.6378999999999999 seconds.

Without the range checking we get this:

```
python3.8 run_bench.py tetrisfinal.py 

...

Average time took 0.67375 seconds.
```

So we can shave off another 35 milliseconds.


Next optimization is to try to put global variables inside the functions because using local variables should be faster than the use of global variables.

Except before that I may have to clean up my code a bit before proceeding.































