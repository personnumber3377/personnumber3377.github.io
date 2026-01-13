
# Day 23

This is a quite a fun challenge imo.. My first idea is to instead of making a numpy matrix, make a dictionary where the keys are coordinates and the value is the index of the thing in the keys. Now when we advance, we make an empty dictionary where we store the hypothetical coordinates of the elves and then checking this list for subsequent accesses and if the coordinates are already in the dictionary, then mark that index in a list where we have a "skip" list which indexes we skip moving.

Lets get cracking!

Here is my start: It parses the input.

{% raw %}
```


import sys



def parse_input():
	stdin = sys.stdin.buffer.read().decode('ascii')
	lines = stdin.split("\n")

	coords = {}
	count = 0

	for y, line in enumerate(lines):
		for x, spot in enumerate(line):
			if spot == "#":

				coords[(x,y)] = count
				count += 1

	return coords



def main_loop(n):
	


def solve_puzzle():
	coordinates = parse_input()

	final_coordinates = main_loop(10)




if __name__=="__main__":

	print("Solution to puzzle: "+str(solve_puzzle()))


```
{% endraw %}


I think the best way to go about deciding if to move or not is to first move hypothetically and then check if two elves would land on the same spot and then add the indexes of those elves to a dictionary if yes and then in stage two lookup the dictionary and see if the index is in the banlist and if not then do not move.

After a bit of fiddling, I got this:

{% raw %}
```


import sys
import numpy as np
from PIL import Image

def parse_input():
	stdin = sys.stdin.buffer.read().decode('ascii')
	lines = stdin.split("\n")
	# max_x, max_y, min_x, min_y
	coords = {}
	count = 0

	max_y = len(lines)
	max_x = len(lines[0])

	for y, line in enumerate(lines):
		for x, spot in enumerate(line):
			if spot == "#":

				coords[(x,y)] = count
				count += 1

	return coords, max_x, max_y, 0, 0



N = [0,-1]
S = [0,1]
W = [-1,0]
E = [1,0]
NW = [-1,-1]
NE = [1,-1]
SW = [-1,1]
SE = [1,1]



def generate_neighbours(place):

	offsets = [[1,0],[1,-1],[1,1],  # E , NE , SE
	[0,1],[0,-1], # N, S
	[-1,0],[-1,1],[-1,-1]] # W , SW, NW

	for off in offsets:
		yield [place[0]+off[0], place[1]+off[1]]

'''
def check_collision(place, move_offset, other_elves):

	offsets = [N,NE,NW,   S,SE,SW,   W,NW,SW,  E,NE,SE] # the rules
	count = 0
	
	while True:

		cur_offset = offsets[(move_offset+count)%12]

		if tuple([place[0]+cur_offset[0], place[1]+cur_offset[1]]) in other_elves:

			print("Proposed move for position "+str(place)+" is "+str(((move_offset+count) % 12)//3))

			return ((move_offset+count) % 12)//3
		count += 1
'''


'''
def check_collision(place, move_offset, other_elves):

	offsets = [[N,NE,NW],   [S,SE,SW],   [W,NW,SW],  [E,NE,SE]] # the rules
	count = 0
	print("Checking collision with place == "+str(place)+" move_offset== "+str(move_offset)+" other_elves == "+str(other_elves))
	for i, thing in enumerate(offsets):
		oof = True
		print("Thing: "+str(thing))
		for offset in thing:
			#print("offset[0] == "+str(offset[0]))
			#print("offset[1] == "+str(offset[1]))
			print("offset: "+str(offset))
			if tuple([place[0]+offset[0], place[1]+offset[1]]) in other_elves:
				oof = False
		if oof:

			print("Proposed move for position "+str(place)+" is "+str(i))


			return i
	return None
	assert False
'''

'''
def check_collision(place, move_offset, other_elves):

	offsets = [[N,NE,NW],   [S,SE,SW],   [W,NW,SW],  [E,NE,SE]] # the rules
	count = 0
	print("Checking collision with place == "+str(place)+" move_offset== "+str(move_offset)+" other_elves == "+str(other_elves))
	for i, thing in enumerate(offsets):
		oof = True
		print("Thing: "+str(thing))
		for offset_count in range(len(thing)):
			print("thing == "+str(thing))

			print("(offset_count+move_offset) == "+str((offset_count+move_offset)))
			offset = thing[(offset_count+move_offset) % 3]
			#print("offset[0] == "+str(offset[0]))
			#print("offset[1] == "+str(offset[1]))
			print("offset: "+str(offset))
			if tuple([place[0]+offset[0], place[1]+offset[1]]) in other_elves:
				oof = False
		if oof:

			print("Proposed move for position "+str(place)+" is "+str(i))


			return i
	return None
	assert False
'''


def check_collision(place, move_offset, other_elves):

	offsets = [[N,NE,NW],   [S,SE,SW],   [W,NW,SW],  [E,NE,SE]] # the rules
	count = 0
	print("Checking collision with place == "+str(place)+" move_offset== "+str(move_offset)+" other_elves == "+str(other_elves))
	for i in range(len(offsets)):
		oof = True

		thing = offsets[(i+move_offset) % 4]

		print("Thing: "+str(thing))
		for offset_count in range(len(thing)):
			print("thing == "+str(thing))

			print("(offset_count+move_offset) == "+str((offset_count+move_offset)))
			offset = thing[offset_count]
			#print("offset[0] == "+str(offset[0]))
			#print("offset[1] == "+str(offset[1]))
			print("offset: "+str(offset))
			if tuple([place[0]+offset[0], place[1]+offset[1]]) in other_elves:
				oof = False
		if oof:

			print("Proposed move for position "+str(place)+" is "+str(i))


			#return i

			return (i+move_offset) % 4

	return None
	assert False



def check_moving(cur_place, other_elves):

	# Check if the elf can move (checks the eight directional) .
	print("Called check_moving with cur_place "+str(cur_place))
	neighbours = list(generate_neighbours(cur_place))

	print("Neighbours: "+str(list(neighbours)))

	count = 0

	for neig in neighbours:
		print("Tuple of neighbour: "+str(tuple(neig)))
		if tuple(neig) in other_elves:
			return 1 # move

		count += 1
	return 0 # do not move


def get_new_place(place, cur_move):
	'''
	match cur_move:
		case 0:
			return [place[0]+N[0], place[1]+N[1]]
		case 1:
			return [place[0]+S[0], place[1]+S[1]]
		case 2:
			return [place[0]+W[0], place[1]+W[1]]
		case 3:
			return [place[0]+E[0], place[1]+E[1]]
		case _:
			print("Invalid proposed move index: "+str(cur_move))
			exit(1)
	'''

	if cur_move == 0:

		return [place[0]+N[0], place[1]+N[1]]

	elif cur_move == 1:

		return [place[0]+S[0], place[1]+S[1]]

	elif cur_move == 2:

		return [place[0]+W[0], place[1]+W[1]]

	elif cur_move == 3:

		return [place[0]+E[0], place[1]+E[1]]

	else:
		print("Invalid proposed move index: "+str(cur_move))
		exit(1)

def render_mat(mat):

	qr_matrix = np.invert(mat.astype(bool).T, dtype=bool)
	print(qr_matrix.astype(int))
	qr_matrix = qr_matrix.astype(np.uint8)
	im = Image.fromarray(qr_matrix * 255)
	im.show()

def render_matrix(coords, max_x,max_y,min_x,min_y):

	x_shape = max_x-min_x
	y_shape = max_y-min_y

	matrix = np.zeros((x_shape, y_shape))

	for coord in coords:

		matrix[coord[0],coord[1]] = 1

	render_mat(matrix)

	return



def main_loop(n, coords, max_x, max_y, min_x, min_y):

	rule_counter = 0

	# -1 for y is up and +1 for y is down. +1 for x is right and -1 for x is left

	dodge_rules = [[[0,-1],[-1,-1],[1,-1]],
	[[0,1],[-1,1],[1,1]],
	[[1,0],[1,-1],[1,1]],
	[[-1,0],[-1,-1],[-1,1]]]   # [[[dx1,dy1]]]  this is a list of lists and each of these lists has a list of offsets where to check   ..
	selected_num = 10
	move_count = 0
	for i in range(n):
		print("Loop number: "+str(i))
		print("Move count: "+str(move_count))
		# First half:

		# Check moving.

		moved_places = {}

		

		banlist = {}
		if i == selected_num:

			render_matrix(coords, max_x,max_y,min_x,min_y)

		for place in coords:
			print("coords == "+str(coords))

			if check_moving(place, coords) == 0:
				# do not move
				print("Place "+str(place)+" does not move.")
				continue

			# get the proposed move
			# def check_collision(place, move_offset, other_elves):
			print("Checking collision:")

			#proposed_move = check_collision(place, move_count*3,coords)
			
			proposed_move = check_collision(place, move_count,coords)

			if proposed_move == None: # Can not move
				
				continue

			#print("Proposed move for position "+str(place)+" is "+str(proposed_move))
			cur_index = coords[place] # get index of current elf.
			print("Get new place:")
			new_place = get_new_place(place, proposed_move)

			# add the index into the new dictionary. This dictionary will be used to check for blocked moves.

			if tuple(new_place) not in moved_places:


				moved_places[tuple(new_place)] = ([tuple((cur_index, place))])
			else:
				moved_places[tuple(new_place)].append(tuple((cur_index, place)))

				#banlist.append()
				for pair in moved_places[tuple(new_place)]:
					banlist[pair[0]] = 1


		# Stage two


		print("==== 2 =====")
		print("Moved places: "+str(moved_places))


		for new_place in moved_places:
			element = moved_places[new_place]



			for thing in element:

				print("moved_places == "+str(moved_places))
				print("element == "+str(element))
				old_place = thing[1]

				index = thing[0]

				# check for blocked move

				if index in banlist:
					continue

				# move
				assert isinstance(old_place, tuple)
				assert old_place in coords

				assert coords[old_place] == index
				#coords[old_place] = new_place # replace coordinates with the new coordinates


				# replace coordinates with the new coordinates

				coords.pop(old_place)

				coords[new_place] = index
		rule_counter += 3


		move_count += 1
	print("Final coords: "+str(coords))

	return coords


def calculate_area(coords):

	# Get the min x coord and min y coord

	min_x = min([k[0] for k in coords])
	min_y = min([k[1] for k in coords])

	max_x = max([k[0] for k in coords])
	max_y = max([k[1] for k in coords])
	
	print("min_x: "+str(min_x))
	print("min_y: "+str(min_y))
	print("max_x: "+str(max_x))
	print("max_y: "+str(max_y))
	area = 0

	for x in range(min_x, max_x+1):
		for y in range(min_y, max_y+1):
			if (x,y) not in coords:
				area += 1
			else:
				print("("+str(x)+","+str(y)+") in coords!")

	return area

def solve_puzzle():
	coordinates, max_x, max_y, min_x, min_y = parse_input()
	print("coordinates == "+str(coordinates))

	# max_x, max_y, min_x, min_y

	final_coordinates = main_loop(11, coordinates,max_x, max_y, min_x, min_y)
	area = calculate_area(final_coordinates)
	return area


if __name__=="__main__":

	print("Solution to puzzle: "+str(solve_puzzle()))



```
{% endraw %}

There is certainly a lot of improvement to be made, but it does the job. One easy optimization to do is to keep track of the min and max of x and y when going through the list instead of calculating it again.

Tomorrow I will maybe do part 2. :)

---------------------

Before doing part two, lets improve part one.

Again, lets run cProfile and see what the output shows us. The output shows that we spend a really long time in generate_neighbours.

This code:

{% raw %}
```

def generate_neighbours(place):

	offsets = [[1,0],[1,-1],[1,1],  # E , NE , SE
	[0,1],[0,-1], # N, S
	[-1,0],[-1,1],[-1,-1]] # W , SW, NW

	for off in offsets:
		yield [place[0]+off[0], place[1]+off[1]]


```
{% endraw %}

Is slow. What if we just simply replace it with this:

{% raw %}
```

def generate_neighbours(place):
	x = place[0]
	y = place[1]
	return [[x+1,y],[x+1,y+1],[x+1,y-1],[x,y+1],[x,y-1],[x-1,y],[x-1,y+1],[x-1,y-1]]

```
{% endraw %}

This code is a lot faster. Currently the cProfile output is this:


{% raw %}
```

Solution to puzzle: 3882
         278076 function calls (276335 primitive calls) in 0.291 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
    25355    0.090    0.000    0.098    0.000 optimization.py:136(check_collision)
        1    0.030    0.030    0.172    0.172 optimization.py:294(main_loop)
    25980    0.022    0.000    0.041    0.000 optimization.py:199(check_moving)
    25980    0.019    0.000    0.019    0.000 optimization.py:41(generate_neighbours)
      114    0.014    0.000    0.014    0.000 {built-in method marshal.loads}
       18    0.010    0.001    0.011    0.001 {built-in method _imp.create_dynamic}
118324/118242    0.008    0.000    0.008    0.000 {built-in method builtins.len}
  226/225    0.005    0.000    0.006    0.000 {built-in method builtins.__build_class__}
      310    0.004    0.000    0.013    0.000 <frozen importlib._bootstrap_external>:1498(find_spec)
      623    0.004    0.000    0.004    0.000 {built-in method posix.stat}
     6527    0.003    0.000    0.003    0.000 optimization.py:218(get_new_place)
      614    0.003    0.000    0.003    0.000 _inspect.py:65(getargs)
      114    0.002    0.000    0.002    0.000 {built-in method io.open_code}
      115    0.002    0.000    0.002    0.000 {method 'read' of '_io.BufferedReader' objects}
     3928    0.002    0.000    0.002    0.000 {built-in method builtins.getattr}
      326    0.002    0.000    0.003    0.000 functools.py:34(update_wrapper)
      314    0.002    0.000    0.013    0.000 overrides.py:170(decorator)
     1605    0.002    0.000    0.004    0.000 <frozen importlib._bootstrap_external>:121(_path_join)
     1605    0.002    0.000    0.002    0.000 <frozen importlib._bootstrap_external>:123(<listcomp>)
      284    0.002    0.000    0.007    0.000 overrides.py:88(verify_matching_signatures)
    10203    0.002    0.000    0.002    0.000 {built-in method builtins.isinstance}
      487    0.001    0.000    0.002    0.000 <frozen importlib._bootstrap>:78(acquire)
    18/13    0.001    0.000    0.007    0.001 {built-in method _imp.exec_dynamic}
      114    0.001    0.000    0.025    0.000 <frozen importlib._bootstrap_external>:914(get_code)
      487    0.001    0.000    0.002    0.000 <frozen importlib._bootstrap>:157(_get_module_lock)
      228    0.001    0.000    0.003    0.000 <frozen importlib._bootstrap_external>:354(cache_from_source)
      150    0.001    0.000    0.017    0.000 <frozen importlib._bootstrap>:890(_find_spec)
        1    0.001    0.001    0.001    0.001 optimization.py:9(parse_input)
    130/1    0.001    0.000    0.291    0.291 {built-in method builtins.exec}
      618    0.001    0.000    0.005    0.000 _inspect.py:96(getargspec)


```
{% endraw %}

Next up is the usual culprits of collision checking and the main loop itself. If I can get this under 100ms then I would be surprised. Looking at the subreddit https://www.reddit.com/r/adventofcode/comments/zt6xz5/comment/j2wamb3/?utm_source=share&utm_medium=web2x&context=3 there is a solution which solves part one in 1.5 microseconds, but it uses SIMD instructions which really can not be used with python.

Currently my check_collision function looks like this:

{% raw %}
```

def check_collision(place, move_offset, other_elves):

	offsets = [[[0,-1],[1,-1],[-1,-1]],   [[0,1],[1,1],[-1,1]],   [[-1,0],[-1,-1],[-1,1]],  [[1,0],[1,-1],[1,1]]] # the rules

	count = 0

	for i in range(len(offsets)):
		oof = True

		thing = offsets[(i+move_offset) % 4]

		for offset_count in range(len(thing)):

			offset = thing[offset_count]

			if (place[0]+offset[0], place[1]+offset[1]) in other_elves:
				oof = False
				break

		if oof:
			return (i+move_offset) % 4
	return None

```
{% endraw %}

After a bit of fiddling I got this:

{% raw %}
```

def check_collision(place, move_offset, other_elves):

	#offsets = [[[0,-1],[1,-1],[-1,-1]],   [[0,1],[1,1],[-1,1]],   [[-1,0],[-1,-1],[-1,1]],  [[1,0],[1,-1],[1,1]]] # the rules
	
	offsets = [[0,-1],[1,-1],[-1,-1],   [0,1],[1,1],[-1,1],   [-1,0],[-1,-1],[-1,1],  [1,0],[1,-1],[1,1]]
	oof = True
	for i in range(len(offsets)):
		

		thing = offsets[(i+move_offset) % 12]

		if tuple([place[0]+thing[0],place[1]+thing[1]]) in other_elves:
			#print("Collision with "+str(tuple([place[0]+thing[0],place[1]+thing[1]])))
			oof = False

		if ((i+1) % 3) == 0:
			if oof and i != 0:
				#print("i == "+str(i))
				#print("Proposed move for place "+str(place)+" is "+str(((i+move_offset) % 12)//3))
				return ((i+move_offset) % 12)//3
			oof = True
	

	return None
	
```
{% endraw %}

Except that it is only barely faster. Here is the cProfile output:

{% raw %}
```

Solution to puzzle: 3882
         188802 function calls (187061 primitive calls) in 0.332 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
    25355    0.138    0.000    0.140    0.000 optimization.py:141(check_collision)
        1    0.029    0.029    0.212    0.212 optimization.py:263(main_loop)
    25980    0.021    0.000    0.040    0.000 optimization.py:168(check_moving)
    25980    0.019    0.000    0.019    0.000 optimization.py:41(generate_neighbours)
      114    0.014    0.000    0.014    0.000 {built-in method marshal.loads}
       18    0.011    0.001    0.012    0.001 {built-in method _imp.create_dynamic}


```
{% endraw %}

Here is a the new code with the "breaks":


{% raw %}
```

def check_collision(place, move_offset, other_elves):

	#offsets = [[[0,-1],[1,-1],[-1,-1]],   [[0,1],[1,1],[-1,1]],   [[-1,0],[-1,-1],[-1,1]],  [[1,0],[1,-1],[1,1]]] # the rules
	
	#offsets = [[0,-1],[1,-1],[-1,-1],   [0,1],[1,1],[-1,1],   [-1,0],[-1,-1],[-1,1],  [1,0],[1,-1],[1,1]]
	
	offsets = [N,NE,NW,   S,SE,SW,   W,NW,SW,  E,NE,SE]

	oof = True
	i = 0
	#for i in range(len(offsets)):
	#print("NewCall")
	#print("Processing place "+str(place))
	while i != 12:
		
		#print("i == "+str(i))

		thing = offsets[(i+move_offset) % 12]
		#print("Checking "+str(tuple([place[0]+thing[0],place[1]+thing[1]])))
		if tuple([place[0]+thing[0],place[1]+thing[1]]) in other_elves:
			#print("Collision with "+str(tuple([place[0]+thing[0],place[1]+thing[1]])))
			#oof = False
			#print("tuple([place[0]+thing[0],place[1]+thing[1]]) == "+str(tuple([place[0]+thing[0],place[1]+thing[1]])))
			oof = True

			# this is sort of "break"
			#print("Previous i: "+str(i))
			#print("Jumping to "+str(((i//3)+1)*3))
			i = ((i//3)+1)*3
			thing = offsets[(i+move_offset) % 12]
			if i == 12:
				break
			continue

		if ((i+1) % 3) == 0:
			if oof and i != 0:
				#print("Returing")
				#print("i == "+str(i))
				#print("Proposed move for place "+str(place)+" is "+str(((i+move_offset) % 12)//3))
				return ((i+move_offset) % 12)//3
			oof = True
		
		i += 1

	return None

```
{% endraw %}

here is the profiling output:

{% raw %}
```

Solution to puzzle: 3882
         163447 function calls (161706 primitive calls) in 0.284 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
    25355    0.097    0.000    0.097    0.000 optimization.py:180(check_collision)
        1    0.025    0.025    0.164    0.164 optimization.py:324(main_loop)
    25980    0.021    0.000    0.040    0.000 optimization.py:229(check_moving)
    25980    0.019    0.000    0.019    0.000 optimization.py:41(generate_neighbours)
      114    0.013    0.000    0.013    0.000 {built-in method marshal.loads}


```
{% endraw %}

It is barely faster than the 0.29 second one. Still an improvement.


Apparently using global variables is faster than using local variables. That's odd.

Instead of trying to do modular arithmetic to get the correct index for the list, maybe we should modify the offset list inplace and then access it with simple arithmetic?

As it turns out popping elements of off a list and then appending them is hella slow. This function takes a lot of time:

{% raw %}
```

def check_collision(place, move_offset, other_elves):
	offsets = [N,NE,NW,   S,SE,SW,   W,NW,SW,  E,NE,SE]
	for _ in range(move_offset):
		thing = offsets.pop(0)
		offsets.append(thing)
	#print("offsets == "+str(offsets))
	i = 0
	while i != 12:
		index = i
		thing = offsets[index]
		#print("indexpoopoo == "+str(index))
		if tuple([place[0]+thing[0],place[1]+thing[1]]) in other_elves:
			#print("tuple([place[0]+thing[0],place[1]+thing[1]]) == "+str(tuple([place[0]+thing[0],place[1]+thing[1]])))
			i = ((i//3)+1)*3
			if i == 12:
				break
			index = i
			#print("index == "+str(index))
			thing = offsets[index]
			
			continue
		if ((i+1) % 3) == 0:
			#print("final index == "+str(index))
			#print("move_offset == "+str(move_offset))
			#print("returning this: "+str(((index+move_offset) % 12)//3))
			return ((index+move_offset) % 12)//3
			#print("i == "+str(i))
			#print()
			#return ((i) % 12)//3
		i += 1
	return None

```
{% endraw %}

Instead of popping shit and appending, maybe we can just use list splicing?

If we use this instead:

{% raw %}
```
offsets = offsets[move_offset%12:] + offsets[:move_offset%12]
```
{% endraw %}

We get this cProfile output:

{% raw %}
```
Solution to puzzle: 3882
         163447 function calls (161706 primitive calls) in 0.275 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
    25355    0.094    0.000    0.094    0.000 optimization.py:291(check_collision)
        1    0.024    0.024    0.155    0.155 optimization.py:424(main_loop)
    25980    0.019    0.000    0.019    0.000 optimization.py:41(generate_neighbours)
    25980    0.015    0.000    0.034    0.000 optimization.py:329(check_moving)
      114    0.013    0.000    0.013    0.000 {built-in method marshal.loads}
```
{% endraw %}

There appears to not be anymore obvious optimizations so this is my final code for part2:


{% raw %}
```


import sys
import numpy as np
#from PIL import Image

# see check_collision and https://stackoverflow.com/questions/18713321/element-wise-addition-of-2-lists
from operator import add

def parse_input():
	stdin = sys.stdin.buffer.read().decode('ascii')
	lines = stdin.split("\n")
	# max_x, max_y, min_x, min_y
	coords = {}
	count = 0

	max_y = len(lines)
	max_x = len(lines[0])

	for y, line in enumerate(lines):
		for x, spot in enumerate(line):
			if spot == "#":

				coords[(x,y)] = count
				count += 1

	return coords, max_x, max_y, 0, 0



N = [0,-1]
S = [0,1]
W = [-1,0]
E = [1,0]
NW = [-1,-1]
NE = [1,-1]
SW = [-1,1]
SE = [1,1]



def generate_neighbours(place):
	x = place[0]
	y = place[1]
	return [[x+1,y],[x+1,y+1],[x+1,y-1],[x,y+1],[x,y-1],[x-1,y],[x-1,y+1],[x-1,y-1]]


'''

def generate_neighbours(place):

	offsets = [[1,0],[1,-1],[1,1],  # E , NE , SE
	[0,1],[0,-1], # N, S
	[-1,0],[-1,1],[-1,-1]] # W , SW, NW

	for off in offsets:
		yield [place[0]+off[0], place[1]+off[1]]

'''



'''
def check_collision(place, move_offset, other_elves):

	offsets = [N,NE,NW,   S,SE,SW,   W,NW,SW,  E,NE,SE] # the rules
	count = 0
	
	while True:

		cur_offset = offsets[(move_offset+count)%12]

		if tuple([place[0]+cur_offset[0], place[1]+cur_offset[1]]) in other_elves:

			#print("Proposed move for position "+str(place)+" is "+str(((move_offset+count) % 12)//3))

			return ((move_offset+count) % 12)//3
		count += 1
'''


'''
def check_collision(place, move_offset, other_elves):

	offsets = [[N,NE,NW],   [S,SE,SW],   [W,NW,SW],  [E,NE,SE]] # the rules
	count = 0
	#print("Checking collision with place == "+str(place)+" move_offset== "+str(move_offset)+" other_elves == "+str(other_elves))
	for i, thing in enumerate(offsets):
		oof = True
		#print("Thing: "+str(thing))
		for offset in thing:
			##print("offset[0] == "+str(offset[0]))
			##print("offset[1] == "+str(offset[1]))
			#print("offset: "+str(offset))
			if tuple([place[0]+offset[0], place[1]+offset[1]]) in other_elves:
				oof = False
		if oof:

			#print("Proposed move for position "+str(place)+" is "+str(i))


			return i
	return None
	assert False
'''




'''
def check_collision(place, move_offset, other_elves):

	offsets = [[N,NE,NW],   [S,SE,SW],   [W,NW,SW],  [E,NE,SE]] # the rules
	count = 0
	#print("Checking collision with place == "+str(place)+" move_offset== "+str(move_offset)+" other_elves == "+str(other_elves))
	for i, thing in enumerate(offsets):
		oof = True
		#print("Thing: "+str(thing))
		for offset_count in range(len(thing)):
			#print("thing == "+str(thing))

			#print("(offset_count+move_offset) == "+str((offset_count+move_offset)))
			offset = thing[(offset_count+move_offset) % 3]
			##print("offset[0] == "+str(offset[0]))
			##print("offset[1] == "+str(offset[1]))
			#print("offset: "+str(offset))
			if tuple([place[0]+offset[0], place[1]+offset[1]]) in other_elves:
				oof = False
		if oof:

			#print("Proposed move for position "+str(place)+" is "+str(i))


			return i
	return None
	assert False

'''

'''

def check_collision(place, move_offset, other_elves):

	#offsets = [[[0,-1],[1,-1],[-1,-1]],   [[0,1],[1,1],[-1,1]],   [[-1,0],[-1,-1],[-1,1]],  [[1,0],[1,-1],[1,1]]] # the rules
	
	offsets = [[0,-1],[1,-1],[-1,-1],   [0,1],[1,1],[-1,1],   [-1,0],[-1,-1],[-1,1],  [1,0],[1,-1],[1,1]]
	oof = True
	i = 0
	#for i in range(len(offsets)):
	print("NewCall")
	print("Processing place "+str(place))
	while i != 12:


		thing = offsets[(i+move_offset) % 12]

		if tuple([place[0]+thing[0],place[1]+thing[1]]) in other_elves:
			#print("Collision with "+str(tuple([place[0]+thing[0],place[1]+thing[1]])))
			oof = False
			# this is sort of "break"
			print("Previous i: "+str(i))
			print("Jumping to "+str(((i//3)+1)*3))
			i = ((i//3)+1)*3
			thing = offsets[(i+move_offset) % 12]
			if i == 12:
				break

		if ((i+1) % 3) == 0:
			if oof and i != 0:
				#print("i == "+str(i))
				#print("Proposed move for place "+str(place)+" is "+str(((i+move_offset) % 12)//3))
				return ((i+move_offset) % 12)//3
			oof = True
		
		i += 1

	return None

'''


'''
def check_collision(place, move_offset, other_elves):

	#offsets = [[[0,-1],[1,-1],[-1,-1]],   [[0,1],[1,1],[-1,1]],   [[-1,0],[-1,-1],[-1,1]],  [[1,0],[1,-1],[1,1]]] # the rules
	
	#offsets = [[0,-1],[1,-1],[-1,-1],   [0,1],[1,1],[-1,1],   [-1,0],[-1,-1],[-1,1],  [1,0],[1,-1],[1,1]]
	
	offsets = [N,NE,NW,   S,SE,SW,   W,NW,SW,  E,NE,SE]

	oof = True
	i = 0
	#for i in range(len(offsets)):
	#print("NewCall")
	#print("Processing place "+str(place))
	while i != 12:
		
		#print("i == "+str(i))

		thing = offsets[(i+move_offset) % 12]
		#print("Checking "+str(tuple([place[0]+thing[0],place[1]+thing[1]])))
		if tuple([place[0]+thing[0],place[1]+thing[1]]) in other_elves:
			#print("Collision with "+str(tuple([place[0]+thing[0],place[1]+thing[1]])))
			#oof = False
			#print("tuple([place[0]+thing[0],place[1]+thing[1]]) == "+str(tuple([place[0]+thing[0],place[1]+thing[1]])))
			oof = True

			# this is sort of "break"
			#print("Previous i: "+str(i))
			#print("Jumping to "+str(((i//3)+1)*3))
			i = ((i//3)+1)*3
			thing = offsets[(i+move_offset) % 12]
			if i == 12:
				break
			continue

		if ((i+1) % 3) == 0:
			if oof and i != 0:
				#print("Returing")
				#print("i == "+str(i))
				#print("Proposed move for place "+str(place)+" is "+str(((i+move_offset) % 12)//3))
				return ((i+move_offset) % 12)//3
			oof = True
		
		i += 1

	return None

'''

'''
def check_collision(place, move_offset, other_elves):

	#offsets = [[[0,-1],[1,-1],[-1,-1]],   [[0,1],[1,1],[-1,1]],   [[-1,0],[-1,-1],[-1,1]],  [[1,0],[1,-1],[1,1]]] # the rules
	
	#offsets = [[0,-1],[1,-1],[-1,-1],   [0,1],[1,1],[-1,1],   [-1,0],[-1,-1],[-1,1],  [1,0],[1,-1],[1,1]]
	
	offsets = [N,NE,NW,   S,SE,SW,   W,NW,SW,  E,NE,SE]
	i = 0

	while i != 12:
		index = (i+move_offset) % 12
		thing = offsets[index]
		if tuple([place[0]+thing[0],place[1]+thing[1]]) in other_elves:

			i = ((i//3)+1)*3
			index = (i+move_offset) % 12
			thing = offsets[index]
			if i == 12:
				break
			continue

		if ((i+1) % 3) == 0:
			#if i != 0:
			return (index)//3
		i += 1
	return None
'''

'''
def check_collision(place, move_offset, other_elves):
	offsets = [N,NE,NW,   S,SE,SW,   W,NW,SW,  E,NE,SE]
	for _ in range(move_offset):
		thing = offsets.pop(0)
		offsets.append(thing)
	print("offsets == "+str(offsets))
	i = 0
	while i != 12:
		index = i
		thing = offsets[index]
		if tuple([place[0]+thing[0],place[1]+thing[1]]) in other_elves:
			i = ((i//3)+1)*3
			if i == 12:
				break
			index = i
			print("index == "+str(index))
			thing = offsets[index]
			
			continue
		if ((i+1) % 3) == 0:
			return (index)//3
		i += 1
	return None

'''


def rot_lst(n,lst):
	index = n % len(lst)
	return lst[index:] + lst[:index]

def check_collision(place, move_offset, other_elves):
	offsets = [N,NE,NW,   S,SE,SW,   W,NW,SW,  E,NE,SE]

	#for _ in range(move_offset):
	#	thing = offsets.pop(0)
	#	offsets.append(thing)

	#offsets = rot_lst(move_offset,offsets)

	offsets = offsets[move_offset%12:] + offsets[:move_offset%12]
	#print("offsets == "+str(offsets))
	i = 0
	while i != 12:
		index = i
		thing = offsets[index]
		#print("indexpoopoo == "+str(index))
		if tuple([place[0]+thing[0],place[1]+thing[1]]) in other_elves:
			#print("tuple([place[0]+thing[0],place[1]+thing[1]]) == "+str(tuple([place[0]+thing[0],place[1]+thing[1]])))
			i = ((i//3)+1)*3
			if i == 12:
				break
			index = i
			#print("index == "+str(index))
			thing = offsets[index]
			
			continue
		if ((i+1) % 3) == 0:
			#print("final index == "+str(index))
			#print("move_offset == "+str(move_offset))
			#print("returning this: "+str(((index+move_offset) % 12)//3))
			return ((index+move_offset) % 12)//3
			#print("i == "+str(i))
			#print()
			#return ((i) % 12)//3
		i += 1
	return None


def check_moving(cur_place, other_elves):

	# Check if the elf can move (checks the eight directional) .
	#print("Called check_moving with cur_place "+str(cur_place))
	neighbours = generate_neighbours(cur_place)

	#print("Neighbours: "+str(list(neighbours)))

	#count = 0

	for neig in neighbours:
		#print("Tuple of neighbour: "+str(tuple(neig)))
		if tuple(neig) in other_elves:
			return 1 # move

		#count += 1
	return 0 # do not move


def get_new_place(place, cur_move):
	'''
	match cur_move:
		case 0:
			return [place[0]+N[0], place[1]+N[1]]
		case 1:
			return [place[0]+S[0], place[1]+S[1]]
		case 2:
			return [place[0]+W[0], place[1]+W[1]]
		case 3:
			return [place[0]+E[0], place[1]+E[1]]
		case _:
			#print("Invalid proposed move index: "+str(cur_move))
			exit(1)
	'''

	if cur_move == 0:

		return [place[0]+N[0], place[1]+N[1]]

	elif cur_move == 1:

		return [place[0]+S[0], place[1]+S[1]]

	elif cur_move == 2:

		return [place[0]+W[0], place[1]+W[1]]

	elif cur_move == 3:

		return [place[0]+E[0], place[1]+E[1]]

	else:
		#print("Invalid proposed move index: "+str(cur_move))
		exit(1)
'''
def render_mat(mat):

	qr_matrix = np.invert(mat.astype(bool).T, dtype=bool)
	#print(qr_matrix.astype(int))
	qr_matrix = qr_matrix.astype(np.uint8)
	im = Image.fromarray(qr_matrix * 255)
	im.show()

def render_matrix(coords):
	#return

	min_x = min([k[0] for k in coords])
	min_y = min([k[1] for k in coords])

	max_x = max([k[0] for k in coords])
	max_y = max([k[1] for k in coords])

	print("max_y: "+str(max_y))
	print("max_x: "+str(max_x))

	print("min_y: "+str(min_y))
	print("min_x: "+str(min_x))

	print("coords == "+str(coords))

	x_shape = max_x-min_x
	y_shape = max_y-min_y

	matrix = np.zeros((x_shape+1, y_shape+1))
	#matrix = np.zeros((20, 20))
	for coord in coords:

		matrix[coord[0]-min_x,coord[1]-min_y] = 1

	render_mat(matrix)

	return
'''


def main_loop(n, coords, max_x, max_y, min_x, min_y):

	move_count = 0
	for i in range(n):
		moved_places = {}
		banlist = {}

		for place in coords:
			if check_moving(place, coords) == 0:
				continue
			proposed_move = check_collision(place, move_count,coords)

			if proposed_move == None: # Can not move
				
				continue

			##print("Proposed move for position "+str(place)+" is "+str(proposed_move))
			cur_index = coords[place] # get index of current elf.
			#print("Get new place:")
			new_place = get_new_place(place, proposed_move)

			# add the index into the new dictionary. This dictionary will be used to check for blocked moves.

			if tuple(new_place) not in moved_places:


				moved_places[tuple(new_place)] = ([tuple((cur_index, place))])
			else:
				moved_places[tuple(new_place)].append(tuple((cur_index, place)))

				#banlist.append()
				for pair in moved_places[tuple(new_place)]:
					banlist[pair[0]] = 1


		# Stage two


		#print("==== 2 =====")
		#print("Moved places: "+str(moved_places))


		for new_place in moved_places:
			element = moved_places[new_place]



			for thing in element:
				old_place = thing[1]

				index = thing[0]
				if index in banlist:
					continue
				coords.pop(old_place)
				coords[new_place] = index
		move_count += 3

	return coords


def calculate_area(coords):

	# Get the min x coord and min y coord

	min_x = min([k[0] for k in coords])
	min_y = min([k[1] for k in coords])

	max_x = max([k[0] for k in coords])
	max_y = max([k[1] for k in coords])
	
	#print("min_x: "+str(min_x))
	#print("min_y: "+str(min_y))
	#print("max_x: "+str(max_x))
	#print("max_y: "+str(max_y))
	area = 0

	for x in range(min_x, max_x+1):
		for y in range(min_y, max_y+1):
			if (x,y) not in coords:
				area += 1
	#print("Assert check:")		
	assert area == ((max_x-min_x+1)*(max_y-min_y+1))-len(coords)
	#print("passed")
	return area

def solve_puzzle():
	coordinates, max_x, max_y, min_x, min_y = parse_input()
	#print("coordinates == "+str(coordinates))

	# max_x, max_y, min_x, min_y

	final_coordinates = main_loop(10, coordinates,max_x, max_y, min_x, min_y)
	area = calculate_area(final_coordinates)
	return area


if __name__=="__main__":

	print("Solution to puzzle: "+str(solve_puzzle()))

```
{% endraw %}

Lets continue on with part two for now. Now the only difference is basically to instead of calculating the area, we count how many rounds it is until no-one moves. We can just add a boolean check.





















