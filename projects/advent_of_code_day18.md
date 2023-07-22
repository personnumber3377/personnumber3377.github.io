
# Day 18

This problem is basically just a problem where we need to count the surface area of a formation made out of cubes. The neighbours of the cubes then add one to the area if they are vacant. The naive method would be to go throuh every spot and then check the neighbours of each block manually. This will probably work for part 1, but won't work for part2, but lets try it anyway.

```

import sys
import numpy as np

def parse_input():

	# return sys.stdin.buffer.read()#.decode('ascii')

	thing = sys.stdin.buffer.read().decode('ascii')

	thing = thing.split("\n")

	out = []
	max_coord = 0

	for coords in thing:
		poopoo = coords.split(",")

		poopoo = [int(x) for x in poopoo]

		out.append(poopoo)
		maximum = max(poopoo)

		if maximum > max_coord:
			max_coord = maximum

	return out, max_coord


def fill_cube(cube, coords):

	for coord in coords:
		cube[coord[0]+1,coord[1]+1,coord[2]+1] = 1
	return cube


def count_area(cube, max_coord):
	count = 0
	size = max_coord+2
	for x in range(1,size):
		for y in range(1,size):
			for z in range(1,size):

				# check if occupied
				
				if cube[x,y,z] == True:
					print("(x,y,z) == "+str("("+str(x)+","+str(y)+","+str(z)+")"))
					if cube[x-1,y,z] == False:
						count += 1

					if cube[x+1,y,z] == False:
						count += 1

					if cube[x,y-1,z] == False:
						count += 1

					if cube[x,y+1,z] == False:
						count += 1

					if cube[x,y,z+1] == False:
						count += 1

					if cube[x,y,z-1] == False:
						count += 1

	return count


def solve_puzzle():

	coords_list, max_coord = parse_input()
	
	cube_size = max_coord+3

	cube_thing = np.zeros((cube_size,cube_size,cube_size), dtype=bool)

	cube_thing = fill_cube(cube_thing, coords_list)
	print(cube_thing)


	area = count_area(cube_thing, max_coord)

	return area



if __name__=="__main__":

	print(solve_puzzle())
	exit(0)



```

The second part of the puzzle is actually not what I expected. I expected the input to be a lot bigger, but it requires us to find the outer surface-area of the object. My first thought is to use pathfinding to find all of the nooks and crannies of the shape and then create a sort of "mask" to mask off the actual outer shape and then calculate that. Another idea is to "walk" over the surface by just going through the neighbours of the outer pieces.


Now here is my code:


```

import sys
import numpy as np

def parse_input():

	# return sys.stdin.buffer.read()#.decode('ascii')

	thing = sys.stdin.buffer.read().decode('ascii')

	thing = thing.split("\n")

	out = []
	max_coord = 0

	for coords in thing:
		poopoo = coords.split(",")

		poopoo = [int(x) for x in poopoo]

		out.append(poopoo)
		maximum = max(poopoo)

		if maximum > max_coord:
			max_coord = maximum

	return out, max_coord


def fill_cube(cube, coords):

	for coord in coords:
		cube[coord[0]+1,coord[1]+1,coord[2]+1] = 1
	return cube


def count_area(cube, max_coord):
	count = 0
	size = max_coord+2
	for x in range(1,size):
		for y in range(1,size):
			for z in range(1,size):

				# check if occupied
				
				if cube[x,y,z] == True:
					print("(x,y,z) == "+str("("+str(x)+","+str(y)+","+str(z)+")"))
					if cube[x-1,y,z] == False:
						count += 1

					if cube[x+1,y,z] == False:
						count += 1

					if cube[x,y-1,z] == False:
						count += 1

					if cube[x,y+1,z] == False:
						count += 1

					if cube[x,y,z+1] == False:
						count += 1

					if cube[x,y,z-1] == False:
						count += 1

	return count



def check_stuff(x,y,z,marked_cube,new_marked_stuff,index,cube):


	index_thing = [x,y,z]


	print("marked_cube[*index_thing] == "+str(marked_cube[*index_thing]))

	if index_thing[index] == 0:
		index_thing[index] += 1

		if marked_cube[*index_thing] != 1 and cube[*index_thing] != 1:
			
			new_marked_stuff.append([*index_thing])
			marked_cube[*index_thing] = 1

	elif index_thing[index] == cube.shape[0]-1:
		

		'''
		index_thing[index] += 1
		if marked_cube[*index_thing] != 1 and cube[*index_thing] != 1:
			
			new_marked_stuff.append([*index_thing])
			marked_cube[*index_thing] = 1

		
		'''

		index_thing[index] -= 1



		if marked_cube[*index_thing] != 1 and cube[*index_thing] != 1:
			
			new_marked_stuff.append([x+1,y,z])
			marked_cube[*index_thing] = 1
	
	else:

		index_thing[index] += 1
		if marked_cube[*index_thing] != 1 and cube[*index_thing] != 1:
			
			new_marked_stuff.append([*index_thing])
			marked_cube[*index_thing] = 1

		index_thing[index] -= 2 # -= 2 because we incremented it by one so to get one lower we must subtract two. one to get to the original value and then one to get to the value which is one less than the original value.


		if marked_cube[*index_thing] != 1 and cube[*index_thing] != 1:
			
			new_marked_stuff.append([x+1,y,z])
			marked_cube[*index_thing] = 1

	return marked_cube, new_marked_stuff



def path_find(cube):

	# This returns the outer shape of the shape.

	marked_stuff = [[0,0,0]]

	marked_cube = np.zeros(cube.shape)

	while True:

		if marked_stuff == []:
			break
		
		new_marked_stuff = []
		
		for coordinates in marked_stuff:

			x = coordinates[0]
			y = coordinates[1]
			z = coordinates[2]
			# check neighbours

			marked_cube, new_marked_stuff = check_stuff(x,y,z,marked_cube,new_marked_stuff,0,cube)
			marked_cube, new_marked_stuff = check_stuff(x,y,z,marked_cube,new_marked_stuff,1,cube)
			marked_cube, new_marked_stuff = check_stuff(x,y,z,marked_cube,new_marked_stuff,2,cube)

		marked_stuff = new_marked_stuff


	return marked_cube






def solve_puzzle():

	coords_list, max_coord = parse_input()
	
	cube_size = max_coord+3

	cube_thing = np.zeros((cube_size,cube_size,cube_size), dtype=bool)

	cube_thing = fill_cube(cube_thing, coords_list)
	print(cube_thing)


	outer_shape = path_find(cube_thing)

	# get the actual shape. the outer_shape is a matrix where the outside is marked

	rock = np.logical_not(outer_shape)
	print("Here is the rock:")
	print(rock)
	#area = count_area(cube_thing, max_coord)
	area = count_area(rock, max_coord)

	return area



if __name__=="__main__":

	print(solve_puzzle())
	exit(0)

```

For some reason it does not work. I have absolutely no idea why so I am going to add a "sanity check" which checks that the rock and the marked area becomes a shape which is all ones.





















