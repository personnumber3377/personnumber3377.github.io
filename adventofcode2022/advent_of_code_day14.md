
# Day 14 writeup.

https://adventofcode.com/2022/day/14

Just read that first. Once again, I am going to first make a naive solution to this problem, but then if this algorithm turns out to be O(n**2) or worse, then I will try to optimize it.

I think that this problem is very similar to the game of life in the sense that the sand follows a certain update rule, but instead of counting neighbours, it advances forward itself.

The very first part is to parse the input. The input is a sequence of lines which describe the terrain.


```

from convenience import *
import sys



def handle_input():
	lines = sys.stdin.readlines()
	# Your scan traces the path of each solid rock structure and reports the x,y coordinates that form the shape of the path, where x represents distance to the right and y represents distance down. Each path appears as a single line of text in your scan. After the first point of each path, each point indicates the end of a straight horizontal or vertical line to be drawn from the previous point.

	# For example: 
	# 498,4 -> 498,6 -> 496,6
	# 503,4 -> 502,4 -> 502,9 -> 494,9

	out_list = []

	for line in lines:
		
		# each line corresponds to one "pattern"

		coords = line.split("->")
		coord_list = [[int(x) for x in coord.split(",")] for coord in coords]
		
		debug("coord_list == "+str(coord_list))

		out_list.append(coord_list)

	debug("out_list == "+str(out_list))

	return out_list




def draw_line(matrix, p0, p1):

	# Draw a straight line

	assert p0[0] == p1[0] or p0[1] == p1[1]


	y_start = min([p0[1], p1[1]])
	x_start = min([p0[0], p1[0]])

	y_end = max([p0[1], p1[1]])
	x_end = max([p0[0], p1[0]])

	matrix[y_start:y_end, x_start:x_end] = 1

	return matrix



def construct_matrix(coordinates):

	# Generate a numpy matrix from the coordinate list

	# First figure out the shape of the matrix:

	x_coord_max = 0
	y_coord_max = 0

	for line_thing in coordinates:
		for coord in line_thing:
			if coord[0] > x_coord_max:
				x_coord_max = coord[0]
			if coord[1] > y_coord_max:
				y_coord_max = coord[1]
	matrix = np.zeros((x_coord_max+1, y_coord_max+1)) # +1 , because if we do not add one we maybe get an edge case where the sand "falls" out of bounds of the matrix. This ensures that we should stay in bounds.

	# Place lines.

	for line_thing in coordinates:
		
		for i in range(len(line_thing)-1):

			matrix = draw_line(matrix, line_thing[i], line_thing[i+1]) # Draw line

	






def solve_puzzle():

	#terr_mat = handle_input()
	coord_list = handle_input()

	mat = construct_matrix(coord_list)




	return 0
```

The convenience package just has a bit of logging stuff.

Now that we have the matrix, it is time to simulate the sand falling through it.





