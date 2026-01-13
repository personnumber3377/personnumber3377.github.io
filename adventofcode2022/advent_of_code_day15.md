
# Day 15 writeup

https://adventofcode.com/2022/day/15

The first part of this was quite fun, because I had to learn a bit about corner cases.

My initial thought was to create a list which signifies the wanted y coordinate and then calculate the range which I had to "mark out" of the list. Now you can not do this by simply counting since the areas can overlap so you can not just add the range to a counter and call it quits. Also another corner case to consider was that the beacon or the sensor was actually on the same line so you had to mark those out:

This is my code now:

{% raw %}
```

import numpy as np
import sys

PUZZLE_NUM = 1

negative_count = 0

'''

               1    1    2    2
     0    5    0    5    0    5
-2 ..........#.................
-1 .........###................
 0 ....S...#####...............
 1 .......#######........S.....
 2 ......#########S............
 3 .....###########SB..........
 4 ....#############...........
 5 ...###############..........
 6 ..#################.........
 7 .#########S#######S#........
 8 ..#################.........
 9 ...###############..........
10 ....B############...........
11 ..S..###########............
12 ......#########.............
13 .......#######..............
14 ........#####.S.......S.....
15 B........###................
16 ..........#SB...............
17 ................S..........B
18 ....S.......................
19 ............................
20 ............S......S........
21 ............................
22 .......................B....


'''


def print_line(line):
	print("".join(["#" if x == 1 else "." for x in line]))
	return


def parse_input()-> list:

	# This function creates a list of sensor coordinates and the coordinates of the nearest beacon.

	stuff = sys.stdin.buffer.read().decode('ascii')
	lines = stuff.split("\n")

	print(lines)
	max_x = 0
	for line in lines:

		words = line.split(" ")

		sensor_x = int(words[2][2:-1]) # Cut out the "x=" and the ","
		sensor_y = int(words[3][2:-1]) # Cut out the "y=" and the ":"

		beac_x = int(words[8][2:-1]) # Cut out the "x=" and the ","
		beac_y = int(words[9][2:]) # Cut out the "y="

		if sensor_x > max_x:
			max_x = sensor_x
		if beac_x > max_x:
			max_x = beac_x

		yield [[sensor_x, sensor_y], [beac_x, beac_y]]

	yield max_x


def manhattan_dist(p0,p1):
	# thanks wikipedia https://en.wikipedia.org/wiki/Taxicab_geometry    "For example, in R2, the taxicab distance between p=(p1,p2) and q=(q1,q2) is |p1 - q1| + |p2 - q2| ."

	# |p1 - q1| + |p2 - q2|
	print("Manhattan distance: "+str(abs(p0[0] - p1[0]) + abs(p0[1] - p1[1])))

	print("p0: "+str(p0))

	print("p1: "+str(p1))

	return abs(p0[0] - p1[0]) + abs(p0[1] - p1[1])

def line_dist(p,y0):
	
	# returns the manhattan distance from the point p to the line y=y0

	return abs(p[1]-y0) # the distance is simply the absolute value of the difference in the y coordinates


def write_line(line, sens_to_beac, sens_to_line, y_line, sensor, beacon):

	global negative_count

	# This actually writes to the line
	x_coord = sensor[0]

	y_coord = sensor[1]

	print("Line == "+str(line))
	print("len(line) == "+str(len(line)))
	print("sens_to_beac == "+str(sens_to_beac))
	print("sens_to_line == "+str(sens_to_line))
	print("x_coord == "+str(x_coord))

	# first is to get the "width" of the shape at the line y=2000000
	if sens_to_beac < sens_to_line:
		print("Does not intersect")
		# The shape does not intersect with the line
		return line



	width = sens_to_beac - sens_to_line
	
	assert width >= 0
	

	offset_thing = 10000000

	print("width == "+str(width))
	start_index = x_coord - width
	end_index = x_coord + width + 1 # + 1 because the range does not include the end index.
	#start_index += 5
	#end_index += 5
	start_index += 1000000
	end_index += 1000000
	assert start_index >= 0
	assert end_index >= 0
	assert end_index >= start_index
	print("start_index: "+str(start_index))
	print("end_index: "+str(end_index))
	line[start_index:end_index] = 1 # mark the line

	#if y_coord == y_line or beacon[1] == y_line:
		#negative_count += 1
		#print("Incremented negative_count!")

	return line 





def calculate_line(sensors_and_beacons: list) -> list:


	global negative_count
	max_x = sensors_and_beacons[-1]
	
	sensors_and_beacons.pop(-1) # the last element is the maximum x coordinate .

	line = np.array([0]*10000000) # I don't know how to create flat lists without doing this. If you do np.zeros((1,10)) you will get a matrix with one column instead of a list.
	#line = np.array([0]*100)
	#print(line)

	y_line = 2000000

	#y_line = 10

	# this next part is the core of the program. It fills in the spots where the beacon can not be, by calculating the Manhattan distance and then using that to mark the line.

	# we need the distance to the closest beacon and the distance to the line y=2000000
	count = 0

	for sens_and_beac in sensors_and_beacons:
		
		sens = sens_and_beac[0]
		closest_beac = sens_and_beac[1]

		dist_sens_to_beac = manhattan_dist(sens, closest_beac)

		dist_sens_to_line = line_dist(sens, y_line)
		#print("Dist sens_to_line : "+str(dist_sens_to_line))
		#print("dist_sens_to_beac : "+str(dist_sens_to_beac))

		line = write_line(line, dist_sens_to_beac, dist_sens_to_line,y_line, sens, closest_beac)
		#print("Line: "+str(line))
		#print("Line: ")
		#print_line(line)
	
	#return count

	# account for shit which is on the line itself

	distinct_sensors_y_coords = {thing[0][1] for thing in sensors_and_beacons}

	distinct_beacons_y_coords = {thing[1][1] for thing in sensors_and_beacons}

	for sens in distinct_sensors_y_coords:
		if sens == y_line:
			negative_count += 1

	for beac in distinct_beacons_y_coords:
		if beac == y_line:
			negative_count += 1



	return line

def solve_puzzle_part1():
	sensors_and_beacons = list(parse_input())


	result = calculate_line(sensors_and_beacons)
	print(result[100000-2:100000+30])
	result = sum(result) # the marked spaces where the beacon can not be is marked with ones and the rest are zeroes so the amount of spaces where it can not be is just the sum of this list.



	return result




if __name__=="__main__":
	if PUZZLE_NUM == 1:
		print("Solution to puzzle: "+str(solve_puzzle_part1()-negative_count))
		#print("negative_count == "+str(negative_count))

```
{% endraw %}

The way python handles ranges is pretty stupid now because when you try accessing with a negative index first and then a positive index like `list[-2:6]` this range is screwed up and does not work properly atleast for our purposes. To circumvent this I added an offset thing which solves our problems. This atleast works for the input given.

That I programmed before even I started to write this writeup. Now I am going to go through my thought process when trying to solve part two.

When looking at the prompt I realized that I can just check if the coordinates satisfies (or basically does not satisfy) every one of the constraints put on it by the sensors and beacons. The sensors and beacons basically form a circle in manhattan distance thing so we can check something like:

{% raw %}
```
for space in spaces:
    if space does not satisfy any of the constraints placed on it by beacons and sensors:
        space is found!

```
{% endraw %}


I am going to implement a check_if_inside function which checks if a point is inside a circle in taxicab manhattan space.

This would hypothetically work, but it is horribly slow in terms of performance. Instead of going through each possible coordinate, we can try to Think a bit smarter.

https://fasterthanli.me/series/advent-of-code-2022/part-15
















