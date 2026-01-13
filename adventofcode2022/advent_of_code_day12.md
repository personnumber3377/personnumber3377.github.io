# Day 12

https://adventofcode.com/2022/day/12

This is quite a fun little challenge.

First things first let's program the parse function for the input. I think I want to make a numpy matrix.

{% raw %}
```


def get_map() -> np.array:
	input_stuff = sys.stdin.read()
	lines = input_stuff.split("\n")

	mat_width = len(lines[0])
	mat_height = len(lines)
	out_matrix = np.zeros((mat_height, mat_width))

	for i, line in enumerate(lines):
		for j, char in enumerate(line):
			
			if char == "S":
				start_point = (i,j)
			elif char == "E":
				end_point = (i,j)
			else:

				num = ord(char) - 97 # ord('a') = 97

				out_matrix[i,j] = num # Update map

	debug(out_matrix)
	return out_matrix, start_point, end_point


```
{% endraw %}

Now my idea is to just make a modified version of a pathfinding algorithm. https://en.wikipedia.org/wiki/Pathfinding#Sample_algorithm

Except that instead of the walls, we have a condition to check if we can move.

After a bit of dabbling I now have this:

{% raw %}
```


def solve() -> int:
	rock_map, start_point, end_point, w, h = get_map()
	debug("rock_map == "+str(rock_map))

	flood_map = np.zeros(rock_map.shape)

	flood_map[start_point[0], start_point[1]] = 1 # Set the start for pathfinding.

	step_count = 0
	important = False
	while flood_map[end_point[0], end_point[1]] == 0:

		# First update the flood map.

		for i in range(h):
			for j in range(w):
				integer = flood_map[i][j]
				#print("integer flood_map[i][j] == "+str(flood_map[i][j]))
				#print("flood_map[i] == "+str(flood_map[i]))
				#print("flood_map[i][j] == "+str(flood_map[i][j]))
				print("i == "+str(i))
				print("j == "+str(j))
				#print("flood_map == "+str(flood_map))
				#print("flood_map[0] == "+str(flood_map[0]))
				#print("flood_map[3] == "+str(flood_map[3]))

				cur_coordinates = [i,j]


				#if i == 1 and j == 1:
				#	print("IMPORTANT")

				if integer >= 1:
					#print("line == "+str(line))
					# Now check neighbours and increment.

					cur_height = rock_map[i][j]

					neighbours = [[i,j-1], [i,j+1], [i+1,j], [i-1,j]]

					if i == 3 and j == 2:
						print("IMPORTANT")
						debug("neighbours == "+str(neighbours))
						important = True
					# bounds check neighbours.
					# 2, 4


					for count, neig in enumerate(neighbours):
						if -1 in neig:
							neighbours[count] = None

						elif neig[0] >= w:
							neighbours[count] = None
						elif neig[1] >= h:
							neighbours[count] = None

					while None in neighbours:
						neighbours.remove(None) # Delete all invalid positions.
					if important:
						print("neighbours after == "+str(neighbours))

					for neig in neighbours:

						y = neig[0]
						x = neig[1]

						other_height = rock_map[y][x]
						if important:
							print("x == "+str(x))
							print("y == "+str(y))
							if x == 4 and y == 2:
								print("cur_height == "+str(cur_height))
								print("other_height == "+str(other_height))
						#print("cur_height == "+str(cur_height))
						#print("other_height == "+str(other_height))
						if cur_height - other_height >= -1: # The other rock can be one more than current height

							#print("Incrementing!")
							#print("[i,j] == "+str([i,j]))
							#print("flood_map[i,j] == "+str(flood_map[i][j]))
							#print("flood_map before increment: "+str(flood_map))
							#flood_map[i][j] += 1
							#print("pooopooooo")

							flood_map[y][x] += 1
							#print("flood_map[y][x] == "+str(flood_map[y][x]))
							#print("after: "+str(flood_map))
				#elif integer > 1:
				#	flood_map[cur_coordinates[0]][cur_coordinates[1]] += 1
				debug("flood_map == "+str(flood_map))
				important = False
		step_count += 1
		
	return step_count


```
{% endraw %}

Now, there is a bug because I get this error when I run it with the example input:

{% raw %}
```

Traceback (most recent call last):
  File "/home/cyberhacker/Asioita/Ohjelmointi/adventofcode2022/chapter_12/main.py", line 143, in <module>
    exit(main())
         ^^^^^^
  File "/home/cyberhacker/Asioita/Ohjelmointi/adventofcode2022/chapter_12/main.py", line 136, in main
    min_path_length = solve()
                      ^^^^^^^
  File "/home/cyberhacker/Asioita/Ohjelmointi/adventofcode2022/chapter_12/main.py", line 105, in solve
    other_height = rock_map[y][x]
                   ~~~~~~~~^^^
IndexError: index 5 is out of bounds for axis 0 with size 5


```
{% endraw %}

After fixing one bug in it, it still does not work:

{% raw %}
```


def solve() -> int:
	rock_map, start_point, end_point, w, h = get_map()
	debug("rock_map == "+str(rock_map))

	flood_map = np.zeros(rock_map.shape)

	flood_map[start_point[0], start_point[1]] = 1 # Set the start for pathfinding.

	step_count = 0
	important = False
	while flood_map[end_point[0], end_point[1]] == 0:
		print("New step!")
		# First update the flood map.
		modified = set()
		for i in range(h):
			for j in range(w):
				integer = flood_map[i][j]
				#print("integer flood_map[i][j] == "+str(flood_map[i][j]))
				#print("flood_map[i] == "+str(flood_map[i]))
				#print("flood_map[i][j] == "+str(flood_map[i][j]))
				print("i == "+str(i))
				print("j == "+str(j))
				#print("flood_map == "+str(flood_map))
				#print("flood_map[0] == "+str(flood_map[0]))
				#print("flood_map[3] == "+str(flood_map[3]))

				cur_coordinates = [i,j]


				#if i == 1 and j == 1:
				#	print("IMPORTANT")

				if integer >= 1:
					#print("line == "+str(line))
					# Now check neighbours and increment.

					cur_height = rock_map[i][j]

					neighbours = [[i,j-1], [i,j+1], [i+1,j], [i-1,j]]

					if i == 3 and j == 2:
						print("IMPORTANT")
						debug("neighbours == "+str(neighbours))
						important = True
					# bounds check neighbours.
					# 2, 4


					for count, neig in enumerate(neighbours):
						if -1 in neig:
							neighbours[count] = None

						elif neig[1] >= w:
							neighbours[count] = None
						elif neig[0] >= h:
							neighbours[count] = None

					while None in neighbours:
						neighbours.remove(None) # Delete all invalid positions.
					#if important:
					#	print("neighbours after == "+str(neighbours))

					print("w == "+str(w))
					print("h == "+str(h))
					print("neighbours after == "+str(neighbours))
					for neig in neighbours:
						if tuple(neig) in modified:
							continue

						modified.add(tuple(neig))
						y = neig[0]
						x = neig[1]
						print("x == "+str(x))
						print("y == "+str(y))
						other_height = rock_map[y][x]
						if important:
							print("x == "+str(x))
							print("y == "+str(y))
							if x == 4 and y == 2:
								print("cur_height == "+str(cur_height))
								print("other_height == "+str(other_height))
						#print("cur_height == "+str(cur_height))
						#print("other_height == "+str(other_height))
						if cur_height - other_height >= -1: # The other rock can be one more than current height

							#print("Incrementing!")
							#print("[i,j] == "+str([i,j]))
							#print("flood_map[i,j] == "+str(flood_map[i][j]))
							#print("flood_map before increment: "+str(flood_map))
							#flood_map[i][j] += 1
							#print("pooopooooo")

							flood_map[y][x] += 1
							#print("flood_map[y][x] == "+str(flood_map[y][x]))
							#print("after: "+str(flood_map))
				#elif integer > 1:
				#	flood_map[cur_coordinates[0]][cur_coordinates[1]] += 1
				
				important = False
		debug("flood_map == "+str(flood_map))
		step_count += 1
		
	return step_count


```
{% endraw %}

This never finds the path. I think I should actually follow the advice of the wikipedia page and do it that way.

{% raw %}
```


import numpy as np
import sys

DEBUG = True

def debug(thing):
	if DEBUG:

		print("[DEBUG] "+str(thing))


def get_map() -> np.array:
	input_stuff = sys.stdin.read()
	lines = input_stuff.split("\n")

	mat_width = len(lines[0])
	mat_height = len(lines)
	out_matrix = np.zeros((mat_height, mat_width))

	for i, line in enumerate(lines):
		for j, char in enumerate(line):
			
			if char == "S":
				start_point = (i,j)
			elif char == "E":
				end_point = (i,j)
				
			else:

				num = ord(char) - 97 # ord('a') = 97

				out_matrix[i][j] = num # Update map

	debug(out_matrix)
	return out_matrix, start_point, end_point, mat_width, mat_height



def render_solution(w,h,shit_oof2):
	matrix = np.zeros((h,w))
	for thing in shit_oof2:
		x = thing[1]
		y = thing[0]

		matrix[y][x] = thing[2]

	print(matrix)

	return




def solve() -> int:
	rock_map, start_point, end_point, w, h = get_map()
	debug("rock_map == "+str(rock_map))

	flood_map = np.zeros(rock_map.shape)

	flood_map[start_point[0], start_point[1]] = 1 # Set the start for pathfinding.

	step_count = 0
	important = False
	shit_oof = set({tuple((0,0))})
	shit_oof2 = set({tuple((0,0,0))})
	print("start_point == "+str(start_point))
	print("tuple(start_point) == "+str(tuple(start_point)))
	print("poop shit_oof "+str(shit_oof))
	while tuple(end_point) not in shit_oof:
		print("New step!")
		# First update the flood map.
		#modified = set()
		print("shit_oofeeweewewew == "+str(shit_oof))

		to_add = []
		for place in shit_oof:
			print("place == "+str(place))
			i = place[0]
			j = place[1]
			integer = 1
			#print("integer flood_map[i][j] == "+str(flood_map[i][j]))
			#print("flood_map[i] == "+str(flood_map[i]))
			#print("flood_map[i][j] == "+str(flood_map[i][j]))
			print("i == "+str(i))
			print("j == "+str(j))
			#print("flood_map == "+str(flood_map))
			#print("flood_map[0] == "+str(flood_map[0]))
			#print("flood_map[3] == "+str(flood_map[3]))

			cur_coordinates = place


			#if i == 1 and j == 1:
			#	print("IMPORTANT")

			if integer >= 1:
				#print("line == "+str(line))
				# Now check neighbours and increment.

				cur_height = rock_map[i][j]

				neighbours = [[i,j-1], [i,j+1], [i+1,j], [i-1,j]]

				if i == 3 and j == 2:
					print("IMPORTANT")
					debug("neighbours == "+str(neighbours))
					important = True
				# bounds check neighbours.
				# 2, 4


				for count, neig in enumerate(neighbours):
					if -1 in neig:
						neighbours[count] = None

					elif neig[1] >= w:
						neighbours[count] = None
					elif neig[0] >= h:
						neighbours[count] = None

				while None in neighbours:
					neighbours.remove(None) # Delete all invalid positions.
				#if important:
				#	print("neighbours after == "+str(neighbours))

				print("w == "+str(w))
				print("h == "+str(h))
				print("neighbours after == "+str(neighbours))
				for neig in neighbours:
					if tuple(neig) in shit_oof: # Check if modified
						continue

					#modified.add(tuple(neig))
					y = neig[0]
					x = neig[1]
					print("x == "+str(x))
					print("y == "+str(y))
					other_height = rock_map[y][x]
					if important:
						print("x == "+str(x))
						print("y == "+str(y))
						if x == 4 and y == 2:
							print("cur_height == "+str(cur_height))
							print("other_height == "+str(other_height))
					#print("cur_height == "+str(cur_height))
					#print("other_height == "+str(other_height))
					if cur_height - other_height >= -1: # The other rock can be one more than current height

						#print("Incrementing!")
						#print("[i,j] == "+str([i,j]))
						#print("flood_map[i,j] == "+str(flood_map[i][j]))
						#print("flood_map before increment: "+str(flood_map))
						#flood_map[i][j] += 1
						#print("pooopooooo")

						#flood_map[y][x] += 1 # instead of adding to the flood map, we just add this position to the set

						#shit_oof.add(tuple(neig))
						to_add.append(tuple(neig))
						print("shit_oof == "+str(shit_oof))
						#print("flood_map[y][x] == "+str(flood_map[y][x]))
						#print("after: "+str(flood_map))
			#elif integer > 1:
			#	flood_map[cur_coordinates[0]][cur_coordinates[1]] += 1

			important = False
		for thing in to_add:
			shit_oof.add(thing)
			shit_oof2.add(tuple(list(thing)+[step_count]))
		#debug("flood_map == "+str(flood_map))
		print("shit_oof == "+str(shit_oof))
		print("shit_oof2 == "+str(shit_oof2))
		step_count += 1

	render_solution(w,h,shit_oof2)
		
	return step_count

def main():

	min_path_length = solve()
	print(min_path_length)
	return 0


if __name__=="__main__":

	exit(main())



```
{% endraw %}

After actually implementing the wikipedia algorithm, we now get 25 as the result for the toy example. I programmed a render_solution function which tells us the problem.

Looking at the render_solution output:

{% raw %}
```

[[ 0.  0.  1. 18. 17. 16. 15. 14.]
 [ 0.  1.  2. 19.  0.  0.  0. 13.]
 [ 1.  2.  3. 20.  0. 24.  0. 12.]
 [ 2.  3.  4. 21. 22. 23. 24. 11.]
 [ 3.  4.  5.  6.  7.  8.  9. 10.]]

```
{% endraw %}

I overlooked one crucial detail in the challenge statement: "... the location that should get the best signal (E) has elevation z." . There is the problem. After setting the end to z height by modifying the parser function:

{% raw %}
```

def get_map() -> np.array:
	input_stuff = sys.stdin.read()
	lines = input_stuff.split("\n")

	mat_width = len(lines[0])
	mat_height = len(lines)
	out_matrix = np.zeros((mat_height, mat_width))

	for i, line in enumerate(lines):
		for j, char in enumerate(line):
			
			if char == "S":
				start_point = (i,j)
			elif char == "E":
				end_point = (i,j)
				num = ord("z") - 97 # ord('a') = 97

				out_matrix[i][j] = num # Update map
			else:

				num = ord(char) - 97 # ord('a') = 97

				out_matrix[i][j] = num # Update map

	debug(out_matrix)
	return out_matrix, start_point, end_point, mat_width, mat_height

```
{% endraw %}

Now it works with the toy input. What about the actual input? Aaaaannnd no. It doesn't work. I am going to solve this tomorrow.



## Making it work with the not toy input

Let's make a function which shows the route by going from the end and advancing to the next step. Except let's not do that because the bug was in the lines:

{% raw %}
```
	shit_oof = set({tuple((0,0))})
	shit_oof2 = set({tuple((0,0,0))})
```
{% endraw %}

because I just assumed the start was at 0,0 , when I changed them to this:

{% raw %}
```

	shit_oof = set({tuple(start_point)})
	shit_oof2 = set({tuple((start_point[0],start_point[1], 0))})

```
{% endraw %}

Now it works perfectly.



## Making it faster.

Instead of jumping to the second part straight away, I am going to first optimize the code, because part two is essentially just a for loop for each spot which has "a" in it.

Cprofile:

{% raw %}
```

[[ 19.  20.  21. ... 228. 229. 230.]
 [ 18.  19.  20. ... 227. 228. 229.]
 [ 17.  18.  19. ... 226. 227. 228.]
 ...
 [ 17.  18.  19. ... 192. 191. 192.]
 [ 18.  19.  20. ... 189. 190. 191.]
 [ 19.  20.  21. ... 188. 189. 190.]]
472
         253461 function calls (251592 primitive calls) in 8.642 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        1    8.465    8.465    8.503    8.503 main.py:68(solve)
   139733    0.024    0.000    0.024    0.000 {method 'remove' of 'list' objects}
      105    0.013    0.000    0.013    0.000 {built-in method marshal.loads}
    25/23    0.009    0.000    0.011    0.000 {built-in method _imp.create_dynamic}
  204/203    0.005    0.000    0.007    0.000 {built-in method builtins.__build_class__}
        1    0.005    0.005    0.005    0.005 main.py:23(get_map)
      280    0.005    0.000    0.015    0.000 <frozen importlib._bootstrap_external>:1676(find_spec)
      580    0.003    0.000    0.003    0.000 {built-in method posix.stat}
    22168    0.003    0.000    0.003    0.000 {method 'add' of 'set' objects}
      476    0.003    0.000    0.005    0.000 <frozen importlib._bootstrap>:216(acquire)
      105    0.003    0.000    0.016    0.000 <frozen importlib._bootstrap_external>:764(_compile_bytecode)
        1    0.003    0.003    0.004    0.004 main.py:53(render_solution)
     3924    0.003    0.000    0.003    0.000 {built-in method builtins.getattr}
      614    0.003    0.000    0.003    0.000 _inspect.py:65(getargs)
     1418    0.002    0.000    0.003    0.000 <frozen importlib._bootstrap_external>:128(<listcomp>)
      105    0.002    0.000    0.002    0.000 {built-in method io.open_code}
     1418    0.002    0.000    0.005    0.000 <frozen importlib._bootstrap_external>:126(_path_join)
      314    0.002    0.000    0.014    0.000 overrides.py:170(decorator)
      105    0.002    0.000    0.002    0.000 {method 'read' of '_io.BufferedReader' objects}
      140    0.002    0.000    0.022    0.000 <frozen importlib._bootstrap>:1183(_find_spec)
    25/16    0.002    0.000    0.010    0.001 {built-in method _imp.exec_dynamic}
      327    0.002    0.000    0.003    0.000 functools.py:35(update_wrapper)
    375/8    0.002    0.000    0.133    0.017 {built-in method builtins.__import__}
      476    0.002    0.000    0.002    0.000 <frozen importlib._bootstrap>:284(release)


```
{% endraw %}


I found this: https://github.com/mahakaal/adventofcode/blob/main/2022/day12/day12.py  on this reddit comment: https://www.reddit.com/r/adventofcode/comments/zjnruc/comment/j3ja3na/?utm_source=share&utm_medium=web2x&context=3

I am going to compare the performance of that with my implementation.

I modified it such that it takes input from stdin, so that does not affect anything.

Here are the results:

{% raw %}
```

Part 1 - 472
         93341 function calls in 0.080 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        1    0.059    0.059    0.079    0.079 main.py:33(bfs)
     6252    0.010    0.000    0.010    0.000 main.py:10(get_adjacent)
    22773    0.005    0.000    0.005    0.000 {method 'append' of 'list' objects}
    22774    0.002    0.000    0.002    0.000 {method 'append' of 'collections.deque' objects}
    22744    0.002    0.000    0.002    0.000 {method 'popleft' of 'collections.deque' objects}
    12505    0.001    0.000    0.001    0.000 {built-in method builtins.len}
     6253    0.001    0.000    0.001    0.000 {method 'add' of 'set' objects}
        1    0.001    0.001    0.080    0.080 main.py:1(<module>)
        1    0.000    0.000    0.000    0.000 {built-in method builtins.print}
        1    0.000    0.000    0.000    0.000 main.py:7(<listcomp>)
        1    0.000    0.000    0.000    0.000 {method 'read' of '_io.TextIOWrapper' objects}
        1    0.000    0.000    0.000    0.000 {method 'split' of 'str' objects}
        1    0.000    0.000    0.000    0.000 main.py:34(<dictcomp>)
        1    0.000    0.000    0.080    0.080 {built-in method builtins.exec}
        1    0.000    0.000    0.000    0.000 <frozen codecs>:319(decode)
        2    0.000    0.000    0.000    0.000 {method 'index' of 'list' objects}
       26    0.000    0.000    0.000    0.000 {built-in method builtins.chr}
        1    0.000    0.000    0.000    0.000 {built-in method _codecs.utf_8_decode}
        1    0.000    0.000    0.000    0.000 {method 'disable' of '_lsprof.Profiler' objects}
        1    0.000    0.000    0.000    0.000 {method 'strip' of 'str' objects}


```
{% endraw %}

Yeah, I have a long way to go. First let's do a code cleanup. I have a nasty habit of leaving the comments from my previous tries in instead of just removing the code. Then another idea is that I am actually going through a lot of spaces which aren't really used in a way. Instead of going through all of the spots, we can just go through the spots which are new. This decreases the execution time to a lot less:

{% raw %}
```

472
         112336 function calls (110563 primitive calls) in 0.193 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        1    0.045    0.045    0.054    0.054 main.py:68(solve)
      105    0.013    0.000    0.013    0.000 {built-in method marshal.loads}
    25/23    0.010    0.000    0.014    0.001 {built-in method _imp.create_dynamic}
        1    0.005    0.005    0.006    0.006 main.py:23(get_map)
  204/203    0.005    0.000    0.007    0.000 {built-in method builtins.__build_class__}
      280    0.005    0.000    0.015    0.000 <frozen importlib._bootstrap_external>:1676(find_spec)

```
{% endraw %}



















