
# Day 10

Ok so this is quite an interesting little puzzle, because we are basically making a virtual machine with only two instructions.

As usual let's program a parsing function first for the input.


{% raw %}
```

def parse_input() -> list:

	stdin_input = sys.stdin.read()
	lines = stdin_input.split("\n")
	
	out = []

	for line in lines:
		if line[0] == "n":
			# nop
			out.append([0])
		else:
			# assume addx
			#print("line.split(" ") == "+str(line.split(" ")))
			#print("line == "+str(line))
			out.append([1, int(line.split(" ")[1])])
	return out


```
{% endraw %}

Then let's create the virtual machine of sorts:

{% raw %}
```

def run_program(program: list) -> int:

	rip = 0

	x = 1

	#result_list = []
	result = 0
	cur_cycle = 0

	while rip != len(program):

		instruction = program[rip] # Fetch

		if instruction[0]:

			debug("Addx instruction. X before: "+str(x))

			# addx instruction
			cur_cycle,result = check_cycle(x,cur_cycle,result,rip=rip)
			cur_cycle,result = check_cycle(x,cur_cycle,result,rip=rip) # x is unmodified for the first two clock cycles, then gets incremented.
			x += instruction[1]
			debug("X after: "+str(x))

			
		else:
			# assume nop
			cur_cycle,result = check_cycle(x,cur_cycle,result,rip=rip)
			#cur_cycle,result = check_cycle(x,cur_cycle,result) # advance the clock for two cycles.

		rip += 1

	if TEST_1:
		assert x == -1


	return result

```
{% endraw %}

The check_cycle is just a function to check if we should add to the total amount:


{% raw %}
```

def check_cycle(x,cur_cycle, result, rip=None): # This is if we want to add to the result.
	if (cur_cycle - 20) % 40 == 0:
		print("x at cycle number "+str(cur_cycle)+" is "+str(x))
		print("rip is "+str(rip))
		print("result == "+str(result))
		print("(cur_cycle * x) == "+str((cur_cycle * x)))
		return cur_cycle + 1, result + (cur_cycle * x)
	else:
		return cur_cycle + 1, result

```
{% endraw %}

Now there was a bug in this program. Can you see it? I got this with this program:

{% raw %}
```

[DEBUG] Addx instruction. X before: 1
[DEBUG] X after: 16
[DEBUG] Addx instruction. X before: 16
[DEBUG] X after: 5
[DEBUG] Addx instruction. X before: 5
[DEBUG] X after: 11
[DEBUG] Addx instruction. X before: 11
[DEBUG] X after: 8
[DEBUG] Addx instruction. X before: 8
[DEBUG] X after: 13
[DEBUG] Addx instruction. X before: 13
[DEBUG] X after: 12
[DEBUG] Addx instruction. X before: 12
[DEBUG] X after: 4
[DEBUG] Addx instruction. X before: 4
[DEBUG] X after: 17
[DEBUG] Addx instruction. X before: 17
[DEBUG] X after: 21
[DEBUG] Addx instruction. X before: 21
x at cycle number 20 is 21
rip is 10
result == 0
(cur_cycle * x) == 420
[DEBUG] X after: 20
[DEBUG] Addx instruction. X before: 20
[DEBUG] X after: 25
[DEBUG] Addx instruction. X before: 25
[DEBUG] X after: 24
[DEBUG] Addx instruction. X before: 24
[DEBUG] X after: 29
[DEBUG] Addx instruction. X before: 29
[DEBUG] X after: 28
[DEBUG] Addx instruction. X before: 28
[DEBUG] X after: 33
[DEBUG] Addx instruction. X before: 33
[DEBUG] X after: 32
[DEBUG] Addx instruction. X before: 32
[DEBUG] X after: 37
[DEBUG] Addx instruction. X before: 37
[DEBUG] X after: 36
[DEBUG] Addx instruction. X before: 36
[DEBUG] X after: 1
[DEBUG] Addx instruction. X before: 1
[DEBUG] X after: 2
[DEBUG] Addx instruction. X before: 2
[DEBUG] X after: 26
[DEBUG] Addx instruction. X before: 26
[DEBUG] X after: 7
[DEBUG] Addx instruction. X before: 7
[DEBUG] X after: 8
[DEBUG] Addx instruction. X before: 8
[DEBUG] X after: 24
[DEBUG] Addx instruction. X before: 24
[DEBUG] X after: 13
[DEBUG] Addx instruction. X before: 13
[DEBUG] X after: 34
[DEBUG] Addx instruction. X before: 34
[DEBUG] X after: 19
[DEBUG] Addx instruction. X before: 19
x at cycle number 60 is 19
rip is 32
result == 420
(cur_cycle * x) == 1140
[DEBUG] X after: 16
[DEBUG] Addx instruction. X before: 16
[DEBUG] X after: 25
[DEBUG] Addx instruction. X before: 25
[DEBUG] X after: 26
[DEBUG] Addx instruction. X before: 26
[DEBUG] X after: 23
[DEBUG] Addx instruction. X before: 23
[DEBUG] X after: 31
[DEBUG] Addx instruction. X before: 31
[DEBUG] X after: 32
[DEBUG] Addx instruction. X before: 32
[DEBUG] X after: 37
[DEBUG] Addx instruction. X before: 37
[DEBUG] X after: 1
[DEBUG] Addx instruction. X before: 1
[DEBUG] X after: 2
[DEBUG] Addx instruction. X before: 2
[DEBUG] X after: 9
[DEBUG] Addx instruction. X before: 9
[DEBUG] X after: 11
[DEBUG] Addx instruction. X before: 11
[DEBUG] X after: 17
[DEBUG] Addx instruction. X before: 17
[DEBUG] X after: 18
x at cycle number 100 is 18
rip is 60
result == 1560
(cur_cycle * x) == 1800
[DEBUG] Addx instruction. X before: 18
[DEBUG] X after: 25
[DEBUG] Addx instruction. X before: 25
[DEBUG] X after: 26
[DEBUG] Addx instruction. X before: 26
[DEBUG] X after: 13
[DEBUG] Addx instruction. X before: 13
[DEBUG] X after: 26
[DEBUG] Addx instruction. X before: 26
[DEBUG] X after: 33
[DEBUG] Addx instruction. X before: 33
[DEBUG] X after: 34
[DEBUG] Addx instruction. X before: 34
[DEBUG] X after: 1
[DEBUG] Addx instruction. X before: 1
[DEBUG] X after: 3
[DEBUG] Addx instruction. X before: 3
[DEBUG] X after: 11
[DEBUG] Addx instruction. X before: 11
[DEBUG] X after: 10
[DEBUG] Addx instruction. X before: 10
[DEBUG] X after: 12
[DEBUG] Addx instruction. X before: 12
[DEBUG] X after: 13
[DEBUG] Addx instruction. X before: 13
[DEBUG] X after: 30
[DEBUG] Addx instruction. X before: 30
[DEBUG] X after: 21
[DEBUG] Addx instruction. X before: 21
x at cycle number 140 is 21
rip is 85
result == 3360
(cur_cycle * x) == 2940
[DEBUG] X after: 22
[DEBUG] Addx instruction. X before: 22
[DEBUG] X after: 23
[DEBUG] Addx instruction. X before: 23
[DEBUG] X after: 20
[DEBUG] Addx instruction. X before: 20
[DEBUG] X after: 31
[DEBUG] Addx instruction. X before: 31
[DEBUG] X after: 32
[DEBUG] Addx instruction. X before: 32
[DEBUG] X after: 33
[DEBUG] Addx instruction. X before: 33
[DEBUG] X after: 20
[DEBUG] Addx instruction. X before: 20
[DEBUG] X after: 1
[DEBUG] Addx instruction. X before: 1
[DEBUG] X after: 2
[DEBUG] Addx instruction. X before: 2
[DEBUG] X after: 5
[DEBUG] Addx instruction. X before: 5
[DEBUG] X after: 31
[DEBUG] Addx instruction. X before: 31
[DEBUG] X after: 1
[DEBUG] Addx instruction. X before: 1
[DEBUG] X after: 13
[DEBUG] Addx instruction. X before: 13
[DEBUG] X after: 12
[DEBUG] Addx instruction. X before: 12
[DEBUG] X after: 15
[DEBUG] Addx instruction. X before: 15
[DEBUG] X after: 16
[DEBUG] Addx instruction. X before: 16
x at cycle number 180 is 16
rip is 109
result == 6300
(cur_cycle * x) == 2880
[DEBUG] X after: 7
[DEBUG] Addx instruction. X before: 7
[DEBUG] X after: 25
[DEBUG] Addx instruction. X before: 25
[DEBUG] X after: 26
[DEBUG] Addx instruction. X before: 26
[DEBUG] X after: 28
[DEBUG] Addx instruction. X before: 28
[DEBUG] X after: 37
[DEBUG] Addx instruction. X before: 37
[DEBUG] X after: 36
[DEBUG] Addx instruction. X before: 36
[DEBUG] X after: 38
[DEBUG] Addx instruction. X before: 38
[DEBUG] X after: 1
[DEBUG] Addx instruction. X before: 1
[DEBUG] X after: 2
[DEBUG] Addx instruction. X before: 2
[DEBUG] X after: 5
[DEBUG] Addx instruction. X before: 5
[DEBUG] X after: 20
[DEBUG] Addx instruction. X before: 20
[DEBUG] X after: -1
[DEBUG] Addx instruction. X before: -1
[DEBUG] X after: 21
[DEBUG] Addx instruction. X before: 21
[DEBUG] X after: 15
[DEBUG] Addx instruction. X before: 15
[DEBUG] X after: 16
[DEBUG] Addx instruction. X before: 16
[DEBUG] X after: 18
[DEBUG] Addx instruction. X before: 18
[DEBUG] X after: 19
x at cycle number 220 is 19
rip is 133
result == 9180
(cur_cycle * x) == 4180
[DEBUG] Addx instruction. X before: 19
[DEBUG] X after: 9
[DEBUG] Addx instruction. X before: 9
[DEBUG] X after: 29
[DEBUG] Addx instruction. X before: 29
[DEBUG] X after: 30
[DEBUG] Addx instruction. X before: 30
[DEBUG] X after: 32
[DEBUG] Addx instruction. X before: 32
[DEBUG] X after: 34
[DEBUG] Addx instruction. X before: 34
[DEBUG] X after: 28
[DEBUG] Addx instruction. X before: 28
[DEBUG] X after: 17
13360


```
{% endraw %}

## Slight bug

Everything else is fine, but in the very last addition to x, x is supposed to be 18, not 19. The reason is that we start the cycle counter from zero, because the very first cycle would be cycle one until the end, not cycle zero. This is a classic off-by-one error.

Here is the fixed version:

{% raw %}
```

def run_program(program: list) -> int:

	rip = 0

	x = 1

	#result_list = []
	result = 0
	cur_cycle = 1

	while rip != len(program):

		instruction = program[rip] # Fetch

		if instruction[0]:

			debug("Addx instruction. X before: "+str(x))

			# addx instruction
			cur_cycle,result = check_cycle(x,cur_cycle,result,rip=rip)
			cur_cycle,result = check_cycle(x,cur_cycle,result,rip=rip) # x is unmodified for the first two clock cycles, then gets incremented.
			x += instruction[1]
			debug("X after: "+str(x))

			
		else:
			# assume nop
			cur_cycle,result = check_cycle(x,cur_cycle,result,rip=rip)
			#cur_cycle,result = check_cycle(x,cur_cycle,result) # advance the clock for two cycles.

		rip += 1

	if TEST_1:
		assert x == -1


	return result

```
{% endraw %}

Now it works!

## Part 2

Ok so before processing every cyclem we should check for the sprite. Checking if we put a bright pixel is just that we need to check the "distance" where x is and the current scanline. The formula for one dimensional distance is just abs( x1 - x2 ). After implementing that, we just need to render the matrix to make sense of what is being displayed. (Thanks to https://stackoverflow.com/questions/2659312/how-do-i-convert-a-numpy-array-to-and-display-an-image !)

Here is my current script:

{% raw %}
```


import sys
import numpy as np
from PIL import Image



'''

Thanks to https://stackoverflow.com/questions/2659312/how-do-i-convert-a-numpy-array-to-and-display-an-image

from PIL import Image
import numpy as np

w, h = 512, 512
data = np.zeros((h, w, 3), dtype=np.uint8)
data[0:256, 0:256] = [255, 0, 0] # red patch in upper left
img = Image.fromarray(data, 'RGB')
img.save('my.png')
img.show()


'''

def render_matrix(matrix: np.array) -> None:

	#w = matrix.shape[0]
	#h = matrix.shape[1]
	# Thanks to https://pillow.readthedocs.io/en/stable/handbook/concepts.html ! 
	img = Image.fromarray(matrix, '1')
	img.show()



DEBUG= True
TEST_1 = False
def debug(string: str):
	if DEBUG:
		print("[DEBUG] "+str(string))


def parse_input() -> list:

	stdin_input = sys.stdin.read()
	lines = stdin_input.split("\n")
	
	out = []

	for line in lines:
		if line[0] == "n":
			# nop
			out.append([0])
		else:
			# assume addx
			#print("line.split(" ") == "+str(line.split(" ")))
			#print("line == "+str(line))
			out.append([1, int(line.split(" ")[1])])
	return out



def check_cycle(x,cur_cycle, result, rip=None): # This is if we want to add to the result.
	if (cur_cycle - 20) % 40 == 0:

		return cur_cycle + 1, result + (cur_cycle * x)
	else:
		return cur_cycle + 1, result


def run_program(program: list) -> int:

	rip = 0

	x = 1

	#result_list = []
	result = 0
	cur_cycle = 1

	while rip != len(program):

		instruction = program[rip] # Fetch

		if instruction[0]:

			# addx instruction
			cur_cycle,result = check_cycle(x,cur_cycle,result,rip=rip)
			cur_cycle,result = check_cycle(x,cur_cycle,result,rip=rip) # x is unmodified for the first two clock cycles, then gets incremented.
			x += instruction[1]

			
		else:
			# assume nop
			cur_cycle,result = check_cycle(x,cur_cycle,result,rip=rip)
			#cur_cycle,result = check_cycle(x,cur_cycle,result) # advance the clock for two cycles.

		rip += 1

	if TEST_1:
		assert x == -1


	return result




def check_cycle_part2(x, cur_cycle, screen_mat, scan_x, scan_y): # This is if we want to add to the result.
	
	# screen_mat, cur_cycle = check_cycle_part2(x,cur_cycle,screen_mat)


	# First draw.

	pixel = 0

	if abs(x - scan_x) < 2:
		pixel = 1
		debug("poopoo")

	screen_mat[scan_x][scan_y] = pixel

	assert scan_y < 7
	assert scan_x < 41
	print("scan_y == "+str(scan_y))
	print("scan_x == "+str(scan_x))
	debug("screen_mat == "+str(screen_mat))
	cur_cycle += 1

	scan_x += 1
	if scan_x == 40:
		scan_x = 0
		scan_y += 1




	return screen_mat, cur_cycle, scan_x, scan_y


def run_program_part2(program: list) -> int:

	rip = 0

	x = 1

	#result_list = []
	#result = 0
	screen_mat = np.zeros((40,6)) # 40px wide and 6px high

	scan_y = 0
	scan_x = 0

	cur_cycle = 1

	while rip != len(program):

		instruction = program[rip] # Fetch


		# First draw, then execute.

		#pixel = 0

		#if abs(scan_x - x) < 2: # Check color
		#	pixel = 1

		#screen_mat[scan_y][scan_x] = pixel

		if instruction[0]:

			# addx instruction
			#cur_cycle,result = check_cycle(x,cur_cycle,result,rip=rip)
			screen_mat, cur_cycle, scan_x, scan_y = check_cycle_part2(x,cur_cycle,screen_mat, scan_x, scan_y)
			screen_mat, cur_cycle, scan_x, scan_y = check_cycle_part2(x,cur_cycle,screen_mat, scan_x, scan_y)
			#cur_cycle,result = check_cycle(x,cur_cycle,result,rip=rip) # x is unmodified for the first two clock cycles, then gets incremented.
			x += instruction[1]

			
		else:
			# assume nop
			#cur_cycle += 1

			screen_mat, cur_cycle, scan_x, scan_y = check_cycle_part2(x,cur_cycle,screen_mat, scan_x, scan_y)
			#cur_cycle,result = check_cycle(x,cur_cycle,result,rip=rip)
			#cur_cycle,result = check_cycle(x,cur_cycle,result) # advance the clock for two cycles.

		rip += 1
		

	#if TEST_1:
	#	assert x == -1


	return screen_mat



def solve_puzzle() -> int:

	program = parse_input()
	#debug("program == "+str(program))
	res = run_program_part2(program)

	return res


def main() -> int:

	solution = solve_puzzle()

	print(str(solution))

	render_matrix(solution)
	return 0


if __name__=="__main__":

	exit(main())



```
{% endraw %}

Except that it doesn't work, because it just shows a repeating pattern as the output. After a bit of debugging I found out that my rendering function sucks ass. Here I fixed it:

{% raw %}
```

def render_matrix(matrix: np.array) -> None:

	#w = matrix.shape[0]
	#h = matrix.shape[1]
	# Thanks to https://pillow.readthedocs.io/en/stable/handbook/concepts.html ! 
	# array = ((array) * 255).astype(np.uint8)
	print("Matrix inside render_matrix: "+str(matrix))
	matrix = (matrix).astype(bool)
	matrix = ((matrix) * 255).astype(np.uint8)

	img = Image.fromarray(matrix)
	#display(img)
	img.show()


```
{% endraw %}

Now it shows the fucking matrix correctly. This is good. Now let's run it on the actual input.

Now it works!

## Making it faster.

Now time to compare myself to others and compare my speed to the speed of other peoples solution.

To make the measurements a lot better I am going to run a thousand times instead of just one time to get a more accurate estimate, because one time only also has the initialization time added onto it.



I found this https://www.reddit.com/r/adventofcode/comments/zhjfo4/comment/j1cv4ti/?utm_source=share&utm_medium=web2x&context=3 so I am going to try to beat it.

My implementation takes 0.714s and that plagiarized takes around 0.351s . Fuck! :( 

Looking at my cprofile output:

{% raw %}
```


         693683 function calls (691910 primitive calls) in 0.714 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
   240000    0.310    0.000    0.333    0.000 main.py:114(check_cycle_part2)
     1000    0.210    0.000    0.561    0.001 main.py:148(run_program_part2)
   240096    0.024    0.000    0.024    0.000 {built-in method builtins.abs}
143625/143555    0.017    0.000    0.017    0.000 {built-in method builtins.len}
      105    0.015    0.000    0.015    0.000 {built-in method marshal.loads}
    25/23    0.012    0.000    0.016    0.001 {built-in method _imp.create_dynamic}
  204/203    0.005    0.000    0.008    0.000 {built-in method builtins.__build_class__}
      280    0.005    0.000    0.016    0.000 <frozen importlib._bootstrap_external>:1676(find_spec)
      582    0.004    0.000    0.004    0.000 {built-in method posix.stat}
      105    0.003    0.000    0.018    0.000 <frozen importlib._bootstrap_external>:764(_compile_bytecode)
      476    0.003    0.000    0.005    0.000 <frozen importlib._bootstrap>:216(acquire)
     3924    0.003    0.000    0.003    0.000 {built-in method builtins.getattr}
      614    0.003    0.000    0.003    0.000 _inspect.py:65(getargs)
      105    0.002    0.000    0.002    0.000 {method 'read' of '_io.BufferedReader' objects}
      105    0.002    0.000    0.002    0.000 {built-in method io.open_code}
    25/16    0.002    0.000    0.011    0.001 {built-in method _imp.exec_dynamic}
     1418    0.002    0.000    0.003    0.000 <frozen importlib._bootstrap_external>:128(<listcomp>)
     1418    0.002    0.000    0.005    0.000 <frozen importlib._bootstrap_external>:126(_path_join)
      140    0.002    0.000    0.023    0.000 <frozen importlib._bootstrap>:1183(_find_spec)
      327    0.002    0.000    0.003    0.000 functools.py:35(update_wrapper)
      314    0.002    0.000    0.015    0.000 overrides.py:170(decorator)
      476    0.002    0.000    0.002    0.000 <frozen importlib._bootstrap>:284(release)
    375/8    0.002    0.000    0.146    0.018 {built-in method builtins.__import__}
     1000    0.002    0.000    0.002    0.000 {built-in method numpy.zeros}
      317    0.002    0.000    0.008    0.000 function_base.py:483(add_newdoc)
      284    0.002    0.000    0.008    0.000 overrides.py:88(verify_matching_signatures)
      618    0.002    0.000    0.006    0.000 _inspect.py:96(getargspec)
       13    0.002    0.000    0.330    0.025 __init__.py:1(<module>)
     5489    0.002    0.000    0.002    0.000 {built-in method builtins.isinstance}
      476    0.002    0.000    0.002    0.000 <frozen importlib._bootstrap>:338(_get_module_lock)
    141/1    0.001    0.000    0.152    0.152 <frozen importlib._bootstrap>:1294(_find_and_load)
      105    0.001    0.000    0.029    0.000 <frozen importlib._bootstrap_external>:1091(get_code)
      210    0.001    0.000    0.004    0.000 <frozen importlib._bootstrap_external>:475(cache_from_source)


```
{% endraw %}

A lot of the time is spent inside check_cycle_part2 .

Let's try to improve it.

Well, let's first get rid of the asserts... that helped, but not faster than the other implementation.

...

After thinking a while I have arrived to the conclusion that I am a dumbass.

I looked at the better code and it seems that I am overcomplicating the logic of the program. First things first, we can just do a nop and then check if the instruction was addx, because the nop instruction is basically the first part of the addx instruction. See:

{% raw %}
```
addx instruction:

wait
wait
update x

and nop is this:

wait

so therefore to simulate the cpu we can just do:

wait
if addx instruction:
    wait
    update x

Therefore we do not need to have an "else" clause.


```
{% endraw %}

Here is my current solve function:

{% raw %}
```

def run_program_part2(program: list) -> int:
	rip = 0
	x = 1
	screen_mat = np.zeros((6,40)) # 40px wide and 6px high
	scan_y = 0
	scan_x = 0
	cur_cycle = 1
	length = len(program)

	for instruction in program:
		if instruction[0]:
			screen_mat, cur_cycle, scan_x, scan_y = check_cycle_part2(x,cur_cycle,screen_mat, scan_x, scan_y)
			screen_mat, cur_cycle, scan_x, scan_y = check_cycle_part2(x,cur_cycle,screen_mat, scan_x, scan_y)
			x += instruction[1]	
		else:
			screen_mat, cur_cycle, scan_x, scan_y = check_cycle_part2(x,cur_cycle,screen_mat, scan_x, scan_y)

	return screen_mat

```
{% endraw %}

We can modify it to look like this:

{% raw %}
```

def run_program_part2(program: list) -> int:
	rip = 0
	x = 1
	screen_mat = np.zeros((6,40)) # 40px wide and 6px high
	scan_y = 0
	scan_x = 0
	cur_cycle = 1
	length = len(program)

	for instruction in program:
		screen_mat, cur_cycle, scan_x, scan_y = check_cycle_part2(x,cur_cycle,screen_mat, scan_x, scan_y)
		if instruction[0]:
			screen_mat, cur_cycle, scan_x, scan_y = check_cycle_part2(x,cur_cycle,screen_mat, scan_x, scan_y)
			x += instruction[1]	

	return screen_mat

```
{% endraw %}

And it causes an increase in performance! Great!

Then I am gonna do something which feels a bit disgusting. I am going to completely remove the check_cycle_part2 function and just copy the code into two places. The packing and unpacking of the arguments and the return values to and from functions takes a long time, so I think this will actually speed up performance instead of slowing us down. And I was correct! We are actually faster than the plagiarized program. This is because I am using the numpy library when as the plagiarized version does not use it. I am going to actually still try to make this faster.


I am now wondering if

{% raw %}
```

			scan_x += 1
			if scan_x == 40:
				scan_x = 0
				scan_y += 1

```
{% endraw %}

is faster than

{% raw %}
```

			if scan_x == 39:
				scan_x = 0
				scan_y += 1
			else:
				scan_x += 1

```
{% endraw %}


Let's actually try that in a separate program.

{% raw %}
```


import time
RUN_COUNT = 100000000



if __name__=="__main__":
	scan_x = 0
	scan_y = 0
	start = time.time()


	

	for _ in range(RUN_COUNT):

		if scan_x == 39:
			scan_x = 0
			scan_y += 1
		else:
			scan_x += 1

	print("First part took "+str(time.time() - start)+ "seconds.")
	scan_x = 0
	scan_y = 0
	start = time.time()

	for _ in range(RUN_COUNT):

		scan_x += 1
		if scan_x == 40:
			scan_x = 0
			scan_y += 1

	print("Second part took "+str(time.time() - start)+ "seconds.")


```
{% endraw %}

The results are:

{% raw %}
```
First part took 14.41629934310913seconds.
Second part took 14.640509605407715seconds.


```
{% endraw %}

Is that the second way is a tiny bit slower.

Our next suspect is `pixel = abs(x - scan_x) < 2` . In the plagiarized version they use ranges and they check if the x position is in a range which contains the three pixel positions, so let's see if that is faster. And holy shit. Checking to see if an element is inside a list with three elements is faster than checking the absolute value apparently. This is honestly kind of sus if you think about it. Yeah after a bit of more testing the absolute value seems to be faster. There is probably some improvement in the parsing code, but I am now going to leave this as is.

Here is the final code:

{% raw %}
```


import sys
import numpy as np
#from PIL import Image



'''

Thanks to https://stackoverflow.com/questions/2659312/how-do-i-convert-a-numpy-array-to-and-display-an-image

from PIL import Image
import numpy as np

w, h = 512, 512
data = np.zeros((h, w, 3), dtype=np.uint8)
data[0:256, 0:256] = [255, 0, 0] # red patch in upper left
img = Image.fromarray(data, 'RGB')
img.save('my.png')
img.show()


'''

def render_matrix(matrix: np.array) -> None:

	#w = matrix.shape[0]
	#h = matrix.shape[1]
	# Thanks to https://pillow.readthedocs.io/en/stable/handbook/concepts.html ! 
	# array = ((array) * 255).astype(np.uint8)
	print("Matrix inside render_matrix: "+str(matrix))
	matrix = (matrix).astype(bool)
	matrix = ((matrix) * 255).astype(np.uint8)

	img = Image.fromarray(matrix)
	#display(img)
	img.show()



DEBUG= True
TEST_1 = False
def debug(string: str):
	if DEBUG:
		print("[DEBUG] "+str(string))


def parse_input() -> list:

	stdin_input = sys.stdin.read()
	lines = stdin_input.split("\n")
	
	out = []

	for line in lines:
		if line[0] == "n":
			# nop
			out.append([0])
		else:
			# assume addx
			#print("line.split(" ") == "+str(line.split(" ")))
			#print("line == "+str(line))
			out.append([1, int(line.split(" ")[1])])
	return out



def check_cycle(x,cur_cycle, result, rip=None): # This is if we want to add to the result.
	if (cur_cycle - 20) % 40 == 0:

		return cur_cycle + 1, result + (cur_cycle * x)
	else:
		return cur_cycle + 1, result


def run_program(program: list) -> int:

	rip = 0

	x = 1

	#result_list = []
	result = 0
	cur_cycle = 1

	while rip != len(program):

		instruction = program[rip] # Fetch

		if instruction[0]:

			# addx instruction
			cur_cycle,result = check_cycle(x,cur_cycle,result,rip=rip)
			cur_cycle,result = check_cycle(x,cur_cycle,result,rip=rip) # x is unmodified for the first two clock cycles, then gets incremented.
			x += instruction[1]

			
		else:
			# assume nop
			cur_cycle,result = check_cycle(x,cur_cycle,result,rip=rip)
			#cur_cycle,result = check_cycle(x,cur_cycle,result) # advance the clock for two cycles.

		rip += 1

	if TEST_1:
		assert x == -1


	return result




def check_cycle_part2(x, cur_cycle, screen_mat, scan_x, scan_y): # This is if we want to add to the result.
	
	# screen_mat, cur_cycle = check_cycle_part2(x,cur_cycle,screen_mat)


	# First draw.

	#pixel = 0

	#if abs(x - scan_x) < 2:
	#	pixel = 1
	#	#debug("poopoo")

	#pixel = x in range(scan_x-1, scan_x+2)
	pixel = abs(x - scan_x) < 2
	#print("x == "+str(x))
	#print("scan_x == "+str(scan_x))
	screen_mat[scan_y][scan_x] = pixel

	#assert scan_y < 7
	#assert scan_x < 41
	#print("scan_y == "+str(scan_y))
	#print("scan_x == "+str(scan_x))
	#debug("screen_mat == "+str(screen_mat))
	#cur_cycle += 1

	scan_x += 1
	if scan_x == 40:
		scan_x = 0
		scan_y += 1

	return screen_mat, cur_cycle + 1, scan_x, scan_y


def run_program_part2(program: list) -> int:
	rip = 0
	x = 1
	screen_mat = np.zeros((6,40)) # 40px wide and 6px high
	scan_y = 0
	scan_x = 0
	cur_cycle = 1
	length = len(program)

	for instruction in program:
		#screen_mat, cur_cycle, scan_x, scan_y = check_cycle_part2(x,cur_cycle,screen_mat, scan_x, scan_y)
		pixel = abs(x - scan_x) < 2
		#pixel = scan_x in range(x-1, x+2)
		screen_mat[scan_y][scan_x] = pixel
		if scan_x == 39:
			scan_x = 0
			scan_y += 1
		else:
			scan_x += 1
		cur_cycle += 1
		#return screen_mat, cur_cycle + 1, scan_x, scan_y

		if instruction[0]:
			#screen_mat, cur_cycle, scan_x, scan_y = check_cycle_part2(x,cur_cycle,screen_mat, scan_x, scan_y)

			pixel = abs(x - scan_x) < 2
			#pixel = (x)&(0xffffffff >> 1) < 2
			#pixel = scan_x in range(x-1, x+2)
			screen_mat[scan_y][scan_x] = pixel
			#scan_x += 1
			if scan_x == 39:
				scan_x = 0
				scan_y += 1
			else:
				scan_x += 1

			cur_cycle += 1

			x += instruction[1]	

	return screen_mat

RUN_COUNT = 10000

def solve_puzzle() -> int:

	program = parse_input()
	#debug("program == "+str(program))
	for _ in range(RUN_COUNT):
		res = run_program_part2(program)

	return res


def main() -> int:

	solution = solve_puzzle()
	#print("Solution")
	#print(str(solution))

	#render_matrix(solution)
	return 0


if __name__=="__main__":

	exit(main())


```
{% endraw %}

































