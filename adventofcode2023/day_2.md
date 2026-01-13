
# Day 2

## Part 1

Ok, so just figure out which of these were possible and which weren't. This should be easy, because the only time an impossible game is when the elf pulls out more cubes of a certain color, than there actually exists. So for each game, we need to go through all of the cube groups which the elf pulls out, and then check if there are any color which exceeds the actual amount.

Here is my first attempt at parsing the input:

{% raw %}
```

def parse_input() -> list:
	lines = sys.stdin.read().split("\n")
	# Game 1: 3 blue, 4 red; 1 red, 2 green, 6 blue; 2 green
	output = []

	color_order = ["red", "green", "blue"]
	for line in lines:
		line = line[8:] # Skip the "Game #: " part. This should work for the toy input, but doesn't work when the Game number exceeds nine.
		showed_cubes_groups = line.split("; ") # get the cubes which were showed at one time
		print(showed_cubes_groups)
		showed_cubes_stuff = []
		for showed_cubes in showed_cubes_groups:
			cubes_of_distinct_color = showed_cubes.split(", ")
			print(cubes_of_distinct_color)
			new_cubes = [0,0,0]
			for cube_amount_of_color_certain in cubes_of_distinct_color:
				integer, color = cube_amount_of_color_certain.split(" ")
				integer = int(integer)
				print(str(integer)+":"+color)
				index = color_order.index(color)
				new_cubes[index] = integer
			showed_cubes_stuff.append(new_cubes)
		output.append(showed_cubes_stuff)
	print(output)

	return output

```
{% endraw %}

It is probably not that fast, but I am going to first make the program work and then I will optimize it.

Now all is left to do is to check each game and check if each "round" is possible.

{% raw %}
```
def check_possible(game: list) -> bool:
	# "if the bag contained only 12 red cubes, 13 green cubes, and 14 blue cubes."
	MAX_RED = 12
	MAX_GREEN = 13
	MAX_BLUE = 14

	for shown_cubes_round in game:
		# Check if we show more cubes of a certain color, than there are in the bag.
		if shown_cubes_round[0] > MAX_RED:
			return False
		elif shown_cubes_round[1] > MAX_GREEN:
			return False
		elif shown_cubes_round[2] > MAX_BLUE:
			return False
	# All rounds of one game are possible, hence that specific game is possible
	return True


def get_possible_count(games: list):
	val = 0
	for i, game in enumerate(games): # Each element in the games list is a list of lists, each of which has the amount of colored cubes shown for each color.
		if check_possible(game):
			val += i+1 # Add the index of the game to the total sum if game is possible (we need to add one, because games start at index 1, not at index 0)
	return val
```
{% endraw %}

Let's test the program...

It works for the toy input, but let's check for the actual input.

It doesn't because there is this line: `line = line[8:] # Skip the "Game #: " part. This should work for the toy input, but doesn't work when the Game number exceeds nine.`, so instead of skipping a set index forward, let's skip to the index of ":" . `line = line[line.index(":")+2:]`

Now it works.

## Part 2

Ok so part 1 was quite easy, let's see what part 2 has in store for us. Part two is basically find the minimum amount of each color, which make the game possible. Therefore we should just find the maximum amount of each color in the game, which were pulled out, because then it is barely possible and we have our minimum amount of each color needed to make the game possible.

So let's modify our "check_possible" function...

Tada:

{% raw %}
```
def check_possible(game: list) -> bool:
	# Here are the maximum number of each color encountered in the game so far.
	cur_max_red = 0
	cur_max_green = 0
	cur_max_blue = 0

	for shown_cubes_round in game:
		# Check if we show more cubes of a certain color, than there are in the bag.
		if shown_cubes_round[0] > cur_max_red:
			cur_max_red = shown_cubes_round[0]
		if shown_cubes_round[1] > cur_max_green:
			cur_max_green = shown_cubes_round[1]
		if shown_cubes_round[2] > cur_max_blue:
			cur_max_blue = shown_cubes_round[2]
	# All rounds of one game are possible, hence that specific game is possible
	return True
```
{% endraw %}

Now, this is horrible programming practice, since we are repeating stuff which we have already typed out, so let's simplify this a bit.

{% raw %}
```
def get_min(game: list) -> bool:
	# Here are the maximum number of each color encountered in the game so far.
	max_cubes = [0,0,0]
	for shown_cubes_round in game:
		# Check if we show more cubes of a certain color, than there are in the bag.
		max_cubes = [max_cubes[i] if max_cubes[i] >= shown_cubes_round[i] else shown_cubes_round[i] for i in range(len(shown_cubes_round))]	
	# Multiply the amounts together
	res = reduce(mul, max_cubes, 1)
	return res
```
{% endraw %}

There you go. I think you can make it even more compact by using map or lambda functions, but I do not really know anything about how to use those. I should probably learn how those works.

## Making it faster

Let's compare our solution to some other solution. Maybe we can learn something. Let's compare our solution to this: https://www.reddit.com/r/adventofcode/comments/188w447/comment/kby9icx/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button

My code is slower. This is because I didn't use a hashmap (a dictionary).

Let's use dictionaries instead, so we do not need to search through the lists...

{% raw %}
```


import sys
from functools import reduce
from operator import mul

def parse_input() -> list:
	contents = sys.stdin.read()
	if contents[-1] == "\n":
		contents = contents[:-1]
	lines = contents.split("\n")
	# Game 1: 3 blue, 4 red; 1 red, 2 green, 6 blue; 2 green
	output = []

	color_order = ["red", "green", "blue"]
	#color_maxes = {"red": 0, "green": 0, "blue": 0}
	#print("Here are the lines")
	for line in lines:
		#print(line)
		line = line[line.index(":")+2:] # Skip the "Game #: " part. This should work for the toy input, but doesn't work when the Game number exceeds nine.
		showed_cubes_groups = line.split("; ") # get the cubes which were showed at one time
		#print(showed_cubes_groups)
		showed_cubes_stuff = []
		for showed_cubes in showed_cubes_groups:
			cubes_of_distinct_color = showed_cubes.split(", ")
			#print(cubes_of_distinct_color)
			#new_cubes = [0,0,0]
			new_cubes = {"red": 0, "green": 0, "blue": 0}
			for cube_amount_of_color_certain in cubes_of_distinct_color:
				#print("cube_amount_of_color_certain == "+str(cube_amount_of_color_certain))
				integer, color = cube_amount_of_color_certain.split(" ")
				integer = int(integer)
				#print(str(integer)+":"+color)
				#index = color_order.index(color)
				new_cubes[color] = integer
			showed_cubes_stuff.append(new_cubes)
		output.append(showed_cubes_stuff)
	#print(output)

	return output

def get_min(game: list) -> bool:
	# Here are the maximum number of each color encountered in the game so far.
	max_cubes = [0,0,0]
	cols = ["red", "green", "blue"]
	color_maxes = {"red": 0, "green": 0, "blue": 0}
	for shown_cubes_round in game:
		#print(shown_cubes_round)
		for col in cols:
			if shown_cubes_round[col] > color_maxes[col]:
				color_maxes[col] = shown_cubes_round[col]

		# Check if we show more cubes of a certain color, than there are in the bag.
		#max_cubes = [max_cubes[i] if max_cubes[i] >= shown_cubes_round[i] else shown_cubes_round[i] for i in range(len(shown_cubes_round))]
		#for cube_amount in 

	# Multiply the amounts together
	res = reduce(mul, color_maxes.values(), 1)
	return res


def get_possible_count(games: list):
	val = 0
	for i, game in enumerate(games): # Each element in the games list is a list of lists, each of which has the amount of colored cubes shown for each color.
		res = get_min(game)
		val += res
	return val


def main() -> int:
	game_integers = parse_input()
	result = get_possible_count(game_integers)
	print(result)
	return 0

if __name__=="__main__":
	exit(main())


```
{% endraw %}

Tada! Now it works quite fast. It actually works faster than the other code, which I plag.. erm.. "imported". ;)

















