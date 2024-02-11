
# Making fair minesweeper (no guessing required)

Ok, so previously I programmed minesweeper: https://personnumber3377.github.io/projects/making_minesweeper.html , but I don't really like RNG in my games, so I decided to make fair minesweeper.

I am now in the commit 5bbc3d99510a400d520a63a7744d92a6b42173ce in this repository: https://github.com/personnumber3377/minesweeper .

Now, numpy didn't want to cooperate with me initially, because I initially used python3.12, but then decided to go with python3.10 to circumvent the errors which I encountered.

Here is the error which I am getting:

```
cyberhacker@cyberhacker-h8-1131sc:~/Asioita/Ohjelmointi/Fair_minesweeper/minesweeper$ python3.10 main.py 
Traceback (most recent call last):
  File "/home/cyberhacker/Asioita/Ohjelmointi/Fair_minesweeper/minesweeper/main.py", line 36, in <module>
    from pynput.keyboard import Listener, Key
ModuleNotFoundError: No module named 'pynput'

```

After running `apt install python3-pip` and then running `python3.10 -m pip install pynput` . We should be good.

## Fixing a win bug

First of all, there is a tiny bug in the game, that it doesn't actually let you win. This is because in the have_won function we have this check:

```
if [j,i] not in self.mine_positions:
```

The reason why this is wrong is because the i and j are the wrong way around. It should be this:

```
if [i,j] not in self.mine_positions:
```

and now it works. This fix is in the c0972a7e5e24e9cf11ab3b4e6bb3fdd92d6cb5db commit.

## Actually making it fair.

Ok so what is the best way to do this?

Now, I think a naive way would be to just generate a new minefield until we get one which doesn't require guessing to solve.

So, now we just need to implement a function which checks if a minefield is solvable without luck.

How do we do that? After some googling, I found this: https://stackoverflow.com/a/68735835/14577985 . Let's try to implement it!

Here are the initial steps:

```
We'll use the following numbers to indicate certain conditions:

-1 to indicate open spaces that are guaranteed to be empty and free (permanent).
0 to indicate a space that could be open or contain a mine (non-permanent).
1 to indicate a possible mine position (non-permanent).
2 to indicate a permanent mine position (permanent).
The first step is to reserve the starting position and the surrounding 8 spaces with -1 and then randomly generate a board filled with possible mines. This is the easy part. The key is to then solve the board internally before presenting it to the user.
```

ok, so now let's create the function skeleton:

Actually fuck that. I am going to do it my own way instead. Here is the start:

```


BOMB_SPACE = 1
UNKNOWN_SPACE = -1
KNOWN_EMPTY_SPACE = 0

def reveal_spot(start_pos: list, board: np.array) -> bool:
	# Should not be a bomb space.
	assert board[start_pos[0]][start_pos[1]] == UNKNOWN_SPACE # The space should be an unknown space

def can_solve(board: np.array, start_pos: list) -> bool: # Checks if the board can be solved without guessing.
	x, y = start_pos
	

```

Ok, so we need to program a main loop which loops over all of the new interesting spots and decides if they aren't solvable without luck or not. One way to solve this is to brute force all of the mine positions and see if there are more than one configuration in which the bombs are valid. Another way to solve this problem is to just make plenty of rules which then we loop over on each bomb spot.

Ok, so what if we just bruteforce all of the bomb positions and check if they are plausable and then if yes, then we skip over that, and try to solve other stuff first?


Here is my current code:

```


import numpy as np

BOMB_SPACE = 10
UNKNOWN_SPACE = -1
KNOWN_EMPTY_SPACE = 0



class Solver:
	def __init__(self, board: np.array, init_pos: list) -> None:
		self.board = board
		self.init_pos = init_pos
		



def del_check(l: list, elem):
	if elem in l:
		l.remove(elem)

def get_neighs(board: np.array, pos: list) -> list:
	neighs = [[pos[0]+1, pos[1]], [pos[0]+1, pos[1]+1], [pos[0]+1, pos[1]-1], [pos[0]-1, pos[1]], [pos[0]-1, pos[1]+1], [pos[0]-1, pos[1]-1], [pos[0], pos[1]+1], [pos[0], pos[1]-1]] # Assume no walls.
	# Then check them.
	if pos[0] == 0: # Remove the left side.
		del_check(neighs, [pos[0]-1, pos[1]])
		del_check(neighs, [pos[0]-1, pos[1]+1])
		del_check(neighs, [pos[0]-1, pos[1]-1])
	elif pos[0] == len(board[0])-1:
		# Remove right side.
		del_check(neighs, [pos[0]+1, pos[1]])
		del_check(neighs, [pos[0]+1, pos[1]+1])
		del_check(neighs, [pos[0]+1, pos[1]-1])
	if pos[1] == 0: # Y == 0    Remove the positions which are up
		del_check(neighs, [pos[0]+1, pos[1]-1])
		del_check(neighs, [pos[0], pos[1]-1])
		del_check(neighs, [pos[0]-1, pos[1]-1])
	elif pos[1] == len(board)-1: # Y is maximum Remove the positions which are down.
		del_check(neighs, [pos[0]+1, pos[1]+1])
		del_check(neighs, [pos[0], pos[1]+1])
		del_check(neighs, [pos[0]-1, pos[1]+1])
	return neighs # Now just return the valid neighbours positions.

def count_bomb_neighs(board: np.array, cur_pos: list) -> int:
	neighs = get_neighs(board, cur_pos)
	# Now check for bombs.
	cnt = 0
	for pos in neighs:
		if board[pos[0]][pos[1]] == BOMB_SPACE:
			cnt += 1
	return cnt

def reveal_spot(start_pos: list, board: np.array) -> bool:
	# Should not be a bomb space.
	assert board[start_pos[0]][start_pos[1]] == UNKNOWN_SPACE # The space should be an unknown space
	new_spots = [start_pos]
	not_zero = []
	revealed_count = 0
	while new_spots:
		new = []
		if board[new_spots[0]][new_spots[1]] != -1: # do not include spots which are already revealed
			continue
		# Now get the bomb amount .
		bomb_count = count_bomb_neighs(board, cur_pos)
		if bomb_count: # There are bombs nearby therefore do not continue, but instead put the bomb number here.
			# Mark the bomb space.
			revealed_count += 1
			board[cur_pos[0]][cur_pos[1]] = bomb_count
			not_zero.append(cur_pos)
		else: # No bombs, therefore reveal this spot and continue.
			board[cur_pos[0]][cur_pos[1]] = KNOWN_EMPTY_SPACE
			new += get_neighs(board, cur_pos)
			revealed_count += 1
	return board, not_zero, revealed_count

def parse_line(line: list) -> str:
	out = ""
	for char in line:
		if char == 0:
			out += " "
		elif char == BOMB_SPACE:
			out += "X"
		else:
			assert char in [int(x) for x in "0123456789"]
			out += str(char)
	return out


def print_board(board: list) -> None:
	x_width = len(board[0])+2
	print("-"*x_width)
	for line in board:
		print("|", end="")
		print(parse_line(line), end="")
		print("|", end="\n")
	print("-"*x_width)
	return


def can_solve(board: np.array, start_pos: list) -> bool: # Checks if the board can be solved without guessing.
	#cur_pos = start_pos
	positions_to_check = [start_pos]
	while positions_to_check:
		for pos in positions_to_check:
			# Now reveal the current spot
			board, not_zero, revealed_count = reveal_spot(pos, board)


def parse_test(filename: str) -> list:
	fh = open(filename, "r")
	lines = fh.readlines()
	fh.close()


def test_print() -> None:
	oof = [[0,BOMB_SPACE],[1,8]]
	print_board(oof)

def main() -> int: # Test function
	test_print()

	'''
	Now here is an example:
	------
	|#X##|
	|###X|
	|#S##|
	|####|
	------
	S is the start spot and there are two mines.
	
	After clicking, we now have this:

	------
	|1X##|
	|112X|
	|  11|
	|    |
	------

	and then we should bruteforce the mines and see if the configurations are possible.


	'''


	return 0

if __name__=="__main__":
	exit(main())




```

My strategy is to just bruteforce all of the mine positions and see if there are more than two valid positions, then just push it back and try to solve the other mines first (they may give us the needed information to solve the mine problem)...

Here is my current code:

```


import numpy as np

BOMB_SPACE = 10
UNKNOWN_SPACE = -1
KNOWN_EMPTY_SPACE = 0

'''
def can_solve(board: np.array, start_pos: list) -> bool: # Checks if the board can be solved without guessing.
	#cur_pos = start_pos
	positions_to_check = [start_pos]
	while positions_to_check:
		for pos in positions_to_check:
			# Now reveal the current spot
			board, not_zero, revealed_count = reveal_spot(pos, board)
'''



class Solver:
	def __init__(self, board: np.array, init_pos: list) -> None:
		self.board = board
		self.init_pos = init_pos
		self.positions_to_check = None
		self.init_pos[0], self.init_pos[1] = self.init_pos[1], self.init_pos[0]
	def main_loop(self) -> bool:
		self.positions_to_check = [self.init_pos]
		while self.positions_to_check:
			for pos in self.positions_to_check:
				board, not_zero, revealed_count = self.reveal_spot(pos)
				self.render()
	def reveal_spot(self, start_pos: list) -> bool: # This basically clicks a space.
		# Should not be a bomb space.

		print("self.board[start_pos[0]][start_pos[1]] == "+str(self.board[start_pos[0]][start_pos[1]]))
		print("self.board[start_pos[0]] == "+str(self.board[start_pos[0]]))
		assert self.board[start_pos[0]][start_pos[1]] == UNKNOWN_SPACE # The space should be an unknown space
		new_spots = [start_pos]
		not_zero = []
		revealed_count = 0
		while new_spots:
			new = []
			for new_spot in new_spots:
				print("Now clicking here: "+str(new_spot))
				if self.board[new_spot[0]][new_spot[1]] != -1: # do not include spots which are already revealed
					continue
				# Now get the bomb amount .
				bomb_count = self.count_bomb_neighs(self.board, new_spot)
				if bomb_count: # There are bombs nearby therefore do not continue, but instead put the bomb number here.
					# Mark the bomb space.
					revealed_count += 1
					self.board[new_spot[0]][new_spot[1]] = bomb_count
					not_zero.append(new_spot)
				else: # No bombs, therefore reveal this spot and continue.
					self.board[new_spot[0]][new_spot[1]] = KNOWN_EMPTY_SPACE
					new += get_neighs(self.board, new_spot)
					revealed_count += 1
			new_spots = new
		return self.board, not_zero, revealed_count

	def count_bomb_neighs(self, board: np.array, cur_pos: list) -> int:
		neighs = get_neighs(board, cur_pos)
		# Now check for bombs.
		cnt = 0
		for pos in neighs:
			if self.board[pos[0]][pos[1]] == BOMB_SPACE:
				cnt += 1
		return cnt

	def render(self) -> None:
		x_width = len(self.board[0])+2
		print("-"*x_width)
		for line in self.board:
			print("|", end="")
			print(parse_line(line), end="")
			print("|", end="\n")
		print("-"*x_width)
		return





def del_check(l: list, elem):
	if elem in l:
		l.remove(elem)

def get_neighs(board: np.array, pos: list) -> list:
	neighs = [[pos[0]+1, pos[1]], [pos[0]+1, pos[1]+1], [pos[0]+1, pos[1]-1], [pos[0]-1, pos[1]], [pos[0]-1, pos[1]+1], [pos[0]-1, pos[1]-1], [pos[0], pos[1]+1], [pos[0], pos[1]-1]] # Assume no walls.
	# Then check them.
	if pos[0] == 0: # Remove the left side.
		del_check(neighs, [pos[0]-1, pos[1]])
		del_check(neighs, [pos[0]-1, pos[1]+1])
		del_check(neighs, [pos[0]-1, pos[1]-1])
	elif pos[0] == len(board[0])-1:
		# Remove right side.
		del_check(neighs, [pos[0]+1, pos[1]])
		del_check(neighs, [pos[0]+1, pos[1]+1])
		del_check(neighs, [pos[0]+1, pos[1]-1])
	if pos[1] == 0: # Y == 0    Remove the positions which are up
		del_check(neighs, [pos[0]+1, pos[1]-1])
		del_check(neighs, [pos[0], pos[1]-1])
		del_check(neighs, [pos[0]-1, pos[1]-1])
	elif pos[1] == len(board)-1: # Y is maximum Remove the positions which are down.
		del_check(neighs, [pos[0]+1, pos[1]+1])
		del_check(neighs, [pos[0], pos[1]+1])
		del_check(neighs, [pos[0]-1, pos[1]+1])
	return neighs # Now just return the valid neighbours positions.




def parse_line(line: list) -> str:
	out = ""
	for char in line:
		#print("Line == "+str(line))
		if char == 0:
			out += " "
		elif char == BOMB_SPACE:
			out += "X"
		elif char == -1:
			out += "#" # unknown
		else:
			assert char in [int(x) for x in "0123456789"]
			out += str(char)
	return out

def can_solve(board: np.array, start_pos: list) -> bool: # Checks if the board can be solved without guessing.
	#cur_pos = start_pos
	positions_to_check = [start_pos]
	while positions_to_check:
		for pos in positions_to_check:
			# Now reveal the current spot
			board, not_zero, revealed_count = reveal_spot(pos, board)


def parse_test(filename: str) -> list:
	fh = open(filename, "r")
	lines = fh.readlines()
	fh.close()


def test_print() -> None:
	oof = [[0,BOMB_SPACE],[1,8]]
	#print_board(oof)

def main() -> int: # Test function
	#test_print()

	'''
	Now here is an example:
	------
	|#X##|
	|###X|
	|#S##|
	|####|
	------
	S is the start spot and there are two mines.
	
	After clicking, we now have this:

	------
	|1X##|
	|112X|
	|  11|
	|    |
	------

	and then we should bruteforce the mines and see if the configurations are possible.


	'''
	# Example board:

	board = [[-1,BOMB_SPACE,-1,-1], [-1,-1,-1,BOMB_SPACE], [-1,-1,-1,-1], [-1,-1,-1,-1]]

	# Create the solver.
	solver = Solver(board, [1,3]) # Make board.

	solver.main_loop() # Jump to the main loop

	return 0

if __name__=="__main__":
	exit(main())





```

and it shows the spaces correctly, now it is time to actually make the solver. Now, when trying to solve the position, I decided to actually go with the rule based thing.

After a bit of fiddling around, I came up with this:

```


import numpy as np
import copy

BOMB_SPACE = 10
UNKNOWN_SPACE = -1
KNOWN_EMPTY_SPACE = 0

'''
def can_solve(board: np.array, start_pos: list) -> bool: # Checks if the board can be solved without guessing.
	#cur_pos = start_pos
	positions_to_check = [start_pos]
	while positions_to_check:
		for pos in positions_to_check:
			# Now reveal the current spot
			board, not_zero, revealed_count = reveal_spot(pos, board)
'''

def remove_mines(board: list) -> list: # We have two copies of the minefield, one without the bombs and one with. When updating the board, we use the board with the bombs, but then when trying to solve, we obviously use the board which doesn't have the bombs
	new_board = copy.deepcopy(board)
	# Now just remove the mines.
	for i in range(len(new_board)):
		for j in range(len(new_board)):
			if new_board[i][j] == BOMB_SPACE:
				#print("new_board[i][j] == "+str(new_board[i][j]))
				new_board[i][j] = -1 # Pretend to be an empty space
	return new_board


class Solver:
	def __init__(self, board: np.array, init_pos: list) -> None:
		self.board_with_mines = board
		self.board = remove_mines(board)
		#print("self.board == "+str(self.board))
		self.init_pos = init_pos
		self.positions_to_check = []
		self.init_pos[0], self.init_pos[1] = self.init_pos[1], self.init_pos[0]
		self.solved_mines = []
		self.unsolved_mine_spots = []
		self.known_mine_spots = []
	def main_loop(self) -> bool:
		self.positions_to_click = [self.init_pos]

		while self.positions_to_click:
			for pos in self.positions_to_click:
				print("eeeee")
				board, not_zero, revealed_count = self.reveal_spot(pos)
				print("Fux")
				self.positions_to_check += not_zero # Add the spots which aren't zero to the list which we need to solve.
				self.render()
				# Now it is time to try to check for safe positions
				#for pos in self.positions_to_check:

				#	self.try_to_solve_position(pos)
				#for pos in self.positions_to_check:

				guaranteed_safe = self.get_safe_spots()
				print("Here is the guaranteed safe: "+str(guaranteed_safe))
	def count_known_empty_neighbours(self,pos: list) -> int:
		# This function gets the known amount of surrounding known empty spaces. This is used in the checking of the spaces.
		neighs = get_neighs(self.board, pos)
		n = 0
		for p in neighs: # Check for known safe spot.
			if self.board[p[0]][p[1]] == KNOWN_EMPTY_SPACE:
				n += 1
		return n

	def validate_positions(self, positions: list) -> list: # Gets rid of invalid positions. (Out of bounds.)
		for pos in positions:

			if pos[0] == -1: # Remove the left side.
				del_check(positions, pos)
			elif pos[0] == len(self.board[0]):
				# Remove right side.
				del_check(positions, pos)
			if pos[1] == -1: # Y == 0    Remove the positions which are up
				del_check(positions, pos)
			elif pos[1] == len(self.board): # Y is maximum Remove the positions which are down.
				del_check(positions, pos)
		return positions

	def get_corner_dir(self, pos) -> list: # This gets the position of the bomb in a corner case.
		direction_stuff = [[pos[0]+1,pos[1]+1], [pos[0]+1,pos[1]-1], [pos[0]-1,pos[1]+1], [pos[0]-1,pos[1]-1]] # these are the diagonal directions.
		direction_stuff = self.validate_positions(direction_stuff)
		print("direction_stuff == "+str(direction_stuff))
		for posother in direction_stuff:
			#print("pos == "+str(pos))
			print("len(self.board) == "+str(len(self.board)))
			print("len(self.board[0]) == "+str(len(self.board[0])))
			print("Here is the shit: ")
			if self.board[posother[0]][posother[1]] == -1: # This is the unknown spot, therefore this should be the bomb.
				return posother
		print("No corner shit found for position: "+str(pos))
		return False

	def get_neighbours_no_diagonal(self, pos: list) -> list:
		direction_stuff = [[pos[0],pos[1]+1], [pos[0],pos[1]-1], [pos[0]-1,pos[1]], [pos[0]+1,pos[1]]] # these are the diagonal directions.
		direction_stuff = self.validate_positions(direction_stuff)
		return direction_stuff
	def check_corner(self, pos: list) -> bool: # Checks if there potentially is a corner.
		# There should be two directions where there are numbers.
		neighs = self.get_neighbours_no_diagonal(pos)
		#assert self.board[pos[0]][pos[1]] == 1
		if self.board[pos[0]][pos[1]] != 1:
			return False
		nums = [self.board[p[0]][p[1]] for p in neighs]
		if nums.count(0) == 2 and -1 not in nums: # The -1 check is to check for a straight line.
			return True


	def corner(self, pos: list): # This checks if there is a corner. If yes, then it returns a bomb position.
		print("pos == "+str(pos))
		print(self.board)
		if self.board[pos[0]][pos[1]] != 1: # There should only be one bomb near this spot.
			return False
		# If the amount of surrounding known empty spaces is 5, therefore it is an almost literal corner case
		if self.count_known_empty_neighbours(pos) >= 3 and self.check_corner(pos):
			bomb_pos = self.get_corner_dir(pos)
			if bomb_pos:
				return bomb_pos
	def get_safe_spots(self) -> bool:
		# Tries to get known safe spots
		for pos in self.positions_to_check:
			res = self.corner(pos)
			print("here is res for the corner: "+str(res))
			if res: # There is a case such as this:
				'''
				 1#
				 11
				'''
				print("Corner case found at position "+str(pos))
				print("Bomb is at "+str(res))
				self.known_mine_spots.append(res) # Add the bomb to the list.
				# Remove the position from the list

		return

	def reveal_spot(self, start_pos: list) -> bool: # This basically clicks a space.
		# Should not be a bomb space.

		print("self.board[start_pos[0]][start_pos[1]] == "+str(self.board[start_pos[0]][start_pos[1]]))
		print("self.board[start_pos[0]] == "+str(self.board[start_pos[0]]))
		assert self.board[start_pos[0]][start_pos[1]] == UNKNOWN_SPACE # The space should be an unknown space
		assert self.board_with_mines[start_pos[0]][start_pos[1]] != BOMB_SPACE # We should not of course try to click on a bomb space.
		new_spots = [start_pos]
		not_zero = []
		revealed_count = 0
		while new_spots:
			new = []
			for new_spot in new_spots:
				print("Now clicking here: "+str(new_spot))
				if self.board[new_spot[0]][new_spot[1]] != -1: # do not include spots which are already revealed
					continue
				# Now get the bomb amount .
				bomb_count = self.count_bomb_neighs(new_spot)
				if bomb_count: # There are bombs nearby therefore do not continue, but instead put the bomb number here.
					# Mark the bomb space.
					revealed_count += 1
					self.board[new_spot[0]][new_spot[1]] = bomb_count
					not_zero.append(new_spot)
				else: # No bombs, therefore reveal this spot and continue.
					self.board[new_spot[0]][new_spot[1]] = KNOWN_EMPTY_SPACE
					new += get_neighs(self.board, new_spot)
					revealed_count += 1
			new_spots = new
		return self.board, not_zero, revealed_count

	def count_bomb_neighs(self, cur_pos: list) -> int:
		neighs = get_neighs(self.board_with_mines, cur_pos)
		# Now check for bombs.
		cnt = 0
		for pos in neighs:
			if self.board_with_mines[pos[0]][pos[1]] == BOMB_SPACE:
				cnt += 1
		return cnt

	def render(self) -> None:
		x_width = len(self.board[0])+2
		print("-"*x_width)
		for line in self.board:
			print("|", end="")
			print(parse_line(line), end="")
			print("|", end="\n")
		print("-"*x_width)
		return





def del_check(l: list, elem):
	if elem in l:
		l.remove(elem)

def get_neighs(board: np.array, pos: list) -> list:
	neighs = [[pos[0]+1, pos[1]], [pos[0]+1, pos[1]+1], [pos[0]+1, pos[1]-1], [pos[0]-1, pos[1]], [pos[0]-1, pos[1]+1], [pos[0]-1, pos[1]-1], [pos[0], pos[1]+1], [pos[0], pos[1]-1]] # Assume no walls.
	# Then check them.
	if pos[0] == 0: # Remove the left side.
		del_check(neighs, [pos[0]-1, pos[1]])
		del_check(neighs, [pos[0]-1, pos[1]+1])
		del_check(neighs, [pos[0]-1, pos[1]-1])
	elif pos[0] == len(board[0])-1:
		# Remove right side.
		del_check(neighs, [pos[0]+1, pos[1]])
		del_check(neighs, [pos[0]+1, pos[1]+1])
		del_check(neighs, [pos[0]+1, pos[1]-1])
	if pos[1] == 0: # Y == 0    Remove the positions which are up
		del_check(neighs, [pos[0]+1, pos[1]-1])
		del_check(neighs, [pos[0], pos[1]-1])
		del_check(neighs, [pos[0]-1, pos[1]-1])
	elif pos[1] == len(board)-1: # Y is maximum Remove the positions which are down.
		del_check(neighs, [pos[0]+1, pos[1]+1])
		del_check(neighs, [pos[0], pos[1]+1])
		del_check(neighs, [pos[0]-1, pos[1]+1])
	return neighs # Now just return the valid neighbours positions.




def parse_line(line: list) -> str:
	out = ""
	for char in line:
		#print("Line == "+str(line))
		if char == 0:
			out += " "
		elif char == BOMB_SPACE:
			out += "X"
		elif char == -1:
			out += "#" # unknown
		else:
			assert char in [int(x) for x in "0123456789"]
			out += str(char)
	return out

def can_solve(board: np.array, start_pos: list) -> bool: # Checks if the board can be solved without guessing.
	#cur_pos = start_pos
	positions_to_check = [start_pos]
	while positions_to_check:
		for pos in positions_to_check:
			# Now reveal the current spot
			board, not_zero, revealed_count = reveal_spot(pos, board)


def parse_test(filename: str) -> list:
	fh = open(filename, "r")
	lines = fh.readlines()
	fh.close()


def test_print() -> None:
	oof = [[0,BOMB_SPACE],[1,8]]
	#print_board(oof)

def main() -> int: # Test function
	#test_print()

	'''
	Now here is an example:
	------
	|#X##|
	|###X|
	|#S##|
	|####|
	------
	S is the start spot and there are two mines.
	
	After clicking, we now have this:

	------
	|1X##|
	|112X|
	|  11|
	|    |
	------

	and then we should bruteforce the mines and see if the configurations are possible.


	'''
	# Example board:

	board = [[-1,BOMB_SPACE,-1,-1], [-1,-1,-1,BOMB_SPACE], [-1,-1,-1,-1], [-1,-1,-1,-1]]

	# Create the solver.
	solver = Solver(board, [1,3]) # Make board.

	solver.main_loop() # Jump to the main loop

	return 0

if __name__=="__main__":
	exit(main())





```

and it basically just detects places where there are corners and there is a bomb in the corner. This handles this scenario for example:

```
------
|  1#|
|  11|
|    |
|    |
------
```

Now, we just need to implement basically all sorts of rules for every possible scenario. Fun!

















