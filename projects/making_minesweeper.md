
# Making a minesweeper program in python3

Hi! This is my minesweeper project. I hope that you know minesweeper, because I won't be explaining it to you.

Now, let's create a minefield object:

```


class Minefield:
	def __init__(self, width, height, num_mines):
		assert num_mines <= width * height # the amount of mines must be less than or equal to the amount of spaces in the minefield.

		self.mines = np.zeros((width, height)) # Minefield.
		self.shown = np.ones((width, height)) # What we show to the user.
		self.shown = self.shown * HIDDEN_SPACE # Mark them as hidden.

```

Now generate a random position for each mine and place mine:

```

HIDDEN_SPACE = 100
MINE_NUMBER = 10

# ...

		# Thanks to https://stackoverflow.com/questions/22842289/generate-n-unique-random-numbers-within-a-range

		positions = random.sample(range(0,width*height), num_mines)
		positions = [[pos//height, pos % height] for pos in positions] # Decode the positions, this should make it such that there are no duplicates.

		# Sanity check

		if len(positions) != len(set([str(x) for x in positions])):
			print("Error!")
			exit(1)

		for pos in positions:
			self.mines[pos[0]][pos[1]] = MINE_NUMBER

```

Then let's program a render function for the minefield.

```

def render(self):

		# Show the "shown" matrix
		print("Printing the minefield now:")
		print("-"*(self.width + 2))

		for line in self.shown:
			print("|", end="")
			for elem in line:
				if elem == HIDDEN_SPACE:
					print(" ", end="")
				elif elem == MARKED_SPACE:
					print("X", end="")
				else:

					print(str(elem), end="")

			print("|", end="\n")
		print("-"*(self.width + 2))

```

There you go.

Now time for the update function, with the move and the position.

```


	def update(self, position, move_type):

		if move_type == REVEAL_MOVE:

			if position in self.mine_positions:

				# Lost.

				print("You hit a mine! You lost.")
				exit(1)

			# First count the neigbhour bombs.

			neig_count = self.count_neighbours(position)

			if neig_count == 0:

				self.shown[position[0]][position[1]] = EMPTY_SHOWN # Show as empty
				for pos in self.get_neighbours(position):
					self.update(pos, REVEAL_MOVE) # recursively show the mines.
				return
			self.shown[position[0]][position[1]] = neig_count # Just show the number.

```

This code actually had a bug in it. I got this error:

```

Traceback (most recent call last):
  File "/home/cyberhacker/Asioita/Ohjelmointi/Python/minesweeper/main.py", line 165, in <module>
    exit(main())
         ^^^^^^
  File "/home/cyberhacker/Asioita/Ohjelmointi/Python/minesweeper/main.py", line 159, in main
    field.update((0,0), REVEAL_MOVE) # Example
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/cyberhacker/Asioita/Ohjelmointi/Python/minesweeper/main.py", line 119, in update
    self.update(pos, REVEAL_MOVE) # recursively show the mines.
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/cyberhacker/Asioita/Ohjelmointi/Python/minesweeper/main.py", line 119, in update
    self.update(pos, REVEAL_MOVE) # recursively show the mines.
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/cyberhacker/Asioita/Ohjelmointi/Python/minesweeper/main.py", line 119, in update
    self.update(pos, REVEAL_MOVE) # recursively show the mines.
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  [Previous line repeated 992 more times]
  File "/home/cyberhacker/Asioita/Ohjelmointi/Python/minesweeper/main.py", line 113, in update
    neig_count = self.count_neighbours(position)
                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/cyberhacker/Asioita/Ohjelmointi/Python/minesweeper/main.py", line 89, in count_neighbours
    neig_positions = self.get_neighbours(position)
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/cyberhacker/Asioita/Ohjelmointi/Python/minesweeper/main.py", line 84, in get_neighbours
    neig_positions = [x for x in neig_positions if x != None]
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
RecursionError: maximum recursion depth exceeded


```

This is because we are marking shown spaces as shown, even though they already were. Adding an if check to check if the new position is already checked prevents this:

```

	def update(self, position, move_type):

		if move_type == REVEAL_MOVE:

			if position in self.mine_positions:

				# Lost.

				print("You hit a mine! You lost.")
				self.reveal_mines()
				exit(1)

			# First count the neigbhour bombs.

			neig_count = self.count_neighbours(position)

			if neig_count == 0:
				if self.shown[position[0]][position[1]] != EMPTY_SHOWN:

					self.shown[position[0]][position[1]] = EMPTY_SHOWN # Show as empty
					for pos in self.get_neighbours(position):
						self.update(pos, REVEAL_MOVE) # recursively show the mines.
				return
			self.shown[position[0]][position[1]] = neig_count # Just show the number.

```

Now the code works.

Here is an example output:

```

Printing the minefield now:
------------
|##########|
|##########|
|##########|
|##########|
|##########|
|##########|
|##########|
|##########|
|##########|
|##########|
------------
Printing the minefield now:
------------
|   1######|
|   1######|
|  11######|
|  1#######|
| 12#######|
| 1########|
| 1########|
|11########|
|##########|
|##########|
------------
Revealing mines: (X means mine)
------------
|    X   X |
|          |
|          |
|   X      |
|          |
|  X X     |
|     X    |
|          |
| X      X |
| XX       |
------------


```

My current code is the following:

```


import numpy as np
import random

HIDDEN_SPACE = 100
MARKED_SPACE = 101
EMPTY_SHOWN = 102
MINE_NUMBER = 10

# def update(self, position, move_type):

MARK_MOVE = 0
REVEAL_MOVE = 1

class Minefield:
	def __init__(self, width, height, num_mines):
		assert num_mines <= width * height # the amount of mines must be less than or equal to the amount of spaces in the minefield.

		self.mines = np.zeros((width, height)) # Minefield.
		self.shown = np.ones((width, height)) # What we show to the user.
		self.shown = self.shown * HIDDEN_SPACE # Mark them as hidden.
		self.width = width
		self.height = height
		# Thanks to https://stackoverflow.com/questions/22842289/generate-n-unique-random-numbers-within-a-range

		positions = random.sample(range(0,width*height), num_mines)
		positions = [[pos//height, pos % height] for pos in positions] # Decode the positions, this should make it such that there are no duplicates.

		# Sanity check

		if len(positions) != len(set([str(x) for x in positions])):
			print("Error!")
			exit(1)
		self.mine_positions = positions

		for pos in positions:
			self.mines[pos[0]][pos[1]] = MINE_NUMBER

	def render(self):

		# Show the "shown" matrix
		print("Printing the minefield now:")
		print("-"*(self.width + 2))

		for line in self.shown:
			print("|", end="")
			for elem in line:
				if elem == HIDDEN_SPACE:
					print("#", end="")
				elif elem == MARKED_SPACE:
					print("X", end="")
				elif elem == EMPTY_SHOWN:
					print(" ",end="")
				else:
					#print("Elem == "+str(elem))
					print(str(int(elem)), end="")

			print("|", end="\n")
		print("-"*(self.width + 2))

	def get_neighbours(self,position):
		
		if position in self.mine_positions:
			print("Tried to call get_neighbours with a position which is a mine!")
			exit(1)
		
		if position[0] >= self.width or position[0] < 0 or position[1] >= self.height or position[1] < 0:
			print("Tried to call get_neighbours with an out of bounds position!")
			exit(1)


		x = position[0]
		y = position[1]
		neig_positions = [[x+1,y],[x-1,y],[x,y+1],[x,y-1],[x+1,y+1],[x-1,y-1],[x-1,y+1],[x+1,y-1]]

		for i,pos in enumerate(neig_positions):
			
			if pos[0] >= self.width or pos[0] < 0:
				neig_positions[i] = None
			
			if pos[1] >= self.height or pos[1] < 0:
				neig_positions[i] = None

		neig_positions = [x for x in neig_positions if x != None]
		return neig_positions


	def count_neighbours(self,position) -> int:
		neig_positions = self.get_neighbours(position)
		# Count how many of them are bombs.

		count = 0
		for pos in neig_positions:
			if pos in self.mine_positions:
				count += 1

		return count

	def update(self, position, move_type):

		if move_type == REVEAL_MOVE:

			if position in self.mine_positions:

				# Lost.

				print("You hit a mine! You lost.")
				self.reveal_mines()
				exit(1)

			# First count the neigbhour bombs.

			neig_count = self.count_neighbours(position)

			if neig_count == 0:
				if self.shown[position[0]][position[1]] != EMPTY_SHOWN:

					self.shown[position[0]][position[1]] = EMPTY_SHOWN # Show as empty
					for pos in self.get_neighbours(position):
						self.update(pos, REVEAL_MOVE) # recursively show the mines.
				return
			self.shown[position[0]][position[1]] = neig_count # Just show the number.

	def reveal_mines(self):

		print("Revealing mines: (X means mine)")

		print("-"*(self.width + 2))

		for line in self.mines:
			print("|", end="")
			for elem in line:
				if elem == MINE_NUMBER:
					print("X", end="")
				else:
					print(" ",end="")
				#else:

				#	print(str(elem), end="")

			print("|", end="\n")
		print("-"*(self.width + 2))














def main() -> int:
	field = Minefield(10, 10, 10)
	field.render()
	field.update((0,0), REVEAL_MOVE) # Example
	field.render()
	field.reveal_mines()

if __name__=="__main__":

	exit(main())


```

Now I think we need to add a win condition to our code. I think the best way to do that is to check if all of the other spaces other than the bomb spots have been revealed.

```

	def have_won(self):
		#print("self.shown == "+str(self.shown))
		for i, line in enumerate(self.shown):
			for j, elem in enumerate(line):
				if elem == HIDDEN_SPACE:
					# Check if a bomb spot, if yes, then continue, if not, then there are bombs, which aren't been designated yet.
					#print("[j,i] == "+s)
					if [j,i] not in self.mine_positions:
						return False # We have not won
		return True

```

Now, the code is not optimized and it could also be refactored a lot.

Here is the final code (for now, I am planning on improving the input mechanism by using keyboard events and the console cursor in the future, so the player does not have to type the coordinates every time):

```


import numpy as np
import random
import sys

HIDDEN_SPACE = 100
MARKED_SPACE = 101
EMPTY_SHOWN = 102
MINE_NUMBER = 10

# def update(self, position, move_type):

MARK_MOVE = 0
REVEAL_MOVE = 1

class Minefield:
	def __init__(self, width, height, num_mines):
		assert num_mines <= width * height # the amount of mines must be less than or equal to the amount of spaces in the minefield.

		self.mines = np.zeros((width, height)) # Minefield.
		self.shown = np.ones((width, height)) # What we show to the user.
		self.shown = self.shown * HIDDEN_SPACE # Mark them as hidden.
		self.width = width
		self.height = height
		# Thanks to https://stackoverflow.com/questions/22842289/generate-n-unique-random-numbers-within-a-range

		positions = random.sample(range(0,width*height), num_mines)
		positions = [[pos//height, pos % height] for pos in positions] # Decode the positions, this should make it such that there are no duplicates.

		# Sanity check

		if len(positions) != len(set([str(x) for x in positions])):
			print("Error!")
			exit(1)
		self.mine_positions = positions

		for pos in positions:
			self.mines[pos[0]][pos[1]] = MINE_NUMBER

	def render(self):

		# Show the "shown" matrix
		print("Printing the minefield now:")
		print("-"*(self.width + 2))

		for line in self.shown:
			print("|", end="")
			for elem in line:
				if elem == HIDDEN_SPACE:
					print("#", end="")
				elif elem == MARKED_SPACE:
					print("X", end="")
				elif elem == EMPTY_SHOWN:
					print(" ",end="")
				else:
					#print("Elem == "+str(elem))
					print(str(int(elem)), end="")

			print("|", end="\n")
		print("-"*(self.width + 2))

	def get_neighbours(self,position):
		
		if position in self.mine_positions:
			print("Tried to call get_neighbours with a position which is a mine!")
			exit(1)
		
		if position[0] >= self.width or position[0] < 0 or position[1] >= self.height or position[1] < 0:
			print("Tried to call get_neighbours with an out of bounds position!")
			exit(1)


		x = position[0]
		y = position[1]
		neig_positions = [[x+1,y],[x-1,y],[x,y+1],[x,y-1],[x+1,y+1],[x-1,y-1],[x-1,y+1],[x+1,y-1]]

		for i,pos in enumerate(neig_positions):
			
			if pos[0] >= self.width or pos[0] < 0:
				neig_positions[i] = None
			
			if pos[1] >= self.height or pos[1] < 0:
				neig_positions[i] = None

		neig_positions = [x for x in neig_positions if x != None]
		return neig_positions


	def count_neighbours(self,position) -> int:
		neig_positions = self.get_neighbours(position)
		# Count how many of them are bombs.

		count = 0
		for pos in neig_positions:
			if pos in self.mine_positions:
				count += 1

		return count

	def update(self, position, move_type):
		position = list(position)
		if move_type == REVEAL_MOVE:
			#print("self.mine_positions == "+str(self.mine_positions))
			#print("position == "+str(position))
			if position in self.mine_positions:

				# Lost.

				print("You hit a mine! You lost.")
				self.reveal_mines()
				#exit(0)
				return 1

			# First count the neigbhour bombs.

			neig_count = self.count_neighbours(position)

			if neig_count == 0:
				if self.shown[position[0]][position[1]] != EMPTY_SHOWN:

					self.shown[position[0]][position[1]] = EMPTY_SHOWN # Show as empty
					for pos in self.get_neighbours(position):
						self.update(pos, REVEAL_MOVE) # recursively show the mines.
				return
			self.shown[position[0]][position[1]] = neig_count # Just show the number.
		return 0

	def have_won(self):
		#print("self.shown == "+str(self.shown))
		for i, line in enumerate(self.shown):
			for j, elem in enumerate(line):
				if elem == HIDDEN_SPACE:
					# Check if a bomb spot, if yes, then continue, if not, then there are bombs, which aren't been designated yet.
					#print("[j,i] == "+s)
					if [j,i] not in self.mine_positions:
						return False # We have not won
		return True



	def reveal_mines(self):

		print("Revealing mines: (X means mine)")

		print("-"*(self.width + 2))

		for line in self.mines:
			print("|", end="")
			for elem in line:
				if elem == MINE_NUMBER:
					print("X", end="")
				else:
					print(" ",end="")
				#else:

				#	print(str(elem), end="")

			print("|", end="\n")
		print("-"*(self.width + 2))








def setup_minefield() -> Minefield:
	width = int(input("How wide do you want the minefield to be? : "))
	height = int(input("How long do you want the minefield to be? : "))
	num_mines = int(input("How many mines do you want? : "))

	print("Creating game...")

	field = Minefield(width, height, num_mines)

	return field




def get_move() -> tuple:
	move_input = str(input("Which position would you like to reveal? : "))
	while move_input == "":
		move_input = str(input("Which position would you like to reveal? :" ))
	if move_input == "showmines":
		return move_input

	if ", " not in move_input:
		if "," not in move_input:
			print("Invalid input.")
			exit(0)
		return reversed([int(x) for x in move_input.split(",")])
	return reversed([int(x) for x in move_input.split(", ")])



def main() -> int:
	field = setup_minefield()
	print("Input coordinates are in the format x, y")
	while True:
		field.render()
		
		move = get_move()
		if move == "showmines":
			field.reveal_mines()
			continue
		if(field.update(move, REVEAL_MOVE)):
			break
		field.render()
		if field.have_won():
			print("You have won! Congratulations!")
			return 0
		#field.render()
		#field.reveal_mines()
		print("\n"*100+"\r"*100)
		sys.stdout.flush()

	return 0

if __name__=="__main__":

	exit(main())


```

## Making it better.

Ok so now a week has passed since i last looked at this.

Now it is time to actually make the controls interactive instead of a having to type the coordinates every time.

After trying out a lot of things, I eventually settled on this:

```


import numpy as np
import random
import sys
import termios
import time

def enable_echo(fd, enabled):
	(iflag, oflag, cflag, lflag, ispeed, ospeed, cc) = termios.tcgetattr(fd)

	if enabled:
		lflag |= termios.ECHO
	else:
		lflag &= ~termios.ECHO

	new_attr = [iflag, oflag, cflag, lflag, ispeed, ospeed, cc]
	termios.tcsetattr(fd, termios.TCSANOW, new_attr)



HIDDEN_SPACE = 100
MARKED_SPACE = 101
EMPTY_SHOWN = 102
MINE_NUMBER = 10

# def update(self, position, move_type):

MARK_MOVE = 0
REVEAL_MOVE = 1

mouse_x = 1
mouse_y = 1

pressed_enter = False

from pynput.keyboard import Listener, Key
from pynput import keyboard
#import logging

# Setup logging
#logging.basicConfig(filename="key_log.txt", level=logging.DEBUG, format='%(asctime)s: %(message)s')


def send(cmd):
	sys.stdout.write(cmd)
	sys.stdout.flush()


def on_press(key):  # The function that's called when a key is pressed
	#print("Key pressed: {0}".format(key))
	global mouse_x
	global pressed_enter
	global mouse_y
	#print("Mouse position: ({0}, {1})".format(mouse_x, mouse_y))


	'''
	if key == Key.up:
		#print("UP!")
		mouse_y += 1
		cursor_move(mouse_x, mouse_y)
	if key == Key.down:
		
		if mouse_y <= 0:
			return # Do not move, because otherwise mouse_y would become negative.

		mouse_y -= 1
		cursor_move(mouse_x, mouse_y)

	if key == Key.right:
		mouse_x += 1
		cursor_move(mouse_x, mouse_y)

	if key == Key.left:
		if mouse_x <= 0:
			return
		mouse_x -= 1
		cursor_move(mouse_x, mouse_y)
	'''


	#print("key == \"w\" == "+str(key == "w"))
	#print(type(key))
	key = str(key)[1]
	if str(key) == "w":
		mouse_y += 1
		cursor_move(mouse_x, mouse_y)
	if str(key) == "s":
		if mouse_y <= 0:
			return # Do not move, because otherwise mouse_y would become negative.

		mouse_y -= 1
		cursor_move(mouse_x, mouse_y)

	if str(key) == "d":
		mouse_x += 1
		cursor_move(mouse_x, mouse_y)

	if str(key) == "a":
		if mouse_x <= 0:
			return
		mouse_x -= 1
		cursor_move(mouse_x, mouse_y)
	#print("",end="\n")

	#if key == Key.enter:
	#	pressed_enter = True
	#	return False
	return True

def on_release(key):
	global pressed_enter
	if key == Key.enter:
		pressed_enter = True
		return False

#def on_release(key):  # The function that's called when a key is released
#	print("Key released: {0}".format(key))






#def cursor_move (x,y):
    #print("\033[%d;%dH" % (y+1, x+1))


    #print("ppooqqqqq")

def cursor_move(column, line):
    send('\033[%s;%sf' % (line+1, column+1))


def clear():
	#print("\033[H\033[2J\033[3J$")
	print("\033[2J\033[H", end="")

class Minefield:
	def __init__(self, width, height, num_mines):
		assert num_mines <= width * height # the amount of mines must be less than or equal to the amount of spaces in the minefield.

		self.mines = np.zeros((width, height)) # Minefield.
		self.shown = np.ones((width, height)) # What we show to the user.
		self.shown = self.shown * HIDDEN_SPACE # Mark them as hidden.
		self.width = width
		self.height = height
		# Thanks to https://stackoverflow.com/questions/22842289/generate-n-unique-random-numbers-within-a-range

		positions = random.sample(range(0,width*height), num_mines)
		positions = [[pos//height, pos % height] for pos in positions] # Decode the positions, this should make it such that there are no duplicates.

		# Sanity check

		if len(positions) != len(set([str(x) for x in positions])):
			print("Error!")
			exit(1)
		self.mine_positions = positions

		for pos in positions:
			self.mines[pos[0]][pos[1]] = MINE_NUMBER

	def render(self):

		# Show the "shown" matrix
		#print("Printing the minefield now:")
		print("-"*(self.width + 2))

		for line in self.shown:
			print("|", end="")
			for elem in line:
				if elem == HIDDEN_SPACE:
					print("#", end="")
				elif elem == MARKED_SPACE:
					print("X", end="")
				elif elem == EMPTY_SHOWN:
					print(" ",end="")
				else:
					#print("Elem == "+str(elem))
					print(str(int(elem)), end="")

			print("|", end="\n")
		print("-"*(self.width + 2))

	def get_neighbours(self,position):
		
		if position in self.mine_positions:
			print("Tried to call get_neighbours with a position which is a mine!")
			exit(1)
		
		if position[0] >= self.width or position[0] < 0 or position[1] >= self.height or position[1] < 0:
			print("Tried to call get_neighbours with an out of bounds position!")
			exit(1)


		x = position[0]
		y = position[1]
		neig_positions = [[x+1,y],[x-1,y],[x,y+1],[x,y-1],[x+1,y+1],[x-1,y-1],[x-1,y+1],[x+1,y-1]]

		for i,pos in enumerate(neig_positions):
			
			if pos[0] >= self.width or pos[0] < 0:
				neig_positions[i] = None
			
			if pos[1] >= self.height or pos[1] < 0:
				neig_positions[i] = None

		neig_positions = [x for x in neig_positions if x != None]
		return neig_positions


	def count_neighbours(self,position) -> int:
		neig_positions = self.get_neighbours(position)
		# Count how many of them are bombs.

		count = 0
		for pos in neig_positions:
			if pos in self.mine_positions:
				count += 1

		return count

	def update(self, position, move_type):
		position = list(position)
		if move_type == REVEAL_MOVE:
			#print("self.mine_positions == "+str(self.mine_positions))
			#print("position == "+str(position))
			if position in self.mine_positions:

				# Lost.

				print("You hit a mine! You lost.")
				self.reveal_mines()
				#exit(0)
				return 1

			# First count the neigbhour bombs.

			neig_count = self.count_neighbours(position)

			if neig_count == 0:
				if self.shown[position[0]][position[1]] != EMPTY_SHOWN:

					self.shown[position[0]][position[1]] = EMPTY_SHOWN # Show as empty
					for pos in self.get_neighbours(position):
						self.update(pos, REVEAL_MOVE) # recursively show the mines.
				return
			self.shown[position[0]][position[1]] = neig_count # Just show the number.
		return 0

	def have_won(self):
		#print("self.shown == "+str(self.shown))
		for i, line in enumerate(self.shown):
			for j, elem in enumerate(line):
				if elem == HIDDEN_SPACE:
					# Check if a bomb spot, if yes, then continue, if not, then there are bombs, which aren't been designated yet.
					#print("[j,i] == "+s)
					if [j,i] not in self.mine_positions:
						return False # We have not won
		return True



	def reveal_mines(self):

		print("Revealing mines: (X means mine)")

		print("-"*(self.width + 2))

		for line in self.mines:
			print("|", end="")
			for elem in line:
				if elem == MINE_NUMBER:
					print("X", end="")
				else:
					print(" ",end="")
				#else:

				#	print(str(elem), end="")

			print("|", end="\n")
		print("-"*(self.width + 2))








def setup_minefield() -> Minefield:
	width = int(input("How wide do you want the minefield to be? : "))
	height = int(input("How long do you want the minefield to be? : "))
	num_mines = int(input("How many mines do you want? : "))

	print("Creating game...")

	field = Minefield(width, height, num_mines)

	return field


def check_press(event, char):
	assert isinstance(char,str)
	assert len(char) == 1
	#res = event == keyboard.Events.Press(keyboard.KeyCode.from_char(char))
	res = (isinstance(event, keyboard.Events.Press) and str(event.key)[1] == char)
	return res

def get_mouse_pos(field: Minefield) -> tuple:
	#move_input = str(input("Which position would you like to reveal? : "))


	#while move_input == "":
	#	move_input = str(input("Which position would you like to reveal? :" ))
	#if move_input == "showmines":
	#	return move_input

	#if ", " not in move_input:
	#	if "," not in move_input:
	#		print("Invalid input.")
	#		exit(0)
	#	return reversed([int(x) for x in move_input.split(",")])


	time.sleep(0.05)

	max_x = len(field.mines[0])
	max_y = len(field.mines)


	#return reversed([int(x) for x in move_input.split(", ")])

	global pressed_enter
	global mouse_y
	global mouse_x

	while pressed_enter == False:
		#continue # Wait for the player to press enter.
		event_list = []
		with keyboard.Events() as events: # Keyboard events.

			for event in events:
				if isinstance(event, keyboard.Events.Release):
					continue
				#event_list.append(event)

				#print("event_list == "+str(event_list))


				#for event in event_list:

				#print(event)
				#print("event.key == "+str(event.key))
				#event = events[0]
				#key = event.key
				#print("event.__dir__() == "+str(event.__dir__()))
				# Copy the logic
				#print("key.__dir__ == "+str(key.__dir__()))
				#key = str(key)[1]
				#print("key == "+str(key))




				if check_press(event, "s"):
					mouse_y += 1
					if mouse_y > max_y:
						mouse_y = max_y
					cursor_move(mouse_x, mouse_y)
				if check_press(event, "w"):
					if mouse_y <= 1:
						continue # Do not move, because otherwise mouse_y would become negative.

					mouse_y -= 1
					cursor_move(mouse_x, mouse_y)

				if check_press(event, "d"):
					mouse_x += 1
					if mouse_x > max_x:
						mouse_x = max_x
					cursor_move(mouse_x, mouse_y)

				if check_press(event, "a"):
					if mouse_x <= 1:
						continue
					mouse_x -= 1
					cursor_move(mouse_x, mouse_y)

				if event.key == Key.enter:
					pressed_enter = True
					#print("Pressed enter")
					break

	#print("Pressed enterfefefefefefefe")
	pressed_enter = False
	#global mouse_x
	#global mouse_y
	return [mouse_y, mouse_x]


def get_move(field: Minefield, mouse_position: tuple):

	# Converts the mouse position to coordinates on the map. Returns None if an invalid position. (Should not be possible.)
	mouse_position = list(mouse_position)
	mouse_position[0] -= 1
	mouse_position[1] -= 1

	x = mouse_position[0]
	y = mouse_position[1]

	if x < 0 or y < 0:
		return None
	if x >= len(field.mines[0]):
		return None
	if y >= len(field.mines):
		return None
	return tuple(mouse_position)

def main() -> int:
	field = setup_minefield()
	#print("Input coordinates are in the format x, y")
	#listener = Listener(on_press=on_press, on_release=on_release)
	#with Listener(on_press=on_press, on_release=on_release) as listener:  # Create an instance of Listener
	#listener.start()  # Join the listener thread to the main thread to keep waiting for keys
	#listener.join()
	
	global mouse_x
	global mouse_y
	
	enable_echo(0,False)
	clear()
	
	while True:
		clear()
		field.render()
		cursor_move(mouse_x, mouse_y)
		#listener.join()
		
		mouse_pos = get_mouse_pos(field)
		#print("move == "+str(move))
		
		move = get_move(field, mouse_pos)
		#if move == "showmines":
		#	field.reveal_mines()
		#	continue
		if(field.update(move, REVEAL_MOVE)):
			break
		field.render()
		if field.have_won():
			print("You have won! Congratulations!")
			return 0
		#field.render()
		#field.reveal_mines()
		#print("\b"*1000+" "*10000+"\b"*100)
		print("poopooo")
		clear()
		#sys.stdout.flush()
	sys.stdin.flush()
	return 0
import atexit
atexit.register(enable_echo, sys.stdin.fileno(), True)
if __name__=="__main__":
	# enable_echo(0,False)
	sys.stdin.flush()
	exit(main())



```

It's not pretty by any means, but it gets the job done without having to do that much of extra work. One thing which bugs me is that after losing the game and getting into the terminal, it spews out all of the characters which were typed during the game into the terminal. I do not know how to get rid of this, but now atleast it works with WASD inputs. Also another thing is that it does not work if the size of the grid is larger than the size of the terminal so that is quite bad. Anyway, now it works.




































