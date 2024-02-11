
# Day 22

## Part 1

Now, I think we can make a list of lists, which have the coordinates used by one block.

For example, we can have something like this: `[[(0,0,0), (0,1,0)], [(0,2,0),(0,3,0)]]` , where the spots `[(0,0,0), (0,1,0)]` are occupied by the block number one and the spots `[(0,2,0),(0,3,0)]` are occupied by block number two.

Then in addition, we can also make a dictionary where the keys are the positions and the values are the block number, (if zero then no block exists there). Now, I am not sure that we need to even simulate the blocks "falling" in place, because hypothetically we can just check all of the spaces above another block when deciding if removing a block is safe or not, but I think that it will be easier to just simulate the blocks falling (i think). Maybe in part 2 we will use the optimization where we do not need to simulate the blocks falling, but idk..

Sooo, first let's create a parse function which creates the list of lists and the dictionary?

After a bit of snooping around I found this: https://www.reddit.com/r/adventofcode/comments/18o7014/comment/kk6tm9e/ which basically made an object oriented approach to solving this puzzle.

Yeah, after a bit of fiddling around, I think the best way to go about this is to create a class for the brick. Anyway, here is my initial attempt:

```
import sys

# Number of dimensions. (Unused, maybe I will refactor the code to support arbitrary dimensions.)
NUM_DIMS = 3
UP_COORD = 1 # Index of the coordinate which signifies the "up" direction.
UP_SIGN = 1 # sign of where is up (positive means that up is in the positive "UP_COORD" dir)


def create_block_range(block_start: tuple, block_end: tuple) -> list:
    # First get the coordinate which changes.
    for x in range(len(block_start)):
        if block_start[x] != block_end[x]:
            # This differs, therefore this is the coordinate which changes.
            change_ind = x
            if block_start[x] <= block_end[x]:
                # block_start is the actual start
                start = block_start
                end = block_end
            else:
                # Otherwise the start is actually block end.
                start = block_end
                end = block_start
            diff = abs(start[x] - end[x])
            break # No need to go over anymore.
    # This creates a list of all of the coordinates occupied by one brick.
    out = []
    for i in range(diff+1): # Here just create the list of coordinates.
        out.append(start)
        start[change_ind] += 1
    return out # return the list of coordinates


def parse_input() -> list: # Outputs a dictionary, where the keys are coordinates and the value is which block there is at that coordinate. Also outputs a list where the blocks at certain coordinates are the elements and the indexes are which block is currently being considered.
    lines = sys.stdin.read().split("\n")
    pos_dict = dict()
    block_coord_list = []
    for block_num, line in enumerate(lines):
        # Separate on "~"
        block_start, block_end = line.split("~")
        # Now split the coordinates on "," .
        block_start = tuple((int(x) for x in block_start.split(",")))
        block_end = tuple((int(x) for x in block_end.split(",")))
        # Now generate the block range.
        blocks_stuff = create_block_range(block_start, block_end)
        # First append to the block coordinates list.
        block_coord_list.append(blocks_stuff)
        # Now we have the list, now add the stuff to the dictionary thing.
        for pos in blocks_stuff:
            pos_dict


def main() -> int:

    return 0

if __name__=="__main__":
    exit(main())

```

Let's create a new script which has the brick object.

Here is my initial attempt:

```
import sys

# Number of dimensions. (Unused, maybe I will refactor the code to support arbitrary dimensions.)
NUM_DIMS = 3
UP_COORD = 1 # Index of the coordinate which signifies the "up" direction.
UP_SIGN = 1 # sign of where is up (positive means that up is in the positive "UP_COORD" dir)


class Brick:
    def __init__(self, id: int, start: tuple, end: tuple) -> None:
        # Constructor
        self.blocks = create_block_range(start, end)
        self.pos1 = list(start)
        self.pos2 = list(end)
        self.below_bricks = set()
        self.above_bricks = set()
        self._supporting = None
        self._is_supported_by = None

    def on_ground(self) -> bool:
        return self.lowest_point() == 1

    def highest_point(self):
        return max(self.pos1[UP_COORD], self.pos2[UP_COORD])
    
    def lowest_point(self):
        return min(self.pos1[UP_COORD], self.pos2[UP_COORD])

    def is_level_below(self, other_brick) -> bool:
        return self.highest_point() == other.lowest_point()-1
    def is_supported_by(self):
        if self._is_supported_by == None:
            self._is_supported_by = [x for x in self.below_bricks if x.is_level_below(self)]
        return self._is_supported_by

    def supporting(self):
        if self._supporting == None:
            self._supporting = [x for x in self.above_bricks if self.is_level_below(x)]
        return self._supporting

    def ranges_overlap(self, r1, r2) -> bool:
        return not (r1[1] < r2[0] or r1[0] > r2[1])

    def is_under(self, other) -> bool: # Check for x and y overlap.
        x_overlap, y_overlap, _ = self.overlaps(other)
        return x_overlap and y_overlap

    def overlaps(self, other) -> bool:
        x1, y1, z1 = self.pos1
        x2, y2, z21 = self.pos2
        x_r1 = (min(x1,x2), max(x1,x2))
        y_r1 = (min(y1,y2), max(y1,y2))
        z_r1 = (min(z1,z2), max(z1,z2))

        x3, y3, z3 = other.pos1
        x4, y4, z4 = other.pos2

        x_r2 = (min(x3,x4), max(x3,x4))
        y_r2 = (min(y3,y4), max(y3,y4))
        z_r2 = (min(z3,z4), max(z3,z4))

        overlap_x = self.ranges_overlap(x_r1, x_r2)
        overlap_y = self.ranges_overlap(y_r1, y_r2)
        overlap_z = self.ranges_overlap(z_r1, z_r2)

        return (overlap_x, overlap_y, overlap_z)

    def drop(self, amount=1) -> None:
        self.pos1[2] -= amount
        self.pos2[2] -= amount


def create_block_range(block_start: tuple, block_end: tuple) -> list:
    # First get the coordinate which changes.
    for x in range(len(block_start)):
        if block_start[x] != block_end[x]:
            # This differs, therefore this is the coordinate which changes.
            change_ind = x
            if block_start[x] <= block_end[x]:
                # block_start is the actual start
                start = block_start
                end = block_end
            else:
                # Otherwise the start is actually block end.
                start = block_end
                end = block_start
            diff = abs(start[x] - end[x])
            break # No need to go over anymore.
    # This creates a list of all of the coordinates occupied by one brick.
    out = []
    for i in range(diff+1): # Here just create the list of coordinates.
        out.append(start)
        start[change_ind] += 1
    return out # return the list of coordinates


def parse_input() -> list: # Outputs a dictionary, where the keys are coordinates and the value is which block there is at that coordinate. Also outputs a list where the blocks at certain coordinates are the elements and the indexes are which block is currently being considered.
    lines = sys.stdin.read().split("\n")
    pos_dict = dict()
    block_coord_list = []
    for block_num, line in enumerate(lines):
        # Separate on "~"
        block_start, block_end = line.split("~")
        # Now split the coordinates on "," .
        block_start = tuple((int(x) for x in block_start.split(",")))
        block_end = tuple((int(x) for x in block_end.split(",")))
        # Now generate the block range.
        new_brick = Brick(block_num, block_start, block_end)


def main() -> int:

    return 0

if __name__=="__main__":
    exit(main())


```

let's try it out with the toy input.

Uh oh...

```
    start[change_ind] += 1
    ~~~~~^^^^^^^^^^^^
TypeError: 'tuple' object does not support item assignment
```

Actually, the `self.blocks` in the `Brick` class is unused, so let's just remove it.

Now that we have actually programmed the input parsing function, let's actually solve the puzzle.

Let's simulate the falling of the blocks first and then go over each brick and check if we could remove it.

First up, the simulation of falling. We fant to first sort by which brick is the lowest.

```
bricks.sort(key=lambda x: x.lowest_point())
```

now go over the bricks in this new order and then update the above and below bricks in the other bricks while we go over them.






...



Here is my current script:

```
import sys
import copy


# Number of dimensions. (Unused, maybe I will refactor the code to support arbitrary dimensions.)
NUM_DIMS = 3
UP_COORD = 1 # Index of the coordinate which signifies the "up" direction.
UP_SIGN = 1 # sign of where is up (positive means that up is in the positive "UP_COORD" dir)
PART = 1

class Brick:
    def __init__(self, id: int, start: tuple, end: tuple) -> None:
        # Constructor
        #self.blocks = create_block_range(start, end)
        self.pos1 = list(start)
        self.pos2 = list(end)
        self.below_bricks = set()
        self.above_bricks = set()
        self._supporting = None
        self._is_supported_by = None

    def on_ground(self) -> bool:
        return self.lowest_point() == 1

    def highest_point(self):
        return max(self.pos1[UP_COORD], self.pos2[UP_COORD])
    
    def lowest_point(self):
        return min(self.pos1[UP_COORD], self.pos2[UP_COORD])

    def is_level_below(self, other) -> bool:
        return self.highest_point() == other.lowest_point()-1
    def is_supported_by(self):
        if self._is_supported_by == None:
            self._is_supported_by = [x for x in self.below_bricks if x.is_level_below(self)]
        return self._is_supported_by

    def supporting(self):
        if self._supporting == None:
            self._supporting = [x for x in self.above_bricks if self.is_level_below(x)]
        return self._supporting

    def ranges_overlap(self, r1, r2) -> bool:
        return not (r1[1] < r2[0] or r1[0] > r2[1])

    def is_under(self, other) -> bool: # Check for x and y overlap.
        x_overlap, y_overlap, _ = self.overlaps(other)
        return x_overlap and y_overlap

    def overlaps(self, other) -> bool:
        x1, y1, z1 = self.pos1
        x2, y2, z2 = self.pos2
        x_r1 = (min(x1,x2), max(x1,x2))
        y_r1 = (min(y1,y2), max(y1,y2))
        z_r1 = (min(z1,z2), max(z1,z2))

        x3, y3, z3 = other.pos1
        x4, y4, z4 = other.pos2

        x_r2 = (min(x3,x4), max(x3,x4))
        y_r2 = (min(y3,y4), max(y3,y4))
        z_r2 = (min(z3,z4), max(z3,z4))

        overlap_x = self.ranges_overlap(x_r1, x_r2)
        overlap_y = self.ranges_overlap(y_r1, y_r2)
        overlap_z = self.ranges_overlap(z_r1, z_r2)

        return (overlap_x, overlap_y, overlap_z)

    def drop(self, amount=1) -> None:
        self.pos1[2] -= amount
        self.pos2[2] -= amount


def create_block_range(block_start: tuple, block_end: tuple) -> list:
    block_start = list(block_start)
    block_end = list(block_end)
    # First get the coordinate which changes.
    for x in range(len(block_start)):
        if block_start[x] != block_end[x]:
            # This differs, therefore this is the coordinate which changes.
            change_ind = x
            if block_start[x] <= block_end[x]:
                # block_start is the actual start
                start = block_start
                end = block_end
            else:
                # Otherwise the start is actually block end.
                start = block_end
                end = block_start
            diff = abs(start[x] - end[x])
            break # No need to go over anymore.
    # This creates a list of all of the coordinates occupied by one brick.
    out = []
    for i in range(diff+1): # Here just create the list of coordinates.
        out.append(start)
        start[change_ind] += 1
    return out # return the list of coordinates

def drop_bricks(bricks: list) -> list:
    # Make a copy of the original bricks.
    orig_bricks = copy.deepcopy(bricks)
    bricks.sort(key=lambda x: x.lowest_point())
    for falling in bricks:
        if falling.on_ground(): # If brick is already on ground, then don't go over it.
            continue
        highest_point = 1
        lower_bricks = [lower for lower in bricks if lower.lowest_point() < falling.lowest_point()] # Here we check all of the bricks and check if the brick is lower than the current falling brick.
        if lower_bricks == []: # If there are no bricks which are lower than this brick (this falling brick will fall to the ground) then continue
            continue
        # Now check for collision with the lower bricks.
        for lower in lower_bricks:
            if lower.is_under(falling): # Here check if we fall on top of this brick.
                falling.below_bricks.add(lower)
                lower.above_bricks.add(falling)
                highest_point = max(highest_point, lower.highest_point()+1) # Update the current highest point.
        if falling.lowest_point() > highest_point: # Check if we need to move the brick.
            falling.drop(falling.lowest_point() - highest_point) # Move the brick by the difference.

    # Now sort the bricks again by their lowest point. This needs to be done, because the positions of the bricks have changed.
    bricks.sort(key=lambda x: x.lowest_point())
    return bricks

def parse_input() -> list: # Outputs a dictionary, where the keys are coordinates and the value is which block there is at that coordinate. Also outputs a list where the blocks at certain coordinates are the elements and the indexes are which block is currently being considered.
    lines = sys.stdin.read().split("\n")
    bricks = []
    for block_num, line in enumerate(lines):
        # Separate on "~"
        block_start, block_end = line.split("~")
        # Now split the coordinates on "," .
        block_start = tuple((int(x) for x in block_start.split(",")))
        block_end = tuple((int(x) for x in block_end.split(",")))
        # Now generate the block range.
        new_brick = Brick(block_num, block_start, block_end)
        print(new_brick)
        bricks.append(new_brick)

    return bricks

def disintegrate(brick: Brick) -> int: # This actually checks if we can remove the brick or not.
    # Loop over each brick which is supported by the current brick.
    for being_supported in brick.supporting():
        if len(being_supported.is_supported_by()) == 1: # If that one brick is supported by only one other brick (the current one) then we can NOT remove it, therefore return zero
            return 0
    return 1 # Otherwise we can remove it. Return one

def solve(solve_func, bricks: list) -> int: # This is the actual solve function
    # Go over each brick with the corresponding part function.
    return sum(solve_func(b) for b in bricks)
def part2(bricks: list) -> int:
    return 0 # To be implemented...

def main() -> int:
    bricks = parse_input()
    bricks = drop_bricks(bricks) # Simulate the falling of the bricks. (We need to do this for both parts.)
    if PART == 1:
        res = solve(disintegrate, bricks)
    elif PART == 2:
        res = solve(part2, bricks)
    else:
        print("Invalid part number: "+str(PART))
        exit(1)

    print(res) # Print final solution.
    return 0

if __name__=="__main__":
    exit(main())
```

Except that it returns 7 as the answer, which is obviously wrong.

Here:

```
def disintegrate(brick: Brick) -> int: # This actually checks if we can remove the brick or not.
    # Loop over each brick which is supported by the current brick.
    for being_supported in brick.supporting():
        assert len(being_supported.is_supported_by()) != 0
        print("being_supported.is_supported_by() == "+str(being_supported.is_supported_by()))
        if len(being_supported.is_supported_by()) == 1: # If that one brick is supported by only one other brick (the current one) then we can NOT remove it, therefore return zero
            return 0
    return 1 # Otherwise we can remove it. Return one
```

We actually do not go over the loop even once. So the _supporting array isn't being updated properly.


Here was my code:

```

import sys
import copy


# Number of dimensions. (Unused, maybe I will refactor the code to support arbitrary dimensions.)
NUM_DIMS = 3
UP_COORD = 1 # Index of the coordinate which signifies the "up" direction.
UP_SIGN = 1 # sign of where is up (positive means that up is in the positive "UP_COORD" dir)
PART = 1

class Brick:
    def __init__(self, id: int, start: tuple, end: tuple) -> None:
        # Constructor
        #self.blocks = create_block_range(start, end)
        self.pos1 = list(start)
        self.pos2 = list(end)
        self.below_bricks = set()
        self.above_bricks = set()
        self._supporting = None
        self._is_supported_by = None

    def on_ground(self) -> bool:
        return self.lowest_point() == 1

    def highest_point(self):
        return max(self.pos1[UP_COORD], self.pos2[UP_COORD])
    
    def lowest_point(self):
        return min(self.pos1[UP_COORD], self.pos2[UP_COORD])

    def is_level_below(self, other) -> bool:
        return self.highest_point() == other.lowest_point()-1
    def is_supported_by(self):
        if self._is_supported_by == None:
            self._is_supported_by = [x for x in self.below_bricks if x.is_level_below(self)]
        return self._is_supported_by

    def supporting(self):
        if self._supporting == None:
            print("self.above_bricks == "+str(self.above_bricks))
            self._supporting = [x for x in self.above_bricks if self.is_level_below(x)]
        print(self._supporting)
        return self._supporting

    def ranges_overlap(self, r1, r2) -> bool:
        return not (r1[1] < r2[0] or r1[0] > r2[1])

    def is_under(self, other) -> bool: # Check for x and y overlap.
        x_overlap, y_overlap, _ = self.overlaps(other)
        return x_overlap and y_overlap

    def overlaps(self, other) -> bool:
        x1, y1, z1 = self.pos1
        x2, y2, z2 = self.pos2
        x_r1 = (min(x1,x2), max(x1,x2))
        y_r1 = (min(y1,y2), max(y1,y2))
        z_r1 = (min(z1,z2), max(z1,z2))

        x3, y3, z3 = other.pos1
        x4, y4, z4 = other.pos2

        x_r2 = (min(x3,x4), max(x3,x4))
        y_r2 = (min(y3,y4), max(y3,y4))
        z_r2 = (min(z3,z4), max(z3,z4))

        overlap_x = self.ranges_overlap(x_r1, x_r2)
        overlap_y = self.ranges_overlap(y_r1, y_r2)
        overlap_z = self.ranges_overlap(z_r1, z_r2)

        return (overlap_x, overlap_y, overlap_z)

    def drop(self, amount=1) -> None:
        self.pos1[2] -= amount
        self.pos2[2] -= amount


def create_block_range(block_start: tuple, block_end: tuple) -> list:
    block_start = list(block_start)
    block_end = list(block_end)
    # First get the coordinate which changes.
    for x in range(len(block_start)):
        if block_start[x] != block_end[x]:
            # This differs, therefore this is the coordinate which changes.
            change_ind = x
            if block_start[x] <= block_end[x]:
                # block_start is the actual start
                start = block_start
                end = block_end
            else:
                # Otherwise the start is actually block end.
                start = block_end
                end = block_start
            diff = abs(start[x] - end[x])
            break # No need to go over anymore.
    # This creates a list of all of the coordinates occupied by one brick.
    out = []
    for i in range(diff+1): # Here just create the list of coordinates.
        out.append(start)
        start[change_ind] += 1
    return out # return the list of coordinates

def drop_bricks(bricks: list) -> list:
    # Make a copy of the original bricks.
    orig_bricks = copy.deepcopy(bricks)
    bricks.sort(key=lambda x: x.lowest_point())
    for falling in bricks:
        if falling.on_ground(): # If brick is already on ground, then don't go over it.
            continue
        highest_point = 1
        lower_bricks = [lower for lower in bricks if lower.lowest_point() < falling.lowest_point()] # Here we check all of the bricks and check if the brick is lower than the current falling brick.
        if lower_bricks == []: # If there are no bricks which are lower than this brick (this falling brick will fall to the ground) then continue
            print(" no lower_bricks")
            continue
        # Now check for collision with the lower bricks.
        for lower in lower_bricks:
            if lower.is_under(falling): # Here check if we fall on top of this brick.
                print("poopoo")
                falling.below_bricks.add(lower)
                lower.above_bricks.add(falling)
                print("lower.above_bricks == "+str(lower.above_bricks))
                highest_point = max(highest_point, lower.highest_point()+1) # Update the current highest point.
        if falling.lowest_point() > highest_point: # Check if we need to move the brick.
            falling.drop(falling.lowest_point() - highest_point) # Move the brick by the difference.

    # Now sort the bricks again by their lowest point. This needs to be done, because the positions of the bricks have changed.
    bricks.sort(key=lambda x: x.lowest_point())
    return bricks

def parse_input() -> list: # Outputs a dictionary, where the keys are coordinates and the value is which block there is at that coordinate. Also outputs a list where the blocks at certain coordinates are the elements and the indexes are which block is currently being considered.
    lines = sys.stdin.read().split("\n")
    bricks = []
    for block_num, line in enumerate(lines):
        # Separate on "~"
        block_start, block_end = line.split("~")
        # Now split the coordinates on "," .
        block_start = tuple((int(x) for x in block_start.split(",")))
        block_end = tuple((int(x) for x in block_end.split(",")))
        # Now generate the block range.
        new_brick = Brick(block_num, block_start, block_end)
        print(new_brick)
        bricks.append(new_brick)

    return bricks

def disintegrate(brick: Brick) -> int: # This actually checks if we can remove the brick or not.
    # Loop over each brick which is supported by the current brick.
    for being_supported in brick.supporting():
        assert len(being_supported.is_supported_by()) != 0
        print("being_supported.is_supported_by() == "+str(being_supported.is_supported_by()))
        if len(being_supported.is_supported_by()) == 1: # If that one brick is supported by only one other brick (the current one) then we can NOT remove it, therefore return zero
            return 0
    return 1 # Otherwise we can remove it. Return one

def solve(solve_func, bricks: list) -> int: # This is the actual solve function
    # Go over each brick with the corresponding part function.
    return sum(solve_func(b) for b in bricks)
def part2(bricks: list) -> int:
    return 0 # To be implemented...

def main() -> int:
    bricks = parse_input()
    bricks = drop_bricks(bricks) # Simulate the falling of the bricks. (We need to do this for both parts.)
    if PART == 1:
        res = solve(disintegrate, bricks)
    elif PART == 2:
        res = solve(part2, bricks)
    else:
        print("Invalid part number: "+str(PART))
        exit(1)

    print(res) # Print final solution.
    return 0

if __name__=="__main__":
    exit(main())





```


The reason for why it doesn't work is because I have defined `UP_COORD = 1` and then I use this in the `lowest_point` and `highest_point`. After setting it to 2 instead, it seems to work.

```
<__main__.Brick object at 0x000001B9FF869B50>
<__main__.Brick object at 0x000001B9FF89D4D0>
<__main__.Brick object at 0x000001B9FF89D650>
<__main__.Brick object at 0x000001B9FF89D910>
<__main__.Brick object at 0x000001B9FF89D950>
<__main__.Brick object at 0x000001B9FF89DB10>
<__main__.Brick object at 0x000001B9FF89DC10>
poopoo
lower.above_bricks == {<__main__.Brick object at 0x000001B9FF89D4D0>}
poopoo
lower.above_bricks == {<__main__.Brick object at 0x000001B9FF89D650>, <__main__.Brick object at 0x000001B9FF89D4D0>}
poopoo
lower.above_bricks == {<__main__.Brick object at 0x000001B9FF89D910>}
poopoo
lower.above_bricks == {<__main__.Brick object at 0x000001B9FF89D910>}
poopoo
lower.above_bricks == {<__main__.Brick object at 0x000001B9FF89D910>, <__main__.Brick object at 0x000001B9FF89D950>}
poopoo
lower.above_bricks == {<__main__.Brick object at 0x000001B9FF89D910>, <__main__.Brick object at 0x000001B9FF89D950>}
poopoo
lower.above_bricks == {<__main__.Brick object at 0x000001B9FF89D650>, <__main__.Brick object at 0x000001B9FF89DB10>, <__main__.Brick object at 0x000001B9FF89D4D0>}
poopoo
lower.above_bricks == {<__main__.Brick object at 0x000001B9FF89DB10>}
poopoo
lower.above_bricks == {<__main__.Brick object at 0x000001B9FF89DB10>}
poopoo
lower.above_bricks == {<__main__.Brick object at 0x000001B9FF89D650>, <__main__.Brick object at 0x000001B9FF89DB10>, <__main__.Brick object at 0x000001B9FF89DC10>, <__main__.Brick object at 0x000001B9FF89D4D0>}
poopoo
lower.above_bricks == {<__main__.Brick object at 0x000001B9FF89DC10>}
self.above_bricks == {<__main__.Brick object at 0x000001B9FF89D650>, <__main__.Brick object at 0x000001B9FF89DB10>, <__main__.Brick object at 0x000001B9FF89DC10>, <__main__.Brick object at 0x000001B9FF89D4D0>}
[<__main__.Brick object at 0x000001B9FF89D650>, <__main__.Brick object at 0x000001B9FF89D4D0>]
being_supported.is_supported_by() == [<__main__.Brick object at 0x000001B9FF869B50>]
self.above_bricks == {<__main__.Brick object at 0x000001B9FF89D910>, <__main__.Brick object at 0x000001B9FF89D950>}
[<__main__.Brick object at 0x000001B9FF89D910>, <__main__.Brick object at 0x000001B9FF89D950>]
being_supported.is_supported_by() == [<__main__.Brick object at 0x000001B9FF89D650>, <__main__.Brick object at 0x000001B9FF89D4D0>]
being_supported.is_supported_by() == [<__main__.Brick object at 0x000001B9FF89D650>, <__main__.Brick object at 0x000001B9FF89D4D0>]
self.above_bricks == {<__main__.Brick object at 0x000001B9FF89D910>, <__main__.Brick object at 0x000001B9FF89D950>}
[<__main__.Brick object at 0x000001B9FF89D910>, <__main__.Brick object at 0x000001B9FF89D950>]
being_supported.is_supported_by() == [<__main__.Brick object at 0x000001B9FF89D650>, <__main__.Brick object at 0x000001B9FF89D4D0>]
being_supported.is_supported_by() == [<__main__.Brick object at 0x000001B9FF89D650>, <__main__.Brick object at 0x000001B9FF89D4D0>]
self.above_bricks == {<__main__.Brick object at 0x000001B9FF89DB10>}
[<__main__.Brick object at 0x000001B9FF89DB10>]
being_supported.is_supported_by() == [<__main__.Brick object at 0x000001B9FF89D910>, <__main__.Brick object at 0x000001B9FF89D950>]
self.above_bricks == {<__main__.Brick object at 0x000001B9FF89DB10>}
[<__main__.Brick object at 0x000001B9FF89DB10>]
being_supported.is_supported_by() == [<__main__.Brick object at 0x000001B9FF89D910>, <__main__.Brick object at 0x000001B9FF89D950>]
self.above_bricks == {<__main__.Brick object at 0x000001B9FF89DC10>}
[<__main__.Brick object at 0x000001B9FF89DC10>]
being_supported.is_supported_by() == [<__main__.Brick object at 0x000001B9FF89DB10>]
self.above_bricks == set()
[]
5
```

I am going to try to solve part two without help. I think that doing a recursive function, which checks the bricks recursively.

Let's create that!

Here was my initial attempt:

```
def fall_check_recursive(brick: Brick, cur_count = 0) -> int:
    # This function checks the bricks recursively to find out how many bricks would fall if one is removed.
    # First get the bricks are below the current brick and loop over them.
    bricks_which_we_supported = []
    for b in brick.supporting():
        if len(b.is_supported_by()) == 1: # The brick is supported only by this one brick, so therefore add one to the count and then add it to the list.
            cur_count += 1
            bricks_which_we_supported.append(b) # Loop over this next brick.
    for b in bricks_which_we_supported:
        cur_count += fall_check_recursive(b, cur_count)
    return cur_count
```
and it results in the answer of 10 for the toy input, which is wrong. There must be some error somewhere which causes this error.

Instead of a recursive function, we can actually just make it a while loop. This should simplify debugging.

Tada!

```
def fall_check_new(initial_brick: Brick) -> int:
    # This function checks the bricks recursively to find out how many bricks would fall if one is removed.
    # First get the bricks are below the current brick and loop over them.
    bricks_which_we_supported = []
    bricks = [initial_brick]
    cur_count = 0
    while bricks != []:
        new_bricks = []
        for brick in bricks:
            print("current brick == "+str(brick))
            print("brick.supporting() == "+str(brick.supporting()))
            for b in brick.supporting():
                if len(b.is_supported_by()) == 1: # The brick is supported only by this one brick, so therefore add one to the count and then add it to the list.
                    cur_count += 1
                    new_bricks.append(b) # Loop over this next brick.
        bricks = new_bricks
    return cur_count

```

Now, I think the error is that when checking the bricks, which could fall, we do not account for the fact that if one brick supports two bricks, then those two bricks support one brick, then when checking the very top brick, the `if len(b.is_supported_by()) == 1:` check fails and it doesn't count the top brick as fallen, even though it should, so instead of checking the length of the is_supported_by list, we should make a set of all of the blocks, which fall when removing one block. This way we circumvent the problem.

Here is the new code:

```
def fall_check_new(initial_brick: Brick) -> int:
    # This function checks the bricks recursively to find out how many bricks would fall if one is removed.
    # First get the bricks are below the current brick and loop over them.
    bricks_which_we_supported = []
    bricks = [initial_brick]
    falling_bricks = set([initial_brick])
    cur_count = 0
    while bricks != []:
        new_bricks = []
        for brick in bricks:
            for b in brick.supporting():
                #if len(b.is_supported_by()) == 1: # The brick is supported only by this one brick, so therefore add one to the count and then add it to the list.
                if all(b in falling_bricks for b in b.is_supported_by()): # 
                    cur_count += 1
                    new_bricks.append(b) # Loop over this next brick.
                    falling_bricks.add(b)
        bricks = new_bricks
    return cur_count
```

it now almost works. I debugged for around twenty minutes and realized that it lacks a check for checking if the block we are now processing has already fell or not.

Here is the function with the check added:

```
def fall_check_new(initial_brick: Brick) -> int:
    # This function checks the bricks recursively to find out how many bricks would fall if one is removed.
    # First get the bricks are below the current brick and loop over them.
    bricks_which_we_supported = []
    bricks = [initial_brick]
    falling_bricks = set([initial_brick])
    cur_count = 0
    while bricks != []:
        new_bricks = []
        for brick in bricks:
            for b in brick.supporting():
                if b in falling_bricks: # Do not try to drop a brick many times. Just once.
                    continue
                #if len(b.is_supported_by()) == 1: # The brick is supported only by this one brick, so therefore add one to the count and then add it to the list.
                if all(b in falling_bricks for b in b.is_supported_by()): # 
                    cur_count += 1
                    new_bricks.append(b) # Loop over this next brick.
                    falling_bricks.add(b)
        bricks = new_bricks
    return cur_count
```

now it works for the toy input, but does it work for the actual input? It does! Now let's try to improve performance:

```
         21256843 function calls (21217876 primitive calls) in 4.704 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
   789365    1.526    0.000    2.691    0.000 newblocks.py:54(overlaps)
  7988765    0.720    0.000    0.720    0.000 {built-in method builtins.min}
  3252575    0.578    0.000    0.860    0.000 newblocks.py:30(lowest_point)
  4938774    0.458    0.000    0.458    0.000 {built-in method builtins.max}
     1251    0.427    0.000    1.256    0.001 newblocks.py:115(<listcomp>)
  2368095    0.289    0.000    0.289    0.000 newblocks.py:47(ranges_overlap)
   789365    0.215    0.000    2.906    0.000 newblocks.py:50(is_under)
        1    0.189    0.189    4.469    4.469 newblocks.py:107(drop_bricks)
     1257    0.067    0.000    0.228    0.000 newblocks.py:193(fall_check_new)
   151938    0.033    0.000    0.047    0.000 newblocks.py:27(highest_point)
   101292    0.032    0.000    0.090    0.000 newblocks.py:33(is_level_below)
  31426/1    0.031    0.000    0.069    0.069 copy.py:128(deepcopy)
   170893    0.026    0.000    0.026    0.000 {method 'add' of 'set' objects}
    70360    0.017    0.000    0.028    0.000 {built-in method builtins.all}
   145551    0.011    0.000    0.011    0.000 newblocks.py:207(<genexpr>)
     1240    0.009    0.000    0.054    0.000 newblocks.py:37(<listcomp>)
    70360    0.008    0.000    0.062    0.000 newblocks.py:35(is_supported_by)
     1257    0.008    0.000    0.053    0.000 newblocks.py:43(<listcomp>)
    70858    0.008    0.000    0.061    0.000 newblocks.py:40(supporting)
    89713    0.006    0.000    0.006    0.000 {method 'append' of 'list' objects}
3771/1257    0.006    0.000    0.063    0.000 copy.py:259(_reconstruct)
    66623    0.005    0.000    0.005    0.000 {method 'get' of 'dict' objects}
   5029/1    0.005    0.000    0.069    0.069 copy.py:201(_deepcopy_list)
     1257    0.004    0.000    0.055    0.000 copy.py:227(_deepcopy_dict)
    10057    0.004    0.000    0.005    0.000 copy.py:243(_keep_alive)
    51541    0.003    0.000    0.003    0.000 {built-in method builtins.id}
        1    0.003    0.003    0.006    0.006 newblocks.py:134(parse_input)
     2515    0.002    0.000    0.003    0.000 copyreg.py:113(_slotnames)
     3771    0.002    0.000    0.005    0.000 {method '__reduce_ex__' of 'object' objects}
     7542    0.001    0.000    0.009    0.000 copy.py:264(<genexpr>)
    21369    0.001    0.000    0.001    0.000 copy.py:182(_deepcopy_atomic)
     1257    0.001    0.000    0.001    0.000 newblocks.py:13(__init__)
     1247    0.001    0.000    0.001    0.000 newblocks.py:74(drop)
     7542    0.001    0.000    0.001    0.000 {built-in method builtins.getattr}
     3772    0.001    0.000    0.001    0.000 {built-in method builtins.hasattr}
     1257    0.001    0.000    0.229    0.000 newblocks.py:214(chain_reaction)
     5028    0.001    0.000    0.001    0.000 newblocks.py:141(<genexpr>)
     5028    0.001    0.000    0.001    0.000 newblocks.py:142(<genexpr>)
        1    0.000    0.000    4.704    4.704 newblocks.py:219(main)
     5028    0.000    0.000    0.000    0.000 {built-in method builtins.isinstance}
     3772    0.000    0.000    0.000    0.000 {method 'split' of 'str' objects}
        2    0.000    0.000    0.001    0.001 {method 'sort' of 'list' objects}
     1257    0.000    0.000    0.001    0.000 newblocks.py:24(on_ground)
     1257    0.000    0.000    0.001    0.000 copyreg.py:104(__newobj__)
     3771    0.000    0.000    0.000    0.000 {built-in method builtins.issubclass}
     2515    0.000    0.000    0.000    0.000 {method 'get' of 'mappingproxy' objects}
        1    0.000    0.000    0.229    0.229 newblocks.py:159(solve)
     1257    0.000    0.000    0.001    0.000 newblocks.py:110(<lambda>)
     1257    0.000    0.000    0.000    0.000 {method 'update' of 'dict' objects}
     1257    0.000    0.000    0.001    0.000 newblocks.py:131(<lambda>)
     1257    0.000    0.000    0.000    0.000 {built-in method __new__ of type object at 0x00007FFAA853DF90}
        1    0.000    0.000    0.000    0.000 {built-in method builtins.print}
     1257    0.000    0.000    0.000    0.000 {method 'items' of 'dict' objects}
        1    0.000    0.000    0.000    0.000 {method 'read' of '_io.TextIOWrapper' objects}
        1    0.000    0.000    0.000    0.000 {built-in method _codecs.charmap_decode}
        1    0.000    0.000    4.704    4.704 newblocks.py:1(<module>)
        1    0.000    0.000    0.000    0.000 {built-in method builtins.__build_class__}
        1    0.000    0.000    0.000    0.000 <frozen _sitebuiltins>:19(__call__)
        1    0.000    0.000    0.000    0.000 {method 'close' of '_io.TextIOWrapper' objects}
        1    0.000    0.000    4.704    4.704 {built-in method builtins.exec}
        1    0.000    0.000    0.000    0.000 cp1252.py:22(decode)
        1    0.000    0.000    0.000    0.000 newblocks.py:12(Brick)
        1    0.000    0.000    0.000    0.000 {method 'disable' of '_lsprof.Profiler' objects}
```

Cprofile output looks quite interesting. One thing, is that we can memoize lowest and highest points. Now, when we drop the bricks, we can call an "update" function, which updates the new value for the lowest and highest points.

Also we can do the same type of memoization for the range stuff, because after dropping the blocks, we know that the ranges no longer change, therefore we can just store them. Also we don't even need to compute the z range, because it is completely unused. The only use for the `overlaps` function is inside the `is_under` function and in that function we just discard the result of the z overlap:

```
    def is_under(self, other) -> bool: # Check for x and y overlap.
        x_overlap, y_overlap, _ = self.overlaps(other)
        return x_overlap and y_overlap
```

So therefore we do not even need to check for z overlap. Let's implement these changes!

After implementing the highest and lowest point memoization, we now have this code:

```
76511
         17936189 function calls (17892194 primitive calls) in 3.641 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
   789370    1.406    0.000    2.515    0.000 faster_blocks.py:66(overlaps)
  4791876    0.424    0.000    0.424    0.000 {built-in method builtins.max}
  4736220    0.421    0.000    0.421    0.000 {built-in method builtins.min}
     1251    0.335    0.000    0.490    0.000 faster_blocks.py:127(<listcomp>)
  2368110    0.271    0.000    0.271    0.000 faster_blocks.py:59(ranges_overlap)
   789370    0.203    0.000    2.718    0.000 faster_blocks.py:62(is_under)
  3252576    0.160    0.000    0.160    0.000 faster_blocks.py:41(lowest_point)
        1    0.157    0.157    3.459    3.459 faster_blocks.py:119(drop_bricks)
     1257    0.070    0.000    0.175    0.000 faster_blocks.py:207(fall_check_new)
  36454/1    0.031    0.000    0.067    0.067 copy.py:128(deepcopy)
   101292    0.025    0.000    0.036    0.000 faster_blocks.py:45(is_level_below)
   177803    0.020    0.000    0.020    0.000 {method 'add' of 'set' objects}
    77090    0.018    0.000    0.030    0.000 {built-in method builtins.all}
   159973    0.012    0.000    0.012    0.000 faster_blocks.py:221(<genexpr>)
   151938    0.010    0.000    0.010    0.000 faster_blocks.py:37(highest_point)
    77768    0.008    0.000    0.033    0.000 faster_blocks.py:52(supporting)
    77090    0.008    0.000    0.032    0.000 faster_blocks.py:47(is_supported_by)
     1240    0.006    0.000    0.024    0.000 faster_blocks.py:49(<listcomp>)
     1257    0.006    0.000    0.025    0.000 faster_blocks.py:55(<listcomp>)
    96623    0.006    0.000    0.006    0.000 {method 'append' of 'list' objects}
3771/1257    0.005    0.000    0.062    0.000 copy.py:259(_reconstruct)
     1257    0.005    0.000    0.055    0.000 copy.py:227(_deepcopy_dict)
    76679    0.005    0.000    0.005    0.000 {method 'get' of 'dict' objects}
   5029/1    0.004    0.000    0.067    0.067 copy.py:201(_deepcopy_list)
    10057    0.003    0.000    0.004    0.000 copy.py:243(_keep_alive)
    56569    0.003    0.000    0.003    0.000 {built-in method builtins.id}
        1    0.003    0.003    0.007    0.007 faster_blocks.py:148(parse_input)
     2515    0.002    0.000    0.003    0.000 copyreg.py:113(_slotnames)
     3771    0.002    0.000    0.004    0.000 {method '__reduce_ex__' of 'object' objects}
    26397    0.001    0.000    0.001    0.000 copy.py:182(_deepcopy_atomic)
     7542    0.001    0.000    0.008    0.000 copy.py:264(<genexpr>)
     1257    0.001    0.000    0.002    0.000 faster_blocks.py:13(__init__)
     2505    0.001    0.000    0.001    0.000 faster_blocks.py:28(update_highest)
     3772    0.001    0.000    0.001    0.000 {built-in method builtins.hasattr}
     7542    0.001    0.000    0.001    0.000 {built-in method builtins.getattr}
     5028    0.001    0.000    0.001    0.000 faster_blocks.py:155(<genexpr>)
     1257    0.001    0.000    0.175    0.000 faster_blocks.py:228(chain_reaction)
     5028    0.001    0.000    0.001    0.000 faster_blocks.py:156(<genexpr>)
     2505    0.001    0.000    0.001    0.000 faster_blocks.py:31(update_lowest)
     1248    0.000    0.000    0.000    0.000 faster_blocks.py:86(drop)
     3772    0.000    0.000    0.000    0.000 {method 'split' of 'str' objects}
     5028    0.000    0.000    0.000    0.000 {built-in method builtins.isinstance}
     1257    0.000    0.000    0.001    0.000 copyreg.py:104(__newobj__)
        2    0.000    0.000    0.001    0.000 {method 'sort' of 'list' objects}
     1257    0.000    0.000    0.000    0.000 faster_blocks.py:34(on_ground)
     3771    0.000    0.000    0.000    0.000 {built-in method builtins.issubclass}
     2515    0.000    0.000    0.000    0.000 {method 'get' of 'mappingproxy' objects}
        1    0.000    0.000    0.176    0.176 faster_blocks.py:173(solve)
     1257    0.000    0.000    0.000    0.000 {method 'update' of 'dict' objects}
        1    0.000    0.000    3.641    3.641 faster_blocks.py:233(main)
     1257    0.000    0.000    0.000    0.000 faster_blocks.py:145(<lambda>)
     1257    0.000    0.000    0.000    0.000 faster_blocks.py:122(<lambda>)
     1257    0.000    0.000    0.000    0.000 {built-in method __new__ of type object at 0x00007FFAA853DF90}
        1    0.000    0.000    0.000    0.000 {built-in method builtins.print}
     1257    0.000    0.000    0.000    0.000 {method 'items' of 'dict' objects}
        1    0.000    0.000    0.000    0.000 {method 'read' of '_io.TextIOWrapper' objects}
        1    0.000    0.000    3.641    3.641 faster_blocks.py:1(<module>)
        1    0.000    0.000    0.000    0.000 {built-in method _codecs.charmap_decode}
        1    0.000    0.000    0.000    0.000 {built-in method builtins.__build_class__}
        1    0.000    0.000    0.000    0.000 <frozen _sitebuiltins>:19(__call__)
        1    0.000    0.000    0.000    0.000 {method 'close' of '_io.TextIOWrapper' objects}
        1    0.000    0.000    3.641    3.641 {built-in method builtins.exec}
        1    0.000    0.000    0.000    0.000 faster_blocks.py:12(Brick)
        1    0.000    0.000    0.000    0.000 cp1252.py:22(decode)
        1    0.000    0.000    0.000    0.000 {method 'disable' of '_lsprof.Profiler' objects}
```

So it is faster!

Now let's get rid of the z range calculation, which is basically just dead weight.

Here is the current cProfile output:

```
         13989327 function calls (13945332 primitive calls) in 15.193 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
   789370    4.729    0.000    8.658    0.000 faster_blocks.py:66(overlaps)
     1251    2.408    0.002    3.315    0.003 faster_blocks.py:124(<listcomp>)
  3157480    1.482    0.000    1.482    0.000 {built-in method builtins.min}
  3213136    1.454    0.000    1.454    0.000 {built-in method builtins.max}
  1578740    1.031    0.000    1.031    0.000 faster_blocks.py:59(ranges_overlap)
        1    1.010    1.010   14.333   14.333 faster_blocks.py:116(drop_bricks)
  3252576    0.935    0.000    0.935    0.000 faster_blocks.py:41(lowest_point)
   789370    0.921    0.000    9.580    0.000 faster_blocks.py:62(is_under)
     1257    0.299    0.000    0.806    0.001 faster_blocks.py:204(fall_check_new)
   101292    0.130    0.000    0.183    0.000 faster_blocks.py:45(is_level_below)
  36454/1    0.119    0.000    0.314    0.314 copy.py:118(deepcopy)
    77090    0.088    0.000    0.127    0.000 {built-in method builtins.all}
   177803    0.057    0.000    0.057    0.000 {method 'add' of 'set' objects}
   151938    0.045    0.000    0.045    0.000 faster_blocks.py:37(highest_point)
    77090    0.044    0.000    0.170    0.000 faster_blocks.py:47(is_supported_by)
    77768    0.042    0.000    0.168    0.000 faster_blocks.py:52(supporting)
   159961    0.039    0.000    0.039    0.000 faster_blocks.py:218(<genexpr>)
    56569    0.038    0.000    0.038    0.000 {built-in method builtins.id}
     1240    0.036    0.000    0.126    0.000 faster_blocks.py:49(<listcomp>)
     1257    0.032    0.000    0.126    0.000 faster_blocks.py:55(<listcomp>)
    96623    0.032    0.000    0.032    0.000 {method 'append' of 'list' objects}
3771/1257    0.026    0.000    0.293    0.000 copy.py:247(_reconstruct)
     1257    0.022    0.000    0.263    0.000 copy.py:217(_deepcopy_dict)
        1    0.018    0.018    0.018    0.018 {method 'read' of '_io.TextIOWrapper' objects}
    76679    0.018    0.000    0.018    0.000 {method 'get' of 'dict' objects}
   5029/1    0.016    0.000    0.314    0.314 copy.py:191(_deepcopy_list)
     3772    0.015    0.000    0.015    0.000 {built-in method builtins.hasattr}
     2515    0.013    0.000    0.028    0.000 copyreg.py:107(_slotnames)
    10057    0.013    0.000    0.017    0.000 copy.py:231(_keep_alive)
     3771    0.012    0.000    0.040    0.000 {method '__reduce_ex__' of 'object' objects}
        1    0.012    0.012    0.050    0.050 faster_blocks.py:145(parse_input)

```


the reason why the time is slower, is because I am currently fuzzing in the meantime.

Because the bricks only fall downwards, we also can just make a dictionary where we store the under stuff, also because the z value is completely irrelevant, we should only store the x and y coordinates in the dictionary.

Here is the output after doing this optimization:

```

         9896834 function calls (9849068 primitive calls) in 7.578 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
   789370    1.786    0.000    4.539    0.000 faster_blocks.py:63(is_under)
   415612    1.442    0.000    2.753    0.000 faster_blocks.py:77(overlaps)
     1251    1.160    0.001    1.665    0.001 faster_blocks.py:135(<listcomp>)
        1    0.520    0.520    7.098    7.098 faster_blocks.py:127(drop_bricks)
  3252576    0.519    0.000    0.519    0.000 faster_blocks.py:42(lowest_point)
  1662448    0.501    0.000    0.501    0.000 {built-in method builtins.min}
  1718104    0.458    0.000    0.458    0.000 {built-in method builtins.max}
   831224    0.378    0.000    0.378    0.000 faster_blocks.py:60(ranges_overlap)
     1257    0.186    0.000    0.440    0.000 faster_blocks.py:215(fall_check_new)
  38968/1    0.131    0.000    0.308    0.308 copy.py:118(deepcopy)
   101292    0.061    0.000    0.085    0.000 faster_blocks.py:46(is_level_below)
    77090    0.044    0.000    0.069    0.000 {built-in method builtins.all}
   177803    0.031    0.000    0.031    0.000 {method 'add' of 'set' objects}
2514/1257    0.029    0.000    0.253    0.000 copy.py:217(_deepcopy_dict)
3771/1257    0.025    0.000    0.284    0.000 copy.py:247(_reconstruct)
    77090    0.025    0.000    0.085    0.000 faster_blocks.py:48(is_supported_by)
    77768    0.025    0.000    0.083    0.000 faster_blocks.py:53(supporting)
   159951    0.025    0.000    0.025    0.000 faster_blocks.py:229(<genexpr>)
   151938    0.021    0.000    0.021    0.000 faster_blocks.py:38(highest_point)
    81707    0.018    0.000    0.018    0.000 {method 'get' of 'dict' objects}
   5029/1    0.018    0.000    0.308    0.308 copy.py:191(_deepcopy_list)
    61597    0.016    0.000    0.016    0.000 {built-in method builtins.id}
     1240    0.016    0.000    0.059    0.000 faster_blocks.py:50(<listcomp>)
     2515    0.016    0.000    0.018    0.000 copyreg.py:107(_slotnames)
     1257    0.016    0.000    0.058    0.000 faster_blocks.py:56(<listcomp>)
    11314    0.015    0.000    0.020    0.000 copy.py:231(_keep_alive)
        1    0.015    0.015    0.037    0.037 faster_blocks.py:156(parse_input)


```

Here is the actual optimization:

```

    def is_under(self, other) -> bool: # Check for x and y overlap.
        x1, y1, _ = self.pos1
        x2, y2, _ = self.pos2

        x3, y3, _ = other.pos1
        x4, y4, _ = other.pos2
        dict_input = tuple((x1,y1,x2,y2,x3,y3,x4,y4))
        if dict_input not in self.under_dict:
            x_overlap, y_overlap = self.overlaps(other)
            res = x_overlap and y_overlap
            self.under_dict[dict_input] = res
            return res
        return self.under_dict[dict_input]

```

and it works!

Ok, so I think this is good enough for now. Let's go on to the next challenge!












