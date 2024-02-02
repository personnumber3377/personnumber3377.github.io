
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















