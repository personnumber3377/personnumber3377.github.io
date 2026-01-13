# Day 21

## Part 1

Ok so this is quite an interesting puzzle, because we need to get all of the places where we could be after x steps, not the total number of places which we can visit.

Let's get through a simple case, a case where there are no obstacles. I think there is a relationship between the area of all of the possible places which we can visit and the amount of all possible spaces.


Here are all of the positions which the thing could visit after 2 steps.

{% raw %}
```
....................
....................
....................
....................
....................
....................
....................
....................
..........#.........
.........###........
........#####.......
.........###........
..........#.........
....................
....................
....................
....................
....................
....................
....................
```
{% endraw %}

Now, all of the final positions would be these:

{% raw %}
```
....................
....................
....................
....................
....................
....................
....................
....................
..........#.........
.........#.#........
........#.#.#.......
.........#.#........
..........#.........
....................
....................
....................
....................
....................
....................
....................
```
{% endraw %}

The total visited area is 12, whileas the amount of distinct final positions is 9. Actually, I think that just doing it the "naive" way and just simulating all of the positions is the best performance wise. I think that keeping track of all of the visited spaces and then trying to come up with a formula for all of them is actually slower and more memory intensive.


Here was my initial attempt at part 1:

{% raw %}
```
import sys

LOOP_COUNT = 64

def get_neig(pos: tuple, matrix: list) -> list:
    possible_neighbours = [tuple((pos[0]-1, pos[1])), tuple((pos[0]+1, pos[1])), tuple((pos[0], pos[1]-1)), tuple((pos[0], pos[1]+1))] # Non-diagonal neighbours only.
    # Now check the validity of these spots
    for pos in possible_neighbours:
        if pos[0] < 0 or pos[1] < 0:
            continue # Do not yield
        if pos[0] >= len(matrix[0]) or pos[1] >= len(matrix):
            continue # Do not yield
        yield pos # Passed bounds checks.

def parse_input() -> list:
    # Parses stdin input
    lines = sys.stdin.read().split("\n")
    out = []
    for y, line in enumerate(lines):
        cur_line = []
        for x, char in enumerate(line):
            if char == "#": # "#" means wall
                cur_line.append(1)
            elif char == "S": # Start
                start = tuple((x,y))
                cur_line.append(0)
            else: # Empty space
                cur_line.append(0)
        out.append(cur_line)
    return out, start

def main() -> int:
    matrix, start = parse_input()
    new_positions = set([start]) # Initialize with the one position
    for i in range(LOOP_COUNT):
        # Main loop.
        new_new = set()
        for pos in new_positions: # optimization. no need to loop over positions which aren't new.
            neighbours = list(get_neig(pos, matrix)) # Get new spots.
            for neig in neighbours:
                assert isinstance(neig, tuple)
                if matrix[neig[1]][neig[0]] == "#": # Wall
                    continue
                #if neig not in visited: # No need to check. the "add" method doesn't do anything if element already is in set.
                new_new.add(neig)
        new_positions = new_new
    return len(new_positions)

if __name__=="__main__":
    exit(main())
```
{% endraw %}

There was a bug in it. The bug is on this line:

{% raw %}
```
                if matrix[neig[1]][neig[0]] == "#": # Wall
```
{% endraw %}

See, I replaced the "#" characters with the integer 1 in the parse function, so this check will never pass. This is the correct version:

{% raw %}
```
                if matrix[neig[1]][neig[0]] == 1: # Wall
```
{% endraw %}

Ok, so for part 2 I think we need the optimization which I talked about. See, for all of the places which we have actually visited, we know that those places alternate.




