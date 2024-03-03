
# Implementing falling sand.

Ok, so I got inspired by this here: https://www.youtube.com/watch?v=L4u7Zy_b868 which describes the programming of a falling sand simulation. I decided to program this myself.

## The beginnings

I am going to make an Object Oriented solution to this problem and I am going to make an object which has all of the sand particles, positions etc and a method to step forward.

Here is the initial skeleton:

```

class SandSim:
	
	def __init__(self, sand_particles: list, width: int, height: int) -> None:
		# Constructor.
		self.sand_particles = sand_particles
		self.width = width
		self.height = height

	def update(self) -> None:
		return # just a stub for now.

	def render(self) -> None:
		return # just a stub for now.

```

Here is my update function. It just simply checks the points which are below the point which we are currently checking. Then it also checks if we are on the ground...

```
class SandSim:
	
	def __init__(self, sand_particles: list, width: int, height: int) -> None:
		# Constructor.
		self.sand_particles = set(sand_particles)
		self.width = width
		self.height = height

	def new_pos(self, point) -> None: # This returns the new position of a point.
		if point[1] == 0: # Check if the sand particle is on the ground
			return point
		# Now go over the three points which are below this one.
		below_points = [(point[0]-1, point[1]-1), (point[0], point[1]-1), (point[0]+1, point[1]-1)]
		are_below_list = [p in self.sand_particles for p in below_points]
		if not are_below_list[1]:
			# Return the point which is straight below.
			return below_points[1]
		if not are_below_list[0]: # Left point is open, therefore return that.
			return below_points[0]
		if not are_below_list[2]: # Left point is open, therefore return that.
			return below_points[2]

		# No need to check. Assumed.
		#if all(are_below_list): # All three points below are occupied, therefore do not move point.
		return point

	def update(self) -> None:
		new_particle_set = set()
		# Loop over the current particles and see if they can be moved.
		for p in self.sand_particles:
			new_particle_set.add(self.new_pos(p))
		self.sand_particles = new_particle_set
		return
		#return # just a stub for now.

	def render(self) -> None:
		return # just a stub for now.
```

## Fucking around with matplotlib

Ok, so I am now trying to render the bullshit, but because matplotlib is fucking me over, we need to do some debugging.

Here is my current code:

```

import matplotlib.pyplot as plt


# Used in rendering
import numpy as np


class SandSim:
	
	def __init__(self, sand_particles: list, width: int, height: int) -> None:
		# Constructor.
		self.sand_particles = set(sand_particles)
		self.width = width
		self.height = height
		#self.figure = plt.figure()
		#self.image = plt.imshow(np.zeros((self.width, self.height)), cmap='gray')

		plt.figure()

	def new_pos(self, point) -> None: # This returns the new position of a point.
		if point[1] == 0: # Check if the sand particle is on the ground
			return point
		# Now go over the three points which are below this one.
		below_points = [(point[0]-1, point[1]-1), (point[0], point[1]-1), (point[0]+1, point[1]-1)]
		are_below_list = [p in self.sand_particles for p in below_points]
		if not are_below_list[1]:
			# Return the point which is straight below.
			return below_points[1]
		if not are_below_list[0]: # Left point is open, therefore return that.
			return below_points[0]
		if not are_below_list[2]: # Left point is open, therefore return that.
			return below_points[2]

		# No need to check. Assumed.
		#if all(are_below_list): # All three points below are occupied, therefore do not move point.
		return point

	def update(self) -> None:
		new_particle_set = set()
		# Loop over the current particles and see if they can be moved.
		for p in self.sand_particles:
			new_particle_set.add(self.new_pos(p))
		self.sand_particles = new_particle_set
		return
		#return # just a stub for now.

	def to_bool_mat(self): # Converts the current points to a boolean matrix.
		mat = [[0 for _ in range(self.width)] for _ in range(self.height)]
		for p in self.sand_particles:
			mat[p[1]][p[0]] = 1
		# Reverse list, because otherwise positive y direction is down.
		mat = list(reversed(mat))
		return mat

	def render(self) -> None:
		# First convert the current point list to a grayscale matrix
		render_mat = self.to_bool_mat()
		
		#plt.show()
		#self.figure.show(render_mat, cmap="gray")


		plt.imshow(render_mat, cmap="gray")
		plt.show()


		#return # just a stub for now.


```

now, when I call render , it waits until I close the window before it shows the next step.

Ok, so I got it to work. Here is the current code:

```
	def render(self) -> None:
		# First convert the current point list to a grayscale matrix
		render_mat = self.to_bool_mat()
		
		#plt.show()
		#self.figure.show(render_mat, cmap="gray")


		plt.imshow(render_mat, cmap="gray")
		plt.show()
		plt.pause(0.01)
		plt.clf()
```

## Making it faster

Cprofile etc...

Ok, so let's add a check which checks the height of the sand particle and then update the "min height" where a sand particle settlement may happen.

Instead of creating a new set of points on every cycle, we could just modify the points in place. Sure it causes problems, because we are modifying it and comparing against the same set at the same time, but I don't think it will be that big of a problem.

Yeah. That sped up things by A LOT! Now the majority of time is actually spent in the render function in matplotlib. We really can't do anything about that.

In addition, now the sand particles don't just magically disappear.

## Implementing gravity

Ok, so currently the sand particles just fall at constant rate. I am just going to skip this shit for now. Maybe I will come back to this later on and see if I can implement this shit.


You can take a closer look at my source code here: https://github.com/personnumber3377/pythonfallingsand

Another idea is to create static spots, (basically static particles which do not move.)































