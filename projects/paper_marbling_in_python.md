
# Implementing the Paper Marbling Algorithm in python

Hi! Inspired by another coding train video here: https://www.youtube.com/watch?v=p7IGZTjC008&t=4s , I decided to try to implement it myself in python and see what happens. Ok, so it seems that paper marbling is an art-style. It is described here in detail in a wikipedia article: https://en.wikipedia.org/wiki/Paper_marbling . I think we are going to come across some fluid dynamics and shit like that soon enough...

## Understanding the marbling process on a high level

Ok, so let's get a feel for what we are about to do before jumping head first into coding...

Ok, so apparently there exists a mathematical solution, which doesn't involve any fluid dynamics, but approximates it good enough to look similar. This is also computationally less expensive than a full-blown fluid simulation.

Let's create the inkdrop object in a file called inkdrop.py .

Here is my very primitive start of the inkdrop object:

```

class InkDrop:

	def __init__(self, r, x0, y0) -> None: # Constructor...
		self.r = r
		self.x0 = x0
		self.y0 = y0
		return

	def update(self) -> None: # Update physics maybe... Stub for now.
		return



```

## Implementing the algorithm...

Ok, so let's say we drop an Inkdrop object on top of another inkdrop object. We want this new inkdrop to avoid the previously placed and sort-of "go around" it. Here is some of the mathematics, which describe this: https://people.csail.mit.edu/jaffer/Marbling/Mathematics and here is the very original "Mathematical Marbling" paper http://www.cad.zju.edu.cn/home/jin/cga2012/mmarbling.pdf .

First of all, we need to modify our inkdrop class to have a list of points which lie on the circumference, because we need those for the computation of the way how the inkrops "avoid" each other.

Here is the new modified inkdrop object:

```



CIRCLE_RESOLUTION = 10 # How many "circumference points" there are for each circle.
SCALE_FACTOR = 100 # Scale the coordinates by this much when drawing..
import math

class InkDrop:

	def __init__(self, r, x0, y0) -> None: # Constructor...
		self.r = r
		self.x0 = x0
		self.y0 = y0
		self.vertices = self.construct_vertices() # These are the very initial points on the circumference
		return

	def construct_vertices(self) -> list: # Returns a list of tuples each of which describes an x,y point on the circumference of the circle.
		cur_angle = 0.0 # Initial calculation angle
		angle_step = 2*math.pi/(CIRCLE_RESOLUTION) # How many radians to step forward on each step
		out = []
		for i in range(CIRCLE_RESOLUTION):
			# Add point.
			dx = math.cos(cur_angle) * self.r
			dy = math.sin(cur_angle) * self.r
			new_point = tuple((self.x0+dx, self.y0+dy))
			out.append(new_point)
			cur_angle += angle_step # Update the angle.
		return out

	def draw(self, t) -> None: # Render the shape. "t" is the turtle object we use to draw with.
		# Go through all of the vertices in order.
		t.penup()
		t.goto(self.vertices[0][0]*SCALE_FACTOR, self.vertices[0][1]*SCALE_FACTOR) # Go to the first vertex
		t.pendown()
		for vert in self.vertices[1:]: # Skip over first vertex here, because we already are there.
			t.goto(vert[0]*SCALE_FACTOR, vert[1]*SCALE_FACTOR)
		# Go back to the first vertex to close the loop.
		t.goto(self.vertices[0][0]*SCALE_FACTOR, self.vertices[0][1]*SCALE_FACTOR)
		t.penup() # Stop drawing...
		return


	def update(self) -> None: # Update physics maybe... Stub for now.
		return






```

let's test it out!

Here is the contents of my main.py file (for now) ... :

```



import turtle
from inkdrop import *
import time

def show_circle() -> None:

	t = turtle.Turtle() # Create a new turtle object.
	# __init__(self, r, x0, y0)
	drop = InkDrop(3, 0, 0) # Circle at (0,0) with radius 3.
	# Render the drop.

	drop.draw(t)

	time.sleep(5) # Wait for a bit for the user to see the result...

	return


if __name__=="__main__":
	# Main program entry point.

	show_circle()

	exit(0)


```

and it seems to work! Good!

## Handling of the new circles.

Let's create a loop, which just shows all of the circles over and over again... and then let's create an event handler which adds a new circle when the canvas gets clicked...


After a bit of fiddling around, I now have this as my main function:

```


import turtle
from inkdrop import *
import time


CIRC_RADIUS = 0.5 # Radius of each circle when added.

new_circle = False
new_x = None
new_y = None


def new_drop(x, y) -> None: # Will be called when the canvas gets clicked. Should create a new drop at x,y
	global drops # We need to modify this global variable, therefore we need this here.
	global new_x
	global new_y
	global new_circle
	print("Clicked at "+str(x)+", "+str(y)+" .")

	# When drawing, we scale by SCALE_FACTOR , therefore we need to divide by that here.

	new_x = x/SCALE_FACTOR
	new_y = y/SCALE_FACTOR
	new_circle = True
	return




def main_loop() -> None:
	global new_circle # We modify this.

	t = turtle.Turtle() # Create a new turtle object.
	# __init__(self, r, x0, y0)

	#t.tracer(0,0)
	turtle.tracer(0,0)
	#drop = InkDrop(3, 0, 0) # Circle at (0,0) with radius 3.
	# Render the drop.

	#drop.draw(t)

	turtle.onscreenclick(new_drop) # Setup click handlers
	drops = [] # This is our main inkdrops list. We will use this to store all of our drop objects...
	t.dot()
	while True: # Main program loop

		if not new_circle:
			# Just show each circle. This is because we haven't added a new circle.
			for drop in drops:
				drop.draw(t)
			#print("Drew all dots!")

		else:
			# Handle new circle.
			print("new_circle == True")

			new_circ = InkDrop(CIRC_RADIUS, new_x, new_y)
			drops.append(new_circ)
			new_circle = False
		time.sleep(0.01) # No need to draw faster than that

		turtle.update()

		t.clear()

	#time.sleep(5) # Wait for a bit for the user to see the result...

	return


if __name__=="__main__":
	# Main program entry point.

	main_loop()

	exit(0)


```

and it seems to work fine.

## Applying the formula for the new circles.

Ok, so now instead of automatically just putting the circle into the list, we need to modify the new circle with the pre-existing circles, such that the new circle avoids the pre-existing circles.

I actually got it the wrong way around, the new circle which we are adding is supposed to be an actual circle. It is the other circles which need to be modified to accommodate the new circle.

Let's program a method for our inkdrop object which updates the vertices with the given formula.

Here:

```

	def marble(self, other) -> None: # This methods updates the vertices of this drop object using the other circle object.
		for i in range(len(self.vertices)): # Loop over each vertex.
			other_center = tuple((other.x0, other.y0))
			other_r = other.r
			#p_minus_c = tuple((self.x0 - other_center[0], self.y0 - other_center[1]))
			p_minus_c = tuple((self.vertices[i][0] - other_center[0], self.vertices[i][1] - other_center[1])) # self.vertices
			magnitude = math.sqrt(p_minus_c[0]**2 + p_minus_c[1]**2)
			root_val = math.sqrt(1 + (other_r * other_r) / (magnitude * magnitude))
			final_vec = tuple((other_center[0] + root_val * p_minus_c[0], other_center[1] + root_val * p_minus_c[1]))
			self.vertices[i] = final_vec
		return


```

That seems to do the trick!

## Implementing line strokes

Ok, so that is quite good. I am thinking that we should also implement some other transformations while we are at it.

The lines called "tine" lines are described in the paper in section 3.1.2 . It defines another transformation function, which draws these "tine" lines.

To implement tinge lines, we first need a way to get user defined lines. I am going to use the "t" keyboard key to signify a tine line ("t" as in "tine") . The line starts from where the mouse position, and then ends at the place where you release the t key.

Here is my current code (it actually works with the "a" key):

```


import turtle
from inkdrop import *
import time


CIRC_RADIUS = 0.5 # Radius of each circle when added.

new_circle = False
new_x = None
new_y = None

# These will be used in the creation of the tine lines when the user presses up.

p0 = None
p1 = None
new_tine = False


class WatchedKey:
	def __init__(self, key):
		self.key = key
		self.down = False
		turtle.onkeypress(self.press, key)
		turtle.onkeyrelease(self.release, key)

	def press(self):
		self.down = True

	def release(self):
		self.down = False



a_key = WatchedKey("a")

def new_drop(x, y) -> None: # Will be called when the canvas gets clicked. Should create a new drop at x,y
	global drops # We need to modify this global variable, therefore we need this here.
	global new_x
	global new_y
	global new_circle
	global a_key
	global p0
	global p1
	global new_tine

	print("Clicked at "+str(x)+", "+str(y)+" .")

	# Check if we are pressing "a" at the same time, if yes, then we have a tine.
	if a_key.down:
		print("Tine press!!!!!!!!!!!!")
		# Tine key press.
		if not p0: # assign p0 and return
			p0 = tuple((x/SCALE_FACTOR, y/SCALE_FACTOR))
			return
		elif not p1:
			p1 = tuple((x/SCALE_FACTOR, y/SCALE_FACTOR))
			# We should have p0
			assert p0 != None
			new_tine = True # Message the main loop about a new tine.

		return



	# When drawing, we scale by SCALE_FACTOR , therefore we need to divide by that here.

	new_x = x/SCALE_FACTOR
	new_y = y/SCALE_FACTOR
	new_circle = True
	return

def process_tine(drops, p0, p1) -> None: # This applies the tine transformation to each of the drops.

	return # Just a stub for now.


def main_loop() -> None:
	global new_circle # We modify this.
	# These two are required for the tine lines
	global p0
	global p1
	global new_tine

	t = turtle.Turtle() # Create a new turtle object.
	# __init__(self, r, x0, y0)

	#t.tracer(0,0)
	turtle.tracer(0,0)
	#drop = InkDrop(3, 0, 0) # Circle at (0,0) with radius 3.
	# Render the drop.

	#drop.draw(t)



	turtle.onscreenclick(new_drop) # Setup click handlers
	#turtle.onkey(new_tine, "Up")
	turtle.listen()
	drops = [] # This is our main inkdrops list. We will use this to store all of our drop objects...
	#t.dot()
	while True: # Main program loop

		if not new_circle:
			# Just show each circle. This is because we haven't added a new circle.
			for drop in drops:
				drop.draw(t)
			#print("Drew all dots!")

		else:
			# Handle new circle.
			#print("new_circle == True")

			new_circ = InkDrop(CIRC_RADIUS, new_x, new_y)
			# Marble every other drop, before adding the new drop to the list.
			for drop in drops:
				drop.marble(new_circ)

			drops.append(new_circ)
			new_circle = False

		if new_tine: # We have a new tine.
			#print("New tine line!")
			#print("p0 == "+str(p0))
			#print("p1 == "+str(p1))
			#p0 =

			# Now process the tine line.

			process_tine(drops, p0, p1)

			new_tine = False
			p0 = None
			p1 = None

		time.sleep(0.01) # No need to draw faster than that

		turtle.update()

		t.clear()

	#time.sleep(5) # Wait for a bit for the user to see the result...

	return


if __name__=="__main__":
	# Main program entry point.

	main_loop()

	exit(0)


```

Now let's implement the process_tine function!

## Implementing the tine algorithm (finally)

Ok, so what do we need for the formula?

I think we need these:

```

	def tine(self, a, l, A, M) -> None: # This method applies the tine line transformation to this ink drop
		# "a" and "l" are both user defined parameters.

		# These are calculated from the mouse clicks:
		# A is the point on the line.
		# M is the unit vector in the direction of the line.

		return # Just a stub for now.


```

Ok, so let's craft these arguments.

Maybe something like this????

```

def process_tine(drops, p0, p1) -> None: # This applies the tine transformation to each of the drops.

	#return # Just a stub for now.
	A = p0 # Just set A to the first point.
	p0_to_p1 = tuple((-p0[0]+p1[0], -p0[1]+p1[1]))
	# Divide by magnitude to get unit vec.
	mag = math.sqrt(p0_to_p1[0]**2 + p0_to_p1[1]**2) # Magnitude of the vector...
	# Now divide...
	unit_vec = tuple((p0_to_p1[0]/mag, p0_to_p1[1]/mag))
	M = unit_vec

	# Let's set alpha and lambda to just some constants.
	a = 0.1 # alpha
	l = 0.1 # lambda
	# def tine(self, a, l, A, M) -> None:
	# Now call tine() on each of the drop objects.
	for drop in drops:
		drop.tine(a, l, A, M)
	return

```

now let's code the method for the ink drop object:

```


	def tine(self, a, l, A, M) -> None: # This method applies the tine line transformation to this ink drop
		# "a" and "l" are both user defined parameters.

		# These are calculated from the mouse clicks:
		# A is the point on the line.
		# M is the unit vector in the direction of the line.

		#return # Just a stub for now.

		# "N is a unit vector perpendicular to L"

		# Let's calculate value of N

		# perpendicular

		N = perpendicular(M) # M is a unit vector in the direction of the line, so therefore we can just call "perpendicular" on it.

		for i in range(len(self.vertices)): # Loop through all points.
			P = self.vertices[i]
			d = calc_d(P, A, N)
			scalar_frac = (a * l) / (d + l)
			thing = tuple((M[0]*scalar_frac, M[1]*scalar_frac))
			self.vertices[i] = tuple((self.vertices[i][0] + thing[0], self.vertices[i][1] + thing[1]))

		return



def perpendicular(a):
	#b = np.empty_like(a)
	b = [0.0, 0.0]
	b[0] = -a[1]
	b[1] = a[0]
	return tuple(b)



```

and it seems to work okay. One issue with this, is that it also moves the entire inkdrop in addition to drawing a streak through it, but maybe that is just a feature and not a bug maybe???? idk..

## Final thoughts

Okay, so now after completing this, I actually think that this was quite fun to try to implement and do. You can check out my github repo here: https://github.com/personnumber3377/paper_marbling_algorithm

































