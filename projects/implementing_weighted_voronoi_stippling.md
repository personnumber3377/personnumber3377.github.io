
# Implementing weighted voronoi stippling.

Ok, so I was scrolling on youtube and I found this: https://www.youtube.com/watch?v=Bxdt6T_1qgc and I was inspired to program my own.

I am going to first try to program without handholding from the youtube video, but if I get stuck, then I will watch snippets of it. You can follow my programming attempt here: https://github.com/personnumber3377/pythonweightedvoronoistippling

After doing a quick google search I found this: https://www.cs.ubc.ca/labs/imager/tr/2002/secord2002b/secord.2002b.pdf . It sure describes the algorithm, but it describes it in a complex way, and I do not really understand how it works. I watched the first minute or so of the youtube video and the guy said that this concept was quite difficult, so I don't know how I am going to get this to work, but let's keep our heads up.

Ok, so I think we need to first try to implement this here: https://en.wikipedia.org/wiki/Lloyd%27s_algorithm . They use terms as a centroid and terms like that but I don't even know what a centroid is.

## "2.2 Generating Centroidal Voronoi Diagrams"

Ok, so just implement a function which takes in a list of generating points and then outputs.

Reading the pdf the `C` variable is something which we want to minimize (for some reason), then `p(x)` is the density function and `x` is the position. Now here is the kicker: the density function is never actually defined anywhere.

"... where A is the region, x is the position and ρ(x) is the density function. For a region of constant density ρ, the centroid can be considered as the centre of mass"

This seems interesting: https://github.com/duhaime/lloyd . One thing is that translating the mathematical formulas to code requires a lot of nuance, for example in the actualy code we need to do a bounding box such that during the iteration, our points do not fly out into the infinite space. Also when converting the mathematical formulas to code, we also usually need discretization of time and space. (In mathematics space is continuous, but in code it isn't necessarily continuous.)

I do not really understand if the density function is the density of the points or just the area. I think we want a constant density area. So therefore we can ignore that.

My usual way of doing this would be to go by the functional way and just create functions for each step, but this time I decided to go with an object orientation and I am going to create a class called Lloyd 

Here is my current Lloyd class skeleton:

```
# This implements the Lloyd's algorithm, which evenly spaces out points.

class Lloyd:
	def __init__(self, points: list) -> None: # Constructor.
		self.points = points
		self.bounds = self.get_bounds() # This is such that we can draw a bounding box around the points such that they do not fly into outer space. Returns a list of [min_x, max_x, min_y, max_y]

	def get_bounds() -> list: # gets the bounds of the points.
		x_vals = [p[0] for p in self.points]
		y_vals = [p[1] for p in self.points]
		return [min(x_vals), max(x_vals), min(y_vals), max(y_vals)]
```

As it turns out, the github code uses the scipy library to create the voronoi points, so that sucks. I don't really want to cheat that way, because I wan't to actually implement everything myself.

So we need to implement the Voronoi points by ourself. Here are some of the possible implementations: https://en.wikipedia.org/wiki/Voronoi_diagram#Algorithms

Let's implement Fortune's algorithm: https://en.wikipedia.org/wiki/Fortune%27s_algorithm in python and see what happens.

I am sure that we will be able to implement this in just a couple of hour.... ohhhhh: https://en.wikipedia.org/wiki/Fortune%27s_algorithm#Algorithm_description

Yeah, I may have bitten off more than what I can chew with this. All of this is just to generate random points evenly. Couldn't we just put dots at every x units in a grid and call it a day?

Ok, so there is an easier implementation of Voronoi graphs, but they are worse in performance: https://stackoverflow.com/a/973140 . 

Let's just watch the Coding Train video and see how he implemented it. My guess is that the guy used some library too. But let's see.

Ok, so the guy didn't use Fortunes algorithm, but instead used Delaunay triangulation which is worse in performance. That sucks for our goal, but let's see what happens.

## Understanding Delaunay triangulation

Ok, so yeah the guy used a library to just calculate the stuff. I am not going to do that. I am going to implement my own version instead.

This seems what I want: https://github.com/jmespadero/pyDelaunay2D

It uses the algorithm described here: http://en.wikipedia.org/wiki/Bowyer-Watson_algorithm to calculate the stuff.

## Implementing delaunay

Ok, so I think I need to make a separate repository for the delaunay algorithm. Ok, so I created a new repository here: https://github.com/personnumber3377/pythondelaunay for this project.

I am going to follow this pseudocode here: https://en.wikipedia.org/wiki/Bowyer%E2%80%93Watson_algorithm#Pseudocode and this python implementation here: https://github.com/jmespadero/pyDelaunay2D/blob/master/delaunay2D.py

Ok, so I need to implement the circumcenter function. The circumcircle is the smallest circle which enscribes all three of the points in a triangle. This link here describes a formula for the center point and the radius: https://ics.uci.edu/~eppstein/junkyard/circumcenter.html

26.2.2024 ok so i implemented a bit of the delaunay stuff. I am now in commit ac060cfb7f5c5f6ceeb60989b3d6e5ce2801d7a9

























