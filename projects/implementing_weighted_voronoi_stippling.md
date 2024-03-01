
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

Ok, so now I have implemented the addPoint function, which adds a singular point to the delaunay graph:

```
	def addPoint(self, p): # This method adds a point in the delaunay triangulation graph.
		p = np.asarray(p)
		idx = len(self.coords)
		self.coords.append(p) # Add point to the point list.

		bad_triangles = [] # badTriangles := empty set

		for tri in self.triangles: # // first find all the triangles that are no longer valid due to the insertion
			if self.inCircleFast(tri, p): # If the triangle is in the triangle, then that triangle is no longer valid.
				bad_triangles.append(tri)
		
		polygon = [] # These are the points of the new polygon.

		#for tri in bad_triangles: #  // find the boundary of the polygonal hole
		#	for edge in tri:
		#		# if edge is not shared by any other triangles in badTriangles
		#		

		tri = bad_triangles[0]
		cur_edge = 0
		while True:
			# Check if edge of triangle T is on the polygonal boundary.
			
			tri_op = self.triangles[tri][edge]
			assert isinstance(tri_op, int) # 
			if tri_op not in bad_triangles:
				# Insert the current edge and external triangle into the boundary list.
				polygon.append((tri[(cur_edge+1) % 3], tri[(cur_edge-1) % 3], tri_op))

				# Move to next CCW edge in this triangle.
				cur_edge = (cur_edge + 1) % 3

				# Check if boundary polygon is closed as a loop. If yes, then break
				if polygon[0][0] == polygon[-1][1]
					break
			else: # tri_op is in bad_triangles.
				# Just move to the next CCW edge in the opposite triangle.
				cur_edge = (self.triangles[tri_op].index(tri) + 1) % 3
				tri = tri_op # Jump to the next triangle.
		
		# Remove the "bad" triangles
		for t in bad_triangles:
			del self.triangles[t]
			del self.circles[t]
		
		# Tetriangle the hole left by bad triangles.
		new_triangles = []
		for (e0, e1, tri_op) in polygon: # e0 is the edge and then the tri_op is the thing.
			# Create a new triangle using point p and edge extremes.
			T = (idx, e0, e1)

			# Store the circumcenter and circumradius of the triangle.
			self.circles[T] = self.circumcenter(T)
			# Set opposite triangle of the edge as neigbhour of T
			self.triangles[T] = [tri_op, None, None]

			# Try to set T as neighbour of the opposite triangle
			if tri_op:
				# Search the neighbour of the opposite triangle.
				for i, neigh in enumerate(self.triangles[tri_op]):
					if neigh:
						if e1 in neigh and e0 in neigh:
							# Change link to use our new triangle.
							self.triangles[tri_op][i] = T
			
			# Add triangle to a temporan list
			new_triangles.append(T)
		
		# Link the new triangles each another.
		N = len(new_triangles)
		for i, T in enumerate(new_triangles):
			self.triangles[T][1] = new_triangles[(i+1) % N] # Next
			self.triangles[T][2] = new_triangles[(i-1) % N] # previous.

```

Let's actually try to understand how it works. To wikipedia we go... actually this seems like a much more indepth explanation: https://paulbourke.net/papers/triangulate/ Let's read that instead. Ok, so I somewhat understand how it does it. Now, let's try to implement a test function for this and maybe a render function which renders the result after adding some points.

Here is my driver code:

```
# This is a driver file for the delaunay file.
from delaunay import *
import turtle

SCALE_FACTOR = 100

def scale_points(point_list: list) -> list: # This scales the points.
	out = []
	for p in point_list:
		p_x = p[0]
		p_y = p[1]
		out.append(tuple((p_x*SCALE_FACTOR, p_y*SCALE_FACTOR)))
	return out

def render_triangles(triangles: list, test_points: list) -> None: # This renders the triangles with turtle
	t = turtle.Turtle()
	t.penup()
	for tri in triangles:
		print("tri: "+str(tri))
		# OK, so tri is a list of the indexes to the points list, therefore get points.
		p1 = test_points[tri[0]]
		p2 = test_points[tri[1]]
		p3 = test_points[tri[2]]

		triangle_points = scale_points([p1,p2,p3])
		turtle.goto(triangle_points[0])
		turtle.pendown()
		turtle.goto(triangle_points[1])
		turtle.goto(triangle_points[2])
		turtle.goto(triangle_points[0])
		turtle.penup()
		turtle.update
	return

def main() -> int:
	# def __init__(self, center=(0,0), radius=1000):
	delaunay = Delaunay()
	# Test points.
	test_points = [(0,0),(0,1),(1,0)] # Should create a simple triangle
	for p in test_points:
		delaunay.addPoint(p)
	tris = delaunay.exportTriangles()
	while True:
		render_triangles(tris, test_points)
	return 0

if __name__=="__main__":
	exit(main())

```

Let's add a point inside that triangle.

```
test_points = [(0,0),(0,1),(1,0),(0.4, 0.45)] # Should create a simple triangle
```
Result:
![Here is the result](pictures/delaunay.png)

Ok, so I somewhat understand the Delaunay stuff. Now we just need to get the voronoi shit and then just do the actual weighted voronoi stippling. Sigh

## Getting the Voronoi stuff from the Delaunay stuff

Ok, so as it turns out, the centers of the circumcircles are the vertexes of the voronoi diagram.

https://en.wikipedia.org/wiki/Delaunay_triangulation#Relationship_with_the_Voronoi_diagram

"The circumcenters of Delaunay triangles are the vertices of the Voronoi diagram. In the 2D case, the Voronoi vertices are connected via edges, that can be derived from adjacency-relationships of the Delaunay triangles: If two triangles share an edge in the Delaunay triangulation, their circumcenters are to be connected with an edge in the Voronoi tesselation."

, ok so just iterate over the areas and then get the circumcircle middle point and then add the connections. if two triangles share a side, then those are also going to be connected together in the voronoi diagram. Ok, so let's do it.

Here is my implementation of the voronoi shit:

```
	def exportVoronoi(self): # This returns the vertexes and the edges of the corresponding voronoi shit.
		useVertex = {i: [] for i in range(len(self.coords))} # This is the dictionary with the triangle index as a key and the value as the corresponding edges of that triangle. Construct this such that the key is always the last edge in the list.
		vor_coords = []
		index = {}
		# Build a list of coordinates and one index per triangle/region
		for tidx, (a,b,c) in enumerate(sorted(self.triangles)):
			vor_coords.append(self.circles[(a,b,c)][0]) # Get the first index, because the first index is the center point.
			# Insert triangle, rotating it so the key is the last vertex in the list.
			useVertex[a] += [(b,c,a)]
			useVertex[b] += [(c,a,b)]
			useVertex[c] += [(a,b,c)]
			# Set tidx as the index to use with this triangle.
			index[(a,b,c)] = tidx
			index[(b,c,a)] = tidx
			index[(c,a,b)] = tidx

		# init regions per coordinate dictionary.
		regions = {}
		# Sort each region in a coherent order, and substitute each triangle by its index.
		for i in range(4, len(self.coords)): # Skip over the first triangles which is the bounding box stuff.
			
			# The current vertex
			v = useVertex[i][0][0]
			r = []
			for _ in range(len(useVertex[i])): # Go over each 
				# Search the triangle from the very first vertex.
				t = [t for t in useVertex[i] if t[0] == v][0] # This get's the triangle vertex
				r.append(index[t])
				v = t[1] # Go to the next vertex
			regions[i-4] = r # Store the region into the set.
		return vor_coords, regions # Regions is the dict where the key is the index of the center point and the value is just the list of the associated 

```

here is the fixed version stuff:

```
	def exportVoronoi(self): # This returns the vertexes and the edges of the corresponding voronoi shit.
		useVertex = {i: [] for i in range(len(self.coords))} # This is the dictionary with the triangle index as a key and the value as the corresponding edges of that triangle. Construct this such that the key is always the last edge in the list.
		vor_coords = []
		index = {}
		# Build a list of coordinates and one index per triangle/region
		for tidx, (a,b,c) in enumerate(sorted(self.triangles)):
			vor_coords.append(self.circles[(a,b,c)][0]) # Get the first index, because the first index is the center point.
			# Insert triangle, rotating it so the key is the last vertex in the list.
			useVertex[a] += [(b,c,a)]
			useVertex[b] += [(c,a,b)]
			useVertex[c] += [(a,b,c)]
			# Set tidx as the index to use with this triangle.
			index[(a,b,c)] = tidx
			index[(b,c,a)] = tidx
			index[(c,a,b)] = tidx

		# init regions per coordinate dictionary.
		regions = {}
		# Sort each region in a coherent order, and substitute each triangle by its index.
		for i in range(4, len(self.coords)): # Skip over the first triangles which is the bounding box stuff.
			
			# The current vertex
			v = useVertex[i][0][0]
			r = []
			for _ in range(len(useVertex[i])): # Go over each 
				# Search the triangle from the very first vertex.
				t = [t for t in useVertex[i] if t[0] == v][0] # This get's the triangle vertex
				r.append(index[t])
				v = t[1] # Go to the next vertex
			regions[i-4] = r # Store the region into the set.
		return vor_coords, regions # Regions is the dict where the key is the index of the center point and the value is just the list of the associated 

```

Ok, so that seems to work.

## Implementing the Lloyd's relaxation algorithm.

Ok, so now that we have the voronoi diagram, it is time to actually program the main loop which actually moves the dots around. (LLoyd's algorithm.). I will put this in the lloyd function.

Now one thing is that I was actually a bit sussed out that if I should use the voronoi diagram or the other diagram when calculating the centroids. I think it is the voronoi points.

Here was my first try at that:

```
from delaunay import * # Import the Delaunay stuff

MOVE_SPEED = 0.1

class Lloyd:
    def __init__(self, points: list, center=(0,0), radius=1000):
        self.points = points
        self.center = center
        self.radius = radius
        self.delaunay_diagram = Delaunay(center=center, radius=radius)
        for p in self.points:
            self.delaunay_diagram.addPoint(p)
        self.circumcenters, self.regions = self.delaunay_diagram.exportVoronoi()
    def updateDelaunay(self) -> None: # This assumes that self.points has been reassigned.
        self.delaunay_diagram = Delaunay(center=center, radius=radius)
        for p in self.points:
            self.delaunay_diagram.addPoint(p)
    def updateVoronoi(self) -> None: # This assumes that updateDelaunay has been called
        self.circumcenters, self.regions = self.delaunay_diagram.exportVoronoi()

    def update(self): # Set's the points to the current centroids of the regions.
        new_points = [] # This will be assigned to self.points later on.
        polygons = self.regions
        cells = polygons
        # Get the current centroids and assign the points to them.
        cur_centroids = [self.get_centroid(poly) for poly in polygons] # These are the current centroids.
        # Lerp the points forward a bit.
        print("Length of points: "+str(len(points)))
        print("Length of the centroids: "+str(len(cur_centroids)))
        for i in range(len(self.points)):
            p = self.points[i]
            centroid = cur_centroids[i]
            # Add a bit of the centroid vector to the point.
            p_to_centroid_vec = (-p[0]+centroid[0], -p[1]+centroid[1])
            how_much_to_advance = (p_to_centroid_vec[0]*MOVE_SPEED, p_to_centroid_vec[1]*MOVE_SPEED)
            new_points.append((p[0]+how_much_to_advance[0], p[1]+how_much_to_advance[1])) # Add the vector.
        # assign the moved points to self.points
        self.points = new_points
        # Now just update the delaunay and voronoi stuff.
        self.updateDelaunay()
        self.updateVoronoi()

    def get_centroid(self, region) -> tuple: # This computes the rough centroid. (Using the average of all of the points in the region)
        # Ok so this assumes that the region is the value in the self.regions dictionary, so the region is a list of point indexes.
        point_indexes = region
        pts = [self.circumcenters[point_indexes[i]] for i in range(len(point_indexes))]
        # pts is the stuff which enscribes one of the regions.
        # Now calculate rough centroid.
        return (sum([p[0] for p in pts])/len(pts), sum([p[1] for p in pts])/len(pts)) # Return the average of the coordinates. This is not the actual centroid, but close enough.
    
    def render(self) -> None: # Renders the stuff.
        
        voronoi_regions = self.regions
        voronoi_points = self.circumcenters
        #def render_voronoi(voronoi_points: list, voronoi_regions: dict) -> None: # This is taken straight from main.py
        # Render all of the regions.
        t = turtle.Turtle()
        print("voronoi_regions == "+str(voronoi_regions))
        t.color("red")
        for reg in voronoi_regions:
            point_indexes = voronoi_regions[reg]
            t.penup()
            t.goto(scale_points([voronoi_points[point_indexes[0]]])[0])
            t.pendown()
            for p in point_indexes:
                print("p == "+str(p))
                #t.pendown()
                print("voronoi_points[p] == "+str(voronoi_points[p]))
                t.goto(scale_points([voronoi_points[p]])[0])
                
            t.penup()

```

this is quite largely based on this: https://editor.p5js.org/codingtrain/sketches/Z_YV25_4G which is basically the code in the coding train video.

## Debugging

```
    pts = [self.circumcenters[point_indexes[i]] for i in range(len(point_indexes))]
                                                               ^^^^^^^^^^^^^^^^^^
TypeError: object of type 'int' has no len()
```

Here is my current implementation:

```
# This is an implementation of Lloyd's algorithm with the Delaunay triangulation Voronoi diagram.  https://en.wikipedia.org/wiki/Lloyd%27s_algorithm

from delaunay import * # Import the Delaunay stuff
import turtle

MOVE_SPEED = 0.1
SCALE_FACTOR = 5
import time

def scale_points(point_list: list) -> list: # This scales the points.
    out = []
    for p in point_list:
        assert len(p) == 2 # sanity checking
        p_x = p[0]
        p_y = p[1]
        out.append(tuple((p_x*SCALE_FACTOR, p_y*SCALE_FACTOR)))
    return out



class Lloyd:
    def __init__(self, points: list, center=(0,0), radius=1000):
        self.points = points
        self.center = center
        self.radius = radius
        self.delaunay_diagram = Delaunay(center=center, radius=radius)
        for p in self.points:
            self.delaunay_diagram.addPoint(p)
        self.circumcenters, self.regions = self.delaunay_diagram.exportVoronoi()
    def updateDelaunay(self) -> None: # This assumes that self.points has been reassigned.
        self.delaunay_diagram = Delaunay(center=self.center, radius=self.radius)
        for p in self.points:
            self.delaunay_diagram.addPoint(p)
    def updateVoronoi(self) -> None: # This assumes that updateDelaunay has been called
        self.circumcenters, self.regions = self.delaunay_diagram.exportVoronoi()

    def update(self): # Set's the points to the current centroids of the regions.
        new_points = [] # This will be assigned to self.points later on.
        polygons = self.regions
        cells = polygons
        # Get the current centroids and assign the points to them.
        #cur_centroids = [self.get_centroid(poly) for poly in polygons] # These are the current centroids.
        cur_centroids = [self.get_centroid(self.regions[poly]) for poly in polygons] # These are the current centroids.
        # Lerp the points forward a bit.
        print("Length of cur_centroids: "+str(len(cur_centroids)))
        print("Length of the centroids: "+str(len(cur_centroids)))
        for i in range(len(self.points)):
            p = self.points[i]
            centroid = cur_centroids[i]
            # Add a bit of the centroid vector to the point.
            p_to_centroid_vec = (-p[0]+centroid[0], -p[1]+centroid[1])
            how_much_to_advance = (p_to_centroid_vec[0]*MOVE_SPEED, p_to_centroid_vec[1]*MOVE_SPEED)
            new_points.append((p[0]+how_much_to_advance[0], p[1]+how_much_to_advance[1])) # Add the vector.
        # assign the moved points to self.points
        self.points = new_points
        # Now just update the delaunay and voronoi stuff.
        self.updateDelaunay()
        self.updateVoronoi()

    def get_centroid(self, region) -> tuple: # This computes the rough centroid. (Using the average of all of the points in the region)
        # Ok so this assumes that the region is the value in the self.regions dictionary, so the region is a list of point indexes.
        point_indexes = region
        pts = [self.circumcenters[point_indexes[i]] for i in range(len(point_indexes))]
        # pts is the stuff which enscribes one of the regions.
        # Now calculate rough centroid.
        return (sum([p[0] for p in pts])/len(pts), sum([p[1] for p in pts])/len(pts)) # Return the average of the coordinates. This is not the actual centroid, but close enough.
    
    def render(self) -> None: # Renders the stuff.
        turtle.speed(0)
        turtle.tracer(0, 0)
        voronoi_regions = self.regions
        voronoi_points = self.circumcenters
        #def render_voronoi(voronoi_points: list, voronoi_regions: dict) -> None: # This is taken straight from main.py
        # Render all of the regions.
        t = turtle.Turtle()
        print("voronoi_regions == "+str(voronoi_regions))
        t.color("red")
        for reg in voronoi_regions:
            point_indexes = voronoi_regions[reg]
            t.penup()
            t.goto(scale_points([voronoi_points[point_indexes[0]]])[0])
            t.pendown()
            for p in point_indexes:
                print("p == "+str(p))
                #t.pendown()
                print("voronoi_points[p] == "+str(voronoi_points[p]))
                t.goto(scale_points([voronoi_points[p]])[0])
                
            t.penup()
        turtle.update()
        time.sleep(0.2)




def main() -> int:
    # First generate testdata:
    numSeeds = 50
    radius = 3
    seeds = radius * np.random.random((numSeeds, 2))
    # First declare the Lloyd object.
    #lloyd = Lloyd(seeds)
    lloyd = Lloyd(seeds, center=(0,0), radius=50)
    # We basically wan't to move the points until the points are are at the centroids of the voronoi cells.
    while True:
        # First update, then render.
        lloyd.update()
        lloyd.render()
        turtle.clearscreen()
    return 0

if __name__=="__main__": # Runs tests.
    exit(main())

```

and I think it somewhat works, but it just expands. This is because the bounds check isn't done by my code. See, in the website the guy used an external library to calculate the voronoi stuff: `voronoi = delaunay.voronoi([0, 0, width, height]);` and it causes us to somehow screw things up.

Let's add a bounds checking stuff. Let's first confirm that this is actually the problem. Let's add a sanity check.

Let's add this to the update function: `assert math.sqrt((new_points[-1][0]**2)+(new_points[-1][1]**2)) <= self.radius` .

Yeah, that was it. I get an assertion error there. We need to do some function which prevents the points from moving farther than that and we should be good.

Ok, so I am just going to actually go look at the source code of the fucking library. I think my code otherwise works perfectly, but for the fucking bounds checking stuff, which is handled by the library which the guy used.

Here is the source code: https://github.com/d3/d3-delaunay

Here is the constructor for the voronoi shit:

```
export default class Voronoi {
  constructor(delaunay, [xmin, ymin, xmax, ymax] = [0, 0, 960, 500]) {
    if (!((xmax = +xmax) >= (xmin = +xmin)) || !((ymax = +ymax) >= (ymin = +ymin))) throw new Error("invalid bounds");
    this.delaunay = delaunay;
    this._circumcenters = new Float64Array(delaunay.points.length * 2);
    this.vectors = new Float64Array(delaunay.points.length * 2);
    this.xmax = xmax, this.xmin = xmin;
    this.ymax = ymax, this.ymin = ymin;
    this._init();
  }
  // SNIP
```

Here I actually realized the problem:

```
delaunay.py:58: RuntimeWarning: invalid value encountered in scalar divide
  p_0 = (((a_0 - c_0) * (a_0 + c_0) + (a_1 - c_1) * (a_1 + c_1)) / 2 * (b_1 - c_1) -  ((b_0 - c_0) * (b_0 + c_0) + (b_1 - c_1) * (b_1 + c_1)) / 2 * (a_1 - c_1)) / D
\delaunay.py:59: RuntimeWarning: divide by zero encountered in scalar divide
  p_1 = (((b_0 - c_0) * (b_0 + c_0) + (b_1 - c_1) * (b_1 + c_1)) / 2 * (a_0 - c_0) -  ((a_0 - c_0) * (a_0 + c_0) + (a_1 - c_1) * (a_1 + c_1)) / 2 * (b_0 - c_0)) / D
```

so we have degenerate cases where stuff goes haywire and breaks.

Here is the bounds check in the library itself:

```
if (Math.abs(ab) < 1e-9) {
        // For a degenerate triangle, the circumcenter is at the infinity, in a
        // direction orthogonal to the halfedge and away from the “center” of
        // the diagram <bx, by>, defined as the hull’s barycenter.
        if (bx === undefined) {
          bx = by = 0;
          for (const i of hull) bx += points[i * 2], by += points[i * 2 + 1];
          bx /= hull.length, by /= hull.length;
        }
        const a = 1e9 * Math.sign((bx - x1) * ey - (by - y1) * ex);
        x = (x1 + x3) / 2 - a * ey;
        y = (y1 + y3) / 2 + a * ex;
      } else {
```

so let's add this to our code???
Yeah, let's just set D to some tiny number if it is really small.
```
		if D <= 10**(-9):
			D = 0.01 # Just force it
```
ok, so now it runs for a bit and then I get this error:

```
    for i, neigh in enumerate(self.triangles[tri_op]):
                              ~~~~~~~~~~~~~~^^^^^^^^
KeyError: (18, 15, 8)
```

It is quite hard to debug a bug, when you don't even know how the code works.

One thing is to do a minimal testcase which reproduces this bug. Let's try to add just two points.

Now, If I try a minimal testcase with this: `seeds = [(-10,0), (10,0)]` . We get some weird lines. If I try this: https://editor.p5js.org/codingtrain/sketches/04sgsAcNu with two points, there is just a singular line going through the thing.

I think the reason for why my code doesn't work, is because my way of calculating the area of the stuff to calculate the centroids is flawed. See, we are getting the average of all of the points, but the "middle" is actually outside the bounding box, therefore we need to actually set the points on the border instead of letting them go outside of the box, therefore we get the actual middle of the area inside the box. See, I added a debug stuff which shows the centroids too:

I added this to the render function:

```
self.draw_points(t=t, points=self.prev_centroids)
```

and here is the current draw_points function:

```
    def draw_points(self, t=None, points=None): # This draws all of the points.
        
        if t == None:
            t = turtle.Turtle()
        turtle.speed(0)
        t.penup()
        if points == None:
            points = self.points
        t.color("black")
        for p in points:
            # Just place a dot everywhere where the points are.
            t.goto(scale_point(p))
            t.dot()
        turtle.update()
        return
```

So before calculating the centroids, we want to clip the coordinates to be inside the box.

Here is my current code to calculate the centroids:

```
    def get_centroid(self, region) -> tuple: # This computes the rough centroid. (Using the average of all of the points in the region)
        # Ok so this assumes that the region is the value in the self.regions dictionary, so the region is a list of point indexes.
        point_indexes = region
        pts = [self.circumcenters[point_indexes[i]] for i in range(len(point_indexes))]
        # pts is the stuff which enscribes one of the regions.
        # Now calculate rough centroid.
        return (sum([p[0] for p in pts])/len(pts), sum([p[1] for p in pts])/len(pts)) # Return the average of the coordinates. This is not the actual centroid, but close enough.
```

so, before calculating we need to put a clipping check before the return statement.

Ok, so that sure made it a bit better, but still not great. I think we should just implement the proper area shit. I am looking at this: https://editor.p5js.org/codingtrain/sketches/04sgsAcNu

and the area algorithm is this:

```
  for (let poly of cells) {
    let area = 0;
    let centroid = createVector(0, 0);
    for (let i = 0; i < poly.length; i++) {
      let v0 = poly[i];
      let v1 = poly[(i + 1) % poly.length];
      let crossValue = v0[0] * v1[1] - v1[0] * v0[1];
      area += crossValue;
      centroid.x += (v0[0] + v1[0]) * crossValue;
      centroid.y += (v0[1] + v1[1]) * crossValue;
    }
    area /= 2;
    centroid.div(6 * area);
    centroids.push(centroid);
  }
```

So the pseudocode would be:
```
For each polygon polygons:
	initialize area to zero
	initialize centroid to the zero vector
	for vertex in polygon:
		initialize v0 to the current vertex
		initialize v1 to the vertex after this.
		initialize crossValue to the equation stuff.

```

I think the guy used this method: https://www.themathdoctors.org/polygon-coordinates-and-areas/ to calculate the area shit.

I need to implement a triangle clipping algorithm, because the fucking area algorithm fucks up the stuff.

If you look at the code here: https://github.com/d3/d3-delaunay/blob/main/src/voronoi.js you can see that roughly two thirds of the code is devoted to solely to triangle clipping.

FUCK!

I am just going to put it into a separate file called triangle_clipping.py in which I am going to implement an algorithm which cuts the points which are outside of the bounding box.

This is probably why the guy used external libraries, because then you don't have to implement another entire library to just compute something which is just a very tiny part of the actual algorithm which we want to implement.

I am going to try to implement this: https://en.wikipedia.org/wiki/Sutherland%E2%80%93Hodgman_algorithm#Pseudocode

Here is a new file called triangle_clipping.py :

```
def is_outside(point, radius):
    # This function checks if "point" is outside of the bounding box.
    x = point[0]
    y = point[1]
    if x > radius or x < -1*radius or y > radius or y < -1*radius:
        return True # The point is outside the bounding box.
    return False # Not outside the box.

def get_vec(prev_point, current_point): # Returns the vector from prev_point to current_point.
    return tuple((-1*prev_point[0]+current_point[0], -1*prev_point[1]+current_point[1]))



def ComputeIntersection(prev_point, current_point, clipEdge):
    # This computes the intersection between clipEdge and the vector created by the line from prev_point to cur_point.
    vec = get_vec(prev_point, current_point)
    
    if clipEdge[1] == None: # The line is x = something
        x_coord = clipEdge[0]
        # solve the equation prev_point[0] + k*vec[0] = x_coord => k = (x_coord - prev_point[0])/(vec[0])
        k =  (x_coord - prev_point[0])/(vec[0])
        # Now add vec*k to the previous point to get intersection point.
        intersec = tuple((prev_point[0]+k*vec[0], prev_point[1]+k*vec[1]))
        return intersec
    else:
        # The line is y = something
        # Just do the same, but with the y coordinate.
        y_coord = clipEdge[1]
        # solve the equation prev_point[0] + k*vec[0] = x_coord => k = (x_coord - prev_point[0])/(vec[0])
        k =  (x_coord - prev_point[1])/(vec[1])
        # Now add vec*k to the previous point to get intersection point.
        intersec = tuple((prev_point[1]+k*vec[1], prev_point[1]+k*vec[1]))
        return intersec


def sutherland_hodgman(points, radius):
    # This clips the polygon described by points against the box which is of distance "radius" from (0,0) . This assumes that the points list is in order (aka the points are in the order where you would connect them).
    '''
    List outputList = subjectPolygon;  

    for (Edge clipEdge in clipPolygon) do
        List inputList = outputList;
        outputList.clear();

        for (int i = 0; i < inputList.count; i += 1) do
            Point current_point = inputList[i];
            Point prev_point = inputList[(i − 1) % inputList.count];

            Point Intersecting_point = ComputeIntersection(prev_point, current_point, clipEdge)

            if (current_point inside clipEdge) then
                if (prev_point not inside clipEdge) then
                    outputList.add(Intersecting_point);
                end if
                outputList.add(current_point);

            else if (prev_point inside clipEdge) then
                outputList.add(Intersecting_point);
            end if

        done
    done
    '''

    out = points
    for clipEdge in [(radius,None),(-radius,None),(None, radius), (None, -radius)]: # This is just a list of the bounding box lines.
        inputList = out
        out = []
        for i in range(len(inputList)):
            current_point = inputList[i]
            prev_point = inputList[(i - 1) % len(inputList)]

            intersecting_point = ComputeIntersection(prev_point, current_point, clipEdge)




def clip_polygon(points, radius): # This clips all of the points and shit.
    val_stuff = [is_outside(p) for p in points]

    n_outside = sum(val_stuff)
    assert n_outside < 2 # There should be no more than one point outside, because I don't know how to program the other cases. :D
    if n_outside == 0:
        # Just return the original point list, if all of the points are inside the box.
        return points
    # Now there should be the one point which is outside the stuff.
    # identify which point is outside.
    # Just implement this function: https://en.wikipedia.org/wiki/Sutherland%E2%80%93Hodgman_algorithm#Pseudocode
    sutherland_hodgman(points, radius)

def test_is_outside():
    radius = 10
    point = tuple((15,0))
    assert is_outside(point, radius)
    point = tuple((9.99,0))
    assert not is_outside(point, radius)
    # Edge case
    point = tuple((10.0,0.0))
    assert not is_outside(point, radius)
    print("test_is_outside passed!!!")
    return

def test_intersection():
    # def ComputeIntersection(prev_point, current_point, clipEdge):
    prev_point = (0,0)
    cur_point = (1,0)
    clipedge = (10,None)
    res = ComputeIntersection(prev_point, cur_point, clipedge)
    assert res == (10,0)
    print("test_intersection passed!!!")
    return
    

def run_tests():
    test_is_outside()
    test_intersection()
    return

def main(): # Just run the tests in the main function
    # radius = 40
    # [center+radius*np.array((-1, -1)), center+radius*np.array((+1, -1)), center+radius*np.array((+1, +1)), center+radius*np.array((-1, +1))]
    run_tests()

if __name__=="__main__":
    exit(main())
```

and those test seem to pass, so we should be good.

Then after implementing the sutherland hodgman stuff, I came up with this:

```

import turtle

def is_outside(point, radius):
    # This function checks if "point" is outside of the bounding box.
    x = point[0]
    y = point[1]
    if x > radius or x < -1*radius or y > radius or y < -1*radius:
        return True # The point is outside the bounding box.
    return False # Not outside the box.

def get_vec(prev_point, current_point): # Returns the vector from prev_point to current_point.
    return tuple((-1*prev_point[0]+current_point[0], -1*prev_point[1]+current_point[1]))



def ComputeIntersection(prev_point, current_point, clipEdge):
    # This computes the intersection between clipEdge and the vector created by the line from prev_point to cur_point.
    vec = get_vec(prev_point, current_point)
    #print("clipEdge == "+str(clipEdge))
    assert not (clipEdge[0] == None and clipEdge[1] == None)
    if clipEdge[1] == None: # The line is x = something
        x_coord = clipEdge[0]
        # solve the equation prev_point[0] + k*vec[0] = x_coord => k = (x_coord - prev_point[0])/(vec[0])
        if vec[0] != 0:

            k =  (x_coord - prev_point[0])/(vec[0])
        else:
            k =  (x_coord - prev_point[0])
        # Now add vec*k to the previous point to get intersection point.
        intersec = tuple((prev_point[0]+k*vec[0], prev_point[1]+k*vec[1]))
        return intersec
    else:
        # The line is y = something
        # Just do the same, but with the y coordinate.
        print("clipEdge[1] == "+str(clipEdge[1]))
        y_coord = clipEdge[1]
        # solve the equation prev_point[0] + k*vec[0] = x_coord => k = (x_coord - prev_point[0])/(vec[0])
        if vec[1] != 0:

            k =  (y_coord - prev_point[1])/(vec[1])
        else:
            k =  (y_coord - prev_point[1])
        # Now add vec*k to the previous point to get intersection point.
        intersec = tuple((prev_point[1]+k*vec[1], prev_point[1]+k*vec[1]))
        return intersec


def check_inside(point, edge): # Check if the point is inside the edge.
    point_x = point[0]
    point_y = point[1]
    assert not (edge[0] == None and edge[1] == None)
    if edge[1] == None: # Check for x coord.
        #print("Checking x coordinate!!!")
        x_coord = edge[0]
        if x_coord <= 0:
            return point_x >= x_coord
        else: # check for below.
            return point_x <= x_coord
    else:
        # Check for y coord.
        y_coord = edge[1]
        if y_coord <= 0:
            return point_y >= y_coord
        else: # check for below.
            return point_y <= y_coord
    # Should not happen.
    assert False


def sutherland_hodgman(points, radius):
    # This clips the polygon described by points against the box which is of distance "radius" from (0,0) . This assumes that the points list is in order (aka the points are in the order where you would connect them).
    '''
    List outputList = subjectPolygon;  

    for (Edge clipEdge in clipPolygon) do
        List inputList = outputList;
        outputList.clear();

        for (int i = 0; i < inputList.count; i += 1) do
            Point current_point = inputList[i];
            Point prev_point = inputList[(i − 1) % inputList.count];

            Point Intersecting_point = ComputeIntersection(prev_point, current_point, clipEdge)

            if (current_point inside clipEdge) then
                if (prev_point not inside clipEdge) then
                    outputList.add(Intersecting_point);
                end if
                outputList.add(current_point);

            else if (prev_point inside clipEdge) then
                outputList.add(Intersecting_point);
            end if

        done
    done
    '''

    out = points
    for clipEdge in [(radius,None),(-radius,None),(None, radius), (None, -radius)]: # This is just a list of the bounding box lines.
        inputList = out
        out = []
        for i in range(len(inputList)):
            current_point = inputList[i]
            prev_point = inputList[(i - 1) % len(inputList)]

            intersecting_point = ComputeIntersection(prev_point, current_point, clipEdge)
            
            if check_inside(current_point, clipEdge):
                if not check_inside(prev_point, clipEdge):
                    out.append(intersecting_point)
                out.append(current_point)
            elif check_inside(prev_point, clipEdge):
                out.append(intersecting_point)
    return out # Output the polygon.


def clip_polygon(points, radius): # This clips all of the points and shit.
    val_stuff = [is_outside(p, radius) for p in points]

    n_outside = sum(val_stuff)
    assert n_outside < 2 # There should be no more than one point outside, because I don't know how to program the other cases. :D
    if n_outside == 0:
        # Just return the original point list, if all of the points are inside the box.
        return points
    # Now there should be the one point which is outside the stuff.
    # identify which point is outside.
    # Just implement this function: https://en.wikipedia.org/wiki/Sutherland%E2%80%93Hodgman_algorithm#Pseudocode
    poly = sutherland_hodgman(points, radius)

    return poly

def test_is_outside():
    radius = 10
    point = tuple((15,0))
    assert is_outside(point, radius)
    point = tuple((9.99,0))
    assert not is_outside(point, radius)
    # Edge case
    point = tuple((10.0,0.0))
    assert not is_outside(point, radius)
    print("test_is_outside passed!!!")
    return

def test_intersection():
    # def ComputeIntersection(prev_point, current_point, clipEdge):
    prev_point = (0,0)
    cur_point = (1,0)
    clipedge = (10,None)
    res = ComputeIntersection(prev_point, cur_point, clipedge)
    assert res == (10,0)
    print("test_intersection passed!!!")
    return

def test_inside_edge():
    point = (0,0)
    edge = (1,None)
    assert check_inside(point, edge)
    edge = (-1,None)
    assert check_inside(point, edge)
    point = (10,0)
    edge = (1,None)
    assert not check_inside(point, edge)
    print("test_inside_edge passed!")
    return

def run_tests():
    test_is_outside()
    test_intersection()
    test_inside_edge()
    return

SCALE_FACTOR = 5

def scale_points(point_list: list) -> list: # This scales the points.
    out = []
    for p in point_list:
        assert len(p) == 2 # sanity checking
        p_x = p[0]
        p_y = p[1]
        out.append(tuple((p_x*SCALE_FACTOR, p_y*SCALE_FACTOR)))
    return out


def render_polygon(polygon, t, color="blue"):
    # t is the turtle
    # color is the... ya know... color
    t.penup()
    t.color(color)
    t.goto(polygon[0])
    t.pendown()
    for pos in polygon[1:]:
        t.goto(pos)
    t.goto(polygon[0])
    t.penup()
    return


def render_stuff(): # Renders some testcases.
    t = turtle.Turtle()
    t.speed(0)
    
    # Ok, so try clipping a polygon and then show the clipped stuff.
    radius = 30
    original_points = [(0,10),(0,-10),(60,10)] # A long triangle
    render_polygon(scale_points(original_points), t)
    box_poly = [(-radius, -radius), (-radius, radius), (radius, radius), (radius, -radius)]
    render_polygon(scale_points(box_poly), t, color="purple")
    # Clip the polygon.
    clipped = clip_polygon(original_points, radius) # Clip.
    render_polygon(scale_points(clipped), t, color="red") # Show the clipped polygon in red

    return


def main(): # Just run the tests in the main function
    # radius = 40
    # [center+radius*np.array((-1, -1)), center+radius*np.array((+1, -1)), center+radius*np.array((+1, +1)), center+radius*np.array((-1, +1))]
    run_tests()
    while True:
        render_stuff()

if __name__=="__main__":
    exit(main())

```

when you run it, it should show a triangle which is being clipped (the original triangle is in blue and the clipped polygon is in red.)

Ok, so now we have a way to clip a polygon! Great!

Let's try a bit more complicated example: `original_points = [(0,10),(0,-10),(60,55)] # A long triangle with one point which goes to the top right` and it doesn't clip correctly.

See, if i clip only with the left side of the box I get this:

![Result](pictures/clipped.png)

If I set `original_points = [(0,0), (30,0), (30,50), (0,50)]` , then one of the vertexes of the polygon just disappears.

Let's add some debug statements.

Ok, so after adding some debug statements it appears that this bug is caused by the addition of the zero division shit. FUCK!

It is caused by this:

```
if vec[0] != 0:

            k =  (x_coord - prev_point[0])/(vec[0])
        else:
            k =  (x_coord - prev_point[0])
```

Let's fix it.

Here:

```
Checking y shit
prev_point == (0, 50)
current_point == (0, 0)
clipEdge[1] == 30
intersec == (30.0, 30.0)
```

is the problem. the 

I think the bug is on this line: `intersec = tuple((prev_point[1]+k*vec[1], prev_point[1]+k*vec[1]))` I tuped this, because I was mindlessly replacing every "0" with a "1" and I accidentally replaced a couple which I shouldn't have. It should be this: `intersec = tuple((prev_point[0]+k*vec[0], prev_point[1]+k*vec[1]))` and now it works.

## Actually using this clipping shit to calculate the area. (Roughly)

Ok, now that we have a working triangle clipping algorithm, let's actually try to use it to calculate the area and therefore the centroid.

Done.

Now I think it is time to improve the calculation of the centroid shit:

```
  for (let poly of cells) {
    let area = 0;
    let centroid = createVector(0, 0);
    for (let i = 0; i < poly.length; i++) {
      let v0 = poly[i];
      let v1 = poly[(i + 1) % poly.length];
      let crossValue = v0[0] * v1[1] - v1[0] * v0[1];
      area += crossValue;
      centroid.x += (v0[0] + v1[0]) * crossValue;
      centroid.y += (v0[1] + v1[1]) * crossValue;
    }
    area /= 2;
    centroid.div(6 * area);
    centroids.push(centroid);
  }
```

Here is my current code to get the centroid:

```
    def get_centroid(self, region) -> tuple: # This computes the rough centroid. (Using the average of all of the points in the region)
        # Ok so this assumes that the region is the value in the self.regions dictionary, so the region is a list of point indexes.
        point_indexes = region
        pts = [self.circumcenters[point_indexes[i]] for i in range(len(point_indexes))]
        # pts is the stuff which enscribes one of the regions.
        #pts = self.check_clipping(pts)
        # self.circumcenters, self.regions

        # Now at this point check for clipping using triangle_clipping.py: 
        new_points = clip_polygon(copy.deepcopy(pts), self.radius)

        # Draw the clipped shit.
        # def render_polygon(polygon, t, color="blue"):
        render_polygon(scale_points(new_points), turtle.Turtle(), color="green")
        turtle.update()
        time.sleep(0.2)
        # Now calculate rough centroid. Clip first
        #return (sum([p[0] for p in pts])/len(pts), sum([p[1] for p in pts])/len(pts)) # Return the average of the coordinates. This is not the actual centroid, but close enough.
        # new_points
        return (sum([p[0] for p in new_points])/len(new_points), sum([p[1] for p in new_points])/len(new_points))
```

let's implement the stuff!!

Here is my current get_centroid function:

```
    def get_centroid(self, region) -> tuple: # This computes the rough centroid. (Using the average of all of the points in the region)
        # Ok so this assumes that the region is the value in the self.regions dictionary, so the region is a list of point indexes.
        point_indexes = region
        pts = [self.circumcenters[point_indexes[i]] for i in range(len(point_indexes))]
        # pts is the stuff which enscribes one of the regions.
        #pts = self.check_clipping(pts)
        # self.circumcenters, self.regions

        # Now at this point check for clipping using triangle_clipping.py: 
        new_points = clip_polygon(copy.deepcopy(pts), self.radius)

        # Draw the clipped shit.
        # def render_polygon(polygon, t, color="blue"):
        render_polygon(scale_points(new_points), turtle.Turtle(), color="green")
        turtle.update()
        time.sleep(0.05) # Sleep to show the green stuff
        # Now calculate rough centroid. Clip first
        #return (sum([p[0] for p in pts])/len(pts), sum([p[1] for p in pts])/len(pts)) # Return the average of the coordinates. This is not the actual centroid, but close enough.
        # new_points
        #return (sum([p[0] for p in new_points])/len(new_points), sum([p[1] for p in new_points])/len(new_points))

        # Ok, so at this point I have the clipped triangle in new_points. Let's apply the appropriate equations to it to get the centroid.

        '''
        for (let poly of cells) {
    let area = 0;
    let centroid = createVector(0, 0);
    for (let i = 0; i < poly.length; i++) {
      let v0 = poly[i];
      let v1 = poly[(i + 1) % poly.length];
      let crossValue = v0[0] * v1[1] - v1[0] * v0[1];
      area += crossValue;
      centroid.x += (v0[0] + v1[0]) * crossValue;
      centroid.y += (v0[1] + v1[1]) * crossValue;
    }
    area /= 2;
    centroid.div(6 * area);
    centroids.push(centroid);
  }
        '''

        area = 0
        centroid = [0,0] # Convert to tuples later on.
        for i in range(len(new_points)):
            # (assumes that the points are in order.)
            v0 = new_points[0]
            v1 = new_points[(i + 1) % len(new_points)]
            crossValue = v0[0] * v1[1] - v1[0] * v0[1]
            area += crossValue
            centroid[0] += (v0[0] + v1[0]) * crossValue
            centroid[1] += (v0[1] + v1[1]) * crossValue
        area /= 2
        centroid = (centroid[0]/(6*area), centroid[1]/(6*area))
        return centroid
```

I wondered why it didn't work. That is because there is this: `v0 = new_points[0]` when it should be: `v0 = new_points[i]` .

## Debugging the weird lines.

Ok, so when I run my current version of the code, I get stuff like this:

![Result](pictures/somewhatworking.png)

It is otherwise working, but there are those weird lines still which connect to the bounding box. The reason why this is weird, is because in this: https://editor.p5js.org/codingtrain/sketches/04sgsAcNu you only get three lines which cut the box into equivalent areas.

Yeah, I am going to skip this bug for now, but I am going to try to fix it later on. I think this is because the program assumes that when lines go out of bounds that the line then goes to the bbox corner instead. Idk.

## Actually implementing the stippling

Ok, so all of that was actually just a prelude to the actual stippling algorithm. To do the stippling algorithm, we assign a "weight" to each spot in the square and then we move the points on each iteration based on that weight. (the higher the weight, the more we move the points.).

Let's look at this: https://editor.p5js.org/codingtrain/sketches/Z_YV25_4G

Ok, so we need to actually be able to load an image first. Let's implement a helper for that which gives us an 2D array of pixels, each of which has three values.

I am going to create a new file called image_loader.py

Done. Now I need to implement an algorithm to figure out which voronoi polygon a certain point belongs to. Fuck! This guy in this video: https://www.youtube.com/watch?v=Bxdt6T_1qgc just used the d3 library to do that, but I am going to implement it by myself (obviously). Ok, so I am going to create a new file called check_inside.py which as the name suggests checks wether a point is inside the polygon or not.

Ok, so after a bit of angry typing I came up with this:

```








import turtle
import copy
import time

SCALE_FACTOR = 60

def render_points(t, check_points, color="black"):
    t.color(color)
    t.penup()
    for p in check_points:
        t.goto((p[0]*SCALE_FACTOR, p[1]*SCALE_FACTOR))
        t.dot()

def check_intersection_quick(p0, p1, y_coord):
    y0 = p0[1]
    y1 = p1[1]
    # If both points are on the other side of the y = something line, then of course they can't intersect.
    if (y0 <= y_coord and y1 <= y_coord) or (y0 >= y_coord and y1 >= y_coord):
        # No intersection
        return False
    return True

def check_intersection_complex(p0, p1, point): # The point is used here to check for the intersections which are greater than it.
    min_x_coord = point[0]
    # First convert the formula to the y - y1 = m * (x - x1)   m = (y1-y0)/(x1-x0)
    # => x = (m * x1 + y - y1)/m
    x0 = p0[0]
    y0 = p0[1]
    x1 = p1[0]
    y1 = p1[1]
    if (x1 - x0) == 0:
        return False
    m = (y1 - y0)/(x1 - x0)
    if m == 0.0: # Division by zero.
        return False
    x_value = (m * x1 + y - y1)/m
    if x_value > min_x_coord: # Always just go to the right.
        return True
    else:
        return False


def render_polygon(polygon, t, color="blue"):
    # t is the turtle
    polygon = scale_points(polygon)
    # color is the... ya know... color
    t.penup()
    t.color(color)
    t.goto(polygon[0])
    t.pendown()
    for pos in polygon[1:]:
        t.goto(pos)
    t.goto(polygon[0])
    t.penup()
    return

def scale_points(point_list: list) -> list: # This scales the points.
    out = []
    for p in point_list:
        assert len(p) == 2 # sanity checking
        p_x = p[0]
        p_y = p[1]
        out.append(tuple((p_x*SCALE_FACTOR, p_y*SCALE_FACTOR)))
    return out



def check_inside_poly(point, polygon):
    # Go over each side.
    y_coord = point[1] # I am just going to use the line y = something to check, because I am lazy
    copy_polygon = copy.deepcopy(polygon)
    copy_polygon.append(copy.deepcopy(copy_polygon[0])) # This simplifies the code a bit.
    for i in range(len(copy_polygon) - 1):
        prev_point = copy_polygon[i]
        cur_point = copy_polygon[i+1]
        # Now check for the intersection.
        if check_intersection_quick(prev_point, cur_point, y_coord):
            # Now check for a more complex intersection.
            print("Poopoo")
            if check_intersection_complex(prev_point, cur_point, point):
                # Inside 
                return True
    return False

def run_inside_test(): # A simple test which shows the points which are inside and which are outside of a certain polygon.
    example_polygon = [(-1,-1), (-1,1), (1,1), (1,-1)] # A simple box.
    min_x = -3
    max_x = 3
    min_y = -3
    max_y = 3
    step_size = 0.1 # How far away are the evenly put points.
    
    check_points = []
    x = min_x
    y = min_y
    while y <= max_y:
        x = min_x
        while x <= max_x:
            point = (x,y)
            check_points.append(point)
            x += step_size
        y += step_size
    check_points = [(0,0)] # Just a debug point.
    # Now we have a grid of points in check_points.
    # Render all of them first
    #while True:
    t = turtle.Turtle()
    turtle.tracer(0,0)
    turtle.speed(0)
    render_points(t, check_points) # First show all of them 

    # Show the bounding polygon:

    render_polygon(example_polygon, t, color="blue")

    turtle.update()
    # Now calculate the points which are inside the polygon.
    red_points = []
    for p in check_points:
        if check_inside_poly(p, example_polygon): # check if inside
            # add to list
            red_points.append(p)
    render_points(t, red_points, color="red")
    turtle.update()
    time.sleep(3)
    return


def run_tests():
    run_inside_test()

def main():
    run_tests()
    return 0

if __name__=="__main__":
    exit(main())

```

and once again, a division by zero bug fucks up our day. Fantastic!

Here is a simple function to account for the vertical lines which would otherwise cause a division by zero:

```
def handle_vertical(p0, p1, point):
    y_range = [p0[1], p1[1]] # This is the y range to check against.
    y_coord = point[1]
    if y_coord >= y_range[0] and y_coord <= y_range[1]:
        return True
    return False
```

After adding some very janky looking code, I now have this:

```








import turtle
import copy
import time

SCALE_FACTOR = 60

def render_points(t, check_points, color="black"):
    t.color(color)
    t.penup()
    for p in check_points:
        t.goto((p[0]*SCALE_FACTOR, p[1]*SCALE_FACTOR))
        t.dot()

def check_intersection_quick(p0, p1, y_coord):
    y0 = p0[1]
    y1 = p1[1]
    # If both points are on the other side of the y = something line, then of course they can't intersect.
    if (y0 <= y_coord and y1 <= y_coord) or (y0 >= y_coord and y1 >= y_coord):
        # No intersection
        return False
    return True

def handle_vertical(p0, p1, point):
    y_range = [p0[1], p1[1]] # This is the y range to check against.
    min_y_coord = point[1]
    y_range = [min(y_range), max(y_range)]
    assert y_range[0] <= y_range[1]
    y_coord = point[1]
    if y_coord >= y_range[0] and y_coord <= y_range[1]:
        #return True
        print("y_coord == "+str(y_coord))
        print("min_y_coord == "+str(min_y_coord))
        return point[0] >= p0[0]
    return False


def handle_horizontal(p0, p1, point):
    return False # Impossible, because we are only considering casting a horizontal ray. A horizontal ray can not intersect another horizontal line.
    min_x_coord = point[0]
    x_range = [p0[0], p1[0]] # This is the y range to check against.
    x_range = [min(x_range), max(x_range)]
    assert x_range[0] <= x_range[1]
    x_coord = point[0]
    if x_coord >= x_range[0] and x_coord <= x_range[1]:
        return x_coord >= min_x_coord
    return False



def check_intersection_complex(p0, p1, point): # The point is used here to check for the intersections which are greater than it.
    min_x_coord = point[0]
    y_coord = point[1]
    # First convert the formula to the y - y1 = m * (x - x1)   m = (y1-y0)/(x1-x0)
    # => x = (m * x1 + y - y1)/m
    print("p0 == "+str(p0))
    print("p1 == "+str(p1))
    x0 = p0[0]
    y0 = p0[1]
    x1 = p1[0]
    y1 = p1[1]
    if (x1 - x0) == 0:
        print("now handling vertical line")
        # The points have the same x coordinate, therefore the line is a vertical line. (in the xy-plane).
        res = handle_vertical(p0, p1, point)
        print("res == "+str(res))
        #return res
        return res
        #return False
    m = (y1 - y0)/(x1 - x0)
    if m == 0.0: # Division by zero.
        return handle_horizontal(p0, p1, point)
        #return False
    x_value = (m * x1 + y_coord - y1)/m
    if x_value > min_x_coord: # Always just go to the right.
        return True
    else:
        return False


def render_polygon(polygon, t, color="blue"):
    # t is the turtle
    polygon = scale_points(polygon)
    # color is the... ya know... color
    t.penup()
    t.color(color)
    t.goto(polygon[0])
    t.pendown()
    for pos in polygon[1:]:
        t.goto(pos)
    t.goto(polygon[0])
    t.penup()
    return

def scale_points(point_list: list) -> list: # This scales the points.
    out = []
    for p in point_list:
        assert len(p) == 2 # sanity checking
        p_x = p[0]
        p_y = p[1]
        out.append(tuple((p_x*SCALE_FACTOR, p_y*SCALE_FACTOR)))
    return out



def check_inside_poly(point, polygon):
    # Go over each side.
    y_coord = point[1] # I am just going to use the line y = something to check, because I am lazy
    copy_polygon = copy.deepcopy(polygon)
    copy_polygon.append(copy.deepcopy(copy_polygon[0])) # This simplifies the code a bit.
    count = 0
    for i in range(len(copy_polygon) - 1):
        prev_point = copy_polygon[i]
        cur_point = copy_polygon[i+1]
        # Now check for the intersection.
        if check_intersection_quick(prev_point, cur_point, y_coord):
            # Now check for a more complex intersection.
            print("Poopoo")
            if check_intersection_complex(prev_point, cur_point, point):
                # Inside 
                count += 1
    print("Count: "+str(count))
    return bool(count % 2)

def run_inside_test(): # A simple test which shows the points which are inside and which are outside of a certain polygon.
    #example_polygon = [(-1,-1), (-1,1), (1,1), (1,-1)] # A simple box.
    example_polygon = [(-2,0), (2,0), (0,2)]
    min_x = -3
    max_x = 3
    min_y = -3
    max_y = 3
    step_size = 0.1 # How far away are the evenly put points.
    
    check_points = []
    x = min_x
    y = min_y
    while y <= max_y:
        x = min_x
        while x <= max_x:
            point = (x,y)
            check_points.append(point)
            x += step_size
        y += step_size
    #check_points = [(0,0)] # Just a debug point.
    # Now we have a grid of points in check_points.
    # Render all of them first
    #while True:
    t = turtle.Turtle()
    turtle.tracer(0,0)
    turtle.speed(0)
    render_points(t, check_points) # First show all of them 

    # Show the bounding polygon:

    render_polygon(example_polygon, t, color="blue")

    turtle.update()
    # Now calculate the points which are inside the polygon.
    red_points = []
    for p in check_points:
        if check_inside_poly(p, example_polygon): # check if inside
            # add to list
            red_points.append(p)
    render_points(t, red_points, color="red")
    turtle.update()
    time.sleep(3)
    return


def run_tests():
    run_inside_test()

def main():
    run_tests()
    return 0

if __name__=="__main__":
    exit(main())

```

## Integrating my polygon inside check to the main code.

Now that I have a working piece of code for the checking if a point is inside a polygon, we can actually implement the rest of the 

Ok, so after doing a bit of typing, I now have this:

```

# This is an implementation of Lloyd's algorithm with the Delaunay triangulation Voronoi diagram.  https://en.wikipedia.org/wiki/Lloyd%27s_algorithm

from delaunay import * # Import the Delaunay stuff
import turtle
import math
from triangle_clipping import * # this is for clip_polygon(original_points, radius)

MOVE_SPEED = 2
SCALE_FACTOR = 5
import time


def render_triangles(triangles: list, test_points: list) -> None: # This renders the triangles with turtle
    t = turtle.Turtle()
    t.speed(0)
    t.penup()
    print("Called render_triangles")
    for tri in triangles:
        print("tri: "+str(tri))
        # OK, so tri is a list of the indexes to the points list, therefore get points.
        p1 = test_points[tri[0]]
        p2 = test_points[tri[1]]
        p3 = test_points[tri[2]]

        triangle_points = scale_points([p1,p2,p3])
        turtle.goto(triangle_points[0])
        turtle.pendown()
        turtle.goto(triangle_points[1])
        turtle.goto(triangle_points[2])
        turtle.goto(triangle_points[0])
        turtle.penup()
        turtle.update()
    return



def render_polygon(polygon, t, color="blue"):
    # t is the turtle
    # color is the... ya know... color
    t.penup()
    t.color(color)
    t.goto(polygon[0])
    t.pendown()
    for pos in polygon[1:]:
        t.goto(pos)
    t.goto(polygon[0])
    t.penup()
    return


def scale_points(point_list: list) -> list: # This scales the points.
    out = []
    for p in point_list:
        assert len(p) == 2 # sanity checking
        p_x = p[0]
        p_y = p[1]
        out.append(tuple((p_x*SCALE_FACTOR, p_y*SCALE_FACTOR)))
    return out

def scale_point(point): # This scales just one point
    return tuple((point[0]*SCALE_FACTOR, point[1]*SCALE_FACTOR))

class Lloyd:
    def __init__(self, points: list, center=(0,0), radius=1000):
        self.points = points
        self.center = center
        self.radius = radius
        self.delaunay_diagram = Delaunay(center=center, radius=radius)
        for p in self.points:
            self.delaunay_diagram.addPoint(p)
        self.circumcenters, self.regions = self.delaunay_diagram.exportVoronoi()
    def updateDelaunay(self) -> None: # This assumes that self.points has been reassigned.
        self.delaunay_diagram = Delaunay(center=self.center, radius=self.radius)
        for p in self.points:
            self.delaunay_diagram.addPoint(p)
    def updateVoronoi(self) -> None: # This assumes that updateDelaunay has been called
        self.circumcenters, self.regions = self.delaunay_diagram.exportVoronoi()

    def update(self): # Set's the points to the current centroids of the regions.
        print("New cycle!!!")
        new_points = [] # This will be assigned to self.points later on.
        polygons = self.regions
        cells = polygons
        # Get the current centroids and assign the points to them.
        #cur_centroids = [self.get_centroid(poly) for poly in polygons] # These are the current centroids.
        cur_centroids = [self.get_centroid(self.regions[poly]) for poly in polygons] # These are the current centroids.
        self.prev_centroids = cur_centroids
        # Lerp the points forward a bit.
        print("Length of cur_centroids: "+str(len(cur_centroids)))
        print("Length of the centroids: "+str(len(cur_centroids)))
        # Show the current centroids.
        #self.draw_points(points=cur_centroids) # Just draw the centroids.
        
        for i in range(len(self.points)):
            p = self.points[i]
            centroid = cur_centroids[i]
            # Add a bit of the centroid vector to the point.
            p_to_centroid_vec = (-p[0]+centroid[0], -p[1]+centroid[1])
            how_much_to_advance = (p_to_centroid_vec[0]*MOVE_SPEED, p_to_centroid_vec[1]*MOVE_SPEED)
            new_points.append((p[0]+how_much_to_advance[0], p[1]+how_much_to_advance[1])) # Add the vector.
            # Sanity check.
            #assert math.sqrt((new_points[-1][0]**2)+(new_points[-1][1]**2)) <= self.radius
        # Instead of an assert, let's put a thing which just forces the point to be inside the stuff.

        # assign the moved points to self.points
        self.points = new_points
        self.check_points() # Bounds check.
        # Sanity check.
        #assert all(math.sqrt((p[0]**2)+(p[1]**2)) <= self.radius for p in self.points)
        # Now just update the delaunay and voronoi stuff.
        self.updateDelaunay()
        self.updateVoronoi()


    def get_polygon_index(self, point): # Get's the index in the current polygons, where the point is inside of .
        # Get's the index of the polygon in self.polygons which contains inside the point called "point"
        for i, poly in enumerate(self.regions):
            polygon_points_indexes = self.regions[poly]
            # pts = [self.circumcenters[point_indexes[i]] for i in range(len(point_indexes))]
            points = [self.circumcenters[polygon_points_indexes[j]] for j in range(len(polygon_points_indexes))]
            # Now check if the point is inside the polygon drawn out by connecting every point in the "points" list.
            # def check_inside_poly(point, polygon):
            res = check_inside_poly(point, points)
            if res:
                # Is inside so return the current index.
                return i
        # The point is not inside of any polygon
        assert False
        return 

    def update_weighted(self, image_data): # Image data is the pixel data of the image.
        # See https://editor.p5js.org/codingtrain/sketches/Z_YV25_4G

        print("New cycle!!!")
        new_points = [] # This will be assigned to self.points later on.
        polygons = self.regions
        cells = polygons
        r = self.radius
        # Get the current centroids and assign the points to them.
        #cur_centroids = [self.get_centroid(poly) for poly in polygons] # These are the current centroids.


        #cur_centroids = [self.get_centroid(self.regions[poly]) for poly in polygons] # These are the current centroids.

        #self.prev_centroids = cur_centroids
        
        
        # Before lerping, we need to calculate the weights of each thing.
        '''
        for i in range(len(image_data)):
            for j in range(len(image_data[0])):
                # Get the brightness
                brightness = (pix[0]+pix[1]+pix[2])/3.0
                w = 1 - (brightness/255)
                centroid_index = self.get_index()
        '''

        centroids = [(0,0) for _ in range(len(polygons))] # Initialize to (0,0)
        weights = [0.0 for _ in range(len(centroids))] # All of the weights
        # Ok, so image_data is the points and the brightnesses.
        for i in range(len(image_data)):
            for j in range(len(image_data[0])):
                pix = img[i][j]
                point = ((i/(len(img)))*r*2-(r), j/(len(img[0]))*r*2-(r))
                brightness = (pix[0]+pix[1]+pix[2])/3.0
                weight = 1 - (brightness / 255)

                cor_index = self.get_polygon_index(point)
                # Now update the weight shit of the centroids using the correct index. Just follow this: https://editor.p5js.org/codingtrain/sketches/Z_YV25_4G
                #centroids[cor_index][0] += i*weight
                #centroids[cor_index][1] += j*weight

                centroids[cor_index][0] += (point[0])*weight
                centroids[cor_index][1] += (point[1])*weight
                weights[cor_index] += weight # Add the weight to the weights

        # Now divide the centroids by the weights
        for i in range(len(centroids)):
            if weights[i] > 0: # avoid division by zero.
                centroids[i] = (centroids[i][0]/weights[i], centroids[i][1]/weights[i])
            else:
                centroids[i] = self.points[i] # Just copy.


        cur_centroids = centroids
        self.prev_centroids = centroids
        # Lerp the points forward a bit.
        print("Length of cur_centroids: "+str(len(cur_centroids)))
        print("Length of the centroids: "+str(len(cur_centroids)))
        # Show the current centroids.
        #self.draw_points(points=cur_centroids) # Just draw the centroids.
        
        for i in range(len(self.points)):
            p = self.points[i]
            centroid = cur_centroids[i]
            # Add a bit of the centroid vector to the point.
            p_to_centroid_vec = (-p[0]+centroid[0], -p[1]+centroid[1])
            how_much_to_advance = (p_to_centroid_vec[0]*MOVE_SPEED, p_to_centroid_vec[1]*MOVE_SPEED)
            new_points.append((p[0]+how_much_to_advance[0], p[1]+how_much_to_advance[1])) # Add the vector.
            # Sanity check.
            #assert math.sqrt((new_points[-1][0]**2)+(new_points[-1][1]**2)) <= self.radius
        # Instead of an assert, let's put a thing which just forces the point to be inside the stuff.

        # assign the moved points to self.points
        self.points = new_points
        self.check_points() # Bounds check.
        # Sanity check.
        #assert all(math.sqrt((p[0]**2)+(p[1]**2)) <= self.radius for p in self.points)
        # Now just update the delaunay and voronoi stuff.
        self.updateDelaunay()
        self.updateVoronoi()


    def check_points(self):
        point_list = self.points
        # Go over each point and do the bounds check.
        dist_bound = self.radius
        clipped = False
        for i, p in enumerate(point_list):
            point_list[i] = list(point_list[i])
            if p[0] > dist_bound:
                clipped = True
                point_list[i][0] = dist_bound
            elif p[0] < -1*dist_bound:
                point_list[i][0] = -1*dist_bound
                clipped = True
            if p[1] > dist_bound:
                point_list[i][1] = dist_bound
                clipped = True
            elif p[1] < -1*dist_bound:
                point_list[i][1] = -1*dist_bound
                clipped = True

            assert math.sqrt((point_list[i][0]**2)+(point_list[i][1]**2)) <= self.radius*2

            point_list[i] = tuple(point_list[i])
        if clipped:
            print("We have clipped some points!!!")
        self.points = point_list
        return

    def get_centroid(self, region) -> tuple: # This computes the rough centroid. (Using the average of all of the points in the region)
        # Ok so this assumes that the region is the value in the self.regions dictionary, so the region is a list of point indexes.
        point_indexes = region
        pts = [self.circumcenters[point_indexes[i]] for i in range(len(point_indexes))]
        # pts is the stuff which enscribes one of the regions.
        #pts = self.check_clipping(pts)
        # self.circumcenters, self.regions

        # Now at this point check for clipping using triangle_clipping.py: 
        new_points = clip_polygon(copy.deepcopy(pts), self.radius)

        # Draw the clipped shit.
        # def render_polygon(polygon, t, color="blue"):
        t = turtle.Turtle()
        t.speed(0)
        turtle.tracer(0, 0)
        render_polygon(scale_points(new_points), t, color="green")
        turtle.update()
        #time.sleep(0.05) # Sleep to show the green stuff
        # Now calculate rough centroid. Clip first
        #return (sum([p[0] for p in pts])/len(pts), sum([p[1] for p in pts])/len(pts)) # Return the average of the coordinates. This is not the actual centroid, but close enough.
        # new_points
        #return (sum([p[0] for p in new_points])/len(new_points), sum([p[1] for p in new_points])/len(new_points))

        # Ok, so at this point I have the clipped triangle in new_points. Let's apply the appropriate equations to it to get the centroid.

        '''
        for (let poly of cells) {
    let area = 0;
    let centroid = createVector(0, 0);
    for (let i = 0; i < poly.length; i++) {
      let v0 = poly[i];
      let v1 = poly[(i + 1) % poly.length];
      let crossValue = v0[0] * v1[1] - v1[0] * v0[1];
      area += crossValue;
      centroid.x += (v0[0] + v1[0]) * crossValue;
      centroid.y += (v0[1] + v1[1]) * crossValue;
    }
    area /= 2;
    centroid.div(6 * area);
    centroids.push(centroid);
  }
        '''

        area = 0
        centroid = [0,0] # Convert to tuples later on.
        for i in range(len(new_points)):
            # (assumes that the points are in order.)
            v0 = new_points[i]
            v1 = new_points[(i + 1) % len(new_points)]
            crossValue = v0[0] * v1[1] - v1[0] * v0[1]
            area += crossValue
            centroid[0] += (v0[0] + v1[0]) * crossValue
            centroid[1] += (v0[1] + v1[1]) * crossValue
        area /= 2
        centroid = (centroid[0]/(6*area), centroid[1]/(6*area))
        return centroid

    def check_clipping(self, points: list): # This makes it such that none of the points are outside of the bounding box.
        dist_bound = self.radius
        for i, p in enumerate(points):
            # Ripped straight from check_points.
            p = list(p)
            points[i] = list(points[i])
            if p[0] > dist_bound:
                clipped = True
                points[i][0] = dist_bound
            elif p[0] < -1*dist_bound:
                points[i][0] = -1*dist_bound
                clipped = True
            if p[1] > dist_bound:
                points[i][1] = dist_bound
                clipped = True
            elif p[1] < -1*dist_bound:
                points[i][1] = -1*dist_bound
                clipped = True
            points[i] = tuple(points[i])
            print("points[i] == "+str(points[i]))
        return points

    def render(self) -> None: # Renders the stuff.
        turtle.speed(0)
        turtle.tracer(0, 0)
        voronoi_regions = self.regions
        voronoi_points = self.circumcenters
        #def render_voronoi(voronoi_points: list, voronoi_regions: dict) -> None: # This is taken straight from main.py
        # Render all of the regions.
        t = turtle.Turtle()
        print("voronoi_regions == "+str(voronoi_regions))
        '''
        t.color("red")
        for reg in voronoi_regions:
            point_indexes = voronoi_regions[reg]
            t.penup()
            t.goto(scale_points([voronoi_points[point_indexes[0]]])[0])
            t.pendown()
            for p in point_indexes:
                print("p == "+str(p))
                #t.pendown()
                print("voronoi_points[p] == "+str(voronoi_points[p]))
                t.goto(scale_points([voronoi_points[p]])[0])
            t.goto(scale_points([voronoi_points[point_indexes[0]]])[0])
            t.penup()
        '''
        t.penup()
        # Draw bounding box.
        self.draw_bounding(t)
        self.draw_bounding_triangle(t)
        self.draw_points(t=t)
        self.draw_points(t=t, points=self.prev_centroids)
        turtle.update()
        #time.sleep(0.01)
    def draw_bounding(self, t):
        t.color("blue")
        r = self.radius*SCALE_FACTOR # Just assign a constant
        points = [(-1*r, 1*r), (r,r), (r,-1*r), (-1*r, -1*r), (-1*r, 1*r)]
        t.penup()
        t.goto(points[0])
        t.pendown()
        for p in points[1:]:
            t.goto(p)
        t.penup()
        return

    def draw_bounding_triangle(self, t):
        # The vertexes are at these coordinates: [center+radius*np.array((-1, -1)), center+radius*np.array((+1, -1)), center+radius*np.array((+1, +1)), center+radius*np.array((-1, +1))]
        radius = self.radius
        center = np.asarray(self.center)
        tri_points = [center+radius*np.array((-1, -1)), center+radius*np.array((+1, -1)), center+radius*np.array((+1, +1)), center+radius*np.array((-1, +1))]
        tri_points = scale_points(tri_points)
        t.color("purple")
        t.penup()
        t.goto(tri_points[0])
        t.pendown()
        for p in tri_points:
            t.goto(p)
        t.goto(tri_points[0])
        t.penup()
        return
    
    def draw_points(self, t=None, points=None): # This draws all of the points.
        
        if t == None:
            t = turtle.Turtle()
        turtle.speed(0)
        t.penup()
        if points == None:
            points = self.points
        t.color("black")
        for p in points:
            # Just place a dot everywhere where the points are.
            t.goto(scale_point(p))
            t.dot()
        turtle.update()
        return

    def render_delaunay(self):
        # tris = delaunay.exportTriangles()
        tris = self.delaunay_diagram.exportTriangles()


        render_triangles(tris, self.points)
        turtle.update()


def main() -> int:
    # First generate testdata:
    numSeeds = 100
    radius = 40
    seeds = radius * np.random.random((numSeeds, 2))
    #seeds = [(10,0),(-10,0),(0,-10),(0,10),(10,10)]
    #seeds = [(x*5,x) for x in range(-5,5,1)]
    #seeds = [(-10,0), (10,0), (10,10)]
    #seeds = [(-10,0), (10,0), (0,10)]
    # First declare the Lloyd object.
    #lloyd = Lloyd(seeds)
    lloyd = Lloyd(seeds, center=(0,0), radius=50)
    # We basically wan't to move the points until the points are are at the centroids of the voronoi cells.
    while True:
        # First update, then render.
        lloyd.update()
        turtle.clearscreen()
        lloyd.render()
        lloyd.render_delaunay() # tris = delaunay.exportTriangles()
        #time.sleep(0.1)
    return 0

if __name__=="__main__": # Runs tests.
    exit(main())


```

Now, we just need to use the update_weighted function in the actual update loop.

## Debugging, debugging and more debugging

Ok, so I had to modify the get_polygon_index function. Currently it looks like this in lloyd.py:

```
    def get_polygon_index(self, point): # Get's the index in the current polygons, where the point is inside of .
        # Get's the index of the polygon in self.polygons which contains inside the point called "point"
        for i, poly in enumerate(self.regions):
            polygon_points_indexes = self.regions[poly]
            # pts = [self.circumcenters[point_indexes[i]] for i in range(len(point_indexes))]
            points = [self.circumcenters[polygon_points_indexes[j]] for j in range(len(polygon_points_indexes))]
            # Now check if the point is inside the polygon drawn out by connecting every point in the "points" list.
            # def check_inside_poly(point, polygon):
            res = check_inside_poly(point, points)
            if res:
                # Is inside so return the current index.
                return i
        # The point is not inside of any polygon
        assert False
        return 
```

after the modifications it looks like this:

```


```

then after doing all of that I get this error:

```
    centroids[cor_index][0] += (point[0])*weight
    ~~~~~~~~~~~~~~~~~~~~^^^
TypeError: 'tuple' object does not support item assignment
```

fuuuuccckkk!!!

Ok, so after a couple of bug fixes it now atleast runs, but it runs slow as fuck. This is because I did some not so great for performance decisions when coding and now it bit

After a minute of processing, I then get this error:

```
 line 219, in exportVoronoi
    v = useVertex[i][0][0]
        ~~~~~~~~~~~~^^^
IndexError: list index out of range
```

FUCK MY LIFE!!!!

Again, some bullshit always happens which fucks me over. ALWAYS!!!

I absolutely hate this.

Maybe I should have used external stupid-ass libraries to do some of the calculations.

Let's just add this to the code:

```
			if i not in useVertex:
				continue # This is just to shut up the warning.
```

I think that I have to implement separate tests for each of these functions and files separately, because this is absolute donkey shit.

## Forcing it

Ok, so let's just bruteforce it to try to show atleast something.

Ok, so instead of going through every pixel in the image, what if we just randomly generate a lot of points and see how light or dark they are later on like in the coding train stuff????

I had to also change this:

```
        #for i in range(len(self.points)):
        for i in range(len(cur_centroids)):
```

because for some reason there are more points than there are centroids. I don't fucking know.

Ok, so let's just do a minimal picture and see how it handles that. The vast majority of the time goes in this fucking loop:

```
        for i in range(len(image_data)):
            #print(str(tot_count/complete_count*100)+" percent done")
            for j in range(len(image_data[0])):
                pix = image_data[i][j]
                point = ((i/(len(image_data)))*r*2-(r), j/(len(image_data[0]))*r*2-(r))
                brightness = (pix[0]+pix[1]+pix[2])/3.0
                weight = 1 - (brightness / 255)

                cor_index = self.get_polygon_index(point)
                # Now update the weight shit of the centroids using the correct index. Just follow this: https://editor.p5js.org/codingtrain/sketches/Z_YV25_4G
                #centroids[cor_index][0] += i*weight
                #centroids[cor_index][1] += j*weight

                centroids[cor_index][0] += (point[0])*weight
                centroids[cor_index][1] += (point[1])*weight
                weights[cor_index] += weight # Add the weight to the weights

                tot_count += 1 # Add one to the counter.
```

Let's just do a small image, because then the calculation of the centroids is a lot less.
Let's just create it in GIMP and let's set the resolution to 30x30 pixels.

## Giving up (for now)

Yeah, I bit off a lot more than what I could chew. There are many layers to this problem and if you try to solve the problem without testing each layer profoundly, then you will face some problems. There are probably plenty of bugs in the way for example I check which polygon is inside of which polygon etc..

For example the reason why my code produces this error:

```
line 130, in get_polygon_index
    assert False
AssertionError

```

is because I clip the polygons when I calculate the shit normally, but when I update using the update_weighted method, I do not clip the polygons. This causes the invalid calculation of the shit and therefore shit goes haywire:

```
def get_centroid(self, region) -> tuple: # This computes the rough centroid. (Using the average of all of the points in the region)
        # Ok so this assumes that the region is the value in the self.regions dictionary, so the region is a list of point indexes.
        point_indexes = region
        pts = [self.circumcenters[point_indexes[i]] for i in range(len(point_indexes))]
        # pts is the stuff which enscribes one of the regions.
        #pts = self.check_clipping(pts)
        # self.circumcenters, self.regions

        # Now at this point check for clipping using triangle_clipping.py: 
        new_points = clip_polygon(copy.deepcopy(pts), self.radius)
        # SNIP SNIP
```

## Implementing a shitload of debug functions

Ok, so let's tackle this problem. First of all, instead of a false assertion, let's return some very big number  (this way we can identify the points which do not belong to any voronoi polygon) and then let's render them.


Ok, so I added this garbage:

```
    def debug_polygon_shit(self): # This should show us the points which do not get assigned to any polygon.
        # First create a box of points.
        # def gen_points(min_x, max_x, min_y, max_y, step_size):
        points = gen_points(-self.radius, self.radius, -self.radius, self.radius, 0.5) # Box of points.
        t = turtle.Turtle()
        turtle.tracer(0,0)
        turtle.speed(0)
        render_points(t, points) # First show all of them 
        # self.get_polygon_index(point)
        # if that function returns "oof" , then we know that that said point is not assigned to any voronoi polygon.
        unassigned_points = []
        for p in points:
            if self.get_polygon_index(p) == "oof":
                unassigned_points.append(p)
        render_points(t, unassigned_points, color="purple")
        # Just render the other shit too.
        #self.render()
        turtle.update()
        time.sleep(50)
        return
```

and then if I run it, I get this:

![](pictures/poly.png)

Where the purple stuff is the area, where the program can not find the polygon index.

This problem goes back to the way we clip the polygons, because once again, we do not handle the shit gracefully, but there are spots, which are not under any of the voronoi polygons, so therefore we need to add code to handle the (literal) corner cases when clipping the polygons.

So I think we should add a thing here:

```
def get_polygon_index(self, point): # Get's the index in the current polygons, where the point is inside of .
        # Get's the index of the polygon in self.polygons which contains inside the point called "point"
        for i, poly in enumerate(self.regions):
            polygon_points_indexes = self.regions[poly]
            # pts = [self.circumcenters[point_indexes[i]] for i in range(len(point_indexes))]
            points = [self.circumcenters[polygon_points_indexes[j]] for j in range(len(polygon_points_indexes))]
            # Now check if the point is inside the polygon drawn out by connecting every point in the "points" list.
            # def check_inside_poly(point, polygon):
            res = check_inside_poly(point, points)
            if res:
                # Is inside so return the current index.
                return i
        # The point is not inside of any polygon
        #assert False
        #return 0 # Just shut up.
        return "oof"
```

which extends the polygons to cover the entire bounding box, instead of just leaving areas unassigned. Or maybe we can just ignore these cases and return None and in the calling function we could add an if check to check for None and if it is None, then just go to the next point. I don't really know. Anyway, I am going to probably continue this tomorrow.












