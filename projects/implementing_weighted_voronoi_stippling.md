
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

















