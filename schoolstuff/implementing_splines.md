
# Implementing splines

Ok, so in my math homework I am dealing with splines. I actually used splines back in high school in chemistry to draw titration graphs in geogebra, but back then we werent explained how they work...

Let's try to implement this here: https://en.wikipedia.org/wiki/Spline_(mathematics)#Algorithm_for_computing_natural_cubic_splines

The motivation for doing my own implementation is that we are having calc2 in college right now and one of the subject matters is multivariable functions and a spline graph is just a multivariable function which is defined piece-wise.

The algorithm detailed on wikipedia is actually a formula for just natural cubic splines, however later on in this writeup we will generalize to splines of any degree.

## The beginning

The algorithm starts out by just initializing the arrays to certain values.

Here is my implementation copied straight from wikipedia:

```

#!/bin/python3


def get_spline_natural_fifth_degree(points: list) -> list: # This function returns the coefficients of the spline as a list. The points are of the format [[x0,y0],[x1,y1]...[xn,yn]] where each value is a float value.
	# This is taken straight from wikipedia: https://en.wikipedia.org/wiki/Spline_(mathematics)#Algorithm_for_computing_natural_cubic_splines
	x_vals = [p[0] for p in points]
	y_vals = [p[1] for p in points]
	# 1. Create new array a of size n + 1 and for i = 0, …, n set a_i = y_i
	a = [p[1] for p in points] + [0.0] # Initialize the thing.
	# 2. Create new arrays b and d, each of size n.
	n = len(points)-1
	b = [0.0 for _ in range(n)]
	d = [0.0 for _ in range(n)]
	# 3. Create new array h of size n and for i = 0, …, n – 1 set h_i = x_(i+1) - x_i
	h = [points[i+1][0] - points[i][0] for i in range(n-1)]
	# 4. Create new array α of size n and for i = 1, …, n – 1 set alpha_1 = (3/h_i)*(a_(i+1) - a_i) - (3/h_(i-1))*(a_i-a_(i-1))
	alpha = [(3.0/h[i])*(a[i+1]-a[i])-(3.0/h[i-1])*(a[i]-a[i-1]) for i in range(1,n)] # Actually n-1, but because python ranges are dumb, we need to do this.
	# 5. Create new arrays c, l, μ, z, each of size n + 1.
	c = [0.0 for _ in range(n+2)]
	l = [0.0 for _ in range(n+2)]
	mu = [0.0 for _ in range(n+2)]
	z = [0.0 for _ in range(n+2)]
	# 7. For i = 1 .. n-1 set the following: l_i = 2*(x_(i+1)-x_(i-1))-(h_(i-1))*(mu_(i-1))    mu_i = h_i/l_i   z_i = (alpha_i-h_(i-1)*z_(i-1))/l_i
	for i in range(1, n):
		l[i] = 2*(x_vals[i+1]-x_vals[i-1])-(h[i-1])*(mu[i-1]) # Stuff.
		mu[i] = h[i]/l[i]
		z[i] = (alpha[i]-h[i-1]*z[i-1])/l[i]
	# 8. Set l_n = 1; z_n = c_n = 0
	l[n] = 1.0
	assert c[n] == 0.0 # Should be zero...
	z[n] = 0.0
	# 9. For j = n – 1, n – 2, …, 0, set the following: c_j = z_j - mu_j*c_(j+1)   b_j = (a_(j+1)-a_j)/h_j - (h_j*(c_(j+1)+2*c_j))/3    and   d_j = (c_(j+1)-c_j)/(3*h_j)
	for j in range(n - 1, 0, -1):
		c[j] = z[j] - mu[j]*c[j+1] # Just do the bullshit here...
		b[j] = (a[j+1]-a[j])/h[j] - (h[j]*(c[j+1]+2*c[j]))/3.0
		d[j] = (c[j+1]-c[j])/3.0
	# Create new set "Splines" and call it "output_set". Populate it with n splines S.
	splines = []
	for i in range(n):
		splines.append([a[i], b[i], c[i], d[i], x[i]])
	print("Here are the splines: ")
	print(splines)
	return splines # Return the output....


def test_spline() -> None: # This function here tests our implementation of splines...
	# These values are taken straight from my homework assignment...
	x_vals=[-0.83,0.14,-1.09,1.09,-0.54,2.03,3.0]
	y_vals=[-2.03,-2.06,0.71,1.49,2.06,2.43,3.0]

	assert len(x_vals) == len(y_vals)
	assert all([isinstance(x, float) for x in x_vals])
	assert all([isinstance(x, float) for x in y_vals])
	points = [[x_vals[i], y_vals[i]] for i in range(len(x_vals))] # Just do the thing...
	spline_vals = get_spline_natural_fifth_degree(points)
	print("Output: ")
	print(spline_vals)
	return


if __name__=="__main__":
	test_spline()
	exit(0)


```

but when running I get this error:

```

Traceback (most recent call last):
  File "/home/oof/school_stuff/spline/myspline.py", line 62, in <module>
    test_spline()
  File "/home/oof/school_stuff/spline/myspline.py", line 55, in test_spline
    spline_vals = get_spline_natural_fifth_degree(points)
                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/school_stuff/spline/myspline.py", line 17, in get_spline_natural_fifth_degree
    alpha = [(3.0/h[i])*(a[i+1]-a[i])-(3.0/h[i-1])*(a[i]-a[i-1]) for i in range(1,n)] # Actually n-1, but because python ranges are dumb, we need to do this.
                  ~^^^
IndexError: list index out of range

```

Here is a revised version:

```

#!/bin/python3


def get_spline_natural_fifth_degree(points: list) -> list: # This function returns the coefficients of the spline as a list. The points are of the format [[x0,y0],[x1,y1]...[xn,yn]] where each value is a float value.
	# This is taken straight from wikipedia: https://en.wikipedia.org/wiki/Spline_(mathematics)#Algorithm_for_computing_natural_cubic_splines
	x_vals = [p[0] for p in points]
	y_vals = [p[1] for p in points]
	# 1. Create new array a of size n + 1 and for i = 0, …, n set a_i = y_i
	a = [p[1] for p in points] + [0.0] # Initialize the thing.
	# 2. Create new arrays b and d, each of size n.
	n = len(points)-1
	b = [0.0 for _ in range(n)]
	d = [0.0 for _ in range(n)]
	# 3. Create new array h of size n and for i = 0, …, n – 1 set h_i = x_(i+1) - x_i
	h = [points[i+1][0] - points[i][0] for i in range(n)]
	# 4. Create new array α of size n and for i = 1, …, n – 1 set alpha_1 = (3/h_i)*(a_(i+1) - a_i) - (3/h_(i-1))*(a_i-a_(i-1))
	alpha = [(3.0/h[i])*(a[i+1]-a[i])-(3.0/h[i-1])*(a[i]-a[i-1]) for i in range(1,n)] # Actually n-1, but because python ranges are dumb, we need to do this.
	alpha.append(0.0)
	assert len(alpha) == n
	print("Length of alpha: "+str(alpha))
	# 5. Create new arrays c, l, μ, z, each of size n + 1.
	c = [0.0 for _ in range(n+2)]
	l = [0.0 for _ in range(n+2)]
	mu = [0.0 for _ in range(n+2)]
	z = [0.0 for _ in range(n+2)]
	# 7. For i = 1 .. n-1 set the following: l_i = 2*(x_(i+1)-x_(i-1))-(h_(i-1))*(mu_(i-1))    mu_i = h_i/l_i   z_i = (alpha_i-h_(i-1)*z_(i-1))/l_i
	print("Value of the bullshit: "+str(n-1))
	for i in range(1, n):
		l[i] = 2*(x_vals[i+1]-x_vals[i-1])-(h[i-1])*(mu[i-1]) # Stuff.
		mu[i] = h[i]/l[i]
		print("Accessing index: "+str(i))
		z[i] = (alpha[i]-h[i-1]*z[i-1])/l[i]
	# 8. Set l_n = 1; z_n = c_n = 0
	l[n] = 1.0
	assert c[n] == 0.0 # Should be zero...
	z[n] = 0.0
	# 9. For j = n – 1, n – 2, …, 0, set the following: c_j = z_j - mu_j*c_(j+1)   b_j = (a_(j+1)-a_j)/h_j - (h_j*(c_(j+1)+2*c_j))/3    and   d_j = (c_(j+1)-c_j)/(3*h_j)
	for j in range(n - 1, 0, -1):
		c[j] = z[j] - mu[j]*c[j+1] # Just do the bullshit here...
		b[j] = (a[j+1]-a[j])/h[j] - (h[j]*(c[j+1]+2*c[j]))/3.0
		d[j] = (c[j+1]-c[j])/3.0
	# Create new set "Splines" and call it "output_set". Populate it with n splines S.
	splines = []
	for i in range(n):
		splines.append([a[i], b[i], c[i], d[i], x_vals[i]])
	print("Here are the splines: ")
	print(splines)
	return splines # Return the output....


def test_spline() -> None: # This function here tests our implementation of splines...
	# These values are taken straight from my homework assignment...
	x_vals=[-0.83,0.14,-1.09,1.09,-0.54,2.03,3.0]
	y_vals=[-2.03,-2.06,0.71,1.49,2.06,2.43,3.0]

	assert len(x_vals) == len(y_vals)
	assert all([isinstance(x, float) for x in x_vals])
	assert all([isinstance(x, float) for x in y_vals])
	points = [[x_vals[i], y_vals[i]] for i in range(len(x_vals))] # Just do the thing...
	spline_vals = get_spline_natural_fifth_degree(points)
	print("Output: ")
	print(spline_vals)
	return


if __name__=="__main__":
	test_spline()
	exit(0)


```

Let's test out our implementation. Let's ask chatgpt how to actually plot this thing...




















