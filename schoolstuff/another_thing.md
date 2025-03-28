# Solving an interesting problem in math with sympy

Ok, so I was given this assignment: 

```

```

the difficulty arises from treating other variables as dependent variables.

My initial try was this:

```

from sympy import *

if __name__=="__main__":
	u,v,w,z = Symbol("u"), Symbol("v"), Symbol("w"), Symbol("z")
	# These are the equations ( = 0)
	eq1 = 2*z+2*w+v+3*u+4
	eq2 = 5*z+w+2*v+u+2
	# Now find the partial derivative dz/dw first:
	# "First derivate both equations with respect to w..."
	diff_eq1_w = diff(eq1, w)
	diff_eq2_w = diff(eq1, w)
	# "This yields to a system of equations which can be solved for (dz/dw)_u..."
	
	# Now do the thing...
	print(dz_dw, dv_du)
	exit(0)


```

but this won't work, because they are dependent stuff...




