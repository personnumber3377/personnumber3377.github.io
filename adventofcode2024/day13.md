# Day 13

## Part 1

Ok, so let's see what we are up against...

This is just a linear optimization problem. Here is a prompt for chatgpt which basically solves the problem: `I have this linear optimization problem. Assume all of the variables are nonnegative integers. I have these two equations: x_red*d_red_x + x_blue*d_blu_x = K_x and x_red*d_red_y + x_blue*d_blu_y = K_y where x_red and x_blue are the unknown variables. Every other variable is known. How can I solve for the combination of x_red and x_blue which minimizes the expression P_red*x_red + P_blue*x_blue  (again P_red and P_blue are known beforehand)?`

and here is the answer:

```

This problem can be solved as an integer linear programming (ILP) problem because all variables are nonnegative integers, and you are minimizing a linear objective function subject to linear equality constraints. Here's the structured approach:

```

chatgpt originally gave an answer which just used a solver library, but that is cheating. I wan't to know how it works. Let's ask it to write one without the help of a library:

This problem is closely correlated to diophantime equations.

Chatgpt gave this answer:

```
4. Implementation
Here’s a Python implementation using direct computation and solving for integer constraints:

python
Kopioi koodi
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = extended_gcd(b, a % b)
    x, y = y1, x1 - (a // b) * y1
    return gcd, x, y

def solve_min_cost_diophantine(P_red, P_blue, d_red_x, d_blue_x, d_red_y, d_blue_y, K_x, K_y):
    # Solve the linear Diophantine system
    det_A = d_red_x * d_blue_y - d_red_y * d_blue_x
    if det_A == 0:
        return None, None, None  # No unique solution

    # Particular solution using Cramer's rule
    x_red_0 = (K_x * d_blue_y - K_y * d_blue_x) // det_A
    x_blue_0 = (K_y * d_red_x - K_x * d_red_y) // det_A

    # Ensure the solution is an integer
    if not (x_red_0 >= 0 and x_blue_0 >= 0):
        return None, None, None  # No nonnegative solution

    # Adjust solutions with parameters
    gcd_dx_dy, p, q = extended_gcd(d_red_x, d_red_y)
    if gcd_dx_dy == 0 or K_x % gcd_dx_dy != 0 or K_y % gcd_dx_dy != 0:
        return None, None, None  # No solution exists

    # Parameterize solutions
    min_cost = float('inf')
    best_x_red, best_x_blue = None, None

    # Loop through possible parameterized solutions
    for k in range(-100, 101):  # Adjust range for reasonable search
        x_red = x_red_0 + k * (d_blue_y // gcd_dx_dy)
        x_blue = x_blue_0 + k * (d_red_y // gcd_dx_dy)

        if x_red >= 0 and x_blue >= 0:
            cost = P_red * x_red + P_blue * x_blue
            if cost < min_cost:
                min_cost = cost
                best_x_red, best_x_blue = x_red, x_blue

    return best_x_red, best_x_blue, min_cost
5. Explanation
Extended GCD: Used to find integer solutions to linear Diophantine equations.
Particular Solution: Found using Cramer's rule or direct substitution.
General Solution: Parameterized with
𝑘
k to explore all possible solutions.
Optimization: Evaluates the cost function for all valid
𝑘
k values within a reasonable range.
```

which basically is just a diophantine equation solver which solves a particular solution.

Let's try to implement it ourselves.

## Our implementation

Here is my backbone:

```






'''

This function tries to give general integral solutions to the system of equations:

x1*a + x2*b = K1
x1*c + x2*d = K2

Using the diophantine equation.

'''

def solve(x1, x2, a, b, c, d, K1, K2):




if __name__=="__main__":



	exit()


```

Ok, so after like an hour of trying shit I now have this which I basically copied from wikipedia:

```

def extended_euclidean_algorithm(a,b,c):
	# https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Description

	r0, r1 = a, b
	s0, s1 = 1, 0
	t0, t1 = 0, 1

	# The computation stops when one reaches a remainder  r_(k+1){\displaystyle r_{k+1}} which is zero; the greatest common divisor is then the last non zero remainder 	r	k	.	{\displaystyle r_{k}.}
	while r1 != 0:
		q = r0 // r1
		r0, r1 = r1, r0 - q*r1
		s0, s1 = s1, s0 - q*s1
		t0, t1 = t1, t0 - q*t1


	# Ok, so now I think that the gcd is in r0 because r1 is now zero.
	# Return the scaled versions
	k = c/r0# // r0
	return r0, s0*k, t0*k # r0 is gcd, s0 and t0 are the coefficients

```

Now `s0*k` is basically x0 and `t0*k` is y0 initial answers, then the actual value for x is basically just this: https://math.stackexchange.com/questions/2018981/how-do-you-solve-diophantine-equations-using-euclidean-algorithm aka  x0 + t*(b/r0) and y is just y0 + t*(a/r0)

Now that we have the specific solution to one of the two equations, we can now solve a system of such equations. We can solve x = x0 + t*(a/gcd(a,b)) from the top equation and substitute it into the bottom equation. This way we can solve for k which is the multiplier.

except maybe we can't do that because the k in x is not the same as the k in y????? Wait it is the same. So I think this problem will boil down to having to differentiate between the machines which only have one possible solution which is automatically the optimal solution since it is the only one and then there are some machines which have infinite solutions and those are the ones which we need to bruteforce or something like that...

Here is my current code (see my notes for the explanation for the formulas):

```






'''

This function tries to give general integral solutions to the system of equations:

x1*a + x2*b = K1
x1*c + x2*d = K2

Using the diophantine equation.

'''

from math import gcd
import sys

'''
def extended_euclidean_algorithm(a,b,c):
	# Solves the euclidean algorithm a*x + b*y = c

	# First transform this into a = b*q + r where q is the quotient and r is the remainder...

	a_remaining = a
	b_current = b
	quotient_list = []
	remainder = 1
	while remainder != 0:
		quotient = a_remaining // b_current
		quotient_list.append(quotient)
		remainder = a_remaining % b_current
		assert quotient*b_current + remainder + a_remaining
		a_remaining = b_current
		b_current = remainder


		print("="*100)
		print(a_remaining)
		print(quotient)
		#print(b_current)
		#print(remainder)
	x0 = a_remaining
	y0 = quotient
	assert c % gcd(a,b) == 0
	scale_factor = c / gcd(a,b)

	x0_scaled = x0 * scale_factor
	y0_scaled = y0 * scale_factor
	print(x0_scaled)
	print(y0_scaled)
	assert x0_scaled*a + y0_scaled*b == c
	return
'''



def extended_euclidean_algorithm(a,b,c):
	# https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Description

	r0, r1 = a, b
	s0, s1 = 1, 0
	t0, t1 = 0, 1

	# The computation stops when one reaches a remainder  r_(k+1){\displaystyle r_{k+1}} which is zero; the greatest common divisor is then the last non zero remainder 	r	k	.	{\displaystyle r_{k}.}
	while r1 != 0:
		q = r0 // r1
		r0, r1 = r1, r0 - q*r1
		s0, s1 = s1, s0 - q*s1
		t0, t1 = t1, t0 - q*t1


	# Ok, so now I think that the gcd is in r0 because r1 is now zero.
	# Return the scaled versions
	k = c/r0# // r0
	return r0, s0*k, t0*k # r0 is gcd, s0 and t0 are the coefficients




BUT_SEP = "Button A: "
LEN_BUT_SEP = len(BUT_SEP)

PRIZE_SEP = "Prize: "
LEN_PRIZE_SEP = len(PRIZE_SEP)

def solve(x1, x2, a, b, c, d, K1, K2):
	# The first equation is x1*a + x*2*b = K1 , if the gcd(a,b) does not divide K1, then no solution exists...
	if gcd(a,b) % K1 != 0:
		return None # No solutions automatically.



def solve_system(d_red_x, d_blue_x, K_x, d_red_y, d_blue_y, K_y):

	# extended_euclidean_algorithm

	# Check for infinite solutions...
	if d_red_x*d_blue_y - d_blue_x*d_red_y == 0:
		print("Infinite solutions..."*1)
		print("Values:")
		print(d_red_x, d_blue_x, K_x, d_red_y, d_blue_y, K_y)
		print("="*30)
		return None
		#exit(1)
	else:
		print("Finite solutions...")
	# The first equation on our list is just  the x coordinates.
	initial_solution = extended_euclidean_algorithm(d_red_x, d_blue_x, K_x)
	gcd_thing, x0, y0 = initial_solution[0], initial_solution[1], initial_solution[2]
	# Now initial_solution[0] is gcd and initial_solution[1] is x0 and initial_solution[2] is y0. These are already scaled, so no need to scale them here.

	# Now calculate the t thing. This can be used to calculate the bullshit.
	# We basically solved the first equation and then substituted the parameterized solution to the bottom equation and just solved for the parameter t (https://math.stackexchange.com/questions/2018981/how-do-you-solve-diophantine-equations-using-euclidean-algorithm)
	t = (K_y - x0*d_red_y-y0*d_blue_y)/(((d_blue_x*d_red_y)/gcd_thing)-((d_red_x*d_blue_y)/gcd_thing))

	# Now calculate the actual solution for the thing...

	# Notice that x = x0 + t*d_blue_x
	actual_x = x0 + t*(d_blue_x)
	print("Here is the actual_x: "+str(actual_x))

	return None










def get_machines(machines_strings) -> list: # Returns the tuples which describe this machine.
	# This assumes that the stuff is in the format.
	a_shit, b_shit, prize = machines_strings
	a_shit = a_shit[LEN_BUT_SEP:]
	b_shit = b_shit[LEN_BUT_SEP:]
	prize = prize[LEN_PRIZE_SEP:]
	a_shit, b_shit, prize = [int(x[2:]) for x in a_shit.split(", ")], [int(x[2:]) for x in a_shit.split(", ")], [int(x[2:]) for x in a_shit.split(", ")]
	return a_shit, b_shit, prize

def solve_machines(machines_strings_list):
	tot = 0
	for machines_strings in machines_strings_list: # machines_strings_list[:1]: # Just run the first thing...
		a_shit, b_shit, prize = get_machines(machines_strings)
		# Ok, so now we have the parameters. Time to just pass to the solve function.

		d_red_x, d_red_y = a_shit # red is basically A
		d_blue_x, d_blue_y = b_shit

		K_x, K_y = prize # The right hand side in our equations...

		# Now we basically have the equation shit, so it is time to actually solve the system of diophantine equations...

		solution = solve_system(d_red_x, d_blue_x, K_x, d_red_y, d_blue_y, K_y)
		if solution == None:
			continue # No solutions, just ignore.
	return tot

def main() -> int: # Main function...

	if len(sys.argv) != 2:
		print("Usage: "+str(sys.argv[0])+" INPUTFILE")
		return 1

	fh = open(sys.argv[1], "r")
	lines = fh.readlines()
	fh.close()

	# Split every four lines...
	n = 4
	machines = [lines[i:i+n-1] for i in range(0, len(lines), n)] # -1 because we don't want the empty lines in our stuff.
	print(machines)

	actual_thing = solve_machines(machines)
	print(actual_thing)

	return 0


if __name__=="__main__":

	ret = main()

	exit(ret)

```

This code has some sort of bug in it:

```

==============================
Infinite solutions...
Values:
44 44 44 84 84 84
==============================
Infinite solutions...
Values:
11 11 11 56 56 56
==============================
Infinite solutions...
Values:
25 25 25 77 77 77
==============================
Infinite solutions...
Values:
28 28 28 73 73 73
==============================
Infinite solutions...
Values:
43 43 43 66 66 66
==============================
Infinite solutions...
Values:
29 29 29 93 93 93
==============================
Infinite solutions...
Values:
57 57 57 17 17 17
==============================
Infinite solutions...
Values:
19 19 19 95 95 95
==============================
Infinite solutions...
Values:
14 14 14 57 57 57
==============================
0

```


so let's get to debugging....

## Debugging

I had the a_shit multiple times. I changed the code to this: `a_shit, b_shit, prize = [int(x[2:]) for x in a_shit.split(", ")], [int(x[2:]) for x in b_shit.split(", ")], [int(x[2:]) for x in prize.split(", ")]` and now it seems to atleast parse the input correctly. Now it calculates the solutions incorrectly:

```
Finite solutions...
Here is the actual_x: -16640.0
Finite solutions...
Here is the actual_x: 141.40454076367314
Finite solutions...
Here is the actual_x: 38.0
Finite solutions...
Here is the actual_x: -24121.161757830763
```

notice that the third solution is actually correct, but the other three are incorrect. There is a problem with this line: `actual_x = x0 + t*(d_blue_x)` we need to divide this by the gcd thing: `actual_x = x0 + t*(d_blue_x/gcd_thing)` and now I get this output:

```

[['Button A: X+94, Y+34\n', 'Button B: X+22, Y+67\n', 'Prize: X=8400, Y=5400\n'], ['Button A: X+26, Y+66\n', 'Button B: X+67, Y+21\n', 'Prize: X=12748, Y=12176\n'], ['Button A: X+17, Y+86\n', 'Button B: X+84, Y+37\n', 'Prize: X=7870, Y=6450\n'], ['Button A: X+69, Y+23\n', 'Button B: X+27, Y+71\n', 'Prize: X=18641, Y=10279']]
Finite solutions...
Here is the actual_x: 80.0
Finite solutions...
Here is the actual_x: 141.40454076367314
Finite solutions...
Here is the actual_x: 38.0
Finite solutions...
Here is the actual_x: 244.50163627863367
0

```

Now the first and third are correct... Let's try to figure out what is going on with the other two...

Both of these are equations which don't have solutions:

```

For the second and fourth claw machines, there is no combination of A and B presses that will ever win a prize.

```

so therefore we need to add some code to check if the solution doesn't actually even exist. Now to check for the solutions existence we need to take the module between the rhs and the gcd. If the modulo is zero, then solution exists and if not, then solution doesn't exist...

Let's add a check...

here:

```
if K_x % gcd_thing != 0 or K_y % gcd(d_red_y, d_blue_y) != 0:
		return None # No solution
```

Now we get this output:

```
Finite solutions...
Here is the actual_x: 80.0
Finite solutions...
Finite solutions...
Here is the actual_x: 38.0
Finite solutions...
0
```



Let's add integer division everywhere because reasons.

Ok, so now we also need to calculate y which is just `y = y0 - t*a/gcd_thing` and we just need to add the actual cost to the total: `tot += x_amount * A_PRICE + y_amount * B_PRICE`

Does it now work for the actual input????? FUCK! It doesn't work for the actual input. Let's see what is going wrong...

This sanity which I added fails: `assert actual_x >= 0 and actual_y >= 0 # Sanity checking...`

Now let's inspect the test case which fucks us over...

This testcase is fucking us over:

```
Button A: X+40, Y+26
Button B: X+13, Y+42
Prize: X=17433, Y=2622
```

So passing these parameters:

```
40
13
17433
```

to `extended_euclidean_algorithm` results in an erroneous output.

Let's investigate...

extended_euclidean_algorithm(40, 13, 17433)


Ok, so here is my current code:

```







'''

This function tries to give general integral solutions to the system of equations:

x1*a + x2*b = K1
x1*c + x2*d = K2

Using the diophantine equation.

'''

from math import gcd
import sys

'''
def extended_euclidean_algorithm(a,b,c):
	# Solves the euclidean algorithm a*x + b*y = c

	# First transform this into a = b*q + r where q is the quotient and r is the remainder...

	a_remaining = a
	b_current = b
	quotient_list = []
	remainder = 1
	while remainder != 0:
		quotient = a_remaining // b_current
		quotient_list.append(quotient)
		remainder = a_remaining % b_current
		assert quotient*b_current + remainder + a_remaining
		a_remaining = b_current
		b_current = remainder


		print("="*100)
		print(a_remaining)
		print(quotient)
		#print(b_current)
		#print(remainder)
	x0 = a_remaining
	y0 = quotient
	assert c % gcd(a,b) == 0
	scale_factor = c / gcd(a,b)

	x0_scaled = x0 * scale_factor
	y0_scaled = y0 * scale_factor
	print(x0_scaled)
	print(y0_scaled)
	assert x0_scaled*a + y0_scaled*b == c
	return
'''





A_PRICE = 3
B_PRICE = 1

def extended_euclidean_algorithm(a,b,c):
	# https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Description

	r0, r1 = a, b
	s0, s1 = 1, 0
	t0, t1 = 0, 1

	# The computation stops when one reaches a remainder  r_(k+1){\displaystyle r_{k+1}} which is zero; the greatest common divisor is then the last non zero remainder 	r	k	.	{\displaystyle r_{k}.}
	while r1 != 0:
		q = r0 // r1
		r0, r1 = r1, r0 - q*r1
		s0, s1 = s1, s0 - q*s1
		t0, t1 = t1, t0 - q*t1

	# Ok, so now I think that the gcd is in r0 because r1 is now zero.
	# Return the scaled versions
	k = c//r0# // r0
	s0 *= k
	t0 *= k

	s0 = (s0 % b + b) % b  # Ensures s0 is in [0, b)
	t0 = (c - a * s0) // b  # Recalculate t0 using the modified s0
	# Make coefficients nonnegative (if desired)
	# Adjust s0 modulo b to be nonnegative
	return r0, s0, t0 # r0 is gcd, s0 and t0 are the coefficients




BUT_SEP = "Button A: "
LEN_BUT_SEP = len(BUT_SEP)

PRIZE_SEP = "Prize: "
LEN_PRIZE_SEP = len(PRIZE_SEP)

def solve(x1, x2, a, b, c, d, K1, K2):
	# The first equation is x1*a + x*2*b = K1 , if the gcd(a,b) does not divide K1, then no solution exists...
	if gcd(a,b) % K1 != 0:
		return None # No solutions automatically.



def solve_system(d_red_x, d_blue_x, K_x, d_red_y, d_blue_y, K_y):

	# extended_euclidean_algorithm

	# Check for infinite solutions...
	if d_red_x*d_blue_y - d_blue_x*d_red_y == 0:
		print("Infinite solutions..."*1)
		print("Values:")
		print(d_red_x, d_blue_x, K_x, d_red_y, d_blue_y, K_y)
		print("="*30)
		exit(1)
		return None
		#exit(1)
	else:
		print("Finite solutions...")
	# The first equation on our list is just  the x coordinates.
	print("Print passing this stuff:")
	print(d_red_x)
	print(d_blue_x)
	print(K_x)
	if K_x % gcd(d_red_x, d_blue_x) != 0 or K_y % gcd(d_red_y, d_blue_y) != 0:
		return None # No solution
	initial_solution = extended_euclidean_algorithm(d_red_x, d_blue_x, K_x)
	gcd_thing, x0, y0 = initial_solution[0], initial_solution[1], initial_solution[2]
	#assert x0 >= 0 and y0 >= 0
	# Now initial_solution[0] is gcd and initial_solution[1] is x0 and initial_solution[2] is y0. These are already scaled, so no need to scale them here.
	assert d_red_x*x0 + d_blue_x*y0 == K_x
	# Check if there actually is a solution. If RHS % gcd != 0 then no solution exists



	# Now calculate the t thing. This can be used to calculate the bullshit.
	# We basically solved the first equation and then substituted the parameterized solution to the bottom equation and just solved for the parameter t (https://math.stackexchange.com/questions/2018981/how-do-you-solve-diophantine-equations-using-euclidean-algorithm)
	t = (K_y - x0*d_red_y-y0*d_blue_y)//(((d_blue_x*d_red_y)//gcd_thing)-((d_red_x*d_blue_y)//gcd_thing))

	# Now calculate the actual solution for the thing...

	# Notice that x = x0 + t*d_blue_x/gcd_thing

	print("x0: "+str(x0))
	print("y0: "+str(y0))

	if x0 == 0 or y0 == 0:
		return x0, y0

	actual_x = x0 + t*(d_blue_x//gcd_thing)
	actual_y = y0 - t*(d_red_x//gcd_thing)
	print("Here is the actual_x: "+str(actual_x))
	print("Here is the actual_y: "+str(actual_y))

	#if actual_x < 0 or actual_y < 0: # Sanity checking..
	#	return None

	# Check for the hundred shit:

	if actual_x > 100 or actual_y > 100:
		#print("poopoo")
		#exit(0)
		return None

	return (actual_x, actual_y)










def get_machines(machines_strings) -> list: # Returns the tuples which describe this machine.
	# This assumes that the stuff is in the format.
	a_shit, b_shit, prize = machines_strings
	a_shit = a_shit[LEN_BUT_SEP:]
	b_shit = b_shit[LEN_BUT_SEP:]
	prize = prize[LEN_PRIZE_SEP:]
	a_shit, b_shit, prize = [int(x[2:]) for x in a_shit.split(", ")], [int(x[2:]) for x in b_shit.split(", ")], [int(x[2:]) for x in prize.split(", ")]
	return a_shit, b_shit, prize

def solve_machines(machines_strings_list):
	tot = 0
	specific_index = 1 # [specific_index:specific_index+1]
	for machines_strings in machines_strings_list: # machines_strings_list[:1]: # Just run the first thing...
		print("Running this:")
		print("".join(machines_strings))
		a_shit, b_shit, prize = get_machines(machines_strings)
		# Ok, so now we have the parameters. Time to just pass to the solve function.

		d_red_x, d_red_y = a_shit # red is basically A
		d_blue_x, d_blue_y = b_shit

		K_x, K_y = prize # The right hand side in our equations...

		# Now we basically have the equation shit, so it is time to actually solve the system of diophantine equations...

		solution = solve_system(d_red_x, d_blue_x, K_x, d_red_y, d_blue_y, K_y)
		if solution == None:
			continue # No solutions, just ignore.
		# We have the solution. Just add the solution
		x_amount, y_amount = solution # x amount is basically red and y is blue.
		tot += x_amount * A_PRICE + y_amount * B_PRICE
	return tot

def main() -> int: # Main function...

	if len(sys.argv) != 2:
		print("Usage: "+str(sys.argv[0])+" INPUTFILE")
		return 1

	fh = open(sys.argv[1], "r")
	lines = fh.readlines()
	fh.close()

	# Split every four lines...
	n = 4
	machines = [lines[i:i+n-1] for i in range(0, len(lines), n)] # -1 because we don't want the empty lines in our stuff.
	print(machines)

	actual_thing = solve_machines(machines)
	print(actual_thing)

	return 0


if __name__=="__main__":

	ret = main()

	exit(ret)


```

and this bullshit doesn't work...

I think we should just program a bruteforce version and compare the solutions from that with our solutions and see what happens...

I added a another sanity checking spot: `assert d_red_y*actual_x + d_blue_y*actual_y == K_y`

After a shit ton of debugging I found the fucking bug. I had to comment out this part:

```
	if x0 == 0 or y0 == 0:
		print("fefe")
		#exit(0)
		if x0 > 100 or y0 > 100:
			return None
		return x0, y0
```

and now it works, this is because I didn't really understand that stuff.

Here is my final code:

```







'''

This function tries to give general integral solutions to the system of equations:

x1*a + x2*b = K1
x1*c + x2*d = K2

Using the diophantine equation.

'''

from math import gcd
import sys

'''
def extended_euclidean_algorithm(a,b,c):
	# Solves the euclidean algorithm a*x + b*y = c

	# First transform this into a = b*q + r where q is the quotient and r is the remainder...

	a_remaining = a
	b_current = b
	quotient_list = []
	remainder = 1
	while remainder != 0:
		quotient = a_remaining // b_current
		quotient_list.append(quotient)
		remainder = a_remaining % b_current
		assert quotient*b_current + remainder + a_remaining
		a_remaining = b_current
		b_current = remainder


		print("="*100)
		print(a_remaining)
		print(quotient)
		#print(b_current)
		#print(remainder)
	x0 = a_remaining
	y0 = quotient
	assert c % gcd(a,b) == 0
	scale_factor = c / gcd(a,b)

	x0_scaled = x0 * scale_factor
	y0_scaled = y0 * scale_factor
	print(x0_scaled)
	print(y0_scaled)
	assert x0_scaled*a + y0_scaled*b == c
	return
'''





A_PRICE = 3
B_PRICE = 1

def extended_euclidean_algorithm(a,b,c):
	# https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Description

	r0, r1 = a, b
	s0, s1 = 1, 0
	t0, t1 = 0, 1

	# The computation stops when one reaches a remainder  r_(k+1){\displaystyle r_{k+1}} which is zero; the greatest common divisor is then the last non zero remainder 	r	k	.	{\displaystyle r_{k}.}
	while r1 != 0:
		q = r0 // r1
		r0, r1 = r1, r0 - q*r1
		s0, s1 = s1, s0 - q*s1
		t0, t1 = t1, t0 - q*t1

	# Ok, so now I think that the gcd is in r0 because r1 is now zero.
	# Return the scaled versions
	k = c//r0# // r0
	if c % r0 != 0:
		print("FUCK!"*1000)
		exit(1)
	s0 *= k
	t0 *= k

	s0 = (s0 % b + b) % b  # Ensures s0 is in [0, b)
	t0 = (c - a * s0) // b  # Recalculate t0 using the modified s0
	if (c - a * s0) % b != 0:
		print("FUCK!"*100)
		exit(1)
	# Make coefficients nonnegative (if desired)
	# Adjust s0 modulo b to be nonnegative
	return r0, s0, t0 # r0 is gcd, s0 and t0 are the coefficients




BUT_SEP = "Button A: "
LEN_BUT_SEP = len(BUT_SEP)

PRIZE_SEP = "Prize: "
LEN_PRIZE_SEP = len(PRIZE_SEP)

def solve(x1, x2, a, b, c, d, K1, K2):
	# The first equation is x1*a + x*2*b = K1 , if the gcd(a,b) does not divide K1, then no solution exists...
	if gcd(a,b) % K1 != 0:
		return None # No solutions automatically.



def solve_system(d_red_x, d_blue_x, K_x, d_red_y, d_blue_y, K_y):

	# extended_euclidean_algorithm

	# Check for infinite solutions...
	if d_red_x*d_blue_y - d_blue_x*d_red_y == 0:
		print("Infinite solutions..."*1)
		print("Values:")
		print(d_red_x, d_blue_x, K_x, d_red_y, d_blue_y, K_y)
		print("="*30)
		exit(1)
		return None
		#exit(1)
	else:
		print("Finite solutions...")
	# The first equation on our list is just  the x coordinates.
	print("Print passing this stuff:")
	print(d_red_x)
	print(d_blue_x)
	print(K_x)
	if K_x % gcd(d_red_x, d_blue_x) != 0 or K_y % gcd(d_red_y, d_blue_y) != 0:
		print("Shitfuck"*100)
		return None # No solution
	initial_solution = extended_euclidean_algorithm(d_red_x, d_blue_x, K_x)
	gcd_thing, x0, y0 = initial_solution[0], initial_solution[1], initial_solution[2]
	assert gcd_thing == gcd(d_red_x,d_blue_x)
	#assert x0 >= 0 and y0 >= 0
	# Now initial_solution[0] is gcd and initial_solution[1] is x0 and initial_solution[2] is y0. These are already scaled, so no need to scale them here.
	assert d_red_x*x0 + d_blue_x*y0 == K_x
	# Check if there actually is a solution. If RHS % gcd != 0 then no solution exists



	# Now calculate the t thing. This can be used to calculate the bullshit.
	# We basically solved the first equation and then substituted the parameterized solution to the bottom equation and just solved for the parameter t (https://math.stackexchange.com/questions/2018981/how-do-you-solve-diophantine-equations-using-euclidean-algorithm)

	# We need to do this bullshit because reasons...

	if (d_blue_x*d_red_y) % gcd_thing != 0 or (d_red_x*d_blue_y) % gcd_thing != 0 or (K_y - x0*d_red_y-y0*d_blue_y) % ((((d_blue_x*d_red_y)//gcd_thing)-((d_red_x*d_blue_y)//gcd_thing))) != 0:
		print("Fuckooofffff")
		return None


	t = (K_y - x0*d_red_y-y0*d_blue_y)//(((d_blue_x*d_red_y)//gcd_thing)-((d_red_x*d_blue_y)//gcd_thing))
	print("t: "+str(t))
	# Now calculate the actual solution for the thing...

	# Notice that x = x0 + t*d_blue_x/gcd_thing

	print("x0: "+str(x0))
	print("y0: "+str(y0))
	'''
	if x0 == 0 or y0 == 0:
		print("fefe")
		#exit(0)
		if x0 > 100 or y0 > 100:
			return None
		return x0, y0
	'''
	actual_x = x0 + t*(d_blue_x//gcd_thing)
	actual_y = y0 - t*(d_red_x//gcd_thing)
	assert d_red_x*x0 + d_blue_x*y0 == K_x
	#assert d_red_y*x0 + d_blue_y*y0 == K_y
	assert d_red_x*actual_x + d_blue_x*actual_y == K_x

	print("Here is the actual_x: "+str(actual_x))
	print("Here is the actual_y: "+str(actual_y))

	#if actual_x < 0 or actual_y < 0: # Sanity checking..
	#	return None

	# Check for the hundred shit:

	if actual_x > 100 or actual_y > 100:
		print("poopoo")
		exit(0)
		return None
	assert d_red_y*actual_x + d_blue_y*actual_y == K_y
	return (actual_x, actual_y)










def get_machines(machines_strings) -> list: # Returns the tuples which describe this machine.
	# This assumes that the stuff is in the format.
	a_shit, b_shit, prize = machines_strings
	a_shit = a_shit[LEN_BUT_SEP:]
	b_shit = b_shit[LEN_BUT_SEP:]
	prize = prize[LEN_PRIZE_SEP:]
	a_shit, b_shit, prize = [int(x[2:]) for x in a_shit.split(", ")], [int(x[2:]) for x in b_shit.split(", ")], [int(x[2:]) for x in prize.split(", ")]
	return a_shit, b_shit, prize

def solve_machines(machines_strings_list):
	tot = 0
	specific_index = 1 # [specific_index:specific_index+1]
	for machines_strings in machines_strings_list: # machines_strings_list[:1]: # Just run the first thing...
		print("Running this:")
		print("".join(machines_strings))
		a_shit, b_shit, prize = get_machines(machines_strings)
		# Ok, so now we have the parameters. Time to just pass to the solve function.

		d_red_x, d_red_y = a_shit # red is basically A
		d_blue_x, d_blue_y = b_shit

		K_x, K_y = prize # The right hand side in our equations...

		# Now we basically have the equation shit, so it is time to actually solve the system of diophantine equations...

		solution = solve_system(d_red_x, d_blue_x, K_x, d_red_y, d_blue_y, K_y)
		sol_bruteforce = bruteforce_solve(d_red_x, d_blue_x, K_x, d_red_y, d_blue_y, K_y)
		if solution != sol_bruteforce: # Mismatch. A bug.
			print("Bruteforced solution: "+str(sol_bruteforce))
			print("Our solution: "+str(solution))
			x_red, x_blue = solution
			print("x_red * d_red_x + x_blue * d_blue_x == "+str(x_red * d_red_x + x_blue * d_blue_x))
			print("K_x: "+str(K_x))
			print("x_red*d_red_y + x_blue * d_blue_y == "+str(x_red*d_red_y + x_blue * d_blue_y))
			print("K_y: "+str(K_y))
			exit(1)
		if solution == None:
			continue # No solutions, just ignore.
		# We have the solution. Just add the solution
		x_amount, y_amount = solution # x amount is basically red and y is blue.
		tot += x_amount * A_PRICE + y_amount * B_PRICE
	return tot



def bruteforce_solve(d_red_x, d_blue_x, K_x, d_red_y, d_blue_y, K_y):
	for x_red in range(101):
		for x_blue in range(101):
			if x_red * d_red_x + x_blue * d_blue_x == K_x and x_red*d_red_y + x_blue * d_blue_y == K_y:
				return (x_red, x_blue)
	return None




def main() -> int: # Main function...

	if len(sys.argv) != 2:
		print("Usage: "+str(sys.argv[0])+" INPUTFILE")
		return 1

	fh = open(sys.argv[1], "r")
	lines = fh.readlines()
	fh.close()

	# Split every four lines...
	n = 4
	machines = [lines[i:i+n-1] for i in range(0, len(lines), n)] # -1 because we don't want the empty lines in our stuff.
	print(machines)

	actual_thing = solve_machines(machines)
	print(actual_thing)

	return 0


if __name__=="__main__":

	ret = main()

	exit(ret)


```

On to part 2!!!!

## Part 2

Ok, so part 2 is just basically our optimization. The previous code worked here too! (Had to limit the )















