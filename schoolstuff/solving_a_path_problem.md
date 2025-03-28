
# Solving a path problem in math

I was given the next prompt:

```
In a meadow temperature varies according to the function T(x,y,z)=4*x+2*y+2*z and a bee is seen flying along the path r(t) = {x(t) = t**3/40 + 7*t/30+5 , y(t) = -t**3/(60)-8*t**2/15+20 , z(t) = 2*t**2/15 + 7*t/30 - 10}
where t is in [0,10]. Applying the chain rule, find the highest and lowest peaks of the temperature experienced by the bee.

```

One way to do this is to just iterate over the range and do it that way, but we can also do it symbolically.

The way we do this symbolically is that we just replace the x, y and z with the corresponding parametric expressions and then we just have a find the minimum or maximum thing.

Let's implement a function.


Here seems a solution:

```

def calculate_min_max_parametric_path(f, variables, parametric, param_variable, start, end):
	# Now this calculates the minimum and maximum along the parametric path on the interval start, end...
	assert len(variables) == len(parametric) # Should be the same stuff.
	f_substituted = f
	# Now substitute the thing...
	for v, par in zip(variables, parametric):
		# Substitute the variable with the parametric representation...
		f_substituted = f_substituted.subs(v, par)
	# Now we should have a function of one variable, the parametric variable param_variable
	print("Free symbols: "+str(f_substituted.free_symbols))
	assert f_substituted.free_symbols == {param_variable}
	# Now iterate over the critical points. Also include the end points maybe???
	# crit_points = [start, end]
	# critical_points = sp.solveset(dg_dt, t, domain=sp.Interval(t_range[0], t_range[1]))
	# critical_points = sp.solveset(dg_dt, t, domain=sp.Interval(t_range[0], t_range[1]))
	print("Substituted stuff: "+str(f_substituted))
	differentiated = diff(f_substituted, param_variable)
	crit_points = list(solveset(differentiated, param_variable, domain=Interval(start, end))) # [start, end]
	# Now add the start and end to the points.
	crit_points += [start, end]
	assert len(crit_points) >= 2 # Should be like this?????
	# Now iterate over the crit points and then get the minimum and maximum maybe????
	max_par = None
	min_par = None
	max_val = None
	min_val = None
	for t in crit_points:
		value = f_substituted.subs(param_variable, t) # Replace the shit here...
		if not min_val or value <= min_val:
			min_par = t
			min_val = value
		elif not max_val or value >= max_val:
			max_par = t
			max_val = value
	return min_par, max_par, min_val, max_val # Return the stuff

```
























