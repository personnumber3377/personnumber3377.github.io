
# Making my chemical equation balancer better.

Long ago I made a chemical equation balancer: https://github.com/personnumber3377/Chemicalequationbalancer/tree/master this is the original version. It lacks a certain functionality which I want. I want to be able to solve a system of chemical equations.

I actually need to remind myself of how to use this. I used to do my chemistry homework with this tool, because I was too lazy to go through the computations myself.

Let's make a system of equations for the hypothetical scenario where we burn sugar, and then we use that carbon dioxide as a reagent in the reaction between it and hydrogen to create methane. So the unbalanced chemical reactions would look like this:

```

C6H12O6 + O2 -> 6CO2 + 6H20

and

CO2 + H2 -> CH4 + H2O

```

Now as the input to the program we should type the first equation as this:

```
C6.H12.O6+O2->C1.O2+H2.O1
y
C1.O2+H2->C1.H4+H2.O1
n
C1.H4
C6.H12.O6
100
```

Here we have 100 grams of glucose and we want to find out how many grams of methane we can create from that resulting carbon dioxide when we burn the sugar. This input results in an error:

```

Paskaaa:
['C6.H12.O6', 'O2', 'C1.O2', 'H2.O1', 'H2', 'C1.H4']
[[[1, 6, 6, 6], (['C6.H12.O6', 'O2'], ['C1.O2', 'H2.O1'])], [[1, 4, 1, 2], (['C1.O2', 'H2'], ['C1.H4', 'H2.O1'])]]
[[1, 6, 6, 6], (['C6.H12.O6', 'O2'], ['C1.O2', 'H2.O1'])]
C6.H12.O6
all_substances == ['C6.H12.O6', 'O2', 'C1.O2', 'H2.O1', 'H2', 'C1.H4']
oofshit == [[[1, 6, 6, 6], (['C6.H12.O6', 'O2'], ['C1.O2', 'H2.O1'])], [[1, 4, 1, 2], (['C1.O2', 'H2'], ['C1.H4', 'H2.O1'])]]
oofshit[0][0] == [1, 6, 6, 6]
substance2 == C1.H4
substance1 == C6.H12.O6
Traceback (most recent call last):
  File "/home/cyberhacker/Asioita/Ohjelmointi/Python/Chemicalequationbalancer/balancerdev", line 573, in <module>
    balanceformula()
  File "/home/cyberhacker/Asioita/Ohjelmointi/Python/Chemicalequationbalancer/balancerdev", line 534, in balanceformula
    ratio = getratio(limiting_factor, unknown, oofshit, all_substances)
  File "/home/cyberhacker/Asioita/Ohjelmointi/Python/Chemicalequationbalancer/balancerdev", line 348, in getratio
    print(oofshit[0][0][all_substances.index(substance2)])
IndexError: list index out of range


```

This is because the oofshit variable is a list of lists and every element in said list has their own equation sort of.

This is the reason why it does not work, because it can't figure out the ratio when the substance which we want is in a different chemical equation than the substance which we know.

I actually posted this question on stackoverflow: https://stackoverflow.com/questions/72876879/programmatically-solve-for-chemical-molar-ratio-between-multiple-reactions and I never got around to implement this.


So I think I need to create a tree type structure, where the starting substance is the substance we know and the end is the substance which we want to know and the edges in the way are the ratios between those two substances.

Also btw looking at my old code makes me cringe so hard.


So, let's implement it!

After a bit of fiddling around I came up with this:

```

# This is a small library to find the ratio between the substance which we want to know and the starting substance. It is implemented as a tree with the known substance as the root and the wanted substance as the destination.


class Elemnode:
	def __init__(self, substance):
		#self.coefficient = coefficient
		self.substance = substance
		self.next_substances = [] # these are actually just a list of "Elemedge" objects
		self.previous_substances = [] # Same with this.
		self.visited = False # This is used to prevent going into an infinite loop when traversing the tree when there is a circular path.


class Elemedge:
	
	def __init__(self, substance1_node, substance2_node, ratio):
		
		self.next_substance = substance2_node
		self.previous_substance = substance1_node
		#self.ratio = coeff2/coeff1
		self.ratio = ratio


class Elemtree:
	def __init__(self, stuff):

		# stuff is basically shitoof in the original script.

		# [[[1, 6, 6, 6], (['C6.H12.O6', 'O2'], ['C1.O2', 'H2.O1'])], [[1, 4, 1, 2], (['C1.O2', 'H2'], ['C1.H4', 'H2.O1'])]]

		self.substances = [] # a list of the nodes of the graph.

		self.stuff = stuff

		self.nodes = []

		self.edges = []

	def construct_tree(self):

		# Loop over all of the chemical equations and add the nodes as we go.

		for equation_stuff in self.stuff:
			print(equation_stuff)
			# Now equation_stuff is of the format [<equation_coefficients> [<elements_left_side>, <elements_right_side>]]
			coeffs = equation_stuff[0]

			# First construct the nodes (the edges aka. "connections" will be added later on)

			rhs_nodes = []
			lhs_nodes = []

			rhs_substances = equation_stuff[1][1]
			rhs_coefficients = coeffs[len(equation_stuff[1][0]):]
			lhs_substances = equation_stuff[1][0]
			for i, subst in enumerate(rhs_substances):


				for subst_node in self.nodes:
					# This is to check if the substance already is in the tree, so we do not add two nodes with the same substance.
					if subst_node.substance == subst:
						rhs_nodes.append(subst_node)
						continue

				new_node = Elemnode(subst)



				self.nodes.append(new_node)

				rhs_nodes.append(new_node)


			lhs_substances = equation_stuff[1][0]
			lhs_coefficients = coeffs[:len(lhs_substances)]

			for i, subst in enumerate(lhs_substances):
				for subst_node in self.nodes:
					# This is to check if the substance already is in the tree, so we do not add two nodes with the same substance.
					if subst_node.substance == subst:
						lhs_nodes.append(subst_node)
						continue
				new_node = Elemnode(subst)

				self.nodes.append(new_node)

				lhs_nodes.append(new_node)
				
			lhs_coefficients = coeffs[:len(lhs_substances)]
			rhs_substances = equation_stuff[1][1]

			# Create the edges. These are the ratios basically between the compounds.

			for i, substance in enumerate(lhs_substances):
				
				# Now create a node for every rhs substance.

				for j, substance2 in enumerate(rhs_substances):

					# Now get the ratio

					lhs_coeff = lhs_coefficients[i]
					rhs_coeff = rhs_coefficients[j]
					ratio = rhs_coeff/lhs_coeff

					# now just create the node.

					#new_edge = Elemedge(substance, substance2, ratio)
					# First just put the edge in to this tree.

					#self.edges.append(new_edge)

					# Now put this new edge to the substance.

					for substance_node in self.nodes:
						if substance_node.substance == substance:
							#substance_node.next_substances.append(new_edge)

							for substance2_node in self.nodes:
								if substance2_node.substance == substance2:
									'''
									new_edge = Elemedge(substance, substance2, ratio)
									substance_node.next_substances.append(new_edge)
									substance2_node.previous_substances.append(new_edge)
									'''

									new_edge = Elemedge(substance_node, substance2_node, ratio)
									substance_node.next_substances.append(new_edge)
									substance2_node.previous_substances.append(new_edge)
						# # Now put this new edge to the substance.
					





				## Create the edge here:
				
				#new_edge = Elemedge(substance)




			# Now set the connections (edges) (old)
			"""
			for lhs_node in lhs_nodes: # If we want to go backwards
				for rhs_node in rhs_nodes:
					rhs_node.previous_substances.append(lhs_node) # set the previous thing

			for rhs_node in rhs_nodes: # If we want to go forwards
				for lhs_node in lhs_nodes:
					lhs_node.next_substances.append(rhs_node)
			"""

		return

	def traverse_tree(self, begin_substance, end_substance):

		# This get's the route from begin_substance to end_substance.

		for node in self.nodes:
			if node.substance == begin_substance:
				return self.traverse_node(node, node, end_substance)


	def traverse_node(self, node, begin_node, end_substance, child_edge = None):
		print("node.substance == "+str(node.substance))
		if node.substance == end_substance:
			#subst1 = begin_node.substance
			#subst2 = end_substance.substance
			prev_edge = child_edge
			# get the previous edge element
			#for child_node in node.previous_substances:
			

			return [prev_edge, node]

		if node.next_substances == []:
			return None
		print("next substances: "+str(node.next_substances))
		for child_edge in node.next_substances:
			next_subst = child_edge.next_substance
			print("Next substance: "+str(next_subst))
			if self.traverse_node(next_subst, begin_node, end_substance) != None:
				return [child_edge, node]+self.traverse_node(next_subst, begin_node, end_substance,child_edge)
				

		return None
	
	def get_ratio(self, substance1, substance2):
		# first get the route
		route = self.traverse_tree(substance1, substance2)
		# Then get the reagents and the products.
		substance_tuples = [x[1] for x in self.stuff]

		reactants, products = [x[0] for x in substance_tuples], [x[1] for x in substance_tuples]

		# If the element is in the 

def fail(string:str) -> None:
	print("[-] "+str(string))
	exit(1)


def run_test(in_list, answer) -> None:

	stuff = in_list[0] #[[[1, 6, 6, 6], (['C6.H12.O6', 'O2'], ['C1.O2', 'H2.O1'])], [[1, 4, 1, 2], (['C1.O2', 'H2'], ['C1.H4', 'H2.O1'])]] # this is the oofshit when running with "sample_system_of_equations.txt" file.
	print("stuff == "+str(stuff))
	tree = Elemtree(stuff)

	tree.construct_tree()
	other_stuff = in_list[1]
	print("other_stuff == "+str(other_stuff))
	print("stuff == "+str(stuff))
	print("Tree: "+str(tree))
	#wanted_materials = in_list[2]
	#start_material = in_list[0]
	#out_material = in_list[1]

	#wanted_materials = stuff[2]
	start_material = other_stuff[0]
	out_material = other_stuff[1]

	route = tree.traverse_tree(start_material, out_material)
	print("Route: "+str(route))
	#print("Elements: "+str([x.substance for x in route]))
	
	ratio_list = []
	for thing in route:
		if isinstance(thing, Elemnode):
			print("elemnode.x == "+str(thing.substance))
		elif isinstance(thing,Elemedge):
			print("ratio == "+str(thing.ratio))
			ratio_list.append(thing.ratio)
	x = 1
	for thing in ratio_list:
		x = x * thing
	print("x: "+str(x))
	#assert round(x,3) == round(float(answer), 3)
	if round(x,3) != round(float(answer), 3):
		fail("In list: "+str(in_list)+" resulted in this answer: "+str(x)+" when the correct answer would have been: "+str(answer))

	return


def run_tests(tests: list):
	
	inputs = tests[0]
	correct_answers = tests[1]

	thing = [(inputs[i], correct_answers[i]) for i in range(len(correct_answers))]


	for input_list, correct_answer in thing:

		# now run the main function.
		print("input_list == "+str(input_list))
		print("correct answer: "+str(correct_answer))
		run_test(input_list, correct_answer)

	print("All tests ran correctly!")

	return



if __name__=="__main__":

	# Test suite.

	#correct_answers = [6.00]

	#in_lists = [[[[1, 6, 6, 6], (['C6.H12.O6', 'O2'], ['C1.O2', 'H2.O1'])], [[1, 4, 1, 2], (['C1.O2', 'H2'], ['C1.H4', 'H2.O1'])]]]
	# other test is this: [[[[1, 2, 1], (['C6.H12.O6', 'O2'], ['C1.O2', 'H2.O1'])], [[1, 4, 1, 2], (['C1.O2', 'H2'], ['C1.H4', 'H2.O1'])]]]
	# tests_list = [[[[[1, 6, 6, 6], (['C6.H12.O6', 'O2'], ['C1.O2', 'H2.O1'])], [[1, 4, 1, 2], (['C1.O2', 'H2'], ['C1.H4', 'H2.O1'])]], ['C6.H12.O6', 'C1.H4']], [6.00]]

	tests_list = [[[[[[1, 6, 6, 6], (['C6.H12.O6', 'O2'], ['C1.O2', 'H2.O1'])], [[1, 4, 1, 2], (['C1.O2', 'H2'], ['C1.H4', 'H2.O1'])]], ['C6.H12.O6', 'C1.H4']]], [6.00]]

	run_tests(tests_list)

	exit(0)


```

now we need to integrate this into my initial code. Here in the getratio function it seems to be a good place to put the tree traversing code:

```

def getratio(substance1, substance2, oofshit, all_substances):
	'''
	oofshit: the solutions to the problem
	all_substances: a list of all the substances
	substance1: a substance
	substance2: a substance


	'''

	# to get the stoichiometric ratio between two compunds is to find the ratio between their coefficients in a chemical equation:
	#print("Paskaaa:")
	#print(all_substances)
	#print(oofshit)
	#print(oofshit[0])
	#print(substance1)
	#print(oofshit[0][0][all_substances.index(substance2)])
	#print(oofshit[0][0][all_substances.index(substance1)])
	#ratio = oofshit[0][0][all_substances.index(substance1)]/oofshit[0][0][all_substances.index(substance2)]
	
	# Instead of doing the janky stuff, let's use the treething tree solver. #  [[[1, 6, 6, 6], (['C6.H12.O6', 'O2'], ['C1.O2', 'H2.O1'])], [[1, 4, 1, 2], (['C1.O2', 'H2'], ['C1.H4', 'H2.O1'])]]
	print("Here is the oofshit: "+str(oofshit))
	# First construct the tree.
	tree = Elemtree(oofshit)
	tree.construct_tree()
	# Now actually find the wanted elements. Remember that substance2 is the substance which we want to find
	route = tree.traverse_tree(substance1, substance2)
	print("Route: "+str(route))
	ratio_list = []
	for thing in route:
		if isinstance(thing, Elemnode):
			print("elemnode.x == "+str(thing.substance))
		elif isinstance(thing,Elemedge):
			print("ratio == "+str(thing.ratio))
			ratio_list.append(thing.ratio)
	x = 1
	for thing in ratio_list:
		x = x * thing
	print("x: "+str(x))
	return 1 / x # We need to divide one by x , because then we get the correct actual ratio

```

and tada! We can now find the ratios between the substances across multiple chemical equations. Let's try it out with a pair of chemical equations which have no elements common and see what we get.

```
line 360, in getratio
    for thing in route:
TypeError: 'NoneType' object is not iterable

```

tada! Maybe we should add some error checking where we check the type of `route` and then stop if it is nonetype.

After commiting I am now in the 51cb9dd0549085bf9e701fe98d7c66067126db5e commit .










