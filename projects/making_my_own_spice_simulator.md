
## Making my own spice simulator.

I have always been curious as to how spice simulators work. I think that they solve the differential equations which describe the movement of charges, but I wanted to learn how they worked in more depth. This is my journey of implementing my own spice simulator.

## Digging through existing simulators.

My preferred programming language is python so I searched for Spice simulators which were written in that language. I quickly came across this: https://github.com/PySpice-org/PySpice which seems quite manageable.

The source code is only around 17k lines:

```
cyberhacker@cyberhacker-h8-1131sc:~/Asioita/Ohjelmointi/spicesimulation/plagiarized/PySpice/PySpice$ find -name \*.py | xargs wc -l
   176 ./Tools/EnumFactory.py
    53 ./Tools/Path.py
   292 ./Tools/File.py
    84 ./Tools/StringTools.py
     0 ./Tools/__init__.py
   477 ./Probe/WaveForm.py
     0 ./Probe/__init__.py
    43 ./Probe/Plot.py
    64 ./Physics/PhysicalConstants.py
    66 ./Physics/SemiConductor.py
    30 ./Physics/Resistor.py
     0 ./Physics/__init__.py
    40 ./Physics/MaterialProperties.py
   164 ./Math/Calculus.py
    46 ./Math/__init__.py
    48 ./Doc/ExampleTools.py
     0 ./Doc/__init__.py
   470 ./Scripts/pyspice_post_installation.py
    70 ./Scripts/cir2py.py
     0 ./Scripts/__init__.py
  1292 ./Spice/Netlist.py
  1715 ./Spice/BasicElement.py
   407 ./Spice/Expression/Ast.py
   346 ./Spice/Expression/Parser.py
    19 ./Spice/Expression/__init__.py
   395 ./Spice/ElementParameter.py
  1236 ./Spice/Simulation.py
  1324 ./Spice/NgSpice/Shared.py
   127 ./Spice/NgSpice/Simulation.py
    90 ./Spice/NgSpice/SimulationType.py
   234 ./Spice/NgSpice/RawFile.py
    23 ./Spice/NgSpice/__init__.py
   162 ./Spice/NgSpice/Server.py
    73 ./Spice/Xyce/Simulation.py
   175 ./Spice/Xyce/RawFile.py
     0 ./Spice/Xyce/__init__.py
   140 ./Spice/Xyce/Server.py
   150 ./Spice/Library.py
   865 ./Spice/HighLevelElement.py
   417 ./Spice/RawFile.py
  1486 ./Spice/Parser_jmgc.py
  1057 ./Spice/Parser.py
    75 ./Spice/__init__.py
   106 ./DeviceLibrary/__init__.py
    60 ./Plot/BodeDiagram.py
     0 ./Plot/__init__.py
    27 ./__init__.py
    65 ./Config/ConfigInstall.py
     0 ./Config/__init__.py
  1944 ./Unit/Unit.py
   330 ./Unit/SiUnits.py
   244 ./Unit/__init__.py
     0 ./Logging/__init__.py
    69 ./Logging/Logging.py
 16776 total

```

Out of these subdirectories the interesting ones are the Math,  Physics,  Spice and Unit .

Ok after a bit of digging I found out that the simulation of the circuit is actually done by either ngspice or Xyce which so lets look at the source code of those. I was quite suspicious about the low line count. Lets get the total lines inside src/ for ngspice:

```
  515131 total
```

There we go! That seems more like it!


So going through the entire ngspice code base is not going to happen, because I am dumb. Instead of that lets try to do some physics reading. After a bit of reading I basically have an idea of how I am going to go about doing this. I am going to Implement a "Component" class which, as the name suggests, can be any type of component. battery, resistor, capacitor, anything. Then for all the batteries or voltage sources just update the voltage at every Node. I am a bit sussed out about transistors, but I think that I can simulate that with a switch which is controlled by the input voltage. We also need to implement a Node object which is an electrical node.


Also I think that this is a very good chance to learn about inheritance in python.

Anyway, lets first think this out on a somewhat high level before jumping in as I would normally do, because I think this actually requires some planning ahead of time:

The algorithm will basically be:

- Calculate effective resistance of each component.
- Calculate the total current.
- Calculate the voltage at the desired point.


After a bit of digging I found this: https://github.com/giaccone/SpicePy which is a spice simulator written in pure python. The only criticism I have of it is that it does not support transistors, but lets take a look at it anyway.

So after staring at formulas and the code for a long bit I think that I have alteast some sort of understanding of what does what. Calling the library on a siple circuit with a power source and a singular resistor basically calls the dc_solve function. The dc_solve function first creates the conductance matrix (self.G):

```
def dc_solve(net):
    """
    "dc_solve" solves DC network

    :return:
        * x, solution
    """
    print("dc_solve")
    net.conductance_matrix()
    #print("conductance_matrix: "+str(net.conductance_matrix()))
    net.rhs_matrix()

    # linear system definition
    print("net.G == "+str(net.G))
    print("net.rhs == "+str(net.rhs))
    net.x = spsolve(net.G, net.rhs)
    print("net.x == "+str(net.x))
```

and then after that it creates the right hand side matrix. The right hand side matrix is basically this when not in transient analysis:

```

            # initialize rhs
            rhs = [0] * (self.node_num + len(self.isort[1]) + len(self.isort[3]) + len(self.isort[5]) + len(self.isort[8]))

            # get index
            NL = len(self.isort[1])
            indexV = sorted(self.isort[3])
            indexI = self.isort[4]

            # cycle on independent voltage sources
            for k, iv in enumerate(indexV):
                # update rhs
                rhs[self.node_num + NL + k] += self.values[iv]

            # cycle on independent current sources
            for ii in indexI:
                # get nodes
                N1, N2 = self.nodes[ii]

                if N1 == 0:
                    # update rhs
                    rhs[N2 - 1] += self.values[ii]

                elif N2 == 0:
                    # update rhs
                    rhs[N1 - 1] -= self.values[ii]

                else:
                    # update rhs
                    rhs[N1 - 1] -= self.values[ii]
                    rhs[N2 - 1] += self.values[ii]

            self.rhs = np.array(rhs)
```

it first initializes the matrix to zeros with length (amount of nodes + num of all components which are NOT resistors) This code basically for all of the voltage sources puts that voltage of the voltage source to that index of the resulting array. To RHS is basically the V vector with the currents.

The G matrix is the conductance matrix. Conductance is basically defined as the repricocal of the resistance. I dunno how this actually works physically but I am just going to accept that for now.

The conductance matrix is calculated by this algorithm:

```
        g = []
        g_row = []
        g_col = []

        # reorder if necessary
        if self.isort is None:
            self.reorder()

        # get index
        indexR = self.isort[0]
        indexL = sorted(self.isort[1])
        indexV = sorted(self.isort[3])
        indexE = sorted(self.isort[5])
        indexF = sorted(self.isort[6])
        indexG = sorted(self.isort[7])
        indexH = sorted(self.isort[8])

        print("indexR == "+str(indexR))
        print("indexL == "+str(indexL))
        print("indexV == "+str(indexV))
        print("indexE == "+str(indexE))
        print("indexF == "+str(indexF))
        print("indexG == "+str(indexG))
        print("indexH == "+str(indexH))


        # cycle on resistances
        for ir in indexR:
            # get nores
            print("Resistor")
            print("self.nodes: "+str(self.nodes))
            N1, N2 = self.nodes[ir]

            # detect connection
            if (N1 == 0) or (N2 == 0): # if grounded...
                # diagonal term
                print("Grounded")
                g.append(1.0 / self.values[ir])
                g_row.append(max([N1, N2]) - 1)
                g_col.append(max([N1, N2]) - 1)

            else:                      # if not grounded...
                # diagonal term
                g.append(1.0 / self.values[ir])
                g_row.append(N1 - 1)
                g_col.append(N1 - 1)

                # diagonal term
                g.append(1.0 / self.values[ir])
                g_row.append(N2 - 1)
                g_col.append(N2 - 1)

                # N1-N2 term
                g.append(-1.0 / self.values[ir])
                g_row.append(N1 - 1)
                g_col.append(N2 - 1)

                # N2-N1 term
                g.append(-1.0 / self.values[ir])
                g_row.append(N2 - 1)
                g_col.append(N1 - 1)
```

This is repeated for the other components like inductors and stuff, but we are only going to make the conductance matrix for now. The indexR variable has the indexes of all of the resistor connections and the self.nodes has all of the connections defined in the example file:

```
* Example of DC network

V1 1 0 5 
R2 2 1 2 
R1 2 1 1
R3 3 2 10
R4 0 3 10
.op
```

This yields this as the nodes:

```
self.nodes: [[1 0]
 [2 1]
 [2 1]
 [3 2]
 [0 3]]
```

I found these two pages which are really useful imo: http://lpsa.swarthmore.edu/Systems/Electrical/mna/MNA2.html and http://lpsa.swarthmore.edu/Systems/Electrical/mna/MNA3.html

Lets first make the algorithm quickly in python before advancing.



I actually got it now! The first resistor equations are added because then the voltages are known. If we didn't add the currents into the matrix then the only solution to the matrix would be that all voltages would be zero, and it makes sense because we are not adding the currents in to it. The repricocal of the resistance times the voltage is the current because U = R*I therefore I = (1/R)*U . This causes us to actually find the correct solution instead of all zeroes.

Here is my algorithm:

```
def generate_matrix(indexes, values):
	print("Indexes: "+str(indexes))
	print("Values: "+str(values))
	max_row_num = max([thing[0] for thing in indexes])
	max_col_num = max([thing[1] for thing in indexes])
	matrix = [[0.0 for _ in range((max_col_num+1))] for _ in range(max_row_num+1)]
	count = 0
	print("Indexes: "+str(indexes))
	print("Values: "+str(values))
	for ind in indexes:
		print("rrrrrrrrrrrrrr: "+str(matrix))
		print("ind == "+str(ind))
		if ind[0] == 0 and ind[1] == 0:
			print("Updating matrix[0][0] with value : "+str(values[count]))
			print("Matrix before: "+str(matrix))

		matrix[ind[0]][ind[1]] += values[count]
		count += 1
		if ind[0] == 0 and ind[1] == 0:
			print("Matrix after: "+str(matrix))

	print("Matrix: "+str(matrix))
	return matrix

def get_conductance_matrix(resistor_values, nodes):
	
	'''
	        for ir in indexR:
            # get nores
            print("Resistor")
            print("self.nodes: "+str(self.nodes))
            N1, N2 = self.nodes[ir]

            # detect connection
            if (N1 == 0) or (N2 == 0): # if grounded...
                # diagonal term
                print("Grounded")
                g.append(1.0 / self.values[ir])
                g_row.append(max([N1, N2]) - 1)
                g_col.append(max([N1, N2]) - 1)

            else:                      # if not grounded...
                # diagonal term
                g.append(1.0 / self.values[ir])
                g_row.append(N1 - 1)
                g_col.append(N1 - 1)

                # diagonal term
                g.append(1.0 / self.values[ir])
                g_row.append(N2 - 1)
                g_col.append(N2 - 1)

                # N1-N2 term
                g.append(-1.0 / self.values[ir])
                g_row.append(N1 - 1)
                g_col.append(N2 - 1)

                # N2-N1 term
                g.append(-1.0 / self.values[ir])
                g_row.append(N2 - 1)
                g_col.append(N1 - 1)
	'''

	g = []
	g_row = []
	g_col = []
	count = 0
	print("========================================================")
	for node in nodes:
		N1 = node[0]
		N2 = node[1]

		print("N1: "+str(N1))
		print("N2: "+str(N2))
		print("values[ir]: "+str(resistor_values[count]))
		if N1 == 0 or N2 == 0:

			g.append(1/resistor_values[count])
			g_row.append(max(N1, N2) - 1)
			g_col.append(max(N1, N2) - 1)
		
		else:

			g.append(1/resistor_values[count])
			g_row.append(N1 - 1)
			g_col.append(N1 - 1)

			g.append(1/resistor_values[count])
			g_row.append(N2 - 1)
			g_col.append(N2 - 1)

			g.append(-1/resistor_values[count])
			g_row.append(N1 - 1)
			g_col.append(N2 - 1)

			g.append(-1/resistor_values[count])
			g_row.append(N2 - 1)
			g_col.append(N1 - 1)
		count += 1
		print("g : "+str(g))
		print("g_row: "+str(g_row))
		print("g_col: "+str(g_col))
	print("========================================================")

	if len(g_col) != len(g_row): # the matrix must be square
		print("Something went wrong.")
		exit(1)
	print("g : "+str(g))
	print("g_row: "+str(g_row))
	print("g_col: "+str(g_col))
	print("resistor_values: "+str(resistor_values))
	'''
	Expected values:

	g == [1.0, 1.0, -1.0, -1.0, 0.5, 0.5, -0.5, -0.5, 0.1, 0.1, -0.1, -0.1, 0.1]
	g_row == [1, 0, 1, 0, 1, 0, 1, 0, 2, 1, 2, 1, 2]
	g_col == [1, 0, 0, 1, 1, 0, 0, 1, 2, 1, 1, 2, 2]

	'''


	index_stuff = [[g_row[i],g_col[i]] for i in range(len(g_col))]
	
	resulting_matrix = generate_matrix(index_stuff, g)

	stuff = csr_matrix((g,(g_row, g_col)))
	print(stuff)
	print(stuff.toarray())


	print("Resulting matrix: "+str(resulting_matrix))
	return resulting_matrix
```

The generate_matrix is basically a function which is synonomous with the csr_matrix function.

The diagonal on the conductance matrix is the sum of all of the conductances to a point. The other elements on any of the rows of the matrix are the conductances of the resistors going out from that node. Lets make a quick example:

![](pictures/schematic.png)

This schematic basically is this:

```
V1 1 0 5 
R1 1 2 10
R2 2 0 20
R3 2 0 30
.op
```

and the solution is this:

```
Solution: [ 5.          2.72727273 -0.22727273]
```

The first two are the voltages at nodes 1 and 2 and the last is the current which goes through V1

If we look at the matrix before adding the voltage sources:

```
Matrix before voltage sources: [[0.1, -0.1], [-0.1, 0.18333333333333335]]
```

This is the same as this:


![](pictures/matrix.png)


If we take the last row of the matrix, it is basically just the conductances to the point at index 2. The first column and the second row (-0.1) is the conductance of the resistor R1 times V1 we subtract this from the sum and the result is the conductances through R2 and R3 multiplied by V2 (aka vb). 

Ok I think I finally understand how this works.

The current to/from another point to some point called p is the voltage drop across that wire times the conductance of that wire. Because U = R*I therefore I = U*(1/R) .

The current is therefore:

$$I_{p}=\frac{V_{p}-V_{n}}{R_{n}}$$

We sum all of these from each of the nodes. (Note that we use the plus sign everywhere because if the current is into the node, the voltage difference is negative between the nodes if the current is into the node and the current is positive when the current is out of the node, because the voltage in the node is greater than the other node.)

$$I_{p}=\sum_{n=1}^{k}I_{p_{n}}=\sum_{n=1}^{k}\frac{V_{p}-V_{n}}{R_{n}}$$

Where k is the number of nodes where the current node p connects to.

Note that this simplifies to this:

$$\sum_{n=1}^{k}\frac{V_{p}-V_{n}}{R_{n}}=\sum_{n=1}^{k}\frac{V_{p}}{R_{n}}-\sum_{n=1}^{k}\frac{V_{n}}{R_{n}}=V_{p}(\sum_{n=1}^{k}\frac{1}{R_{n}})-(\sum_{n=1}^{k}\frac{V_{n}}{R_{n}})$$

The $V_{p}(\sum_{n=1}^{k}\frac{1}{R_{n}})$ term is the sum of the conductances from the inspected point (this is the term on the diagonal) times the voltage at that point (remember that we multiply the matrix with the voltage and current vector which results in this term.) The $-(\sum_{n=1}^{k}\frac{V_{n}}{R_{n}})$ term is the other terms in the row of the matrix. (Remember the negative terms? These are those.) The algorithm which we just programmed just implements this automatically, because it inserts the resistors in to the matrix automatically.

If we just inspect this code:

```
		else:
			# This adds the admittance to the start point.
			g.append(1/resistor_values[count])
			g_row.append(N1 - 1)
			g_col.append(N1 - 1)
			# This adds the admittance to the start point.
			g.append(1/resistor_values[count])
			g_row.append(N2 - 1)
			g_col.append(N2 - 1)

			g.append(-1/resistor_values[count])
			g_row.append(N1 - 1)
			g_col.append(N2 - 1)

			g.append(-1/resistor_values[count])
			g_row.append(N2 - 1)
			g_col.append(N1 - 1)

```


The first two segments just add the resistor value to the end and start indexes to the diagonal, because one resistor adds two connections. The start index is N1 so if the resistor is between indexes 1 and 2, then it adds the resistor at coordinates (1,1) and (2,2) because now the nodes 1 and 2 have this connection. The two ones after that adds the non-diagonal elements which describe the $-(\sum_{n=1}^{k}\frac{V_{n}}{R_{n}})$ elements. If some resistor already exists at that point (lets say we add a resistor between nodes 1 and 2 and there already is a resistor there), then we just subtract that from the existing value. If there is nothing there then we just set that element in the matrix to that (because anything subtracted from zero is that negative anything like 0-1 = (-1)*1 and 0-14 = (-1)*14 = -14) .

The voltage source currents are in their own columns. For example the first line in the matrix has the current which goes through the battery, because the current is by convention going through the battery in a reverse kinda way, the one is added into the matrix. Notice that if the power source is always between ground and vcc, then it always just adds the ones to the matrix. This is the most common configuration, but when other power sources are involved and which are NOT between the ground reference point (0) then the negative currents are involved.


Ok so now we are going to take the inductors into the mix:

if we use this circuit:

```
* Example of DC network

V1 1 0 5 
R1 1 2 10
R2 2 0 20
R3 2 0 30
L1 2 0 10m
.op

```


the right hand side is this:
```
net.rhs == [0. 0. 0. 5.]
```
and the matrix before the voltage sources is this:

```
[[ 0.1        -0.1         0.        ]
 [-0.1         0.18333333  1.        ]
 [ 0.          1.          0.        ]]
```

and then after the voltage sources it is this:

```
[[ 0.1        -0.1         0.          1.        ]
 [-0.1         0.18333333  1.          0.        ]
 [ 0.          1.          0.          0.        ]
 [ 1.          0.          0.          0.        ]]
```

The inductors in the circuit act as short circuits. This causes the current in the other nodes to be zero, because the inductor shorts to ground. Lets do this:

```
V1 1 0 5 
R1 1 2 10
R2 2 3 20
R3 2 3 30
R4 3 0 40
L1 2 0 10m
.op

```


```
[[ 0.1        -0.1         0.          0.          1.        ]
 [-0.1         0.18333333 -0.08333333  1.          0.        ]
 [ 0.         -0.08333333  0.10833333  0.          0.        ]
 [ 0.          1.          0.          0.          0.        ]
 [ 1.          0.          0.          0.          0.        ]]
```

and:

```
net.x == [ 5.   0.   0.   0.5 -0.5]
```

The reason why currents at 2 and 3 are zero is because the inductor shorts it to ground.

I don't really understand the logic as to how the adding elements into the matrix accounts to the current being zero. Lets try a smaller example of just a battery and a resistor and an inductor in series:

```

* Example of DC network

V1 1 0 5 
R1 1 2 10
L1 2 0 30

.op

```

and the resulting matrix is this:

```
[[ 0.1 -0.1  0.   1. ]
 [-0.1  0.1  1.   0. ]
 [ 0.   1.   0.   0. ]
 [ 1.   0.   0.   0. ]]
```

without the inductor the matrix is this:

```
[[0.1 1. ]
 [1.  0. ]]
```

Without the inductor the equations is basically just V/R-I=0 (the first line) and V=5 (the second line)

With the inductor the first equation is basically this:

$$\frac{V_{a}-V_{b}}{R_{1}}-I_{battery}=0$$

and then the second equation is basically this:

\frac{V_{b}-V_{a}}{R_{1}}-I_{inductor}=0

So the inductors basically act like batteries, but with zero voltage (I think). Lets test our hypothesis by putting a battery with actually zero voltage instead of the inductor:

```

* Example of DC network

V1 1 0 5 
R1 1 2 10
V2 2 0 0

.op

```

and this should result in the same matrix:

```
* Example of DC network

V1 1 0 5 
R1 1 2 10
V2 2 0 0

.op
```

and:

```
[[ 0.1 -0.1  1.   0. ]
 [-0.1  0.1  0.   1. ]
 [ 1.   0.   0.   0. ]
 [ 0.   1.   0.   0. ]]
```

Our hypothesis is correct! (the places of the ones is changed because the order of the currents are switched around now, but if they were in the original order then the ones would be in the original order.)


After implementing inductors into our own solver we now finally have a working program which we actually understand the inner workings of! Fantastic!

## Adding transient analysis.

Now comes the hard part. Transient analysis. This is the electrical simulation what we usually think about. It is the simulation of how the state of the circuit changes over time. The main objective of this is to get a V versus t graph aka a voltage over time graph. Lets do some more reading!

The code in the plagiarized version is this:

```
def transient_solve(net):

    # ========================
    # compute OP related to IC
    # ========================

    # (deep) copy of the network
    from copy import deepcopy
    net_op = deepcopy(net)

    # dictionary to track changes (L <-> I and C <-> V)
    track_change = {}

    # reorder original network and get index
    net_op.reorder()
    indexL = sorted(net_op.isort[1])
    indexC = sorted(net_op.isort[2])
    indexV = sorted(net_op.isort[3])
    indexI = sorted(net_op.isort[4])

    nv = 1  # get max IDnumber for voltage sources
    for iv in indexV:
        Vnum = int(net.names[iv][1:])

        if isinstance(net.values[iv],list):
            tsr_fun = getattr(tsr, net.source_type[net.names[iv]])
            net_op.values[iv] = tsr_fun(*net.values[iv], t=0)

        if Vnum >= nv:
            nv = Vnum + 1
    ni = 1  # get max IDnumber for current sources
    for ii in indexI:
        Inum = int(net.names[ii][1:])

        if isinstance(net.values[ii],list):
            tsr_fun = getattr(tsr, net.source_type[net.names[ii]])
            net_op.values[ii] = tsr_fun(*net.values[ii], t=0)

        if Inum >= ni:
            ni = Inum + 1

    # transform inductors (to current sources)
    for k, il in enumerate(indexL):
        new_name = 'I' + str(ni + k)
        track_change[new_name] = net_op.names[il]
        net_op.values[il] = net_op.IC[net_op.names[il]]
        net_op.names[il] = new_name

    # transform capacitors (to voltage sources)
    for k, ic in enumerate(indexC):
        new_name = 'V' + str(nv + k)
        track_change[new_name] = net_op.names[ic]
        net_op.values[ic] = net_op.IC[net_op.names[ic]]
        net_op.names[ic] = new_name

    # reorder new network (to avoid confusion)
    net_op.reorder()
    # change type of analysis and solve (to get IC)
    net_op.analysis = ['.op']
    net_solve(net_op)

    # ==================
    # transient analysis
    # ==================

    # get time step and tend
    h = float(net.convert_unit(net.analysis[1]))
    tend = float(net.convert_unit(net.analysis[2]))
    # create time array
    net.t = np.arange(0, tend, h)  # if tend is not multiple of h --> net.t[-1] < tend

    # build required matrices
    net.conductance_matrix()
    net.dynamic_matrix()
    rhs_fun = net.rhs_matrix()

    # initialize solution space
    net.x = np.zeros((net.G.shape[0], net.t.size))

    # fill with initial conditions
    NV = len(net.isort[3])
    NE = len(net.isort[5])
    NH = len(net.isort[8])
    net.x[:, 0] = np.concatenate((net_op.x[:net_op.node_num],
                                  np.array(net_op.values)[sorted(net.isort[1])],
                                  net_op.x[net_op.node_num:(net_op.node_num + NV)],
                                  net_op.x[(net_op.node_num + NV):(net_op.node_num + NV + NE)],
                                  net_op.x[(net_op.node_num + NV + NE):(net_op.node_num + NV + NE + NH)]))

    # Solution (Integration using trepezoidal rule. Ref: Vlach, eq 9.4.6, pag. 277)
    K = net.C + 0.5 * h * net.G
    for k in range(1, net.t.size):
        rhs = (net.C - 0.5 * h * net.G) * net.x[:, k - 1] + 0.5 * h * (rhs_fun(net.t[k - 1]) + rhs_fun(net.t[k]))
        net.x[:, k] = spsolve(K, rhs)
```


Maybe lets try understanding it with a minimal example?

Lets make a simple LCR circuit:

```
* Example transient analysis
V1 1 0 10
R1 1 2 10
L1 2 3 1m
C1 3 0 1u
.tran 1u 1m
.plot v(C1) v(L1) i(L1) v(2) v(1,2)

```


The code comments basically just say that the inductors are modeled as current sources while as the capacitors are modeled as voltage sources for the initial conditions (note that the net_op netlist does not actually get used in the calculation themselves. it is purely used to calculate the initial conditions for the network.):

```
    # transform inductors (to current sources)
    for k, il in enumerate(indexL):
        new_name = 'I' + str(ni + k)
        track_change[new_name] = net_op.names[il]
        net_op.values[il] = net_op.IC[net_op.names[il]]
        net_op.names[il] = new_name

    # transform capacitors (to voltage sources)
    for k, ic in enumerate(indexC):
        new_name = 'V' + str(nv + k)
        track_change[new_name] = net_op.names[ic]
        net_op.values[ic] = net_op.IC[net_op.names[ic]]
        net_op.names[ic] = new_name
```


The transient analysis method requires initial conditions, because it numerically calculates what the voltages should be after a certain timestep. This is a function of the previous voltages, so this means that we need to figure out what those initial conditions are. In the code this is done with the following:

```
    net_op.reorder()
    # change type of analysis and solve (to get IC)
    net_op.analysis = ['.op']
    net_solve(net_op)
```

net.x now has the initial conditions.


After this we calculate the conductance matrix just as with the MNA. In addition to this we also calculate `net.dynamic_matrix()` .

The conductance matrix before the dynamic matrix calculation is this:

```
 [[ 0.1 -0.1  0.   0.   1. ]
 [-0.1  0.1  0.   1.   0. ]
 [ 0.   0.   0.  -1.   0. ]
 [ 0.   1.  -1.   0.   0. ]
 [ 1.   0.   0.   0.   0. ]]
```

After adding some debug messages we get this:

```
Before inductors: 
g == [0.1, 0.1, -0.1, -0.1]
g_row == [0, 1, 0, 1]
g_col == [0, 1, 1, 0]
As an array: [[ 0.1 -0.1]
 [-0.1  0.1]]
Before voltage sources: 
g == [0.1, 0.1, -0.1, -0.1, 1, 1, -1, -1]
g_row == [0, 1, 0, 1, 1, 3, 2, 3]
g_col == [0, 1, 1, 0, 3, 1, 3, 2]
As an array: [[ 0.1 -0.1  0.   0. ]
 [-0.1  0.1  0.   1. ]
 [ 0.   0.   0.  -1. ]
 [ 0.   1.  -1.   0. ]]
the G matrix is this: [[ 0.1 -0.1  0.   0.   1. ]
 [-0.1  0.1  0.   1.   0. ]
 [ 0.   0.   0.  -1.   0. ]
 [ 0.   1.  -1.   0.   0. ]
 [ 1.   0.   0.   0.   0. ]]
```

Now, the before voltage sources is after the inductors notice that the matrix does not even take into account the capacitors. It is inductors and resistors and voltage sources only. Notice that on the row three the the equation is basically this: -1*I_inductor we will inspect the right hand side later.

After the conductance matrix we move on to the dynamic matrix calculation:

The dynamic matrix for that circuit is this:

```

[[ 0.e+00  0.e+00  0.e+00  0.e+00  0.e+00]
 [ 0.e+00  0.e+00  0.e+00  0.e+00  0.e+00]
 [ 0.e+00  0.e+00  1.e-06  0.e+00  0.e+00]
 [ 0.e+00  0.e+00  0.e+00 -1.e-03  0.e+00]
 [ 0.e+00  0.e+00  0.e+00  0.e+00  0.e+00]]

 ```

I have stared at the referenced book for a long while now, but I still fail to understand how the person came up with that equation. Maybe I should just ask the guy?

After a bit of digging I found this on wikipedia: https://en.wikipedia.org/wiki/Laplace_transform#s-domain_equivalent_circuits_and_impedances which describes the laplace transforms for equivalent circuits.

Also after a bit of digging I found this: https://www.eeeguide.com/s-domain/

So the term which I am looking for is s-domain. That would have been really helpful a couple of hours ago. Anyway. This is helpful in figuring out impedance in the formula is s*C (in the derivation of the formula), but that does not explain why the inductance acts like it acts.



-------------------------------------------


Ok it is the next day and I figured it out.

The conductance matrix and the capacitance/inductance matrix basically simplifies to this:

$$-i_{a}+C\frac{dV_{c}}{dt}=0$$
$$v_{b}-v_{c}-L\frac{dI_{a}}{dt}=0$$
$$\frac{1}{R_{1}}v_{b}-\frac{1}{R_{1}}v_{a}+i_{a}=0$$
$$\frac{1}{R_{1}}v_{a}-\frac{1}{R_{1}}v_{b}+i_{b}=0$$


and this simplifies to this:

$$RI(t)+L\frac{dI(t)}{dt}+\frac{1}{C}\int_{0}^{t}I(t)dt=V_{a}$$

Here V_a is the voltage of the source.

The initial conditions for this differential equation is that the current initially is zero aka I(0)=0 and also if we simplify the thing a bit:

because I(0)=0 then the initial rate of change of the current is this:

$$RI(t)+L\frac{dI(t)}{dt}+\frac{1}{C}\int_{0}^{t}I(t)dt=L\frac{dI(t)}{dt}=V_{a}$$

$$\frac{dI(t)}{dt}=\frac{V_{a}}{L}$$

Therefore the derivative of the current at the start of time is V/L .

With these initial conditions if we slap the equation into wolfram alpha we get this answer:

![](pictures/solution.png)

Now, the function actually obtains imaginary values for some values of L, R, C and V, but after a bit of fiddling I found out that you just need to get the real component of the result. See:

```
from sympy import *
import math
import matplotlib.pyplot as plt

def I(r,l,C,V_val):

	# f(x)=(sqrt(c)*V*(e**(-(x*(sqrt(a^2 c - 4 b)/sqrt(c) + a))/(2*b))) (e**((x*sqrt((a**2)*c - 4*b))/(b*sqrt(c))) - 1))/sqrt((a**2)*c - 4*b)

	a = Symbol('a')
	b = Symbol('b')
	c = Symbol('c')
	V = Symbol('V')
	x = Symbol('x')

	expression = (sqrt(c)*V*(math.e**(-(x*(sqrt((a**2)*c - 4*b)/sqrt(c) + a))/(2*b)))*(math.e**((x*sqrt((a**2)*c - 4*b))/(b*sqrt(c))) - 1))/sqrt((a**2)*c - 4*b)
	# -2.71828182845905**(-1/2 - sqrt(3)*I/2)*sqrt(3)*I*(-1 + 2.71828182845905**(sqrt(3)*I))/3

	print(expression)

	print(expression.subs({a:r,b:l,c:C,V:V_val}))

	expression = expression.subs({a:r,b:l,c:C,V:V_val})
	print(expression.subs({x:1}))
	print(complex(expression.subs({x:1})))
	print((complex(expression.subs({x:1}))))
	h = 0.1
	cur = 0
	end = 10
	
	x_vals = []
	y_vals = []

	while cur <= end:

		x_vals.append(cur)
		y_vals.append(complex(expression.subs({x:cur})).real)
		cur += h


	plt.plot(x_vals,y_vals)
	plt.show()

	return 0

if __name__=="__main__":

	print(I(1,1,0.1,1))
```

This shows this result:

![](pictures/graph.png)


I confirmed that this is in agreement with the result which I got from this circuit sim: https://www.falstad.com/circuit/ . I made a LCR circuit in that with the same values and the graph was identical.

Why did I do all of this? Because I was confused about this:

$$\mathbf{Gx+Cx'=w}$$

This formula is referenced in the book which the original source references.

--------------

So I just proved that the formula actually works, because it simplifies to the differential equations which describe an LCR circuit, because the currents can be described by the rate of change of the voltage over time times the capacitance and the rate of change of the current times inductance is the voltage.

Lets implement the formula in python like in the other version:

In the dynamic_matrix function in the plagiarized version there is this:

```

        for k, il in enumerate(indexL):
            print("k is this: "+str(k))
            print("il is this: "+str(il))
            c.append(-self.values[il])
            c_row.append(self.node_num + k)
            c_col.append(self.node_num + k)
            print("poopooshitoof: "+str((c_row, c_col)))

```

which had me confused for a while. The loop always puts the inductance on the diagonal of the matrix. This is because the self.node_num is the number of nodes and then the rows and columns which are after the matrix which is of shape self.node_num*self.node_num is the voltage equations. For example the matrix for this circuit in transient analysis:

```
* Example of DC network

V1 1 0 5 
R1 2 1 10
L1 0 2 1
L2 0 2 1
L3 0 2 3

.tran 1m 1
.plot i(R1)
```

are these:

```

G matrix:

[[ 0.1 -0.1  0.   0.   0.   1. ]
 [-0.1  0.1 -1.  -1.  -1.   0. ]
 [ 0.  -1.   0.   0.   0.   0. ]
 [ 0.  -1.   0.   0.   0.   0. ]
 [ 0.  -1.   0.   0.   0.   0. ]
 [ 1.   0.   0.   0.   0.   0. ]]

C matrix:

[[ 0.  0.  0.  0.  0.  0.]
 [ 0.  0.  0.  0.  0.  0.]
 [ 0.  0. -1.  0.  0.  0.]
 [ 0.  0.  0. -1.  0.  0.]
 [ 0.  0.  0.  0. -3.  0.]
 [ 0.  0.  0.  0.  0.  0.]]


```

See, the inductor values are added to places where the equations becoma for example the third line from both of these matrixes becomes this:

$$-v_{b}-L_{1}\frac{dI_{L_{1}}}{dt}=0$$

See, the reason why the conductance matrix goes like resistors and then inductors and then voltage sources is that the currents before the voltage sources are the inductor currents. That is why there are the -1 and +1 stuff in the inductors for the conductance matrix. Then in the capacitance and inductance matrix the values are there. The inductance values are of course for the voltages, because the function is a function of current and returns volts. (V=L*dI(t)/dt) .

Now here is my implementation:

```

	K = C + 0.5*h*G

	solution = np.array([solution])
	solution = solution.T
	print("K == "+str(K))
	print("solutionpoopoo == "+str(solution))

	####

	#solution = np.array([[ 5.,   0.,  -0.5]]).T

	####


	solutions = [solution]

	original_rhs = copy.deepcopy(np.array([rhs]).T)
	print("original_rhs == "+str(original_rhs))
	
	x_vals = [0]
	cur_x = 0

	for _ in range(count-1):
		# rhs = (net.C - 0.5 * h * net.G) * net.x[:, k - 1] + 0.5 * h * (rhs_fun(net.t[k - 1]) + rhs_fun(net.t[k]))
		#rhs = (C - 0.5 * h * G) * solution + 0.5 * h * (original_rhs * 2)
		rhs = np.dot((C - 0.5 * h * G),solution) + 0.5 * h * (original_rhs * 2)
		print("="*30)
		print("C == "+str(C))
		print("G == "+str(G))
		print("solution == "+str(solution))
		print("(C - 0.5 * h * G) * solution == "+str((C - 0.5 * h * G) * solution))
		print("np.dot((C - 0.5 * h * G),solution) == "+str(np.dot((C - 0.5 * h * G),solution)))
		print("0.5 * h * (original_rhs * 2) == "+str(0.5 * h * (original_rhs * 2)))
		print("K == "+str(K))
		print("rhs == "+str(rhs))
		print("="*30)
		#net.x[:, k] = spsolve(K, rhs)
		solution = np.linalg.solve(K, rhs)
		solutions.append(solution)
		x_vals.append(cur_x)
		cur_x += h

```

This code won't work for some odd reason. The initial condition is somehow screwed up, because 


-----------------------

because the initial condition isn't actually the solution to the network, but instead it is the solution to the net where the inductors are replaced with current sources and capacitors are replaced with voltage sources. Look at this:

```
poopoofirst = [resistor_values, resistor_nodes, voltage_nodes, voltage_values, nodes_inductors, inductor_values, nodes_capacitors, capacitor_values]
	poopoofirst = [copy.deepcopy(x) for x in poopoofirst]


	resistor_values2, resistor_nodes2, voltage_nodes2, voltage_values2, nodes_inductors2, inductor_values2, nodes_capacitors2, capacitor_values2 = get_initial_stuff(resistor_values, resistor_nodes, voltage_nodes, voltage_values, nodes_inductors, inductor_values, nodes_capacitors, capacitor_values)
	print("voltage_nodes after: "+str(voltage_nodes))
	
	if poopoofirst != [resistor_values, resistor_nodes, voltage_nodes, voltage_values, nodes_inductors, inductor_values, nodes_capacitors, capacitor_values]:
		print("Fail")
		exit(1)
	G, max_node_num = get_conductance_matrix(resistor_values, resistor_nodes, voltage_nodes, voltage_values, nodes_inductors)
	
	print("[resistor_values, resistor_nodes, voltage_nodes, voltage_values, nodes_inductors, inductor_values, nodes_capacitors, capacitor_values] == "+str([resistor_values, resistor_nodes, voltage_nodes, voltage_values, nodes_inductors, inductor_values, nodes_capacitors, capacitor_values]))

	print("[resistor_values2, resistor_nodes2, voltage_nodes2, voltage_values2, nodes_inductors2] == "+str([resistor_values2, resistor_nodes2, voltage_nodes2, voltage_values2, nodes_inductors2]))

	print("Getting initial shit:")
	Ginitial, max_node_num2 = get_conductance_matrix(resistor_values2, resistor_nodes2, voltage_nodes2, voltage_values2, nodes_inductors2)

	print("G == "+str(G))
	
	print("[len(G[0]), len(G)] == "+str([len(G[0]), len(G)]))


	C, _ = get_capacitance_and_inductance_matrix(nodes_inductors, inductor_values, nodes_capacitors, capacitor_values, max_node_num, [len(G[0]), len(G)])
	print(resistor_nodes)
	#stuff = len(Ginitial[0])

	stuff = len(G[0])
	#rhs = generate_rhs(stuff, voltage_values2)

	rhs = generate_rhs(stuff, voltage_values)


	stuff2 = len(Ginitial[0])
	rhs2 = generate_rhs(stuff2, voltage_values2)

	print("rhs: "+str(rhs))
	print("result: "+str(G))
	print("C == "+str(C))
	print("Ginitial == "+str(Ginitial))
	print("rhs2 == "+str(rhs2))
	#print("Ginitial == "+str(Ginitial))

	#solution = np.linalg.solve(np.array(Ginitial), np.array(rhs))

	#x = np.linalg.solve(np.array(Ginitial), np.array(rhs2))
	# lstsq

	x = np.linalg.lstsq(np.array(Ginitial), np.array(rhs2))
	x = x[0]
	print("x initial: "+str(x))
	print("x[0] == "+str(x[0]))
	print("max_node_num2 == "+str(max_node_num2))
	print("x[:max_node_num2] == "+str(x[:max_node_num2]))
	print("max_node_num2 == "+str(max_node_num2))
	print("inductor_values == "+str(inductor_values))
	print("x[max_node_num2:(max_node_num2+len(voltage_nodes))] == "+str(x[max_node_num2:(max_node_num2+len(voltage_nodes))]))
	solution = np.concatenate((x[:max_node_num2],np.array(inductor_values),x[max_node_num2:(max_node_num2+len(voltage_nodes))]))


```

Here the get_initial_stuff does the replacement. If you are curious just look at the source code on my github page.

So I think that this project is done for now. Maybe I will come back and add non-linear circuits like diodes and transistors and stuff and maybe I will clean up the code at some point. (Emphasis on the word "maybe". :)  )

-----------------

Ok so now I have this some sort of idea about how to go about doing this. I did some research and found this powerpoint presentation: http://emlab.illinois.edu/ece546/Lect_16.pdf

I also found this: https://electronics.stackexchange.com/questions/328027/modified-nodal-analysis-for-diode-approach which describes the algorithm to find the solution.

I think that I will implement a function called solve_non_linear or something like that which solves the solution with the numerical method described.

Here is the plan:

- 















 


















