
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


















