
# Optimizing my own graphics library

Hi!

Recently I actually developed a graphics library. It works decently, but I wanted to challenge myself to try to optimize it in a couple of ways.

## Finding bottlenecks

Ok, so first things first let's try to run the program with the cProfile profiler and see where we are going wrong... (the source code for my graphics engine is here: https://github.com/personnumber3377/Graphicslibrary and I am using commit 30fbafc8dabd1fe587871594489fc6a84dfb62ae)

The vast majority of the time is spent inside this loop:

{% raw %}
```

	while "time 1" not in lines[oof]:

		another = 0
		appendable_thing = lines[oof].split(" ")
		appendable_thing = remove_values_from_list(appendable_thing, "")
		#print(appendable_thing)
		for vertice in vertices:
			#print("bullshit")
			#print(appendable_thing)
			if vertice[0] == float(appendable_thing[1]) and vertice[1] == float(appendable_thing[2]) and vertice[2] == float(appendable_thing[3]):
				if int(appendable_thing[0]) not in vertice_shit.keys():
					vertice_shit[int(appendable_thing[0])] = [another]

				else:
					vertice_shit[int(appendable_thing[0])].append(another)

				#
			another += 1
		oof += 1

		if oof % 1000 == 0:
			print(oof)
	print("Done")

```
{% endraw %}

and the `remove_values_from_list` function...

{% raw %}
```

def remove_values_from_list(the_list, val):
	return [value for value in the_list if value != val]

```
{% endraw %}

Let's put these code pieces in to an independent file. Let's called it `optimize_me.py`.

Here:

{% raw %}
```






def remove_values_from_list(the_list, val):
	return [value for value in the_list if value != val]





'''


while "time 1" not in lines[oof]:

	another = 0
	appendable_thing = lines[oof].split(" ")
	appendable_thing = remove_values_from_list(appendable_thing, "")
	#print(appendable_thing)
	for vertice in vertices:
		#print("bullshit")
		#print(appendable_thing)
		if vertice[0] == float(appendable_thing[1]) and vertice[1] == float(appendable_thing[2]) and vertice[2] == float(appendable_thing[3]):
			if int(appendable_thing[0]) not in vertice_shit.keys():
				vertice_shit[int(appendable_thing[0])] = [another]

			else:
				vertice_shit[int(appendable_thing[0])].append(another)

			#
		another += 1
	oof += 1

	if oof % 1000 == 0:
		print(oof)
print("Done")

'''

def f(lines, vertices): # vertice_shit = {}
	vertice_shit = {} # Vertice stuff.



	counter = 0
	while "vertexanimation" not in lines[counter]:
		counter += 1


	while "time 0" not in lines[counter]:
		counter += 1

	counter += 1

	oof = counter

	while "time 1" not in lines[oof]:
		another = 0
		appendable_thing = lines[oof].split(" ")
		appendable_thing = remove_values_from_list(appendable_thing, "")
		for vertice in vertices:
			if vertice[0] == float(appendable_thing[1]) and vertice[1] == float(appendable_thing[2]) and vertice[2] == float(appendable_thing[3]):
				if int(appendable_thing[0]) not in vertice_shit.keys():
					vertice_shit[int(appendable_thing[0])] = [another]
				else:
					vertice_shit[int(appendable_thing[0])].append(another)
			another += 1
		oof += 1
		if oof % 100 == 0:
			print(oof)
	print("Done")

	return




import pickle

if __name__=="__main__":


	filehandler = open("lines.pickle", 'rb')
	lines = pickle.load(filehandler)
	filehandler.close()


	filehandler = open("vertices.pickle", 'rb')
	vertices = pickle.load(filehandler)
	filehandler.close()

	# print(vertices)

	f(lines, vertices)

	exit(0)




```
{% endraw %}

let's see what we can do...

## Finding a bug in the original code

Ok, so as it turns out, there is a bug in the code.










