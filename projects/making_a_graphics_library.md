
# Making (or more specifically actually improving) a graphics library.

Long ago, I made this graphics engine: https://github.com/personnumber3377/Graphicslibrary/commit/30fbafc8dabd1fe587871594489fc6a84dfb62ae and it can actually load a vta frame (https://developer.valvesoftware.com/wiki/Flex_animation) . The VTA file format is not that well documented. So I decided to do this to explain some parts of it.

The vta frame is for the most part loaded inside this function:

{% raw %}
```

def load_vta_frame(time, triangles, base_filename, anim_filename=None, offset=np.array([0.0,0.0,0.0,0.0]), add=False):
	

	# at this point the triangles are in triangles and we need to modify the list:
	fh = open(anim_filename, "r")
	lines = fh.readlines()
	fh.close()
	print("Triangle number 150 in the original triangles: ")
	print(triangles[149].point_matrix)

	counter = 0
	while "vertexanimation" not in lines[counter]:
		counter += 1
	

	while "time 0" not in lines[counter]:
		counter += 1

	counter += 1

	vertices = load_smd_vertices(base_filename, offset)
	oof = counter

	vertice_shit = {}

	

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



	while "time "+str(time) not in lines[counter]:
		counter += 1
	counter+=1
	anim_lines = []
	
	print("Vertices for triangles number 150 from load_smd_vertices: ")
	print(vertices[149*3:150*3])
	shit = 0




	while "time" not in lines[counter]:
		appendable_thing = lines[counter].split(" ")
		appendable_thing = remove_values_from_list(appendable_thing, "")
		#anim_lines.append(appendable_thing)
		#print(lines[counter].split(" "))
		# we need to generate the new vector:
		print("Vertices before modifying: ")
		
		print(vertices[int(appendable_thing[0])])
		print("Appendable thing:")
		print(appendable_thing)
		print(appendable_thing[1:4])
		# ['4.208581', '-7.113604', '54.759979']
		if appendable_thing[1:4] == ["4.208581", "-7.113604", "54.759979"]:
			print("ok so now is the important thing:")
			print("Current line: ")
			print(appendable_thing)
			print("The vertex which we are replacing (index): ")
			print(vertice_shit[int(appendable_thing[0])])
			print("Actual:")
			#print(vertices[vertice_shit[int(appendable_thing[0])]])

		for poopoo in vertice_shit[int(appendable_thing[0])]:
			if add:

				vertices[poopoo][0] += float(appendable_thing[1])
				vertices[poopoo][1] += float(appendable_thing[2])
				vertices[poopoo][2] += float(appendable_thing[3])
			else:
				vertices[poopoo][0] = float(appendable_thing[1])
				vertices[poopoo][1] = float(appendable_thing[2])
				vertices[poopoo][2] = float(appendable_thing[3])
		#print("Modified vertex: " + str(int(appendable_thing[0])))
		#print(lines[counter])

		counter += 1
		shit += 1
	#print("Modified triangles: " + str(shit))
	#print("Vertices for triangles[149]: " + str(vertices[149*3:149*3++3]))
	returned_triangles = triangles_from_vertices(vertices)
	#print("Triangle number 150 in the resulting triangles: ")
	#print(returned_triangles[149].point_matrix)
	return returned_triangles

```
{% endraw %}

So our goal is to optimize basically this function and the functions it calls. This becomes apparent when looking at the cProfile output.


