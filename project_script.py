
import sys
import os

if __name__=="__main__":


	#print("![](pictures/{})".format(sys.argv[1]))
	files = os.listdir("projects/")
	fh = open("projects/index.md")

	already_in_index = fh.read()
	fh.close()
	for file in files:
		if ".md" not in file:
			continue
		file = file[:-3] + ".html" # Get rid of .md and replace with .html
		#print("File : "+str(file))
		#print("already_in_index == "+str(already_in_index))
		assert isinstance(already_in_index, str)
		#print("file in already_in_index == "+str(file in already_in_index))
		if file in already_in_index:
			continue
		#if "" in file: # Check for md extension.
		# Create link
		print("[TEXTHERE](/projects/"+str(file)+")")
