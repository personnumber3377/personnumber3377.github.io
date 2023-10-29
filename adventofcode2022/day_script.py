
import os

if __name__=="__main__":

	files = os.listdir(".")

	for file in sorted(files):
		if "advent" in file:
			index_day = file.index("day")+3
			end_index = file.index(".md")
			#writeup_index = file.index("writeup")

			day_num = int(file[index_day:end_index])
			#print("File "+str(file)+" number is "+str(day_num))
			print("[Day {}]({})".format(str(day_num), "adventofcode2022/"+str(file)))


