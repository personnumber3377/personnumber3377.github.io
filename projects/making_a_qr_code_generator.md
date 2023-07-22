
## Making a QR code generator in python3

This is my blog about writing a "simple" QR code generator.

Looking at the spec, the alignment stuff and the corner markers are quite easy to do:

```

import numpy as np
from PIL import Image



table_string = '''1 0
2 1 6 18
3 1 6 22
4 1 6 26
5 1 6 30
6 1 6 34
7 6 6 22 38
8 6 6 24 42
9 6 6 26 46
10 6 6 28 50
11 6 6 30 54
12 6 6 32 58
13 6 6 34 62
14 13 6 26 46 66
15 13 6 26 48 70
16 13 6 26 50 74
17 13 6 30 54 78
18 13 6 30 56 82
19 13 6 30 58 86
20 13 6 34 62 90
21 22 6 28 50 72 94
22 22 6 26 50 74 98
23 22 6 30 54 78 102
24 22 6 28 54 80 106
25 22 6 32 58 84 110
26 22 6 30 58 86 114
27 22 6 34 62 90 118
28 33 6 26 50 74 98 122
29 33 6 30 54 78 102 126
30 33 6 26 52 78 104 130
31 33 6 30 56 82 108 134
32 33 6 34 60 86 112 138
33 33 6 30 58 86 114 142
34 33 6 34 62 90 118 146
35 46 6 30 54 78 102 126 150
36 46 6 24 50 76 102 128 154
37 46 6 28 54 80 106 132 158
38 46 6 32 58 84 110 136 162
39 46 6 26 54 82 110 138 166
40 46 6 30 58 86 114 142 170'''


def create_coord_table():

	outlist = []

	lines = table_string.split("\n")

	for line in lines:


		outlist.append([int(x) for x in line.split(" ")])

	#print(outlist)

	return outlist














def fail(msg):
	print("Error: "+str(msg))
	exit(1)




def place_big_box_thing(qr,x,y):
	
	# outer square

	# upper horizontal line

	box_side_length = 7

	for i in range(box_side_length):
		qr[y,x+i] = 1

	# lower horizontal line

	for i in range(box_side_length):
		qr[y+6,x+i] = 1

	# left side

	for i in range(box_side_length):
		qr[y+i,x] = 1

	# right side

	for i in range(box_side_length):
		qr[y+i,x+6] = 1


	# inner box

	qr[y+2:y+5,x+2:x+5] = 1





	return qr

def place_alignment_stuff(qr):

	# This function places all of the alignment and timing patterns into the qr code

	qr_side_length = qr.shape[0]


	qr = place_big_box_thing(qr, 0,0)

	qr = place_big_box_thing(qr, qr_side_length-7,0)

	qr = place_big_box_thing(qr, 0, qr_side_length-7)

	return qr

'''

def timing_stuff(qr_code):

	element = 1

	for i in range(qr_code.shape[0]):
		
		qr_code[6,i] = element
		qr_code[i,6] = element
		element ^= 1 # this flips the element from one to zero and from zero to one

	#element = 1

	#for i in range(qr_code.shape[0]):
		
	#	qr_code[i,6] = element
		
	#	element ^= 1

	return qr_code

'''

def timing_stuff(qr_code):

	element = 1

	for i in range(qr_code.shape[0]):
		
		qr_code[6,i] = element
		qr_code[i,6] = element
		element ^= 1 # this flips the element from one to zero and from zero to one

	return qr_code



def draw_small_box(qr_code, coordinates):

	coordinates[0] = coordinates[0]-2
	coordinates[1] = coordinates[1]-2

	y = coordinates[0]
	x = coordinates[1]

	qr_code[y:y+5,x:x+5] = 1 # draw black first the entire thing

	x += 1
	y += 1

	qr_code[y:y+3,x:x+3] = 0 # white again

	qr_code[y+1,x+1] = 1 # the small black dot

	return qr_code


def draw_small_box_stuff(qr_code, coord):

	# coord is now a list of numbers. For each of these numbers, we need to go through the other ones to get the centers of the small boxes.



	for y in coord:
		for x in coord:
			coordinates = [y,x]
			
			# now we need to check the ban stuff

			# first the obvious check:

			if coordinates == [6,6]:
				continue
			elif coordinates[0] == coord[-1] and coordinates[1] == coord[0]: # bottom left
				continue
			elif coordinates[0] == coord[0] and coordinates[1] == coord[-1]: # top right
				continue
			else:

				qr_code = draw_small_box(qr_code, coordinates)

	return qr_code





def place_small_boxes(qr_code, version):

	if version < 0:
		fail("Invalid version!")

	if version == 1: # the smallest QR code does not have these
		return qr_code 
	
	coord_table = create_coord_table() # get table
	print(coord_table)
	coord_stuff = coord_table[version-1]

	coord_stuff = coord_stuff[2:]

	#for coord in coord_stuff:
	#	# coord is now the row/column of the center of the square
	#	print("coord: "+str(coord))

	qr_code = draw_small_box_stuff(qr_code, coord_stuff)

	return qr_code



def generate_qr_code(encoding, data):

	ver = 40
	if ver < 1 or ver > 40:
		fail("Invalid QR code version!")
	modules = 17+ver*4

	qr_code = np.zeros((modules, modules))

	print(qr_code)
	qr_code = timing_stuff(qr_code)
	qr_code = place_alignment_stuff(qr_code)

	qr_code = place_small_boxes(qr_code, ver)



	return qr_code





if __name__=="__main__":

	encoding = "alpha_num"
	#modules = 21
	data = ""

	qr_matrix = generate_qr_code(encoding, data)
	qr_matrix = np.invert(qr_matrix.astype(bool), dtype=bool)
	print(qr_matrix.astype(int))
	qr_matrix = qr_matrix.astype(np.uint8)
	im = Image.fromarray(qr_matrix * 255)
	im.show()

```

The script now at this point fills in the corner squares, alignment squares and the timing oscillating stuff. Otherwise it is empty. Also a thing to note is that in a qr code black means a one and white means zero, but in computer graphics 255 is white (aka zero in qr codes) and 0 is black (aka one in a qr code), so we actually want to invert the matrix before displaying it.

Next up is the task to implement the version stuff which are put beside the big boxes.

To do the version information stuff, we need to implement a way to get BCH codes. https://en.wikipedia.org/wiki/BCH_code   BCH stands for Bose-Chaudhuri-Hocquenghem .

I do not understand the part in the spec where they say how to encode the BCH for the version. They say that the polynomial x**12 + x**10 should be divided by the generator g(x)=x**10 + x**8 + x**5 + x**4 + x**2 + x + 1 and supposedly this results in certain polynomial. The polynomial is completely wrong.

--------------------------------------

I think that I finally got the thing to work. The thing which fucked me over is in the wikipedia it says that the calculation of the BCH code is almost identical to calculating a CRC, but the CRC calculation is slightly different.

Here is the current BCH code:

```
def polyremainder(dividend, divisor):

	# this basically just gets the remainder by converting the polynomials to integers and then doing integer modulo calculation.

	dividend = conv_to_int(dividend)
	print("divisor before call: "+str(divisor))
	divisor = conv_to_int(divisor)

	print("divisor int: "+str(divisor))

	print("dividend: "+str(dividend))

	pad_bits = math.floor(math.log(divisor, 2)) # amount of pad bits

	dividend_bits = math.floor(math.log(dividend, 2))
	print("pad_bits: "+str(pad_bits))

	dividend = dividend << pad_bits

	dividend_bits += pad_bits

	shift_bits = dividend_bits - pad_bits

	print("shift_bits: "+str(shift_bits))
	print("divisor: "+str(bin(divisor)))
	print("Starting loop: \n\n\n")

	while shift_bits >= 0:

		print("="*40)

		print("Dividend: "+str(bin(dividend)[2:]))

		print("Divisor:  "+str(bin(divisor)[2:]))




		print("="*40)

		poopooresult = (dividend ^ (divisor<<shift_bits))>>shift_bits


		# here poopooresult is the result of the xor. We need to figure out how many bits to shift the divisor left.








		if poopooresult > 0:

			shift_bullshit = math.floor(math.log(divisor, 2)) - math.floor(math.log(poopooresult,2))
		else:
			shift_bullshit = math.floor(math.log(divisor, 2))# - math.floor(math.log(poopooresult,2))



		dividend ^= divisor<<shift_bits

		# check for zeros
		#if dividend & (2**(pad_bits)-1)<<shift_bits==0:
		#	print("poopooo")
		#	shift_bits -= pad_bits

		#print(bin(dividend))
		#print("poopoo")
		#print(bin(divisor<<shift_bits))

		shift_bits-= shift_bullshit





	print("Ending loop \n\n\n")

	print("Remainder (modulo) : "+str(dividend) + " == "+str(bin(dividend)))

	return dividend

```

this is the new code:

```
def polyremainder(dividend, divisor):

	# this basically just gets the remainder by converting the polynomials to integers and then doing integer modulo calculation.

	dividend = conv_to_int(dividend)
	print("divisor before call: "+str(divisor))
	divisor = conv_to_int(divisor)

	print("divisor int: "+str(divisor))

	print("dividend: "+str(dividend))

	pad_bits = math.floor(math.log(divisor, 2)) # amount of pad bits

	dividend_bits = math.floor(math.log(dividend, 2))
	print("pad_bits: "+str(pad_bits))

	#dividend = dividend << pad_bits

	dividend_bits += pad_bits

	shift_bits = dividend_bits - pad_bits

	print("shift_bits: "+str(shift_bits))
	print("divisor: "+str(bin(divisor)))
	print("Starting loop: \n\n\n")

	while shift_bits >= 0:

		print("="*40)

		print("Dividend: "+str(bin(dividend)[2:]))

		print("Divisor:  "+str(bin(divisor)[2:]))




		print("="*40)

		poopooresult = (dividend ^ (divisor<<shift_bits))>>shift_bits


		# here poopooresult is the result of the xor. We need to figure out how many bits to shift the divisor left.








		if poopooresult > 0:

			shift_bullshit = math.floor(math.log(divisor, 2)) - math.floor(math.log(poopooresult,2))
		else:
			shift_bullshit = math.floor(math.log(divisor, 2))# - math.floor(math.log(poopooresult,2))



		dividend ^= divisor<<shift_bits

		# check for zeros
		#if dividend & (2**(pad_bits)-1)<<shift_bits==0:
		#	print("poopooo")
		#	shift_bits -= pad_bits

		#print(bin(dividend))
		#print("poopoo")
		#print(bin(divisor<<shift_bits))

		shift_bits-= shift_bullshit





	print("Ending loop \n\n\n")

	print("Remainder (modulo) : "+str(dividend) + " == "+str(bin(dividend)))

	return dividend

```

The only change is that the `#dividend = dividend << pad_bits` is now commented out. In the CRC calculation there are pad bits, but in the BCH code there are no pad bits. I implemented polyremainder_no_pad which calculates this thing and it now works correctly (I think)

```
def polyremainder_no_pad(dividend, divisor):

	# this basically just gets the remainder by converting the polynomials to integers and then doing integer modulo calculation.

	dividend = conv_to_int(dividend)
	#print("divisor before call: "+str(divisor))
	divisor = conv_to_int(divisor)
	
	original_divisor = divisor

	bit_length_diff = get_bit_count(dividend) - get_bit_count(divisor)
	print("Bit length difference: "+str(bit_length_diff))
	if bit_length_diff < 0:
		fail("bit_length_diff can not be less than zero")
	
	# divident is to be the one divided by the divisor

	initial_shift = get_bit_count(divisor) - 1 # shift stuff left for the amount of bits in the divisor minus one.
	print("Initial dividend before shifting: "+str(bin(dividend)[2:]))
	dividend = dividend# << initial_shift

	original_dividend = dividend

	print("Initial dividend: "+str(bin(dividend)[2:]))
	print("Divisor before shifting: "+str(bin(divisor)[2:]))

	print("divisor<<bit_length_diff<<initial_shift == "+str(bin(divisor<<bit_length_diff<<initial_shift)[2:]))
	divisor = divisor<<bit_length_diff#<<initial_shift

	if len(bin(divisor)) != len(bin(dividend)):
		fail("length of divisor must be the same as dividend in the division algorithm.")


	total_shift_count = 0

	while True:

		# Checks

		if len(bin(divisor)) != len(bin(dividend)):

			print("="*30)

			print("bin(divisor) == "+str(bin(divisor)))
			print("bin(dividend) == "+str(bin(dividend)))
			fail("length of divisor must be the same as dividend in the division algorithm.")

		# XOR

		dividend ^= divisor # This assumes that the dividend and divisor are aligned

		# how much to shift right?

		xor_result = dividend>>(get_bit_count(divisor) - get_bit_count(original_divisor))
		print("Xor result: "+str(bin(xor_result)[2:]))
		if xor_result > 0:

			right_shift_count = get_bit_count(original_divisor) - get_bit_count(xor_result)
		elif xor_result == 0:
			right_shift_count = get_bit_count(original_divisor)
		else:
			fail("Somehow xor result is negative?")
		if right_shift_count <= 0:
			fail("right_shift_count must be more than zero. something went wrong")

		print("right_shift_count: "+str(right_shift_count))
		divisor = divisor >> right_shift_count

		total_shift_count += right_shift_count

		if total_shift_count >= initial_shift+bit_length_diff:
			#if total_shift_count >= initial_shift+bit_length_diff:
			break
		print("dividend >> initial_shift == "+str(bin(dividend >> initial_shift)[2:]))
		

		print("Divisor after shifting right: "+str(bin(divisor)[2:]))

		print("Dividend: "+str(bin(dividend)[2:]))


		if dividend >> initial_shift == 0:
			break
		

		input()
	#if dividend != original_dividend:
	#	fail("shitoof")
	print("bin(original_dividend):"+bin(original_dividend))
	print("bin(dividend) == "+str(bin(dividend)))

	print("bin(original_divisor) == "+str(bin(original_divisor)))


	return "0"*(len(bin(original_divisor)[2:]) - len(str(bin(dividend)[2:]))-1)+str(bin(dividend)[2:])

```

Now I need to implement the way to generate the generator polynomials. (Maybe I shouldn't implement all this shit but I think that this is quite fun so I am going to generate all of the numbers from scratch instead of using a lookup table in the generation of the QR codes.)

Reading the wikipedia page the generator polynomial is the product of the minimal polynomials of x=1 to n (I think or something like that idk). Some powerpoint presentation which I read on BCH codes identified the BCH codes with three numbers, but the QR code spec itself only identifies the BCH codes by two numbers: "The Bose-Chaudhuri-Hocquenghem (15,5) code shall be used for error correction." (direct quote). I think (emphasis on those words) this is because q is always two in the calculation of binary BCH codes (aka there are only two atomic elements in GF(q) or something like that). I found this implementation in python which seems simple enough to understand: https://github.com/jkrauze/bch/tree/master . That program hardcodes q = 2 in the BchCodeGenerator class. Also fuck undescriptive variable names. There is a function in mathtools.py which is called "order" which takes arguments x and p. I did some digging and found out that this order does not reference the order of a polynomial but instead this order: https://en.wikipedia.org/wiki/Multiplicative_order

I think that for now I will just implement a function which gets the minimal polynomial for some i in alpha i .

I think that the numbers in the qr code spec refer to n (q**m-1 aka for our purposes this means 2**m-1 for some m) and then the second number refers to the number of the original message data bits.

Looking at the gen() function it looks like it first creates the irr_poly polynomial which in the case of m=4 is a**4+a+1 which is in agreement with the wikipedia page. I also learned that irreducible polynomial in the galois field F means that the polynomial can not factored into two non-constant polynomials whose coefficients are also in F, for example the x^4+x+1 is not reducible in integers or in F().

---------

After digging around the interwebs for an explanation what a minimal polynomial even is, I came up empty. There is no intuitive explanation for what is a minimal polynomial. Sure, some things are simply too complex to have an intuitive explanation, but surely there is atleast one explanation which does not require previous knowledge of Galois fields or abstract algebra, right? No. Every single source I looked at explained minimal polynomials in very complex terms. Terms that I haven't even heard of until now. I stared at the wikipedia page for a couple of hours just trying to understand a piece of text the size of this paragraph, but to no avail.

Let me just try to explain my frustration a bit:

In wikipedia, there is this page https://en.wikipedia.org/wiki/BCH_code . In said page there is this section: https://en.wikipedia.org/wiki/BCH_code#Definition_and_illustration which describe what a BCH code is. The code which I wrote multiplies the generator polynomial by the message polynomial and gets the remainder polynomial which is the BCH code itself (I think, again, all of this is just my own understanding of the topic so take all of this with a grain of salt.). In the explanation, the generator function g(x) is defined as the least common multiple of all of the minimal polynomials which have coefficients in GF(q) and for binary encoding (the type we are interested in) q=2 so the coefficients must be in GF(2) (aka a zero or a one in my understanding) .

When digging into the Minimal polynomial wikipedia page there is this:

"""In field theory, a branch of mathematics, the minimal polynomial of an element α of a field extension is, roughly speaking, the polynomial of lowest degree having coefficients in the field, such that α is a root of the polynomial. If the minimal polynomial of α exists, it is unique. The coefficient of the highest-degree term in the polynomial is required to be 1."""

Ok so lowest degree and a is a root of said polynomial. Got it (maybe).

Lets try to get a minimal polynomial over GF(16).


--------

Update: I don't get it. This stuff does not make any sense to me for some reason. The lowest degree and which has a root at x=16 is x - 16 right? But that is not correct.

-------

Yeah I watched a couple of videos and I still have absolutely no clue what the guy is even talking about. I think that this requires some advanced knowledge of abstract algebra and stuff to understand completely. I am just gonna hardcode the generator polynomial in my code and be done with it. Maybe some day I will program something which generates the generator polynomials for some pair of numbers.

Now I implemented the function which puts the version information into the qr code. One thing which really annoys me is that a lot of this stuff requires the binary integers to have preceding zeroes so I have to fiddle around with keeping the binary strings the same length as they are expected. I found that pythons bin implementation is quite great for this because I can get the binary string and we can pad the extra zeroes in the front by simply subtracting the length of the original binary string from the expected length and boom.

Now when trying to implement the format stuff I find it quite annoying that they are thrown around the qr codes corners instead of it being in one block like the version information.

Next up I think is the most difficult part: the encoding process of the data itself. after that the final step of masking also needs to be done which requires the penalty calculation of different masking patterns.

-------

The encoding process is quite easy for the encoding of alphanumeric data (the default encoding format for my qr code generator). The error code shit is kinda weird because they provide a table in the spec for the different amounts of data blocks for a given qr code version and a given error correction level, but the thing is that this table is not copy pasteable for some reason so I had to program a parser just to get this data from the table. I copied the table as a string which garbles it a bit and then extracts the tuples out of it.

Now, I really didn't understand the error correction codeword generation because you need to do some modulo 0x11d shit which I do not really understand, so I just plagiarized it from another source.

After getting the error correction codewords with the half plagiarized code, I now have all of the data stuff which is needed for the placement of the actual data into the QR code. Once again I plagiarized this stuff from the github version, because I was too dumb to figure out the placement logic myself. Here it is (uncommented by me):

```
	def _draw_codewords(self, data: bytes) -> None:
		"""Draws the given sequence of 8-bit codewords (data and error correction) onto the entire
		data area of this QR Code. Function modules need to be marked off before this is called."""
		assert len(data) == QrCode._get_num_raw_data_modules(self._version) // 8
		
		i: int = 0  # Bit index into the data
		# Do the funny zigzag scan
		for right in range(self._size - 1, 0, -2):  # Index of right column in each column pair
			if right <= 6:
				right -= 1
			for vert in range(self._size):  # Vertical counter
				for j in range(2):
					x: int = right - j  # Actual x coordinate
					upward: bool = (right + 1) & 2 == 0
					y: int = (self._size - 1 - vert) if upward else vert  # Actual y coordinate
					if (not self._isfunction[y][x]) and (i < len(data) * 8):
						self._modules[y][x] = _get_bit(data[i >> 3], 7 - (i & 7))
						i += 1
					# If this QR Code has any remainder bits (0 to 7), they were assigned as
					# 0/false/light by the constructor and are left unchanged by this method
		assert i == len(data) * 8

		
'''
...
...
...
'''


def _get_bit(x: int, i: int) -> bool:
	"""Returns true iff the i'th bit of x is set to 1."""
	return (x >> i) & 1 != 0
	

```

Basically what you need to understand is that self._modules is the QR code matrix.

The way QR codes implement the data placement is that it usually has the 8 bits of the byte placed in a 2x4 matrix as shown on page 47 of the spec. As you can see, the way the bytes are aligned in the QR code is quite difficult to program in, because you need to weave through the functional patterns like the corners and the timing stuff.


Here is the commented version:

```
def _draw_codewords(self, data: bytes) -> None:
	"""Draws the given sequence of 8-bit codewords (data and error correction) onto the entire
	data area of this QR Code. Function modules need to be marked off before this is called."""

	# Just a sanity check
	assert len(data) == QrCode._get_num_raw_data_modules(self._version) // 8
	
	i: int = 0  # Bit index into the data
	# Do the funny zigzag scan
	# This loop jumps two at a time to the left, because the bytes are in a 2x4 matrix
	for right in range(self._size - 1, 0, -2):  # Index of right column in each column pair
		# This check is to avoid the timing pattern
		if right <= 6:
			right -= 1
		for vert in range(self._size):  # Vertical counter
			# This is loop for the x coord in the one byte matrix. j==0 means the right column, and j==1 means the left column
			for j in range(2):
				
				x: int = right - j  # Actual x coordinate
				
				# Every other columns goes upward.
				upward: bool = (right + 1) & 2 == 0
				y: int = (self._size - 1 - vert) if upward else vert  # Actual y coordinate
				
				# Skip this space if this space is occupied by a functional module

				if (not self._isfunction[y][x]) and (i < len(data) * 8):
					# Get the i//8 'th byte and the 7 - (i & 7) 'th bit, because MSB first (I think)
					self._modules[y][x] = _get_bit(data[i >> 3], 7 - (i & 7))
					# Increase bit counter
					i += 1
				# If this QR Code has any remainder bits (0 to 7), they were assigned as
				# 0/false/light by the constructor and are left unchanged by this method
	# Must have gone over each bit of data
	assert i == len(data) * 8
```

So the logic is not that bad as you can see. Basically just go down and up and down and up on each column and skip said space if it is marked as functional. The program fills in the bytes like in this following picture expresses:

![](pictures/qr_code_thing.png)


Well, actually we need a way to mark the functional parts of the QR code first before trying to fill it in. I am just going to use the same method they use, that is to make a matrix which marks the functional tiles. I actually dumped the functional matrix from the plagiarized code and compared the result of my code with it and they agree which each other (in terms of the functional stuff)! Great!

----------

Now that we have the functionality marking, it is time to do a check to see if our QR code generator generates the same output as the other one. And as it turns out, it does not :( . I had to do quite a bit of debugging and the reason why it does not work is that the length of the encoded data is gotten from the table to get how many padding sequences to add and my code is erroneous and gets the wrong length, so it pads more than what is necessary.

```
Plagiarized code:

[32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236]

Our code:

[4, 218, 208, 30, 139, 78, 59, 178, 194, 2, 55, 136, 55, 136, 55, 136, 55, 136, 55]

(Note that the bit order is reversed. Otherwise these two are the same and our version appends too many padding sequences.)

```

As it turns out this is not even my fault. In the plagiarized version there is this:

```
        ...
        
        
		# Increase the error correction level while the data still fits in the current version number
		for newecl in (QrCode.Ecc.MEDIUM, QrCode.Ecc.QUARTILE, QrCode.Ecc.HIGH):  # From low to high
			if boostecl and (datausedbits <= QrCode._get_num_data_codewords(version, newecl) * 8):
				ecl = newecl


		...		

```

The comment is quite self explanatory. Why even have the option to specify the error correction level when you are going to get the maximum error correction level possible anyway? What kind of retarded design is that? Why do you even offer the option to specify the error correction level if you are going to change it anyway internally? I don't see the point. Maybe someone can enlighten me on this. Anyway. After commenting out that shit I get the same answer as with my own encoder. Except no. There is some error still somewhere. Lets keep digging.

After a bit of digging I found the problem in the padding code, because the padding code puts the padding sequences in the wrong endianness.

Except after that the pain does not end yet. After said fix there were even more bugs to iron out. I conducted my investigation in the completely wrong direction, because I thought that the error was in the generation of the error correction codes, but instead my code actually worked as intended, but the reason why the generated qr code of the plagiarized version made a different output than mine is because the plagiarized code had placed the mask version and stuff as zero by default before choosing the correct mask with the penalty method, but mine just assumes the mask to be a certain mask so that made the format information bits wrong and this caused the qr code to look wrong. Now it works. I spent way too much trying to debug this bug which wasn't even in the piece of code which I was inspecting.

Next up is choosing the appropriate mask.

The masking functions are thankfully defined as some modulo stuff with the x and y coordinates.


```

Mask Pattern
Reference
000
001
010
011
100
101
110
111
Condition
(i + j) mod 2 = 0
i mod 2 = 0
j mod 3 = 0
(i + j) mod 3 = 0
((i div 2) + (j div 3)) mod 2 = 0
(i j) mod 2 + (i j) mod 3 = 0
((i j) mod 2 + (i j) mod 3) mod 2 = 0
((i j) mod 3 + (i+j) mod 2) mod 2 = 0


```

In addition to checking this condition we also need to make sure that we are not applying the mask to the functional parts of the QR code with the functional matrix.


-------------

Now after implementing the penalty function, I am puzzled as to how the plagiarized code calculates the penalty, because here is this:

```

		for y in range(size):
			runcolor: bool = False
			runx: int = 0
			runhistory = collections.deque([0] * 7, 7)
			for x in range(size):
				if modules[y][x] == runcolor:
					runx += 1
					if runx == 5:
						result += QrCode._PENALTY_N1
						N1_count += 1
					elif runx > 5:
						leftovers += 1
						result += 1
				else:
					self._finder_penalty_add_history(runx, runhistory)
					if not runcolor:
						thing = self._finder_penalty_count_patterns(runhistory)
						N3_count += thing
						result += thing * QrCode._PENALTY_N3
						#N3_count += self._finder_penalty_count_patterns(runhistory)
					runcolor = modules[y][x]
					runx = 1
			
			thing = self._finder_penalty_terminate_and_count(runcolor, runx, runhistory)
			result += thing * QrCode._PENALTY_N3
			N3_count += thing

			'''.......
			......
			......
			'''
			
			
				def _finder_penalty_count_patterns(self, runhistory: collections.deque) -> int:
		"""Can only be called immediately after a light run is added, and
		returns either 0, 1, or 2. A helper function for _get_penalty_score()."""
		n: int = runhistory[1]
		assert n <= self._size * 3
		core: bool = n > 0 and (runhistory[2] == runhistory[4] == runhistory[5] == n) and runhistory[3] == n * 3
		return (1 if (core and runhistory[0] >= n * 4 and runhistory[6] >= n) else 0) \
		     + (1 if (core and runhistory[6] >= n * 4 and runhistory[0] >= n) else 0)

```

Which calculates the penalty for the third condition. When looking at this https://www.thonky.com/qr-code-tutorial/data-masking the third conditions should only count when there are certain patterns in the QR matrix, but this code is somehow wrong and I can not figure out what goes wrong in it. Whatever. The plagiarized version of the QR code generator chooses mask number 7, when as our version chooses mask number 2 because of this error. I tried, but I do not understand how the _finder_penalty_count_patterns function works.

And the result is, that we can now create a valid QR code! Maybe I will come back to this and try to figure out some of the stuff which I just plagiarized verbatim from the plagiarized version, but I don't know.

Thanks for reading!

Todo for future me:

- Add other encodings.
- Calculate the optimum error correction instead of taking one verbatim.
- Understand the _finder_penalty_count_patterns function better.
- Make the version change according to the size of the message instead of the user having to change it until it is big enough.
- Understand the "Proportion of dark modules in entire symbol" penalty calculation stuff.
- Make the code more readable.
- Delete some of the redundant debug messages.
- Reformat the code in general.






