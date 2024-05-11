
# (Re)Implementing zlib.decompress in python3

I searched up on google on how to write a png decoder in python and as it turns out, PNG data is just zlib DEFLATE compressed data in a wrapper. This blog post here: https://pyokagan.name/blog/2019-10-18-zlibinflate/ describes how to decompress zlib data in python3. In this blog post, I am going to try to follow along and make my own version.

## Implementing a bitreader

The tutorial starts off with implementing a bitreader class which reads the data. I am going to do the same. I am going to create a new file called bitreader.py .

In addition, I am going to create a file called helpers.py which contains some helper functions such as strict type checking to add asserts in the code. I am also a bit bummed that the type hints in python3 are purely cosmetic, because they do not actually check the type on runtime. This sucks in my opinion, but we have to deal with it.

Here is the contents of helpers.py:

```

def type_check(input, type) -> bool: # Checks that the input is of type "type"
	assert isinstance(input, type)

def strict_val_check(a, b) -> bool:
	if not type(a) != type(b):
		# differ by type
		return False
	if a != b:
		# differ by value
		return False
	return True # Match

```

and here is my very initial implementation of a bitreader class:

```

# Implements a bitreader class which is used to interpret the zlib data from the datastream.

class Bitreader:

	def __init__(self, data: bytes): # Initializes the bitreader with the supplied data.
		self.current_byte = 0 # index of the current byte.
		self.current_bit = 0 # index of the current bit being read.

	def read_bit(self) -> bool: # Reads one bit from the bitstream
		byte_val = self.data[self.current_byte] # Get the current byte in the data which we are working with.
		bit_val = ( byte_val << self.current_bit ) & 0b00000001 # Shift to the current bit and then and it with 0b00000001 to get the current bit.
		assert strict_val_check(bit_val, 1) or strict_val_check(bit_val, 0) # the value which we read must be 1 or 0 and of type integer.
		# Update counters.
		self.current_bit += 1
		# Check if we skip to the next byte
		if self.current_bit == 7:
			self.current_bit = 0
			self.current_byte += 1
		return bool(bit_val) # convert to boolean type before returning

	def read_byte(self) -> int: # Reads a byte from the bitstream
		output = 0 # output integer
		for _ in range(8): # 8 bits in a byte
			bit = self.read_bit()
			output <<= 1 # first shift to the left, because the bit which we just read will take up bit position 0
			output |= int(bit) # append bit to integer (must first convert to integer, because "bit" is actually of type bool)
		return int(output) # Return as integer



```

In addition, let's also create a file called "tests.py" which contains tests for the different parts of the program. For example we should add a testcase for the bitreader class.

Here is a test script which tests a lot of the stuff:

```


def test_bitreader() -> None:
	# Just verify that we read the same bytes as are in the thing.
	byte_input_bytes = [0x01, 0x02, 0x03, 0x04, 0xff, 0xdd]
	byte_inputs = bytes(byte_input_bytes)
	reader = bitreader.Bitreader(byte_inputs)
	for k in range(len(byte_input_bytes)):
		print("New byte...")
		cur_int = 0
		for i in range(8):
			bit_val = int(reader.read_bit())
			#cur_int <<= 1 # shift to the left once
			cur_int |= ( bit_val << i )
		# Check for the stuff
		assert byte_input_bytes[k] == cur_int
		print("Here is the value which we read: "+str(bin(cur_int)))

	print("Bit reader test passed!!!")

	return

```

and it passes. Good!!!

After doing a couple of modifications, my bitreader class now looks like this:

```

class Bitreader:

	def __init__(self, data: bytes): # Initializes the bitreader with the supplied data.
		self.current_byte = 0 # index of the current byte.
		self.current_bit = 0 # index of the current bit being read.
		self.data = data

	def read_bit(self) -> bool: # Reads one bit from the bitstream
		byte_val = self.data[self.current_byte] # Get the current byte in the data which we are working with.
		bit_val = ( byte_val >> self.current_bit ) & 0b00000001 # Shift to the current bit and then and it with 0b00000001 to get the current bit.
		#print("bit_val == "+str(bit_val))
		#print("type(bit_val) == "+str(type(bit_val)))
		assert strict_val_check(bit_val, 1) or strict_val_check(bit_val, 0) # the value which we read must be 1 or 0 and of type integer.
		# Update counters.
		self.current_bit += 1
		# Check if we skip to the next byte
		if self.current_bit == 8:
			self.current_bit = 0
			self.current_byte += 1
			#print("self.current_byte == "+str(self.current_byte))
			#print("self.data[self.current_byte] == "+str(self.data[self.current_byte]))
		return bool(bit_val) # convert to boolean type before returning

	def read_byte(self) -> int: # Reads a byte from the bitstream
		output = 0 # output integer
		for _ in range(8): # 8 bits in a byte
			bit = self.read_bit()
			output <<= 1 # first shift to the left, because the bit which we just read will take up bit position 0
			output |= int(bit) # append bit to integer (must first convert to integer, because "bit" is actually of type bool)
		return int(output) # Return as integer

	def read_n_bytes(self, n) -> int: # Reads the next n bits as an integer
		output = 0
		for _ in range(n): # read n bytes
			bit = self.read_byte()
			assert 0 <= bit <= 255
			output <<= 8
			output |= int(bit)
		return int(output) # Return as integer

```

## Actually starting to implement the zlib decompression.

As it turns out, after tring to use my bitreader class, I actuall got it the wrong way around (I mean the order of the bits), so here is a new version of the thing:

```

from helpers import *

class Bitreader:

	def __init__(self, data: bytes): # Initializes the bitreader with the supplied data.
		self.current_byte = 0 # index of the current byte.
		self.current_bit = 0 # index of the current bit being read.
		self.data = data

	def read_bit(self) -> bool: # Reads one bit from the bitstream
		byte_val = self.data[self.current_byte] # Get the current byte in the data which we are working with.
		bit_val = ( byte_val >> self.current_bit ) & 0b00000001 # Shift to the current bit and then and it with 0b00000001 to get the current bit.
		#print("bit_val == "+str(bit_val))
		#print("type(bit_val) == "+str(type(bit_val)))
		assert strict_val_check(bit_val, 1) or strict_val_check(bit_val, 0) # the value which we read must be 1 or 0 and of type integer.
		# Update counters.
		self.current_bit += 1
		# Check if we skip to the next byte
		if self.current_bit == 8:
			self.current_bit = 0
			self.current_byte += 1
			#print("self.current_byte == "+str(self.current_byte))
			#print("self.data[self.current_byte] == "+str(self.data[self.current_byte]))
		return bool(bit_val) # convert to boolean type before returning

	def read_byte(self) -> int: # Reads a byte from the bitstream
		output = 0 # output integer
		for count in range(8): # 8 bits in a byte
			bit = self.read_bit()
			print("Here is the bit: "+str(bit))
			#output <<= 1 # first shift to the left, because the bit which we just read will take up bit position 0
			output |= ( int(bit) << count ) # append bit to integer (must first convert to integer, because "bit" is actually of type bool)
		return int(output) # Return as integer

	def read_n_bytes(self, n) -> int: # Reads the next n bits as an integer
		output = 0
		for count in range(n): # read n bytes
			bit = self.read_byte()
			assert 0 <= bit <= 255
			#output <<= 8
			output |= ( int(bit) << (count*8) )
		return int(output) # Return as integer

	def read_n_bits(self, n) -> int: # Reads the next n bits as an integer
		output = 0
		for count in range(n): # read n bytes
			bit = self.read_bit()
			assert 0 <= bit <= 1
			#output <<= 1
			output |= (int(bit) << count )
		return int(output) # Return as integer

```

now it works properly.

Here is the start of the decompression function:

```

def our_decompress(input_data: bytes) -> bytes:
	# This is the main decompression function...
	# Create a reader from the data.
	reader = Bitreader(input_data)
	# Now try to read the four first bytes which should be equal to 8 in decimal
	CMF = reader.read_byte()

	print("CMF == "+str(CMF))
	CM = CMF & 15
	CINFO = ( CMF & 0b11110000 ) >> 4

	'''
	 Compression info. This is the base-2 logarithm of the LZ77 window size, minus eight. In other words, the window size is . The maximum window size that is allowed by the spec is 32768, which is . In other words, CINFO must be , and any other value should be treated as an error.

	'''

	# Must be less than equal to seven

	assert CINFO <= 7
	print("CINFO == "+str(CINFO))
	LZ77_WINDOW_SIZE = 2 ** ( CINFO + 8 )

	print("CM == "+str(CM))
	assert CM == 8
	print("CM test passed... (CM is equal to 8)")

	# The next byte is the flag byte (or FLG for short)

	FLG = reader.read_byte()

	# Bits 0 to 4: FCHECK --- Used as part of the  checksum. See below.

	FCHECK = FLG & 0b11111 # First four bytes
	FDICT = ( FLG & 0b100000 ) >> 5

	#  Compression level. This indicates whether the original data was compressed with the fastest/fast/default/max-compression compression level. It's not needed for de-compression at all, and is only there to indicate if recompression might be worthwhile. For our purposes, we can simply ignore it.

	FLEVEL = ( FLG >> 6 )

	# These flag values also act as a checksum of sorts.

	if ( CMF * 256 + FLG ) % 31 != 0:
		print("zlib header checksum failure")
		assert False

	output = inflate(reader) # Main decompression algorithm.

	CHECKSUM = reader.read_n_bytes(4)

	return 0


```

## Implementing inflate algorithm

Ok, so the INFLATE format is comprised of "blocks" . Each block begins with a three bit header. The first bit tells if the block is a final block or not, then the second and third bits tell the type of this block...

Here is my function which detects the type of these blocks and then calls the appropriate function:

```


def inflate(reader) -> bytes:
	# Main decompression algorith

	# Loop over each block.

	FINAL_BLOCK = 0
	output = [] # This will be the output bytes.
	while not FINAL_BLOCK:
		FINAL_BLOCK = reader.read_bit()
		BLOCK_TYPE = reader.read_n_bits(2)

		if BLOCK_TYPE == 0: # Block isn't compressed
			inflate_no_compression(reader, output)
		elif BLOCK_TYPE == 1:
			# A so called "fixed" block.
			inflate_fixed_block(reader, output)
		elif BLOCK_TYPE == 2:
			# A so called "dynamic" block.
			inflate_block_dynamic(reader, output)
		else:
			print("Invalid block type: "+str(BLOCK_TYPE))
			assert False
	return bytes(output) # Convert list of integers to a bytestring before returning

```

Now, we will go over each of these functions. I am going to start with the easiest one first (inflate_no_compression)..

## Implementing non-compressed blocks

The first two bytes should be the length of the block (not including the header) and then the next two bytes should be the ones complement (bitwise not) of the length, therefore we should add a sanity check for that. Then the next "length" number of bytes are the content. Here is my implementation:

```

def inflate_no_compression(reader, output):
	# Implements noncompressed blocks.
	LENGTH = reader.read_n_bytes(2) # The first two bytes have the length
	NLENGTH = reader.read_n_bytes(2) # This is the ones complement of LENGTH
	# Sanity checks.
	assert LENGTH & NLENGTH == 0 # No bits should match.
	assert (~NLENGTH) & LENGTH == LENGTH # The complemented version of NLENGTH should be LENGTH
	# Add the bytes.
	stuff_to_add = [reader.read_byte() for _ in range(LENGTH)]

	output += stuff_to_add # add.

	return

```

After a bit of debugging, I actually found a bug in my code:

```

def inflate_no_compression(reader, output):
	# Implements noncompressed blocks.
	LENGTH = reader.read_n_bytes(2) # The first two bytes have the length
	NLENGTH = reader.read_n_bytes(2) # This is the ones complement of LENGTH
	# Sanity checks.
	print("Here is LENGTH: "+str(bin(LENGTH)))
	print("Here is NLENGTH: "+str(bin(NLENGTH)))

	assert LENGTH & NLENGTH == 0 # No bits should match.
	assert (~NLENGTH) & LENGTH == LENGTH # The complemented version of NLENGTH should be LENGTH
	assert ((~NLENGTH) & 0xffff) == LENGTH
	# Add the bytes.
	print("Here is the LENGTH: "+str(LENGTH))
	stuff_to_add = []
	for _ in range(LENGTH):
		byte_contents = reader.read_byte()
		print("Here is the current byte: "+str(chr(byte_contents)))
		stuff_to_add.append(byte_contents)

	output += stuff_to_add # add.

	return


```

This errors out with this output:

```

b'x\x01\x01\x0c\x00\xf3\xffHello World!\x1cI\x04>'
CMF == 120
CINFO == 7
CM == 8
CM test passed... (CM is equal to 8)
Here is BLOCK_TYPE: 0
Here is LENGTH: 0b110000000
Here is NLENGTH: 0b1111111001100000
Traceback (most recent call last):
  File "/home/oof/programming/implementing_zlib_decompress/main.py", line 142, in <module>
    exit(main())
  File "/home/oof/programming/implementing_zlib_decompress/main.py", line 135, in main
    result = our_decompress(compressed_data)
  File "/home/oof/programming/implementing_zlib_decompress/main.py", line 113, in our_decompress
    output = inflate(reader) # Main decompression algorithm.
  File "/home/oof/programming/implementing_zlib_decompress/main.py", line 55, in inflate
    inflate_no_compression(reader, output)
  File "/home/oof/programming/implementing_zlib_decompress/main.py", line 20, in inflate_no_compression
    assert ((~NLENGTH) & 0xffff) == LENGTH
AssertionError


```

This is because when we are reading the LENGTH and the NLENGTH fields, the reader isn't byte aligned, and therefore it gives us the wrong answer.

Here: `Here is LENGTH: 0b110000000` if we shift the value left 5 bits, then we get `0b1100` (or 12 in decimal), which is the correct length. I am actually going to implement a method on our bytereader object which skips to the start of the next byte:

(in bitreader.py)

```

	def skip_to_start_of_next_byte(self) -> None: # This should skip to the start of the next byte.
		self.current_bit = 0 # First bit...
		self.current_byte += 1 # of the next byte.
		return


```

then if we call this function, before trying to read the header, then we get this:

```

b'x\x01\x01\x0c\x00\xf3\xffHello World!\x1cI\x04>'
CMF == 120
CINFO == 7
CM == 8
CM test passed... (CM is equal to 8)
Here is BLOCK_TYPE: 0
Here is LENGTH: 0b1100
Here is NLENGTH: 0b1111111111110011
Here is the LENGTH: 12
Here is the current byte: H
Here is the current byte: e
Here is the current byte: l
Here is the current byte: l
Here is the current byte: o
Here is the current byte:
Here is the current byte: W
Here is the current byte: o
Here is the current byte: r
Here is the current byte: l
Here is the current byte: d
Here is the current byte: !
Here is the result: 0


```

that seems more like it!

## Some information about huffman coding.

Now, the DEFLATE format takes advantage of two things: Huffman coding and LZ77 , both of these are compression algorithms themselves. Actually DEFLATE uses a special case of Huffman coding, where no code is a prefix for another huffman code. This is to avoid ambiguity when decoding a DEFLATE stream. I think I am getting ahead of myself.

Huffman codes are codes which are used to replace symbols in text with a certain "code" which corresponds to that piece of text. This huffman binary tree (of which the leaves tells the encoded data and the left/right steps are the binary digits of the code) can be predetermined (by convention aka by just agreeing to use a certain tree) or it can be encoded in the data and then decoded during decompression (this is the usual way).

I am going to create a new file called huffman.py which implements these huffman trees.

As a helper, I am going to implement an "integer to bytes" method, which converts an integer to a bytestring. The DEFLATE spec specifies that the first bit is the most significant and the last bit read is the least significant.

In the article they use the name of code_to_bytes , but I am going to call it simply int_to_bytes , because that is exactly what it is

Here it is:

```


def int_to_bytes(integer: int, n: int) -> bytes: # Encodes "integer" to a bytestring of length "n" bits.

	'''

	r = BitReader(code_to_bytes(0b11101000001, 11))
	print([r.read_bit() for _ in range(11)]) # [1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1]

	'''

	output = [0] # Must be initialized with the zero value.

	cur_bit = 0
	for i in range(n-1, -1, -1): # Go from n-1 to 0 inclusive
		if cur_bit >= 8: # Skip over to the next byte.
			output.append(0)
			cur_bit = 0
		# Operate on the very last byte.
		output[-1] |= ((1 << cur_bit) if integer & (1 << i) else 0)
		cur_bit += 1
	return bytes(output)

```

There actually exists a method called to_bytes on the integer object, but I am not sure that it is what we want, besides it was fun trying to implement that myself.

Let's actually go to implement a huffman tree! The tree is composed of leaves (or so called "nodes") so we also need a class for that.

Here is the beginnings of the node structure:

```

RIGHT = 1
LEFT = 0

class Node:

	def __init__(self) -> None: # Constructor, which just initializes stuff.
		# These values are going to be modified externally
		self.left = None
		self.right = None
		self.parent = None
		self.value = None # This will be only set on leaf nodes

	def isLeaf(self) -> bool: # This checks if this node is a leaf of the tree.
		if self.value != None:
			return True
		return False

	def isTrunk(self) -> bool: # Check if this node is not a leaf. this is equal to "not isLeaf()" .
		return not self.isLeaf()

	def add_node(direction: int, child: Node) -> None: # This adds a child node to this node. direction is left or right (0 is left and 1 is right)
		assert self.value == None # Because we are adding a child node, this node can not be a leaf, and therefore must not have a value associated.
		assert direction == RIGHT or direction == LEFT
		if direction == RIGHT:
			self.right = child
		else:
			self.left = child
		# Set the parent of the child node as this node.
		child.parent = self
		return


```

and here is the huffman tree structure:

```


class HuffmanTree:

	def __init__(self) -> None: # Constructor, which just initializes some values.
		self.root = Node() # The root of the tree.

	def traverse_tree(self, path_int: int, n: int): # This functions traverses the tree by following the code path_int which is of length n bits
		# First convert the path to DEFLATE compliant bytes and then read it bit by bit and traverse the tree.
		path_bytes = int_to_bytes(path_int, n)
		# Now make a reader
		r = bitreader.Bitreader(path_bytes)
		cur_node = self.root # Start from the root.
		for _ in range(n):
			bit_val = r.read_bit()
			if bit_val == LEFT:
				cur_node = cur_node.left
			else:
				cur_node = cur_node.right
			assert cur_node != None # We should not try to traverse downwards a nonexistent path.
		# Now we have reached the leaf. Verify that it actually is a leaf.
		assert cur_node.isLeaf()
		# Return the leaf
		return cur_node

	def add_node(self, node, path_int: int, n: int) -> None:
		# This adds a node at the path "path_int". This functions assumes that the path to the parent child of the node which is going to be added exists already. For example if the path 0b11 does not exist and you try to call this function with 0b111 , then this function will error out and will NOT create the 0b11 node for you.

		# First get the node and then call add_node on that.
		parent_node = self.traverse_tree(path_int << 1, n) # Here we need to discard the very last bit of the path, because that will be the thing which we are adding
		# The direction is just the last bit of path_int.
		direction = path_int & 0b1
		assert direction == RIGHT or direction == LEFT
		# Then just call add_node on that.
		parent_node.add_node(direction, node)
		return


```

Let's take it out for a test drive! Here is my test function:

Actually, I am going to modify the "add_node" method such that it creates the nodes when traversing. This will make it a lot easier to deal with in the future.

Here:

```

	def add_node(self, node, path_int: int, n: int) -> None:
		node = self.root

		path_bytes = int_to_bytes(path_int, n)
		# Now make a reader
		r = bitreader.Bitreader(path_bytes)

		# Now traverse the tree and add nodes if needed.
		for _ in range(n):
			bit_val = r.read_bit() # Get the current bit...
			if bit_val == RIGHT:
				child = node.right
				if child == None: # Check if that node is nonexistent...
					child = Node() # Create it.
					# def add_node(direction: int, child: Node)
					node.add_node(bit_val, child)
			else: # LEFT
				child = node.left
				if child == None: # Check if that node is nonexistent...
					child = Node() # Create it.
					# def add_node(direction: int, child: Node)
					node.add_node(bit_val, child)

```

and I added a couple more methods:

```

	def add_value(self, path_int: int, n: int, value) -> None: # A wrapper around add_node
		new_node = Node()
		new_node.value = value
		self.add_node(new_node, path_int, n)
		return

	def read_symbol(self, reader: bitreader.Bitreader): # This function reads bits from the reader until a valid path is found and then returns the value of that path.
		cur_node = self.root # Start from the root.
		while True: # Loop.
			bit_val = r.read_bit()
			if bit_val == LEFT:
				cur_node = cur_node.left
			else:
				cur_node = cur_node.right
			# If add_nodes is true, then we are currently adding a leaf to the node, so
			# Check if the current node is a leaf, if yes, then return that value...
			if cur_node.isLeaf():
				assert cur_node.value != None # Should have a value assigned to it.
				return cur_node.value

```

here is a function to test the functionality of this tree structure:

```

def test_huffman_tree() -> None:

	# First create the huffman tree...
	tree = HuffmanTree()

	# Insert some leaves and nodes...

	tree.add_value(0b01, 2, "A")
	tree.add_value(0b1, 1, "B")
	tree.add_value(0b000, 3, "C")
	tree.add_value(0b001, 3, "D")

	# Try reading some of the values from the tree.

	r = bitreader.Bitreader(int_to_bytes(0b11101000001, 11)) # Some stuff.

	correct_answers = ["B", "B", "B", "A", "C", "D"]

	for i in range(len(correct_answers)):
		sym = tree.read_symbol(r)
		print("Here is the current symbol: "+str(sym))
		assert sym == correct_answers[i]

	print("test_huffman_tree passed!!!")

	return


```

and the test passes. Good!!!

## Implementing LZ77 compression

Let's create a new file called lz77.py and implement this compression algorithm in it.

This will be by far the most difficult part of the entire compression spec, because we are actually using two different tables. This is because we have both literal values and `<length, backwards_distance>` pairs in the data. One of these tables encodes literal values and the other table encodes distances.

The blog post actually describes the LZ77 algorithm first and then it goes on to describe the way how these literal value and distance trees are encoded in the data.

I am going to actually do this the other way around, I am going to first implement a function to convert a "bit length list" to a huffman tree, then afterwards I am going to implement the function which uses this huffman tree to decode data.

So we need a first a way to get the amount of occurences of each value up to max bitlength in the list:

Something like this?

```


def bitlengths_to_tree(bitlengths: list, alphabet: list) -> huffman.HuffmanTree:
	# Converts a list of bitlengths to a huffman tree with the given alphabet (the alphabet is assumed to already be in order)

	# This function returns a so called "canonical" huffman tree.

	max_bit_len = max(bitlengths) # Get the maximum length of all the lengths.

	bit_length_counts = [bl.count(x) if x != 0 else 0 for x in range(max_bit_len+1)] # This is a list of the count of all of the lengths, for example the value at index 0 of this list is the amount of occurences of the value of zero in the bitlengths list. then the value at index 1 is the total amount of the value 1 which is in the bitlength list and so on...


	print(bit_length_counts)

	return

```

Let's create a test function for it in the tests.py file...

```

def test_bitlengths_to_tree() -> None:

	# bitlengths_to_tree(bitlengths, alphabet)
	alphabet = 'ABCD'
	bl = [2, 1, 3, 3]

	result = bitlengths_to_tree(bl, alphabet)

	print("Here is the bitlength stuff: "+str(result))

	return



```

and here is the result:

```
Here is the bitlength stuff: [0, 1, 1, 2]
```

seems ok to me!

Let's continue...

In the article: "Next, we compute `next_code` such that `next_code[n]` is the smallest codeword with code length `n`."

This I don't really understand the logic of:

```

for bits in range(2, MAX_BITS+1):
	next_code.append((next_code[bits-1] + bl_count[bits-1]) << 1)
print(next_code) # [0, 0, 2, 6]

```

Why does this work? Maybe this has something to do with the canonicality of the huffman table. Maybe that, but it could also be something else.

I am going to mark areas which I do not understand as DONOTUNDERSTAND and then return to them later on. Let's just assume that this works and try to understand it later on...

Here is my very initial draft of the function which converts the bitlengths and the alphabet to a canonical huffman tree:

```

def bitlengths_to_tree(bitlengths: list, alphabet: list) -> HuffmanTree:
	# Converts a list of bitlengths to a huffman tree with the given alphabet (the alphabet is assumed to already be in order)

	# This function returns a so called "canonical" huffman tree.

	max_bit_len = max(bitlengths) # Get the maximum length of all the lengths.

	bit_length_counts = [bitlengths.count(x) if x != 0 else 0 for x in range(max_bit_len+1)] # This is a list of the count of all of the lengths, for example the value at index 0 of this list is the amount of occurences of the value of zero in the bitlengths list. then the value at index 1 is the total amount of the value 1 which is in the bitlength list and so on...


	# "Next, we compute next_code such that next_code[n] is the smallest codeword with code length n."

	# First initialize next_code to [0,0], because, when n == 0, aka code length is zero, then the smallest codeword is nothing, so it doesn't really matter, then on n == 1 case the smallest codeword is 0b0 , because the other possibility is 0b1, which is of course larger, so we automatically know the first two.

	next_code = [0, 0]

	for i in range(2, max_bit_len+1): # Go through all of the bitlengths.

		# I don't really understand how this works, but let's return to this later. DONOTUNDERSTAND

		next_code.append((next_code[i-1] + bl_count[i-1]) << 1)

		'''

		next_code = [0, 0]
		for bits in range(2, MAX_BITS+1):
			next_code.append((next_code[bits-1] + bl_count[bits-1]) << 1)
		print(next_code) # [0, 0, 2, 6]

		'''

	output_tree = HuffmanTree()

	for c, bitlength in zip(alphabet, bitlengths):
		if bitlength != 0:
			# def add_value(self, path_int: int, n: int, value) -> None: # A wrapper around add_node

			output_tree.add_value(next_code[bitlength], bitlength, c) # Add the alphabet to the thing.
			next_code[bitlength] += 1 # This works, because initially next_code[n] is the smallest codeword with bitlength zero, and we need to add one to this, because then when we encounter another code with the same bitlength, we add the new value (aka the value which we added one to). This assumes that the data is not malformed, because for example we could have many codes with the same bitlength, and then when we add to this number, we can flow over and next_code[n] is of bitlength n+1 instead and that messes up our decoding.

	return output_tree # Return the decoded tree object...



```

Let's write a test for this...

Here:

```

def test_bitlengths_to_tree() -> None:

	# bitlengths_to_tree(bitlengths, alphabet)
	alphabet = 'ABCD'
	bl = [2, 1, 3, 3]

	tree = bitlengths_to_tree(bl, alphabet)

	r = bitreader.Bitreader(int_to_bytes(0b00010110111, 11))

	correct_answers = ["B", "B", "B", "A", "C", "D"]

	for i in range(len(correct_answers)):
		# This should decode the correct answer...
		sym = tree.read_symbol(r)
		#print("We read this symbol: "+str(sym))
		assert sym == correct_answers[i]

	print("test_bitlengths_to_tree passed!!!")
	return

```

and after a couple of tweaks, here is the working version of the function:

```

def bitlengths_to_tree(bitlengths: list, alphabet: list) -> HuffmanTree:
	# Converts a list of bitlengths to a huffman tree with the given alphabet (the alphabet is assumed to already be in order)

	# This function returns a so called "canonical" huffman tree.

	max_bit_len = max(bitlengths) # Get the maximum length of all the lengths.

	bit_length_counts = [bitlengths.count(x) if x != 0 else 0 for x in range(max_bit_len+1)] # This is a list of the count of all of the lengths, for example the value at index 0 of this list is the amount of occurences of the value of zero in the bitlengths list. then the value at index 1 is the total amount of the value 1 which is in the bitlength list and so on...


	# "Next, we compute next_code such that next_code[n] is the smallest codeword with code length n."

	# First initialize next_code to [0,0], because, when n == 0, aka code length is zero, then the smallest codeword is nothing, so it doesn't really matter, then on n == 1 case the smallest codeword is 0b0 , because the other possibility is 0b1, which is of course larger, so we automatically know the first two.

	next_code = [0, 0]

	for i in range(2, max_bit_len+1): # Go through all of the bitlengths.

		# I don't really understand how this works, but let's return to this later. DONOTUNDERSTAND

		next_code.append((next_code[i-1] + bit_length_counts[i-1]) << 1)

		'''

		next_code = [0, 0]
		for bits in range(2, MAX_BITS+1):
			next_code.append((next_code[bits-1] + bl_count[bits-1]) << 1)
		print(next_code) # [0, 0, 2, 6]

		'''

	print("Here is the value of next_code: "+str(next_code))

	output_tree = HuffmanTree()

	for c, bitlength in zip(alphabet, bitlengths):
		if bitlength != 0:
			# def add_value(self, path_int: int, n: int, value) -> None: # A wrapper around add_node
			print("Now trying to add "+str(c)+" to bit path "+str(bin(next_code[bitlength])[2:]))
			output_tree.add_value(next_code[bitlength], bitlength, c) # Add the alphabet to the thing.
			next_code[bitlength] += 1 # This works, because initially next_code[n] is the smallest codeword with bitlength zero, and we need to add one to this, because then when we encounter another code with the same bitlength, we add the new value (aka the value which we added one to). This assumes that the data is not malformed, because for example we could have many codes with the same bitlength, and then when we add to this number, we can flow over and next_code[n] is of bitlength n+1 instead and that messes up our decoding.

	return output_tree # Return the decoded tree object...

```

Let's continue on!

## Implementing some more bullshit

Uh oh... "However, the DEFLATE spec adds yet another twist. Rather than just specifying the code lengths directly, for even greater compactness, the code length sequences themselves are compressed using a Huffman code! The alphabet for the code lengths is as follows:"

There are layers upon layers of different compression algorithms in use.

Ok, so as I understand it, there is the alphabet and the codelengths. These codelengths are used to create the canonical huffman tree with the additional requirements. However, the codelengths list isn't given directly, but instead it is given as another canonical huffman tree with the additional restrictions the codelengths of which are encoded as the bitstream.

Here is my very initial draft of the function which decodes the trees from the data:

```

code_length_orders = [16, 17, 18, 0, 8, 7, 9, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15] # This is the order of the the bitlengths when decoding the code length sequences.

def decode_trees(r) -> list: # This shit decodes the trees from the bitreader object r
	HLIT = r.read_n_bits(5) + 257
	HDIST = r.read_n_bits(5) + 1
	HCLEN = r.read_n_bits(4) + 4


	code_length_tree_bitlengths = [0 for _ in range(19)] # Just assign zeros for now. This makes it easy to use the CodeLengthsCodesOrder to actually put the values at the correct indexes.

	for i in range(HCLEN):
		code_length_tree_bitlengths[code_length_orders[i]] = r.read_n_bits(3)

	# Construct the codelength tree. This will be used to actually get the codelengths.

	code_length_tree = bitlengths_to_tree(code_length_tree_bitlengths, [x for x in range(19)])

	# Read literal/length + distance code length list, this will take advantage of the previously generated code_length_tree .

	bitlengths = [] # This will be the list passed to bitlengths_to_tree which will give us the very final tree used to decode the data.


	'''

	Symbol	Meaning

	0 - 15	Represent code lengths of 0 - 15
	16	    Copy the previous code length 3 - 6 times. The next 2 bits indicate repeat length ( 0 = 3, ..., 3 = 6)
	17	    Repeat a code length of 0 for 3 - 10 times. (3 bits of length)
	18	    Repeat a code length of 0 for 11 - 138 times. (7 bits of length)

	'''

	while len(bitlengths) < HLIT + HDIST: # Decode the literal/(length + distance) trees.
		symbol = code_length_tree.read_symbol(r) # Read a symbol from the code length tree.
		if 0 <= symbol <= 15:
			bitlengths.append(symbol)
		elif symbol == 16: # This means to copy the previous code length 3 - 6 times.
			repeat_count = r.read_n_bits(2) + 3 # Read how many times to repeat
			what_to_repeat = bitlengths[-1] # What to repeat
			bitlengths += [what_to_repeat for _ in range(repeat_count)] # Repeat code
		elif symbol == 17: # repeat 3..10 times .
			repeat_count = r.read_n_bits(3) + 3 # Read how many times to repeat
			bitlengths += [0 for _ in range(repeat_count)] # Repeat code
		elif symbol == 18: # repeat 11..138 times.
			repeat_count = r.read_n_bits(7) + 11 # Read how many times to repeat
			bitlengths += [0 for _ in range(repeat_count)] # Repeat code
		else:
			print("Invalid symbol when decoding length tree: "+str(symbol))
			assert False

	# Final tree construction. Now that we have the bitlengths, we can finally get our literal/(length + distance) trees and the distance tree
	literal_length_distance_tree = bitlengths_to_tree(bitlengths[:HLIT], [x for x in range(286)]) # alphabet is to 0-285 inclusive
	distances_tree = bitlengths_to_tree(bitlengths[HLIT:], [x for x in range(30)]) # this is the tree used to decode the backwards distances.
	return literal_length_distance_tree, distances_tree


```

## Using these trees to decode a symbol from the bitstream

Ok, so now that we have the way to decode the trees from the bitstream, we need to implement a function which uses these functions to decode a symbol from the bitstream...

After a bit of fiddling, I came up with this:

```

length_extra_bits = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0] # These are the extra bits when reading the length codes from the bitstream.
length_bases = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258] # These are the length bases. We are going to add the integer to these when reading the bitstream.
# These are the tables used in the decoding of the backwards distances...
backwards_distance_extra_bits = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]

backwards_distance_bases = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577]

# Decodes a block from the bitstream with the given literal/length and distance trees.

def lz77_decode_block(r: Bitreader, literal_length_tree: HuffmanTree, distance_tree: HuffmanTree, output: list) -> None: # The output is the list of bytes to output. This function modifies it in-place.
	while True: # Main decoding loop.
		val = literal_length_tree.read_symbol(r) # Get value
		if val <= 256: # Literal value
			output.append(val)
		elif val == 256: # End of block
			return output # Return the final data
		else: # The value encodes the length portion.
			symbol = val - 257

			# Now read the extra bits. and add it to the baselength to get the final length
			final_length = r.read_n_bits(length_extra_bits[symbol]) + length_bases[symbol]
			# Now read the distance amount in a similar fashion
			distance_amount = distance_tree.read_symbol(r)
			final_distance = r.read_n_bits(backwards_distance_extra_bits[symbol]) + backwards_distance_bases[symbol]
			# Now we have the final <length, distance> pair decoded from the bitstream. add to the output.
			# Take advantage of pythons ability to access with negative indexes. Note that this works, because the index [-n] changes as we are appending to the list.
			for _ in range(final_length):
				output.append(output[-1*final_distance])

	return output # Return the final byte list.

```

which is my very initial draft of this function... Let's try to create the inflate_block_dynamic function now that we have all of the building blocks.

## Putting it together

Ok, so here is the very final decompression function:

```

def inflate_block_dynamic(reader, output) -> None:
	# First get the trees from the bitstream, then use these trees to decode the block data.
	# decode_trees(reader)
	literal_length_tree, distance_tree = decode_trees(reader) # Get the trees.
	# def lz77_decode_block(r: Bitreader, literal_length_tree: HuffmanTree, distance_tree: HuffmanTree, output: list) -> None:
	lz77_decode_block(reader, literal_length_tree, distance_tree, output) # This will modify output in-place.
	return


```

Now, I had a bit of trouble, because the zlib.compress actually seems to output static blocks for some reason. This is because my input is quite small and therefore can efficiently be encoded by a static block, with the predetermined trees.

Here is some code which decompresses static blocks:

```

def inflate_fixed_block(reader, output) -> None: # Fixed block. Uses a predetermined literal_length tree and a backwards distance tree.
	bl = ([8 for _ in range(144)] + [9 for _ in range(144, 256)] +
	[7 for _ in range(256, 280)] + [8 for _ in range(280, 288)])
	literal_length_tree = bitlengths_to_tree(bl, range(286))

	bl = [5 for _ in range(30)]
	distance_tree = bitlengths_to_tree(bl, range(30))

	# def bitlengths_to_tree(bitlengths: list, alphabet: list) -> HuffmanTree:

	lz77_decode_block(reader, literal_length_tree, distance_tree, output)
	return


```

Uh oh..


```

b'x\xda\xf3H\xcd\xc9\xc9W\x08\xcf/\xcaIQ\x04\x00\x1cI\x04>'
CMF == 120
CINFO == 7
CM == 8
CM test passed... (CM is equal to 8)
Here is BLOCK_TYPE: 1
final_distance == 447
Traceback (most recent call last):
  File "/home/oof/programming/implementing_zlib_decompress/main.py", line 195, in <module>
    exit(main())
  File "/home/oof/programming/implementing_zlib_decompress/main.py", line 178, in main
    result = our_decompress(compressed_data)
  File "/home/oof/programming/implementing_zlib_decompress/main.py", line 150, in our_decompress
    output = inflate(reader) # Main decompression algorithm.
  File "/home/oof/programming/implementing_zlib_decompress/main.py", line 95, in inflate
    inflate_fixed_block(reader, output)
  File "/home/oof/programming/implementing_zlib_decompress/main.py", line 64, in inflate_fixed_block
    lz77_decode_block(reader, literal_length_tree, distance_tree, output)
  File "/home/oof/programming/implementing_zlib_decompress/lz77.py", line 144, in lz77_decode_block
    output.append(output[-1*final_distance])
IndexError: list index out of range


```

fuck!

## Debugging a bit...

Ok, so let's copy the source code from the blog post and then compare our results with the results of the reference implementation.

Here is the output of the reference implementation:

```

Called inflate_block_fixed!
Decoded this symbol: 72
Decoded this symbol: 101
Decoded this symbol: 108
Decoded this symbol: 108
Decoded this symbol: 111
Decoded this symbol: 32
Decoded this symbol: 87
Decoded this symbol: 111
Decoded this symbol: 114
Decoded this symbol: 108
Decoded this symbol: 100
Decoded this symbol: 33
Decoded this symbol: 256
b'Hello World!'


```

and here is our output:

```

b'x\x9c\xf3H\xcd\xc9\xc9W\x08\xcf/\xcaIQ\x04\x00\x1cI\x04>'
CMF == 120
CINFO == 7
CM == 8
CM test passed... (CM is equal to 8)
Here is BLOCK_TYPE: 1
Decoded this value: 72
Decoded this value: 101
Decoded this value: 108
Decoded this value: 108
Decoded this value: 111
Decoded this value: 32
Decoded this value: 87
Decoded this value: 111
Decoded this value: 114
Decoded this value: 108
Decoded this value: 100
Decoded this value: 33
Decoded this value: 256
Decoded this value: 256
Decoded this value: 65
Decoded this value: 274
final_distance == 447
Traceback (most recent call last):
  File "/home/oof/programming/implementing_zlib_decompress/main.py", line 195, in <module>
    exit(main())
  File "/home/oof/programming/implementing_zlib_decompress/main.py", line 178, in main
    result = our_decompress(compressed_data)
  File "/home/oof/programming/implementing_zlib_decompress/main.py", line 150, in our_decompress
    output = inflate(reader) # Main decompression algorithm.
  File "/home/oof/programming/implementing_zlib_decompress/main.py", line 95, in inflate
    inflate_fixed_block(reader, output)
  File "/home/oof/programming/implementing_zlib_decompress/main.py", line 64, in inflate_fixed_block
    lz77_decode_block(reader, literal_length_tree, distance_tree, output)
  File "/home/oof/programming/implementing_zlib_decompress/lz77.py", line 145, in lz77_decode_block
    output.append(output[-1*final_distance])
IndexError: list index out of range


```


why aren't we stopping on the 256 symbol???

(aka here)

```
Decoded this value: 33
Decoded this value: 256
Decoded this value: 256
Decoded this value: 65
```

here in lz77.py :

```
		if val <= 256: # Literal value
			output.append(val)
```

that is supposed to just be less than. Let's change it.

There you go!

```

b'x\x9c\xf3H\xcd\xc9\xc9W\x08\xcf/\xcaIQ\x04\x00\x1cI\x04>'
CMF == 120
CINFO == 7
CM == 8
CM test passed... (CM is equal to 8)
Here is BLOCK_TYPE: 1
Decoded this value: 72
Decoded this value: 101
Decoded this value: 108
Decoded this value: 108
Decoded this value: 111
Decoded this value: 32
Decoded this value: 87
Decoded this value: 111
Decoded this value: 114
Decoded this value: 108
Decoded this value: 100
Decoded this value: 33
Decoded this value: 256
Here is the result: b'Hello World!'
Here is the decompressed output: Hello World!


```

## Trying to test the dynamic blocks.

Ok, so now we know that the static blocks work, but the main boss is yet to be defeated. We need to also test the algorithm to decode the trees from the bitstream.




























