
# Implementing a PNG decoder

This blog post is based on this another blog post: https://pyokagan.name/blog/2019-10-14-png/ . Feel free to follow along.

## Prerequisites

 - A zlib implementation

The PNG spec is just wrapper around the zlib compression algorithm and zlib is itself a wrapper around the DEFLATE algorithm. I actually implemented zlib myself here: https://personnumber3377.github.io/projects/implementing_zlib_decompress.html . It turned out alright in my opinion. During the development of the PNG reader, I am actually going to use that zlib decompressor which I implemented myself.

## Starting out

Ok, so as many file formats, the PNG file consists of different "blocks" each of which serve a distinct purpose. In addition, PNG files have a distinct file header to signify that they are PNG files:

{% raw %}
```

PngSignature = b'\x89PNG\r\n\x1a\n'

```
{% endraw %}

Actually, I am just going to implement a file called "const.py" where I store all of the constants (as the name suggests).

Here is the beginnings of my code:

{% raw %}
```


# Main PNG decoder entrypoint...

import sys
#import const
from const import * # Some constants
import struct # For reading binary data without having to worry about endianness etc etc..
import zlib # This is for zlib.crc32 only!

'''

SOME NOTES

Length	4-byte unsigned integer giving the number of bytes in the chunk's data field. The length counts only the data field, not itself, the chunk type, or the CRC. Zero is a valid length.
Chunk Type	A sequence of 4 bytes defining the chunk type.
Chunk Data	The data bytes appropriate to the chunk type, if any. This field can be of zero length.
CRC	A 4-byte CRC (Cyclic Redundancy Code) calculated on the preceding bytes in the chunk, including the chunk type field and the chunk data fields, but not including the length field. The CRC can be used to check for corruption of the data.

'''

def read_chunks(data: bytes) -> list: # Returns a list of the binary chunks.
	chunks = []
	while True: # While there are chunks to be read.
		chunk_header = data[:SIZEOF_CHUNK_HEADER] # Read the chunk header.
		print("chunk_header == "+str(chunk_header))
		print("len(chunk_header) == "+str(len(chunk_header)))
		data = data[SIZEOF_CHUNK_HEADER:] # Advance the data.
		chunk_length, chunk_type = struct.unpack('>I4s', chunk_header) # Decode the chunk header
		# Now read the chunk contents.
		chunk_data = data[:chunk_length]
		data = data[chunk_length:] # Advance the data.
		calculated_checksum = zlib.crc32(chunk_data, zlib.crc32(struct.pack('>4s', chunk_type))) # Calculate checksum.
		crc_bytes = data[:CHUNK_CRC_SIZE]
		data = data[CHUNK_CRC_SIZE:] # Advance data pointer.
		chunk_crc, = struct.unpack('>I', crc_bytes) # The expected CRC.
		if chunk_crc != calculated_checksum: # CRC mismatch, therefore data is corrupted!
			print("File is corrupted!")
			exit(1)
		chunks.append(tuple((chunk_data, chunk_type))) # Add the chunk and the chunk type to the list.
		print("chunk_type == "+str(chunk_type))
		if chunk_type == IEND_CHUNK_IDENTIFIER: # The last chunk. Break now.
			break
	return chunks

def read_png(data: bytes) -> None: # Just show as an image (for now).
	if data[:len(PNG_HEADER)] != PNG_HEADER: # Not a PNG file!
		print("File isn't a PNG file!")
		exit(1)
	data = data[len(PNG_HEADER):] # Skip the PNG header for reading the chunks
	chunks = read_chunks(data)
	# Get the chunk types as a list.
	chunk_types = [chunk[1] for chunk in chunks]
	# The very first chunk should be a b'IHDR' chunk.
	if chunk_types[0] != b'IHDR':
		print("Very first chunk should be a b'IHDR' chunk!")
		exit(1)
	return 0 # Return success

def main() -> int: # Main function
	# Read contents from the file supplied in argv[1]
	if len(sys.argv) < 2: # aka 1
		print("Usage: "+str(sys.argv[0])+" PNG_FILE")
		exit(1)
	filename = sys.argv[1]
	# Open file and read file as bytes
	fh = open(filename, "rb")
	data = fh.read()
	fh.close()
	# Now decode the data.
	read_png(data)
	return 0 # Return success


if __name__=="__main__":
	exit(main())


```
{% endraw %}

Basically, it is just code which loops over each chunk in the file and then adds all of the chunks to a list while reading.

Here is my code with some additional checks in-place:

{% raw %}
```


# Main PNG decoder entrypoint...

import sys
#import const
from const import * # Some constants
import struct # For reading binary data without having to worry about endianness etc etc..
import zlib # This is for zlib.crc32 only!

'''

SOME NOTES

Length	4-byte unsigned integer giving the number of bytes in the chunk's data field. The length counts only the data field, not itself, the chunk type, or the CRC. Zero is a valid length.
Chunk Type	A sequence of 4 bytes defining the chunk type.
Chunk Data	The data bytes appropriate to the chunk type, if any. This field can be of zero length.
CRC	A 4-byte CRC (Cyclic Redundancy Code) calculated on the preceding bytes in the chunk, including the chunk type field and the chunk data fields, but not including the length field. The CRC can be used to check for corruption of the data.

'''

def read_chunks(data: bytes) -> list: # Returns a list of the binary chunks.
	chunks = []
	while True: # While there are chunks to be read.
		chunk_header = data[:SIZEOF_CHUNK_HEADER] # Read the chunk header.
		print("chunk_header == "+str(chunk_header))
		print("len(chunk_header) == "+str(len(chunk_header)))
		data = data[SIZEOF_CHUNK_HEADER:] # Advance the data.
		chunk_length, chunk_type = struct.unpack('>I4s', chunk_header) # Decode the chunk header
		# Now read the chunk contents.
		chunk_data = data[:chunk_length]
		data = data[chunk_length:] # Advance the data.
		calculated_checksum = zlib.crc32(chunk_data, zlib.crc32(struct.pack('>4s', chunk_type))) # Calculate checksum.
		crc_bytes = data[:CHUNK_CRC_SIZE]
		data = data[CHUNK_CRC_SIZE:] # Advance data pointer.
		chunk_crc, = struct.unpack('>I', crc_bytes) # The expected CRC.
		if chunk_crc != calculated_checksum: # CRC mismatch, therefore data is corrupted!
			print("File is corrupted!")
			exit(1)
		chunks.append(tuple((chunk_data, chunk_type))) # Add the chunk and the chunk type to the list.
		print("chunk_type == "+str(chunk_type))
		if chunk_type == IEND_CHUNK_IDENTIFIER: # The last chunk. Break now.
			break
	return chunks

def read_png(data: bytes) -> None: # Just show as an image (for now).
	if data[:len(PNG_HEADER)] != PNG_HEADER: # Not a PNG file!
		print("File isn't a PNG file!")
		exit(1)
	data = data[len(PNG_HEADER):] # Skip the PNG header for reading the chunks
	chunks = read_chunks(data)
	# Get the chunk types as a list.
	chunk_types = [chunk[1] for chunk in chunks]
	# The very first chunk should be a b'IHDR' chunk.
	#if chunk_types[0] != b'IHDR':
	#	print("Very first chunk should be a b'IHDR' chunk!")
	#	exit(1)
	assert chunk_types[0] == IHDR_CHUNK_IDENTIFIER # First chunk should be "IHDR"
	assert chunk_types[-1] == IEND_CHUNK_IDENTIFIER # Final chunk should be "IEND"
	assert IDAT_CHUNK_IDENTIFIER in chunk_types # There should be atleast one data chunk.



	return 0 # Return success

def main() -> int: # Main function
	# Read contents from the file supplied in argv[1]
	if len(sys.argv) < 2: # aka 1
		print("Usage: "+str(sys.argv[0])+" PNG_FILE")
		exit(1)
	filename = sys.argv[1]
	# Open file and read file as bytes
	fh = open(filename, "rb")
	data = fh.read()
	fh.close()
	# Now decode the data.
	read_png(data)
	return 0 # Return success


if __name__=="__main__":
	exit(main())


```
{% endraw %}

## Interpreting the IHDR chunk:

Ok, so let's start with the header chunk. It should always be 13 bytes in length and it has well defined fields:










## Debugging the zlib library.

Ok, so as it turns out, there exists a bug in my zlib library and that causes shit to go haywire.

Here is the program output:

{% raw %}
```

chunk_header == b'\x00\x00\x00\rIHDR'
len(chunk_header) == 8
chunk_type == b'IHDR'
chunk_header == b'\x00\x00\x00\x04gAMA'
len(chunk_header) == 8
chunk_type == b'gAMA'
chunk_header == b'\x00\x00\x00oIDAT'
len(chunk_header) == 8
chunk_type == b'IDAT'
chunk_header == b'\x00\x00\x00\x00IEND'
len(chunk_header) == 8
chunk_type == b'IEND'
Here is the IDAT data concatenated: b'x\x9c\xed\xd61\n\x800\x0cF\xe1\'dhO\xa1\xf7?U\x04\x8f!\xc4\xdd\xc5Ex\x1dR\xe8P(\xfc\x1fM(\xd9\x8a\x010^{~\x9c\xff\xba3\x83\x1du\x05G\x03\xca\x06\xa8\xf9\rX\xa0\x07N5\x1e"}\x80\\\x82T\xe3\x1b\xb0B\x0f\\\xdc.\x00y \x88\x92\xff\xe2\xa0\x016\xa0{@\x07\x94<\x10\x04\xd9\x00\x19P6@\x7f\x01\x1b\xf0\x00R \x1a\x9c'
CMF == 120
CINFO == 7
CM == 8
CM test passed... (CM is equal to 8)
Here is BLOCK_TYPE: 2
Traceback (most recent call last):
  File "/home/oof/programming/png_decoder/main.py", line 121, in <module>
    exit(main())
  File "/home/oof/programming/png_decoder/main.py", line 116, in main
    read_png(data)
  File "/home/oof/programming/png_decoder/main.py", line 100, in read_png
    decompressed_data = our_decompress(idat_data)
  File "/home/oof/programming/png_decoder/own_zlib.py", line 150, in our_decompress
    output = inflate(reader) # Main decompression algorithm.
  File "/home/oof/programming/png_decoder/own_zlib.py", line 98, in inflate
    inflate_block_dynamic(reader, output)
  File "/home/oof/programming/png_decoder/own_zlib.py", line 73, in inflate_block_dynamic
    lz77_decode_block(reader, literal_length_tree, distance_tree, output) # This will modify output in-place.
  File "/home/oof/programming/png_decoder/lz77.py", line 127, in lz77_decode_block
    val = literal_length_tree.read_symbol(r) # Get value
  File "/home/oof/programming/png_decoder/huffman.py", line 118, in read_symbol
    if cur_node.isLeaf():
AttributeError: 'NoneType' object has no attribute 'isLeaf'



```
{% endraw %}

we can see that it is a so called "dynamic" block, which makes sense, because I didn't actually do the stuff when programming the zlib library. I didn't add a test for the dynamic trees, because encoding simple strings with zlib.compress yields usually "static" blocks.

Let's take a look at the code from here: https://pyokagan.name/blog/2019-10-18-zlibinflate/ and see where our code fucks up.

Here is the reference implementation:

{% raw %}
```

class BitReader:
    def __init__(self, mem):
        self.mem = mem
        self.pos = 0
        self.b = 0
        self.numbits = 0

    def read_byte(self):
        self.numbits = 0 # discard unread bits
        b = self.mem[self.pos]
        self.pos += 1
        return b

    def read_bit(self):
        if self.numbits <= 0:
            self.b = self.read_byte()
            self.numbits = 8
        self.numbits -= 1
        # shift bit out of byte
        bit = self.b & 1
        self.b >>= 1
        return bit

    def read_bits(self, n):
        o = 0
        for i in range(n):
            o |= self.read_bit() << i
        return o

    def read_bytes(self, n):
        # read bytes as an integer in little-endian
        o = 0
        for i in range(n):
            o |= self.read_byte() << (8 * i)
        return o

def decompress(input):
    r = BitReader(input)
    CMF = r.read_byte()
    CM = CMF & 15 # Compression method
    if CM != 8: # only CM=8 is supported
        raise Exception('invalid CM')
    CINFO = (CMF >> 4) & 15 # Compression info
    if CINFO > 7:
        raise Exception('invalid CINFO')
    FLG = r.read_byte()
    if (CMF * 256 + FLG) % 31 != 0:
        raise Exception('CMF+FLG checksum failed')
    FDICT = (FLG >> 5) & 1 # preset dictionary?
    if FDICT:
        raise Exception('preset dictionary not supported')
    out = inflate(r) # decompress DEFLATE data
    ADLER32 = r.read_bytes(4) # Adler-32 checksum (for this exercise, we ignore it)
    return out

def inflate(r):
    BFINAL = 0
    out = []
    while not BFINAL:
        BFINAL = r.read_bit()
        BTYPE = r.read_bits(2)
        if BTYPE == 0:
            inflate_block_no_compression(r, out)
        elif BTYPE == 1:
            inflate_block_fixed(r, out)
        elif BTYPE == 2:
            inflate_block_dynamic(r, out)
        else:
            raise Exception('invalid BTYPE')
    return bytes(out)

def inflate_block_no_compression(r, o):
    LEN = r.read_bytes(2)
    NLEN = r.read_bytes(2)
    o.extend(r.read_byte() for _ in range(LEN))

def code_to_bytes(code, n):
    # Encodes a code that is `n` bits long into bytes that is conformant with DEFLATE spec
    out = [0]
    numbits = 0
    for i in range(n-1, -1, -1):
        if numbits >= 8:
            out.append(0)
            numbits = 0
        out[-1] |= (1 if code & (1 << i) else 0) << numbits
        numbits += 1
    return bytes(out)

class Node:
    def __init__(self):
        self.symbol = ''
        self.left = None
        self.right = None

class HuffmanTree:
    def __init__(self):
        self.root = Node()
        self.root.symbol = ''

    def insert(self, codeword, n, symbol):
        # Insert an entry into the tree mapping `codeword` of len `n` to `symbol`
        node = self.root
        for i in range(n-1, -1, -1):
            b = codeword & (1 << i)
            if b:
                next_node = node.right
                if next_node is None:
                    node.right = Node()
                    next_node = node.right
            else:
                next_node = node.left
                if next_node is None:
                    node.left = Node()
                    next_node = node.left
            node = next_node
        node.symbol = symbol

def decode_symbol(r, t):
    "Decodes one symbol from bitstream `r` using HuffmanTree `t`"
    node = t.root
    while node.left or node.right:
        b = r.read_bit()
        node = node.right if b else node.left
    return node.symbol

LengthExtraBits = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3,
        3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
LengthBase = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43,
        51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]
DistanceExtraBits = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7,
        8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]
DistanceBase = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257,
        385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385,
        24577]

def inflate_block_data(r, literal_length_tree, distance_tree, out):
    while True:
        sym = decode_symbol(r, literal_length_tree)
        if sym <= 255: # Literal byte
            out.append(sym)
        elif sym == 256: # End of block
            return
        else: # <length, backward distance> pair
            sym -= 257
            length = r.read_bits(LengthExtraBits[sym]) + LengthBase[sym]
            dist_sym = decode_symbol(r, distance_tree)
            dist = r.read_bits(DistanceExtraBits[dist_sym]) + DistanceBase[dist_sym]
            for _ in range(length):
                out.append(out[-dist])

def bl_list_to_tree(bl, alphabet):
    MAX_BITS = max(bl)
    bl_count = [sum(1 for x in bl if x == y and y != 0) for y in range(MAX_BITS+1)]
    next_code = [0, 0]
    for bits in range(2, MAX_BITS+1):
        next_code.append((next_code[bits-1] + bl_count[bits-1]) << 1)
    t = HuffmanTree()
    for c, bitlen in zip(alphabet, bl):
        if bitlen != 0:
            t.insert(next_code[bitlen], bitlen, c)
            next_code[bitlen] += 1
    return t

CodeLengthCodesOrder = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]

def decode_trees(r):
    # The number of literal/length codes
    HLIT = r.read_bits(5) + 257

    # The number of distance codes
    HDIST = r.read_bits(5) + 1

    # The number of code length codes
    HCLEN = r.read_bits(4) + 4

    # Read code lengths for the code length alphabet
    code_length_tree_bl = [0 for _ in range(19)]
    for i in range(HCLEN):
        code_length_tree_bl[CodeLengthCodesOrder[i]] = r.read_bits(3)

    # Construct code length tree
    code_length_tree = bl_list_to_tree(code_length_tree_bl, range(19))

    # Read literal/length + distance code length list
    bl = []
    while len(bl) < HLIT + HDIST:
        sym = decode_symbol(r, code_length_tree)
        if 0 <= sym <= 15: # literal value
            bl.append(sym)
        elif sym == 16:
            # copy the previous code length 3..6 times.
            # the next 2 bits indicate repeat length ( 0 = 3, ..., 3 = 6 )
            prev_code_length = bl[-1]
            repeat_length = r.read_bits(2) + 3
            bl.extend(prev_code_length for _ in range(repeat_length))
        elif sym == 17:
            # repeat code length 0 for 3..10 times. (3 bits of length)
            repeat_length = r.read_bits(3) + 3
            bl.extend(0 for _ in range(repeat_length))
        elif sym == 18:
            # repeat code length 0 for 11..138 times. (7 bits of length)
            repeat_length = r.read_bits(7) + 11
            bl.extend(0 for _ in range(repeat_length))
        else:
            raise Exception('invalid symbol')

    # Construct trees
    literal_length_tree = bl_list_to_tree(bl[:HLIT], range(286))
    distance_tree = bl_list_to_tree(bl[HLIT:], range(30))
    return literal_length_tree, distance_tree

def inflate_block_dynamic(r, o):
    literal_length_tree, distance_tree = decode_trees(r)
    inflate_block_data(r, literal_length_tree, distance_tree, o)

def inflate_block_fixed(r, o):
    bl = ([8 for _ in range(144)] + [9 for _ in range(144, 256)] +
        [7 for _ in range(256, 280)] + [8 for _ in range(280, 288)])
    literal_length_tree = bl_list_to_tree(bl, range(286))

    bl = [5 for _ in range(30)]
    distance_tree = bl_list_to_tree(bl, range(30))

    inflate_block_data(r, literal_length_tree, distance_tree, o)

import zlib
#x = zlib.compress(b'Hello World!')
#print(decompress(x)) # b'Hello World!'


compressed_data = b'x\x9c\xed\xd61\n\x800\x0cF\xe1\'dhO\xa1\xf7?U\x04\x8f!\xc4\xdd\xc5Ex\x1dR\xe8P(\xfc\x1fM(\xd9\x8a\x010^{~\x9c\xff\xba3\x83\x1du\x05G\x03\xca\x06\xa8\xf9\rX\xa0\x07N5\x1e"}\x80\\\x82T\xe3\x1b\xb0B\x0f\\\xdc.\x00y \x88\x92\xff\xe2\xa0\x016\xa0{@\x07\x94<\x10\x04\xd9\x00\x19P6@\x7f\x01\x1b\xf0\x00R \x1a\x9c' # This is the data from the PNG file for now.

print(decompress(compressed_data))




```
{% endraw %}

Here is the output of this code:

{% raw %}
```

def lz77_decode_block(r: Bitreader, literal_length_tree: HuffmanTree, distance_tree: HuffmanTree, output: list) -> None: # The output is the list of bytes to output. This function modifies it in-place.
	while True: # Main decoding loop.
		val = literal_length_tree.read_symbol(r) # Get value
		print("Decoded this value: "+str(val))
		if val < 256: # Literal value
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
				print("final_distance == "+str(final_distance))
				output.append(output[-1*final_distance])

	return output # Return the final byte list.

```
{% endraw %}

here:

{% raw %}
```

Decoded this value: 1
Decoded this value: 255
Decoded this value: 0
Decoded this value: 8
Decoded this value: 0
Decoded this value: 0
Decoded this value: 0
Decoded this value: 0
Decoded this value: 8
Decoded this value: 267


```
{% endraw %}

and here is the reference output:

{% raw %}
```

Decoded this value: 1
Decoded this value: 255
Decoded this value: 0
Decoded this value: 8
Decoded this value: 0
Decoded this value: 0
Decoded this value: 0
Decoded this value: 0
Decoded this value: 8
Decoded this value: 267
Decoded this value: 9
Decoded this value: 272
Decoded this value: 277
Decoded this value: 9
Decoded this value: 4
Decoded this value: 0
Decoded this value: 31
# SNIP

```
{% endraw %}

Here is some more debug info from my implementation:

{% raw %}
```

Decoded this value: 1
Decoded this value: 255
Decoded this value: 0
Decoded this value: 8
Decoded this value: 0
Decoded this value: 0
Decoded this value: 0
Decoded this value: 0
Decoded this value: 8
Decoded this value: 267
final_length == 15
final_distance == 36
final_distance == 36



```
{% endraw %}

and here is the reference implementation:

{% raw %}
```

Decoded this value: 1
Decoded this value: 255
Decoded this value: 0
Decoded this value: 8
Decoded this value: 0
Decoded this value: 0
Decoded this value: 0
Decoded this value: 0
Decoded this value: 8
Decoded this value: 267
final_length == 4
final_distance == 15

```
{% endraw %}

Here is my current code:

{% raw %}
```
def lz77_decode_block(r: Bitreader, literal_length_tree: HuffmanTree, distance_tree: HuffmanTree, output: list) -> None: # The output is the list of bytes to output. This function modifies it in-place.
	while True: # Main decoding loop.
		val = literal_length_tree.read_symbol(r) # Get value
		print("Decoded this value: "+str(val))
		if val < 256: # Literal value
			output.append(val)
		elif val == 256: # End of block
			return output # Return the final data
		else: # The value encodes the length portion.
			symbol = val - 257
			print("length_bases[symbol] == "+str(length_bases[symbol]))
			print("length_extra_bits[symbol] == "+str(length_extra_bits[symbol]))
			# Now read the extra bits. and add it to the baselength to get the final length
			final_length = r.read_n_bits(length_extra_bits[symbol]) + length_bases[symbol]
			# Now read the distance amount in a similar fashion
			distance_amount = distance_tree.read_symbol(r)
			print("backwards_distance_extra_bits[symbol] == "+str(backwards_distance_extra_bits[symbol]))
			print("backwards_distance_bases[symbol] == "+str(backwards_distance_bases[symbol]))
			final_distance = r.read_n_bits(backwards_distance_extra_bits[symbol]) + backwards_distance_bases[symbol]
			# Now we have the final <length, distance> pair decoded from the bitstream. add to the output.
			# Take advantage of pythons ability to access with negative indexes. Note that this works, because the index [-n] changes as we are appending to the list.
			print("final_length == "+str(final_length))
			print("final_distance == "+str(final_distance))
			for _ in range(final_length):
				#print("final_distance == "+str(final_distance))
				output.append(output[-1*final_distance])

	return output # Return the final byte list.
```
{% endraw %}

and here is the output:

{% raw %}
```
Decoded this value: 1
Decoded this value: 255
Decoded this value: 0
Decoded this value: 8
Decoded this value: 0
Decoded this value: 0
Decoded this value: 0
Decoded this value: 0
Decoded this value: 8
Decoded this value: 267
length_bases[symbol] == 15
length_extra_bits[symbol] == 1
backwards_distance_extra_bits[symbol] == 4
backwards_distance_bases[symbol] == 33
final_length == 15
final_distance == 36
```
{% endraw %}

and here is what the output should be:

{% raw %}
```

Decoded this value: 1
Decoded this value: 255
Decoded this value: 0
Decoded this value: 8
Decoded this value: 0
Decoded this value: 0
Decoded this value: 0
Decoded this value: 0
Decoded this value: 8
Decoded this value: 267
length_bases[symbol] == 15
length_extra_bits[symbol] == 1
backwards_distance_extra_bits[symbol] == 0
backwards_distance_bases[symbol] == 4
final_length == 4
final_distance == 15

```
{% endraw %}

my code produces this: `backwards_distance_extra_bits[symbol] == 4` while the reference implementation has this: `backwards_distance_extra_bits[symbol] == 0`

Actually, the problem here:

{% raw %}
```

def lz77_decode_block(r: Bitreader, literal_length_tree: HuffmanTree, distance_tree: HuffmanTree, output: list) -> None: # The output is the list of bytes to output. This function modifies it in-place.
	while True: # Main decoding loop.
		val = literal_length_tree.read_symbol(r) # Get value
		print("Decoded this value: "+str(val))
		if val < 256: # Literal value
			output.append(val)
		elif val == 256: # End of block
			return output # Return the final data
		else: # The value encodes the length portion.
			symbol = val - 257
			print("length_bases[symbol] == "+str(length_bases[symbol]))
			print("length_extra_bits[symbol] == "+str(length_extra_bits[symbol]))
			# Now read the extra bits. and add it to the baselength to get the final length
			final_length = r.read_n_bits(length_extra_bits[symbol]) + length_bases[symbol]
			# Now read the distance amount in a similar fashion
			distance_amount = distance_tree.read_symbol(r)
			print("backwards_distance_extra_bits[symbol] == "+str(backwards_distance_extra_bits[symbol]))
			print("backwards_distance_bases[symbol] == "+str(backwards_distance_bases[symbol]))
			final_distance = r.read_n_bits(backwards_distance_extra_bits[symbol]) + backwards_distance_bases[symbol]
			# Now we have the final <length, distance> pair decoded from the bitstream. add to the output.
			# Take advantage of pythons ability to access with negative indexes. Note that this works, because the index [-n] changes as we are appending to the list.
			print("final_length == "+str(final_length))
			print("final_distance == "+str(final_distance))
			for _ in range(final_length):
				#print("final_distance == "+str(final_distance))
				output.append(output[-1*final_distance])

	return output # Return the final byte list.
```
{% endraw %}

because I never actually use the `distance_amount` variable anywhere. I had quite a brain fart here and that caused shit to go wrong..

After fixing this function looks like this:

{% raw %}
```
def lz77_decode_block(r: Bitreader, literal_length_tree: HuffmanTree, distance_tree: HuffmanTree, output: list) -> None: # The output is the list of bytes to output. This function modifies it in-place.
	while True: # Main decoding loop.
		val = literal_length_tree.read_symbol(r) # Get value
		print("Decoded this value: "+str(val))
		if val < 256: # Literal value
			output.append(val)
		elif val == 256: # End of block
			return output # Return the final data
		else: # The value encodes the length portion.
			symbol = val - 257
			print("length_bases[symbol] == "+str(length_bases[symbol]))
			print("length_extra_bits[symbol] == "+str(length_extra_bits[symbol]))
			# Now read the extra bits. and add it to the baselength to get the final length
			final_length = r.read_n_bits(length_extra_bits[symbol]) + length_bases[symbol]
			# Now read the distance amount in a similar fashion
			distance_symbol = distance_tree.read_symbol(r)

			print("backwards_distance_extra_bits[distance_symbol] == "+str(backwards_distance_extra_bits[distance_symbol]))
			print("backwards_distance_bases[distance_symbol] == "+str(backwards_distance_bases[distance_symbol]))
			final_distance = r.read_n_bits(backwards_distance_extra_bits[distance_symbol]) + backwards_distance_bases[distance_symbol]
			# Now we have the final <length, distance> pair decoded from the bitstream. add to the output.
			# Take advantage of pythons ability to access with negative indexes. Note that this works, because the index [-n] changes as we are appending to the list.
			print("final_length == "+str(final_length))
			print("final_distance == "+str(final_distance))
			for _ in range(final_length):
				#print("final_distance == "+str(final_distance))
				output.append(output[-1*final_distance])

	return output # Return the final byte list.
```
{% endraw %}

After these fixes, my PNG data get's correctly decompressed! Good!

## Decoding the decompressed data

Ok, so now that we can extract the data from the scanlines. The very first byte signifies the so called "filter type". The blog post which I am following doesn't really shed that much light on these filter types and how they were chosen, but I am just going to take that as granted and implement them.

Here is my main decoding function:

{% raw %}
```

def read_png(data: bytes) -> None: # Just show as an image (for now).
	if data[:len(PNG_HEADER)] != PNG_HEADER: # Not a PNG file!
		print("File isn't a PNG file!")
		exit(1)
	data = data[len(PNG_HEADER):] # Skip the PNG header for reading the chunks
	chunks = read_chunks(data)
	# Get the chunk types as a list.
	chunk_types = [chunk[1] for chunk in chunks]
	# The very first chunk should be a b'IHDR' chunk.
	#if chunk_types[0] != b'IHDR':
	#	print("Very first chunk should be a b'IHDR' chunk!")
	#	exit(1)
	assert chunk_types[0] == IHDR_CHUNK_IDENTIFIER # First chunk should be "IHDR"
	assert chunk_types[-1] == IEND_CHUNK_IDENTIFIER # Final chunk should be "IEND"
	assert IDAT_CHUNK_IDENTIFIER in chunk_types # There should be atleast one data chunk.

	# Now process the IHDR chunk:

	'''

	Field name	Field size	Description
	Width	4 bytes	4-byte unsigned integer. Gives the image dimensions in pixels. Zero is an invalid value.
	Height	4 bytes
	Bit depth	1 byte	A single-byte integer giving the number of bits per sample or per palette index (not per pixel). Only certain values are valid (see below).
	Color type	1 byte	A single-byte integer that defines the PNG image type. Valid values are 0 (grayscale), 2 (truecolor), 3 (indexed-color), 4 (greyscale with alpha) and 6 (truecolor with alpha).
	Compression method	1 byte	A single-byte integer that indicates the method used to compress the image data. Only compression method 0 (deflate/inflate compression with a sliding window of at most 32768 bytes) is defined in the spec.
	Filter method	1 byte	A single-byte integer that indicates the preprocessing method applied to the image data before compression. Only filter method 0 (adaptive filtering with five basic filter types) is defined in the spec.
	Interlace method	1 byte	A single-byte integer that indicates whether there is interlacing. Two values are defined in the spec: 0 (no interlace) or 1 (Adam7 interlace).

	'''

	ihdr_chunk, _ = chunks[0] # Get the IHDR chunk.

	# Unpack the values from that chunk...

	width, height, bitd, colort, compm, filterm, interlacem = struct.unpack('>IIBBBBB', ihdr_chunk)

	if compm != 0:
		print('invalid compression method')
		exit(1)
	if filterm != 0:
		print('invalid filter method')
		exit(1)

	chunks = chunks[1:] # Get rid of the IHDR chunk.

	# Now go over each IDAT chunk...

	idat_data = b''.join(chunk[0] for chunk in chunks if chunk[1] == IDAT_CHUNK_IDENTIFIER)

	print("Here is the IDAT data concatenated: "+str(idat_data))

	# Now use our own version of zlib.decompress to decompress it...

	decompressed_data = our_decompress(idat_data)
	print("Here is the decompressed data: "+str(decompressed_data))
	#decompressed_data = zlib.decompress(idat_data)
	print("Here is the length of the data: "+str(len(decompressed_data)))


	'''
	# Thanks to https://www.geeksforgeeks.org/break-list-chunks-size-n-python/ !!!

	    for i in range(0, len(l), n):
        yield l[i:i + n]

	'''

	# Just assume picture is 8 bit RGBA for now.

	scanline_size = 1 + width * 4 # Four bytes per pixel times the amount of pixels plus one, because the very first byte is the filter type.

	scanlines = [decompressed_data[i:i + scanline_size] for i in range(0, len(decompressed_data), scanline_size)]

	out = [[0 for _ in range(len(scanlines[0]) - 1)] for _ in range(len(scanlines))] # Final RGBA image. Zero out first, such that we do not need to do shit with this later on. " - 1" , because the first byte of the scanline is the filter type.



	# Just print the filter types for each scanline...

	filter_types = [scanline[0] for scanline in scanlines] # Just show the filter types for now.

	# Go over each scanline and add the data to the output list.
	tot_values = 0
	for r, scanline in enumerate(scanlines):
		# Main loop

		filt_type = scanline[0]

		scanline = scanline[1:] # Cut out the filter type byte.
		print("scanline == "+str(scanline))
		print("len(scanline) == "+str(len(scanline)))
		assert len(scanline) == width * BYTES_PER_PIXEL
		for c, byte in enumerate(scanline): # Loop over each byte in the


			tot_values += 1

			match filt_type: # Switch case basically. (This is only in python3.10 and upwards)
				case 0: # "None"
					reconstructed = byte
				case 1:
					reconstructed = byte + Reconstruct_a(r, c, out, scanlines)
				case 2:
					reconstructed = byte + Reconstruct_b(r, c, out, scanlines)
				case 3:
					reconstructed = byte + (Reconstruct_a(r, c, out, scanlines) + Reconstruct_b(r, c, out, scanlines)) // 2
				case 4:
					reconstructed = byte + PaethPredictor(Reconstruct_a(r, c, out, scanlines), Reconstruct_b(r, c, out, scanlines), Reconstruct_c(r, c, out, scanlines)) # Paeth stuff.
				case _: # Undefined filter type.
					print("Invalid filter type: "+str(filt_type))
					exit(1)

			out[r][c] = reconstructed & 0xff # Place the reconstructed byte into the output.

	#print(filter_types)

	print("tot_values == "+str(tot_values))

	# Now we have a reconstructed image in out.


	image_bytes = []

	for line in out:
		#image_bytes += line
		image_bytes.extend(line)
	#print("Here are the final bytes: "+str(image_bytes))


	# Now show the final output:

	import matplotlib.pyplot as plt
	import numpy as np
	plt.imshow(np.array(image_bytes).reshape((height, width, 4)))
	plt.show()

	print("[+] Done!")
	return 0 # Return success

```
{% endraw %}

and here are the helper functions:

{% raw %}
```

# These are used in the different filters.

BYTES_PER_PIXEL = 4 # This is the hardcoded value for one byte RGBA images which is usually the case.

def Reconstruct_a(r,c,out,scanlines): # out is the current output array and scanlines are the.. ya know.. scanlines. :D
	# return Recon[r * stride + c - bytesPerPixel] if c >= bytesPerPixel else 0
	return out[r][c - BYTES_PER_PIXEL] if c >= BYTES_PER_PIXEL else 0 # "r * stride" is basically the current scanline and then the c is the current pixel thing.

def Reconstruct_b(r,c,out,scanlines):
	# return Recon[(r-1) * stride + c] if r > 0 else 0
	return out[r-1][c] if r > 0 else 0 # The same thing as the same pixel on the previous scanline.

def Reconstruct_c(r,c,out,scanlines):
	# return Recon[(r-1) * stride + c - bytesPerPixel] if r > 0 and c >= bytesPerPixel else 0
	return out[r-1][c - BYTES_PER_PIXEL] if r > 0 and c >= BYTES_PER_PIXEL else 0 #

def PaethPredictor(a,b,c): # This is just a spec defined function
	p = a + b - c
	pa = abs(p - a)
	pb = abs(p - b)
	pc = abs(p - c)
	if pa <= pb and pa <= pc:
		Pr = a
	elif pb <= pc:
		Pr = b
	else:
		Pr = c
	return Pr

```
{% endraw %}

and it seems to work fine.

Now when I run my program on the PNG picture, it works! Good!

## Adding support for other image formats (let's start with "colort == 2" first)

Ok, so now we have a working PNG decoder. The problem is that it only works for RGBA images with color depth of 8 bits. Let's try to implement other picture types too.

Let's implement the `colort == 2` case (the `Truecolor	2	8, 16	Each pixel is a R,G,B triple.` image type) .

I think the easiest way to do this is to just improve the read_png function and then when showing the image, check if it has the alpha channel or not and then render it based on that.

Here is my current code:

{% raw %}
```



def read_png(data: bytes) -> None: # Just show as an image (for now).
	if data[:len(PNG_HEADER)] != PNG_HEADER: # Not a PNG file!
		print("File isn't a PNG file!")
		exit(1)

	global BYTES_PER_PIXEL # We may modify this when we read "colort" (the image type) . Up until then, this is assumed to be 4

	data = data[len(PNG_HEADER):] # Skip the PNG header for reading the chunks
	chunks = read_chunks(data)
	# Get the chunk types as a list.
	chunk_types = [chunk[1] for chunk in chunks]
	# The very first chunk should be a b'IHDR' chunk.
	#if chunk_types[0] != b'IHDR':
	#	print("Very first chunk should be a b'IHDR' chunk!")
	#	exit(1)
	assert chunk_types[0] == IHDR_CHUNK_IDENTIFIER # First chunk should be "IHDR"
	assert chunk_types[-1] == IEND_CHUNK_IDENTIFIER # Final chunk should be "IEND"
	assert IDAT_CHUNK_IDENTIFIER in chunk_types # There should be atleast one data chunk.

	# Now process the IHDR chunk:

	'''

	Field name	Field size	Description
	Width	4 bytes	4-byte unsigned integer. Gives the image dimensions in pixels. Zero is an invalid value.
	Height	4 bytes
	Bit depth	1 byte	A single-byte integer giving the number of bits per sample or per palette index (not per pixel). Only certain values are valid (see below).
	Color type	1 byte	A single-byte integer that defines the PNG image type. Valid values are 0 (grayscale), 2 (truecolor), 3 (indexed-color), 4 (greyscale with alpha) and 6 (truecolor with alpha).
	Compression method	1 byte	A single-byte integer that indicates the method used to compress the image data. Only compression method 0 (deflate/inflate compression with a sliding window of at most 32768 bytes) is defined in the spec.
	Filter method	1 byte	A single-byte integer that indicates the preprocessing method applied to the image data before compression. Only filter method 0 (adaptive filtering with five basic filter types) is defined in the spec.
	Interlace method	1 byte	A single-byte integer that indicates whether there is interlacing. Two values are defined in the spec: 0 (no interlace) or 1 (Adam7 interlace).

	'''

	ihdr_chunk, _ = chunks[0] # Get the IHDR chunk.

	# Unpack the values from that chunk...

	width, height, bitd, colort, compm, filterm, interlacem = struct.unpack('>IIBBBBB', ihdr_chunk)

	# Check for the image type. The usual case is the colort == 6 case (truecolor with alpha)

	# Let's check for the stuff.

	assert colort == 6 or colort == 2 # We only support truecolor with alpha (6) or truecolor (2).

	if colort == 2: # Truecolor without alpha channel, therefore set BYTES_PER_PIXEL to three instead of four.
		BYTES_PER_PIXEL = 3

	# Check for the bitdepth. (Must be 8 for now).

	assert bitd == 8

	if compm != 0:
		print('invalid compression method')
		exit(1)
	if filterm != 0:
		print('invalid filter method')
		exit(1)

	chunks = chunks[1:] # Get rid of the IHDR chunk.

	# Now go over each IDAT chunk...

	idat_data = b''.join(chunk[0] for chunk in chunks if chunk[1] == IDAT_CHUNK_IDENTIFIER)

	print("Here is the IDAT data concatenated: "+str(idat_data))

	# Now use our own version of zlib.decompress to decompress it...

	decompressed_data = our_decompress(idat_data)
	print("Here is the decompressed data: "+str(decompressed_data))
	#decompressed_data = zlib.decompress(idat_data)
	print("Here is the length of the data: "+str(len(decompressed_data)))


	'''
	# Thanks to https://www.geeksforgeeks.org/break-list-chunks-size-n-python/ !!!

	    for i in range(0, len(l), n):
        yield l[i:i + n]

	'''

	# Just assume picture is 8 bit RGBA for now.

	scanline_size = 1 + width * 4 # Four bytes per pixel times the amount of pixels plus one, because the very first byte is the filter type.

	scanlines = [decompressed_data[i:i + scanline_size] for i in range(0, len(decompressed_data), scanline_size)]

	out = [[0 for _ in range(len(scanlines[0]) - 1)] for _ in range(len(scanlines))] # Final RGBA image. Zero out first, such that we do not need to do shit with this later on. " - 1" , because the first byte of the scanline is the filter type.



	# Just print the filter types for each scanline...

	filter_types = [scanline[0] for scanline in scanlines] # Just show the filter types for now.

	# Go over each scanline and add the data to the output list.
	tot_values = 0
	for r, scanline in enumerate(scanlines):
		# Main loop

		filt_type = scanline[0]

		scanline = scanline[1:] # Cut out the filter type byte.
		print("scanline == "+str(scanline))
		print("len(scanline) == "+str(len(scanline)))
		print("BYTES_PER_PIXEL == "+str(BYTES_PER_PIXEL))
		print("colort == "+str(colort))
		assert len(scanline) == width * BYTES_PER_PIXEL
		for c, byte in enumerate(scanline): # Loop over each byte in the


			tot_values += 1

			match filt_type: # Switch case basically. (This is only in python3.10 and upwards)
				case 0: # "None"
					reconstructed = byte
				case 1:
					reconstructed = byte + Reconstruct_a(r, c, out, scanlines)
				case 2:
					reconstructed = byte + Reconstruct_b(r, c, out, scanlines)
				case 3:
					reconstructed = byte + (Reconstruct_a(r, c, out, scanlines) + Reconstruct_b(r, c, out, scanlines)) // 2
				case 4:
					reconstructed = byte + PaethPredictor(Reconstruct_a(r, c, out, scanlines), Reconstruct_b(r, c, out, scanlines), Reconstruct_c(r, c, out, scanlines)) # Paeth stuff.
				case _: # Undefined filter type.
					print("Invalid filter type: "+str(filt_type))
					exit(1)

			out[r][c] = reconstructed & 0xff # Place the reconstructed byte into the output.

	#print(filter_types)

	print("tot_values == "+str(tot_values))

	# Now we have a reconstructed image in out.


	image_bytes = []

	for line in out:
		#image_bytes += line
		image_bytes.extend(line)
	#print("Here are the final bytes: "+str(image_bytes))


	# Now show the final output:

	import matplotlib.pyplot as plt
	import numpy as np
	plt.imshow(np.array(image_bytes).reshape((height, width, BYTES_PER_PIXEL)))
	plt.show()

	print("[+] Done!")
	return 0 # Return success

```
{% endraw %}

except it results in this error:

{% raw %}
```

len(scanline) == 2560
BYTES_PER_PIXEL == 3
colort == 2
Traceback (most recent call last):
  File "/home/oof/programming/python_png_decoder/main.py", line 250, in <module>
    exit(main())
  File "/home/oof/programming/python_png_decoder/main.py", line 245, in main
    read_png(data)
  File "/home/oof/programming/python_png_decoder/main.py", line 186, in read_png
    assert len(scanline) == width * BYTES_PER_PIXEL
AssertionError


```
{% endraw %}

the image which I am using is 640 pixels wide, so therefore what if we divide 2560 by that?

{% raw %}
```
>>> 2560 / 640
4.0
```
{% endraw %}

What? That doesn't seem good. OOOooohhh, the bug is here: `scanline_size = 1 + width * 4 # Four bytes per pixel times the amount of pixels plus one, because the very first byte is the filter type.` . Let's replace that "4" with "BYTES_PER_PIXEL" and see what happens. After fixing this quick little bug. Now the thing works for both the `colort == 6` case and the `colort == 2` cases.

Supporting other bit depths other than 8 bits is quite difficult, because then the values aren't byte aligned, but let's worry about that later on. Actually, we do not need to worry about such cases, because if we look at the allowed bitdepths, we can see that the allowed bitdepths are all multiples of two, therefore we do not even need to try other cases, because we can just use some bit logic when reading.


























