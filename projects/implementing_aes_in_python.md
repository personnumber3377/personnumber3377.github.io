
# Implementing AES in python

This is just my implementation. It is not the fastest not only for the reason that it is in python, but I haven't really optimized code that much. This is just to practice programming. This is heavily inspired by this: https://blog.nindalf.com/posts/implementing-aes/

AES encrypts stuff in 16 byte segments called "states" which are basically matrices.

Here is the code in that said website:

```

func encrypt(state, expkey []uint32, rounds int) {
	keyi := 0
	addRoundKey(state, expkey[keyi:keyi+4])
	keyi += 4
	for i := 0; i < rounds; i++ {
		subBytes(state)
		shiftRows(state)
		mixColumns(state)
		addRoundKey(state, expkey[keyi:keyi+4])
		keyi += 4
	}
	subBytes(state)
	shiftRows(state)
	addRoundKey(state, expkey[keyi:keyi+4])
}

```

You may also want to take a look at https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#High-level_description_of_the_algorithm

I don't really understand the key expansion function, but let's learn as we go on.

The reason why we have the key expansion function is to make the key for each round. Let's just support 128 bit keys first. The key expansion algorithm is basically this: https://en.wikipedia.org/wiki/AES_key_schedule#The_key_schedule

...

Ok, so I am going to actually support all of the key sizes. Here is my current code:

```


import numpy as np
import rijndael

'''
The key size used for an AES cipher specifies the number of transformation rounds that convert the input, called the plaintext, into the final output, called the ciphertext. The number of rounds are as follows:

10 rounds for 128-bit keys.
12 rounds for 192-bit keys.
14 rounds for 256-bit keys.
'''

def fail(msg: str):
	print("[-] "+str(msg))
	exit(1)


def encrypt(state, expanded_key, num_rounds):
	# State is a 4x4 matrix which each element is one byte
	# expanded key is the expanded key
	# num rounds is the number of rounds.
	cur_key = 0

'''
i	1	2	3	4	5	6	7	8	9	10
rci	01	02	04	08	10	20	40	80	1B	36

0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
'''
RCON_VALUES = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36] # index is i and value is... ya know... the value of rcon_i .
# See https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
def rcon(i: int) -> bytes:
	return bytes([RCON_VALUES[i - 1], 0, 0, 0])

# Also define RotWord as a one-byte left circular shift:[note 6]
def RotWord(word: bytes) -> bytes:
	# The word should actually be a word
	assert len(word) == 4
	return bytes([word[1], word[2], word[3], word[0]])

def S(x: int) -> int:
	# https://en.wikipedia.org/wiki/Rijndael_S-box
	return rijndael.S_BOX[x]

def test_S() -> None:
	assert rijndael.S_BOX[0x9a] == 0xb8

def SubWord(word: bytes) -> bytes:
	assert len(word) == 4
	return bytes([S(x) for x in word])

VALID_VERSIONS = ["128", "192", "256"]

# This is the main key expansion function which does the heavy lifting.
def W(i: int, N: int, K: bytes) -> bytes:
	return # Stub for now.

def pad_key(orig_key: bytes, N: int) -> list: # This basically returns K
	if len(orig_key) > N*4: # If the amount of words is greater than N , then the key is too long.
		print("Key length too long! Choose a shorter encryption key or choose bigger AES version!")
		exit()
	return orig_key + bytes([0 for _ in range(N*4 - len(orig_key))])


def keyExpansion(encryption_key: bytes, AES_version: str):
	# Thanks wikipedia https://en.wikipedia.org/wiki/AES_key_schedule  !!!
	#if len(encryption_key) != 16:
	#	fail("Encryption key must be 128 bits in length! Other lengths are not supported!")
	
	# N as the length of the key in 32-bit words: 4 words for AES-128, 6 words for AES-192, and 8 words for AES-256
	# K0, K1, ... KN-1 as the 32-bit words of the original key
	# R as the number of round keys needed: 11 round keys for AES-128, 13 keys for AES-192, and 15 keys for AES-256
	# W0, W1, ... W4R-1 as the 32-bit words of the expanded key
	assert AES_version in VALID_VERSIONS
	num_bits = int(AES_version)
	N = (num_bits)//32 # Length of key in bits divided by 32
	R = 10+((VALID_VERSIONS.index(AES_version)*2)+1)
	encryption_key = pad_key(encryption_key, N)
	assert len(encryption_key) == N*4
	return
def run_tests() -> None:
	test_S()
	return

def main():
	run_tests() # Sanity tests.
	encryption_key = "oofoof"
	expanded_key = keyExpansion(bytes(encryption_key, encoding="ascii"), "128")



if __name__=="__main__":

	exit(main())




```

The function name keyExpansion is a bit bad, because I am actually going to encrypt with it and then I should move the key expansion to some other function. Ok, so NIST actually released example vectors: https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf . It seems that my key expansion works! Great! Here is my current code:

```


import numpy as np
import rijndael

'''
The key size used for an AES cipher specifies the number of transformation rounds that convert the input, called the plaintext, into the final output, called the ciphertext. The number of rounds are as follows:

10 rounds for 128-bit keys.
12 rounds for 192-bit keys.
14 rounds for 256-bit keys.
'''

def fail(msg: str):
	print("[-] "+str(msg))
	exit(1)


def encrypt(state, expanded_key, num_rounds):
	# State is a 4x4 matrix which each element is one byte
	# expanded key is the expanded key
	# num rounds is the number of rounds.
	cur_key = 0

'''
i	1	2	3	4	5	6	7	8	9	10
rci	01	02	04	08	10	20	40	80	1B	36

0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
'''
RCON_VALUES = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36] # index is i and value is... ya know... the value of rcon_i .
# See https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
def rcon(i: int) -> bytes:
	return bytes([RCON_VALUES[i - 1], 0, 0, 0])

# Also define RotWord as a one-byte left circular shift:[note 6]
def RotWord(word: bytes) -> bytes:
	# The word should actually be a word
	assert len(word) == 4
	return bytes([word[1], word[2], word[3], word[0]])

def S(x: int) -> int:
	# https://en.wikipedia.org/wiki/Rijndael_S-box
	return rijndael.S_BOX[x]

def test_S() -> None:
	assert rijndael.S_BOX[0x9a] == 0xb8

def SubWord(word: bytes) -> bytes:
	assert len(word) == 4
	return bytes([S(x) for x in word])

VALID_VERSIONS = ["128", "192", "256"]

def xor_bytes(a: bytes, b: bytes) -> bytes:
	assert len(a) == len(b)
	return bytes([a[i] ^ b[i] for i in range(len(a))])

# This is the main key expansion function which does the heavy lifting.
def W(i: int, N: int, K: bytes, W: list) -> bytes: # The W list is being filled as we go.
	if i < N:
		return K[i]
	elif i >= N and (i % N == 0 % N):
		return xor_bytes(xor_bytes((W[i-N]), SubWord(RotWord(W[i-1]))), rcon(i//N))
	elif i >= N and N > 6 and (i % N == 4 % N):
		return xor_bytes(W[i-N], SubWord(W[i-1]))
	else:
		print("paskaaa")
		return xor_bytes(W[i-N], W[i-1])

def pad_key(orig_key: bytes, N: int) -> list: # This basically returns K
	if len(orig_key) > N*4: # If the amount of words is greater than N , then the key is too long.
		print("Key length too long! Choose a shorter encryption key or choose bigger AES version!")
		exit()
	return orig_key + bytes([0 for _ in range(N*4 - len(orig_key))])

def splice_K(encryption_key: bytes) -> list:
	assert len(encryption_key) % 4 == 0
	return [encryption_key[x:x+4] for x in range(0, len(encryption_key),4)]


def key_expansion(encryption_key: bytes, AES_version: str):
	# Thanks wikipedia https://en.wikipedia.org/wiki/AES_key_schedule  !!!
	#if len(encryption_key) != 16:
	#	fail("Encryption key must be 128 bits in length! Other lengths are not supported!")
	
	# N as the length of the key in 32-bit words: 4 words for AES-128, 6 words for AES-192, and 8 words for AES-256
	# K0, K1, ... KN-1 as the 32-bit words of the original key
	# R as the number of round keys needed: 11 round keys for AES-128, 13 keys for AES-192, and 15 keys for AES-256
	# W0, W1, ... W4R-1 as the 32-bit words of the expanded key
	assert AES_version in VALID_VERSIONS
	num_bits = int(AES_version)
	N = (num_bits)//32 # Length of key in bits divided by 32
	R = 10+((VALID_VERSIONS.index(AES_version)*2)+1)
	encryption_key = pad_key(encryption_key, N)
	assert len(encryption_key) == N*4
	# Splice K
	K = splice_K(encryption_key)
	# Now here is the actual key expansion.
	W_list = []
	for i in range(4*R): # We include 4R.
		W_list.append(W(i, N, K, W_list))
	# Ok, so now the expanded key is in W_list
	#return W_list
	print(W_list)
	return W_list

def print_hex(byte_list: bytes) -> None:
	print("="*30)
	for x in byte_list:
		print(hex(int.from_bytes(x, byteorder='big')))
	print("="*30)

def test_key_expansion():
	string = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c"
	key = bytes([int(x, base=16) for x in string.split(" ")])
	expanded_key = key_expansion(bytes(key), "128")
	print_hex(expanded_key)



def run_tests() -> None:
	test_S()
	test_key_expansion()
	return

def main():
	run_tests() # Sanity tests.
	encryption_key = "oofoof"
	expanded_key = key_expansion(bytes(encryption_key, encoding="ascii"), "128")



if __name__=="__main__":

	exit(main())




```

Now that I have implemented the key expansion, it is time to actually implement the encryption function.

...

Ok, so usually I write the functions which compose the main function and tthat is what I am going to do here.

I am going to write out every matrix manipulation function first then I am going to write out the main encryption function.

Here is my current code.

```

import numpy as np
import rijndael
import copy
from typing import Iterable 
'''
The key size used for an AES cipher specifies the number of transformation rounds that convert the input, called the plaintext, into the final output, called the ciphertext. The number of rounds are as follows:

10 rounds for 128-bit keys.
12 rounds for 192-bit keys.
14 rounds for 256-bit keys.
'''

def fail(msg: str):
	print("[-] "+str(msg))
	exit(1)


def encrypt(state, expanded_key, num_rounds):
	# State is a 4x4 matrix which each element is one byte
	# expanded key is the expanded key
	# num rounds is the number of rounds.
	cur_key = 0

'''
i	1	2	3	4	5	6	7	8	9	10
rci	01	02	04	08	10	20	40	80	1B	36

0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
'''
RCON_VALUES = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36] # index is i and value is... ya know... the value of rcon_i .
# See https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
def rcon(i: int) -> bytes:
	return bytes([RCON_VALUES[i - 1], 0, 0, 0])

# Also define RotWord as a one-byte left circular shift:[note 6]
def RotWord(word: bytes) -> bytes:
	# The word should actually be a word
	assert len(word) == 4
	return bytes([word[1], word[2], word[3], word[0]])

def S(x: int) -> int:
	# https://en.wikipedia.org/wiki/Rijndael_S-box
	return rijndael.S_BOX[x]

def test_S() -> None:
	assert rijndael.S_BOX[0x9a] == 0xb8

def SubWord(word: bytes) -> bytes:
	assert len(word) == 4
	return bytes([S(x) for x in word])

VALID_VERSIONS = ["128", "192", "256"]

def xor_bytes(a: bytes, b: bytes) -> bytes:
	assert len(a) == len(b)
	return bytes([a[i] ^ b[i] for i in range(len(a))])

# This is the main key expansion function which does the heavy lifting.
def W(i: int, N: int, K: bytes, W: list) -> bytes: # The W list is being filled as we go.
	if i < N:
		return K[i]
	elif i >= N and (i % N == 0 % N):
		return xor_bytes(xor_bytes((W[i-N]), SubWord(RotWord(W[i-1]))), rcon(i//N))
	elif i >= N and N > 6 and (i % N == 4 % N):
		return xor_bytes(W[i-N], SubWord(W[i-1]))
	else:
		#print("paskaaa")
		return xor_bytes(W[i-N], W[i-1])

def pad_key(orig_key: bytes, N: int) -> list: # This basically returns K
	if len(orig_key) > N*4: # If the amount of words is greater than N , then the key is too long.
		print("Key length too long! Choose a shorter encryption key or choose bigger AES version!")
		exit()
	return orig_key + bytes([0 for _ in range(N*4 - len(orig_key))])

def pad_plain_text(orig_plaintext: bytes, length: int) -> list:
	return orig_plaintext + bytes([0 for _ in range(length - len(orig_plaintext))])

def splice_K(encryption_key: bytes) -> list:
	assert len(encryption_key) % 4 == 0
	return [encryption_key[x:x+4] for x in range(0, len(encryption_key),4)]


def key_expansion(encryption_key: bytes, AES_version: str):
	# Thanks wikipedia https://en.wikipedia.org/wiki/AES_key_schedule  !!!
	#if len(encryption_key) != 16:
	#	fail("Encryption key must be 128 bits in length! Other lengths are not supported!")
	
	# N as the length of the key in 32-bit words: 4 words for AES-128, 6 words for AES-192, and 8 words for AES-256
	# K0, K1, ... KN-1 as the 32-bit words of the original key
	# R as the number of round keys needed: 11 round keys for AES-128, 13 keys for AES-192, and 15 keys for AES-256
	# W0, W1, ... W4R-1 as the 32-bit words of the expanded key
	assert AES_version in VALID_VERSIONS
	num_bits = int(AES_version)
	N = (num_bits)//32 # Length of key in bits divided by 32
	R = 10+((VALID_VERSIONS.index(AES_version)*2)+1)
	encryption_key = pad_key(encryption_key, N)
	assert len(encryption_key) == N*4
	# Splice K
	K = splice_K(encryption_key)
	# Now here is the actual key expansion.
	W_list = []
	for i in range(4*R): # We include 4R.
		W_list.append(W(i, N, K, W_list))
	# Ok, so now the expanded key is in W_list
	#return W_list
	#print(W_list)
	#print("length of W_list: "+str(len(W_list)))
	# This cuts the matrix into 4x4 matrixes.
	W_list = [W_list[x:x+4] for x in range(0, len(W_list),4)]
	return R, W_list


# Thanks to https://stackoverflow.com/questions/952914/how-do-i-make-a-flat-list-out-of-a-list-of-lists
def flatten(items):
	"""Yield items from any nested iterable; see Reference."""
	for x in items:
		if isinstance(x, Iterable) and not isinstance(x, (str, bytes)):
			for sub_x in flatten(x):
				yield sub_x
		else:
			yield x

def print_hex(byte_list: bytes) -> None:
	flattened_list = list(flatten(byte_list))
	#print("="*30)
	out = ""
	#print(flattened_list)
	for x in flattened_list:
		#print("x == "+str(x))
		#print(hex(int.from_bytes(x, byteorder='big')))
		if isinstance(x, bytes):
			oof = hex(int.from_bytes(x))[2:]
			if len(oof) == 1:
				oof = "0"+oof
			
			out += oof
		else:
			#out += hex(x)[2:]
			oof = hex(x)[2:]
			if len(oof) == 1:
				oof = "0"+oof
			out += oof
	return out
	#print("="*30)

def test_key_expansion():
	string = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c"
	key = bytes([int(x, base=16) for x in string.split(" ")])
	_, expanded_key = key_expansion(bytes(key), "128")
	print_hex(expanded_key)

def create_state(plaintext: bytes) -> bytes:
	assert len(plaintext) <= 16
	padded_plain_text = pad_plain_text(plaintext, 16)
	assert len(padded_plain_text) == 16
	# Now split into a list and then create a numpy array and then transpose.
	cut_list = [padded_plain_text[x:x+4] for x in range(0, len(padded_plain_text),4)]
	state = [[0 for _ in range(4)] for _ in range(4)]
	# Now transpose the matrix
	for i in range(len(cut_list)):
		for j in range(len(cut_list[0])):
			state[j][i] = cut_list[i][j]
	return state

def SubBytes(input_matrix: list) -> list:
	#input_matrix = flatten(input_matrix)
	#input_matrix = list(input_matrix)
	#out = copy.deepcopy(input_matrix)
	for i in range(len(input_matrix)):
		for j in range(len(input_matrix[0])):
			#print("input_matrix[i][j] == "+str(input_matrix[i][j]))
			#print("rijndael.S_BOX_SPLIT == "+str(rijndael.S_BOX_SPLIT))
			index_integer = input_matrix[i][j]
			ind_x = index_integer & 0b1111
			ind_y = (index_integer & 0b11110000) >> 4
			#print("ind_x == "+str(ind_x))
			#print("ind_y == "+str(ind_y))
			#print("rijndael.S_BOX_SPLIT[8] == "+str(rijndael.S_BOX_SPLIT[8]))
			#print("rijndael.S_BOX_SPLIT == "+str(rijndael.S_BOX_SPLIT))
			input_matrix[i][j] = rijndael.S_BOX_MATRIX[ind_y][ind_x]
	return input_matrix

def shift_row_once(row: list) -> list:
	out = [row[i] for i in range(1,len(row))] + [row[0]]
	return out

def shift_row(row: list, n: int) -> list: # This shifts one singular line by n indexes.
	for i in range(n):
		row = shift_row_once(row)
	return row

def ShiftRows(input_mat: list) -> list:
	assert len(input_mat) == 4
	assert len(input_mat[0]) == 4
	input_mat[1] = shift_row(input_mat[1], 1)
	input_mat[2] = shift_row(input_mat[1], 2)
	input_mat[3] = shift_row(input_mat[1], 3)
	return input_mat

def mat_xor(mat1: list, mat2: list) -> list:
	out = copy.deepcopy(mat2)
	for i in range(len(mat1)):
		for j in range(len(mat2)):
			out[i][j] = out[i][j] ^ mat1[i][j]
	return out

def multiply_vec_mat(vec: list, mat: list) -> list:
	out = []
	for i in range(len(mat)):
		cur_line = mat[i]
		assert len(cur_line) == len(vec)
		out.append(sum(cur_line[i]*vec[i] for i in range(len(vec))))
	return out

def mix_one_column(in_list: list) -> list:
	'''
	This function multiplies the vector in_list with this matrix:
	[[2,3,1,1],
	[1,2,3,1],
	[1,1,2,3],
	[3,1,1,2]]
	'''
	mix_mat = [[2,3,1,1],
	[1,2,3,1],
	[1,1,2,3],
	[3,1,1,2]]

	out = multiply_vec_mat(in_list, mix_mat)
	return out


def transpose_mat(input_mat: list) -> list:
	out = copy.deepcopy(input_mat)
	for i in range(len(input_mat)):
		for j in range(len(input_mat[0])):
			out[j][i] = input_mat[i][j]
	return out

def MixColumns(input_matrix: list) -> list:
	# Get each column and then apply the matrix transformation.
	out = []
	for i in range(4):
		out.append(mix_one_column([input_matrix[j][i] for j in range(4)]))
	out = transpose_mat(out)
	return out

def AddRoundKey(input_mat: list, i: int, W: list) -> list:
	subkey = get_key_matrix(i, W)
	print("subkey == "+str(subkey))
	print("input_mat == "+str(input_mat))
	print("subkey == "+str(subkey))
	#input_mat = mat_xor(input_mat, subkey) # These need to be the other way around, because bytes type object can
	input_mat = mat_xor(subkey, input_mat)
	return input_mat

def get_key_matrix(i: int, W: list) -> list:
	# This get's the correct 4x4 matrix from the expanded key.
	cor_key_thing = W[i]
	return cor_key_thing
	#return rijndael.S_BOX_SPLIT[i]

def BoundsCheck(state: list) -> list:
	for i in range(len(state)):
		for j in range(len(state[0])):
			state[i][j] &= 0xff
	return state

def encrypt_state(expanded_key: list, plaintext: bytes, num_rounds: int, W_list: list) -> bytes:
	state = create_state(plaintext)
	# Initial round key addition:
	print("Here is the expanded key: "+str(expanded_key))
	print("Here is the length of the key: "+str(len(expanded_key)))
	print("round[0].input : "+str(print_hex(state)))
	state = AddRoundKey(state, 0, W_list)
	print("round[0].k_sch : "+str(print_hex(expanded_key)))
	# 9, 11 or 13 rounds:
	for i in range(1,num_rounds-1):
		print("round["+str(i)+"].start == "+str(print_hex(state)))
		state = SubBytes(state)
		print("round["+str(i)+"].s_box == "+str(print_hex(state)))
		state = ShiftRows(state)
		print("round["+str(i)+"].s_row == "+str(print_hex(state)))
		state = MixColumns(state)
		print("round["+str(i)+"].m_col == "+str(print_hex(state)))
		state = BoundsCheck(state) # This here to bounds check every element to the inclusive range 0-255 .
		state = AddRoundKey(state, i, W_list)
		print("round["+str(i)+"].k_sch == "+str(print_hex(state)))
	# Final round (making 10, 12 or 14 rounds in total):
	state = SubBytes(state)
	state = ShiftRows(state)
	state = AddRoundKey(state, num_rounds-1, W_list)
	state = BoundsCheck(state)
	return state

def run_tests() -> None:
	test_S()
	test_key_expansion()
	return

def main():
	run_tests() # Sanity tests.
	encryption_key = "oofoof"
	num_rounds, expanded_key = key_expansion(bytes(encryption_key, encoding="ascii"), "128")
	# 00112233445566778899aabbccddeeff
	# example_plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
	example_plaintext = bytes.fromhex("004488cc115599dd2266aaee3377bbff")
	key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
	print("Here is the key: "+str(key))
	#key = bytes.fromhex("004488cc115599dd2266aaee3377bbff")
	num_rounds, expanded_key = key_expansion(key, "128")
	encrypted = encrypt_state(expanded_key, example_plaintext, num_rounds, expanded_key)
	print(encrypted)
	print("Done!")
	return 0

if __name__=="__main__":

	exit(main())



```

and here is some of the output.

```
Here is the key: b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f'
Here is the expanded key: [[b'\x00\x01\x02\x03', b'\x04\x05\x06\x07', b'\x08\t\n\x0b', b'\x0c\r\x0e\x0f'], [b'\xd6\xaat\xfd', b'\xd2\xafr\xfa', b'\xda\xa6x\xf1', b'\xd6\xabv\xfe'], [b'\xb6\x92\xcf\x0b', b'd=\xbd\xf1', b'\xbe\x9b\xc5\x00', b'h0\xb3\xfe'], [b'\xb6\xfftN', b'\xd2\xc2\xc9\xbf', b'lY\x0c\xbf', b'\x04i\xbfA'], [b'G\xf7\xf7\xbc', b'\x955>\x03', b'\xf9l2\xbc', b'\xfd\x05\x8d\xfd'], [b'<\xaa\xa3\xe8', b'\xa9\x9f\x9d\xeb', b'P\xf3\xafW', b'\xad\xf6"\xaa'], [b'^9\x0f}', b'\xf7\xa6\x92\x96', b'\xa7U=\xc1', b'\n\xa3\x1fk'], [b'\x14\xf9p\x1a', b'\xe3_\xe2\x8c', b'D\n\xdfM', b'N\xa9\xc0&'], [b'GC\x875', b'\xa4\x1ce\xb9', b'\xe0\x16\xba\xf4', b'\xae\xbfz\xd2'], [b'T\x992\xd1', b'\xf0\x85Wh', b'\x10\x93\xed\x9c', b'\xbe,\x97N'], [b'\x13\x11\x1d\x7f', b'\xe3\x94J\x17', b'\xf3\x07\xa7\x8b', b'M+0\xc5']]
Here is the length of the key: 11
round[0].input : 00112233445566778899aabbccddeeff
subkey == [b'\x00\x01\x02\x03', b'\x04\x05\x06\x07', b'\x08\t\n\x0b', b'\x0c\r\x0e\x0f']
input_mat == [[0, 17, 34, 51], [68, 85, 102, 119], [136, 153, 170, 187], [204, 221, 238, 255]]
subkey == [b'\x00\x01\x02\x03', b'\x04\x05\x06\x07', b'\x08\t\n\x0b', b'\x0c\r\x0e\x0f']
round[0].k_sch : 1020340506078090a0bc0d0e0fd6aa74fdd2af72fadaa678f1d6ab76feb692cf0b643dbdf1be9bc5006830b3feb6ff744ed2c2c9bf6c590cbf469bf4147f7f7bc95353e03f96c32bcfd058dfd3caaa3e8a99f9deb50f3af57adf622aa5e390f7df7a69296a7553dc1aa31f6b14f9701ae35fe28c440adf4d4ea9c02647438735a41c65b9e016baf4aebf7ad2549932d1f08557681093ed9cbe2c974e13111d7fe3944a17f307a78b4d2b30c5
round[1].start == 00102030405060708090a0b0c0d0e0f0
round[1].s_box == 63cab7040953d051cd60e0e7ba70e18c
round[1].s_row == 63cab70453d05109510953d00953d051
round[1].m_col == 2194603841442052d83222d71732a541e2a01df3dd469187
```

This line here: `round[1].s_box == 63cab7040953d051cd60e0e7ba70e18c` is correct, but the line after it: `round[1].s_row == 63cab70453d05109510953d00953d051` is not, the correct result would be this: `6353e08c0960e104cd70b751bacad0e7` .

Here we have the incorrect output: `63cab70453d05109510953d00953d051`
Here we have the correct output:   `6353e08c0960e104cd70b751bacad0e7`

Let's get to debugging...

Ok, so I improved some of the debugging functions, and came to the conclusion that the bug is in ShiftRows .

```


def ShiftRows(input_mat: list) -> list:
	assert len(input_mat) == 4
	assert len(input_mat[0]) == 4
	print("input_mat[1] == "+str(input_mat[1]))
	input_mat[1] = shift_row(input_mat[1], 1)
	print("after: "+str(input_mat[1]))
	input_mat[2] = shift_row(input_mat[1], 2)
	input_mat[3] = shift_row(input_mat[1], 3)
	return input_mat

```

See the bug?

I forgot to put the correct indexes to the `input_mat[]` lines.

Here is the fixed version:

```
def ShiftRows(input_mat: list) -> list:
	assert len(input_mat) == 4
	assert len(input_mat[0]) == 4
	print("input_mat[1] == "+str(input_mat[1]))
	input_mat[1] = shift_row(input_mat[1], 1)
	print("after: "+str(input_mat[1]))
	input_mat[2] = shift_row(input_mat[2], 2)
	input_mat[3] = shift_row(input_mat[3], 3)
	return input_mat
```

## Fixing m_col

Ok, now that we have fixed the row shifting, now we just need to fix the column mixing.

```
round[1].s_row == 6353e08c0960e104cd70b751bacad0e7
input_matrix to MixColumns == [[99, 9, 205, 186], [83, 96, 112, 202], [224, 225, 183, 208], [140, 4, 81, 231]]
length of flattened_list : 16
Here is the flattened list: [811, 1077, 1050, 884, 535, 880, 567, 356, 1010, 1059, 926, 1072, 1417, 1445, 1497, 1430]
flattened_list[0] == 811
```

Let's mix these columns:

```
[[99, 9, 205, 186],
 [83, 96, 112, 202],
 [224, 225, 183, 208],
 [140, 4, 81, 231]]
```

after adding a couple of more debug statements:

```
round[1].s_row == 6353e08c0960e104cd70b751bacad0e7
input_matrix to MixColumns == [[99, 9, 205, 186], [83, 96, 112, 202], [224, 225, 183, 208], [140, 4, 81, 231]]
Here is the cur_column: [99, 83, 224, 140]
Here is the cur_column: [9, 96, 225, 4]
Here is the cur_column: [205, 112, 183, 81]
Here is the cur_column: [186, 202, 208, 231]
Outputting this from MixColumns: [[811, 535, 1010, 1417], [1077, 880, 1059, 1445], [1050, 567, 926, 1497], [884, 356, 1072, 1430]]
length of flattened_list : 16
Here is the flattened list: [811, 1077, 1050, 884, 535, 880, 567, 356, 1010, 1059, 926, 1072, 1417, 1445, 1497, 1430]
flattened_list[0] == 811
```

After actually reading the wikipedia article: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_MixColumns_step .

"Addition is simply XOR." oookkk. I think that the modular arithmetic is explained in a convoluted way in the example stuff.

I then found this: https://medium.com/quick-code/understanding-the-advanced-encryption-standard-7d7884277e7

```
In Mix Columns we will perform a matrix multiplication between our current matrix and a predefined given matrix, constant through out the rounds. But it’s a slight trickier matrix multiplication, as the sum operation is substituted by xor and multiplication for and.

```

This is a much more concise explanation in my opinion, but it is too concise and doesn't give that much detail.

Ok, so it is time to read this: https://en.wikipedia.org/wiki/Rijndael_MixColumns . After reading around 20 minutes, I still don't understand how the code works, but anyway. Let's just rewrite the function in python code instead.

```
def mix_col(r: list) -> list:
	a = [0,0,0,0]
	b = [0,0,0,0]
	print("r original: "+str(r))
	assert all([r[i] <=255 for i in range(len(r))])
	for c in range(4):
		a[c] = r[c]
		h = r[c] >> 7
		b[c] = r[c] << 1
		print("b[c] == "+str(b[c]))
		print("h * 0x1B + 0x100 == "+str(hex(h * 0x1B + 0x100)))
		b[c] ^= h * 0x1B
		b[c] &= 0xff # This must be here, because in c code if we try to shift 0x80 << 1 , then it will go to zero, but not in python, so we need to clamp manually.
		print("b[c] final == "+str(b[c]))
	assert all([a[c] == r[c] for c in range(len(r))])
	r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]#; /* 2 * a0 + a3 + a2 + 3 * a1 */
	r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]#; /* 2 * a1 + a0 + a3 + 3 * a2 */
	r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]#; /* 2 * a2 + a1 + a0 + 3 * a3 */
	r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]#; /* 2 * a3 + a2 + a1 + 3 * a0 */
	print("r == "+str(r))
	assert all([r[i] <=255 for i in range(len(r))])
	return r
```

After using this function instead, the code now works.

Here is the final code which works:

```

import numpy as np
import rijndael
import copy
from typing import Iterable 
'''
The key size used for an AES cipher specifies the number of transformation rounds that convert the input, called the plaintext, into the final output, called the ciphertext. The number of rounds are as follows:

10 rounds for 128-bit keys.
12 rounds for 192-bit keys.
14 rounds for 256-bit keys.
'''

def fail(msg: str):
	print("[-] "+str(msg))
	exit(1)


def encrypt(state, expanded_key, num_rounds):
	# State is a 4x4 matrix which each element is one byte
	# expanded key is the expanded key
	# num rounds is the number of rounds.
	cur_key = 0

'''
i	1	2	3	4	5	6	7	8	9	10
rci	01	02	04	08	10	20	40	80	1B	36

0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
'''
RCON_VALUES = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36] # index is i and value is... ya know... the value of rcon_i .
# See https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
def rcon(i: int) -> bytes:
	return bytes([RCON_VALUES[i - 1], 0, 0, 0])

# Also define RotWord as a one-byte left circular shift:[note 6]
def RotWord(word: bytes) -> bytes:
	# The word should actually be a word
	assert len(word) == 4
	return bytes([word[1], word[2], word[3], word[0]])

def S(x: int) -> int:
	# https://en.wikipedia.org/wiki/Rijndael_S-box
	return rijndael.S_BOX[x]

def test_S() -> None:
	assert rijndael.S_BOX[0x9a] == 0xb8

def SubWord(word: bytes) -> bytes:
	assert len(word) == 4
	return bytes([S(x) for x in word])

VALID_VERSIONS = ["128", "192", "256"]

def xor_bytes(a: bytes, b: bytes) -> bytes:
	assert len(a) == len(b)
	return bytes([a[i] ^ b[i] for i in range(len(a))])

# This is the main key expansion function which does the heavy lifting.
def W(i: int, N: int, K: bytes, W: list) -> bytes: # The W list is being filled as we go.
	if i < N:
		return K[i]
	elif i >= N and (i % N == 0 % N):
		return xor_bytes(xor_bytes((W[i-N]), SubWord(RotWord(W[i-1]))), rcon(i//N))
	elif i >= N and N > 6 and (i % N == 4 % N):
		return xor_bytes(W[i-N], SubWord(W[i-1]))
	else:
		#print("paskaaa")
		return xor_bytes(W[i-N], W[i-1])

def pad_key(orig_key: bytes, N: int) -> list: # This basically returns K
	if len(orig_key) > N*4: # If the amount of words is greater than N , then the key is too long.
		print("Key length too long! Choose a shorter encryption key or choose bigger AES version!")
		exit()
	return orig_key + bytes([0 for _ in range(N*4 - len(orig_key))])

def pad_plain_text(orig_plaintext: bytes, length: int) -> list:
	return orig_plaintext + bytes([0 for _ in range(length - len(orig_plaintext))])

def splice_K(encryption_key: bytes) -> list:
	assert len(encryption_key) % 4 == 0
	return [encryption_key[x:x+4] for x in range(0, len(encryption_key),4)]


def make_integer_list(W_list: list) -> list:
	out = []
	for mat in W_list:
		# First convert the bytes lists to integers.
		int_mat = [[x for x in b] for b in mat]
		print(int_mat)
		# Now transpose, because the numbers are the wrong way around.
		int_mat = transpose_mat(int_mat)
		out.append(int_mat)
	return out

def key_expansion(encryption_key: bytes, AES_version: str):
	# Thanks wikipedia https://en.wikipedia.org/wiki/AES_key_schedule  !!!
	#if len(encryption_key) != 16:
	#	fail("Encryption key must be 128 bits in length! Other lengths are not supported!")
	
	# N as the length of the key in 32-bit words: 4 words for AES-128, 6 words for AES-192, and 8 words for AES-256
	# K0, K1, ... KN-1 as the 32-bit words of the original key
	# R as the number of round keys needed: 11 round keys for AES-128, 13 keys for AES-192, and 15 keys for AES-256
	# W0, W1, ... W4R-1 as the 32-bit words of the expanded key
	assert AES_version in VALID_VERSIONS
	num_bits = int(AES_version)
	N = (num_bits)//32 # Length of key in bits divided by 32
	R = 10+((VALID_VERSIONS.index(AES_version)*2)+1)
	encryption_key = pad_key(encryption_key, N)
	assert len(encryption_key) == N*4
	# Splice K
	K = splice_K(encryption_key)
	# Now here is the actual key expansion.
	W_list = []
	for i in range(4*R): # We include 4R.
		W_list.append(W(i, N, K, W_list))
	# Ok, so now the expanded key is in W_list
	#return W_list
	#print(W_list)
	#print("length of W_list: "+str(len(W_list)))
	# This cuts the matrix into 4x4 matrixes.
	W_list = [W_list[x:x+4] for x in range(0, len(W_list),4)]
	W_actual = make_integer_list(W_list)
	return R, W_actual


# Thanks to https://stackoverflow.com/questions/952914/how-do-i-make-a-flat-list-out-of-a-list-of-lists
def flatten(items):
	"""Yield items from any nested iterable; see Reference."""
	for x in items:
		if isinstance(x, Iterable) and not isinstance(x, (str, bytes)):
			for sub_x in flatten(x):
				yield sub_x
		else:
			yield x

def print_hex(byte_list: bytes) -> None:
	# print("byte_list == "+str(byte_list))
	# Check if the matrix is a 4x4 state.
	if len(byte_list) == 4 and len(byte_list[0]) == 4 and isinstance(byte_list[0][0], int):
		# Now transpose, because the state is a 4x4 matrix.
		'''
		[[b0,b4,b8,b12],
		[b1,b5,b9,b13],
		[b2,b6,b10,b14],
		[b3,b7,b11,b15]]
		'''

		byte_list = transpose_mat(byte_list)

	flattened_list = list(flatten(byte_list))
	print("length of flattened_list : "+str(len(flattened_list)))
	print("Here is the flattened list: "+str(flattened_list))
	print("flattened_list[0] == "+str(flattened_list[0]))
	#assert len(flattened_list) == 4*4
	#print("="*30)
	out = ""
	#print(flattened_list)
	for x in flattened_list:
		#print("x == "+str(x))
		#print(hex(int.from_bytes(x, byteorder='big')))
		if isinstance(x, bytes):
			for b in x:
				print("b == "+str(b))
				oof = hex(b)[2:]
				if len(oof) == 1:
					oof = "0"+oof
				print("oof == "+str(oof))
				out += oof
		else:
			#out += hex(x)[2:]
			oof = hex(x)[2:]
			if len(oof) == 1:
				oof = "0"+oof
			out += oof
	return out
	#print("="*30)

def test_key_expansion():
	string = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c"
	key = bytes([int(x, base=16) for x in string.split(" ")])
	_, expanded_key = key_expansion(bytes(key), "128")
	print_hex(expanded_key)

def create_state(plaintext: bytes) -> bytes:
	assert len(plaintext) <= 16
	padded_plain_text = pad_plain_text(plaintext, 16)
	assert len(padded_plain_text) == 16
	# Now split into a list and then create a numpy array and then transpose.
	cut_list = [padded_plain_text[x:x+4] for x in range(0, len(padded_plain_text),4)]
	state = [[0 for _ in range(4)] for _ in range(4)]
	# Now transpose the matrix
	for i in range(len(cut_list)):
		for j in range(len(cut_list[0])):
			state[j][i] = cut_list[i][j]
	return state

def SubBytes(input_matrix: list) -> list:
	#input_matrix = flatten(input_matrix)
	#input_matrix = list(input_matrix)
	#out = copy.deepcopy(input_matrix)
	for i in range(len(input_matrix)):
		for j in range(len(input_matrix[0])):
			#print("input_matrix[i][j] == "+str(input_matrix[i][j]))
			#print("rijndael.S_BOX_SPLIT == "+str(rijndael.S_BOX_SPLIT))
			index_integer = input_matrix[i][j]
			ind_x = index_integer & 0b1111
			ind_y = (index_integer & 0b11110000) >> 4
			#print("ind_x == "+str(ind_x))
			#print("ind_y == "+str(ind_y))
			#print("rijndael.S_BOX_SPLIT[8] == "+str(rijndael.S_BOX_SPLIT[8]))
			#print("rijndael.S_BOX_SPLIT == "+str(rijndael.S_BOX_SPLIT))
			input_matrix[i][j] = rijndael.S_BOX_MATRIX[ind_y][ind_x]
	return input_matrix

def shift_row_once(row: list) -> list:
	out = [row[i] for i in range(1,len(row))] + [row[0]]
	return out

def shift_row(row: list, n: int) -> list: # This shifts one singular line by n indexes.
	for i in range(n):
		row = shift_row_once(row)
	return row

def ShiftRows(input_mat: list) -> list:
	assert len(input_mat) == 4
	assert len(input_mat[0]) == 4
	print("input_mat[1] == "+str(input_mat[1]))
	input_mat[1] = shift_row(input_mat[1], 1)
	print("after: "+str(input_mat[1]))
	input_mat[2] = shift_row(input_mat[2], 2)
	input_mat[3] = shift_row(input_mat[3], 3)
	return input_mat

def mat_xor(mat1: list, mat2: list) -> list:
	out = copy.deepcopy(mat2)
	for i in range(len(mat1)):
		for j in range(len(mat2)):
			out[i][j] = out[i][j] ^ mat1[i][j]
	return out

'''
def multiply_vec_mat_polynomial(vec: list, mat: list) -> list: # This is matrix multiplication, but with polynomial.
	out = []
	for i in range(len(mat)):
		cur_line = mat[i]
		assert len(cur_line) == len(vec)
		#out.append(sum(cur_line[i]*vec[i] for i in range(len(vec))))
		# But it’s a slight trickier matrix multiplication, as the sum operation is substituted by xor and multiplication for and.
		oof = [cur_line[i]&vec[i] for i in range(len(vec))] # https://medium.com/quick-code/understanding-the-advanced-encryption-standard-7d7884277e7
		res = 0
		for elem in oof:
			res ^= elem
		out.append(res)
	return out
'''

def mix_col(r: list) -> list:
	a = [0,0,0,0]
	b = [0,0,0,0]
	print("r original: "+str(r))
	assert all([r[i] <=255 for i in range(len(r))])
	for c in range(4):
		a[c] = r[c]
		h = r[c] >> 7
		b[c] = r[c] << 1
		print("b[c] == "+str(b[c]))
		print("h * 0x1B + 0x100 == "+str(hex(h * 0x1B + 0x100)))
		b[c] ^= h * 0x1B
		b[c] &= 0xff # This must be here, because in c code if we try to shift 0x80 << 1 , then it will go to zero, but not in python, so we need to clamp manually.
		print("b[c] final == "+str(b[c]))
	assert all([a[c] == r[c] for c in range(len(r))])
	r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]#; /* 2 * a0 + a3 + a2 + 3 * a1 */
	r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]#; /* 2 * a1 + a0 + a3 + 3 * a2 */
	r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]#; /* 2 * a2 + a1 + a0 + 3 * a3 */
	r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]#; /* 2 * a3 + a2 + a1 + 3 * a0 */
	print("r == "+str(r))
	assert all([r[i] <=255 for i in range(len(r))])
	return r

def byte_check(int_list: list) -> list:
	return [x & 0xff for x in int_list]

def mix_one_column(in_list: list) -> list:
	'''
	This function multiplies the vector in_list with this matrix:
	[[2,3,1,1],
	[1,2,3,1],
	[1,1,2,3],
	[3,1,1,2]]
	'''

	out = mix_col(in_list)
	return out


def transpose_mat(input_mat: list) -> list:
	# The matrixes which are inputted to this function should be 4x4 matrixes.
	assert len(input_mat) == 4
	assert len(input_mat[0]) == 4
	out = copy.deepcopy(input_mat)
	for i in range(len(input_mat)):
		for j in range(len(input_mat[0])):
			out[j][i] = input_mat[i][j]
	return out

def MixColumns(input_matrix: list) -> list:
	# Get each column and then apply the matrix transformation.
	out = []
	print("input_matrix to MixColumns == "+str(input_matrix))
	for i in range(4):
		cur_column = [input_matrix[j][i] for j in range(4)]
		print("Here is the cur_column: "+str(cur_column))
		out.append(mix_one_column(cur_column))
	out = transpose_mat(out)
	print("Outputting this from MixColumns: "+str(out))
	return out

def AddRoundKey(input_mat: list, i: int, W: list) -> list:
	subkey = get_key_matrix(i, W)
	print("subkey == "+str(subkey))
	print("input_mat == "+str(input_mat))
	print("subkey == "+str(subkey))
	#input_mat = mat_xor(input_mat, subkey) # These need to be the other way around, because bytes type object can
	input_mat = mat_xor(subkey, input_mat)
	return input_mat

def get_key_matrix(i: int, W: list) -> list:
	# This get's the correct 4x4 matrix from the expanded key.
	cor_key_thing = W[i]
	return cor_key_thing
	#return rijndael.S_BOX_SPLIT[i]

def BoundsCheck(state: list) -> list:
	for i in range(len(state)):
		for j in range(len(state[0])):
			state[i][j] &= 0xff
	return state

def encrypt_state(expanded_key: list, plaintext: bytes, num_rounds: int, W_list: list) -> bytes:
	state = create_state(plaintext)
	# Initial round key addition:
	print("Here is the expanded key: "+str(expanded_key))
	print("Here is the length of the key: "+str(len(expanded_key)))
	print("round[0].input : "+str(print_hex(state)))
	state = AddRoundKey(state, 0, W_list)
	print("round[0].k_sch : "+str(print_hex(expanded_key)))
	# 9, 11 or 13 rounds:
	for i in range(1,num_rounds-1):
		print("round["+str(i)+"].start == "+str(print_hex(state)))
		state = SubBytes(state)
		print("round["+str(i)+"].s_box == "+str(print_hex(state)))
		state = ShiftRows(state)
		print("round["+str(i)+"].s_row == "+str(print_hex(state)))
		state = MixColumns(state)
		print("round["+str(i)+"].m_col == "+str(print_hex(state)))
		state = BoundsCheck(state) # This here to bounds check every element to the inclusive range 0-255 .
		state = AddRoundKey(state, i, W_list)
		print("round["+str(i)+"].k_sch == "+str(print_hex(state)))
	# Final round (making 10, 12 or 14 rounds in total):
	state = SubBytes(state)
	print("round["+str(num_rounds-1)+"].s_box == "+str(print_hex(state)))
	state = ShiftRows(state)
	print("round["+str(num_rounds-1)+"].s_row == "+str(print_hex(state)))
	state = AddRoundKey(state, num_rounds-1, W_list)
	print("round["+str(num_rounds-1)+"].k_sch == "+str(print_hex(state)))
	state = BoundsCheck(state)
	print("Final state after encryption: "+str(print_hex(state)))
	return state

def test_print_hex() -> None:
	test_mat = [[0,4,8,12],
				[1,5,9,13],
				[2,6,10,14],
				[3,7,11,15]]
	# Now test the printing
	print("Here is the test output.")
	out = print_hex(test_mat)
	print(out)
	# 000102030405060708090a0b0c0d0e0f
	assert out == "000102030405060708090a0b0c0d0e0f" # Should be this

def test_transpose_mat() -> None:
	test_mat = [[0,4,8,12],
				[1,5,9,13],
				[2,6,10,14],
				[3,7,11,15]]
	out = transpose_mat(test_mat)
	assert out == [[0,1,2,3],
				[4,5,6,7],
				[8,9,10,11],
				[12,13,14,15]]

def run_tests() -> None:
	test_transpose_mat()
	test_S()
	test_key_expansion()
	test_print_hex()
	return

def main():
	run_tests() # Sanity tests.
	encryption_key = "oofoof"
	num_rounds, expanded_key = key_expansion(bytes(encryption_key, encoding="ascii"), "128")
	# 00112233445566778899aabbccddeeff
	# example_plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
	#example_plaintext = bytes.fromhex("004488cc115599dd2266aaee3377bbff")
	example_plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
	key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
	print("Here is the key: "+str(key))
	#key = bytes.fromhex("004488cc115599dd2266aaee3377bbff")
	num_rounds, expanded_key = key_expansion(key, "128")
	encrypted = encrypt_state(expanded_key, example_plaintext, num_rounds, expanded_key)
	print(encrypted)
	print("Done!")
	return 0

if __name__=="__main__":

	exit(main())



```

## Implementing decryption

Ok, so to decrypt, we just need to program the reverse functions for each of the functions used in encryption.

I am also programming some test functions for the functions used in encryption and decryption, so I think that separating those to a separate python file would be good, but I am going to do that later (aka. never). These sanity tests are mainly to check that if we input x to some function and then pass the result to the reverse function, then of course we should end up with the original input.

Here is an example to test the SubBytes and RevSubBytes:

```
def test_s_box() -> None:
	# Go through every index and check the reverse.
	for ind in range(256):
		orig_val = access_table(rijndael.S_BOX_MATRIX, ind)
		should_be_ind = access_table(rijndael.S_BOX_MATRIX_REV, ind)
		assert should_be_ind == ind
	print("test_s_box passed!")
	return
```

I also put the way to access a table into a separate function for convenience:

```
def access_table(table: list, index: int) -> int: # This is used to access the S box and the reverse S box.
	assert index <= 255 and index >= 0 # Sanity check.
	ind_x = index & 0b1111
	ind_y = (index & 0b11110000) >> 4
	return table[ind_y][ind_x]
```

Here is my current code:

```
def SubBytes(input_matrix: list) -> list:
	for i in range(len(input_matrix)):
		for j in range(len(input_matrix[0])):
			input_matrix[i][j] = access_table(rijndael.S_BOX_MATRIX, input_matrix[i][j])
	return input_matrix

def InvSubBytes(input_matrix: list) -> list:
	# Reverse of SubBytes. Otherwise similar, but use the reverse matrix instead.
	for i in range(len(input_matrix)):
		for j in range(len(input_matrix[0])):
			input_matrix[i][j] = access_table(rijndael.S_BOX_MATRIX_REV, input_matrix[i][j])
	return input_matrix
```

we can just refactor that to this:

```
def SubBytes(input_matrix: list, table=rijndael.S_BOX_MATRIX) -> list:
	for i in range(len(input_matrix)):
		for j in range(len(input_matrix[0])):
			input_matrix[i][j] = access_table(table, input_matrix[i][j])
	return input_matrix

def InvSubBytes(input_matrix: list) -> list:
	# Reverse of SubBytes. Otherwise similar, but use the reverse matrix instead.
	return SubBytes(input_matrix, table=rijndael.S_BOX_MATRIX_REV)
```

Next up is InvMixColumns . This is quite hard, because I didn't initially even understand precisely how this works, so I think I am going to just reason my way out of this.

Ok, so looking at the inverse matrix in the pdf file, we need a lot more intermediary lists than in the forward pass MixColumns. This is because we need to multiply by 0xe, 0x9, 0xd and 0xb .

I wondered why there was the 0x1B and where it came from. After reading the pdf file a bit more closely, I realized there is this part: "In the polynomial representation, multiplication in GF(28) (denoted by •) corresponds with the multiplication of polynomials modulo an irreducible polynomial of degree 8. A polynomial is irreducible if its only divisors are one and itself. For the AES algorithm, this irreducible polynomial is x\*\*8 + x\*\*4 + x\*\*3 + x\*\*2 + x + 1 "

ok, so that is where the (1)1b comes from in the code.

The reverse function multiplies by 0xb and stuff. Now, in the forward case we could weasel out of implementing polynomial multiplication in G(2), because the maximum result was pretty much always less than 256*2, so you can just subtract the modulo polynomial , but now when we are multiplying by 0xd and stuff, we need to implement polynomial multiplication properly.

Here:

```

```








