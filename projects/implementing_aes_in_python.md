
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
def poly_mul(a: int, b: int) -> int: # This function multiplies the polynomial a with b in G(2) and then modulo x**8 + x**4 + x**3 + x**2 + x + 1.
	out = 0
	k = b
	while k: # This basically shifts left and then if the current bit is a one, then xor the current thing with the thing.
		cur_bit = k & 1 # current bit.
		if cur_bit:
			out ^= (a) # xor if bit is one.
		# shift
		a <<= 1
		k >>= 1
	# Now modulo in polynomial in GF(2) # See https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
	out = poly_mod(out, 0x11B)
	return out
```

and therefore we must also implement a poly remainder function in GF(2). Here it is:

```
def poly_mod(dividend: int, divisor: int) -> int:
	# First align the integers for the long division.
	if dividend < divisor:
		return dividend
	# This is used to align
	num_bits_dividend = math.ceil(math.log(dividend,2))
	num_bits_divisor = math.ceil(math.log(divisor,2))
	# We need to shift the divisor such that the most significant bits are aligned.
	diff = num_bits_dividend - num_bits_divisor
	divisor <<= diff # Align.
	# Main loop.
	while diff:
		if (1 << diff) & dividend:
			# We are aligned, therefore divide (XOR)
			dividend ^= divisor
		divisor >>= 1 # Shift one to the right
		diff -= 1
	return dividend
```

but it does not work.

Let's get to debugging!

Yeah, my bit shifts were wrong and after a bit of debugging this seems to work somewhat:

```
def poly_mod(dividend: int, divisor: int) -> int:
	# First align the integers for the long division.
	if dividend < divisor:
		return dividend
	# This is used to align
	num_bits_dividend = bits(dividend)
	num_bits_divisor = bits(divisor)
	# We need to shift the divisor such that the most significant bits are aligned.
	diff = num_bits_dividend - num_bits_divisor
	divisor <<= diff # Align.
	print("Here is the divisor in binary: "+str(bin(divisor)[2:]))
	print("Here is the dividend in binary: "+str(bin(dividend)[2:]))
	print("1 << diff == "+str(bin(dividend)[2:]))
	# Main loop.
	while diff:
		#print("(1 << diff) & dividend == "+str(bin((1 << diff) & dividend)[2:]))
		#print("========")
		#print("dividend == "+str(bin(dividend)[2:]))
		#print("(1 << (diff+num_bits_dividend-1)) == "+str(bin((1 << (diff+num_bits_dividend-1)))[2:]))
		print("========")
		#print("((divisor << diff) & dividend) == "+str(bin(((divisor << diff) & dividend))))
		#print("(1 << (bits(divisor << diff) - 1) == "+str(bin((1 << (bits(divisor << diff) - 1)))))
		#print("(divisor << diff) == "+str(bin((divisor << diff))))
		#if ((divisor << diff) & dividend) & (1 << (bits(divisor << diff))):
		print("1 << (bits(divisor)) == "+str(bin(1 << (bits(divisor)))))
		print("((divisor) & dividend) == "+str(bin(((divisor) & dividend))))
		print("bin(divisor) == "+str(bin(divisor)))
		print("bin(dividend) == "+str(bin(dividend)))
		if ((divisor) & dividend) & (1 << (bits(divisor)-1)):
			# We are aligned, therefore divide (XOR)
			dividend ^= divisor
			print("after xor: "+str(bin(dividend)[2:]))
		divisor >>= 1 # Shift one to the right
		diff -= 1
	return dividend
```

though I am going to add a more complicated test before I am convinced that it works.

I am going to program a tiny utility function, which takes the polynomial coefficients (in GF2) and then outputs a binary number which represents that polynomial. I am going to put that into a separate file called util.

```
def coef_to_pol(where_coef_is_one: list) -> int: # Converts the coefficients to a polynomial. The list actually doesn't represent the coefficients, but the indexes where the coefficient is one. For example passing [2] to this would represent x**2 or 0b100 , not 2 . This is because this is in GF(2).
    out = 0
    for ind in where_coef_is_one:
        out |= 1 << ind
    return out
```

This is such that we can convert the polynomials listed in the pdf file to integers fast instead of manually typing the zeroes and ones.

I implemented this to create a good test case for the polynomial modulo:

```
>>> coef_to_pol([13,11,9,8,6,5,4,3,0])
11129
```

here is my current test function:

```
def test_poly_mod() -> None:
	# Tests the polynomial modulo (remainder) in GF(2)
	pol1 = 0b100 # x**2
	pol2 = 0b10000 # x**4
	res = poly_mod(pol2, pol1)
	print("result of the polynomial modulo test: "+str(res))
	assert res == 0 # Polynomial remainder should be zero.
	#input()
	# A bit of a more complex testcase. This is taken from the pdf file multiplication section.
	pol1 = 11129
	pol2 = 283
	res = poly_mod(pol1, pol2)
	print("res == "+str(bin(res)))
	assert res == 193
	#input()
	return
```

and it passes!!! Great! Now we finally have everything we need to program the poly_mul function which first multiplies and then gets the modulo by the specific 0x11b polynomial.

Here it is:

```
def poly_mul(a: int, b: int) -> int: # This function multiplies the polynomial a with b in G(2) and then modulo x**8 + x**4 + x**3 + x**2 + x + 1.
	out = 0
	k = b
	while k: # This basically shifts left and then if the current bit is a one, then xor the current thing with the thing.
		cur_bit = k & 1 # current bit.
		if cur_bit:
			out ^= (a) # xor if bit is one.
		# shift
		a <<= 1
		k >>= 1
	# Now modulo in polynomial in GF(2) # See https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
	out = poly_mod(out, 0x11B)
	return out
```

Let's write a test function for this too with the example straight from the pdf file:

```
def test_poly_mul() -> None:
	a = 0b100
	b = 0b100
	res = poly_mul(a,b)
	assert res == 0b10000 # x**2 * x**2 == x**4
	
	# This example is ripped straight from the polynomial multiplication section of this pdf document: https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
	a = 87
	b = 131
	res = poly_mul(a,b)
	assert res == 193
	print("test_poly_mul passed")
	return
```

Now we can finally implement the inv_mix_col function which is the inverse of the mix_col function.

```
def rev_mix_column(r: list) -> list: # This is used in InvMixColumns.
	a = [0,0,0,0]
	b = [0,0,0,0]
	c = [0,0,0,0]
	d = [0,0,0,0]
	e = [0,0,0,0]
	'''
	/* The array 'a' is simply a copy of the input array 'r'
     * The array 'b' is each element of the array 'a' multiplied by 0xe
	 * The array 'c' is each element of the array 'a' multiplied by 0x9
	 * The array 'd' is each element of the array 'a' multiplied by 0xd
	 * The array 'e' is each element of the array 'a' multiplied by 0xb
     * in Rijndael's Galois field
     * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */ 
	'''
	for k in range(4): # Can't use 'c' here, because it is already a name of a list.
		a[k] = r[k]
		#b[k] = r[k] * 0xe # multiplied by 0xe
		#c[k] = r[k] * 0x9 # multiplied by 0x9
		#d[k] = r[k] * 0xd # multiplied by 0xd
		#e[k] = r[k] * 0xb # multiplied by 0xb
		b[k] = poly_mul(r[k], 0xe)
		c[k] = poly_mul(r[k], 0x9)
		d[k] = poly_mul(r[k], 0xd)
		e[k] = poly_mul(r[k], 0xb)
	# Now we do something similar to what we did in mix_col
	r[0] = b[0] ^ e[1] ^ d[2] ^ c[3]
	r[1] = c[0] ^ b[1] ^ e[2] ^ d[3]
	r[2] = d[0] ^ c[1] ^ b[2] ^ e[3]
	r[3] = e[0] ^ d[1] ^ c[2] ^ b[3]

	return r
```

This seems to be correct. Let's create a test function with the test data supplied by wikipedia.

Here is the test function:

```
def test_mix_col() -> None:
	# This is ripped straight from wikipedia.  https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
	orig = [0xdb,0x13,0x53,0x45]
	orig_copy = copy.deepcopy(orig)
	expected_result = [0x8e,0x4d,0xa1,0xbc]
	# Now actually compute using our function.
	our_function_result = mix_col(orig)
	assert our_function_result == expected_result
	print("test_mix_col passed!")
	return
```

and it seems to work! Great! Actually, you know what, let's just go through every one of the testcases, because reasons.

The test cases are given on the wikipedia page are in a table so we need to do some string manipulation to get the testcases out.

```
db 13 53 45	8e 4d a1 bc	219 19 83 69	142 77 161 188
f2 0a 22 5c	9f dc 58 9d	242 10 34 92	159 220 88 157
01 01 01 01	01 01 01 01	1 1 1 1	1 1 1 1
c6 c6 c6 c6	c6 c6 c6 c6	198 198 198 198	198 198 198 198
d4 d4 d4 d5	d5 d5 d7 d6	212 212 212 213	213 213 215 214
2d 26 31 4c	4d 7e bd f8	45 38 49 76	77 126 189 248
```

Fuck! After programming a testcase parser and trying to run the tests, we fail. Here:

```
def test_mix_col() -> None:
	# This is ripped straight from wikipedia.  https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
	tests = testdatahelper.MIX_COL_TESTS
	for x,y in tests: # x is input and y is expected output. We also test the reverse function.
		print("Now running another test.")
		print("Here is the expected: "+str(hex_list_to_str(y)))
		print("Here is the input: "+str(hex_list_to_str(x)))
		x_copy = copy.deepcopy(x)
		x = mix_col(x)
		assert x == y # Should be the expected output
		# Test the reverse function now. We should end up with the original input.
		x = rev_mix_column(x)
		print("Here is the output from the reverse function: "+str(hex_list_to_str(x)))
		assert x == x_copy
	print("test_mix_col passed!!!")
	return
```

and here is the important part of the output:

```
Here is the expected: 0x8e 0x4d 0xa1 0xbc
Here is the input: 0xdb 0x13 0x53 0x45
r original: [219, 19, 83, 69]
b[c] == 438
h * 0x1B + 0x100 == 0x11b
b[c] final == 173
b[c] == 38
h * 0x1B + 0x100 == 0x100
b[c] final == 38
b[c] == 166
h * 0x1B + 0x100 == 0x100
b[c] final == 166
b[c] == 138
h * 0x1B + 0x100 == 0x100
b[c] final == 138
r == [142, 77, 161, 188]
Here is the output from the reverse function: 0x1c0 0x13 0x53 0x15e
```

Ok, so it calculates 0x1c0 incorrectly. That sucks. Let's see what it does wrong.

We know that the test_poly_mul passes, so the poly_mul function works correctly. So therefore the error is somewhere in this code:

```
def rev_mix_column(r: list) -> list: # This is used in InvMixColumns.
	a = [0,0,0,0]
	b = [0,0,0,0]
	c = [0,0,0,0]
	d = [0,0,0,0]
	e = [0,0,0,0]
	'''
	/* The array 'a' is simply a copy of the input array 'r'
     * The array 'b' is each element of the array 'a' multiplied by 0xe
	 * The array 'c' is each element of the array 'a' multiplied by 0x9
	 * The array 'd' is each element of the array 'a' multiplied by 0xd
	 * The array 'e' is each element of the array 'a' multiplied by 0xb
     * in Rijndael's Galois field
     * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */ 
	'''
	for k in range(4): # Can't use 'c' here, because it is already a name of a list.
		a[k] = r[k]
		#b[k] = r[k] * 0xe # multiplied by 0xe
		#c[k] = r[k] * 0x9 # multiplied by 0x9
		#d[k] = r[k] * 0xd # multiplied by 0xd
		#e[k] = r[k] * 0xb # multiplied by 0xb
		b[k] = poly_mul(r[k], 0xe)
		c[k] = poly_mul(r[k], 0x9)
		d[k] = poly_mul(r[k], 0xd)
		e[k] = poly_mul(r[k], 0xb)
	# Now we do something similar to what we did in mix_col
	r[0] = b[0] ^ e[1] ^ d[2] ^ c[3]
	r[1] = c[0] ^ b[1] ^ e[2] ^ d[3]
	r[2] = d[0] ^ c[1] ^ b[2] ^ e[3]
	r[3] = e[0] ^ d[1] ^ c[2] ^ b[3]

	return r
```

Let's add some debug statements????

I added a tiny sanity check to rev_mix_column and there is the problem:

```
def rev_mix_column(r: list) -> list: # This is used in InvMixColumns.
	a = [0,0,0,0]
	b = [0,0,0,0]
	c = [0,0,0,0]
	d = [0,0,0,0]
	e = [0,0,0,0]
	'''
	/* The array 'a' is simply a copy of the input array 'r'
     * The array 'b' is each element of the array 'a' multiplied by 0xe
	 * The array 'c' is each element of the array 'a' multiplied by 0x9
	 * The array 'd' is each element of the array 'a' multiplied by 0xd
	 * The array 'e' is each element of the array 'a' multiplied by 0xb
     * in Rijndael's Galois field
     * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */ 
	'''
	for k in range(4): # Can't use 'c' here, because it is already a name of a list.
		a[k] = r[k]
		#b[k] = r[k] * 0xe # multiplied by 0xe
		#c[k] = r[k] * 0x9 # multiplied by 0x9
		#d[k] = r[k] * 0xd # multiplied by 0xd
		#e[k] = r[k] * 0xb # multiplied by 0xb
		b[k] = poly_mul(r[k], 0xe)
		c[k] = poly_mul(r[k], 0x9)
		d[k] = poly_mul(r[k], 0xd)
		e[k] = poly_mul(r[k], 0xb)
		# Sanity check.
		int_list = [b[k], c[k], d[k], e[k]]
		assert all([x < 0x11B for x in int_list])

	# Now we do something similar to what we did in mix_col
	r[0] = b[0] ^ e[1] ^ d[2] ^ c[3]
	r[1] = c[0] ^ b[1] ^ e[2] ^ d[3]
	r[2] = d[0] ^ c[1] ^ b[2] ^ e[3]
	r[3] = e[0] ^ d[1] ^ c[2] ^ b[3]

	return r
```

the assert fails. Therefore the problem actually IS in poly_mul. Let's keep on investigating.

```
def poly_mul(a: int, b: int) -> int: # This function multiplies the polynomial a with b in G(2) and then modulo x**8 + x**4 + x**3 + x**2 + x + 1.
	out = 0
	k = b
	while k: # This basically shifts left and then if the current bit is a one, then xor the current thing with the thing.
		cur_bit = k & 1 # current bit.
		if cur_bit:
			out ^= (a) # xor if bit is one.
		# shift
		a <<= 1
		k >>= 1
	# Now modulo in polynomial in GF(2) # See https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
	out = poly_mod(out, 0x11B)
	return out
```

The bug may actually be in poly_mod. Fuck! Our testcase just happened to work, but some other cases may not work.

After doing adding a couple of debug statements:

```
def poly_mod(dividend: int, divisor: int) -> int:
	# First align the integers for the long division.
	if dividend < divisor:
		return dividend
	# This is used to align
	num_bits_dividend = bits(dividend)
	num_bits_divisor = bits(divisor)
	# We need to shift the divisor such that the most significant bits are aligned.
	diff = num_bits_dividend - num_bits_divisor
	divisor <<= diff # Align.
	# Main loop.
	while diff:
		print("Dividend: "+str(bin(dividend)[2:]))
		print("Divisor: "+str(bin(divisor)[2:]))
		if ((divisor) & dividend) & (1 << (bits(divisor)-1)):
			# We are aligned, therefore divide (XOR)
			dividend ^= divisor
		divisor >>= 1 # Shift one to the right
		diff -= 1
	return dividend
```

The relevant debug output is this:

```
Dividend: 10111100010
Divisor:  10001101100
Dividend: 110001110
Divisor:  1000110110
result is this: 0x18e
```

0x11B is 100011011 in binary, so why does the loop exit early? This is because there is a mistake in the while statement:

```
while diff:
```

we actually wan't `while diff >= 0:` , because we also wan't to run still once when diff == 0. After doing this quick change, now the code works correctly.

Now we have implemented InvMixColumns!

```
def MixColumns(input_matrix: list, reverse=False) -> list:
	# Get each column and then apply the matrix transformation.
	out = []
	print("input_matrix to MixColumns == "+str(input_matrix))
	for i in range(4):
		cur_column = [input_matrix[j][i] for j in range(4)]
		print("Here is the cur_column: "+str(cur_column))
		if not reverse:

			out.append(mix_one_column(cur_column))
		else:
			out.append(rev_mix_column(cur_column))
	out = transpose_mat(out)
	print("Outputting this from MixColumns: "+str(out))
	return out

def InvMixColumns(input_matrix: list) -> list:
	return MixColumns(input_matrix, reverse=True)
```

## Implementing InvAddRoundKey

No need to implement InvAddRoundKey. Because xor is its own inverse function, we can just pass the output of AddRoundKey to AddRoundKey again, and we get the original input. From the pdf: "AddRoundKey(), which was described in Sec. 5 1.4, is its own inverse, since it only involves an application of the XOR operation. "

## Programming the main decryption function.

In the pdf there is figure 15 which basically describes the decryption function.

Now, my current code is this:

```


import numpy as np
import rijndael
import copy
from typing import Iterable
import math
import testdatahelper # This is for MIX_COL_TESTS (for now.)

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

def access_table(table: list, index: int) -> int: # This is used to access the S box and the reverse S box.
	assert index <= 255 and index >= 0 # Sanity check.
	ind_x = index & 0b1111
	ind_y = (index & 0b11110000) >> 4
	return table[ind_y][ind_x]

def SubBytes(input_matrix: list, table=rijndael.S_BOX_MATRIX) -> list:
	for i in range(len(input_matrix)):
		for j in range(len(input_matrix[0])):
			input_matrix[i][j] = access_table(table, input_matrix[i][j])
	return input_matrix

def InvSubBytes(input_matrix: list) -> list:
	# Reverse of SubBytes. Otherwise similar, but use the reverse matrix instead.
	return SubBytes(input_matrix, table=rijndael.S_BOX_MATRIX_REV)


def shift_row_once(row: list, reverse=False) -> list:
	if not reverse:
		out = [row[i] for i in range(1,len(row))] + [row[0]]
	else:
		out = [row[-1]] + [row[i] for i in range(0,len(row)-1)]
	return out

def shift_row(row: list, n: int, reverse=False) -> list: # This shifts one singular line by n indexes.
	for i in range(n):
		row = shift_row_once(row, reverse=reverse)
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

def InvShiftRows(input_mat: list) -> list:

	assert len(input_mat) == 4
	assert len(input_mat[0]) == 4
	input_mat[1] = shift_row(input_mat[1], 1, reverse=True)
	input_mat[2] = shift_row(input_mat[2], 2, reverse=True)
	input_mat[3] = shift_row(input_mat[3], 3, reverse=True)

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

def bits(n: int) -> int:
	return math.ceil(math.log(n+1,2))



def poly_mod(dividend: int, divisor: int) -> int:
	# First align the integers for the long division.
	#print("Called poly_mod.")
	if dividend < divisor:
		#print("poopoo")
		return dividend
	# This is used to align
	num_bits_dividend = bits(dividend)
	num_bits_divisor = bits(divisor)
	# We need to shift the divisor such that the most significant bits are aligned.
	diff = num_bits_dividend - num_bits_divisor
	divisor <<= diff # Align.
	# Main loop.
	#print("diff == "+str(diff))
	assert diff >= 0
	while diff >= 0:
		#print("Dividend: "+str(bin(dividend)[2:]))
		#print("Divisor: "+str(bin(divisor)[2:]))
		if ((divisor) & dividend) & (1 << (bits(divisor)-1)):
			# We are aligned, therefore divide (XOR)
			dividend ^= divisor
		divisor >>= 1 # Shift one to the right
		diff -= 1
	return dividend

def poly_mul(a: int, b: int) -> int: # This function multiplies the polynomial a with b in G(2) and then modulo x**8 + x**4 + x**3 + x**2 + x + 1.
	out = 0
	k = b
	while k: # This basically shifts left and then if the current bit is a one, then xor the current thing with the thing.
		cur_bit = k & 1 # current bit.
		if cur_bit:
			out ^= (a) # xor if bit is one.
		# shift
		a <<= 1
		k >>= 1
	# Now modulo in polynomial in GF(2) # See https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
	#print("passing "+str(hex(out))+" to poly mod.")
	out = poly_mod(out, 0x11B)
	#print("result is this: "+str(hex(out)))
	assert out < 0x11B
	return out

def rev_mix_column(r: list) -> list: # This is used in InvMixColumns.
	a = [0,0,0,0]
	b = [0,0,0,0]
	c = [0,0,0,0]
	d = [0,0,0,0]
	e = [0,0,0,0]
	'''
	/* The array 'a' is simply a copy of the input array 'r'
     * The array 'b' is each element of the array 'a' multiplied by 0xe
	 * The array 'c' is each element of the array 'a' multiplied by 0x9
	 * The array 'd' is each element of the array 'a' multiplied by 0xd
	 * The array 'e' is each element of the array 'a' multiplied by 0xb
     * in Rijndael's Galois field
     * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */ 
	'''
	for k in range(4): # Can't use 'c' here, because it is already a name of a list.
		a[k] = r[k]
		#b[k] = r[k] * 0xe # multiplied by 0xe
		#c[k] = r[k] * 0x9 # multiplied by 0x9
		#d[k] = r[k] * 0xd # multiplied by 0xd
		#e[k] = r[k] * 0xb # multiplied by 0xb
		b[k] = poly_mul(r[k], 0xe)
		c[k] = poly_mul(r[k], 0x9)
		d[k] = poly_mul(r[k], 0xd)
		e[k] = poly_mul(r[k], 0xb)
		# Sanity check.
		int_list = [b[k], c[k], d[k], e[k]]
		assert all([x < 0x11B for x in int_list])

	# Now we do something similar to what we did in mix_col
	r[0] = b[0] ^ e[1] ^ d[2] ^ c[3]
	r[1] = c[0] ^ b[1] ^ e[2] ^ d[3]
	r[2] = d[0] ^ c[1] ^ b[2] ^ e[3]
	r[3] = e[0] ^ d[1] ^ c[2] ^ b[3]

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

def MixColumns(input_matrix: list, reverse=False) -> list:
	# Get each column and then apply the matrix transformation.
	out = []
	print("input_matrix to MixColumns == "+str(input_matrix))
	for i in range(4):
		cur_column = [input_matrix[j][i] for j in range(4)]
		print("Here is the cur_column: "+str(cur_column))
		if not reverse:

			out.append(mix_one_column(cur_column))
		else:
			out.append(rev_mix_column(cur_column))
	out = transpose_mat(out)
	print("Outputting this from MixColumns: "+str(out))
	return out

def InvMixColumns(input_matrix: list) -> list:
	return MixColumns(input_matrix, reverse=True)

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
	return print_hex(state)

def hex_list_to_str(int_list: list) -> None:
	oof = ''.join([hex(x)+" " for x in int_list])
	oof = oof[:-1]
	#print(oof)
	return oof


def test_mix_col() -> None:
	# This is ripped straight from wikipedia.  https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
	tests = testdatahelper.MIX_COL_TESTS
	for x,y in tests: # x is input and y is expected output. We also test the reverse function.
		print("Now running another test.")
		print("Here is the expected: "+str(hex_list_to_str(y)))
		print("Here is the input: "+str(hex_list_to_str(x)))
		x_copy = copy.deepcopy(x)
		x = mix_col(x)
		assert x == y # Should be the expected output
		# Test the reverse function now. We should end up with the original input.
		x = rev_mix_column(y)
		print("Here is the output from the reverse function: "+str(hex_list_to_str(x)))
		assert x == x_copy
	print("test_mix_col passed!!!")
	return

def test_poly_mul() -> None:
	a = 0b100
	b = 0b100
	res = poly_mul(a,b)
	assert res == 0b10000 # x**2 * x**2 == x**4
	
	# This example is ripped straight from the polynomial multiplication section of this pdf document: https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
	a = 87
	b = 131
	res = poly_mul(a,b)
	assert res == 193
	print("test_poly_mul passed")
	return

def test_poly_mod() -> None:
	# Tests the polynomial modulo (remainder) in GF(2)
	pol1 = 0b100 # x**2
	pol2 = 0b10000 # x**4
	res = poly_mod(pol2, pol1)
	print("result of the polynomial modulo test: "+str(res))
	assert res == 0 # Polynomial remainder should be zero.
	#input()
	# A bit of a more complex testcase. This is taken from the pdf file multiplication section.
	pol1 = 11129
	pol2 = 283
	res = poly_mod(pol1, pol2)
	print("res == "+str(bin(res)))
	assert res == 193
	#input()
	return

'''
InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])

begin

byte state[4,Nb]

state = in

AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1]) // See Sec. 5.1.4

for round = Nr-1 step -1 downto 1

InvShiftRows(state) // See Sec. 5.3.1

InvSubBytes(state) // See Sec. 5.3.2

AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])

InvMixColumns(state) // See Sec. 5.3.3

end for

InvShiftRows(state)

InvSubBytes(state)

AddRoundKey(state, w[0, Nb-1])

out = state

end
 
'''

def decrypt_state(expanded_key: list, encrypted_data: list, num_rounds: int, W_list: list) -> str:
	# This is the main decryption function.
	state = create_state(encrypted_data)
	state = AddRoundKey(state, num_rounds-1, W_list)
	# for round = Nr-1 step -1 downto 1
	for i in range(num_rounds-1, 0, -1): # zero is not included, so 1 is the final value of i
		# InvShiftRows(state) 
		state = InvSubBytes(state)
		state = InvShiftRows(state)
		state = InvMixColumns(state)
		state = AddRoundKey(state, i, W_list)

	state = InvSubBytes(state)
	state = InvShiftRows(state)
	state = AddRoundKey(state, 0, W_list)

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

def test_shift() -> None:
	paska = [[0,1,2,3],
			[4,5,6,7],
			[8,9,10,11],
			[12,13,14,15]]
	old_paska = copy.deepcopy(paska)
	ret = ShiftRows(paska)
	oof = [[0,1,2,3],
			[5,6,7,4],
			[10,11,8,9],
			[15,12,13,14]]
	assert ret == oof
	# Now test inverse function.
	oof = InvShiftRows(paska)
	assert oof == old_paska
	print("Passed test_shift!")

def test_s_box() -> None:
	# Go through every index and check the reverse.
	for ind in range(256):
		orig_val = access_table(rijndael.S_BOX_MATRIX, ind)
		should_be_ind = access_table(rijndael.S_BOX_MATRIX_REV, ind)
		assert should_be_ind == ind
	print("test_s_box passed!")
	return

MAX_TEST_BITS = 0xffff

def test_bits() -> None:
	for i in range(1,MAX_TEST_BITS):
		assert bits(i) == len(bin(i))-2
def run_tests() -> None:
	test_transpose_mat()
	test_S()
	test_key_expansion()
	test_print_hex()
	test_s_box
	# Test the reverse functions. If there is a function called f and an inverse function called F , then f(F(x)) = F(f(x)) = x
	test_shift()
	test_poly_mul()
	test_bits()
	test_poly_mod()
	test_mix_col()
	
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

	# encrypted = encrypt_state(expanded_key, example_plaintext, num_rounds, expanded_key)
	# print(encrypted)
	# Sanity check. It should be this.
	#assert encrypted == "69c4e0d86a7b0430d8cdb78070b4c55a" # This is the example vector from the pdf file.

	encrypted = "69c4e0d86a7b0430d8cdb78070b4c55a"
	# Now the encrypted data is in "encrypted". Now decrypting it, should return in the original plaintext.
	# First convert the encrypted stuff to bytes before decrypt_state.
	encrypted = bytes.fromhex(encrypted)
	decrypted = decrypt_state(expanded_key, encrypted, num_rounds, expanded_key)
	print("Done!")
	return 0

if __name__=="__main__":

	exit(main())




```

(Notice that I removed the encryption function, because we know that it works.)

I now get this error here:

```
    assert index <= 255 and index >= 0 # Sanity check.
                            ^^^^^^^^^^
AssertionError

```

soo there is some bug in the way we access some table.

I think the reason this happens, is that when we add the round key, we actually do not do any bounds checking, when we pass stuff to Inv ... actually nevermind. It may actually be in the MixColumns thing. Here is again a tiny snippet of the output:

```
Outputting this from MixColumns: [[71, 247, 97, 161], [115, 47, 203, 230], [185, 53, 1, 207], [31, 67, 142, 44]]
Cor key thing: [[19, 227, 243, 77], [17, 148, 7, 43], [29, 74, 167, 48], [127, 23, 139, 197]]
subkey == [[19, 227, 243, 77], [17, 148, 7, 43], [29, 74, 167, 48], [127, 23, 139, 197]]
input_mat == [[71, 247, 97, 161], [115, 47, 203, 230], [185, 53, 1, 207], [31, 67, 142, 44]]
subkey == [[19, 227, 243, 77], [17, 148, 7, 43], [29, 74, 167, 48], [127, 23, 139, 197]]
Here is the output from AddRoundKey: [[84, 20, 146, 236], [98, 187, 204, 205], [164, 127, 166, 255], [96, 84, 5, 233]]
input_matrix to MixColumns == [[253, 155, 116, 131], [128, 171, 254, 39], [197, 125, 29, 107], [253, 54, 235, 144]]
Here is the cur_column: [253, 128, 197, 253]
Here is the cur_column: [155, 171, 125, 54]
Here is the cur_column: [116, 254, 29, 235]
Here is the cur_column: [131, 39, 107, 144]
Outputting this from MixColumns: [[188, 192, 117, 204], [190, 208, 198, 196], [14, 208, 228, 154], [73, 416, 43, 205]] # <----- The problem occurs on this line, because there is 416 which is more than 255.
Cor key thing: [[84, 240, 16, 190], [153, 133, 147, 44], [50, 87, 237, 151], [209, 104, 156, 78]]
subkey == [[84, 240, 16, 190], [153, 133, 147, 44], [50, 87, 237, 151], [209, 104, 156, 78]]
input_mat == [[188, 192, 117, 204], [190, 208, 198, 196], [14, 208, 228, 154], [73, 416, 43, 205]]
subkey == [[84, 240, 16, 190], [153, 133, 147, 44], [50, 87, 237, 151], [209, 104, 156, 78]]
Here is the output from AddRoundKey: [[232, 48, 101, 114], [39, 85, 85, 232], [60, 135, 9, 13], [152, 456, 183, 131]]
```

after adding a sanity check to MixColumns, the problem becomes apparent:

```
def MixColumns(input_matrix: list, reverse=False) -> list:
	# Get each column and then apply the matrix transformation.
	out = []
	sanity_copy = copy.deepcopy(input_matrix)
	assert all([x >= 0 and x <= 255 for x in flatten(sanity_copy)]) # Here is the sanity check on the input.
	print("input_matrix to MixColumns == "+str(input_matrix))
	for i in range(4):
		cur_column = [input_matrix[j][i] for j in range(4)]
		print("Here is the cur_column: "+str(cur_column))
		if not reverse:

			out.append(mix_one_column(cur_column))
		else:
			out.append(rev_mix_column(cur_column))
	print("Outputting this from MixColumns: "+str(out))
	# Sanity checking.
	sanity_copy = copy.deepcopy(out)
	assert all([x >= 0 and x <= 255 for x in flatten(sanity_copy)])
	out = transpose_mat(out)
	return out
```

here:

```
    assert all([x >= 0 and x <= 255 for x in flatten(sanity_copy)])
AssertionError
```

After adding a couple of debug statements:

```
def MixColumns(input_matrix: list, reverse=False) -> list:
	# Get each column and then apply the matrix transformation.
	out = []
	sanity_copy = copy.deepcopy(input_matrix)
	assert all([x >= 0 and x <= 255 for x in flatten(sanity_copy)]) # Here is the sanity check on the input.
	#print("input_matrix to MixColumns == "+str(input_matrix))
	for i in range(4):
		cur_column = [input_matrix[j][i] for j in range(4)]
		print("Here is the cur_column: "+str(cur_column))
		if not reverse:

			out.append(mix_one_column(cur_column))
		else:
			print("cur_column: "+str(cur_column))
			reverse_mixing = rev_mix_column(cur_column)
			print("output from rev_mix_column: "+str(reverse_mixing))
			assert all([x >= 0 and x <= 255 for x in reverse_mixing])
			out.append(reverse_mixing)

	print("Outputting this from MixColumns: "+str(out))
	# Sanity checking.
	sanity_copy = copy.deepcopy(out)
	assert all([x >= 0 and x <= 255 for x in flatten(sanity_copy)])
	out = transpose_mat(out)
	return out
```

and here is the output:

```
cur_column: [155, 171, 125, 54]
output from rev_mix_column: [192, 208, 208, 416]
```

so the input list of `[155, 171, 125, 54]` causes the function to produce incorrect output.

As it turns out, there is a bug in the poly_mod function.

This is because even if the polynomial is less than 0x11B, we can still get the modulo, if there is still the same amount of bits, therefore this part here:

```
	if dividend < divisor:
		return dividend
```

is erroneous. We can still divide even if the divisor is greater than the dividend. This is because we work in the Galois Field 2 thing.

Here is my decryption function:

```
def decrypt_state(expanded_key: list, encrypted_data: list, num_rounds: int, W_list: list) -> str:
	# This is the main decryption function.
	state = create_state(encrypted_data)
	state = AddRoundKey(state, num_rounds-1, W_list)
	# for round = Nr-1 step -1 downto 1
	for i in range(num_rounds-1, 0, -1): # zero is not included, so 1 is the final value of i
		# InvShiftRows(state) 
		state = InvSubBytes(state)
		state = InvShiftRows(state)
		state = InvMixColumns(state)
		state = AddRoundKey(state, i, W_list)
	print("End of the loop!!!!")
	state = InvSubBytes(state)
	state = InvShiftRows(state)
	state = AddRoundKey(state, 0, W_list)

	return state
```

except that it doesn't get the original plaintext back. This is partly because there are additional steps in Figure 15 in the pdf file:

```
For the Equivalent Inverse Cipher, the following pseudo code is added at

the end of the Key Expansion routine (Sec. 5.2):

for i = 0 step 1 to (Nr+1)*Nb-1

dw[i] = w[i]

end for

for round = 1 step 1 to Nr-1

InvMixColumns(dw[round*Nb, (round+1)*Nb-1]) // note change of

type

end for

Note that, since InvMixColumns operates on a two-dimensional array of bytes

while the Round Keys are held in an array of words, the call to

InvMixColumns in this code sequence involves a change of type (i.e. the

input to InvMixColumns() is normally the State array, which is considered

to be a two-dimensional array of bytes, whereas the input here is a Round

Key computed as a one-dimensional array of words).
 
```

let's add debug statements which show the "state" in hex for each step.
Here are the steps used in decryption:

```
INVERSE CIPHER (DECRYPT):
round[ 0].iinput 69c4e0d86a7b0430d8cdb78070b4c55a
round[ 0].ik_sch 13111d7fe3944a17f307a78b4d2b30c5
round[ 1].istart 7ad5fda789ef4e272bca100b3d9ff59f
round[ 1].is_row 7a9f102789d5f50b2beffd9f3dca4ea7
round[ 1].is_box bd6e7c3df2b5779e0b61216e8b10b689
round[ 1].ik_sch 549932d1f08557681093ed9cbe2c974e
round[ 1].ik_add e9f74eec023020f61bf2ccf2353c21c7
round[ 2].istart 54d990a16ba09ab596bbf40ea111702f
round[ 2].is_row 5411f4b56bd9700e96a0902fa1bb9aa1
round[ 2].is_box fde3bad205e5d0d73547964ef1fe37f1
round[ 2].ik_sch 47438735a41c65b9e016baf4aebf7ad2
round[ 2].ik_add baa03de7a1f9b56ed5512cba5f414d23
round[ 3].istart 3e1c22c0b6fcbf768da85067f6170495
round[ 3].is_row 3e175076b61c04678dfc2295f6a8bfc0
round[ 3].is_box d1876c0f79c4300ab45594add66ff41f
round[ 3].ik_sch 14f9701ae35fe28c440adf4d4ea9c026
round[ 3].ik_add c57e1c159a9bd286f05f4be098c63439
round[ 4].istart b458124c68b68a014b99f82e5f15554c
round[ 4].is_row b415f8016858552e4bb6124c5f998a4c
round[ 4].is_box c62fe109f75eedc3cc79395d84f9cf5d
round[ 4].ik_sch 5e390f7df7a69296a7553dc10aa31f6b
round[ 4].ik_add 9816ee7400f87f556b2c049c8e5ad036
round[ 5].istart e8dab6901477d4653ff7f5e2e747dd4f
round[ 5].is_row e847f56514dadde23f77b64fe7f7d490
round[ 5].is_box c81677bc9b7ac93b25027992b0261996
round[ 5].ik_sch 3caaa3e8a99f9deb50f3af57adf622aa
round[ 5].ik_add f4bcd45432e554d075f1d6c51dd03b3c
round[ 6].istart 36339d50f9b539269f2c092dc4406d23
round[ 6].is_row 36400926f9336d2d9fb59d23c42c3950
round[ 6].is_box 247240236966b3fa6ed2753288425b6c
round[ 6].ik_sch 47f7f7bc95353e03f96c32bcfd058dfd
round[ 6].ik_add 6385b79ffc538df997be478e7547d691
round[ 7].istart 2d6d7ef03f33e334093602dd5bfb12c7
round[ 7].is_row 2dfb02343f6d12dd09337ec75b36e3f0
round[ 7].is_box fa636a2825b339c940668a3157244d17
round[ 7].ik_sch b6ff744ed2c2c9bf6c590cbf0469bf41
round[ 7].ik_add 4c9c1e66f771f0762c3f868e534df256
round[ 8].istart 3bd92268fc74fb735767cbe0c0590e2d
round[ 8].is_row 3b59cb73fcd90ee05774222dc067fb68
round[ 8].is_box 4915598f55e5d7a0daca94fa1f0a63f7
round[ 8].ik_sch b692cf0b643dbdf1be9bc5006830b3fe
round[ 8].ik_add ff87968431d86a51645151fa773ad009
round[ 9].istart a7be1a6997ad739bd8c9ca451f618b61
round[ 9].is_row a761ca9b97be8b45d8ad1a611fc97369
round[ 9].is_box 89d810e8855ace682d1843d8cb128fe4
round[ 9].ik_sch d6aa74fdd2af72fadaa678f1d6ab76fe
round[ 9].ik_add 5f72641557f5bc92f7be3b291db9f91a
round[10].istart 6353e08c0960e104cd70b751bacad0e7
round[10].is_row 63cab7040953d051cd60e0e7ba70e18c
round[10].is_box 00102030405060708090a0b0c0d0e0f0
round[10].ik_sch 000102030405060708090a0b0c0d0e0f
round[10].ioutput 00112233445566778899aabbccddeeff
 
```

so, let's add the debug statements...

Here is the output after adding debug statements:

```
round[0].iinput: 69c4e0d86a7b0430d8cdb78070b4c55a
Cor key thing: [[19, 227, 243, 77], [17, 148, 7, 43], [29, 74, 167, 48], [127, 23, 139, 197]]
length of flattened_list : 16
Here is the flattened list: [19, 17, 29, 127, 227, 148, 74, 23, 243, 7, 167, 139, 77, 43, 48, 197]
flattened_list[0] == 19
round[0].ik_sch == 13111d7fe3944a17f307a78b4d2b30c5
length of flattened_list : 16
Here is the flattened list: [122, 213, 253, 167, 137, 239, 78, 39, 43, 202, 16, 11, 61, 159, 245, 159]
flattened_list[0] == 122
round[1].istart: 7ad5fda789ef4e272bca100b3d9ff59f
length of flattened_list : 16
Here is the flattened list: [189, 181, 33, 137, 242, 97, 182, 61, 11, 16, 124, 158, 139, 110, 119, 110]
flattened_list[0] == 189
round[1].is_row: bdb52189f261b63d0b107c9e8b6e776e
length of flattened_list : 16
Here is the flattened list: [189, 110, 124, 61, 242, 181, 119, 158, 11, 97, 33, 110, 139, 16, 182, 137]
flattened_list[0] == 189
round[1].is_box: bd6e7c3df2b5779e0b61216e8b10b689
Here is the cur_column: [189, 110, 124, 61]
cur_column: [189, 110, 124, 61]
output from rev_mix_column: [71, 115, 185, 31]
Here is the cur_column: [242, 181, 119, 158]
cur_column: [242, 181, 119, 158]
output from rev_mix_column: [247, 47, 53, 67]
Here is the cur_column: [11, 97, 33, 110]
cur_column: [11, 97, 33, 110]
output from rev_mix_column: [97, 203, 1, 142]
Here is the cur_column: [139, 16, 182, 137]
cur_column: [139, 16, 182, 137]
output from rev_mix_column: [161, 230, 207, 44]
Outputting this from MixColumns: [[71, 115, 185, 31], [247, 47, 53, 67], [97, 203, 1, 142], [161, 230, 207, 44]]
length of flattened_list : 16
Here is the flattened list: [71, 115, 185, 31, 247, 47, 53, 67, 97, 203, 1, 142, 161, 230, 207, 44]
flattened_list[0] == 71
round[1].ik_add: 4773b91ff72f354361cb018ea1e6cf2c
Cor key thing: [[84, 240, 16, 190], [153, 133, 147, 44], [50, 87, 237, 151], [209, 104, 156, 78]]
length of flattened_list : 16
Here is the flattened list: [84, 153, 50, 209, 240, 133, 87, 104, 16, 147, 237, 156, 190, 44, 151, 78]
flattened_list[0] == 84
round[1].ik_sch == 549932d1f08557681093ed9cbe2c974e
length of flattened_list : 16
Here is the flattened list: [19, 234, 139, 206, 7, 170, 98, 43, 113, 88, 236, 18, 31, 202, 88, 98]
flattened_list[0] == 19
round[2].istart: 13ea8bce07aa622b7158ec121fca5862
```
Here is my current key expansion function:
```
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
	# At this spot here we should add the stuff for the inverse key.
	return R, W_actual
```

Yeah, I don't really understand the additional stuff for the InvMixColumns in figure 15 in the pdf file. I am going to continue tomorrow (also today is the 20th of February 2024 at 15:27 finnish time.).

To be continued.

Ok, so I changed the key_expansion to this:

```
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
	inverse_key_stuff = copy.deepcopy(W_actual)
	# Now do the stuff...
	'''
	for round = 1 step 1 to Nr-1
		InvMixColumns(dw[round*Nb, (round+1)*Nb-1]) 
	'''
	inverse_key_mat = [inverse_key_stuff[0]] # add the initial key shit.
	for k in range(1,len(inverse_key_stuff)):
		# Here do the inverse shit.
		inverse_key = [] # This is the 4x4 matrix.
		assert len(inverse_key_stuff[k]) == 4 # Sanity.
		cur_mat = inverse_key_stuff[k]
		for l in range(4):
			cur_column = [cur_mat[j][l] for j in range(4)]
			cur_column = rev_mix_column(cur_column)
			inverse_key.append(cur_column)
		inverse_key_mat.append(inverse_key)

	return R, W_actual, inverse_key_mat # inverse_key_mat is basically the reverse key list, where each element is the 4x4 key matrix.
```

and it produces the wrong key.

See, in the pdf document the `.ik_sch` lines are the corresponding key matrixes printed as hex. And it is wrong. Now i get `round[0].ik_sch == 000102030405060708090a0b0c0d0e0f` even though it should be `13111d7fe3944a17f307a78b4d2b30c5` . Here is the stuff which i do not understand in figure 15:

```
For the Equivalent Inverse Cipher, the following pseudo code is added at
the end of the Key Expansion routine (Sec. 5.2):
	for i = 0 step 1 to (Nr+1)*Nb-1
		dw[i] = w[i]
	end for
	for round = 1 step 1 to Nr-1
		InvMixColumns(dw[round*Nb, (round+1)*Nb-1]) // note change of type
	end for
Note that, since InvMixColumns operates on a two-dimensional array of bytes
while the Round Keys are held in an array of words, the call to
InvMixColumns in this code sequence involves a change of type (i.e. the
input to InvMixColumns() is normally the State array, which is considered
to be a two-dimensional array of bytes, whereas the input here is a Round
Key computed as a one-dimensional array of words).
```

This part here:

```
for i = 0 step 1 to (Nr+1)*Nb-1
		dw[i] = w[i]
	end for
```

just copies the keys and stuff.

...

Ok, so I implemented this function to print the keys:

```
def print_keys(keys: list) -> list:
	print("="*30)
	for key_mat in keys:
		stuff = print_hex(key_mat)
		print(stuff)
	print("="*30)
	return
```

and then when printing the keys (the non-reversed keys aka the ones which are used in the encryption function) I get this output:
```
==============================
000102030405060708090a0b0c0d0e0f
d6aa74fdd2af72fadaa678f1d6ab76fe
b692cf0b643dbdf1be9bc5006830b3fe
b6ff744ed2c2c9bf6c590cbf0469bf41
47f7f7bc95353e03f96c32bcfd058dfd
3caaa3e8a99f9deb50f3af57adf622aa
5e390f7df7a69296a7553dc10aa31f6b
14f9701ae35fe28c440adf4d4ea9c026
47438735a41c65b9e016baf4aebf7ad2
549932d1f08557681093ed9cbe2c974e
13111d7fe3944a17f307a78b4d2b30c5
==============================
```

ok, so the inverse cipher and the equivalent inverse cipher aren't the same thing and the weird stuff with the expanded key are only in the equivalent inverse cipher. (See this: https://www.studocu.com/en-us/messages/question/2863800/what-is-the-difference-between-the-aes-decryption-algorithm-and-the-equivalent-inverse-cipher)

Because I do not want to deal with the inverse cipher bullshit, I am just going to use the inverse cipher.

Ok, so the reason why it didn't work is that I looked at the equivalent inverse cipher, when I actually wanted to use the normal inverse cipher. I looked at the wrong pseudocode.

Here is the actual pseudocode for the correct inverse cipher:

```
InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
begin
byte state[4,Nb]
state = in
AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1]) // See Sec. 5.1.4
for round = Nr-1 step -1 downto 1
InvShiftRows(state) // See Sec. 5.3.1
InvSubBytes(state) // See Sec. 5.3.2
AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
InvMixColumns(state) // See Sec. 5.3.3
end for
InvShiftRows(state)
InvSubBytes(state)
AddRoundKey(state, w[0, Nb-1])
out = state
end
```

(As seen in Figure 12.)

and here is my current decryption function:

```
def decrypt_state(expanded_key: list, encrypted_data: list, num_rounds: int, W_list: list) -> str:
	# This is the main decryption function.
	state = create_state(encrypted_data)
	print("round[0].iinput: "+str(print_hex(state)))
	#state = AddRoundKey(state, num_rounds-1, W_list)
	print("num_rounds-1 == "+str(num_rounds-1))
	print("len(W_list) == "+str(len(W_list)))
	state = AddRoundKey(state, num_rounds-1, W_list, cur_round_num=0)

	#state = AddRoundKey(state, 0, W_list, cur_round_num=0) # Maybe this will actually work?????
	#print("round[0].ik_sch == "+str(print_hex(state)))
	# for round = Nr-1 step -1 downto 1
	count = 0
	for i in range(num_rounds-2, 0, -1): # zero is not included, so 1 is the final value of i
		count += 1
		# InvShiftRows(state) 
		print("round["+str(count)+"].istart: "+str(print_hex(state)))
		state = InvSubBytes(state)
		print("round["+str(count)+"].is_row: "+str(print_hex(state)))
		state = InvShiftRows(state)
		print("round["+str(count)+"].is_box: "+str(print_hex(state)))
		state = InvMixColumns(state)
		print("round["+str(count)+"].im_col: "+str(print_hex(state)))
		state = AddRoundKey(state, i, W_list, cur_round_num=count)
		#print("round["+str(count)+"].istart: "+str(print_hex(state)))
	print("End of the loop!!!!")
	state = InvSubBytes(state)
	state = InvShiftRows(state)
	state = AddRoundKey(state, 0, W_list)

	return state
```

As we can see, I used the equivalent inverse cipher pseudocode instead of the normal inverse cipher. Let's fix that.

After fixing the decryption function to actually match the correct pseudocode, it now works:

```

def decrypt_state(expanded_key: list, encrypted_data: list, num_rounds: int, W_list: list) -> str:
	# This is the main decryption function.
	state = create_state(encrypted_data)
	print("round[0].iinput: "+str(print_hex(state)))
	#state = AddRoundKey(state, num_rounds-1, W_list)
	print("num_rounds-1 == "+str(num_rounds-1))
	print("len(W_list) == "+str(len(W_list)))
	state = AddRoundKey(state, num_rounds-1, W_list, cur_round_num=0)

	#state = AddRoundKey(state, 0, W_list, cur_round_num=0) # Maybe this will actually work?????
	#print("round[0].ik_sch == "+str(print_hex(state)))
	# for round = Nr-1 step -1 downto 1
	count = 0
	for i in range(num_rounds-2, 0, -1): # zero is not included, so 1 is the final value of i
		count += 1
		# InvShiftRows(state) 
		print("round["+str(count)+"].istart: "+str(print_hex(state)))
		state = InvShiftRows(state)
		print("round["+str(count)+"].is_row: "+str(print_hex(state)))
		state = InvSubBytes(state)
		#print("round["+str(count)+"].im_col: "+str(print_hex(state)))
		state = AddRoundKey(state, i, W_list, cur_round_num=count)
		print("round["+str(count)+"].is_box: "+str(print_hex(state)))
		state = InvMixColumns(state)
		#print("round["+str(count)+"].istart: "+str(print_hex(state)))
	print("End of the loop!!!!")
	state = InvShiftRows(state)
	state = InvSubBytes(state)
	state = AddRoundKey(state, 0, W_list)

	return state
```

Now it decrypts the stuff correctly:

```
# SNIP
Here is the cur_column: [247, 190, 59, 41]
cur_column: [247, 190, 59, 41]
output from rev_mix_column: [205, 112, 183, 81]
Here is the cur_column: [29, 185, 249, 26]
cur_column: [29, 185, 249, 26]
output from rev_mix_column: [186, 202, 208, 231]
Outputting this from MixColumns: [[99, 83, 224, 140], [9, 96, 225, 4], [205, 112, 183, 81], [186, 202, 208, 231]]
End of the loop!!!!
Cor key thing: [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]]
Here is the final decrypted result: 00112233445566778899aabbccddeeff
Done!
```

## Where to go from here?

Ok, so maybe we could add support for the 192 and 256 bit variants. There are some nuances in both of these. Also I think there are actually different modes of aes, some of which are more secure than others (https://ciit.finki.ukim.mk/data/papers/10CiiT/10CiiT-46.pdf) . ECB (Electronic Code Book) is the weakest, because it encrypts each 16 byte block independently and therefore if there are repetitions of 16 bytes, they are easily recognizable and therefore decreasing entropy. There is also CBC (Cipher Block Chaining) which is a bit stronger. According to this: https://stackoverflow.com/questions/1220751/how-to-choose-an-aes-encryption-mode-cbc-ecb-ctr-ocb-cfb OCB is the most secure, but that mode is not mentioned in that pdf file and it also has some patent shit going on. Ok, so I think I am going to first start to try to support 192 and 256 bit modes on AES before trying to implement the multiblock encryption.

Also another thing is to refactor the code. For example separate the tests from the actual code and also wrap the encrypt and decrypt stuff into a class maybe. (Yucky! Object oriented programming!)

Ok, so I moved all of the test stuff to tests.py:

```


from main import * # This is used to import the functions which this file actually tests.
import rijndael

def run_tests() -> None:
	print("="*30)
	print("="*30)
	print("="*30)
	print("Now running tests!!!")
	test_transpose_mat()
	test_S()
	test_key_expansion()
	test_print_hex()
	test_s_box()
	# Test the reverse functions. If there is a function called f and an inverse function called F , then f(F(x)) = F(f(x)) = x
	test_shift()
	test_poly_mul()
	test_bits()
	test_poly_mod()
	test_mix_col()
	print("All tests passed!!!")
	print("="*30)
	print("="*30)
	print("="*30)

	return

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

def test_S() -> None:
	assert rijndael.S_BOX[0x9a] == 0xb8

def test_key_expansion():
	string = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c"
	key = bytes([int(x, base=16) for x in string.split(" ")])
	_, expanded_key, _ = key_expansion(bytes(key), "128")
	print_hex(expanded_key)


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


def test_shift() -> None:
	paska = [[0,1,2,3],
			[4,5,6,7],
			[8,9,10,11],
			[12,13,14,15]]
	old_paska = copy.deepcopy(paska)
	ret = ShiftRows(paska)
	oof = [[0,1,2,3],
			[5,6,7,4],
			[10,11,8,9],
			[15,12,13,14]]
	assert ret == oof
	# Now test inverse function.
	oof = InvShiftRows(paska)
	assert oof == old_paska
	print("Passed test_shift!")

def test_s_box() -> None:
	# Go through every index and check the reverse.
	for ind in range(256):
		orig_val = access_table(rijndael.S_BOX_MATRIX, ind)
		should_be_ind = access_table(rijndael.S_BOX_MATRIX_REV, orig_val)
		assert should_be_ind == ind
	print("test_s_box passed!")
	return


def test_poly_mul() -> None:
	a = 0b100
	b = 0b100
	res = poly_mul(a,b)
	assert res == 0b10000 # x**2 * x**2 == x**4
	
	# This example is ripped straight from the polynomial multiplication section of this pdf document: https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
	a = 87
	b = 131
	res = poly_mul(a,b)
	assert res == 193
	print("test_poly_mul passed")
	return


MAX_TEST_BITS = 0xffff

def test_bits() -> None:
	for i in range(1,MAX_TEST_BITS):
		assert bits(i) == len(bin(i))-2

def test_poly_mod() -> None:
	# Tests the polynomial modulo (remainder) in GF(2)
	pol1 = 0b100 # x**2
	pol2 = 0b10000 # x**4
	res = poly_mod(pol2, pol1)
	print("result of the polynomial modulo test: "+str(res))
	assert res == 0 # Polynomial remainder should be zero.
	#input()
	# A bit of a more complex testcase. This is taken from the pdf file multiplication section.
	pol1 = 11129
	pol2 = 283
	res = poly_mod(pol1, pol2)
	print("res == "+str(bin(res)))
	assert res == 193
	#input()
	return

def test_mix_col() -> None:
	# This is ripped straight from wikipedia.  https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
	tests = testdatahelper.MIX_COL_TESTS
	for x,y in tests: # x is input and y is expected output. We also test the reverse function.
		print("Now running another test.")
		print("Here is the expected: "+str(hex_list_to_str(y)))
		print("Here is the input: "+str(hex_list_to_str(x)))
		x_copy = copy.deepcopy(x)
		x = mix_col(x)
		assert x == y # Should be the expected output
		# Test the reverse function now. We should end up with the original input.
		x = rev_mix_column(y)
		print("Here is the output from the reverse function: "+str(hex_list_to_str(x)))
		assert x == x_copy
	print("test_mix_col passed!!!")
	return

```

Maybe I should create a function called test_enc_dec to test the encryption and decryption. Done! Now, let's create a function which tests the 192 bit encryption version. I don't think that there are any nuances in the 192 bit version, but we'll see soon enough.

And holy shit!!!!!!!!! I can't believe it! The code works immediately without any debugging for the 192 bit key version! This is absolutely fantastic!

## Ironing out the 256-bit version

Ok, so in the pdf file (this one: )

There is this notice in section 5.2 ("Key expansion"): "It is important to note that the Key Expansion routine for 256-bit Cipher Keys (Nk = 8) is slightly different than for 128- and 192-bit Cipher Keys. If Nk = 8 and i-4 is a multiple of Nk, then SubWord() is applied to w\[i-1\] prior to the XOR." so therefore we need to add a special case to the key expansion function, which accounts for this.

As it turns out, that stuff said in the pdf file is total bullshit, because if I have this code here in the W function (the key expansion function):

```
# This is the main key expansion function which does the heavy lifting.
def W(i: int, N: int, K: bytes, W: list, version="128") -> bytes: # The W list is being filled as we go.

	if version == "256": # This is the special case for the 256 bit key
		# Taken from https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
		# See section 5.2
		'''
		It is important to note that the Key Expansion routine for 256-bit Cipher Keys (Nk = 8) is slightly different than for 128- and 192-bit Cipher Keys. If Nk = 8 and i-4 is a multiple of Nk, then SubWord() is applied to w[i-1] prior to the XOR.
		'''
		if (i-4) % 8 == 0: # If Nk = 8 and i-4 is a multiple of Nk, then...
			# ... SubWord() is applied to w[i-1] prior to the XOR.
			#W_list[-1] = SubWord(W_list[-1])
			W[-1] = SubWord(W[-1])

	if i < N:
		return K[i]
	elif i >= N and (i % N == 0 % N):
		return xor_bytes(xor_bytes((W[i-N]), SubWord(RotWord(W[i-1]))), rcon(i//N))
	elif i >= N and N > 6 and (i % N == 4 % N):
		return xor_bytes(W[i-N], SubWord(W[i-1]))
	else:
		#print("paskaaa")
		return xor_bytes(W[i-N], W[i-1])
```

it produces the wrong answer, but if I remove the special case for the 256 bit key stuff, it works perfectly:

```
# This is the main key expansion function which does the heavy lifting.
def W(i: int, N: int, K: bytes, W: list, version="128") -> bytes: # The W list is being filled as we go.
	if i < N:
		return K[i]
	elif i >= N and (i % N == 0 % N):
		return xor_bytes(xor_bytes((W[i-N]), SubWord(RotWord(W[i-1]))), rcon(i//N))
	elif i >= N and N > 6 and (i % N == 4 % N):
		return xor_bytes(W[i-N], SubWord(W[i-1]))
	else:
		#print("paskaaa")
		return xor_bytes(W[i-N], W[i-1])
```

Then it works correctly. I don't know if the people who made the pdf just forgot to add this stuff to their implementation, which produced the example vectors, so there is a chance that the example vectors in the pdf are wrong, or maybe the special case stuff is somehow wrong idk.. I am just going to leave the code out for now, such that my code produces the example vector outputs.

## Cleaner wrapper and multiblock encryption

Ok, so I think it is time to make a cleaner wrapper around these encryption and decryption functions, and make it such that the user can just provide a list of bytes as the key and a list of bytes as the plaintext data which we need to encode. 

To accomplish this, we need to create a function which pads the bytes with zeroes when the data length is not a multiple of 16 bytes.

After a bit of typing, this is what I came up with:

```
def split_data_blocks(data: bytes) -> list: # This creates a list of data blocks.
	blocks = [data[i:i+16] for i in range(0,math.ceil(len(data)/16),16)] # Split into blocks.
	# Then we should pad the very last block.
	assert all([len(x)<=16 for x in blocks]) # Sanity checking
	if len(blocks[-1]) < 16:
		# pad the last block, because data length is not a multiple of 16 (in bytes).
		blocks[-1] = pad_plain_text(blocks[-1])
		assert len(blocks[-1]) == 16 # Sanity checking.
	return blocks
```

... create a test function ...

```
def test_split_data_blocks() -> None: # This tests the splitting of the data to 16 byte blocks. If the length of the data is not a multiple of 16 bytes, then pad the very last block with zeroes.
	example_data = "\x41"*16+"\x42\x43\x44\x45" # There are 16 "A" characters followed by "BCDE" in ascii.
	# Now try splitting.
	blocks = split_data_blocks(example_data)
	assert len(blocks) == 2 # There should only be 2 blocks.
	assert blocks[0] == "\x41"*16# The first block should be just 16 "A" characters.
	assert blocks[1] == "\x42\x43\x44\x45"+(16-len("\x42\x43\x44\x45"))*"\x00" # In the second block, there should be "\x42\x43\x44\x45" followed by 16-4=12 null bytes.
	print("test_split_data_blocks passed!!!")
	return
```

Does it pass? Fuck! It doesn't...

```
    assert len(blocks) == 2 # There should only be 2 blocks.
           ^^^^^^^^^^^^^^^^
AssertionError
```

Ok, so after a bit of debugging, I now have this:

```
def split_data_blocks(data: bytes) -> list: # This creates a list of data blocks.
	print("math.ceil(len(data)/16) == "+str(math.ceil(len(data)/16)))
	blocks = [data[i:i+16] for i in range(0,math.ceil(len(data)/16)*16,16)] # Split into blocks.
	print("blocks == "+str(blocks))
	# Then we should pad the very last block.
	assert all([len(x)<=16 for x in blocks]) # Sanity checking
	if len(blocks[-1]) < 16:
		# pad the last block, because data length is not a multiple of 16 (in bytes).
		blocks[-1] = pad_plain_text(blocks[-1], 16)
		assert len(blocks[-1]) == 16 # Sanity checking.
	return blocks
```

The bug was here: `math.ceil(len(data)/16)` , now it is: `math.ceil(len(data)/16)*16` , because we want to loop as if there were two full blocks instead of one full and one partial.

Then I had to modify the test function a bit, because I accidentally used strings instead of bytes.

```
def test_split_data_blocks() -> None: # This tests the splitting of the data to 16 byte blocks. If the length of the data is not a multiple of 16 bytes, then pad the very last block with zeroes.
	example_data = (b"\x41")*16+(b"\x42\x43\x44\x45") # There are 16 "A" characters followed by "BCDE" in ascii.
	# Now try splitting.
	blocks = split_data_blocks(example_data)
	print("Here is the blocks: "+str(blocks))
	assert len(blocks) == 2 # There should only be 2 blocks.
	assert blocks[0] == (b"\x41")*16# The first block should be just 16 "A" characters.
	assert blocks[1] == b"\x42\x43\x44\x45"+(16-len("\x42\x43\x44\x45"))*(b"\x00") # In the second block, there should be "\x42\x43\x44\x45" followed by 16-4=12 null bytes.
	print("test_split_data_blocks passed!!!")
	example_data = (b"\x41")*16 # There are 16 "A" characters 
	# Now try splitting.
	blocks = split_data_blocks(example_data)
	assert len(blocks) == 1
	assert blocks[0] == (b"\x41")*16
	return
```

Ok, so let's keep on programming the main encryption function. Currently it looks like this:

```
def encrypt(data: bytes, key: bytes, mode="ECB") -> bytes: # This is the main encryption function. Default to the electronic code book encryption mode. (ECB is the WEAKEST!!!)
	# Now get the appropriate AES version.
	version = get_aes_ver_from_key(key)
	# Now run the key expansion.
	num_rounds, expanded_key, reverse_keys = key_expansion(key, version) # Use the 192 bit version instead of the 128
	print_keys(expanded_key)
	if mode == "ECB": # Electronic code book mode.
		# Now go over the data blocks.
		data_blocks = split_data_blocks(data)
	return # Stub for now
```

Yeah, I know that ECB is like the weakest usage of AES, but I do not really care, because I'll implement the stronger modes later on.

Here is the final encryption function:

```
def encrypt(data: bytes, key: bytes, mode="ECB") -> bytes: # This is the main encryption function. Default to the electronic code book encryption mode. (ECB is the WEAKEST!!!)
	# Now get the appropriate AES version.
	version = get_aes_ver_from_key(key)
	# Now run the key expansion.
	num_rounds, expanded_key, reverse_keys = key_expansion(key, version) # Use the 192 bit version instead of the 128
	print_keys(expanded_key)
	if mode == "ECB": # Electronic code book mode.
		# Now go over the data blocks.
		data_blocks = split_data_blocks(data)
		# encrypt each data block separately.
		# def encrypt_state(expanded_key: list, plaintext: bytes, num_rounds: int, W_list: list) -> bytes:
		# encrypt_state(expanded_key, example_plaintext, num_rounds, expanded_key)
		orig_expanded_key = copy.deepcopy(expanded_key)
		encrypted_data_blocks = [encrypt_state(expanded_key, block, num_rounds, expanded_key) for block in data_blocks] # Encrypt each block.
		assert orig_expanded_key == expanded_key # Check for in-place modification. This should not change.
		# Join data blocks.
		encrypted_as_hex = ''.join(encrypted_data_blocks)
		# Convert to bytes.
		encrypted = bytes.fromhex(encrypted_as_hex)
		# Sanity check.
		assert len(encrypted) == 16 # Should be the size of the "state" matrix.
		return encrypted
	return # Stub for now
```

once again, I am going to program a test function for this. I should also program a test function for they key padding too.

One bug, which I found was that I forgot to put the `len` around the key in this function. Now I fixed it:

```
def get_aes_ver_from_key(key: bytes) -> str:
	if len(key) > (256//8):
		# Invalid key size.
		print("Invalid key size!!!")
		print("length of key must be less than or equal to 256!!!")
		print("length of key: "+str(len(key)))
		assert False # Invalid key size.
	version = None
	if len(key) > (192//8):
		# key must be 256 bit
		version = "256"
	elif len(key) > (128//8):
		# key must be 192 bit
		version = "192"
	else:
		version = "128" # default to 128 bit key.
	assert version != None # We should have assigned version as of now.
	return version
```

Here is the test functions:

```
def encrypt_helper(data: str, key: str, expected_result: str) -> bool: # Returns true if passed.
	example_plaintext = bytes.fromhex(data)
	key_bytes = bytes.fromhex(key)
	encrypted = encrypt(example_plaintext, key_bytes, mode="ECB") # Just Electronic Code Book, for now.
	return encrypted == bytes.fromhex(expected_result) # Check.

def test_enc() -> None:
	assert encrypt_helper("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a") # 128 bit keysize.
	assert encrypt_helper("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191") # 192 bit keysize.
	assert encrypt_helper("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089") # 256 bit keysize.
	print("test_enc passed!!!")
	return
```

and the tests pass! Hooray!!!

Let's just create a test for the key padding function.

```
def test_key_padding() -> None:
	num_bits = 128
	N = (num_bits)//32 # Length of key in bits divided by 32
	R = 10+((0*2)+1)
	# encryption_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
	encryption_key = bytes.fromhex("000102030405060708090a0b0c0d") # Just removed two bytes from the end.
	encryption_key = pad_key(encryption_key, N)
	assert len(encryption_key) == N*4
	assert encryption_key == bytes.fromhex("000102030405060708090a0b0c0d0000") # Check for the padded zeroes.
	print("test_key_padding passed!!!")
	return
```

## Implementing the decryption wrapper.

Ok, so now that we have programmed the encryption wrapper, it is time to program the decryption wrapper. I'll just use the same code as in encryption. Also I commented out this line: `assert len(encrypted) == 16 # Should be the size of the "state" matrix.` , because it only applied to the tests.

I just modified the encryption function to use the decryption:

```
def encrypt(data: bytes, key: bytes, mode="ECB", encryption=True) -> bytes: # This is the main encryption function. Default to the electronic code book encryption mode. (ECB is the WEAKEST!!!) encryption=True means that we are encrypting and encryption=False means that we are decrypting.
	# Now get the appropriate AES version.
	version = get_aes_ver_from_key(key)
	# Now run the key expansion.
	num_rounds, expanded_key, reverse_keys = key_expansion(key, version) # Use the 192 bit version instead of the 128
	print_keys(expanded_key)
	if mode == "ECB": # Electronic code book mode.
		# Now go over the data blocks.
		data_blocks = split_data_blocks(data)
		# encrypt each data block separately.
		# def encrypt_state(expanded_key: list, plaintext: bytes, num_rounds: int, W_list: list) -> bytes:
		# encrypt_state(expanded_key, example_plaintext, num_rounds, expanded_key)
		orig_expanded_key = copy.deepcopy(expanded_key)
		if encryption:

			encrypted_data_blocks = [encrypt_state(expanded_key, block, num_rounds, expanded_key) for block in data_blocks] # Encrypt each block.
		else:
			# Decryption
			encrypted_data_blocks = [decrypt_state(expanded_key, block, num_rounds, expanded_key) for block in data_blocks] # Encrypt each block.
		assert orig_expanded_key == expanded_key # Check for in-place modification. This should not change.
		# Join data blocks.
		encrypted_as_hex = ''.join(encrypted_data_blocks)
		# Convert to bytes.
		encrypted = bytes.fromhex(encrypted_as_hex)
		# Sanity check.
		#assert len(encrypted) == 16 # Should be the size of the "state" matrix.
		return encrypted
	return # Stub for now
```
and here is the decrypt function:
```
def decrypt(encrypted: bytes, key: bytes, mode="ECB") -> bytes:
	return encrypt(encrypted, key, mode=mode)
```

Here is the test helper:

```
def decrypt_helper(data: str, key: str, expected_result: str) -> bool:# Returns true if passed.
	example_plaintext = bytes.fromhex(data)
	key_bytes = bytes.fromhex(key)
	decrypted = decrypt(example_plaintext, key_bytes, mode="ECB") # Just Electronic Code Book, for now.
	return decrypted == bytes.fromhex(expected_result) # Check.
```
and here is the decryption test:

```
def test_dec() -> None:
	assert decrypt_helper("69c4e0d86a7b0430d8cdb78070b4c55a", "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff") # 128 bit keysize.
	assert decrypt_helper("dda97ca4864cdfe06eaf70a0ec0d7191", "000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff") # 192 bit keysize.
	assert decrypt_helper("8ea2b7ca516745bfeafc49904b496089", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff") # 256 bit keysize.
	print("test_enc passed!!!")
	return
```

does it pass???!!??! It does!

Now, let's create a final test with data which is not a multiple of 16 and an arbitrary key.

Actually no, the decryption did not pass, because I actually put `test_dec` instead of `test_dec()` in the tests function!
Fuck!!!!

Here is the error:

```
    assert decrypt_helper("69c4e0d86a7b0430d8cdb78070b4c55a", "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff") # 128 bit keysize.
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AssertionError

```

Ahhh, i see:

Here is my current code:

```
def decrypt(encrypted: bytes, key: bytes, mode="ECB") -> bytes:
	return encrypt(encrypted, key, mode=mode)
```

and here is the fixed code:

```
def decrypt(encrypted: bytes, key: bytes, mode="ECB") -> bytes:
	return encrypt(encrypted, key, mode=mode, encryption=False)
```

I forgot to actually tell the function to decrypt instead of encrypt. Let's try again..

Uh oh...

```
   encrypted_as_hex = ''.join(encrypted_data_blocks)
                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
TypeError: sequence item 0: expected str instance, list found
```

That is because in the encryption function we actually return the stuff as a hex string, but in the decryption function we return as bytes: `return state` it should be : `return print_hex(state)`

Let's make it such that the decrypt and encrypt functions actually return bytes instead of the hex string. It will make our lives a lot easier. I don't know why I even initially made it such that the functions return a hex string.

Here is a tiny helper function:

```
def list_to_bytes(bytes_list: bytes) -> bytes: # This function returns the 4x4 matrix or whatever as a bytes string.
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
	out = b""
	for x in flattened_list:
		out += bytes([x])
	return out
```

Here is the test function:

```
def test_list_to_bytes() -> None:
	# This tests the 4x4 matrix to bytes conversion.
	test_mat = [[0,4,8,12],
				[1,5,9,13],
				[2,6,10,14],
				[3,7,11,15]]
	# Now just create the bytes string.
	bytes_string = list_to_bytes(test_mat)
	# Check the result.
	assert bytes_string == bytes.fromhex("000102030405060708090a0b0c0d0e0f")
	print("test_list_to_bytes passed!!!")
	return
```

and it passes!!! Good. Ok, so now we just need to change the stuff to work with this instead.

Ok, so I changed some stuff such that it now assumes that both encrypt and decrypt return bytes instead of hex string. (This is in commit 54b5838714aa235c4e602328095842d5260db3d8 )

## Implementing different encryption modes

Ok, so now we only support ECB, which is the least secure out of all of these. I was sussed out that there wasn't a wikipedia page on the different block encryption modes in AES, but I was just searching with the wrong keywords. Here is the page: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

We actually probably don't need to pad the input bytes with zeroes, because of this: https://en.wikipedia.org/wiki/Ciphertext_stealing Maybe I should implement that too.

Let's implement Cipher Block Chaining first for example: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)

Now, the bad thing about these different block encryption modes is that there aren't that many test vectors available in the pdf, because the pdf just describes the aes encryption itself, but not how to use AES in multiple blocks of data. After googling, I found this: https://github.com/ircmaxell/quality-checker/blob/master/tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/aes-cbc.test-vectors which seems what we are looking for. It is for the CBC mode. CBC mode is more secure than ECB, but it is still quite insecure. I am still going to implement it because reasons.

## Implementing CBC (Cipher Block Chaining)

Let's look at wikipedia (as usual) https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)

I modified the encryption helper a bit:
```
def encrypt_helper(data: str, key: str, expected_result: str, mode="ECB") -> bool: # Returns true if passed.
	example_plaintext = bytes.fromhex(data)
	key_bytes = bytes.fromhex(key)
	encrypted = encrypt(example_plaintext, key_bytes, mode=mode) # Just Electronic Code Book, for now.
	return encrypted == bytes.fromhex(expected_result) # Check.
```
I also made this test:
```
def test_encrypt_cbc() -> None: # Cipher Block Chaining mode.
	# See https://github.com/ircmaxell/quality-checker/blob/master/tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/aes-cbc.test-vectors for the CBC test vectors.
	assert encrypt_helper("6bc1bee22e409f96e93d7e117393172a", "2b7e151628aed2a6abf7158809cf4f3c", "7649abac8119b246cee98e9b12e9197d", mode="CBC") # 128 bit keysize.
```

which fails. The reason for why it fails is because in the test vectors (aka here: https://github.com/ircmaxell/quality-checker/blob/master/tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/aes-cbc.test-vectors ) we have iv defined and the iv is basically just the stuff with which we xor the input before passing it to the encryption function. Because there aren't test vectors which do not have this, we need to program a special case for this:

```
def encrypt(data: bytes, key: bytes, mode="ECB", encryption=True, iv=None) -> bytes: # This is the main encryption function. Default to the electronic code book encryption mode. (ECB is the WEAKEST!!!) encryption=True means that we are encrypting and encryption=False means that we are decrypting.
	# Now get the appropriate AES version.
	version = get_aes_ver_from_key(key)
	# Now run the key expansion.
	num_rounds, expanded_key, reverse_keys = key_expansion(key, version) # Use the 192 bit version instead of the 128
	print_keys(expanded_key)
	if mode == "ECB" or mode == "CBC": # Electronic code book mode.
		# Now go over the data blocks.
		data_blocks = split_data_blocks(data)
		# encrypt each data block separately.
		# def encrypt_state(expanded_key: list, plaintext: bytes, num_rounds: int, W_list: list) -> bytes:
		# encrypt_state(expanded_key, example_plaintext, num_rounds, expanded_key)
		orig_expanded_key = copy.deepcopy(expanded_key)
		if encryption:
			if mode == "CBC":
				# CBC mode
				# Encrypt the first block normally, then xor the input with the last encrypted output before putting it through the encryption process in subsequent blocks.
				# Here is the debug shit. If the iv variable is defined, then just do the xor straight away with the iv vector.
				if iv == None:

					encrypted_data_blocks = [encrypt_state(expanded_key, data_blocks[0], num_rounds, expanded_key)] # Encrypt the first block normally.
					for block in data_blocks[1:]:
						# First xor the input. with the previous encrypted block.
						input_block = xor_bytes(block, encrypted_data_blocks[-1])
						encrypted_block = encrypt_state(expanded_key, input_block, num_rounds, expanded_key)
						# Now append the encrypted block to the output.
						encrypted_data_blocks.append(encrypted_block)
				else:
					# This is the debug shit.
					encrypted_data_blocks = []
					#encrypted_data_blocks = [encrypt_state(expanded_key, data_blocks[0], num_rounds, expanded_key)] # Encrypt the first block normally.
					first_block = True
					for block in data_blocks:
						if first_block:
							input_block = xor_bytes(block, bytes.fromhex(iv)) # This is used to simulate the earlier blocks...
						else:
							# First xor the input. with the previous encrypted block.
							input_block = xor_bytes(block, encrypted_data_blocks[-1])
						encrypted_block = encrypt_state(expanded_key, input_block, num_rounds, expanded_key)
						# Now append the encrypted block to the output.
						encrypted_data_blocks.append(encrypted_block)
```

after adding this special case, now the code works properly. Now it is time to implement the decryption using CBC mode. Ok, so if you actually read the wikipedia article, the iv stands for initialization vector and is actually a required part of encryption. I am going to program a function which generates this initalization vector later on. Let's keep on implementing the CBC decryption...








