
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















