
# Fuzzing IAVL

Hi!

Today I realized that there is a bug bounty program set in place for cosmos which is some crypto bro shit which I do not really know about: https://hackerone.com/cosmos/policy_scopes . Anyway, the important thing is that they have this custom format here: https://github.com/cosmos/iavl which implements a treestyle structure. There actually exists a fuzzer for this: https://github.com/cosmos/iavl/blob/master/tree_fuzz_test.go but the thing is that it only generates completely random trees and does not do coverage based fuzzing or doesn't use any "smart" strategies. We need to basically program a function which converts the fuzz data to a program.

This is a quick deserialization function which I quickly wrote up:

```
// Deserialize a program from a bytebuffer
func deserializeProgram(data []byte) *program {
	p := &program{}
	nextVersion := 1
	cur_index := 0 // Just set the index to zero to start with.
	// for p.size() < size {
	for true { // Basically simulate a "while" loop because while loops do not exist in golang :D

		if cur_index+1 >= len(data) {
			break
		}

		k, v := []byte{data[cur_index]}, []byte{data[cur_index+1]} // [...]byte{int(data[cur_index])}, [...]byte{int(data[cur_index+1])}

		cur_index += 2

		if cur_index >= len(data) {
			break
		}

		opcode := data[cur_index]
		cur_index += 1

		switch opcode % 7 {
		case 0, 1, 2:
			p.addInstruction(instruction{op: "SET", k: k, v: v})
		case 3, 4:
			p.addInstruction(instruction{op: "REMOVE", k: k})
		case 5:
			p.addInstruction(instruction{op: "SAVE", version: int64(nextVersion)})
			nextVersion++
		case 6:
			if cur_index >= len(data) {
				break
			}
			if rv := int(data[cur_index]) % nextVersion; rv < nextVersion && rv > 0 {
				p.addInstruction(instruction{op: "DELETE", version: int64(rv)})
			}
		}
		if cur_index >= len(data) {
			break
		}
	}
	return p
}

```

## Results

Ok, so I fuzzed the program for a bit. Now let's see if it found any crashes. Most likely not, but you never know.


