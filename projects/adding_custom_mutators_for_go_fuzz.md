
# Adding custom mutators for go-fuzz

I discovered go-fuzz on github: https://github.com/dvyukov/go-fuzz and it otherwise seems fine, but it doesn't support custom mutators for some reason...

I decided to add support for python custom mutators because I have written a specific custom mutator which I would like to use in the future.

I discovered this quick thing: https://github.com/tliron/py4go which seems to be a way to call python from go.

Let's smash these two together and see what happens...

## Initial investigation

The `go-fuzz-build/main.go` file seems to be a nice place to put the custom mutator and stuff like that... except the thing is that I do not even know how to build the thing, so let's figure out that first...

## Giving up

Ok, so because I don't even know how to compile the darn thing from a local source, I decided to file this issue and ask for help: https://github.com/dvyukov/go-fuzz/issues/355

Instead of using my python custom mutator, let's create a custom mutator in golang in a similar fashion.

## The beginnings of the custom mutator

Because the mutator has to be based on the input itself (remember we can't use the custom mutator api) it needs to be based on the input data itself.

I think the way to do this is to have a kind of compression type thing going on where the first let's say two bytes indicate the repeat count and then the next two bytes indicate the repeat length, and then there is "repeat length" number of characters after that get repeated "repeat count" times. I think that is a decent plan eh?

I think the best strategy is to use some kind of bitreader class type thing?????


Something like this??

```

func parse(data []byte) []byte { // Parse the bullshit
	// Parse the byte array thing.
	var out []byte // Output byte array.
	repeat_count := 0 // How much to repeat
	repeat_length := 0 // How many characters to repeat
	for cur_idx := 0; cur_idx < len(data); cur_idx++ { // Our current index into the bytearray.
		repeat_count = 0
		repeat_length = 0
		if len(data) - cur_idx <= 4 { // Break if the length of the data isn't useful anymore.
			break
		}
		// First read the repeat_count
		repeat_count |= int(data[cur_idx])
		cur_idx++ // Increment
		repeat_count |= int((data[cur_idx])) << 8 // Shift to the left to get the higher byte.
		cur_idx++
		// Then read the repeat_length.
		repeat_length |= int(data[cur_idx])
		cur_idx++ // Increment
		repeat_length |= int((data[cur_idx])) << 8
		cur_idx++
		// Increment the index and then if it skips over the buffer, then break.
		if cur_idx + repeat_length >= len(data) {
			// Final append.
			// What to append is basically bytes.Repeat(data[cur_idx:], repeat_count)
			out = append(out, bytes.Repeat(data[cur_idx:], repeat_count)...) // Add to the output.
			break
		} else {
			out = append(out, bytes.Repeat(data[cur_idx:cur_idx+repeat_length], repeat_count)...)
		}
		cur_idx += repeat_length
	}
	return out
}

```

that seems quite succifient at a first glance...

## Testing our new tool out...

Let's see what happens...

I think a good idea is to add an absolute maximum to our input and also add a hard cap to the repeat stuff such that we do not spit out obscenely large outputs...

Something like this???

```


func parse(data []byte) []byte { // Parse the bullshit
	// Parse the byte array thing.
	var out []byte // Output byte array.
	repeat_count := 0 // How much to repeat
	repeat_length := 0 // How many characters to repeat

	// Hardcoded constants.

	max_repeat_count := 10000
	max_repeat_length := 100

	max_output_size := 100000 // Hardcap at 100k

	for cur_idx := 0; cur_idx < len(data); cur_idx++ { // Our current index into the bytearray.
		repeat_count = 0
		repeat_length = 0
		if len(data) - cur_idx <= 4 { // Break if the length of the data isn't useful anymore.
			break
		}
		// First read the repeat_count
		repeat_count |= int(data[cur_idx])
		cur_idx++ // Increment
		repeat_count |= int((data[cur_idx])) << 8 // Shift to the left to get the higher byte.
		cur_idx++

		repeat_count = repeat_count % max_repeat_count

		// Then read the repeat_length.
		repeat_length |= int(data[cur_idx])
		cur_idx++ // Increment
		repeat_length |= int((data[cur_idx])) << 8
		cur_idx++

		repeat_length = repeat_length % max_repeat_length

		// Increment the index and then if it skips over the buffer, then break.
		if cur_idx + repeat_length >= len(data) {
			// Final append.
			// What to append is basically bytes.Repeat(data[cur_idx:], repeat_count)
			out = append(out, bytes.Repeat(data[cur_idx:], repeat_count)...) // Add to the output.
			break
		} else {
			out = append(out, bytes.Repeat(data[cur_idx:cur_idx+repeat_length], repeat_count)...)
		}
		cur_idx += repeat_length
	}

	// Final output check...

	if len(out) > max_output_size {
		out = out[:max_output_size] // Slice
	}

	return out
}


```







