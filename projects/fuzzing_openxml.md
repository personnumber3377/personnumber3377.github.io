# Fuzzing openxml document formats

I recently found openxml which is the format that microsoft office uses.

```


from dos_finder import * # This is to import the mutator stuff
import io
import zipfile

def mutate_xml_contents(fn: str, original_contents: bytes):
	assert isinstance(original_contents, bytes) # Should be of type bytes
	# print("Mutating this: "+str(fn))
	new = mutate(original_contents) # Call the dos finder stuff.
	print(new)
	return new # Just a dummy for now.

def mutate_openxml(zip_bytes, modify_func): # Thanks to ChatGPT!!!
	"""
	Modifies a ZIP file in memory by applying `modify_func` to its contents.

	Args:
		zip_bytes (bytes): The original ZIP file as a byte stream.
		modify_func (function): A function that takes (filename, content) and returns modified content.

	Returns:
		bytes: The modified ZIP file as a byte stream.
	"""
	# Read original ZIP from memory
	input_zip = io.BytesIO(zip_bytes)
	# print("Length of bytes: "+str(len(zip_bytes)))
	with zipfile.ZipFile(input_zip, 'r') as zip_in:
		# Store the modified contents
		modified_files = {}

		# Here instead of mutating each file, just choose one and mutate it instead.

		'''
		for file_name in zip_in.namelist():
			with zip_in.open(file_name) as f:
				original_content = f.read()
				modified_content = modify_func(file_name, original_content)
				modified_files[file_name] = modified_content
		'''
		shit = zip_in.namelist()
		# print("Here is the thing: "+str(list(shit)))
		# print("zip_in.namelist() == "+str(zip_in.namelist()))
		target_file_name = random.choice(zip_in.namelist())
		for file_name in zip_in.namelist():

			if file_name == target_file_name:

				with zip_in.open(file_name) as f:
					original_content = f.read()
					modified_content = modify_func(file_name, original_content)
					modified_files[file_name] = modified_content

			else:
				# Now just do the stuff...
				with zip_in.open(file_name) as f:
					original_content = f.read()
					# modified_content = modify_func(file_name, original_content)
					modified_files[file_name] = original_content # Just copy the original contents...

	# Create a new ZIP file in memory
	output_zip = io.BytesIO()
	with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zip_out:
		for file_name, content in modified_files.items():
			zip_out.writestr(file_name, content)

	return output_zip.getvalue()


def init():
	pass

def deinit():
	pass

def fuzz(buf, add_buf, max_size): # For AFL and AFL++

	data = buf

	#print(str(type(data)) * 100)

	#assert (isinstance(data, bytes))

	data = bytes(data) # Convert bytearray to bytes.

	data = mutate_openxml(data, mutate_xml_contents)

	if len(data) >= max_size:
		print("Truncating returned fuzz data...\n")
		print("Orig len is " + str(len(data)) + " . New len is " + str(max_size))
		data = data[:max_size] # Truncate

	data = bytearray(data) # Convert bytes back to bytearray.

	return data


TEST_MUT_COUNT=1000

TEST_FILENAME = "test.ppt"

def load_test_data():
	fh = open(TEST_FILENAME, "rb")
	data = fh.read()
	fh.close()
	return data

def test_mut():
	# Tests the mutator.
	test_data = load_test_data()
	for _ in range(TEST_MUT_COUNT):
		# Run the thing...
		test_data = mutate_openxml(test_data, mutate_xml_contents)
	return



if __name__=="__main__":
	test_mut()
	exit()


```

Here is quick mutator I whipped up. Let's see how it succeeds...





