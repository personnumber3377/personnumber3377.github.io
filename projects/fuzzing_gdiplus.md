# Fuzzing gdiplus

Here:

```


#define _CRT_SECURE_NO_WARNINGS // Just shut up compiler warnings

#include <stdio.h>
#include <windows.h>
#include <gdiplus.h>

using namespace Gdiplus;

wchar_t* charToWChar(const char* text)
{
	size_t size = strlen(text) + 1;
	wchar_t* wa = new wchar_t[size];
	mbstowcs(wa, text, size);
	return wa;
}


__declspec(noinline) void loop(wchar_t* filename) {
	// Main persistent loop here
	Image* image = NULL;
	Image* thumbnail=NULL;

	image = new Image(filename);
	if (image && (Ok == image->GetLastStatus())) {
		//printf("Image loaded\n");
		thumbnail = image->GetThumbnailImage(100, 100, NULL, NULL);
		/*
		if(thumbnail && (Ok == thumbnail->GetLastStatus())) {
			//printf("Thumbnail created\n");
		}
		*/

	}

	//printf("Done\n");

	if (image) delete image;
	if(thumbnail) delete thumbnail;
}



int main(int argc, char** argv)
{
	if (argc < 2) {
		printf("Usage: %s <image file>\n", argv[0]);
		return 0;
	}

	GdiplusStartupInput gdiplusStartupInput;
	ULONG_PTR gdiplusToken;
	GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

	wchar_t* fname = charToWChar(argv[1]);

	while (true) {
		loop(fname); // Just call the target method in a loop. This is to use the persistent mode of winafl.
	}

	GdiplusShutdown(gdiplusToken);

	return 0;
}


```

I am going to just call the loop method.

Here is just a fuzzing script:

```
C:\Users\elsku\winafl\winafl\build\bin\Release\afl-fuzz.exe -i c:\Users\elsku\inputs -o c:\Users\elsku\outputs -D C:\Users\elsku\dynamorio2\DynamoRIO-Windows-11.3.0-1\bin64 -I 40000   -t 40000 -f input.emf -- -coverage_module gdiplus.dll -fuzz_iterations 1000 -persistence_mode in_app -target_module gdiplusharness.exe -verbose 100 -target_offset 0x1170 -nargs 1 -- "C:\Users\elsku\source\repos\gdiplusharness\x64\Release\gdiplusharness.exe" "@@"
```

I originally tried with the `-target_method loop` command line option, but I actually got an error complaining that `to_wrap` wasn't found. I filed an issue with winafl for this bug. https://github.com/googleprojectzero/winafl/issues/456

## Adding a custom mutator...

Ok, so the file format is actually quite well documented and so we can just add a custom mutator for this...

Here is my custom mutator library: https://github.com/personnumber3377/emf_custom_mutator

Here is a documentation of the file format: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-emf/91c257d7-c39d-4a36-9b1f-63e3f73d30ca

The spec itself is roughly 300 pages, but fuck that. I am just going to skim over it. It specifies every possible command and transformation.

I actually think that programming a metaprogrammer which goes through the pdf and get's every possible EMF record type and then writes a fuzzer for each type should be a good strategy????

The spec is huge and the probability that the mcafee guys went through absolutely every possible edgecase is slim to none, so I think there are some very juicy bugs yet to be found...

Actually let's just create a separate repo for a parser.

## Adding a metaprogrammer for header files.

Ok, so let's also add an implementation for the actual bullshit which takes in a .h header and then outputs a reader for that file.

```

typedef struct tagENHMETAHEADER {
    DWORD   iType;              // Record type
    DWORD   nSize;              // Size of this record in bytes
    RECTL   rclBounds;          // Bounds in device units (4 DWORDs)
    RECTL   rclFrame;           // Frame in .01 millimeter units (4 DWORDs)
    DWORD   dSignature;         // Signature
    DWORD   nVersion;           // Version of the metafile
    DWORD   nBytes;             // Total size of the metafile in bytes
    DWORD   nRecords;           // Number of records in the metafile
    WORD    nHandles;           // Number of handles in the handle table
    WORD    sReserved;          // Reserved, must be 0
    DWORD   nDescription;       // Number of characters in the description string
    DWORD   offDescription;     // Offset to the description string
    DWORD   nPalEntries;        // Number of palette entries
    SIZEL   szlDevice;          // Device resolution in pixels (2 DWORDs)
    SIZEL   szlMillimeters;     // Device resolution in millimeters (2 DWORDs)
} ENHMETAHEADER;

```

Something like this maybe?

```

import re

def c_header_to_python(header):
    # Mapping of C types to struct format characters
    type_mapping = {
        "DWORD": "I",   # Unsigned 4 bytes
        "WORD": "H",    # Unsigned 2 bytes
        "LONG": "i",    # Signed 4 bytes
        "RECTL": "4i",  # 4 LONGs
        "SIZEL": "2i",  # 2 LONGs
    }

    # Regular expression to match C-style fields
    field_regex = re.compile(r"(\w+)\s+(\w+);")
    struct_format = ""
    fields = []

    # Process the header line by line
    for line in header.splitlines():
        match = field_regex.search(line)
        if match:
            c_type, field_name = match.groups()
            if c_type in type_mapping:
                struct_format += type_mapping[c_type]
                fields.append(field_name)
            else:
                raise ValueError(f"Unknown type: {c_type}")

    # Generate Python code
    python_code = f"""import struct

class EMFHeader:
    format = '{struct_format}'

    def __init__(self, data):
        unpacked = struct.unpack(self.format, data)
        fields = {fields}
        for field, value in zip(fields, unpacked):
            setattr(self, field, value)

    @classmethod
    def from_file(cls, filename):
        with open(filename, 'rb') as f:
            data = f.read(struct.calcsize(cls.format))
            return cls(data)
"""
    return python_code


# Example usage
c_header = """
DWORD   iType;
DWORD   nSize;
RECTL   rclBounds;
RECTL   rclFrame;
DWORD   dSignature;
DWORD   nVersion;
DWORD   nBytes;
DWORD   nRecords;
WORD    nHandles;
WORD    sReserved;
DWORD   nDescription;
DWORD   offDescription;
DWORD   nPalEntries;
SIZEL   szlDevice;
SIZEL   szlMillimeters;
"""

generated_code = c_header_to_python(c_header)
print(generated_code)

```

Here is an improved version:

```

import re

def c_header_to_python(header):
    # Mapping of C types to struct format characters
    type_mapping = {
        # Integer types
        "BYTE": "B",         # Unsigned 1 byte
        "CHAR": "b",         # Signed 1 byte
        "UCHAR": "B",        # Unsigned 1 byte
        "SHORT": "h",        # Signed 2 bytes
        "USHORT": "H",       # Unsigned 2 bytes
        "WORD": "H",         # Unsigned 2 bytes (Windows-specific)
        "INT": "i",          # Signed 4 bytes
        "UINT": "I",         # Unsigned 4 bytes
        "LONG": "l",         # Signed 4 bytes
        "ULONG": "L",        # Unsigned 4 bytes
        "DWORD": "I",        # Unsigned 4 bytes (Windows-specific)
        "LONGLONG": "q",     # Signed 8 bytes
        "ULONGLONG": "Q",    # Unsigned 8 bytes
        "SIZE_T": "Q",       # Platform-dependent size type (64-bit here)

        # Floating-point types
        "FLOAT": "f",        # 4 bytes
        "DOUBLE": "d",       # 8 bytes

        # Character types
        "TCHAR": "c",        # 1 character (use Unicode-specific mappings if needed)
        "WCHAR": "H",        # 2 bytes (Unicode character)
        "CHAR16": "H",       # UTF-16 2-byte character
        "CHAR32": "I",       # UTF-32 4-byte character

        # Composite types
        "RECTL": "4i",       # Rectangle (4 signed LONGs)
        "SIZEL": "2i",       # Size (2 signed LONGs)
        "POINTL": "2i",      # Point (2 signed LONGs)
        "RECT": "4i",        # Rectangle structure
        "SIZE": "2i",        # Size structure
        "POINT": "2i",       # Point structure

        # Boolean types
        "BOOL": "I",         # 4 bytes (commonly used in Windows)
        "BOOLEAN": "B",      # 1 byte (commonly used in Unix)

        # Special types
        "HANDLE": "P",       # Pointer to a handle (platform-dependent size)
        "LPVOID": "P",       # Void pointer
        "LPSTR": "P",        # Pointer to a string
        "LPCSTR": "P",       # Pointer to a constant string
        "LPWSTR": "P",       # Pointer to a wide string
        "LPCWSTR": "P",      # Pointer to a constant wide string

        # Unix-specific
        "int8_t": "b",       # Signed 1 byte
        "uint8_t": "B",      # Unsigned 1 byte
        "int16_t": "h",      # Signed 2 bytes
        "uint16_t": "H",     # Unsigned 2 bytes
        "int32_t": "i",      # Signed 4 bytes
        "uint32_t": "I",     # Unsigned 4 bytes
        "int64_t": "q",      # Signed 8 bytes
        "uint64_t": "Q",     # Unsigned 8 bytes
        "pid_t": "i",        # Process ID type
        "off_t": "q",        # File offset type
        "time_t": "q",       # Time type (signed 8 bytes)
        "ssize_t": "q",      # Signed size type
        "size_t": "Q",       # Unsigned size type
        "uid_t": "I",        # User ID
        "gid_t": "I",        # Group ID

        # Pointers
        "void*": "P",        # Generic pointer (platform-dependent)
        "char*": "P",        # Pointer to a character array
        "int*": "P",         # Pointer to an integer
        "float*": "P",       # Pointer to a float
        "double*": "P",      # Pointer to a double
    }

    # Regular expression to match C-style fields
    field_regex = re.compile(r"(\w+)\s+(\w+);")
    struct_format = ""
    fields = []

    # Process the header line by line
    for line in header.splitlines():
        match = field_regex.search(line)
        if match:
            c_type, field_name = match.groups()
            if c_type in type_mapping:
                struct_format += type_mapping[c_type]
                fields.append(field_name)
            else:
                raise ValueError(f"Unknown type: {c_type}")

    # Generate Python code
    python_code = f"""import struct

class EMFHeader:
    format = '{struct_format}'

    def __init__(self, data):
        unpacked = struct.unpack(self.format, data)
        fields = {fields}
        for field, value in zip(fields, unpacked):
            setattr(self, field, value)

    @classmethod
    def from_file(cls, filename):
        with open(filename, 'rb') as f:
            data = f.read(struct.calcsize(cls.format))
            return cls(data)
"""
    return python_code

'''
# Example usage
c_header = """
DWORD   iType;
DWORD   nSize;
RECTL   rclBounds;
RECTL   rclFrame;
DWORD   dSignature;
DWORD   nVersion;
DWORD   nBytes;
DWORD   nRecords;
WORD    nHandles;
WORD    sReserved;
DWORD   nDescription;
DWORD   offDescription;
DWORD   nPalEntries;
SIZEL   szlDevice;
SIZEL   szlMillimeters;
"""
'''
#generated_code = c_header_to_python(c_header)
#print(generated_code)


def gen_header(filename: str) -> None:
    fh = open(filename, "r")
    data = fh.read()
    fh.close()
    print(c_header_to_python(data))
    return

import sys

if __name__=="__main__":
    if len(sys.argv) != 2:
        print("Usage: "+str(sys.argv[0])+" INPUT_C_HEADER_FILE")
        exit(0)
    gen_header(sys.argv[1])
    exit(0)

```

Let's modify this program such that it returns the rest of the data (if not all if it wasn't consumed)...

Here is the final version:

```

import re

def c_header_to_python(header):
    # Mapping of C types to struct format characters
    type_mapping = {
        # Integer types
        "BYTE": "B",         # Unsigned 1 byte
        "CHAR": "b",         # Signed 1 byte
        "UCHAR": "B",        # Unsigned 1 byte
        "SHORT": "h",        # Signed 2 bytes
        "USHORT": "H",       # Unsigned 2 bytes
        "WORD": "H",         # Unsigned 2 bytes (Windows-specific)
        "INT": "i",          # Signed 4 bytes
        "UINT": "I",         # Unsigned 4 bytes
        "LONG": "l",         # Signed 4 bytes
        "ULONG": "L",        # Unsigned 4 bytes
        "DWORD": "I",        # Unsigned 4 bytes (Windows-specific)
        "LONGLONG": "q",     # Signed 8 bytes
        "ULONGLONG": "Q",    # Unsigned 8 bytes
        "SIZE_T": "Q",       # Platform-dependent size type (64-bit here)

        # Floating-point types
        "FLOAT": "f",        # 4 bytes
        "DOUBLE": "d",       # 8 bytes

        # Character types
        "TCHAR": "c",        # 1 character (use Unicode-specific mappings if needed)
        "WCHAR": "H",        # 2 bytes (Unicode character)
        "CHAR16": "H",       # UTF-16 2-byte character
        "CHAR32": "I",       # UTF-32 4-byte character

        # Composite types
        "RECTL": "4i",       # Rectangle (4 signed LONGs)
        "SIZEL": "2i",       # Size (2 signed LONGs)
        "POINTL": "2i",      # Point (2 signed LONGs)
        "RECT": "4i",        # Rectangle structure
        "SIZE": "2i",        # Size structure
        "POINT": "2i",       # Point structure

        # Boolean types
        "BOOL": "I",         # 4 bytes (commonly used in Windows)
        "BOOLEAN": "B",      # 1 byte (commonly used in Unix)

        # Special types
        "HANDLE": "P",       # Pointer to a handle (platform-dependent size)
        "LPVOID": "P",       # Void pointer
        "LPSTR": "P",        # Pointer to a string
        "LPCSTR": "P",       # Pointer to a constant string
        "LPWSTR": "P",       # Pointer to a wide string
        "LPCWSTR": "P",      # Pointer to a constant wide string

        # Unix-specific
        "int8_t": "b",       # Signed 1 byte
        "uint8_t": "B",      # Unsigned 1 byte
        "int16_t": "h",      # Signed 2 bytes
        "uint16_t": "H",     # Unsigned 2 bytes
        "int32_t": "i",      # Signed 4 bytes
        "uint32_t": "I",     # Unsigned 4 bytes
        "int64_t": "q",      # Signed 8 bytes
        "uint64_t": "Q",     # Unsigned 8 bytes
        "pid_t": "i",        # Process ID type
        "off_t": "q",        # File offset type
        "time_t": "q",       # Time type (signed 8 bytes)
        "ssize_t": "q",      # Signed size type
        "size_t": "Q",       # Unsigned size type
        "uid_t": "I",        # User ID
        "gid_t": "I",        # Group ID

        # Pointers
        "void*": "P",        # Generic pointer (platform-dependent)
        "char*": "P",        # Pointer to a character array
        "int*": "P",         # Pointer to an integer
        "float*": "P",       # Pointer to a float
        "double*": "P",      # Pointer to a double
    }

    # Regular expression to match C-style fields
    field_regex = re.compile(r"(\w+)\s+(\w+);")
    struct_format = ""
    fields = []

    # Process the header line by line
    for line in header.splitlines():
        match = field_regex.search(line)
        if match:
            c_type, field_name = match.groups()
            if c_type in type_mapping:
                struct_format += type_mapping[c_type]
                fields.append(field_name)
            else:
                raise ValueError(f"Unknown type: {c_type}")

    # Generate Python code
    '''
    python_code = f"""import struct

class EMFHeader:
    format = '{struct_format}'

    def __init__(self, data):
        unpacked = struct.unpack(self.format, data)
        fields = {fields}
        for field, value in zip(fields, unpacked):
            setattr(self, field, value)

    @classmethod
    def from_file(cls, filename):
        with open(filename, 'rb') as f:
            data = f.read(struct.calcsize(cls.format))
            return cls(data)
"""
    '''

    python_code = f"""import struct

class ParsedHeader:
    format = '{struct_format}'

    def __init__(self, data):
        unpacked = struct.unpack(self.format, data[:struct.calcsize(self.format)])
        fields = {fields}
        for field, value in zip(fields, unpacked):
            setattr(self, field, value)
        self.remaining_data = data[struct.calcsize(self.format):]
        return self.remaining_data # Return the remaining data after reading the header.

    @classmethod
    def from_file(cls, filename):
        with open(filename, 'rb') as f:
            data = f.read()
            return cls(data)

    def __repr__(self):
        fields = {fields}
        parsed_fields = {{field: getattr(self, field) for field in fields}}
        return f"<ParsedHeader {{parsed_fields}}, Remaining: {{len(self.remaining_data)}} bytes>"
"""
    return python_code

'''
# Example usage
c_header = """
DWORD   iType;
DWORD   nSize;
RECTL   rclBounds;
RECTL   rclFrame;
DWORD   dSignature;
DWORD   nVersion;
DWORD   nBytes;
DWORD   nRecords;
WORD    nHandles;
WORD    sReserved;
DWORD   nDescription;
DWORD   offDescription;
DWORD   nPalEntries;
SIZEL   szlDevice;
SIZEL   szlMillimeters;
"""
'''
#generated_code = c_header_to_python(c_header)
#print(generated_code)


def gen_header(filename: str) -> None:
    fh = open(filename, "r")
    data = fh.read()
    fh.close()
    print(c_header_to_python(data))
    return

import sys

if __name__=="__main__":
    if len(sys.argv) != 2:
        print("Usage: "+str(sys.argv[0])+" INPUT_C_HEADER_FILE")
        exit(0)
    gen_header(sys.argv[1])
    exit(0)

```

Here is a program generated from the header:

```



```




Actually here is some bullshit...

4+4+12+12+4+4+4+4+2+2+4+4+4+8+8+4+4+4+8


Here is some bullshit:

```

class ParsedHeader:
    format = 'II4i4iIIIIHHIII2i2iIII2i'

    def __init__(self, data):
        unpacked = struct.unpack(self.format, data[:struct.calcsize(self.format)])
        fields = ['iType', 'nSize', 'rclBounds', 'rclFrame', 'dSignature', 'nVersion', 'nBytes', 'nRecords', 'nHandles', 'sReserved', 'nDescription', 'offDescription', 'nPalEntries', 'szlDevice', 'szlMillimeters', 'cbPixelFormat', 'offPixelFormat', 'bOpenGL', 'szlMicrometers']
        for field, value in zip(fields, unpacked):
            setattr(self, field, value)
        self.remaining_data = data[struct.calcsize(self.format):]
        print("Here is the size thing: "+str(struct.calcsize(self.format)))
        # return self.remaining_data # Return the remaining data after reading the header.

    @classmethod
    def from_file(cls, filename):
        with open(filename, 'rb') as f:
            data = f.read()
            return cls(data)

    def __repr__(self):
        fields = ['iType', 'nSize', 'rclBounds', 'rclFrame', 'dSignature', 'nVersion', 'nBytes', 'nRecords', 'nHandles', 'sReserved', 'nDescription', 'offDescription', 'nPalEntries', 'szlDevice', 'szlMillimeters', 'cbPixelFormat', 'offPixelFormat', 'bOpenGL', 'szlMicrometers']
        parsed_fields = {field: getattr(self, field) for field in fields}
        return f"<ParsedHeader {parsed_fields}, Remaining: {len(self.remaining_data)} bytes>"

```

the fucking thing doesn't work, since the size thing returns 88, but the correct size is 108 .

## Solving some bugs.

Ok, so the python struct library doesn't support unpacking integers of arbitrary size, so instead we need to do some bullshit to get this to work. Let's put the template into a separate file.

Here is the template file:

```

import struct

class ParsedHeader:
    format = 'STRUCT_FORMAT'

    def __init__(self, data):
        unpacked = struct.unpack(self.format, data[:struct.calcsize(self.format)])
        fields = FIELDS
        for field, value in zip(fields, unpacked):
            setattr(self, field, value)
        self.remaining_data = data[struct.calcsize(self.format):]
        print("Here is the size thing: "+str(struct.calcsize(self.format)))
        # return self.remaining_data # Return the remaining data after reading the header.

    @classmethod
    def from_file(cls, filename):
        with open(filename, 'rb') as f:
            data = f.read()
            return cls(data)

    def __repr__(self):
        fields = FIELDS
        parsed_fields = {field: getattr(self, field) for field in fields}
        return f"<ParsedHeader {{parsed_fields}}, Remaining: {{len(self.remaining_data)}} bytes>"

```

Now the problem is that we don't know the sizes of the fields, but we need to know them during mutation, so I think we should make the elements as tuples which the first element is the expected size and the second element is the current value?????? Also we should transform each of these type identifiers to just use bytes, because then we don't need to deal with the signedness issue bullshit and shit like that...


My idea is to just generate the bytes and then just transform the tuple list of byte values to an integer???????????

## Adding serialization

Now in order to fuzz the structures of an EMF file, we also need to program some functionality which serializes the modified object back into binary. This way we can mutate the structures in python.

Something like this?

```

    def serialize(parsed):
        """
        Serializes a Python dictionary representing the structure back into binary data.
        """
        values = [parsed[name] for name, _ in fields]
        return struct.pack(format_string, *values)

```

(Thanks chatgpt)

Actually the serialization is more like:

```

    def serialize(self):
        fields = FIELDS # These are the fields of this object.
        out = b"" # Initialize empty bytes output
        for i, format_string in enumerate(self.format):
            # The corresponding field is fields[i]
            field_name = fields[i]
            field_val = getattr(self, field_name) # Get the actual value of the field from this object.
            # Now try to unpack the integer into the format.
            field_bytes = struct.pack(format_string, field_val)
            out += field_bytes # Add the actual value to the output
        return out # Return the output bytes

```

## Parsing records

Here is a function which tries to parse the rest of the records:

```

def parse_records(record_data):
	# Returns a list of record objects...
	b = record_data # Keep track of the rest of the data
	while b:
		# Unpack type and length.
		assert len(b) >= 8 # Should be atleast 8 bytes for the type and length.
		t_and_l = b[:8]
		# try to unpack the stuff here
		t, l = struct.unpack('<I<I', data) # Unpack two little endian integers.
		rec_bytes = b[:l] # Cutoff at l.
		print("Here are the record bytes: "+str(rec_bytes))
		b = b[l:] # Cutoff the thing
	return

```

Let's take a look at https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-emf/1eec80ba-799b-4784-a9ac-91597d590ae1 and the records and see what kinds of records are in the file...

Here is the output:

```

Here are the record bytes: b'F\x00\x00\x00,\x00\x00\x00 \x00\x00\x00EMF+\x01@\x00\x00\x1c\x00\x00\x00\x10\x00\x00\x00\x02\x10\xc0\xdb\x01\x00\x00\x00`\x00\x00\x00`\x00\x00\x00'
Here are the record bytes: b'F\x00\x00\x00\x14\x01\x00\x00\x08\x01\x00\x00EMF+\x08@\x00\x060\x00\x00\x00$\x00\x00\x00\x02\x10\xc0\xdb\x00\x00 B\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00A\x00R\x00I\x00A\x00L\x00\x00\x00\x08@\x01\x07H\x00\x00\x00<\x00\x00\x00\x02\x10\xc0\xdb\x00\x00\x00\x00\x00\x00\xcb\x85\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xaa*>\xab\xaa*>\n\xd7\x83?\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08@\x02\x01<\x00\x00\x000\x00\x00\x00\x02\x10\xc0\xdb\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8B\x00\x00\xc8B\x00\x00\xff\xff\xff\x00\x00\xff\x00\x00\xff\xff\xff\x00\x00\xff\x1c@\x00\x00P\x00\x00\x00D\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8B\x00\x00\xc8BH\x00e\x00l\x00l\x00o\x00 \x00W\x00o\x00r\x00l\x00d\x00 \x001\x00 \x002\x00 \x003\x00 \x004\x00!\x00'
Here are the record bytes: b'!\x00\x00\x00\x08\x00\x00\x00'
Here are the record bytes: b'b\x00\x00\x00\x0c\x00\x00\x00\x01\x00\x00\x00'
Here are the record bytes: b'L\x00\x00\x00d\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00c\x00\x00\x00`\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00U\x00\x00\x00a\x00\x00\x00)\x00\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80?\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80?\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
Here are the record bytes: b'"\x00\x00\x00\x0c\x00\x00\x00\xff\xff\xff\xff'
Here are the record bytes: b'F\x00\x00\x00\x1c\x00\x00\x00\x10\x00\x00\x00EMF+\x02@\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00'
Here are the record bytes: b'\x0e\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x14\x00\x00\x00'

```

The first record is a comment. See:

```
   EMR_COMMENT = 0x00000046,
```

and `chr(0x46) == 'F'`

Let's take a look at the comment record: "The EMR_COMMENT record contains arbitrary private data." . Welp that's good and all.

Ok, so it just contains some data which isn't needed.

The field starting with "!" is this: `   EMR_SAVEDC = 0x00000021,`

Here: "EMR_SAVEDC: This record saves the current state of the playback device context (section 3.1) in an array of states saved by preceding EMR_SAVEDC records if any."

also: "Note: The EMR_REALIZEPALETTE and EMR_SAVEDC records do not specify parameters"

Let's move on to the next thing. It seems to start with the character "b" : ` EMR_SETICMMODE = 0x00000062,` : `EMR_SETICMMODE: This record specifies the mode of Image Color Management (ICM) for graphics operations.<5>`

```
Image Color Management (ICM): Technology that ensures that a color image, graphic, or text
object is rendered as closely as possible to its original intent on any device despite differences in
imaging technologies and color capabilities between devices.
```

Here is the thing: `2.3.11.14`

Next is the record starting with the character "L" which is `   EMR_BITBLT = 0x0000004C,`

Here:

```
EMR_BITBLT: This record specifies a block transfer of pixels from a source bitmap to a destination
rectangle, optionally in combination with a brush pattern, according to a specified raster
operation.
```

Ok, so ```b'L\x00\x00\x00d\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00c\x00\x00\x00`\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00U\x00\x00\x00a\x00\x00\x00)\x00\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80?\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80?\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'```

is the actual raster command.

Now, going over each type of record will take forever. My plan is to get the pdf or the website and then automatically generate parsers for each record type. This way we don't need to write a parser for each record type manually and we can just use a generic function to mutate the stuff, then we can override some interesting record types to cause some interesting mutations which actually exercise the deep logic inside the EMF parser, not just some surface level parsing logic.

Before doing that, let's manually try to parse this packet.

Here is from the doc:

```

BitBltRasterOperation (4 bytes): An unsigned integer that specifies the raster operation code. This
code defines how the color data of the source rectangle is to be combined with the color data of
the destination rectangle and optionally a brush pattern, to achieve the final color.
This value is in the Ternary Raster Operation enumeration ([MS-WMF] section 2.1.1.31).


```

that section doesn't even exist in the same pdf document.

Here seems to be some documentation: `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wmf/1605dd68-a635-4639-ab81-99ff3e3fc5a3`

Here seems to be our value:

```
D:

Reverse Polish = 00AA0029
```

because we had that but in reverse byteorder:

```
0\x00\x00\x00\x00\x00\x00\x00\x80?\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
EMR_BITBLT
BitmapBuffer: b''
BitBltRasterOperation: 0x2900aa00
```


The "D" value from the documentation seems to mean the destination bitmap.

```
0x2900aa00
```

so 0x29 is the operand index and 0xaa is something else. Let's try to figure out what that something else means...
Yeah, so I don't understand how the algorithm works in the thing. Let's hope that isn't important.

But still, point still stands that writing a custom parser for each record type will take absolutely forever anyway, so we should automatically parse the pdf to generate the parsers.



## Parsing the PDF (or at least trying to)

Now, let's just make an automatic way to parse the pdf.

I have created a github repo for this:

Ok, so I just copy pasted the entire contents of the PDF file to a text file and here is a simple script which checks for the stuff:

```

    # Regular expression to match C-style fields
    # field_regex = re.compile(r"(\w+)\s+(\w+);")
    record_regex = re.compile(r"^\d+\.\d+\.\d+\.\d+ \S+ Record$")


    lines = contents.splitlines()
    line_ind = 0
    in_rec = False

    while True:
        if line_ind == len(lines):
            break
        line = lines[line_ind]

        struct_format = [] # ""
        fields = []

        # Process the header line by line
        #for line in header.splitlines():

        # match = field_regex.search(line)
        if not in_rec: # Not in record yet. Check if we have encountered a record section:
            if record_regex.search(line): # There exists a match
                print("This line has the thing:"+str(line))

        '''
        if match:
            c_type, field_name = match.groups()
            if c_type in type_mapping:
                # struct_format += type_mapping[c_type]
                struct_format.append(type_mapping[c_type])
                fields.append(field_name)
            else:
                raise ValueError(f"Unknown type: {c_type}")

        # Generate python code.

        python_code = gen_python_code(str(struct_format), str(fields))
        return python_code
        '''


        # Increment line counter...
        line_ind += 1

```

it checks for the section stuff on each line and then just reports if a record section is encountered.

Here happens the shit bug:

```

2.3.4.1 EMR_EOF Record
The EMR_EOF record indicates the end of the metafile and specifies a palette.
Fields not specified in this section are specified in section 2.3.4.
0 1 2 3 4 5 6 7 8 9
1
0 1 2 3 4 5 6 7 8 9
2
0 1 2 3 4 5 6 7 8 9
3
0 1
Type
Size
nPalEntries
offPalEntries
PaletteBuffer (variable, optional)
...
SizeLast
Type (4 bytes): An unsigned integer that identifies this record type as EMR_EOF. This value is
0x0000000E.
nPalEntries (4 bytes): An unsigned integer that specifies the number of palette entries.
offPalEntries (4 bytes): An unsigned integer that specifies the offset to the palette entries from the
start of this record.
PaletteBuffer (variable, optional): An array of bytes that contains palette data, which is not
required to be contiguous with the fixed-length portion of the EMR_EOF record. Thus, fields in this
buffer that are labeled "UndefinedSpace" are optional and MUST be ignored.
0 1 2 3 4 5 6 7 8 9
1
0 1 2 3 4 5 6 7 8 9
2
0 1 2 3 4 5 6 7 8 9
3
0 1
UndefinedSpace1 (variable, optional)
...
117 / 282
[MS-EMF] - v20240423
Enhanced Metafile Format
Copyright © 2024 Microsoft Corporation
Release: April 23, 2024
PaletteEntries (variable)
...
UndefinedSpace2 (variable, optional)
...
PaletteEntries (variable): An array of LogPaletteEntry objects (section 2.2.18) that specifies the
palette data.
SizeLast (4 bytes): An unsigned integer that MUST be the same as Size and MUST be the last field
of the record and hence the metafile. LogPaletteEntry objects, if they exist, MUST precede this
field.
See section 2.3.4 for more control record types.
2.3.4.2 EMR_HEADER Record Types
The EMR_HEADER record is the starting point of an EMF metafile. It specifies properties of the
device on which the image in the metafile was recorded; this information in the header record makes
it possible for EMF metafiles to be independent of any specific output device.
The following are the EMR_HEADER record types.
Name Section Description
EmfMetafileHeader 2.3.4.2.1 The original EMF header record.
EmfMetafileHeaderExtension1 2.3.4.2.2 The header record defined in the first extension to EMF, which added
support for OpenGL records and an optional internal pixel format
descriptor.<62>
EmfMetafileHeaderExtension2 2.3.4.2.3 The header record defined in the second extension to EMF, which
added the capability of measuring display dimensions in
micrometers.<63>
EMF metafiles SHOULD be created with an EmfMetafileHeaderExtension2 header record.
The generic structure of EMR_HEADER records is specified as follows.
Fields not specified in this section are specified in section 2.3.4.
0 1 2 3 4 5 6 7 8 9

```

ok so there is also another bug when parsing the variable, optional things. I assumed that all variable fields are marked as "(variable)", but there are also "(variable, optional)" fields...

## Adding some tests

Ok, so let's add a testset for this bullshit...

Let's create a dir called testfiles

I also added this utility function which takes a hexdump and outputs bytes:

```

def parse_hex_dump(hex_dump): # This parses an xxd -g 1 style hex dump and returns a "bytes" object which corresponds to that hexdump.
	ls = hex_dump.splitlines() # Each line.
	o = b"" # Init output.
	for l in ls:
		assert ":" in l
		l = l[l.index(":")+1:]
		bs = l.split(" ")
		print(bs)
		for b in bs:
			if not b: # Empty string? (This can be caused by spaces in the front and end)
				continue
			i = int(b, base=16)
			assert 0 <= i <= 255 # Should represent single byte
			o += bytes([i])
	return o

```

This can be used to take examples from the spec and then using in them in tests etc etc...

Let's fixup the thing

Ok, so I think we have an automatic parser.

## Continuing the actual mutator.


Ok, so let's keep on going with the actual mutator.

Now first of all we need a way to lookup the record type from our autogenerated library. I think this can just be done with using the enum which enums the fucking record types...

Here is the enum thing:

```

typedef enum
{
 EMR_HEADER = 0x00000001,
 EMR_POLYBEZIER = 0x00000002,
 EMR_POLYGON = 0x00000003,
 EMR_POLYLINE = 0x00000004,
 EMR_POLYBEZIERTO = 0x00000005,
 EMR_POLYLINETO = 0x00000006,
 EMR_POLYPOLYLINE = 0x00000007,
 EMR_POLYPOLYGON = 0x00000008,
 EMR_SETWINDOWEXTEX = 0x00000009,
 EMR_SETWINDOWORGEX = 0x0000000A,
 EMR_SETVIEWPORTEXTEX = 0x0000000B,
 EMR_SETVIEWPORTORGEX = 0x0000000C,
 EMR_SETBRUSHORGEX = 0x0000000D,
 EMR_EOF = 0x0000000E,
 EMR_SETPIXELV = 0x0000000F,
 EMR_SETMAPPERFLAGS = 0x00000010,
 EMR_SETMAPMODE = 0x00000011,
 EMR_SETBKMODE = 0x00000012,
 EMR_SETPOLYFILLMODE = 0x00000013,
 EMR_SETROP2 = 0x00000014,
 EMR_SETSTRETCHBLTMODE = 0x00000015,
 EMR_SETTEXTALIGN = 0x00000016,
 EMR_SETCOLORADJUSTMENT = 0x00000017,
 EMR_SETTEXTCOLOR = 0x00000018,
 EMR_SETBKCOLOR = 0x00000019,
 EMR_OFFSETCLIPRGN = 0x0000001A,
 EMR_MOVETOEX = 0x0000001B,
 EMR_SETMETARGN = 0x0000001C,
 EMR_EXCLUDECLIPRECT = 0x0000001D,
 EMR_INTERSECTCLIPRECT = 0x0000001E,
 EMR_SCALEVIEWPORTEXTEX = 0x0000001F,
 EMR_SCALEWINDOWEXTEX = 0x00000020,
 EMR_SAVEDC = 0x00000021,
 EMR_RESTOREDC = 0x00000022,
 EMR_SETWORLDTRANSFORM = 0x00000023,
 EMR_MODIFYWORLDTRANSFORM = 0x00000024,
 EMR_SELECTOBJECT = 0x00000025,
 EMR_CREATEPEN = 0x00000026,
 EMR_CREATEBRUSHINDIRECT = 0x00000027,
 EMR_DELETEOBJECT = 0x00000028,
 EMR_ANGLEARC = 0x00000029,
 EMR_ELLIPSE = 0x0000002A,
 EMR_RECTANGLE = 0x0000002B,
 EMR_ROUNDRECT = 0x0000002C,
 EMR_ARC = 0x0000002D,
 EMR_CHORD = 0x0000002E,
 EMR_PIE = 0x0000002F,
 EMR_SELECTPALETTE = 0x00000030,
 EMR_CREATEPALETTE = 0x00000031,
 EMR_SETPALETTEENTRIES = 0x00000032,
 EMR_RESIZEPALETTE = 0x00000033,
 EMR_REALIZEPALETTE = 0x00000034,
 EMR_EXTFLOODFILL = 0x00000035,
 EMR_LINETO = 0x00000036,
 EMR_ARCTO = 0x00000037,
 EMR_POLYDRAW = 0x00000038,
 EMR_SETARCDIRECTION = 0x00000039,
 EMR_SETMITERLIMIT = 0x0000003A,
 EMR_BEGINPATH = 0x0000003B,
 EMR_ENDPATH = 0x0000003C,
 EMR_CLOSEFIGURE = 0x0000003D,
 EMR_FILLPATH = 0x0000003E,
 EMR_STROKEANDFILLPATH = 0x0000003F,
 EMR_STROKEPATH = 0x00000040,
 EMR_FLATTENPATH = 0x00000041,
 EMR_WIDENPATH = 0x00000042,
 EMR_SELECTCLIPPATH = 0x00000043,
 EMR_ABORTPATH = 0x00000044,
 EMR_COMMENT = 0x00000046,
 EMR_FILLRGN = 0x00000047,
 EMR_FRAMERGN = 0x00000048,
 EMR_INVERTRGN = 0x00000049,
 EMR_PAINTRGN = 0x0000004A,
 EMR_EXTSELECTCLIPRGN = 0x0000004B,
 EMR_BITBLT = 0x0000004C,
 EMR_STRETCHBLT = 0x0000004D,
 EMR_MASKBLT = 0x0000004E,
 EMR_PLGBLT = 0x0000004F,
 EMR_SETDIBITSTODEVICE = 0x00000050,
 EMR_STRETCHDIBITS = 0x00000051,
 EMR_EXTCREATEFONTINDIRECTW = 0x00000052,
 EMR_EXTTEXTOUTA = 0x00000053,
 EMR_EXTTEXTOUTW = 0x00000054,
 EMR_POLYBEZIER16 = 0x00000055,
 EMR_POLYGON16 = 0x00000056,
 EMR_POLYLINE16 = 0x00000057,
 EMR_POLYBEZIERTO16 = 0x00000058,
 EMR_POLYLINETO16 = 0x00000059,
 EMR_POLYPOLYLINE16 = 0x0000005A,
 EMR_POLYPOLYGON16 = 0x0000005B,
 EMR_POLYDRAW16 = 0x0000005C,
 EMR_CREATEMONOBRUSH = 0x0000005D,
 EMR_CREATEDIBPATTERNBRUSHPT = 0x0000005E,
 EMR_EXTCREATEPEN = 0x0000005F,
 EMR_POLYTEXTOUTA = 0x00000060,
 EMR_POLYTEXTOUTW = 0x00000061,
 EMR_SETICMMODE = 0x00000062,
 EMR_CREATECOLORSPACE = 0x00000063,
 EMR_SETCOLORSPACE = 0x00000064,
 EMR_DELETECOLORSPACE = 0x00000065,
 EMR_GLSRECORD = 0x00000066,
 EMR_GLSBOUNDEDRECORD = 0x00000067,
 EMR_PIXELFORMAT = 0x00000068,
 EMR_DRAWESCAPE = 0x00000069,
 EMR_EXTESCAPE = 0x0000006A,
 EMR_SMALLTEXTOUT = 0x0000006C,
 EMR_FORCEUFIMAPPING = 0x0000006D,
 EMR_NAMEDESCAPE = 0x0000006E,
 EMR_COLORCORRECTPALETTE = 0x0000006F,
 EMR_SETICMPROFILEA = 0x00000070,
 EMR_SETICMPROFILEW = 0x00000071,
 EMR_ALPHABLEND = 0x00000072,
 EMR_SETLAYOUT = 0x00000073,
 EMR_TRANSPARENTBLT = 0x00000074,
 EMR_GRADIENTFILL = 0x00000076,
 EMR_SETLINKEDUFIS = 0x00000077,
 EMR_SETTEXTJUSTIFICATION = 0x00000078,
 EMR_COLORMATCHTOTARGETW = 0x00000079,
 EMR_CREATECOLORSPACEW = 0x0000007A
} RecordType;


```

My idea is to parse the file as an object.

Let's create a file called emf_file.py which specifies the class which is an object representation of the file. My idea is to just have it and then have a records attribute which contains the records and a serialization function which then serializes the object back into the file....

Maybe something like this?

```





import copy
import struct


def read_bytes(buffer, n): # Cuts first n bytes from buffer. Returns tuple where first element is the cut bytes and second element is the rest of the data.
	return buffer[:n], buffer[n:]

def parse_records(record_data):
	# Returns a list of record objects...
	b = record_data # Keep track of the rest of the data
	while b:
		# Unpack type and length.
		assert len(b) >= 8 # Should be atleast 8 bytes for the type and length.
		t_and_l = b[:8]
		# try to unpack the stuff here
		t, l = struct.unpack('II', t_and_l) # Unpack two little endian integers.
		rec_bytes = b[:l] # Cutoff at l.
		print("Here are the record bytes: "+str(rec_bytes))
		#print(t == 0x0000004C)
		if TEST and t == 0x0000004C: # EMR_BITBLT record
			print("EMR_BITBLT")
			stuff = copy.deepcopy(rec_bytes)
			_, stuff = read_bytes(stuff, 4) # Skip type
			_, stuff = read_bytes(stuff, 4) # Skip length
			bounds, stuff = read_bytes(stuff, 16) # Bounds which is a RectL object.
			xDest, stuff = read_bytes(stuff, 4) # xDest
			yDest, stuff = read_bytes(stuff, 4) # yDest

			cxDest, stuff = read_bytes(stuff, 4) # cxDest
			cyDest, stuff = read_bytes(stuff, 4) # cyDest

			# BitBltRasterOperation
			BitBltRasterOperation, stuff = read_bytes(stuff, 4) # cyDest

			xSrc, stuff = read_bytes(stuff, 4) # xSrc
			ySrc, stuff = read_bytes(stuff, 4) # ySrc

			# XformSrc
			xSrc, stuff = read_bytes(stuff, 24) #  An XForm object (section 2.2.28) that specifies a world-space to pagespace transform to apply to the source bitmap.

			BkColorSrc, stuff = read_bytes(stuff, 4) # BkColorSrc
			# UsageSrc
			UsageSrc, stuff = read_bytes(stuff, 4) # UsageSrc
			offBmiSrc, stuff = read_bytes(stuff, 4) # offBmiSrc

			cbBmiSrc, stuff = read_bytes(stuff, 4) # cbBmiSrc

			offBitsSrc, stuff = read_bytes(stuff, 4) # offBitsSrc
			cbBitsSrc, stuff = read_bytes(stuff, 4) # cbBitsSrc
			#cbBitsSrc, stuff = read_bytes(stuff, 4)
			BitmapBuffer = stuff # This should be rest of the stuff.
			print("BitmapBuffer: "+str(BitmapBuffer))
			BitBltRasterOperation = int.from_bytes(BitBltRasterOperation)# struct.unpack("I", BitBltRasterOperation)
			print("BitBltRasterOperation: "+str(hex(BitBltRasterOperation)))
			print("Done!!!"*100)

		b = b[l:] # Cutoff the thing
	return



class EMFFile:
	def __init__(self, h, recs, orig_data): # Initialization function
		self.h = h # Header.
		self.records = recs # Records
		self.mutated = False # Has been mutated?

	def serialize(self): # Serialize data back.


def parse_emf_file(data):
	h, rest_of_data = parse_header(data)
	# Now try to parse the records
	records = parse_records(rest_of_data) # Try to parse the records from the data.
	obj = EMFFile(h, records, copy.deepcopy(data))

	return obj


```

Now we want to make a design decision, do we want to modify the Size fields in the record objects themselves or do we want to just modify the "Size" field in the mutation function?????

I think the way to do this is just to modify the Size field in the mutation function....

We also want the names of the stuff.

So here is the stuff:

```


EMR_HEADER = 0x00000001
EMR_POLYBEZIER = 0x00000002
EMR_POLYGON = 0x00000003
EMR_POLYLINE = 0x00000004
EMR_POLYBEZIERTO = 0x00000005
EMR_POLYLINETO = 0x00000006
EMR_POLYPOLYLINE = 0x00000007
EMR_POLYPOLYGON = 0x00000008
EMR_SETWINDOWEXTEX = 0x00000009
EMR_SETWINDOWORGEX = 0x0000000A
EMR_SETVIEWPORTEXTEX = 0x0000000B
EMR_SETVIEWPORTORGEX = 0x0000000C
EMR_SETBRUSHORGEX = 0x0000000D
EMR_EOF = 0x0000000E
EMR_SETPIXELV = 0x0000000F
EMR_SETMAPPERFLAGS = 0x00000010
EMR_SETMAPMODE = 0x00000011
EMR_SETBKMODE = 0x00000012
EMR_SETPOLYFILLMODE = 0x00000013
EMR_SETROP2 = 0x00000014
EMR_SETSTRETCHBLTMODE = 0x00000015
EMR_SETTEXTALIGN = 0x00000016
EMR_SETCOLORADJUSTMENT = 0x00000017
EMR_SETTEXTCOLOR = 0x00000018
EMR_SETBKCOLOR = 0x00000019
EMR_OFFSETCLIPRGN = 0x0000001A
EMR_MOVETOEX = 0x0000001B
EMR_SETMETARGN = 0x0000001C
EMR_EXCLUDECLIPRECT = 0x0000001D
EMR_INTERSECTCLIPRECT = 0x0000001E
EMR_SCALEVIEWPORTEXTEX = 0x0000001F
EMR_SCALEWINDOWEXTEX = 0x00000020
EMR_SAVEDC = 0x00000021
EMR_RESTOREDC = 0x00000022
EMR_SETWORLDTRANSFORM = 0x00000023
EMR_MODIFYWORLDTRANSFORM = 0x00000024
EMR_SELECTOBJECT = 0x00000025
EMR_CREATEPEN = 0x00000026
EMR_CREATEBRUSHINDIRECT = 0x00000027
EMR_DELETEOBJECT = 0x00000028
EMR_ANGLEARC = 0x00000029
EMR_ELLIPSE = 0x0000002A
EMR_RECTANGLE = 0x0000002B
EMR_ROUNDRECT = 0x0000002C
EMR_ARC = 0x0000002D
EMR_CHORD = 0x0000002E
EMR_PIE = 0x0000002F
EMR_SELECTPALETTE = 0x00000030
EMR_CREATEPALETTE = 0x00000031
EMR_SETPALETTEENTRIES = 0x00000032
EMR_RESIZEPALETTE = 0x00000033
EMR_REALIZEPALETTE = 0x00000034
EMR_EXTFLOODFILL = 0x00000035
EMR_LINETO = 0x00000036
EMR_ARCTO = 0x00000037
EMR_POLYDRAW = 0x00000038
EMR_SETARCDIRECTION = 0x00000039
EMR_SETMITERLIMIT = 0x0000003A
EMR_BEGINPATH = 0x0000003B
EMR_ENDPATH = 0x0000003C
EMR_CLOSEFIGURE = 0x0000003D
EMR_FILLPATH = 0x0000003E
EMR_STROKEANDFILLPATH = 0x0000003F
EMR_STROKEPATH = 0x00000040
EMR_FLATTENPATH = 0x00000041
EMR_WIDENPATH = 0x00000042
EMR_SELECTCLIPPATH = 0x00000043
EMR_ABORTPATH = 0x00000044
EMR_COMMENT = 0x00000046
EMR_FILLRGN = 0x00000047
EMR_FRAMERGN = 0x00000048
EMR_INVERTRGN = 0x00000049
EMR_PAINTRGN = 0x0000004A
EMR_EXTSELECTCLIPRGN = 0x0000004B
EMR_BITBLT = 0x0000004C
EMR_STRETCHBLT = 0x0000004D
EMR_MASKBLT = 0x0000004E
EMR_PLGBLT = 0x0000004F
EMR_SETDIBITSTODEVICE = 0x00000050
EMR_STRETCHDIBITS = 0x00000051
EMR_EXTCREATEFONTINDIRECTW = 0x00000052
EMR_EXTTEXTOUTA = 0x00000053
EMR_EXTTEXTOUTW = 0x00000054
EMR_POLYBEZIER16 = 0x00000055
EMR_POLYGON16 = 0x00000056
EMR_POLYLINE16 = 0x00000057
EMR_POLYBEZIERTO16 = 0x00000058
EMR_POLYLINETO16 = 0x00000059
EMR_POLYPOLYLINE16 = 0x0000005A
EMR_POLYPOLYGON16 = 0x0000005B
EMR_POLYDRAW16 = 0x0000005C
EMR_CREATEMONOBRUSH = 0x0000005D
EMR_CREATEDIBPATTERNBRUSHPT = 0x0000005E
EMR_EXTCREATEPEN = 0x0000005F
EMR_POLYTEXTOUTA = 0x00000060
EMR_POLYTEXTOUTW = 0x00000061
EMR_SETICMMODE = 0x00000062
EMR_CREATECOLORSPACE = 0x00000063
EMR_SETCOLORSPACE = 0x00000064
EMR_DELETECOLORSPACE = 0x00000065
EMR_GLSRECORD = 0x00000066
EMR_GLSBOUNDEDRECORD = 0x00000067
EMR_PIXELFORMAT = 0x00000068
EMR_DRAWESCAPE = 0x00000069
EMR_EXTESCAPE = 0x0000006A
EMR_SMALLTEXTOUT = 0x0000006C
EMR_FORCEUFIMAPPING = 0x0000006D
EMR_NAMEDESCAPE = 0x0000006E
EMR_COLORCORRECTPALETTE = 0x0000006F
EMR_SETICMPROFILEA = 0x00000070
EMR_SETICMPROFILEW = 0x00000071
EMR_ALPHABLEND = 0x00000072
EMR_SETLAYOUT = 0x00000073
EMR_TRANSPARENTBLT = 0x00000074
EMR_GRADIENTFILL = 0x00000076
EMR_SETLINKEDUFIS = 0x00000077
EMR_SETTEXTJUSTIFICATION = 0x00000078
EMR_COLORMATCHTOTARGETW = 0x00000079
EMR_CREATECOLORSPACEW = 0x0000007A
```


we also want a dictionary where the key is the integer and the key is actually the string "EMR_COMMENT" etc etc.. I think we can do that by just: `reverse_dict = {value: key for key, value in globals().items() if isinstance(value, int)}` thanks chatgpt!!!!!!

Something like this?????

```


def lookup_emr_record_class(t): # This returns the class name of the record object which corresponds to record type t.
	return getattr(autogenerated, EMR_NAMES[t]) # autogenerated

def parse_records(record_data):
	# Returns a list of record objects...
	b = record_data # Keep track of the rest of the data
	record_objects = []
	while b:
		# Unpack type and length.
		assert len(b) >= 8 # Should be atleast 8 bytes for the type and length.
		t_and_l = b[:8]
		# try to unpack the stuff here
		t, l = struct.unpack('II', t_and_l) # Unpack two little endian integers.
		rec_bytes = b[:l] # Cutoff at l.
		print("Here are the record bytes: "+str(rec_bytes))
		#print(t == 0x0000004C)
		if TEST and t == 0x0000004C: # EMR_BITBLT record
			print("EMR_BITBLT")
			stuff = copy.deepcopy(rec_bytes)
			_, stuff = read_bytes(stuff, 4) # Skip type
			_, stuff = read_bytes(stuff, 4) # Skip length
			bounds, stuff = read_bytes(stuff, 16) # Bounds which is a RectL object.
			xDest, stuff = read_bytes(stuff, 4) # xDest
			yDest, stuff = read_bytes(stuff, 4) # yDest

			cxDest, stuff = read_bytes(stuff, 4) # cxDest
			cyDest, stuff = read_bytes(stuff, 4) # cyDest

			# BitBltRasterOperation
			BitBltRasterOperation, stuff = read_bytes(stuff, 4) # cyDest

			xSrc, stuff = read_bytes(stuff, 4) # xSrc
			ySrc, stuff = read_bytes(stuff, 4) # ySrc

			# XformSrc
			xSrc, stuff = read_bytes(stuff, 24) #  An XForm object (section 2.2.28) that specifies a world-space to pagespace transform to apply to the source bitmap.

			BkColorSrc, stuff = read_bytes(stuff, 4) # BkColorSrc
			# UsageSrc
			UsageSrc, stuff = read_bytes(stuff, 4) # UsageSrc
			offBmiSrc, stuff = read_bytes(stuff, 4) # offBmiSrc

			cbBmiSrc, stuff = read_bytes(stuff, 4) # cbBmiSrc

			offBitsSrc, stuff = read_bytes(stuff, 4) # offBitsSrc
			cbBitsSrc, stuff = read_bytes(stuff, 4) # cbBitsSrc
			#cbBitsSrc, stuff = read_bytes(stuff, 4)
			BitmapBuffer = stuff # This should be rest of the stuff.
			print("BitmapBuffer: "+str(BitmapBuffer))
			BitBltRasterOperation = int.from_bytes(BitBltRasterOperation)# struct.unpack("I", BitBltRasterOperation)
			print("BitBltRasterOperation: "+str(hex(BitBltRasterOperation)))
			print("Done!!!"*100)
		c = lookup_emr_record_class(t)
		# Now actually initialize the object.
		rec = c(rec_bytes)
		b = b[l:] # Cutoff the thing
	return


```

This almost works, but the problem is that there are records which aren't actually in the PDF file in the usual format. Fuck!!!

```

[]
Here is the size thing: 0
Here are the record bytes: b'!\x00\x00\x00\x08\x00\x00\x00'
Traceback (most recent call last):
  File "/home/oof/emf_parser/parser.py", line 83, in <module>
    test_parser()
  File "/home/oof/emf_parser/parser.py", line 79, in test_parser
    emf_obj = parse_emf_file(data)
              ^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_parser/emf_file.py", line 93, in parse_emf_file
    records = parse_records(rest_of_data) # Try to parse the records from the data.
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_parser/emf_file.py", line 72, in parse_records
    c = lookup_emr_record_class(t)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_parser/emf_file.py", line 21, in lookup_emr_record_class
    return getattr(autogenerated, EMR_NAMES[t]) # autogenerated
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AttributeError: module 'autogenerated' has no attribute 'EMR_SAVEDC'

```


So I think we need to fucking add some records manually. This is complete dogshit imo...

Here is another bug:

```

unpacked:
[(34, 0, 0, 0), (12, 0, 0, 0), (-1, -1, -1, -1)]
value == (34, 0, 0, 0)
value == (12, 0, 0, 0)
value == (-1, -1, -1, -1)
Here is the size thing: 12
Here are the record bytes: b'F\x00\x00\x00\x1c\x00\x00\x00\x10\x00\x00\x00EMF+\x02@\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00'
unpacked:
[]
Here is the size thing: 0
Here are the record bytes: b'\x0e\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x14\x00\x00\x00'
Traceback (most recent call last):
  File "/home/oof/emf_parser/parser.py", line 83, in <module>
    test_parser()
  File "/home/oof/emf_parser/parser.py", line 79, in test_parser
    emf_obj = parse_emf_file(data)
              ^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_parser/emf_file.py", line 93, in parse_emf_file
    records = parse_records(rest_of_data) # Try to parse the records from the data.
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_parser/emf_file.py", line 72, in parse_records
    c = lookup_emr_record_class(t)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_parser/emf_file.py", line 21, in lookup_emr_record_class
    return getattr(autogenerated, EMR_NAMES[t]) # autogenerated
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AttributeError: module 'autogenerated' has no attribute 'EMR_EOF'

```

Here is my current record generation code:

```

def spec_to_python(contents):
    global has_start
    if not has_start:
        fh = open("output.py", "a")
        fh.write('''import struct

def to_unsigned(byte_integer: int) -> int: # Converts a signed integer in a single byte to an unsigned integer.
    # assert byte_integer >= 0 and byte_integer <= 255
    assert byte_integer >= -128 and byte_integer <= 127
    if byte_integer < 0:
        byte_integer += 256
    return byte_integer
''')
        fh.write("\n\n")
        fh.close()
        has_start = True
    # field_regex = re.compile(r"(\w+)\s+(\w+);")
    record_regex = re.compile(r"^\d+\.\d+\.\d+\.\d+ \S+ Record$")
    bytes_field_regex = re.compile(r'\w+\s\(\d+\sbytes\):') # This is for fixed length fields...
    variable_field_regex = re.compile(r'\w+\s\(variable\):') # This is for fixed length fields...

    lines = contents.splitlines()
    line_ind = 0
    in_rec = False

    has_variable = False # This signifies if the record type has variable field at the end of it...
    name_of_rec = None
    struct_format = [] # ""
    fields = []

    # This part doesn't work for "2.3.4.2 EMR_HEADER Record Types" because reasons...

    output = "" # Final output code...


    while True:

        if line_ind == len(lines):
            code = gen_python_code(str(struct_format), str(fields), name_of_rec, str(has_variable))
            save_code(code)
            output += code + "\n\n" # Add a couple of newlines just to be safe
            break
        line = lines[line_ind]
        tok = line.split(" ")
        if line == "3 Structure Examples":
            code = gen_python_code(str(struct_format), str(fields), name_of_rec, str(has_variable))
            save_code(code)
            output += code + "\n\n" # Add a couple of newlines just to be safe
            break

        name = None
        # Process the header line by line
        #for line in header.splitlines():

        # match = field_regex.search(line)
        if not in_rec: # Not in record yet. Check if we have encountered a record section:
            if record_regex.search(line): # There exists a match
                # print("This line has the thing:"+str(line))
                in_rec = True
                name_of_rec = tok[-2] # Second last.
                # print("Name of rec: "+str(name_of_rec))

        else: # In record..., therefore check if the thing has a field in it.
            if record_regex.search(line): # There exists a match
                # We have encountered a new record type. Save the old one as a parser and be done with it.
                # print("oof")
                # Save the shit here..
                # print("Name of reeeeeeeeeeec: "+str(name_of_rec))
                # assert False
                code = gen_python_code(str(struct_format), str(fields), name_of_rec, str(has_variable))
                output += code + "\n\n" # Add a couple of newlines just to be safe
                # print("output shit: "+str(output))
                save_code(code)
                name_of_rec = tok[-2] # Second last.
                struct_format = [] # ""
                fields = []
                has_variable = False
                # print("Name of rec: "+str(name_of_rec))

            elif len(line) >= len("2.3.4.2") and line[1] == "." and line[3] == "." and line[5] == "." and "Record Types" in line: # This is to fix the bug in the parser when it encounters "2.3.4.2 EMR_HEADER Record Types"
                print("Not in record.")
                print("Previous record name: "+str(name_of_rec))
                in_rec = False


                # Maybe this bullshit here?????
                code = gen_python_code(str(struct_format), str(fields), name_of_rec, str(has_variable))
                output += code + "\n\n" # Add a couple of newlines just to be safe
                # print("output shit: "+str(output))
                save_code(code)
                name_of_rec = tok[-2] # Second last.
                struct_format = [] # ""
                fields = []
                has_variable = False


            else:
                # Checks for the type line.
                if bytes_field_regex.search(line):
                    # A fixed length field.

                    length = int(tok[1][1:])
                    # print("Length: "+str(length))
                    struct_format.append(str(length)+"b") # b for bytes.
                    # print("Here is a field: "+str(tok[0]))
                    fields.append(tok[0])
                elif variable_field_regex.search(line):
                    has_variable = True # Add variable stuff.

        '''
        if match:
            c_type, field_name = match.groups()
            if c_type in type_mapping:
                # struct_format += type_mapping[c_type]
                struct_format.append(type_mapping[c_type])
                fields.append(field_name)
            else:
                raise ValueError(f"Unknown type: {c_type}")

        # Generate python code.

        python_code = gen_python_code(str(struct_format), str(fields))
        return python_code
        '''


        # Increment line counter...
        line_ind += 1
    return output

```


Ok, so now we can create the record objects from the data I think. Now we need to program a serialization function for our EMFFile object:

```


class EMFFile:
	def __init__(self, h, recs, orig_data): # Initialization function
		self.h = h # Header.
		self.records = recs # Records
		self.mutated = False # Has been mutated?

	def serialize(self): # Serialize data back.
		# First serialize all of the record objects... we can not use orig_data because the object may have been mutated or changed.



		return


```

I think the best way to do this is to just first serialize each record and then after this add the header and fix up all the lengths etc etc...

Also in addition I think we need to keep track of the variable data at the end in each record object.

Let's modify our template.

```


class EMFFile:
	def __init__(self, h, recs, orig_data): # Initialization function
		self.h = h # Header.
		self.records = recs # Records
		self.mutated = False # Has been mutated?

	def serialize(self): # Serialize data back.
		# First serialize all of the record objects... we can not use orig_data because the object may have been mutated or changed.



		return


```

Here is our current template for the EMR record:

```

class NAME:
    format = STRUCT_FORMAT
    name = "NAME"
    has_variable = HAS_VARIABLE
    fields = FIELDS # These are the fields of this object.
    variable_data = None
    def __init__(self, data):
        unpacked = []
        for f in self.format:
            unpacked.append(struct.unpack(f, data[:struct.calcsize(f)]))
            data = data[struct.calcsize(f):]
        print("unpacked: ")
        print(unpacked)
        for field, value in zip(self.fields, unpacked):
            print("value == "+str(value))
            if isinstance(value, tuple): # This is a multibyte value.
                # Should be integers all
                # Convert to unsigned bytes...
                value = [to_unsigned(x) for x in value]
                assert all([x >= 0 and x <= 255 for x in value]) # Should be integers representing single bytes.
                # Make a list and then just use bytes
                b = bytes(value)
                # Now make the integer...
                # int.from_bytes(byte_data, byteorder='little')
                integer = int.from_bytes(b, byteorder='little')
                setattr(self, field, (len(b), integer))
            else:
                value = to_unsigned(value)
                assert value >= 0 and value <= 255
                setattr(self, field, (1, value)) # Size of one byte
        self.remaining_data = data[struct.calcsize("".join(self.format)):]
        print("Here is the size thing: "+str(struct.calcsize("".join(self.format))))
        # return self.remaining_data # Return the remaining data after reading the header.
        # Sanity checking. If the record doesn't have variable fields, then all of the data should be consumed. Otherwise this is an error condition.
        if not self.has_variable and self.remaining_data: # There is left over data even though record should not be variable.
            assert False
        if self.has_variable:
            # Set the variable data.
            self.variable_data = self.remaining_data # The variable data should be the data at the end. This actually may be b"" for optional fields...


    @classmethod
    def from_file(cls, filename):
        with open(filename, 'rb') as f:
            data = f.read()
            return cls(data)

    def __repr__(self):
        parsed_fields = {field: getattr(self, field) for field in self.fields}
        return f"<NAME {parsed_fields}, Remaining: {len(self.remaining_data)} bytes>"

    def serialize(self):
        out = b"" # Initialize empty bytes output
        for i, format_string in enumerate(self.format):
            # The corresponding field is fields[i]
            field_name = self.fields[i]
            field_val = getattr(self, field_name) # Get the actual value of the field from this object.
            field_length = field_val[0]
            field_integer = field_val[1]
            # Now try to unpack the integer into the format.
            # field_bytes = struct.pack(format_string, field_val)
            field_bytes = field_integer.to_bytes(field_length, byteorder='little') # num.to_bytes(4, byteorder='little')
            out += field_bytes # Add the actual value to the output
        return out # Return the output bytes




```

We also need to add some sanity checking to the serialization function and we also should add the variable data shit to the serialization stuff...

Here is the serialization function:

```

    def serialize(self):
        out = b"" # Initialize empty bytes output
        for i, format_string in enumerate(self.format):
            # The corresponding field is fields[i]
            field_name = self.fields[i]
            field_val = getattr(self, field_name) # Get the actual value of the field from this object.
            field_length = field_val[0]
            field_integer = field_val[1]
            # Now try to unpack the integer into the format.
            # field_bytes = struct.pack(format_string, field_val)
            field_bytes = field_integer.to_bytes(field_length, byteorder='little') # num.to_bytes(4, byteorder='little')
            out += field_bytes # Add the actual value to the output
        if self.has_variable:
            # Add variable data to the end.
            out += self.variable_data
        # Sanity checking. The "Size" field should actually match the size upon serialization. If not, then the mutator did not take care of the size correctly and there is a bug in the mutator.
        assert self.Size == len(out)
        return out # Return the output bytes

```

there is also some jankiness going on with the Size and Type fields, because in the spec, sometimes they are explicitly stated when as during other times, they are omitted from the listing in the format our autogenerator expects. This basically causes there to sometimes be a Type field and sometimes not and same with Size, so let's also fix this in the autogenerator....

Here is my current autogenerator:

```


import re
import os

# This code is based on an earlier implementation of a thing.

has_start = False

def fixup_stuff(struct_format, fields): # This looks at the struct format and fields and sees if there is the Type or Size field and then puts them at the start.
    struct_format = eval(struct_format) # Obvious possible command injection, but idc
    fields = eval(fields) # Same here too.

    assert isinstance(struct_format, list)
    assert isinstance(fields, list)

    assert len(struct_format) == len(fields)

    if "Type" in fields:
        # Remove the Type and the corresponding struct thing
        ind = fields.index("Type")
        # Remove.
        fields.pop(ind)
        struct_format.pop(ind)
    # Do the same for "Size"
    if "Size" in fields:
        # Remove the Type and the corresponding struct thing
        ind = fields.index("Size")
        # Remove.
        fields.pop(ind)
        struct_format.pop(ind)

    assert len(struct_format) == len(fields)
    assert "Size" not in fields and "Type" not in fields
    # Now add them to the start, since each record is guaranteed to have these fields at the start.
    fields = ["Type", "Size"] + fields # Add the two stuff.
    struct_format = ["4b", "4b"] + struct_format # Add the two integer fields


    return str(struct_format), str(fields)

def gen_python_code(struct_format, fields, name, has_variable):
    fh = open("template.py", "r")
    data = fh.read()
    fh.close()
    #
    assert fields != "[]" or has_variable
    #assert fields != [] or has_variable
    # STRUCT_FORMAT is struct_format and FIELDS is fields in the template.

    struct_format, fields = fixup_stuff(struct_format, fields)

    data = data.replace("STRUCT_FORMAT", struct_format)
    data = data.replace("FIELDS", fields)
    data = data.replace("NAME", name)
    data = data.replace("HAS_VARIABLE", has_variable)
    return data

def save_code(code_string):
    fh = open("output.py", "a")
    fh.write(code_string)
    fh.write("\n\n\n") # Add a bit of this.
    fh.close()

def spec_to_python(contents):
    global has_start
    if not has_start:
        fh = open("output.py", "a")
        fh.write('''import struct

def to_unsigned(byte_integer: int) -> int: # Converts a signed integer in a single byte to an unsigned integer.
    # assert byte_integer >= 0 and byte_integer <= 255
    assert byte_integer >= -128 and byte_integer <= 127
    if byte_integer < 0:
        byte_integer += 256
    return byte_integer
''')
        fh.write("\n\n")
        fh.close()
        has_start = True
    # field_regex = re.compile(r"(\w+)\s+(\w+);")
    record_regex = re.compile(r"^\d+\.\d+\.\d+\.\d+ \S+ Record$")
    bytes_field_regex = re.compile(r'\w+\s\(\d+\sbytes\):') # This is for fixed length fields...
    variable_field_regex = re.compile(r'\w+\s\(variable\):') # This is for fixed length fields...

    lines = contents.splitlines()
    line_ind = 0
    in_rec = False

    has_variable = False # This signifies if the record type has variable field at the end of it...
    name_of_rec = None
    struct_format = [] # ""
    fields = []

    # This part doesn't work for "2.3.4.2 EMR_HEADER Record Types" because reasons...

    output = "" # Final output code...


    while True:

        if line_ind == len(lines):
            code = gen_python_code(str(struct_format), str(fields), name_of_rec, str(has_variable))
            save_code(code)
            output += code + "\n\n" # Add a couple of newlines just to be safe
            break
        line = lines[line_ind]
        tok = line.split(" ")
        if line == "3 Structure Examples":
            code = gen_python_code(str(struct_format), str(fields), name_of_rec, str(has_variable))
            save_code(code)
            output += code + "\n\n" # Add a couple of newlines just to be safe
            break

        name = None
        # Process the header line by line
        #for line in header.splitlines():

        # match = field_regex.search(line)
        if not in_rec: # Not in record yet. Check if we have encountered a record section:
            if record_regex.search(line): # There exists a match
                # print("This line has the thing:"+str(line))
                in_rec = True
                name_of_rec = tok[-2] # Second last.
                # print("Name of rec: "+str(name_of_rec))

        else: # In record..., therefore check if the thing has a field in it.
            if record_regex.search(line): # There exists a match
                # We have encountered a new record type. Save the old one as a parser and be done with it.
                # print("oof")
                # Save the shit here..
                # print("Name of reeeeeeeeeeec: "+str(name_of_rec))
                # assert False
                code = gen_python_code(str(struct_format), str(fields), name_of_rec, str(has_variable))
                output += code + "\n\n" # Add a couple of newlines just to be safe
                # print("output shit: "+str(output))
                save_code(code)
                name_of_rec = tok[-2] # Second last.
                struct_format = [] # ""
                fields = []
                has_variable = False
                # print("Name of rec: "+str(name_of_rec))

            elif len(line) >= len("2.3.4.2") and line[1] == "." and line[3] == "." and line[5] == "." and "Record Types" in line: # This is to fix the bug in the parser when it encounters "2.3.4.2 EMR_HEADER Record Types"
                print("Not in record.")
                print("Previous record name: "+str(name_of_rec))
                in_rec = False


                # Maybe this bullshit here?????
                code = gen_python_code(str(struct_format), str(fields), name_of_rec, str(has_variable))
                output += code + "\n\n" # Add a couple of newlines just to be safe
                # print("output shit: "+str(output))
                save_code(code)
                name_of_rec = tok[-2] # Second last.
                struct_format = [] # ""
                fields = []
                has_variable = False


            else:
                # Checks for the type line.
                if bytes_field_regex.search(line):
                    # A fixed length field.

                    length = int(tok[1][1:])
                    # print("Length: "+str(length))
                    struct_format.append(str(length)+"b") # b for bytes.
                    # print("Here is a field: "+str(tok[0]))
                    fields.append(tok[0])
                elif variable_field_regex.search(line):
                    has_variable = True # Add variable stuff.

        '''
        if match:
            c_type, field_name = match.groups()
            if c_type in type_mapping:
                # struct_format += type_mapping[c_type]
                struct_format.append(type_mapping[c_type])
                fields.append(field_name)
            else:
                raise ValueError(f"Unknown type: {c_type}")

        # Generate python code.

        python_code = gen_python_code(str(struct_format), str(fields))
        return python_code
        '''


        # Increment line counter...
        line_ind += 1
    return output


def save_manual_input(): # This function is here because some records aren't documented in the PDF in the format this autogenerator expects. This causes the parser to miss some record types. These types are manually programmed in manual.py
    fh = open("manual.py")
    data = fh.read()
    fh.close()
    save_code(data)
    return


def gen_parsers(filename: str) -> None:
    fh = open(filename, "r")
    data = fh.read()
    fh.close()
    print(spec_to_python(data))
    # Save the manual shit....
    save_manual_input()
    return


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: "+str(sys.argv[0])+" INPUT_CONTENTS_FILE")
        exit(0)
    # Delete the old stuff.
    os.system("rm output.py")
    gen_parsers(sys.argv[1])
    return 0


import sys

if __name__=="__main__":
    ret = main()

    exit(ret)


```

## More bugs

Ok, so there is some bullshit happening with the generation function because I get this assertion error here:

```

Here is the fields: ['Type', 'Size', 'Bounds', 'xDest', 'yDest', 'xSrc', 'ySrc', 'cxSrc', 'cySrc', 'offBmiSrc', 'cbBmiSrc', 'offBitsSrc', 'cbBitsSrc', 'UsageSrc', 'BitBltRasterOperation', 'cxDest', 'cyDest']
Fields before: ['Type', 'Bounds', 'xDest', 'yDest', 'cxDest', 'cyDest', 'TransparentColor', 'xSrc', 'ySrc', 'XformSrc', 'BkColorSrc', 'UsageSrc', 'offBmiSrc', 'cbBmiSrc', 'offBitsSrc', 'cbBitsSrc', 'cxSrc', 'cySrc', 'Type', 'Size']
Fields after: ['Bounds', 'xDest', 'yDest', 'cxDest', 'cyDest', 'TransparentColor', 'xSrc', 'ySrc', 'XformSrc', 'BkColorSrc', 'UsageSrc', 'offBmiSrc', 'cbBmiSrc', 'offBitsSrc', 'cbBitsSrc', 'cxSrc', 'cySrc', 'Type']
Traceback (most recent call last):
  File "/home/oof/emf_pdf_parsing_stuff/generate.py", line 230, in <module>
    ret = main()
          ^^^^^^
  File "/home/oof/emf_pdf_parsing_stuff/generate.py", line 223, in main
    gen_parsers(sys.argv[1])
  File "/home/oof/emf_pdf_parsing_stuff/generate.py", line 211, in gen_parsers
    print(spec_to_python(data))
          ^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_pdf_parsing_stuff/generate.py", line 137, in spec_to_python
    code = gen_python_code(str(struct_format), str(fields), name_of_rec, str(has_variable))
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_pdf_parsing_stuff/generate.py", line 52, in gen_python_code
    struct_format, fields = fixup_stuff(struct_format, fields)
                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_pdf_parsing_stuff/generate.py", line 35, in fixup_stuff
    assert "Size" not in fields and "Type" not in fields
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AssertionError

```

this happens with the EMR_STRETCHDIBITS field. Let's copy the shit from the file and see what happens.

Ok, so I fixed that bug. Now I am getting this error:

```

\xff\xffF\x00\x00\x00\x1c\x00\x00\x00\x10\x00\x00\x00EMF+\x02@\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x14\x00\x00\x00'
Test succeeded!
Here are the record bytes: b'F\x00\x00\x00,\x00\x00\x00 \x00\x00\x00EMF+\x01@\x00\x00\x1c\x00\x00\x00\x10\x00\x00\x00\x02\x10\xc0\xdb\x01\x00\x00\x00`\x00\x00\x00`\x00\x00\x00'
Here is self.name: EMR_COMMENT
Here is self.has_variable: False
Here is self.remaining_data: b'\x01@\x00\x00\x1c\x00\x00\x00\x10\x00\x00\x00\x02\x10\xc0\xdb\x01\x00\x00\x00`\x00\x00\x00`\x00\x00\x00'
Traceback (most recent call last):
  File "/home/oof/emf_parser/parser.py", line 83, in <module>
    test_parser()
  File "/home/oof/emf_parser/parser.py", line 79, in test_parser
    emf_obj = parse_emf_file(data)
              ^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_parser/emf_file.py", line 101, in parse_emf_file
    records = parse_records(rest_of_data) # Try to parse the records from the data.
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_parser/emf_file.py", line 74, in parse_records
    rec = c(rec_bytes)
          ^^^^^^^^^^^^
  File "/home/oof/emf_parser/autogenerated.py", line 1050, in __init__
    assert False
           ^^^^^
AssertionError

```

this is because the has_variable isn't being set properly during autogeneration...

This is again, because the fucking documentation didn't specify the field in the expected format. This is honestly fucking ridiculous.

```

Name: EMR_SELECTCLIPPATH
Here is the struct format: ['4b', '4b', '4b']
Here is the fields: ['Type', 'Size', 'RegionMode']
Line: The EMR_COMMENT record contains arbitrary private data. wasn't a variable thing
Line: Fields not specified in this section are specified in section 2.3.3. wasn't a variable thing
Line: 0 1 2 3 4 5 6 7 8 9 wasn't a variable thing
Line: 1 wasn't a variable thing
Line: 0 1 2 3 4 5 6 7 8 9 wasn't a variable thing
Line: 2 wasn't a variable thing
Line: 0 1 2 3 4 5 6 7 8 9 wasn't a variable thing
Line: 3 wasn't a variable thing
Line: 0 1 wasn't a variable thing
Line: Type wasn't a variable thing
Line: Size wasn't a variable thing
Line: DataSize wasn't a variable thing
Line: PrivateData (variable, optional) wasn't a variable thing
Line: ... wasn't a variable thing
Line: 109 / 282 wasn't a variable thing
Line: [MS-EMF] - v20240423 wasn't a variable thing
Line: Enhanced Metafile Format wasn't a variable thing
Line: Copyright © 2024 Microsoft Corporation wasn't a variable thing
Line: Release: April 23, 2024 wasn't a variable thing
Line: PrivateData (variable, optional): An array of bytes that specifies the private data. The first 32-bit wasn't a variable thing
Line: field of this data MUST NOT be one of the predefined comment identifier values specified in section wasn't a variable thing
Line: 2.3.3. wasn't a variable thing
Line: Private data is unknown to EMF; it is meaningful only to applications that know the format of the data wasn't a variable thing
Line: and how to use it. EMR_COMMENT private data records MAY<60> be ignored. wasn't a variable thing
Line: See section 2.3.3 for more comment record types. wasn't a variable thing
Name: EMR_COMMENT
has_variable: False
fields: []
struct_format: []
Bullshit before...
Name: EMR_COMMENT
Here is the struct format: []
Here is the fields: []
Fields before: []
Fields after: []
Bullshit after...

```

Wait nevermind. This is because it is optional:

```
PrivateData (variable, optional): An array of bytes that specifies the private data. The first 32-bit
```

Here is the old field: `variable_field_regex = re.compile(r'\w+\s\(variable\):') # This is for fixed length fields...`

Here is a better version of it: `variable_field_regex = re.compile(r'\w+\s\(variable') # This is for fixed length fields...`

There you go! Now we can parse the EMF file into an EMFFile parsed object which has all of the records in it!!!

I did some cleanup of debug prints and here is now the current output:

```
unpacked:
[(1, 0, 0, 0), (108, 0, 0, 0), (15, 0, 0, 0, 0, 0, 0, 0, 99, 0, 0, 0, 96, 0, 0, 0), (-21, 0, 0, 0, 0, 0, 0, 0, 16, 6, 0, 0, -32, 5, 0, 0), (32, 69, 77, 70), (0, 0, 1, 0), (96, 2, 0, 0), (9, 0, 0, 0), (1, 0), (0, 0), (0, 0, 0, 0), (0, 0, 0, 0), (0, 0, 0, 0), (-128, 7, 0, 0, -80, 4, 0, 0), (45, 1, 0, 0, -68, 0, 0, 0)]
value == (1, 0, 0, 0)
value == (108, 0, 0, 0)
value == (15, 0, 0, 0, 0, 0, 0, 0, 99, 0, 0, 0, 96, 0, 0, 0)
value == (-21, 0, 0, 0, 0, 0, 0, 0, 16, 6, 0, 0, -32, 5, 0, 0)
value == (32, 69, 77, 70)
value == (0, 0, 1, 0)
value == (96, 2, 0, 0)
value == (9, 0, 0, 0)
value == (1, 0)
value == (0, 0)
value == (0, 0, 0, 0)
value == (0, 0, 0, 0)
value == (0, 0, 0, 0)
value == (-128, 7, 0, 0, -80, 4, 0, 0)
value == (45, 1, 0, 0, -68, 0, 0, 0)
Here is the size thing: 88
Here is the header: <ParsedHeader {'iType': (4, 1), 'nSize': (4, 108), 'rclBounds': (16, 7605903603195604072277464842255), 'rclFrame': (16, 119159156450082910543087325413611), 'dSignature': (4, 1179469088), 'nVersion': (4, 65536), 'nBytes': (4, 608), 'nRecords': (4, 9), 'nHandles': (2, 1), 'sReserved': (2, 0), 'nDescription': (4, 0), 'offDescription': (4, 0), 'nPalEntries': (4, 0), 'szlDevice': (8, 5153960757120), 'szlMillimeters': (8, 807453851949)}, Remaining: 432 bytes>
header_object.nSize == (4, 108)
Extension 2...
Size: (4, 108)
unpacked:
[(1, 0, 0, 0), (108, 0, 0, 0), (15, 0, 0, 0, 0, 0, 0, 0, 99, 0, 0, 0, 96, 0, 0, 0), (-21, 0, 0, 0, 0, 0, 0, 0, 16, 6, 0, 0, -32, 5, 0, 0), (32, 69, 77, 70), (0, 0, 1, 0), (96, 2, 0, 0), (9, 0, 0, 0), (1, 0), (0, 0), (0, 0, 0, 0), (0, 0, 0, 0), (0, 0, 0, 0), (-128, 7, 0, 0, -80, 4, 0, 0), (45, 1, 0, 0, -68, 0, 0, 0), (0, 0, 0, 0), (0, 0, 0, 0), (0, 0, 0, 0), (-56, -105, 4, 0, 96, -34, 2, 0)]
value == (1, 0, 0, 0)
value == (108, 0, 0, 0)
value == (15, 0, 0, 0, 0, 0, 0, 0, 99, 0, 0, 0, 96, 0, 0, 0)
value == (-21, 0, 0, 0, 0, 0, 0, 0, 16, 6, 0, 0, -32, 5, 0, 0)
value == (32, 69, 77, 70)
value == (0, 0, 1, 0)
value == (96, 2, 0, 0)
value == (9, 0, 0, 0)
value == (1, 0)
value == (0, 0)
value == (0, 0, 0, 0)
value == (0, 0, 0, 0)
value == (0, 0, 0, 0)
value == (-128, 7, 0, 0, -80, 4, 0, 0)
value == (45, 1, 0, 0, -68, 0, 0, 0)
value == (0, 0, 0, 0)
value == (0, 0, 0, 0)
value == (0, 0, 0, 0)
value == (-56, -105, 4, 0, 96, -34, 2, 0)
Here is the size thing: 108
Here is the header: <ParsedHeader {'iType': (4, 1), 'nSize': (4, 108), 'rclBounds': (16, 7605903603195604072277464842255), 'rclFrame': (16, 119159156450082910543087325413611), 'dSignature': (4, 1179469088), 'nVersion': (4, 65536), 'nBytes': (4, 608), 'nRecords': (4, 9), 'nHandles': (2, 1), 'sReserved': (2, 0), 'nDescription': (4, 0), 'offDescription': (4, 0), 'nPalEntries': (4, 0), 'szlDevice': (8, 5153960757120), 'szlMillimeters': (8, 807453851949), 'cbPixelFormat': (4, 0), 'offPixelFormat': (4, 0), 'bOpenGL': (4, 0), 'szlMicrometers': (8, 807453851949000)}, Remaining: 392 bytes>
Header bytes:
b'\x01\x00\x00\x00l\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00c\x00\x00\x00`\x00\x00\x00\xeb\x00\x00\x00\x00\x00\x00\x00\x10\x06\x00\x00\xe0\x05\x00\x00 EMF\x00\x00\x01\x00`\x02\x00\x00\t\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x07\x00\x00\xb0\x04\x00\x00-\x01\x00\x00\xbc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8\x97\x04\x00`\xde\x02\x00'
Actual rest of data: b'F\x00\x00\x00,\x00\x00\x00 \x00\x00\x00EMF+\x01@\x00\x00\x1c\x00\x00\x00\x10\x00\x00\x00\x02\x10\xc0\xdb\x01\x00\x00\x00`\x00\x00\x00`\x00\x00\x00F\x00\x00\x00\x14\x01\x00\x00\x08\x01\x00\x00EMF+\x08@\x00\x060\x00\x00\x00$\x00\x00\x00\x02\x10\xc0\xdb\x00\x00 B\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00A\x00R\x00I\x00A\x00L\x00\x00\x00\x08@\x01\x07H\x00\x00\x00<\x00\x00\x00\x02\x10\xc0\xdb\x00\x00\x00\x00\x00\x00\xcb\x85\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xaa*>\xab\xaa*>\n\xd7\x83?\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08@\x02\x01<\x00\x00\x000\x00\x00\x00\x02\x10\xc0\xdb\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8B\x00\x00\xc8B\x00\x00\xff\xff\xff\x00\x00\xff\x00\x00\xff\xff\xff\x00\x00\xff\x1c@\x00\x00P\x00\x00\x00D\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8B\x00\x00\xc8BH\x00e\x00l\x00l\x00o\x00 \x00W\x00o\x00r\x00l\x00d\x00 \x001\x00 \x002\x00 \x003\x00 \x004\x00!\x00!\x00\x00\x00\x08\x00\x00\x00b\x00\x00\x00\x0c\x00\x00\x00\x01\x00\x00\x00L\x00\x00\x00d\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00c\x00\x00\x00`\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00U\x00\x00\x00a\x00\x00\x00)\x00\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80?\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80?\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\x00\x00\x00\x0c\x00\x00\x00\xff\xff\xff\xffF\x00\x00\x00\x1c\x00\x00\x00\x10\x00\x00\x00EMF+\x02@\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x14\x00\x00\x00'
Test succeeded!
unpacked:
[(1, 0, 0, 0), (108, 0, 0, 0), (15, 0, 0, 0, 0, 0, 0, 0, 99, 0, 0, 0, 96, 0, 0, 0), (-21, 0, 0, 0, 0, 0, 0, 0, 16, 6, 0, 0, -32, 5, 0, 0), (32, 69, 77, 70), (0, 0, 1, 0), (96, 2, 0, 0), (9, 0, 0, 0), (1, 0), (0, 0), (0, 0, 0, 0), (0, 0, 0, 0), (0, 0, 0, 0), (-128, 7, 0, 0, -80, 4, 0, 0), (45, 1, 0, 0, -68, 0, 0, 0)]
value == (1, 0, 0, 0)
value == (108, 0, 0, 0)
value == (15, 0, 0, 0, 0, 0, 0, 0, 99, 0, 0, 0, 96, 0, 0, 0)
value == (-21, 0, 0, 0, 0, 0, 0, 0, 16, 6, 0, 0, -32, 5, 0, 0)
value == (32, 69, 77, 70)
value == (0, 0, 1, 0)
value == (96, 2, 0, 0)
value == (9, 0, 0, 0)
value == (1, 0)
value == (0, 0)
value == (0, 0, 0, 0)
value == (0, 0, 0, 0)
value == (0, 0, 0, 0)
value == (-128, 7, 0, 0, -80, 4, 0, 0)
value == (45, 1, 0, 0, -68, 0, 0, 0)
Here is the size thing: 88
Here is the header: <ParsedHeader {'iType': (4, 1), 'nSize': (4, 108), 'rclBounds': (16, 7605903603195604072277464842255), 'rclFrame': (16, 119159156450082910543087325413611), 'dSignature': (4, 1179469088), 'nVersion': (4, 65536), 'nBytes': (4, 608), 'nRecords': (4, 9), 'nHandles': (2, 1), 'sReserved': (2, 0), 'nDescription': (4, 0), 'offDescription': (4, 0), 'nPalEntries': (4, 0), 'szlDevice': (8, 5153960757120), 'szlMillimeters': (8, 807453851949)}, Remaining: 432 bytes>
header_object.nSize == (4, 108)
Extension 2...
Size: (4, 108)
unpacked:
[(1, 0, 0, 0), (108, 0, 0, 0), (15, 0, 0, 0, 0, 0, 0, 0, 99, 0, 0, 0, 96, 0, 0, 0), (-21, 0, 0, 0, 0, 0, 0, 0, 16, 6, 0, 0, -32, 5, 0, 0), (32, 69, 77, 70), (0, 0, 1, 0), (96, 2, 0, 0), (9, 0, 0, 0), (1, 0), (0, 0), (0, 0, 0, 0), (0, 0, 0, 0), (0, 0, 0, 0), (-128, 7, 0, 0, -80, 4, 0, 0), (45, 1, 0, 0, -68, 0, 0, 0), (0, 0, 0, 0), (0, 0, 0, 0), (0, 0, 0, 0), (-56, -105, 4, 0, 96, -34, 2, 0)]
value == (1, 0, 0, 0)
value == (108, 0, 0, 0)
value == (15, 0, 0, 0, 0, 0, 0, 0, 99, 0, 0, 0, 96, 0, 0, 0)
value == (-21, 0, 0, 0, 0, 0, 0, 0, 16, 6, 0, 0, -32, 5, 0, 0)
value == (32, 69, 77, 70)
value == (0, 0, 1, 0)
value == (96, 2, 0, 0)
value == (9, 0, 0, 0)
value == (1, 0)
value == (0, 0)
value == (0, 0, 0, 0)
value == (0, 0, 0, 0)
value == (0, 0, 0, 0)
value == (-128, 7, 0, 0, -80, 4, 0, 0)
value == (45, 1, 0, 0, -68, 0, 0, 0)
value == (0, 0, 0, 0)
value == (0, 0, 0, 0)
value == (0, 0, 0, 0)
value == (-56, -105, 4, 0, 96, -34, 2, 0)
Here is the size thing: 108
Here is the header: <ParsedHeader {'iType': (4, 1), 'nSize': (4, 108), 'rclBounds': (16, 7605903603195604072277464842255), 'rclFrame': (16, 119159156450082910543087325413611), 'dSignature': (4, 1179469088), 'nVersion': (4, 65536), 'nBytes': (4, 608), 'nRecords': (4, 9), 'nHandles': (2, 1), 'sReserved': (2, 0), 'nDescription': (4, 0), 'offDescription': (4, 0), 'nPalEntries': (4, 0), 'szlDevice': (8, 5153960757120), 'szlMillimeters': (8, 807453851949), 'cbPixelFormat': (4, 0), 'offPixelFormat': (4, 0), 'bOpenGL': (4, 0), 'szlMicrometers': (8, 807453851949000)}, Remaining: 392 bytes>
Header bytes:
b'\x01\x00\x00\x00l\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00c\x00\x00\x00`\x00\x00\x00\xeb\x00\x00\x00\x00\x00\x00\x00\x10\x06\x00\x00\xe0\x05\x00\x00 EMF\x00\x00\x01\x00`\x02\x00\x00\t\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x07\x00\x00\xb0\x04\x00\x00-\x01\x00\x00\xbc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8\x97\x04\x00`\xde\x02\x00'
Actual rest of data: b'F\x00\x00\x00,\x00\x00\x00 \x00\x00\x00EMF+\x01@\x00\x00\x1c\x00\x00\x00\x10\x00\x00\x00\x02\x10\xc0\xdb\x01\x00\x00\x00`\x00\x00\x00`\x00\x00\x00F\x00\x00\x00\x14\x01\x00\x00\x08\x01\x00\x00EMF+\x08@\x00\x060\x00\x00\x00$\x00\x00\x00\x02\x10\xc0\xdb\x00\x00 B\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00A\x00R\x00I\x00A\x00L\x00\x00\x00\x08@\x01\x07H\x00\x00\x00<\x00\x00\x00\x02\x10\xc0\xdb\x00\x00\x00\x00\x00\x00\xcb\x85\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xaa*>\xab\xaa*>\n\xd7\x83?\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08@\x02\x01<\x00\x00\x000\x00\x00\x00\x02\x10\xc0\xdb\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8B\x00\x00\xc8B\x00\x00\xff\xff\xff\x00\x00\xff\x00\x00\xff\xff\xff\x00\x00\xff\x1c@\x00\x00P\x00\x00\x00D\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8B\x00\x00\xc8BH\x00e\x00l\x00l\x00o\x00 \x00W\x00o\x00r\x00l\x00d\x00 \x001\x00 \x002\x00 \x003\x00 \x004\x00!\x00!\x00\x00\x00\x08\x00\x00\x00b\x00\x00\x00\x0c\x00\x00\x00\x01\x00\x00\x00L\x00\x00\x00d\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00c\x00\x00\x00`\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00U\x00\x00\x00a\x00\x00\x00)\x00\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80?\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80?\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\x00\x00\x00\x0c\x00\x00\x00\xff\xff\xff\xffF\x00\x00\x00\x1c\x00\x00\x00\x10\x00\x00\x00EMF+\x02@\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x14\x00\x00\x00'
Test succeeded!
Here are the record bytes: b'F\x00\x00\x00,\x00\x00\x00 \x00\x00\x00EMF+\x01@\x00\x00\x1c\x00\x00\x00\x10\x00\x00\x00\x02\x10\xc0\xdb\x01\x00\x00\x00`\x00\x00\x00`\x00\x00\x00'
Here is self.name: EMR_COMMENT
Here is self.has_variable: True
Here is self.remaining_data: b'\x01@\x00\x00\x1c\x00\x00\x00\x10\x00\x00\x00\x02\x10\xc0\xdb\x01\x00\x00\x00`\x00\x00\x00`\x00\x00\x00'
Here are the record bytes: b'F\x00\x00\x00\x14\x01\x00\x00\x08\x01\x00\x00EMF+\x08@\x00\x060\x00\x00\x00$\x00\x00\x00\x02\x10\xc0\xdb\x00\x00 B\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00A\x00R\x00I\x00A\x00L\x00\x00\x00\x08@\x01\x07H\x00\x00\x00<\x00\x00\x00\x02\x10\xc0\xdb\x00\x00\x00\x00\x00\x00\xcb\x85\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xaa*>\xab\xaa*>\n\xd7\x83?\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08@\x02\x01<\x00\x00\x000\x00\x00\x00\x02\x10\xc0\xdb\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8B\x00\x00\xc8B\x00\x00\xff\xff\xff\x00\x00\xff\x00\x00\xff\xff\xff\x00\x00\xff\x1c@\x00\x00P\x00\x00\x00D\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8B\x00\x00\xc8BH\x00e\x00l\x00l\x00o\x00 \x00W\x00o\x00r\x00l\x00d\x00 \x001\x00 \x002\x00 \x003\x00 \x004\x00!\x00'
Here is self.name: EMR_COMMENT
Here is self.has_variable: True
Here is self.remaining_data: b'\x08@\x00\x060\x00\x00\x00$\x00\x00\x00\x02\x10\xc0\xdb\x00\x00 B\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00A\x00R\x00I\x00A\x00L\x00\x00\x00\x08@\x01\x07H\x00\x00\x00<\x00\x00\x00\x02\x10\xc0\xdb\x00\x00\x00\x00\x00\x00\xcb\x85\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xaa*>\xab\xaa*>\n\xd7\x83?\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08@\x02\x01<\x00\x00\x000\x00\x00\x00\x02\x10\xc0\xdb\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8B\x00\x00\xc8B\x00\x00\xff\xff\xff\x00\x00\xff\x00\x00\xff\xff\xff\x00\x00\xff\x1c@\x00\x00P\x00\x00\x00D\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8B\x00\x00\xc8BH\x00e\x00l\x00l\x00o\x00 \x00W\x00o\x00r\x00l\x00d\x00 \x001\x00 \x002\x00 \x003\x00 \x004\x00!\x00'
Here are the record bytes: b'!\x00\x00\x00\x08\x00\x00\x00'
unpacked:
[(33, 0, 0, 0), (8, 0, 0, 0)]
value == (33, 0, 0, 0)
value == (8, 0, 0, 0)
Here is the size thing: 8
Here are the record bytes: b'b\x00\x00\x00\x0c\x00\x00\x00\x01\x00\x00\x00'
Here is self.name: EMR_SETICMMODE
Here is self.has_variable: False
Here is self.remaining_data: b''
Here are the record bytes: b'L\x00\x00\x00d\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00c\x00\x00\x00`\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00U\x00\x00\x00a\x00\x00\x00)\x00\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80?\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80?\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
Here is self.name: EMR_BITBLT
Here is self.has_variable: True
Here is self.remaining_data: b''
Here are the record bytes: b'"\x00\x00\x00\x0c\x00\x00\x00\xff\xff\xff\xff'
Here is self.name: EMR_RESTOREDC
Here is self.has_variable: False
Here is self.remaining_data: b''
Here are the record bytes: b'F\x00\x00\x00\x1c\x00\x00\x00\x10\x00\x00\x00EMF+\x02@\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00'
Here is self.name: EMR_COMMENT
Here is self.has_variable: True
Here is self.remaining_data: b'\x02@\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00'
Here are the record bytes: b'\x0e\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x14\x00\x00\x00'
Here is self.name: EMR_EOF
Here is self.has_variable: True
Here is self.remaining_data: b''
Here are the records: [<EMR_COMMENT {'Type': (4, 70), 'Size': (4, 44)}, Remaining: 28 bytes>, <EMR_COMMENT {'Type': (4, 70), 'Size': (4, 276)}, Remaining: 260 bytes>, <EMR_SAVEDC {'Type': (4, 33), 'Size': (4, 8)}, Remaining: 0 bytes>, <EMR_SETICMMODE {'Type': (4, 98), 'Size': (4, 12), 'ICMMode': (4, 1)}, Remaining: 0 bytes>, <EMR_BITBLT {'Type': (4, 76), 'Size': (4, 100), 'Bounds': (16, 7605903603195604072277464842255), 'xDest': (4, 15), 'yDest': (4, 0), 'cxDest': (4, 85), 'cyDest': (4, 97), 'BitBltRasterOperation': (4, 11141161), 'xSrc': (4, 0), 'ySrc': (4, 0), 'XformSrc': (24, 84405977732342157929391748328867233792), 'BkColorSrc': (4, 0), 'UsageSrc': (4, 0), 'offBmiSrc': (4, 0), 'cbBmiSrc': (4, 0), 'offBitsSrc': (4, 0), 'cbBitsSrc': (4, 0)}, Remaining: 0 bytes>, <EMR_RESTOREDC {'Type': (4, 34), 'Size': (4, 12), 'SavedDC': (4, 4294967295)}, Remaining: 0 bytes>, <EMR_COMMENT {'Type': (4, 70), 'Size': (4, 28)}, Remaining: 12 bytes>, <EMR_EOF {'Type': (4, 14), 'Size': (4, 20), 'nPalEntries': (4, 0), 'offPalEntries': (4, 16), 'SizeLast': (4, 20)}, Remaining: 0 bytes>]

```

for this EMF file:

```
00000000: 01 00 00 00 6c 00 00 00 0f 00 00 00 00 00 00 00  ....l...........
00000010: 63 00 00 00 60 00 00 00 eb 00 00 00 00 00 00 00  c...`...........
00000020: 10 06 00 00 e0 05 00 00 20 45 4d 46 00 00 01 00  ........ EMF....
00000030: 60 02 00 00 09 00 00 00 01 00 00 00 00 00 00 00  `...............
00000040: 00 00 00 00 00 00 00 00 80 07 00 00 b0 04 00 00  ................
00000050: 2d 01 00 00 bc 00 00 00 00 00 00 00 00 00 00 00  -...............
00000060: 00 00 00 00 c8 97 04 00 60 de 02 00 46 00 00 00  ........`...F...
00000070: 2c 00 00 00 20 00 00 00 45 4d 46 2b 01 40 00 00  ,... ...EMF+.@..
00000080: 1c 00 00 00 10 00 00 00 02 10 c0 db 01 00 00 00  ................
00000090: 60 00 00 00 60 00 00 00 46 00 00 00 14 01 00 00  `...`...F.......
000000a0: 08 01 00 00 45 4d 46 2b 08 40 00 06 30 00 00 00  ....EMF+.@..0...
000000b0: 24 00 00 00 02 10 c0 db 00 00 20 42 02 00 00 00  $......... B....
000000c0: 04 00 00 00 00 00 00 00 05 00 00 00 41 00 52 00  ............A.R.
000000d0: 49 00 41 00 4c 00 00 00 08 40 01 07 48 00 00 00  I.A.L....@..H...
000000e0: 3c 00 00 00 02 10 c0 db 00 00 00 00 00 00 cb 85  <...............
000000f0: 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000100: 00 00 00 00 00 00 00 00 ab aa 2a 3e ab aa 2a 3e  ..........*>..*>
00000110: 0a d7 83 3f 01 00 00 00 00 00 00 00 00 00 00 00  ...?............
00000120: 08 40 02 01 3c 00 00 00 30 00 00 00 02 10 c0 db  .@..<...0.......
00000130: 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000140: 00 00 00 00 00 00 c8 42 00 00 c8 42 00 00 ff ff  .......B...B....
00000150: ff 00 00 ff 00 00 ff ff ff 00 00 ff 1c 40 00 00  .............@..
00000160: 50 00 00 00 44 00 00 00 02 00 00 00 01 00 00 00  P...D...........
00000170: 14 00 00 00 00 00 00 00 00 00 00 00 00 00 c8 42  ...............B
00000180: 00 00 c8 42 48 00 65 00 6c 00 6c 00 6f 00 20 00  ...BH.e.l.l.o. .
00000190: 57 00 6f 00 72 00 6c 00 64 00 20 00 31 00 20 00  W.o.r.l.d. .1. .
000001a0: 32 00 20 00 33 00 20 00 34 00 21 00 21 00 00 00  2. .3. .4.!.!...
000001b0: 08 00 00 00 62 00 00 00 0c 00 00 00 01 00 00 00  ....b...........
000001c0: 4c 00 00 00 64 00 00 00 0f 00 00 00 00 00 00 00  L...d...........
000001d0: 63 00 00 00 60 00 00 00 0f 00 00 00 00 00 00 00  c...`...........
000001e0: 55 00 00 00 61 00 00 00 29 00 aa 00 00 00 00 00  U...a...).......
000001f0: 00 00 00 00 00 00 80 3f 00 00 00 00 00 00 00 00  .......?........
00000200: 00 00 80 3f 00 00 00 00 00 00 00 00 00 00 00 00  ...?............
00000210: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000220: 00 00 00 00 22 00 00 00 0c 00 00 00 ff ff ff ff  ...."...........
00000230: 46 00 00 00 1c 00 00 00 10 00 00 00 45 4d 46 2b  F...........EMF+
00000240: 02 40 00 00 0c 00 00 00 00 00 00 00 0e 00 00 00  .@..............
00000250: 14 00 00 00 00 00 00 00 10 00 00 00 14 00 00 00  ................
```

Now we need a way to parse the structure back into bytes!!!

## Implementing serialization

Ok, so now we need to serialize the structure correctly.

Something like this? This doesn't serialize the header yet, but we will implement that later:

```

class EMFFile:
	def __init__(self, h, recs, orig_data): # Initialization function
		self.h = h # Header.
		self.records = recs # Records
		self.mutated = False # Has been mutated?

	def serialize(self): # Serialize data back.
		# First serialize all of the record objects... we can not use orig_data because the object may have been mutated or changed.

		rec_files = [r.serialize() for r in self.records] # Just serialize each??
		out = b""
		for r in rec_files:
			assert isinstance(r, bytes)
			out += r

		return out

```

another bug!!

```

Traceback (most recent call last):
  File "/home/oof/emf_parser/parser.py", line 84, in <module>
    test_parser()
  File "/home/oof/emf_parser/parser.py", line 80, in test_parser
    print("Serialized bytes: "+str(emf_obj.serialize()))
                                   ^^^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_parser/emf_file.py", line 94, in serialize
    rec_files = [r.serialize() for r in self.records] # Just serialize each??
                 ^^^^^^^^^^^^^
  File "/home/oof/emf_parser/autogenerated.py", line 1085, in serialize
    assert self.Size == len(out)
           ^^^^^^^^^^^^^^^^^^^^^
AssertionError

```

Add some debugging????

```


    def serialize(self):
        out = b"" # Initialize empty bytes output
        for i, format_string in enumerate(self.format):
            # The corresponding field is fields[i]
            field_name = self.fields[i]
            field_val = getattr(self, field_name) # Get the actual value of the field from this object.
            field_length = field_val[0]
            field_integer = field_val[1]
            # Now try to unpack the integer into the format.
            # field_bytes = struct.pack(format_string, field_val)
            field_bytes = field_integer.to_bytes(field_length, byteorder='little') # num.to_bytes(4, byteorder='little')
            out += field_bytes # Add the actual value to the output
        print("Here is the data without the variable shit: "+str(out))
        if self.has_variable:
            # Add variable data to the end.
            out += self.variable_data
        print("Here is the variable data: "+str(self.variable_data))
        print("Length of the variable data: "+str(len(self.variable_data)))
        print("Here is the Size: "+str(self.Size))


        # Sanity checking. The "Size" field should actually match the size upon serialization. If not, then the mutator did not take care of the size correctly and there is a bug in the mutator.
        assert self.Size == len(out)
        return out # Return the output bytes


```

oh, it looks like I am using the entire thing:

```
aining: 0 bytes>]
Here is the data without the variable shit: b'F\x00\x00\x00,\x00\x00\x00'
Here is the variable data: b'\x01@\x00\x00\x1c\x00\x00\x00\x10\x00\x00\x00\x02\x10\xc0\xdb\x01\x00\x00\x00`\x00\x00\x00`\x00\x00\x00'
Length of the variable data: 28
Here is the Size: (4, 44)
Traceback (most recent call last):
  File "/home/oof/emf_parser/parser.py", line 84, in <module>
    test_parser()
  File "/home/oof/emf_parser/parser.py", line 80, in test_parser
    print("Serialized bytes: "+str(emf_obj.serialize()))
                                   ^^^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_parser/emf_file.py", line 94, in serialize
    rec_files = [r.serialize() for r in self.records] # Just serialize each??
                 ^^^^^^^^^^^^^
  File "/home/oof/emf_parser/autogenerated.py", line 1088, in serialize
    assert self.Size == len(out)
           ^^^^^^^^^^^^^^^^^^^^^
AssertionError
```

we want `self.Size[1]` instead of just `self.Size[0]`

wait that still doesn't work. Something is going on..

If we look at the thing:

```

Test succeeded!
We have comment...
l == 44
Here are the record bytes: b'F\x00\x00\x00,\x00\x00\x00 \x00\x00\x00EMF+\x01@\x00\x00\x1c\x00\x00\x00\x10\x00\x00\x00\x02\x10\xc0\xdb\x01\x00\x00\x00`\x00\x00\x00`\x00\x00\x00'
Here is the data in EMR_COMMENT: b'F\x00\x00\x00,\x00\x00\x00

```

and here is the thing at the end:

```

'offPalEntries': (4, 16), 'SizeLast': (4, 20)}, Remaining: 0 bytes>]
Here is the data without the variable shit: b'F\x00\x00\x00,\x00\x00\x00'
Here is the variable data: b'\x01@\x00\x00\x1c\x00\x00\x00\x10\x00\x00\x00\x02\x10\xc0\xdb\x01\x00\x00\x00`\x00\x00\x00`\x00\x00\x00'
Length of the variable data: 28
Here is the Size: (4, 44)


```

we can see that the difference is that when reading the stuff, we cut out the ` \x00\x00\x00EMF+` part. Which seems to make sense since, since the difference between the expected and the parsed is 8 bytes...

Ah, I see that we actually cut the thing in the `__init__` function here:

```
        for f in self.format:
            unpacked.append(struct.unpack(f, data[:struct.calcsize(f)]))
            data = data[struct.calcsize(f):]
```

this essentially means that the data gets truncated and that is why the check fails..

fixed it. Now I think we can serialize the bytes.

Ok, so now we can serialize back the bytes of the other records.

## Serializing header.

Ok, so this is just as simple as `self.h.serialize()` .

## Starting with the mutator.

Ok, so now that have a some sort of parser for EFM files, we need to program the mutator

Now one mutation strategy is to simply modify an existing record in the file. I think this is the easiest to implement. Then there is a mutation strategy to add a record and to delete a record from a file. Adding records will be quite hard if we want to generate them from scratch, but I think we can manage it. Other option is to use the splicing mechanism in afl which sort of "combines" testcases. This can be used to just copy a record from another EMF testcase into our program...

Here is the mutator skeleton:

```
# This mutator is for EMF files. See https://www.mcafee.com/blogs/other-blogs/mcafee-labs/analyzing-cve-2021-1665-remote-code-execution-vulnerability-in-windows-gdi/ and

from parser import * # Import all of the stuff from the parser.
import random
from value_mut import * # This is for the actual mutation strategies. This implements mutate_tuple


def mut_field(rec) -> None:
	# Mutates a field in a record.
	field = random.choice(rec.fields)
	assert isinstance(field, str) # Should be string...
	field_tup = getattr(rec, field) # Get the actual attribute thing...
	# Now just do the thing...
	field_tup = mutate_tuple(field_tup)
	# Now set the mutated value to the object.
	setattr(rec, field)
	return

def modify_record(obj: EMFFile) -> None:
	rand_rec = random.choice(obj.records) # Just take some record from the object.
	# Now try to modify the stuff.
	mut_field(rand_rec)
	return

def mutate_emf_obj(obj: EMFFile) -> None: # This modifies the structure in place. This is basically needed to mutate the structure in structure-aware ways such that we exercise the deep logic of the program.
	# Select mut strat.
	mut_strat = random.randrange(1) # This should always be zero. This is just so we can add more strategies later on...

	if mut_strat == 0:
		# Modify record.
		modify_record(obj)
	else:
		print("Invalid mut strat")
		assert False
	return

def mutate_emf(emf_data): # This is the main mutation function. Takes an EMF file, parses it, modifies it and then serializes it back to bytes...
	emf_obj = parse_emf_file(data)
	# Now mutate the thing
	mutate_emf_obj(emf_obj)
	ser_bytes = emf_obj.serialize()
	print("Serialized bytes: "+str(ser_bytes))
	assert len(header_bytes) == 108 # This because the header is extension 2
	ext_stuff = emf_obj.serialize_header() # Serialize the header.
	print("Header seems to be the correct size...")
	return ext_stuff + ser_bytes # Return the header + records which should be a(n atleast somewhat) valid EMF file.



TEST_MUT_COUNT = 100

def test_mut():

	fh = open(TEST_FILE_NAME, "rb")
	data = fh.read()
	fh.close()
	orig_data = copy.deepcopy(data)
	# Now parse header...
	# h, rest_of_data = parse_header(data)
	# Now try to parse the records
	# records = parse_records(rest_of_data) # Try to parse the records from the data.
	for _ in range(TEST_MUT_COUNT):
		#

	return

if __name__=="__main__":
	test_mut()
	exit(0)
```

and here is the mutation strategies:

```


import random


def mutate_integer(value: int, n: int) -> int: # Thanks ChatGPT!!!
	"""Randomly mutates an integer while ensuring it fits within n bytes.

	Args:
		value (int): The integer to mutate.
		n (int): The maximum number of bytes.

	Returns:
		int: The mutated integer.
	"""
	if n <= 0:
		raise ValueError("Number of bytes (n) must be positive.")

	# Maximum value that fits in n bytes
	max_value = (1 << (n * 8)) - 1

	# Choose a random mutation
	mutation = random.choice(["left_shift", "right_shift", "bit_flip", "add", "subtract"])

	if mutation == "left_shift":
		shift = random.randint(1, n * 8 - 1)  # Shift amount
		value = (value << shift) & max_value  # Ensure it fits in n bytes

	elif mutation == "right_shift":
		shift = random.randint(1, n * 8 - 1)  # Shift amount
		value = value >> shift

	elif mutation == "bit_flip":
		bit_to_flip = random.randint(0, n * 8 - 1)  # Random bit position
		value ^= (1 << bit_to_flip)  # Flip the bit
		value &= max_value  # Ensure it fits in n bytes

	elif mutation == "add":
		value = (value + random.randint(1, 255)) & max_value  # Add a small value, wrap if needed

	elif mutation == "subtract":
		value = (value - random.randint(1, 255)) & max_value  # Subtract a small value, wrap if needed

	return value

def mutate_tuple(field): # This mutates the thing with fixed size integer...
	length, value = field # Field is actually a tuple of length and the actual value
	value = mutate_integer(value, length)
	return (length, value)




```

There is quite an obvious bug here. We shouldn't mutate the Size or Type fields, so let's remove those from the list before choosing a field to mutate.

Here seems to be a sufficient fix:

```
def mut_field(rec) -> None:
	# Mutates a field in a record.
	available_fields = copy.deepcopy(rec.fields) # We need to do a copy here because otherwise we would modifying the object itself.
	assert "Size" in available_fields and "Type" in available_fields
	# Doesn't make sense to mutate these.
	available_fields.remove("Type")
	available_fields.remove("Size")
	if not available_fields: # Record only has the "Type" and "Size" fields.
		return
	field = random.choice(available_fields)
	assert isinstance(field, str) # Should be string...
	field_tup = getattr(rec, field) # Get the actual attribute thing...
	# Now just do the thing...
	field_tup = mutate_tuple(field_tup)
	# Now set the mutated value to the object.
	setattr(rec, field, field_tup)
	return

```

Ok, so now I think we actually have a fully functioning mutator which we can now test out. We just only need to add the afl specific functions to our code and we should be golden...

Here this seems to do the thing:

```


# This mutator is for EMF files. See https://www.mcafee.com/blogs/other-blogs/mcafee-labs/analyzing-cve-2021-1665-remote-code-execution-vulnerability-in-windows-gdi/ and

from parser import * # Import all of the stuff from the parser.
import random
from value_mut import * # This is for the actual mutation strategies. This implements mutate_tuple
import copy

def mut_field(rec) -> None:
	# Mutates a field in a record.
	available_fields = copy.deepcopy(rec.fields) # We need to do a copy here because otherwise we would modifying the object itself.
	assert "Size" in available_fields and "Type" in available_fields
	# Doesn't make sense to mutate these.
	available_fields.remove("Type")
	available_fields.remove("Size")
	if not available_fields: # Record only has the "Type" and "Size" fields.
		return
	field = random.choice(available_fields)
	assert isinstance(field, str) # Should be string...
	field_tup = getattr(rec, field) # Get the actual attribute thing...
	# Now just do the thing...
	field_tup = mutate_tuple(field_tup)
	# Now set the mutated value to the object.
	setattr(rec, field, field_tup)
	return

def modify_record(obj: EMFFile) -> None:
	rand_rec = random.choice(obj.records) # Just take some record from the object.
	# Now try to modify the stuff.
	mut_field(rand_rec)
	return

def mutate_emf_obj(obj: EMFFile) -> None: # This modifies the structure in place. This is basically needed to mutate the structure in structure-aware ways such that we exercise the deep logic of the program.
	# Select mut strat.
	mut_strat = random.randrange(1) # This should always be zero. This is just so we can add more strategies later on...

	if mut_strat == 0:
		# Modify record.
		modify_record(obj)
	else:
		print("Invalid mut strat")
		assert False
	return

def mutate_emf(emf_data): # This is the main mutation function. Takes an EMF file, parses it, modifies it and then serializes it back to bytes...
	emf_obj = parse_emf_file(emf_data)
	# Now mutate the thing
	mutate_emf_obj(emf_obj)
	ser_bytes = emf_obj.serialize()
	print("Serialized bytes: "+str(ser_bytes))
	# assert len(header_bytes) == 108 # This because the header is extension 2
	ext_stuff = emf_obj.serialize_header() # Serialize the header.
	print("Header seems to be the correct size...")
	return ext_stuff + ser_bytes # Return the header + records which should be a(n atleast somewhat) valid EMF file.



def init(seed):
	pass


def fuzz(buf, add_buf, max_size):
	assert isinstance(buf, bytearray) # Should be a bytearray
	buf = bytes(buf)
	buf = mutate_emf(buf) # Mutate the EMF file...
	assert isinstance(buf, bytes)
	buf = bytearray(buf) # Convert back to bytearray
	# Now just do this such that we don't overflow the buffer...
	buf = buf[:max_size]
	return buf # Return the mutated buffer

TEST_MUT_COUNT = 100

def test_mut():

	fh = open(TEST_FILE_NAME, "rb")
	data = fh.read()
	fh.close()
	orig_data = copy.deepcopy(data)
	# Now parse header...
	# h, rest_of_data = parse_header(data)
	# Now try to parse the records
	# records = parse_records(rest_of_data) # Try to parse the records from the data.
	for _ in range(TEST_MUT_COUNT):
		data = mutate_emf(data)

	return

if __name__=="__main__":
	test_mut()
	exit(0)


```

One small problem... the python custom mutator shit doesn't exist for winafl... FUCK!!!!!!!!!

I asked chatgpt to write me a custom mutator dll for python for winafl and it came up with this:

```

#include <Python.h>
#include <afl-fuzz.h>

// Initialize the Python interpreter and call the Python init function
void *afl_custom_init(void *afl, unsigned int seed) {
    Py_Initialize(); // Start Python interpreter
    PyObject *pName = PyUnicode_DecodeFSDefault("python_mutator"); // Python script name
    PyObject *pModule = PyImport_Import(pName);
    Py_XDECREF(pName);

    if (!pModule) {
        PyErr_Print();
        return NULL;
    }

    PyObject *pInitFunc = PyObject_GetAttrString(pModule, "custom_init");
    if (pInitFunc && PyCallable_Check(pInitFunc)) {
        PyObject *pResult = PyObject_CallFunction(pInitFunc, "(I)", seed);
        Py_XDECREF(pResult);
    }
    Py_XDECREF(pInitFunc);
    Py_XDECREF(pModule);

    return NULL; // No custom state
}

// Call the Python fuzz function
size_t afl_custom_fuzz(void *data, unsigned char *buf, size_t buf_size, unsigned char **out_buf, size_t *out_buf_size, unsigned int max_size) {
    PyObject *pName = PyUnicode_DecodeFSDefault("python_mutator");
    PyObject *pModule = PyImport_Import(pName);
    Py_XDECREF(pName);

    if (!pModule) {
        PyErr_Print();
        return 0;
    }

    PyObject *pFuzzFunc = PyObject_GetAttrString(pModule, "custom_fuzz");
    if (pFuzzFunc && PyCallable_Check(pFuzzFunc)) {
        PyObject *pResult = PyObject_CallFunction(pFuzzFunc, "(y#)", buf, buf_size);
        if (pResult) {
            Py_ssize_t new_size;
            const char *new_buf = PyBytes_AsStringAndSize(pResult, &new_size);
            *out_buf = malloc(new_size);
            memcpy(*out_buf, new_buf, new_size);
            *out_buf_size = new_size;
            Py_XDECREF(pResult);
        }
    }

    Py_XDECREF(pFuzzFunc);
    Py_XDECREF(pModule);

    return *out_buf_size;
}

// Cleanup
void afl_custom_deinit(void *data) {
    Py_Finalize();
}

```

Let's create a repo for this garbage: https://github.com/personnumber3377/winafl_python_custom_mutator

## Trying to compile the bullshit

Ok, so I asked how to compile in Visual Studio and I got this here: `cl /LD python_mutator.c /I"path\to\python\include" /link /LIBPATH:"path\to\python\libs" python39.lib`




```

cl /LD python_mutator.c /I"C:\Python39\include" /link /LIBPATH:"C:\Python39\libs" python39.lib


C:\Users\elsku\AppData\Local\Programs\Python\Python313\Include
C:\Users\elsku\AppData\Local\Programs\Python\Python313\libs
python313.dll


 /MACHINE:x64

cl /LD python_mutator.c /I"C:\Users\elsku\AppData\Local\Programs\Python\Python313\Include" /link  /MACHINE:x64 /LIBPATH:"C:\Users\elsku\AppData\Local\Programs\Python\Python313\libs" python313.dll
cl /LD python_mutator.c /I"C:\Users\elsku\AppData\Local\Programs\Python\Python313\Include" /link /LIBPATH:"C:\Users\elsku\AppData\Local\Programs\Python\Python313\libs" python313.lib




```

Ok, so I managed to compile the bullshit with the help of chatgpt. Now it is time to try and run the thing. Maybe something like this???

```

C:\Users\elsku\winafl\winafl\build\bin\Release\afl-fuzz.exe -i c:\Users\elsku\inputs -o c:\Users\elsku\outputs3 -D C:\Users\elsku\dynamorio2\DynamoRIO-Windows-11.3.0-1\bin64 -I 40000   -t 4000 -f input.emf -- -coverage_module gdiplus.dll -fuzz_iterations 1000 -persistence_mode in_app -target_module gdiplusharness.exe -verbose 100 -target_offset 0x1170 -nargs 1 -- "C:\Users\elsku\source\repos\gdiplusharness\x64\Release\gdiplusharness.exe" "@@"

```


Ok, so the chatgpt generated was wrong I think (surprise) and here is actually something which we want:

```

    if (dll_mutate_testcase_ptr(argv, in_buf, len, common_fuzz_stuff))
      goto abandon_entry;
  }


and here:

  // Get pointer to user-defined mutate_testcase function using GetProcAddress:
  dll_mutate_testcase_ptr = (dll_mutate_testcase)GetProcAddress(hLib, "dll_mutate_testcase");
  SAYF("dll_mutate_testcase %s defined.\n", dll_mutate_testcase_ptr ? "is" : "isn't");
```

so we actually want to define the function as dll_mutate_testcase .

The common_fuzz_stuff is actually a function pointer which does some stuff. I don't know if we should do something with it but idk..

Fuck. I am getting an error saying some bullshit....

```

#include <windows.h>
#include <stdio.h>

int main() {
    // Load the DLL
    HMODULE hDll = LoadLibrary("example.dll");
    if (hDll == NULL) {
        printf("Failed to load DLL. Error: %lu\n", GetLastError());
        return 1;
    }
    printf("DLL loaded successfully.\n");

    // Free the DLL when done
    if (FreeLibrary(hDll)) {
        printf("DLL unloaded successfully.\n");
    } else {
        printf("Failed to unload DLL. Error: %lu\n", GetLastError());
    }

    return 0;
}

```


Let's try to load the dll manually and see what happens...


```

cl /LD python_mutator.c /I"C:\Users\elsku\AppData\Local\Programs\Python\Python313\Include" /link  /MACHINE:x64 /LIBPATH:"C:\Users\elsku\AppData\Local\Programs\Python\Python313\libs" python313.lib

```


```

cl /LD "C:\Users\elsku\winafl\winafl\python_mutator.c" /I"C:\Users\elsku\AppData\Local\Programs\Python\Python313\Include" /link  /MACHINE:x64 /LIBPATH:"C:\Users\elsku\AppData\Local\Programs\Python\Python313\libs" python313.lib


```




I think this is some binary versioning bullshit and we actually need to compile the bullshit with the 32 version of binaries and that is why it claims that it can't find it, because it can but it is the wrong binary version...

```

cl /LD "C:\Users\elsku\winafl\winafl\python_mutator.c" /I"C:\py32\Include" /link   /LIBPATH:"C:\py32\libs" python312.lib

```

Ok, so now I get this bullshit:

```

C:\Users\elsku\source\repos\gdiplusharness>C:\Users\elsku\winafl\winafl\build\bin\Release\afl-fuzz.exe -i c:\Users\elsku\inputs -o c:\Users\elsku\outputs4 -D C:\Users\elsku\dynamorio2\DynamoRIO-Windows-11.3.0-1\bin64 -I 40000   -t 4000 -f input.emf -l python_mutator.dll -- -coverage_module gdiplus.dll -fuzz_iterations 1000 -persistence_mode in_app -target_module gdiplusharness.exe -verbose 100 -target_offset 0x1170 -nargs 1 -- "C:\Users\elsku\source\repos\gdiplusharness\x64\Release\gdiplusharness.exe" "@@"
WinAFL 1.17 by <ifratric@google.com>
Based on AFL 2.43b by <lcamtuf@google.com>
Loading custom winAFL server library
Using absolute path to search for dll...

[-] PROGRAM ABORT : Unable to load custom server library, GetLastError = 0xc1
         Location : load_custom_library(), C:\Users\elsku\winafl\winafl\afl-fuzz.c:8140

```

the error code 0xc1 means that the binary format is wrong. Fuck!!!!

Just compile with the norma command???


```
C:\Users\elsku\winafl\winafl\build\bin\Release\afl-fuzz.exe -i c:\Users\elsku\inputs -o c:\Users\elsku\outputs4 -D C:\Users\elsku\dynamorio2\DynamoRIO-Windows-11.3.0-1\bin64 -I 40000   -t 4000 -f input.emf -l python_mutator.dll -- -coverage_module gdiplus.dll -fuzz_iterations 1000 -persistence_mode in_app -target_module gdiplusharness.exe -verbose 100 -target_offset 0x1170 -nargs 1 -- "C:\Users\elsku\source\repos\gdiplusharness\x64\Release\gdiplusharness.exe" "@@"
```

Ok, so this is quite annoying. The error is in the environment variable script. See, I am running the fuzzer as follows:

```


set AFL_AUTORESUME=1
set AFL_CUSTOM_MUTATOR_ONLY=1
set PYTHONPATH="."
set AFL_PYTHON_MODULE="mutator"
copy C:\Users\elsku\winafl\winafl\python_mutator.dll .


C:\Users\elsku\winafl\testing\afl-fuzz.exe -i c:\Users\elsku\inputs -o c:\Users\elsku\outputs4 -D C:\Users\elsku\dynamorio2\DynamoRIO-Windows-11.3.0-1\bin64 -I 40000   -t 4000 -f input.emf -l python_mutator.dll -- -coverage_module gdiplus.dll -fuzz_iterations 1000 -persistence_mode in_app -target_module gdiplusharness.exe -verbose 100 -target_offset 0x1170 -nargs 1 -- "C:\Users\elsku\source\repos\gdiplusharness\x64\Release\gdiplusharness.exe" "@@"
```



where the error is actually caused by the setting of the pythonpath variable!!!!!!! Holy shit this was annoying to debug. I mean I was the one who did that but still..

## More debugging windows bullshit

Ok, so now I think the next course of action is to try to make it actually load succesfully the custom mutator function, right now it doesn't find the custom mutator function and I get the following error message:

```

Using absolute path to search for dll...
dll_init isn't defined.
dll_run_ptr isn't defined.
dll_run_target isn't defined.
dll_write_to_testcase isn't defined.
dll_mutate_testcase isn't defined.
dll_trim_testcase isn't defined.
dll_mutate_testcase_with_energy isn't defined.

```

which means that it is unable to find the custom mutation functions which is of course not what we want.

Ok, so I managed to write this:

```

__declspec(dllexport) void *dll_init(void) {
    Py_Initialize(); // Start Python interpreter
    PyObject *pName = PyUnicode_DecodeFSDefault("mutator"); // Python script name
    PyObject *pModule = PyImport_Import(pName);
    Py_XDECREF(pName);

    if (!pModule) {
        PyErr_Print();
        return NULL;
    }

    PyObject *pInitFunc = PyObject_GetAttrString(pModule, "init");
    if (pInitFunc && PyCallable_Check(pInitFunc)) {
        PyObject *pResult = PyObject_CallFunction(pInitFunc, "(I)", 0); // Just call custom_init with seed 0 because reasons.
        Py_XDECREF(pResult);
    }
    Py_XDECREF(pInitFunc);
    Py_XDECREF(pModule);

    return NULL; // No custom state
}

```

except here is the return value:

```

[*] Attempting dry run with 'id_000000'...

[-]  SYSTEM ERROR : User-defined custom initialization routine returned 0
    Stop location : run_target(), C:\Users\elsku\winafl\winafl\afl-fuzz.c:2883
       OS message : No error

```

so therefore I think the function should return something and chatgpt did something wrong???????

Let's just take a look at the actual documentation and see what it says on custom mutators...


Here is my current code:

```

#include <Python.h>
#include <stdint.h>
//#include <afl-fuzz.h>

// Initialize the Python interpreter and call the Python init function
// void *afl_custom_init(void *afl, unsigned int seed) {



/*
__declspec(dllexport) void *dll_init(void) {
    Py_Initialize(); // Start Python interpreter
    PyObject *pName = PyUnicode_DecodeFSDefault("mutator"); // Python script name
    PyObject *pModule = PyImport_Import(pName);
    Py_XDECREF(pName);

    if (!pModule) {
        PyErr_Print();
        return NULL;
    }

    PyObject *pInitFunc = PyObject_GetAttrString(pModule, "init");
    if (pInitFunc && PyCallable_Check(pInitFunc)) {
        PyObject *pResult = PyObject_CallFunction(pInitFunc, "(I)", 0); // Just call custom_init with seed 0 because reasons.
        Py_XDECREF(pResult);
    }
    Py_XDECREF(pInitFunc);
    Py_XDECREF(pModule);

    return NULL; // No custom state
}
*/


// Call the Python fuzz function
/*

size_t afl_custom_fuzz(void *data, unsigned char *buf, size_t buf_size, unsigned char **out_buf, size_t *out_buf_size, unsigned int max_size) {
    PyObject *pName = PyUnicode_DecodeFSDefault("python_mutator");
    PyObject *pModule = PyImport_Import(pName);
    Py_XDECREF(pName);

    if (!pModule) {
        PyErr_Print();
        return 0;
    }

    PyObject *pFuzzFunc = PyObject_GetAttrString(pModule, "custom_fuzz");
    if (pFuzzFunc && PyCallable_Check(pFuzzFunc)) {
        PyObject *pResult = PyObject_CallFunction(pFuzzFunc, "(y#)", buf, buf_size);
        if (pResult) {
            Py_ssize_t new_size;
            const char *new_buf = PyBytes_AsStringAndSize(pResult, &new_size);
            *out_buf = malloc(new_size);
            memcpy(*out_buf, new_buf, new_size);
            *out_buf_size = new_size;
            Py_XDECREF(pResult);
        }
    }

    Py_XDECREF(pFuzzFunc);
    Py_XDECREF(pModule);

    return *out_buf_size;
}
*/







/*

u8 dll_mutate_testcase(char **argv, u8 *buf, u32 len, u8 (*common_fuzz_stuff)(char**, u8*, u32))
{
    u8 bailout = 0;
    u8 *newbuf;
    u32 i;
    // duplicate the input buffer
    newbuf = malloc(len);
    if (!newbuf) return bailout;
    memcpy(newbuf, buf, len);
    // increment every byte by one and call common_fuzz_stuff for every new test case
    for (i = 0; i < len; i++) {
       newbuf[i] += 1;
       if (common_fuzz_stuff(argv, newbuf, len)) {
           bailout = 1; // skip the rest of the mutation per common_fuzz_stuff
           break;
       }
    }
    free(newbuf);
    return bailout;
}

(*common_fuzz_stuff)(char**, u8*, u32)


*/


// size_t dll_mutate_testcase(void *data, unsigned char *buf, size_t buf_size, unsigned char **out_buf, size_t *out_buf_size, unsigned int max_size) {
//__declspec(dllexport) unsigned char dll_mutate_testcase(char** argv, unsigned char *buf, unsigned int buf_size, u8 (*common_fuzz_stuff)(char**, u8*, u32))   // void* common_fuzz_stuff) { // common_fuzz_stuff is just some bullshit stuff.

typedef unsigned char (*common_fuzz_stuff_t)(char **, u8 *, u32);

//unsigned char dll_mutate_testcase(char **argv, u8 *buf, u32 len, u8 (*common_fuzz_stuff)(char**, u8*, u32)) {
__declspec(dllexport) unsigned char dll_mutate_testcase(char** argv, unsigned char *buf, unsigned int buf_size, common_fuzz_stuff_t common_fuzz_stuff) {   // void* common_fuzz_stuff) { // common_fuzz_stuff is just some bullshit stuff.
    char* out_buf; // Output buffer.
    unsigned char bail = 0; // Init at zero
    unsigned int* out_buf_size;
    PyObject *pName = PyUnicode_DecodeFSDefault("mutator");
    PyObject *pModule = PyImport_Import(pName);
    Py_XDECREF(pName);

    if (!pModule) {
        PyErr_Print();
        return 0;
    }

    PyObject *pFuzzFunc = PyObject_GetAttrString(pModule, "fuzz");
    if (pFuzzFunc && PyCallable_Check(pFuzzFunc)) {
        PyObject *pResult = PyObject_CallFunction(pFuzzFunc, "(y#)", buf, buf_size);
        if (pResult) {
            char *new_buf;
            Py_ssize_t new_size;

            // Correct usage of PyBytes_AsStringAndSize
            if (PyBytes_AsStringAndSize(pResult, &new_buf, &new_size) == -1) {
                PyErr_Print();
                Py_XDECREF(pResult);
                return 0;
            }

            *out_buf = malloc(new_size);
            if (*out_buf == NULL) {
                fprintf(stderr, "Error: Memory allocation failed\n");
                Py_XDECREF(pResult);
                return 0;
            }

            memcpy(*out_buf, new_buf, new_size);
            *out_buf_size = (size_t)new_size;

            if (common_fuzz_stuff(argv, out_buf, len)) {
                bail = 1; // skip the rest of the mutation per common_fuzz_stuff
                break;
            }

            Py_XDECREF(pResult);
            Py_XDECREF(pFuzzFunc);
            Py_XDECREF(pModule);
            return bail;
        }
    }

    Py_XDECREF(pFuzzFunc);
    Py_XDECREF(pModule);
    return bail;
}

// Cleanup
__declspec(dllexport) void afl_custom_deinit(void *data) {
    Py_Finalize();
}

```

here is a working thing:

```

#include <Python.h>
#include <stdint.h>

typedef unsigned char (*common_fuzz_stuff_t)(char **, unsigned char *, unsigned int);

unsigned char has_inited = 0; // Have we inited the python environment??
PyObject *pModule = NULL; // Custom mutator module


void init_python(void) {
    Py_Initialize();
    PyObject* pName = PyUnicode_FromString("mutator");
    pModule = PyImport_Import(pName);
    Py_XDECREF(pName);

    if (!pModule) {
        //print_python_error_to_stderr();
        //PyErr_Print();
        if (PyErr_Occurred()) {
            fprintf(stderr, "FuckFuckFuckFUckUfefefwfwwwww\n");
            PyErr_Print();
            fprintf(stderr, "Error: Failed to load external Python module \"%s\"\n",
            "mutator");
          //py_fatal_error();
            fprintf(stderr, "Crashing in the init bullshit fuck......");
          exit(1);
        }
            fprintf(stderr, "Crashing in the init bullshit fuck......");
          exit(1);

        fprintf(stderr, "Crashing in the init bullshit fuck......");
        memcpy(0, 00, 10);
        //return 0;
    }
    fprintf(stderr, "Returning from the init function..........");
    has_inited = 1;
    return;
}

/*
void print_python_error_to_stderr() {
    fprintf(stderr, "fuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuck...\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    if (PyErr_Occurred()) {
        PyObject *ptype, *pvalue, *ptraceback;

        // Fetch the error information
        PyErr_Fetch(&ptype, &pvalue, &ptraceback);
        PyErr_NormalizeException(&ptype, &pvalue, &ptraceback);

        // Convert the error value to a string
        if (pvalue) {
            PyObject *pStr = PyObject_Str(pvalue);  // Get the string representation of the error
            if (pStr) {
                const char *error_message = PyUnicode_AsUTF8(pStr);  // Convert to UTF-8
                if (error_message) {
                    fprintf(stderr, "Python error: %s\n", error_message);
                }
                Py_DECREF(pStr);  // Decrement reference count
            }
        }

        // Clean up
        Py_XDECREF(ptype);
        Py_XDECREF(pvalue);
        Py_XDECREF(ptraceback);

        // Clear the Python error indicator
        PyErr_Clear();
    }
}
*/

void spam_string(const char* string) {
    for (int i = 0; i < 100; i++) {
        fprintf(stderr, string);
    }
    return;
}

//unsigned char dll_mutate_testcase(char **argv, u8 *buf, u32 len, u8 (*common_fuzz_stuff)(char**, u8*, u32)) {
__declspec(dllexport) unsigned char dll_mutate_testcase(char** argv, unsigned char *buf, unsigned int buf_size, common_fuzz_stuff_t common_fuzz_stuff) {   // void* common_fuzz_stuff) { // common_fuzz_stuff is just some bullshit stuff.
    char* out_buf = NULL; // Output buffer. Avoid uninitialized memory here.
    unsigned char bail = 0; // Init at zero
    unsigned int* out_buf_size;
    spam_string("Called again..\n");
    //if (!(has_inited)) {
    if (!has_inited) {
        spam_string("wasn't initigedfefwefwewe again..\n");
        init_python();

    }

    //int x = 0 / 0; // Zero division exception.
    if (!pModule) {
        //print_python_error_to_stderr();
        PyErr_Print();
        memcpy(0, buf, 10);
        return 0;
    } else {
        fprintf(stderr, "already inited the bullshit....\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    }

    PyObject *pFuzzFunc = PyObject_GetAttrString(pModule, "fuzz");

    fprintf(stderr, "Calling fuzz...........\nCalling fuzz...........\nCalling fuzz...........\nCalling fuzz...........\nCalling fuzz...........\nCalling fuzz...........\nCalling fuzz...........\nCalling fuzz...........\nCalling fuzz...........\nCalling fuzz...........\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    //memcpy(0, buf, 10);
    if (pFuzzFunc && PyCallable_Check(pFuzzFunc)) {
        spam_string("Is callable\n");
        PyObject *pResult = PyObject_CallFunction(pFuzzFunc, "(y#)", buf, buf_size);
        if (pResult) {
            spam_string("Got result\n");
            char *new_buf;
            Py_ssize_t new_size;

            // Correct usage of PyBytes_AsStringAndSize
            if (PyBytes_AsStringAndSize(pResult, &new_buf, &new_size) == -1) {
                spam_string("PyBytes_AsStringAndSize failed\n");
                PyErr_Print();
                memcpy(0, buf, 10);
                Py_XDECREF(pResult);
                return 0;
            }

            out_buf = malloc(new_size);
            if (out_buf == NULL) {
                fprintf(stderr, "Error: Memory allocation failed\n");
                Py_XDECREF(pResult);
                return 0;
            }

            memcpy(out_buf, new_buf, new_size);
            //out_buf_size = (size_t)new_size;

            if (common_fuzz_stuff(argv, out_buf, new_size)) {
                bail = 1; // skip the rest of the mutation per common_fuzz_stuff
                //break;
            }

            Py_XDECREF(pResult);
            Py_XDECREF(pFuzzFunc);
            //Py_XDECREF(pModule);
            if (out_buf) {
                free(out_buf);
            }
            return bail;
        } else {
            spam_string("Didn't get result!!!!!!!!!!!!!!!!!\n");
            if (common_fuzz_stuff(argv, buf, buf_size)) {
                bail = 1; // skip the rest of the mutation per common_fuzz_stuff
                //break;
            }
        }
    }
    spam_string("Py_XDECREF pFuzzFunc!!!!!!!!!!!!!!!!!\n");
    Py_XDECREF(pFuzzFunc);
    spam_string("free out_buf!!!!!!!!!!!!!!!!!\n");
    //Py_XDECREF(pModule);
    if (out_buf) {
        free(out_buf);
    }
    spam_string("eeeeeeeeeeeee out_buf!!!!!!!!!!!!!!!!!\n");
    return bail;
}

// Cleanup
__declspec(dllexport) void afl_custom_deinit(void *data) {
    Py_Finalize();
}

```

and now I think we actually want to return one on purpose and see what happens...

```
copy C:\Users\elsku\winafl\winafl\python_mutator.dll .
```

Ok, so if we actually take a look at a working custom mutator example from winafl itself:

```

u8 dll_mutate_testcase(char **argv, u8 *buf, u32 len, u8 (*common_fuzz_stuff)(char**, u8*, u32))
{
    u8 bailout = 0;
    u8 *newbuf;
    u32 i;
    // duplicate the input buffer
    newbuf = malloc(len);
    if (!newbuf) return bailout;
    memcpy(newbuf, buf, len);
    // increment every byte by one and call common_fuzz_stuff for every new test case
    for (i = 0; i < len; i++) {
       newbuf[i] += 1;
       if (common_fuzz_stuff(argv, newbuf, len)) {
           bailout = 1; // skip the rest of the mutation per common_fuzz_stuff
           break;
       }
    }
    free(newbuf);
    return bailout;
}


```

Now we have basically two choices: We can either modify winafl itself to incorporate an environment variable for python fuzz only OR we can modify the mutator to run in a loop, this is some bullshit, but idk...

Let's take a look at original afl-fuzz and see the environment variables...

## Debugging some more of the debugger.

Just looking at the hex dumps, there doesn't really seem to be any mutating going on which is quite odd.

```

00000000: 01 00 00 00 6c 00 00 00 0f 00 00 00 00 00 00 00  ....l...........
00000010: 63 00 00 00 60 00 00 00 eb 00 00 00 00 00 00 00  c...`...........
00000020: 10 06 00 00 e0 05 00 00 20 45 4d 46 00 00 01 00  ........ EMF....
00000030: 60 02 00 00 09 00 00 00 01 00 00 00 00 00 00 00  `...............
00000040: 00 00 00 00 00 00 00 00 80 07 00 00 b0 04 00 00  ................
00000050: 2d 01 00 00 bc 00 00 00 00 00 00 00 00 00 00 00  -...............
00000060: 00 00 00 00 c8 97 04 00 60 de 02 00 46 00 00 00  ........`...F...
00000070: 2c 00 00 00 20 00 00 00 45 4d 46 2b 01 40 00 00  ,... ...EMF+.@..
00000080: 1c 00 00 00 10 00 00 00 02 10 c0 db 01 00 00 00  ................
00000090: 60 00 00 00 60 00 00 00 46 00 00 00 14 01 00 00  `...`...F.......
000000a0: 08 01 00 00 45 4d 46 2b 08 40 00 06 30 00 00 00  ....EMF+.@..0...
000000b0: 24 00 00 00 02 10 c0 db 00 00 20 42 02 00 00 00  $......... B....
000000c0: 04 00 00 00 00 00 00 00 05 00 00 00 41 00 52 00  ............A.R.
000000d0: 49 00 41 00 4c 00 00 00 08 40 01 07 48 00 00 00  I.A.L....@..H...
000000e0: 3c 00 00 00 02 10 c0 db 00 00 00 00 00 00 cb 85  <...............
000000f0: 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000100: 00 00 00 00 00 00 00 00 ab aa 2a 3e ab aa 2a 3e  ..........*>..*>
00000110: 0a d7 83 3f 01 00 00 00 00 00 00 00 00 00 00 00  ...?............
00000120: 08 40 02 01 3c 00 00 00 30 00 00 00 02 10 c0 db  .@..<...0.......
00000130: 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000140: 00 00 00 00 00 00 c8 42 00 00 c8 42 00 00 ff ff  .......B...B....
00000150: ff 00 00 ff 00 00 ff ff ff 00 00 ff 1c 40 00 00  .............@..
00000160: 50 00 00 00 44 00 00 00 02 00 00 00 01 00 00 00  P...D...........
00000170: 14 00 00 00 00 00 00 00 00 00 00 00 00 00 c8 42  ...............B
00000180: 00 00 c8 42 48 00 65 00 6c 00 6c 00 6f 00 20 00  ...BH.e.l.l.o. .
00000190: 57 00 6f 00 72 00 6c 00 64 00 20 00 31 00 20 00  W.o.r.l.d. .1. .
000001a0: 32 00 20 00 33 00 20 00 34 00 21 00 21 00 00 00  2. .3. .4.!.!...
000001b0: 08 00 00 00 62 00 00 00 0c 00 00 00 01 00 00 00  ....b...........
000001c0: 63 00 00 00 60 00 00 00 0f 00 00 00 00 00 00 00  c...`...........
000001d0: 55 00 00 00 61 00 00 00 29 00 aa 00 00 00 00 00  U...a...).......
000001e0: 00 00 00 00 00 00 80 3f 00 00 00 00 00 00 00 00  .......?........
000001f0: 00 00 80 3f 00 00 00 00 00 00 00 00 00 00 00 00  ...?............
00000200: 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000210: 00 00 00 00 22 00 00 00 0c 00 00 00 ff ff ff ff  ...."...........
00000220: 46 00 00 00 1c 00 00 00 10 00 00 00 45 4d 46 2b  F...........EMF+
00000230: 02 40 00 00 0c 00 00 00 00 00 00 00 0e 00 00 00  .@..............
00000240: 14 00 00 00 00 00 00 00 10 00 00 00 14 00 00 00  ................

```

this binary data doesn't get mutated in the custom mutator, so let's try to figure out why...



Let's try to use a generic byte mutator as a fallback and see if something happens?????

No that doesn't work.

Here is a thing:

```

oof@elskun-lppri:/mnt/c/Users/elsku$ ls outputs4/queue/
id_000000  id_000001

```

so we actually only have two things in the thing... , so therefore we run the thing once, so what if we initialize the thing on each iteration???

Like so???

Wait nevermind, I actually have this here:

```

def fuzz(buf):
	debugprint("Called theeeee mutator!!!!!")
	assert isinstance(buf, bytes) # Should be a bytearray
	orig_dat = copy.deepcopy(buf)
	print("="*20)
	print("Original data here:")
	hexdump(orig_dat)
	print("="*20)


	debugprint("="*20)
	debugprint("Original data here:")
	hexdumpdebug(buf)
	debugprint("="*20)

	debugprint("2!!!!!")


	orig_data = copy.deepcopy(buf)

	buf = bytes(buf)
	try:
		buf = mutate_emf(buf) # Mutate the EMF file...
		return buf
		if buf == orig_data: # Mutate generic.
			return generic_mutator_bytes.mutate_generic(buf)
	except:
		debugprint("EMF mutation failed!!!!! Falling back to generic mutator!")
		debugprint("Type of buffer before: "+str(type(buf)))
		buf = generic_mutator_bytes.mutate_generic(buf)
		debugprint("Type of buffer after: "+str(type(buf)))
		debugprint("Returning the generic mutated data.")
		#return buf
		return orig_data
	print("="*20)
	print("After mutation:")
	hexdump(buf)
	print("="*20)

	debugprint("="*20)
	debugprint("After mutation:")
	hexdumpdebug(buf)
	debugprint("="*20)

	debugprint("3!!!!!")
	assert isinstance(buf, bytes)
	debugprint("4!!!!!")
	#buf = bytearray(buf) # Convert back to bytearray
	debugprint("4!!!!!")



	# Now just do this such that we don't overflow the buffer...
	# buf = buf[:max_size]
	return buf # Return the mutated buffer

```

and we only get two files in the output. This probably means that we need to investigate the bullshit.

## Our fuzzer is shit

Ok, so the actual reason why we are not finding any coverage is because our mutator is shit and it actually isn't finding any coverage. This sucks donkey dick, because this means that all of our effort may be for fuck all.

## Adding more mutation strategies.

I think we should add a helper to the record objects which returns the mutable fields. Aka all of the fields which aren't the type or size.

Maybe something like this????

```

    def mutable_fields(self) -> list:
        # This method returns the fields which do NOT contain the type or size fields.
        assert "Type" in self.fields
        assert "Size" in self.fields
        o = self.fields # Now try to do the thing.
        o.remove("Type")
        o.remove("Size")
        assert "Type" not in self.fields
        assert "Size" not in self.fields
        return 0

```

## Cleaning up some shit..

Ok, so I think it is time to get rid of some old debug messages and shit like that....


Here is the old python custom mutator:

```

#include <Python.h>
#include <stdint.h>

typedef unsigned char (*common_fuzz_stuff_t)(char **, unsigned char *, unsigned int);

unsigned char has_inited = 0; // Have we inited the python environment??
PyObject *pModule = NULL; // Custom mutator module


void init_python(void) {
    Py_Initialize();
    PyObject* pName = PyUnicode_FromString("mutator");
    pModule = PyImport_Import(pName);
    Py_XDECREF(pName);

    if (!pModule) {
        if (PyErr_Occurred()) {
            PyErr_Print()
          exit(1);
        }
            fprintf(stderr, "Crashing in the init bullshit fuck......");
          exit(1);

        fprintf(stderr, "Crashing in the init bullshit fuck......");
        memcpy(0, 00, 10);
        //return 0;
    }
    fprintf(stderr, "Returning from the init function..........");
    has_inited = 1;
    return;
}

/*
void print_python_error_to_stderr() {
    fprintf(stderr, "fuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuck...\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    if (PyErr_Occurred()) {
        PyObject *ptype, *pvalue, *ptraceback;

        // Fetch the error information
        PyErr_Fetch(&ptype, &pvalue, &ptraceback);
        PyErr_NormalizeException(&ptype, &pvalue, &ptraceback);

        // Convert the error value to a string
        if (pvalue) {
            PyObject *pStr = PyObject_Str(pvalue);  // Get the string representation of the error
            if (pStr) {
                const char *error_message = PyUnicode_AsUTF8(pStr);  // Convert to UTF-8
                if (error_message) {
                    fprintf(stderr, "Python error: %s\n", error_message);
                }
                Py_DECREF(pStr);  // Decrement reference count
            }
        }

        // Clean up
        Py_XDECREF(ptype);
        Py_XDECREF(pvalue);
        Py_XDECREF(ptraceback);

        // Clear the Python error indicator
        PyErr_Clear();
    }
}
*/

void spam_string(const char* string) {
    for (int i = 0; i < 100; i++) {
        fprintf(stderr, string);
    }
    return;
}

//unsigned char dll_mutate_testcase(char **argv, u8 *buf, u32 len, u8 (*common_fuzz_stuff)(char**, u8*, u32)) {
__declspec(dllexport) unsigned char dll_mutate_testcase(char** argv, unsigned char *buf, unsigned int buf_size, common_fuzz_stuff_t common_fuzz_stuff) {   // void* common_fuzz_stuff) { // common_fuzz_stuff is just some bullshit stuff.
    char* out_buf = NULL; // Output buffer. Avoid uninitialized memory here.
    unsigned char bail = 0; // Init at zero
    unsigned int* out_buf_size;
    spam_string("Called again..\n");
    //if (!(has_inited)) {


    if (!has_inited) {
        spam_string("wasn't initigedfefwefwewe again..\n");
        init_python();

    }


    // init_python
    if (pModule == NULL) {
        spam_string("wasn't initigedfefwefwewe again..\n");
        memcpy(0, buf, 10);
        // init_python();

    }
    /*
    if (pModule == NULL) {
        spam_string("wasn't initigedfefwefwewe again..\n");
        init_python();

    }
    */


    //int x = 0 / 0; // Zero division exception.
    /*
    if (!pModule) {
        //print_python_error_to_stderr();
        PyErr_Print();
        memcpy(0, buf, 10);
        return 0;
    } else {
        fprintf(stderr, "already inited the bullshit....\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    }
    */

    PyObject *pFuzzFunc = PyObject_GetAttrString(pModule, "fuzz");

    fprintf(stderr, "Calling fuzz...........\nCalling fuzz...........\nCalling fuzz...........\nCalling fuzz...........\nCalling fuzz...........\nCalling fuzz...........\nCalling fuzz...........\nCalling fuzz...........\nCalling fuzz...........\nCalling fuzz...........\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    //memcpy(0, buf, 10);
    if (pFuzzFunc && PyCallable_Check(pFuzzFunc)) {
        spam_string("Is callable\n");
        PyObject *pResult = PyObject_CallFunction(pFuzzFunc, "(y#)", buf, buf_size);
        spam_string("Got result..\n");
        if (pResult) {
            spam_string("qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\n");
            char *new_buf;
            Py_ssize_t new_size;

            // Correct usage of PyBytes_AsStringAndSize
            if (PyBytes_AsStringAndSize(pResult, &new_buf, &new_size) == -1) {
                spam_string("PyBytes_AsStringAndSize failed\n");
                PyErr_Print();
                memcpy(0, buf, 10);
                Py_XDECREF(pResult);
                return 0;
            }

            out_buf = malloc(new_size);
            if (out_buf == NULL) {
                spam_string("Mem alloc failedefefefefefee\n");
                fprintf(stderr, "Error: Memory allocation failed\n");
                Py_XDECREF(pResult);
                memcpy(0, buf, 10);
                return 0;
            }

            memcpy(out_buf, new_buf, new_size);
            //out_buf_size = (size_t)new_size;

            if (common_fuzz_stuff(argv, out_buf, new_size)) {
                bail = 1; // skip the rest of the mutation per common_fuzz_stuff
                //break;
            }

            Py_XDECREF(pResult);
            Py_XDECREF(pFuzzFunc);
            // Py_XDECREF(pModule);
            if (out_buf) {
                free(out_buf);
            }
            spam_string("We executed the thing!!!!!!!!!!!!!!\n");
            return bail;
        } else {
            spam_string("Didn't get result!!!!!!!!!!!!!!!!!\n");
            spam_string("Didn't get result!!!!!!!!!!!!!!!!!\n");
            spam_string("Didn't get result!!!!!!!!!!!!!!!!!\n");
            memcpy(0, buf, 10); // Just crash here
            spam_string("Didn't get result!!!!!!!!!!!!!!!!!\n");
            if (common_fuzz_stuff(argv, buf, buf_size)) {
                bail = 1; // skip the rest of the mutation per common_fuzz_stuff
                //break;
            }
        }
    }
    spam_string("Wasn't callable!!\n");
    memcpy(0, buf, 10);
    spam_string("Py_XDECREF pFuzzFunc!!!!!!!!!!!!!!!!!\n");
    Py_XDECREF(pFuzzFunc);
    spam_string("free out_buf!!!!!!!!!!!!!!!!!\n");
    // Py_XDECREF(pModule);
    if (out_buf) {
        free(out_buf);
    }
    spam_string("eeeeeeeeeeeee out_buf!!!!!!!!!!!!!!!!!\n");
    spam_string("We executed the thing!!!!!!!!!!!!!!\n");
    return bail;
}

// Cleanup
__declspec(dllexport) void afl_custom_deinit(void *data) {
    Py_Finalize();
}

```

Here is a cleaned up version of it:

```


#include <Python.h>
#include <stdint.h>

typedef unsigned char (*common_fuzz_stuff_t)(char **, unsigned char *, unsigned int);

unsigned char has_inited = 0; // Have we inited the python environment??
PyObject *pModule = NULL; // Custom mutator module


void init_python(void) {
    Py_Initialize();
    PyObject* pName = PyUnicode_FromString("mutator");
    pModule = PyImport_Import(pName);
    Py_XDECREF(pName);

    if (!pModule) {
        if (PyErr_Occurred()) {
            PyErr_Print()
          exit(1);
        }
            fprintf(stderr, "Crashing in the init bullshit fuck......");
          exit(1);

        fprintf(stderr, "Crashing in the init bullshit fuck......");
        memcpy(0, 00, 10);
        //return 0;
    }
    fprintf(stderr, "Returning from the init function..........");
    has_inited = 1;
    return;
}

void spam_string(const char* string) {
    for (int i = 0; i < 100; i++) {
        fprintf(stderr, string);
    }
    return;
}

//unsigned char dll_mutate_testcase(char **argv, u8 *buf, u32 len, u8 (*common_fuzz_stuff)(char**, u8*, u32)) {
__declspec(dllexport) unsigned char dll_mutate_testcase(char** argv, unsigned char *buf, unsigned int buf_size, common_fuzz_stuff_t common_fuzz_stuff) {   // void* common_fuzz_stuff) { // common_fuzz_stuff is just some bullshit stuff.
    char* out_buf = NULL; // Output buffer. Avoid uninitialized memory here.
    unsigned char bail = 0; // Init at zero
    unsigned int* out_buf_size;
    //if (!(has_inited)) {


    if (!has_inited) {
        spam_string("wasn't initigedfefwefwewe again..\n");
        init_python();

    }


    // init_python
    if (pModule == NULL) {
        spam_string("wasn't initigedfefwefwewe again..\n");
        memcpy(0, buf, 10);
        // init_python();

    }

    PyObject *pFuzzFunc = PyObject_GetAttrString(pModule, "fuzz");
    //memcpy(0, buf, 10);
    if (pFuzzFunc && PyCallable_Check(pFuzzFunc)) {
        PyObject *pResult = PyObject_CallFunction(pFuzzFunc, "(y#)", buf, buf_size);
        if (pResult) {
            char *new_buf;
            Py_ssize_t new_size;

            // Correct usage of PyBytes_AsStringAndSize
            if (PyBytes_AsStringAndSize(pResult, &new_buf, &new_size) == -1) {
                spam_string("PyBytes_AsStringAndSize failed\n");
                PyErr_Print();
                memcpy(0, buf, 10);
                Py_XDECREF(pResult);
                return 0;
            }

            out_buf = malloc(new_size);
            if (out_buf == NULL) {
                spam_string("Mem alloc failedefefefefefee\n");
                fprintf(stderr, "Error: Memory allocation failed\n");
                Py_XDECREF(pResult);
                memcpy(0, buf, 10);
                return 0;
            }

            memcpy(out_buf, new_buf, new_size);
            //out_buf_size = (size_t)new_size;

            if (common_fuzz_stuff(argv, out_buf, new_size)) {
                bail = 1; // skip the rest of the mutation per common_fuzz_stuff
                //break;
            }

            Py_XDECREF(pResult);
            Py_XDECREF(pFuzzFunc);
            // Py_XDECREF(pModule);
            if (out_buf) {
                free(out_buf);
            }
            return bail;
        } else {
            memcpy(0, buf, 10); // Just crash here
            if (common_fuzz_stuff(argv, buf, buf_size)) {
                bail = 1; // skip the rest of the mutation per common_fuzz_stuff
                //break;
            }
        }
    }
    spam_string("Wasn't callable!!\n");
    memcpy(0, buf, 10);
    spam_string("Py_XDECREF pFuzzFunc!!!!!!!!!!!!!!!!!\n");
    Py_XDECREF(pFuzzFunc);
    // Py_XDECREF(pModule);
    if (out_buf) {
        free(out_buf);
    }
    spam_string("eeeeeeeeeeeee out_buf!!!!!!!!!!!!!!!!!\n");
    spam_string("We executed the thing!!!!!!!!!!!!!!\n");
    return bail;
}

// Cleanup
__declspec(dllexport) void afl_custom_deinit(void *data) {
    Py_Finalize();
}
```

Then I think the next step to do is fixup my horrible python code...

Here is my cleaned up code:

```

#include <Python.h>
#include <stdint.h>

typedef unsigned char (*common_fuzz_stuff_t)(char **, unsigned char *, unsigned int);

unsigned char has_inited = 0; // Have we inited the python environment??
PyObject *pModule = NULL; // Custom mutator module

void init_python(void) {
    Py_Initialize();
    PyObject* pName = PyUnicode_FromString("mutator");
    pModule = PyImport_Import(pName);
    Py_XDECREF(pName);

    if (!pModule) {
        memcpy(0, 00, 10);
    }
    has_inited = 1;
    return;
}

void spam_string(const char* string) {
    for (int i = 0; i < 100; i++) {
        fprintf(stderr, string);
    }
    return;
}

//unsigned char dll_mutate_testcase(char **argv, u8 *buf, u32 len, u8 (*common_fuzz_stuff)(char**, u8*, u32)) {
__declspec(dllexport) unsigned char dll_mutate_testcase(char** argv, unsigned char *buf, unsigned int buf_size, common_fuzz_stuff_t common_fuzz_stuff) {   // void* common_fuzz_stuff) { // common_fuzz_stuff is just some bullshit stuff.
    char* out_buf = NULL; // Output buffer. Avoid uninitialized memory here.
    unsigned char bail = 0; // Init at zero
    unsigned int* out_buf_size;
    if (!has_inited) {
        init_python();
    }
    if (pModule == NULL) {
        memcpy(0, buf, 10);
    }

    PyObject *pFuzzFunc = PyObject_GetAttrString(pModule, "fuzz");
    if (pFuzzFunc && PyCallable_Check(pFuzzFunc)) {
        PyObject *pResult = PyObject_CallFunction(pFuzzFunc, "(y#)", buf, buf_size);
        if (pResult) {
            char *new_buf;
            Py_ssize_t new_size;
            // Correct usage of PyBytes_AsStringAndSize
            if (PyBytes_AsStringAndSize(pResult, &new_buf, &new_size) == -1) {
                PyErr_Print();
                memcpy(0, buf, 10);
                Py_XDECREF(pResult);
                return 0;
            }

            out_buf = malloc(new_size);
            if (out_buf == NULL) {
                Py_XDECREF(pResult);
                memcpy(0, buf, 10);
                return 0;
            }

            memcpy(out_buf, new_buf, new_size);
            if (common_fuzz_stuff(argv, out_buf, new_size)) {
                bail = 1; // skip the rest of the mutation per common_fuzz_stuff
                //break;
            }

            Py_XDECREF(pResult);
            Py_XDECREF(pFuzzFunc);
            // Py_XDECREF(pModule);
            if (out_buf) {
                free(out_buf);
            }
            return bail;
        } else {
            memcpy(0, buf, 10); // Just crash here
            if (common_fuzz_stuff(argv, buf, buf_size)) {
                bail = 1; // skip the rest of the mutation per common_fuzz_stuff
                //break;
            }
        }
    }
    memcpy(0, buf, 10);
    Py_XDECREF(pFuzzFunc);
    // Py_XDECREF(pModule);
    if (out_buf) {
        free(out_buf);
    }
    return bail;
}

// Cleanup
__declspec(dllexport) void afl_custom_deinit(void *data) {
    Py_Finalize();
}

```

I am getting roughly 100 execs a second on my machine with the custom mutator which was similar to when running without so I don't think the performance overhead is that bad... but idk..

## Adding even better mut strategies...

I think we should also check if the mutated EMF files are structurally valid by using a C program which tries to actually load it with gdiplus and sees if it get's compiled.


```
cmake -A Win32 .. -DDynamoRIO_DIR=C:\Users\elsku\dynamorio2\DynamoRIO-Windows-11.3.0-1\cmake -DINTELPT=1 -DUSE_COLOR=1

 cmake --build . --config Release
```

Here is a program which checks if the image is actually valid or not:

```




#define _CRT_SECURE_NO_WARNINGS // Just shut up compiler warnings

#include <stdio.h>
#include <windows.h>
#include <gdiplus.h>

using namespace Gdiplus;

wchar_t* charToWChar(const char* text)
{
	size_t size = strlen(text) + 1;
	wchar_t* wa = new wchar_t[size];
	mbstowcs(wa, text, size);
	return wa;
}




int main(int argc, char** argv)
{
	/*
	GdiplusStartupInput gdiplusStartupInput;
	GdiplusStartupOutput gdiplusStartupOutput;
	ULONG_PTR gdiplusToken = 0;
	*/
	if (argc < 2) {
		printf("Usage: %s <image file>\n", argv[0]);
		return 0;
	}

	GdiplusStartupInput gdiplusStartupInput;
	ULONG_PTR gdiplusToken;
	GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

	wchar_t* fname = charToWChar(argv[1]);

	// Main persistent loop here
	Image* image = NULL;
	Image* thumbnail = NULL;
	int ret = 0;
	image = new Image(fname);
	if (image && (Ok == image->GetLastStatus())) {
		//printf("Image loaded\n");
		thumbnail = image->GetThumbnailImage(100, 100, NULL, NULL);
		printf("Valid\n");
		if (thumbnail && (Ok == thumbnail->GetLastStatus())) {
			printf("Valid\n");
			ret = 0; // Return value is zero
		}


	}
	else {
		printf("Invalid\n");
		ret = 1;
	}

	//printf("Done\n");

	if (image) delete image;
	if (thumbnail) delete thumbnail;

	GdiplusShutdown(gdiplusToken);


	return ret;
}




```

## Fixing extra data bullshit...

Ok, so I downloaded the example from microsoft from here:  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-emf/2d7b37b4-e170-42f6-bd0b-3638d456549c and when trying to parse it, I get the following output:

```

orig_data[:header_object.nSize[1]] == b'\x01\x00\x00\x00\xd4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Y\x00\x00\x00Y\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00B\x0c\x00\x00A\x0c\x00\x00 EMF\x00\x00\x01\x00\xfc7\x00\x00\x16\x00\x00\x00\x05\x00\x00\x004\x00\x00\x00l\x00\x00\x00\x00\x00\x00\x00\x80\x07\x00\x00\xb0\x04\x00\x00\xa5\x02\x00\x00\xa7\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd5U\n\x00\xa5u\x06\x00S\x00a\x00m\x00p\x00l\x00e\x00 \x00E\x00M\x00F\x00 \x00t\x00h\x00a\x00t\x00 \x00h\x00a\x00s\x00 \x00a\x00 \x00b\x00r\x00u\x00s\x00h\x00 \x00f\x00i\x00l\x00l\x00,\x00 \x00b\x00i\x00t\x00m\x00a\x00p\x00,\x00 \x00a\x00n\x00d\x00 \x00t\x00e\x00x\x00t\x00\x00\x00\x00\x00'
serialized_data == b'\x01\x00\x00\x00\xd4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Y\x00\x00\x00Y\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00B\x0c\x00\x00A\x0c\x00\x00 EMF\x00\x00\x01\x00\xfc7\x00\x00\x16\x00\x00\x00\x05\x00\x00\x004\x00\x00\x00l\x00\x00\x00\x00\x00\x00\x00\x80\x07\x00\x00\xb0\x04\x00\x00\xa5\x02\x00\x00\xa7\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd5U\n\x00\xa5u\x06\x00'
serialized_data length: 108
orig_data[:header_object.nSize[1]] length: 212
Traceback (most recent call last):
  File "/home/oof/emf_parser/parser.py", line 100, in <module>
    test_parser()
  File "/home/oof/emf_parser/parser.py", line 83, in test_parser
    emf_obj = parse_emf_file(data)
              ^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_parser/emf_file.py", line 71, in parse_emf_file
    h, rest_of_data = parse_header(data)
                      ^^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_parser/emf_file.py", line 14, in parse_header
    h, restofdata = read_header(data) # Read the header from the data...
                    ^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_parser/header.py", line 26, in read_header
    assert serialized_data == orig_data[:header_object.nSize[1]] # Cut first header_object.nSize[1] bytes, because that is the actual value of the header...
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AssertionError

```

So therefore there seems to be bug in parsing of extra data in the headers and stuff.

This bug was caused by an invalid template script which handled the extradata incorrectly, I fixed it and now it seems to be working just fine...

## Making a mutator for extra data.

Ok, so now I have this idea of mutating the extra data in the records. The extra data is assumed to be at the end of the record (if it exists).

The extra data mutation could be implemented with the generic mutator which we have whipped up. The challenging part of this mutation is fixing up the size field after such a mutation. This is actually a mutation which vanilla winafl most likely misses, because when adding or removing bytes from the extra data, it is very unlikely that the vanilla fuzzer fixes up the size field correctly too, therefore this leads to rejection of the input in the parsing stage of GDI+.

Maybe try mutating like so?

```

def mutate_extra_data(record) -> None: # This function mutates extra data in
	assert record.has_variable

	orig_data = copy.deepcopy(record.remaining_data)
	orig_len = len(orig_data)
	new_data = generic_mutator_bytes.mutate_generic(orig_data) # Call the generic byte mutator
	# Now try to fix up the length field such that it works
	diff = len(new_data) - orig_len # Difference
	# Set the values
	record.remaining_data = new_data
	assert hasattr(record, 'Size') # Should have the size stuff
	record.nSize += diff # Add (or subtract) the difference.
	return

```

Let's try it out... ok, so this seems to work fine.

## Adding a mutator for generating random records.

Ok, so now I am going to make a generator for creating random records out of thin air. I have this idea of choosing a random record type and then just adding the corresponding bytes. This should result in a valid random record.

There is the smart way of doing this and then the not-so-smart way. See, I think that if we try to unpack after there is no longer data, we get an exception, so what we can do is just have a for loop which checks for exceptions and if an exception occurs, then we can just add a 0xff byte for example. If we don't get an exception, then we know we have reached a valid length for that type of record. After that we could check for if the record has extra data, if yes, then just append like 50 0xff bytes for the extra data field.

Maybe something like this????

```


def add_random_record(obj: EMFFile) -> None: # Generates a random record for this EMF file and appends it somewhere in the file.
    # Lookup a random record type.
    # If you look at https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-emf/1eec80ba-799b-4784-a9ac-91597d590ae1 the maximum record type is 0x7a .

    rec_type = random.randrange(2, 0x7a+1) # record type 1 is the header type, so don't bother generating another header.
    rec_name = record_types.EMR_NAMES[rec_type] # This is the string representation of the thing.
    rec_class = getattr(autogenerated, rec_name) # Get the actual class.
    length = 8
    added_bytes = b"" # The bytes which we have added.
    while True:
        # autogenerated.
        # Try to initialize the record object. If this causes an exception, then we have the wrong number of bytes.
        all_bytes = struct.pack("I", rec_type) + struct.pack("I", length) + added_bytes
        assert len(all_bytes) == length # Should match.
        try:

            rec_obj = rec_class(all_bytes) # Try to initialize the thing...
        except:
            # Try to add a random byte maybe???
            added_bytes += bytes([random.randrange(0,256)]) # Add one byte.
            length += 1 # Add one.
            continue
        # No exception. We now have a (length-wise) valid record. Now we can check for extra data and add some if we want
        if rec_obj.has_variable:
            assert rec_obj.variable_data == b"" # Should be empty as of now.
            rand_data = os.urandom(random.randrange(MUT_MIN_RAND_EXTRA_DATA_LEN, MUT_MAX_RAND_EXTRA_DATA_LEN+1))
            rec_obj.variable_data = rand_data # Assign the extra data.
            # Fixup the length.
            diff = len(rand_data)
            rec_obj.Size = (rec_obj.Size[0], rec_obj.Size[1] + diff) # Fixup the length.
        break
    assert len(rec_obj.serialize()) == rec_obj.Size[1] # Should actually match.
    # Now add the newly generated record somewhere to the object.
    index = random.randint(0, len(obj.records))  # Random index in the range [0, len(lst)]
    obj.records.insert(index, copy.deepcopy(rec_obj)) # Insert the randomly generated value into the records in the object.
    return

```

## Figuring out some stuff.

Ok, so after fuzzing a test run, I noticed that the reason why we aren't getting any coverage is because in the serialization, we actually need to patch the header too, because it tells the amount of bytes and then number of records in the file, but I am not patching those, so therefore it causes shit to not work, so let's do that.

I think I am going to implement a so called "Fix header" function, which as the name implies tries to fix the header such that the file is actually valid.

These are the fields in the header:

```

 fields = ['iType', 'nSize', 'rclBounds', 'rclFrame', 'dSignature', 'nVersion', 'nBytes', 'nRecords', 'nHandles', 'sReserved', 'nDescription', 'offDescription', 'nPalEntries', 'szlDevice', 'szlMillimeters', 'cbPixelFormat', 'offPixelFormat', 'bOpenGL', 'szlMicrometers']

```

the nBytes and nRecords are the ones which we want to modify.

## Benchmarking

Ok, so how many of these files which we mutate are actually valid EMF for a parser?

Let's copy our binary over which checks for validity and program a quick benchmark and see what kind of stuff happens..

Ok, so after benchmarking, it looks like this program seems to actually produce 100% valid EMF!!!! This is good.

## Making the python mutator faster

First of all, we enter a trimming stage right after finding one good result. This is because we should have a loop in our dll adapter custom thing.


```

#include <Python.h>
#include <stdint.h>

typedef unsigned char (*common_fuzz_stuff_t)(char **, unsigned char *, unsigned int);

unsigned char has_inited = 0; // Have we inited the python environment??
PyObject *pModule = NULL; // Custom mutator module

void init_python(void) {
    Py_Initialize();
    PyObject* pName = PyUnicode_FromString("mutator");
    pModule = PyImport_Import(pName);
    Py_XDECREF(pName);

    if (!pModule) {
        memcpy(0, 00, 10);
    }
    has_inited = 1;
    return;
}

void spam_string(const char* string) {
    for (int i = 0; i < 100; i++) {
        fprintf(stderr, string);
    }
    return;
}

//unsigned char dll_mutate_testcase(char **argv, u8 *buf, u32 len, u8 (*common_fuzz_stuff)(char**, u8*, u32)) {
__declspec(dllexport) unsigned char dll_mutate_testcase(char** argv, unsigned char *buf, unsigned int buf_size, common_fuzz_stuff_t common_fuzz_stuff) {   // void* common_fuzz_stuff) { // common_fuzz_stuff is just some bullshit stuff. 
    char* out_buf = NULL; // Output buffer. Avoid uninitialized memory here.
    unsigned char bail = 0; // Init at zero
    unsigned int* out_buf_size;
    if (!has_inited) {
        init_python();
    }
    if (pModule == NULL) {
        memcpy(0, buf, 10);
    }

    PyObject *pFuzzFunc = PyObject_GetAttrString(pModule, "fuzz");
    if (pFuzzFunc && PyCallable_Check(pFuzzFunc)) {
        PyObject *pResult = PyObject_CallFunction(pFuzzFunc, "(y#)", buf, buf_size);
        if (pResult) {
            char *new_buf;
            Py_ssize_t new_size;
            // Correct usage of PyBytes_AsStringAndSize
            if (PyBytes_AsStringAndSize(pResult, &new_buf, &new_size) == -1) {
                PyErr_Print();
                memcpy(0, buf, 10);
                Py_XDECREF(pResult);
                return 0;
            }

            out_buf = malloc(new_size);
            if (out_buf == NULL) {
                Py_XDECREF(pResult);
                memcpy(0, buf, 10);
                return 0;
            }

            memcpy(out_buf, new_buf, new_size);
            if (common_fuzz_stuff(argv, out_buf, new_size)) {
                bail = 1; // skip the rest of the mutation per common_fuzz_stuff
                break;
            }

            Py_XDECREF(pResult);
            Py_XDECREF(pFuzzFunc);
            // Py_XDECREF(pModule);
            if (out_buf) {
                free(out_buf);
            }
            return bail;
        } else {
            memcpy(0, buf, 10); // Just crash here
            if (common_fuzz_stuff(argv, buf, buf_size)) {
                bail = 1; // skip the rest of the mutation per common_fuzz_stuff
                //break;
            }
        }
    }
    return bail;
    /*
    memcpy(0, buf, 10);
    Py_XDECREF(pFuzzFunc);
    // Py_XDECREF(pModule);
    if (out_buf) {
        free(out_buf);
    }
    return bail;
    */

}

// Cleanup
__declspec(dllexport) void afl_custom_deinit(void *data) {
    Py_Finalize();
}

```

## Profiling the code...

Here is the cProfile stuff:

```

         4845991 function calls (4845209 primitive calls) in 41.332 seconds

   Ordered by: internal time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
      202   21.583    0.107   21.583    0.107 {method 'poll' of 'select.poll' objects}
    90677    8.904    0.000    8.904    0.000 {method 'close' of '_io.TextIOWrapper' objects}
    90577    4.787    0.000    4.861    0.000 {built-in method _io.open}
      100    1.687    0.017   18.838    0.188 debug.py:33(hexdumpdebug)
   179489    1.260    0.000    3.065    0.000 {method 'join' of 'str' objects}
  1522800    1.093    0.000    1.093    0.000 debug.py:43(<genexpr>)
  1522800    0.559    0.000    0.712    0.000 debug.py:46(<genexpr>)
    90276    0.352    0.000   14.197    0.000 debug.py:1(debugprint)
   648200    0.153    0.000    0.153    0.000 {built-in method builtins.chr}
   180552    0.117    0.000    0.117    0.000 {method 'write' of '_io.TextIOWrapper' objects}
     1374    0.117    0.000    0.117    0.000 {built-in method builtins.print}
      100    0.092    0.001    0.092    0.001 {built-in method _posixsubprocess.fork_exec}
    90276    0.051    0.000    0.051    0.000 <frozen codecs>:186(__init__)
      200    0.029    0.000    0.043    0.000 autogenerated.py:107(__init__)
      300    0.024    0.000    0.225    0.001 emf_file.py:53(serialize)
    90276    0.023    0.000    0.023    0.000 <frozen codecs>:214(setstate)
      800    0.021    0.000    0.030    0.000 autogenerated.py:6498(__init__)
     2400    0.021    0.000    0.029    0.000 autogenerated.py:6556(serialize)
      100    0.020    0.000    0.020    0.000 {method 'close' of '_io.BufferedWriter' objects}
      100    0.018    0.000    0.027    0.000 emfheader_ext2.py:13(__init__)
      100    0.018    0.000    0.027    0.000 emfheader.py:13(__init__)
    33363    0.018    0.000    0.018    0.000 {method 'to_bytes' of 'int' objects}
     1210    0.018    0.000    0.122    0.000 autogenerated.py:6015(serialize)
      100    0.015    0.000    0.015    0.000 {method 'write' of '_io.BufferedWriter' objects}
      603    0.015    0.000    0.023    0.000 autogenerated.py:165(serialize)
    36188    0.015    0.000    0.015    0.000 {built-in method builtins.getattr}
      100    0.014    0.000    0.145    0.001 emf_file.py:23(parse_records)
      100    0.012    0.000   21.637    0.216 subprocess.py:2062(_communicate)
      405    0.012    0.000    0.016    0.000 autogenerated.py:5957(__init__)
    47692    0.010    0.000    0.010    0.000 autogenerated.py:3(to_unsigned)
24970/24956    0.009    0.000    0.009    0.000 {built-in method builtins.len}
      300    0.008    0.000    0.008    0.000 {built-in method posix.pipe}
    16490    0.008    0.000    0.008    0.000 {built-in method _struct.unpack}
      100    0.007    0.000   19.430    0.194 mutator.py:214(fuzz)
      202    0.007    0.000   21.591    0.107 selectors.py:402(select)
    21201    0.007    0.000    0.008    0.000 {built-in method builtins.isinstance}
    31864    0.007    0.000    0.007    0.000 {built-in method _struct.calcsize}
      300    0.007    0.000    0.010    0.000 autogenerated.py:6318(__init__)
    17154    0.007    0.000    0.007    0.000 {method 'append' of 'list' objects}
    13262    0.006    0.000    0.007    0.000 {built-in method builtins.setattr}
      100    0.006    0.000    0.144    0.001 subprocess.py:807(__init__)
      900    0.006    0.000    0.009    0.000 autogenerated.py:6376(serialize)
    13248    0.006    0.000    0.006    0.000 {built-in method from_bytes}
    13194    0.006    0.000    0.006    0.000 {built-in method builtins.all}
      200    0.006    0.000    0.009    0.000 emfheader_ext2.py:54(serialize)
      100    0.005    0.000    0.008    0.000 autogenerated.py:2177(__init__)
      100    0.005    0.000    0.119    0.001 subprocess.py:1791(_execute_child)
      100    0.005    0.000    0.005    0.000 {built-in method posix.waitpid}
      100    0.005    0.000    0.007    0.000 autogenerated.py:5327(__init__)
 1106/546    0.005    0.000    0.010    0.000 copy.py:118(deepcopy)
       18    0.005    0.000    0.005    0.000 {built-in method marshal.loads}
      400    0.004    0.000    0.004    0.000 {built-in method posix.read}
      100    0.004    0.000    0.006    0.000 autogenerated.py:1457(__init__)
      100    0.004    0.000   21.788    0.218 subprocess.py:506(run)
      100    0.004    0.000   21.804    0.218 validity_benchmark.py:15(valid)
      303    0.003    0.000    0.005    0.000 autogenerated.py:2235(serialize)
      400    0.003    0.000    0.003    0.000 {built-in method posix.close}
      131    0.003    0.000    0.004    0.000 {built-in method builtins.__build_class__}
      300    0.003    0.000    0.004    0.000 autogenerated.py:1515(serialize)
       22    0.003    0.000    0.017    0.001 mutator.py:67(add_random_record)
      300    0.003    0.000    0.004    0.000 autogenerated.py:5385(serialize)
        1    0.003    0.003   41.301   41.301 validity_benchmark.py:25(run_benchmark)
      100    0.003    0.000    0.004    0.000 autogenerated.py:7938(__init__)
      100    0.003    0.000    0.009    0.000 subprocess.py:1282(_close_pipe_fds)
      100    0.003    0.000    0.061    0.001 header.py:8(read_header)
    10800    0.002    0.000    0.002    0.000 emfheader_ext2.py:3(to_unsigned)
      200    0.002    0.000    0.004    0.000 <frozen posixpath>:179(dirname)
     1302    0.002    0.000    0.003    0.000 random.py:242(_randbelow_with_getrandbits)
     8800    0.002    0.000    0.002    0.000 emfheader.py:3(to_unsigned)
      100    0.002    0.000    0.010    0.000 subprocess.py:1688(_get_handles)
      300    0.002    0.000    0.003    0.000 autogenerated.py:7996(serialize)
     2100    0.002    0.000    0.004    0.000 emf_file.py:20(lookup_emr_record_class)
       30    0.002    0.000    0.002    0.000 <frozen importlib._bootstrap>:426(_get_module_lock)
      200    0.002    0.000    0.004    0.000 selectors.py:234(register)
      200    0.002    0.000    0.006    0.000 selectors.py:365(unregister)
      400    0.002    0.000    0.004    0.000 selectors.py:21(_fileobj_to_fd)
      200    0.002    0.000    0.003    0.000 contextlib.py:530(callback)
     2531    0.002    0.000    0.002    0.000 {method 'get' of 'dict' objects}
      550    0.002    0.000    0.004    0.000 random.py:291(randrange)
      100    0.001    0.000    0.485    0.005 mutator.py:179(mutate_emf)
      300    0.001    0.000    0.007    0.000 subprocess.py:2021(_wait)
      400    0.001    0.000    0.001    0.000 {method 'fileno' of '_io.TextIOWrapper' objects}
      100    0.001    0.000    0.150    0.001 mutator.py:198(fixup_header)
      100    0.001    0.000   21.639    0.216 subprocess.py:1165(communicate)
      200    0.001    0.000    0.001    0.000 <frozen codecs>:309(__init__)
      100    0.001    0.000    0.002    0.000 contextlib.py:567(__exit__)
      200    0.001    0.000    0.006    0.000 selectors.py:351(register)
      200    0.001    0.000    0.001    0.000 contextlib.py:548(_push_exit_callback)
      100    0.001    0.000    0.208    0.002 emf_file.py:70(parse_emf_file)
       94    0.001    0.000    0.001    0.000 {built-in method posix.stat}
     1358    0.001    0.000    0.001    0.000 {built-in method builtins.id}
       35    0.001    0.000    0.002    0.000 random.py:350(shuffle)
      100    0.001    0.000    0.002    0.000 selectors.py:347(__init__)
       44    0.001    0.000    0.003    0.000 <frozen importlib._bootstrap_external>:1593(find_spec)
       19    0.001    0.000    0.001    0.000 {method 'read' of '_io.BufferedReader' objects}
       18    0.001    0.000    0.005    0.000 <frozen importlib._bootstrap_external>:751(_compile_bytecode)
      300    0.001    0.000    0.001    0.000 selectors.py:275(_key_from_fd)
      100    0.001    0.000    0.002    0.000 contextlib.py:299(helper)
      101    0.001    0.000    0.001    0.000 {built-in method builtins.sorted}
        3    0.001    0.000    0.001    0.000 enum.py:1708(convert_class)
      100    0.001    0.000    0.001    0.000 contextlib.py:104(__init__)
      100    0.001    0.000    0.001    0.000 selectors.py:209(__init__)
      100    0.001    0.000    0.001    0.000 subprocess.py:361(_text_encoding)
       18    0.001    0.000    0.001    0.000 {built-in method _io.open_code}
      302    0.001    0.000    0.001    0.000 {built-in method __new__ of type object at 0xa44b40}
      100    0.001    0.000    0.001    0.000 {built-in method _abc._abc_instancecheck}
      200    0.001    0.000    0.001    0.000 {built-in method builtins.next}
      400    0.001    0.000    0.004    0.000 selectors.py:215(_fileobj_lookup)
     2140    0.001    0.000    0.001    0.000 {method 'getrandbits' of '_random.Random' objects}
      200    0.001    0.000    0.004    0.000 selectors.py:247(unregister)
      100    0.001    0.000    0.043    0.000 mutator.py:159(mutate_emf_obj)
      100    0.001    0.000    0.001    0.000 subprocess.py:1092(__exit__)
      200    0.001    0.000    0.001    0.000 subprocess.py:1085(_translate_newlines)
       25    0.001    0.000    0.001    0.000 autogenerated.py:5597(__init__)
       94    0.001    0.000    0.001    0.000 copy.py:200(_deepcopy_tuple)
      100    0.001    0.000    0.001    0.000 {built-in method _locale.getencoding}
      300    0.001    0.000    0.008    0.000 subprocess.py:1259(wait)
      100    0.001    0.000    0.001    0.000 contextlib.py:481(__init__)
     1302    0.001    0.000    0.001    0.000 {method 'bit_length' of 'int' objects}
      250    0.001    0.000    0.001    0.000 <frozen importlib._bootstrap_external>:126(_path_join)
      100    0.000    0.000    0.001    0.000 contextlib.py:141(__exit__)
       29    0.000    0.000    0.005    0.000 <frozen importlib._bootstrap>:1240(_find_spec)
      100    0.000    0.000    0.001    0.000 selectors.py:268(close)
      400    0.000    0.000    0.000    0.000 {method 'replace' of 'str' objects}
      544    0.000    0.000    0.000    0.000 {built-in method builtins.hasattr}
      136    0.000    0.000    0.000    0.000 {method 'rfind' of 'str' objects}
     1328    0.000    0.000    0.000    0.000 {built-in method _operator.index}
      302    0.000    0.000    0.001    0.000 selectors.py:66(__len__)
       20    0.000    0.000    0.014    0.001 mutator.py:105(modify_record)
      129    0.000    0.000    0.000    0.000 {built-in method _thread.allocate_lock}
       23    0.000    0.000    0.004    0.000 mutator.py:137(switch_records)
      100    0.000    0.000    0.000    0.000 {method 'rfind' of 'bytes' objects}
        9    0.000    0.000    0.000    0.000 {built-in method _imp.create_builtin}
       22    0.000    0.000    0.003    0.000 copy.py:247(_reconstruct)
      200    0.000    0.000    0.000    0.000 {method 'decode' of 'bytes' objects}
       30    0.000    0.000    0.001    0.000 <frozen importlib._bootstrap>:304(acquire)
       33    0.000    0.000    0.001    0.000 autogenerated.py:2807(__init__)
     29/2    0.000    0.000    0.030    0.015 <frozen importlib._bootstrap>:1349(_find_and_load)
      100    0.000    0.000    0.000    0.000 subprocess.py:268(_cleanup)
       16    0.000    0.000    0.006    0.000 mutator.py:21(mut_field)
       18    0.000    0.000    0.008    0.000 <frozen importlib._bootstrap_external>:1062(get_code)
       34    0.000    0.000    0.001    0.000 autogenerated.py:6138(__init__)
      636    0.000    0.000    0.000    0.000 {method 'rstrip' of 'str' objects}
       22    0.000    0.000    0.001    0.000 {method '__reduce_ex__' of 'object' objects}
      100    0.000    0.000    0.000    0.000 subprocess.py:1120(__del__)
      200    0.000    0.000    0.001    0.000 <string>:1(<lambda>)
      100    0.000    0.000    0.001    0.000 contextlib.py:132(__enter__)
     11/1    0.000    0.000    0.001    0.001 _parser.py:512(_parse)
      100    0.000    0.000    0.001    0.000 <frozen os>:812(fsencode)
       22    0.000    0.000    0.002    0.000 copy.py:217(_deepcopy_dict)
     19/1    0.000    0.000   41.332   41.332 {built-in method builtins.exec}
      100    0.000    0.000    0.061    0.001 emf_file.py:12(parse_header)
      200    0.000    0.000    0.000    0.000 {method 'join' of 'bytes' objects}
      100    0.000    0.000    0.000    0.000 {built-in method sys.exc_info}
      200    0.000    0.000    0.000    0.000 contextlib.py:475(_create_cb_wrapper)
        1    0.000    0.000    0.004    0.004 autogenerated.py:1(<module>)
      200    0.000    0.000    0.000    0.000 {method 'register' of 'select.poll' objects}
        3    0.000    0.000    0.002    0.001 enum.py:919(_convert_)
      676    0.000    0.000    0.000    0.000 {built-in method _struct.pack}
      100    0.000    0.000    0.001    0.000 selectors.py:202(__exit__)
      200    0.000    0.000    0.000    0.000 {method 'unregister' of 'select.poll' objects}
      100    0.000    0.000    0.000    0.000 {built-in method select.poll}
       16    0.000    0.000    0.003    0.000 value_mut.py:5(mutate_integer)
        9    0.000    0.000    0.000    0.000 {built-in method _imp.exec_builtin}
      100    0.000    0.000    0.005    0.000 subprocess.py:2008(_try_wait)
       36    0.000    0.000    0.001    0.000 <frozen importlib._bootstrap_external>:482(cache_from_source)
      100    0.000    0.000    0.000    0.000 subprocess.py:1961(_handle_exitstatus)
     28/2    0.000    0.000    0.030    0.015 <frozen importlib._bootstrap>:911(_load_unlocked)
      100    0.000    0.000    0.005    0.000 emf_file.py:64(serialize_header)
      952    0.000    0.000    0.000    0.000 copy.py:172(_deepcopy_atomic)
      100    0.000    0.000    0.000    0.000 {method 'clear' of 'dict' objects}
        4    0.000    0.000    0.003    0.001 mutator.py:41(mutate_extra_data)
       29    0.000    0.000    0.003    0.000 <frozen importlib._bootstrap>:416(__enter__)
      229    0.000    0.000    0.000    0.000 {method 'pop' of 'dict' objects}
       35    0.000    0.000    0.006    0.000 mutator.py:150(shuffle_records)
       28    0.000    0.000    0.001    0.000 <frozen importlib._bootstrap>:733(_init_module_attrs)
       33    0.000    0.000    0.000    0.000 autogenerated.py:1637(__init__)
       21    0.000    0.000    0.000    0.000 autogenerated.py:3437(__init__)
      100    0.000    0.000    0.000    0.000 {method 'strip' of 'str' objects}
     18/2    0.000    0.000    0.029    0.015 <frozen importlib._bootstrap_external>:989(exec_module)
      200    0.000    0.000    0.000    0.000 <frozen posixpath>:41(_get_sep)
       60    0.000    0.000    0.000    0.000 copy.py:231(_keep_alive)
       21    0.000    0.000    0.000    0.000 autogenerated.py:3077(__init__)
       21    0.000    0.000    0.000    0.000 autogenerated.py:6048(__init__)
      209    0.000    0.000    0.000    0.000 {method 'extend' of 'list' objects}
       20    0.000    0.000    0.004    0.000 <frozen importlib._bootstrap_external>:1491(_get_spec)
      100    0.000    0.000    0.000    0.000 {method 'encode' of 'str' objects}
       20    0.000    0.000    0.000    0.000 copyreg.py:107(_slotnames)
      302    0.000    0.000    0.000    0.000 selectors.py:272(get_map)
      100    0.000    0.000    0.001    0.000 <frozen abc>:117(__instancecheck__)
       30    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:372(release)
      354    0.000    0.000    0.000    0.000 {built-in method posix.fspath}
      200    0.000    0.000    0.001    0.000 contextlib.py:477(_exit_wrapper)
        5    0.000    0.000    0.000    0.000 autogenerated.py:161(__repr__)
      402    0.000    0.000    0.000    0.000 subprocess.py:1239(_remaining_time)
       21    0.000    0.000    0.000    0.000 autogenerated.py:1547(__init__)
       18    0.000    0.000    0.000    0.000 {method '__exit__' of '_io._IOBase' objects}
       10    0.000    0.000    0.000    0.000 autogenerated.py:6552(__repr__)
      100    0.000    0.000    0.000    0.000 subprocess.py:1233(poll)
      200    0.000    0.000    0.000    0.000 {method 'append' of 'collections.deque' objects}
     29/2    0.000    0.000    0.030    0.015 <frozen importlib._bootstrap>:1304(_find_and_load_unlocked)
      100    0.000    0.000    0.000    0.000 {method 'rstrip' of 'bytes' objects}
       30    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:124(setdefault)
      202    0.000    0.000    0.000    0.000 subprocess.py:1247(_check_timeout)
       28    0.000    0.000    0.002    0.000 <frozen importlib._bootstrap>:806(module_from_spec)
       47    0.000    0.000    0.000    0.000 enum.py:850(__setattr__)
      100    0.000    0.000    0.000    0.000 {method 'count' of 'list' objects}
       29    0.000    0.000    0.000    0.000 __init__.py:89(find_spec)
        9    0.000    0.000    0.000    0.000 autogenerated.py:9378(__init__)
      268    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:491(_verbose_message)
        1    0.000    0.000    0.000    0.000 {built-in method builtins.eval}
       21    0.000    0.000    0.000    0.000 autogenerated.py:3527(__init__)
       21    0.000    0.000    0.000    0.000 autogenerated.py:3257(__init__)
       18    0.000    0.000    0.002    0.000 <frozen importlib._bootstrap_external>:1183(get_data)
        9    0.000    0.000    0.000    0.000 autogenerated.py:6011(__repr__)
       16    0.000    0.000    0.000    0.000 copy.py:191(_deepcopy_list)
      100    0.000    0.000    0.000    0.000 {built-in method sys.audit}
       52    0.000    0.000    0.000    0.000 random.py:341(choice)
     13/1    0.000    0.000    0.000    0.000 _compiler.py:37(_compile)
      316    0.000    0.000    0.000    0.000 _parser.py:261(get)
        1    0.000    0.000    0.002    0.002 random.py:1(<module>)
       10    0.000    0.000    0.000    0.000 autogenerated.py:8748(__init__)
       36    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:132(_path_split)
       18    0.000    0.000    0.000    0.000 {built-in method posix.getcwd}
        1    0.000    0.000    0.011    0.011 emf_file.py:1(<module>)
      104    0.000    0.000    0.000    0.000 {method 'add' of 'set' objects}
        1    0.000    0.000   41.332   41.332 validity_benchmark.py:1(<module>)
       18    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:802(spec_from_file_location)
        1    0.000    0.000    0.013    0.013 parser.py:1(<module>)
       17    0.000    0.000    0.000    0.000 autogenerated.py:4517(__init__)
        1    0.000    0.000    0.021    0.021 mutator.py:1(<module>)
       18    0.000    0.000    0.001    0.000 <frozen importlib._bootstrap_external>:611(_get_cached)
        1    0.000    0.000    0.000    0.000 __init__.py:355(namedtuple)
       13    0.000    0.000    0.000    0.000 autogenerated.py:8568(__init__)
      200    0.000    0.000    0.000    0.000 {method 'pop' of 'collections.deque' objects}
       38    0.000    0.000    0.000    0.000 random.py:332(randint)
        1    0.000    0.000    0.002    0.002 signal.py:1(<module>)
      374    0.000    0.000    0.000    0.000 _parser.py:240(__next)
        4    0.000    0.000    0.000    0.000 autogenerated.py:2865(serialize)
       46    0.000    0.000    0.000    0.000 {built-in method builtins.max}
        8    0.000    0.000    0.000    0.000 autogenerated.py:8806(serialize)
      200    0.000    0.000    0.000    0.000 subprocess.py:1311(_on_error_fd_closer)
      100    0.000    0.000    0.000    0.000 {method '__exit__' of '_thread.lock' objects}
       30    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:162(__enter__)
        5    0.000    0.000    0.000    0.000 autogenerated.py:5147(__init__)
        1    0.000    0.000    0.007    0.007 subprocess.py:1(<module>)
       18    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:666(_classify_pyc)
       30    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:74(__new__)
        1    0.000    0.000    0.000    0.000 {method 'disable' of '_lsprof.Profiler' objects}
       27    0.000    0.000    0.000    0.000 {method 'format' of 'str' objects}
        9    0.000    0.000    0.000    0.000 {built-in method posix.urandom}
       54    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:84(_unpack_uint32)
        8    0.000    0.000    0.000    0.000 autogenerated.py:6196(serialize)
       27    0.000    0.000    0.000    0.000 {built-in method builtins.locals}
      100    0.000    0.000    0.000    0.000 {built-in method posix.WIFSTOPPED}
      200    0.000    0.000    0.000    0.000 subprocess.py:1973(_internal_poll)
     57/4    0.000    0.000    0.028    0.007 <frozen importlib._bootstrap>:480(_call_with_frames_removed)
      141    0.000    0.000    0.000    0.000 {method 'rpartition' of 'str' objects}
       94    0.000    0.000    0.001    0.000 <frozen importlib._bootstrap_external>:140(_path_stat)
        9    0.000    0.000    0.000    0.000 autogenerated.py:1007(__init__)
       18    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1588(_get_spec)
        4    0.000    0.000    0.000    0.000 _compiler.py:243(_optimize_charset)
        4    0.000    0.000    0.000    0.000 autogenerated.py:5655(serialize)
       77    0.000    0.000    0.000    0.000 signal.py:9(<lambda>)
      8/1    0.000    0.000    0.001    0.001 _parser.py:452(_parse_sub)
      200    0.000    0.000    0.000    0.000 <frozen codecs>:260(__init__)
      154    0.000    0.000    0.000    0.000 {method 'startswith' of 'str' objects}
       53    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1469(_path_importer_cache)
        4    0.000    0.000    0.000    0.000 autogenerated.py:1605(serialize)
       29    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:232(__init__)
        3    0.000    0.000    0.000    0.000 autogenerated.py:2231(__repr__)
        1    0.000    0.000    0.000    0.000 record_types.py:1(<module>)
        9    0.000    0.000    0.000    0.000 autogenerated.py:7128(__init__)
      157    0.000    0.000    0.000    0.000 {built-in method _imp.acquire_lock}
        1    0.000    0.000    0.000    0.000 {built-in method posix.listdir}
       22    0.000    0.000    0.000    0.000 copyreg.py:98(__newobj__)
        5    0.000    0.000    0.000    0.000 autogenerated.py:9018(__init__)
       29    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:445(cb)
       30    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:79(__init__)
      100    0.000    0.000    0.000    0.000 subprocess.py:481(__init__)
       18    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:643(_check_name_wrapper)
       20    0.000    0.000    0.004    0.000 <frozen importlib._bootstrap_external>:1520(find_spec)
      100    0.000    0.000    0.000    0.000 subprocess.py:2164(_save_input)
      100    0.000    0.000    0.000    0.000 emf_file.py:48(__init__)
        4    0.000    0.000    0.000    0.000 autogenerated.py:1695(serialize)
      157    0.000    0.000    0.000    0.000 {built-in method _imp.release_lock}
        4    0.000    0.000    0.000    0.000 autogenerated.py:3495(serialize)
       98    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:1226(__exit__)
        4    0.000    0.000    0.000    0.000 autogenerated.py:4575(serialize)
       18    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:699(_validate_timestamp_pyc)
       26    0.000    0.000    0.000    0.000 {method 'update' of 'dict' objects}
       72    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:134(<genexpr>)
       98    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:1222(__enter__)
       31    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:150(_path_is_mode_type)
       41    0.000    0.000    0.000    0.000 types.py:192(__init__)
       47    0.000    0.000    0.000    0.000 enum.py:48(_is_dunder)
        4    0.000    0.000    0.000    0.000 autogenerated.py:3135(serialize)
       30    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:82(remove)
        9    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:662(spec_from_loader)
       73    0.000    0.000    0.000    0.000 {method 'get' of 'mappingproxy' objects}
      100    0.000    0.000    0.000    0.000 selectors.py:63(__init__)
        4    0.000    0.000    0.000    0.000 autogenerated.py:6106(serialize)
       29    0.000    0.000    0.000    0.000 {built-in method _imp.is_builtin}
        5    0.000    0.000    0.000    0.000 autogenerated.py:6678(__init__)
      100    0.000    0.000    0.000    0.000 {built-in method posix.waitstatus_to_exitcode}
       16    0.000    0.000    0.003    0.000 value_mut.py:46(mutate_tuple)
        1    0.000    0.000    0.001    0.001 selectors.py:1(<module>)
        4    0.000    0.000    0.000    0.000 autogenerated.py:9436(serialize)
        1    0.000    0.000    0.000    0.000 subprocess.py:749(Popen)
       19    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:48(_new_module)
       44    0.000    0.000    0.000    0.000 copy.py:252(<genexpr>)
       41    0.000    0.000    0.000    0.000 enum.py:79(_is_private)
        4    0.000    0.000    0.000    0.000 autogenerated.py:5205(serialize)
       41    0.000    0.000    0.000    0.000 enum.py:38(_is_descriptor)
       62    0.000    0.000    0.000    0.000 {method 'remove' of 'list' objects}
       30    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:173(__exit__)
        2    0.000    0.000    0.000    0.000 generic_mutator_bytes.py:23(add_character)
       29    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:982(find_spec)
        7    0.000    0.000    0.000    0.000 {built-in method _abc._abc_init}
        4    0.000    0.000    0.000    0.000 autogenerated.py:1065(serialize)
        4    0.000    0.000    0.000    0.000 autogenerated.py:9076(serialize)
        1    0.000    0.000    0.000    0.000 subprocess.py:695(_use_posix_spawn)
        1    0.000    0.000    0.000    0.000 random.py:110(Random)
       29    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:420(__exit__)
        4    0.000    0.000    0.000    0.000 autogenerated.py:3585(serialize)
       28    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:159(_path_isfile)
        1    0.000    0.000    0.000    0.000 <frozen _sitebuiltins>:19(__call__)
     17/5    0.000    0.000    0.000    0.000 _parser.py:178(getwidth)
       36    0.000    0.000    0.001    0.000 <frozen importlib._bootstrap>:632(cached)
       20    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:1128(find_spec)
        2    0.000    0.000    0.000    0.000 {method 'translate' of 'bytearray' objects}
       60    0.000    0.000    0.000    0.000 {method '__exit__' of '_thread.RLock' objects}
       28    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:645(parent)
       57    0.000    0.000    0.000    0.000 _parser.py:168(__getitem__)
        9    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:501(_requires_builtin_wrapper)
        1    0.000    0.000    0.000    0.000 {function Random.seed at 0x7f6f528f2520}
        1    0.000    0.000    0.000    0.000 random.py:135(seed)
       18    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1202(path_stats)
        4    0.000    0.000    0.000    0.000 autogenerated.py:8626(serialize)
      100    0.000    0.000    0.000    0.000 contextlib.py:564(__enter__)
        4    0.000    0.000    0.000    0.000 autogenerated.py:6736(serialize)
       41    0.000    0.000    0.000    0.000 enum.py:59(_is_sunder)
        4    0.000    0.000    0.000    0.000 autogenerated.py:7186(serialize)
        4    0.000    0.000    0.000    0.000 autogenerated.py:3315(serialize)
      100    0.000    0.000    0.000    0.000 subprocess.py:1089(__enter__)
       60    0.000    0.000    0.000    0.000 {built-in method _thread.get_ident}
      100    0.000    0.000    0.000    0.000 selectors.py:199(__enter__)
        1    0.000    0.000    0.001    0.001 __init__.py:280(_compile)
        3    0.000    0.000    0.000    0.000 {method 'sort' of 'list' objects}
        9    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:989(create_module)
       22    0.000    0.000    0.000    0.000 {method 'insert' of 'list' objects}
        4    0.000    0.000    0.000    0.000 generic_mutator_bytes.py:32(mutate_generic)
        1    0.000    0.000    0.000    0.000 _compiler.py:573(_code)
       20    0.000    0.000    0.000    0.000 {built-in method _imp.find_frozen}
        2    0.000    0.000    0.000    0.000 generic_mutator_bytes.py:14(multiply_substring)
        1    0.000    0.000    0.000    0.000 autogenerated.py:1511(__repr__)
       28    0.000    0.000    0.000    0.000 {built-in method builtins.issubclass}
       31    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:599(__init__)
        1    0.000    0.000    0.002    0.002 string.py:1(<module>)
        1    0.000    0.000    0.000    0.000 {built-in method math.exp}
        2    0.000    0.000    0.000    0.000 selectors.py:588(_can_use)
        1    0.000    0.000    0.000    0.000 subprocess.py:470(CompletedProcess)
       77    0.000    0.000    0.000    0.000 {method 'isupper' of 'str' objects}
        1    0.000    0.000    0.000    0.000 bisect.py:1(<module>)
        2    0.000    0.000    0.000    0.000 _compiler.py:386(_mk_bitmap)
       19    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:180(_path_isabs)
       49    0.000    0.000    0.000    0.000 _parser.py:256(match)
        2    0.000    0.000    0.000    0.000 _parser.py:372(_escape)
       30    0.000    0.000    0.000    0.000 {built-in method _weakref._remove_dead_weakref}
        1    0.000    0.000    0.000    0.000 enum.py:1414(_missing_)
        1    0.000    0.000    0.002    0.002 string.py:69(__init_subclass__)
        1    0.000    0.000    0.000    0.000 _compiler.py:511(_compile_info)
        1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1567(__init__)
       30    0.000    0.000    0.000    0.000 {method 'items' of 'dict' objects}
       32    0.000    0.000    0.000    0.000 {method 'pop' of 'list' objects}
       30    0.000    0.000    0.000    0.000 {built-in method builtins.min}
        1    0.000    0.000    0.000    0.000 struct.py:1(<module>)
       19    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:185(_path_abspath)
       18    0.000    0.000    0.000    0.000 {method 'endswith' of 'str' objects}
        1    0.000    0.000    0.001    0.001 _compiler.py:740(compile)
        1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1456(_path_hooks)
        3    0.000    0.000    0.000    0.000 enum.py:1129(__new__)
        1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1685(path_hook_for_FileFinder)
        6    0.000    0.000    0.000    0.000 signal.py:51(decorator)
        7    0.000    0.000    0.000    0.000 <frozen abc>:105(__new__)
        1    0.000    0.000    0.001    0.001 _parser.py:969(parse)
       41    0.000    0.000    0.000    0.000 enum.py:241(__set_name__)
        1    0.000    0.000    0.003    0.003 header.py:1(<module>)
       78    0.000    0.000    0.000    0.000 signal.py:16(<lambda>)
        1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1644(_fill_cache)
        1    0.000    0.000    0.000    0.000 autogenerated.py:11(EMR_ALPHABLEND)
        1    0.000    0.000    0.000    0.000 autogenerated.py:6672(EMR_SETCOLORSPACE)
        9    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:997(exec_module)
        4    0.000    0.000    0.000    0.000 _parser.py:274(getuntil)
        1    0.000    0.000    0.000    0.000 autogenerated.py:911(EMR_INTERSECTCLIPRECT)
       10    0.000    0.000    0.000    0.000 {method 'random' of '_random.Random' objects}
       22    0.000    0.000    0.000    0.000 _parser.py:293(tell)
       79    0.000    0.000    0.000    0.000 signal.py:21(<lambda>)
       44    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:71(_relax_case)
       29    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:412(__init__)
        1    0.000    0.000    0.000    0.000 autogenerated.py:461(EMR_STRETCHBLT)
        1    0.000    0.000    0.000    0.000 enum.py:1551(__or__)
       18    0.000    0.000    0.000    0.000 {built-in method _imp._fix_co_filename}
        1    0.000    0.000    0.000    0.000 subprocess.py:126(CalledProcessError)
       20    0.000    0.000    0.000    0.000 {method 'find' of 'bytearray' objects}
        1    0.000    0.000    0.000    0.000 autogenerated.py:4781(EMR_SMALLTEXTOUT)
        4    0.000    0.000    0.000    0.000 _compiler.py:216(_compile_charset)
        1    0.000    0.000    0.000    0.000 autogenerated.py:3611(EMR_POLYLINE)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1367(__iter__)
        1    0.000    0.000    0.000    0.000 emfheader.py:10(ParsedHeader)
        1    0.000    0.000    0.000    0.000 {method 'close' of '_io.BufferedReader' objects}
        1    0.000    0.000    0.000    0.000 autogenerated.py:7302(EMR_MOVETOEX)
        1    0.000    0.000    0.000    0.000 selectors.py:341(_PollLikeSelector)
        1    0.000    0.000    0.000    0.000 value_mut.py:1(<module>)
        1    0.000    0.000    0.000    0.000 {built-in method _abc._abc_subclasscheck}
       41    0.000    0.000    0.000    0.000 enum.py:942(<lambda>)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1349(_get_parent_path)
        1    0.000    0.000    0.000    0.000 _compiler.py:436(_get_literal_prefix)
        1    0.000    0.000    0.000    0.000 emfheader.py:1(<module>)
        3    0.000    0.000    0.000    0.000 enum.py:1394(_iter_member_by_value_)
        3    0.000    0.000    0.000    0.000 enum.py:726(__call__)
        4    0.000    0.000    0.000    0.000 _parser.py:86(opengroup)
        1    0.000    0.000    0.000    0.000 <frozen zipimport>:64(__init__)
        1    0.000    0.000    0.000    0.000 autogenerated.py:3881(EMR_POLYLINETO16)
        2    0.000    0.000    0.000    0.000 enum.py:1562(__and__)
        1    0.000    0.000    0.000    0.000 autogenerated.py:8652(EMR_SETMAPMODE)
        1    0.000    0.000    0.000    0.000 autogenerated.py:9642(EMR_SETWINDOWEXTEX)
        1    0.000    0.000    0.000    0.000 autogenerated.py:6852(EMR_GLSBOUNDEDRECORD)
        1    0.000    0.000    0.000    0.000 autogenerated.py:4061(EMR_POLYPOLYGON16)
        1    0.000    0.000    0.000    0.000 autogenerated.py:5051(EMR_DRAWESCAPE)
        1    0.000    0.000    0.000    0.000 autogenerated.py:3161(EMR_POLYBEZIERTO16)
        1    0.000    0.000    0.000    0.000 autogenerated.py:5951(EMR_EXTCREATEFONTINDIRECTW)
        1    0.000    0.000    0.000    0.000 autogenerated.py:8382(EMR_SETICMPROFILEW)
        1    0.000    0.000    0.000    0.000 functools.py:35(update_wrapper)
       30    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:158(__init__)
        4    0.000    0.000    0.000    0.000 _parser.py:98(closegroup)
        1    0.000    0.000    0.000    0.000 autogenerated.py:2711(EMR_PAINTRGN)
        1    0.000    0.000    0.000    0.000 autogenerated.py:8742(EMR_SETMAPPERFLAGS)
       21    0.000    0.000    0.000    0.000 _parser.py:164(__len__)
        1    0.000    0.000    0.000    0.000 autogenerated.py:9552(EMR_SETVIEWPORTORGEX)
        1    0.000    0.000    0.000    0.000 autogenerated.py:5501(EMR_CREATECOLORSPACEW)
        1    0.000    0.000    0.000    0.000 autogenerated.py:9192(EMR_SETTEXTALIGN)
        9    0.000    0.000    0.000    0.000 enum.py:1544(_get_value)
        1    0.000    0.000    0.000    0.000 autogenerated.py:6402(EMR_RESIZEPALETTE)
        1    0.000    0.000    0.000    0.000 contextlib.py:272(contextmanager)
        1    0.000    0.000    0.000    0.000 autogenerated.py:2261(EMR_FILLPATH)
        1    0.000    0.000    0.000    0.000 autogenerated.py:4421(EMR_POLYTEXTOUTW)
        1    0.000    0.000    0.000    0.000 autogenerated.py:1811(EMR_CHORD)
        1    0.000    0.000    0.000    0.000 autogenerated.py:7752(EMR_SETARCDIRECTION)
        4    0.000    0.000    0.000    0.000 _parser.py:449(_uniq)
        1    0.000    0.000    0.000    0.000 autogenerated.py:4511(EMR_RECTANGLE)
       16    0.000    0.000    0.000    0.000 _parser.py:176(append)
        1    0.000    0.000    0.000    0.000 autogenerated.py:8202(EMR_SETICMMODE)
        1    0.000    0.000    0.000    0.000 autogenerated.py:3971(EMR_POLYPOLYGON)
        1    0.000    0.000    0.000    0.000 autogenerated.py:1361(EMR_COMMENT_EMFSPOOL)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1353(_recalculate)
        1    0.000    0.000    0.000    0.000 autogenerated.py:101(EMR_BITBLT)
       38    0.000    0.000    0.000    0.000 enum.py:1185(__init__)
        1    0.000    0.000    0.000    0.000 {method 'close' of 'select.epoll' objects}
        3    0.000    0.000    0.000    0.000 enum.py:528(__new__)
        4    0.000    0.000    0.000    0.000 _parser.py:304(checkgroupname)
        1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1332(__init__)
        2    0.000    0.000    0.000    0.000 _parser.py:893(_parse_flags)
        1    0.000    0.000    0.002    0.002 generic_mutator_bytes.py:1(<module>)
        1    0.000    0.000    0.000    0.000 <frozen _collections_abc>:104(_check_methods)
       28    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:653(has_location)
        3    0.000    0.000    0.000    0.000 enum.py:1404(_iter_member_by_def_)
        1    0.000    0.000    0.000    0.000 autogenerated.py:5591(EMR_CREATEDIBPATTERNBRUSHPT)
       18    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1153(__init__)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1339(_find_parent_path_names)
        1    0.000    0.000    0.000    0.000 random.py:222(__init_subclass__)
        3    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:164(_path_isdir)
        3    0.000    0.000    0.000    0.000 _parser.py:172(__setitem__)
        1    0.000    0.000    0.000    0.000 random.py:126(__init__)
        1    0.000    0.000    0.000    0.000 autogenerated.py:281(EMR_PLGBLT)
       27    0.000    0.000    0.000    0.000 __init__.py:96(<lambda>)
        1    0.000    0.000    0.000    0.000 selectors.py:80(BaseSelector)
        1    0.000    0.000    0.000    0.000 autogenerated.py:731(EMR_EXCLUDECLIPRECT)
        1    0.000    0.000    0.000    0.000 autogenerated.py:6042(EMR_EXTCREATEPEN)
        1    0.000    0.000    0.000    0.000 autogenerated.py:3791(EMR_POLYLINETO)
        1    0.000    0.000    0.000    0.000 autogenerated.py:191(EMR_MASKBLT)
        1    0.000    0.000    0.000    0.000 autogenerated.py:641(EMR_TRANSPARENTBLT)
        1    0.000    0.000    0.000    0.000 autogenerated.py:9102(EMR_SETSTRETCHBLTMODE)
       14    0.000    0.000    0.000    0.000 _parser.py:113(__init__)
        1    0.000    0.000    0.000    0.000 autogenerated.py:8292(EMR_SETICMPROFILEA)
        1    0.000    0.000    0.000    0.000 emfheader_ext2.py:10(ParsedHeader)
        1    0.000    0.000    0.000    0.000 selectors.py:60(_SelectorMapping)
        1    0.000    0.000    0.000    0.000 autogenerated.py:1181(EMR_COMMENT)
        1    0.000    0.000    0.000    0.000 autogenerated.py:5771(EMR_CREATEPALETTE)
        1    0.000    0.000    0.000    0.000 autogenerated.py:9822(EMR_MODIFYWORLDTRANSFORM)
        2    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:1390(_handle_fromlist)
        1    0.000    0.000    0.000    0.000 autogenerated.py:5861(EMR_CREATEPEN)
        1    0.000    0.000    0.000    0.000 autogenerated.py:6132(EMR_COLORCORRECTPALETTE)
        1    0.000    0.000    0.000    0.000 autogenerated.py:2891(EMR_POLYBEZIER)
        1    0.000    0.000    0.000    0.000 autogenerated.py:2531(EMR_GRADIENTFILL)
        1    0.000    0.000    0.000    0.000 autogenerated.py:2351(EMR_FILLRGN)
        1    0.000    0.000    0.000    0.000 autogenerated.py:7572(EMR_SCALEVIEWPORTEXTEX)
        1    0.000    0.000    0.000    0.000 autogenerated.py:1271(EMR_COMMENT_EMFPLUS)
        1    0.000    0.000    0.000    0.000 autogenerated.py:4331(EMR_POLYTEXTOUTA)
        1    0.000    0.000    0.000    0.000 autogenerated.py:1721(EMR_ARCTO)
        1    0.000    0.000    0.000    0.000 autogenerated.py:5321(EMR_CREATEBRUSHINDIRECT)
        1    0.000    0.000    0.000    0.000 autogenerated.py:8112(EMR_SETCOLORADJUSTMENT)
        1    0.000    0.000    0.000    0.000 autogenerated.py:2171(EMR_EXTTEXTOUTW)
        1    0.000    0.000    0.000    0.000 autogenerated.py:1541(EMR_ANGLEARC)
        1    0.000    0.000    0.000    0.000 autogenerated.py:1991(EMR_EXTFLOODFILL)
        1    0.000    0.000    0.000    0.000 autogenerated.py:551(EMR_STRETCHDIBITS)
        1    0.000    0.000    0.000    0.000 autogenerated.py:9282(EMR_SETTEXTCOLOR)
        1    0.000    0.000    0.000    0.000 autogenerated.py:9372(EMR_SETTEXTJUSTIFICATION)
        1    0.000    0.000    0.000    0.000 autogenerated.py:9732(EMR_SETWINDOWORGEX)
        1    0.000    0.000    0.000    0.000 autogenerated.py:1631(EMR_ARC)
        1    0.000    0.000    0.000    0.000 autogenerated.py:2441(EMR_FRAMERGN)
        1    0.000    0.000    0.000    0.000 autogenerated.py:8472(EMR_SETLAYOUT)
        6    0.000    0.000    0.000    0.000 signal.py:50(_wraps)
        1    0.000    0.000    0.000    0.000 autogenerated.py:9012(EMR_SETROP2)
        1    0.000    0.000    0.000    0.000 autogenerated.py:7122(EMR_FORCEUFIMAPPING)
        1    0.000    0.000    0.000    0.000 autogenerated.py:9462(EMR_SETVIEWPORTEXTEX)
        1    0.000    0.000    0.000    0.000 autogenerated.py:1091(EMR_SELECTCLIPPATH)
       20    0.000    0.000    0.000    0.000 {built-in method builtins.ord}
        1    0.000    0.000    0.000    0.000 autogenerated.py:8562(EMR_SETLINKEDUFIS)
       18    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1178(get_filename)
        1    0.000    0.000    0.000    0.000 autogenerated.py:2801(EMR_PIE)
        2    0.000    0.000    0.000    0.000 {method 'split' of 'str' objects}
        1    0.000    0.000    0.000    0.000 autogenerated.py:7032(EMR_COLORMATCHTOTARGETW)
        1    0.000    0.000    0.000    0.000 autogenerated.py:6312(EMR_DELETEOBJECT)
        1    0.000    0.000    0.000    0.000 autogenerated.py:6492(EMR_SELECTOBJECT)
        1    0.000    0.000    0.000    0.000 autogenerated.py:7392(EMR_PIXELFORMAT)
        1    0.000    0.000    0.000    0.000 autogenerated.py:7662(EMR_SCALEWINDOWEXTEX)
        1    0.000    0.000    0.000    0.000 autogenerated.py:1901(EMR_ELLIPSE)
        1    0.000    0.000    0.000    0.000 autogenerated.py:4961(EMR_STROKEPATH)
        1    0.000    0.000    0.000    0.000 autogenerated.py:7482(EMR_RESTOREDC)
        1    0.000    0.000    0.000    0.000 autogenerated.py:8022(EMR_SETBRUSHORGEX)
        1    0.000    0.000    0.000    0.000 autogenerated.py:5141(EMR_EXTESCAPE)
        1    0.000    0.000    0.000    0.000 autogenerated.py:2981(EMR_POLYBEZIER16)
        1    0.000    0.000    0.000    0.000 autogenerated.py:4871(EMR_STROKEANDFILLPATH)
        1    0.000    0.000    0.000    0.000 autogenerated.py:3521(EMR_POLYGON16)
        1    0.000    0.000    0.000    0.000 autogenerated.py:6762(EMR_SETPALETTEENTRIES)
        1    0.000    0.000    0.001    0.001 __init__.py:226(compile)
        1    0.000    0.000    0.000    0.000 autogenerated.py:4601(EMR_ROUNDRECT)
        1    0.000    0.000    0.000    0.000 subprocess.py:163(TimeoutExpired)
        1    0.000    0.000    0.000    0.000 string.py:57(Template)
        1    0.000    0.000    0.000    0.000 autogenerated.py:8832(EMR_SETMITERLIMIT)
        1    0.000    0.000    0.000    0.000 autogenerated.py:7932(EMR_SETBKMODE)
        1    0.000    0.000    0.000    0.000 autogenerated.py:10005(EMR_SAVEDC)
        1    0.000    0.000    0.000    0.000 autogenerated.py:371(EMR_SETDIBITSTODEVICE)
        1    0.000    0.000    0.000    0.000 autogenerated.py:1001(EMR_OFFSETCLIPRGN)
        1    0.000    0.000    0.000    0.000 autogenerated.py:1451(EMR_EOF)
        1    0.000    0.000    0.000    0.000 autogenerated.py:2621(EMR_LINETO)
        1    0.000    0.000    0.000    0.000 autogenerated.py:6582(EMR_SELECTPALETTE)
        1    0.000    0.000    0.000    0.000 autogenerated.py:7842(EMR_SETBKCOLOR)
        1    0.000    0.000    0.000    0.000 autogenerated.py:4241(EMR_POLYPOLYLINE16)
        1    0.000    0.000    0.000    0.000 autogenerated.py:6942(EMR_GLSRECORD)
        1    0.000    0.000    0.000    0.000 autogenerated.py:3071(EMR_POLYBEZIERTO)
        1    0.000    0.000    0.000    0.000 autogenerated.py:6222(EMR_DELETECOLORSPACE)
        1    0.000    0.000    0.000    0.000 autogenerated.py:4151(EMR_POLYPOLYLINE)
        1    0.000    0.000    0.000    0.000 autogenerated.py:5411(EMR_CREATECOLORSPACE)
        1    0.000    0.000    0.000    0.000 autogenerated.py:4691(EMR_SETPIXELV)
        1    0.000    0.000    0.000    0.000 autogenerated.py:2081(EMR_EXTTEXTOUTA)
        1    0.000    0.000    0.000    0.000 autogenerated.py:3431(EMR_POLYGON)
        1    0.000    0.000    0.000    0.000 autogenerated.py:3701(EMR_POLYLINE16)
       18    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:986(create_module)
        1    0.000    0.000    0.000    0.000 autogenerated.py:9912(EMR_SETWORLDTRANSFORM)
        1    0.000    0.000    0.000    0.000 autogenerated.py:7212(EMR_INVERTRGN)
        1    0.000    0.000    0.000    0.000 autogenerated.py:8922(EMR_SETPOLYFILLMODE)
        1    0.000    0.000    0.000    0.000 string.py:188(Formatter)
        1    0.000    0.000    0.000    0.000 autogenerated.py:5231(EMR_NAMEDESCAPE)
        1    0.000    0.000    0.000    0.000 autogenerated.py:3341(EMR_POLYDRAW16)
        1    0.000    0.000    0.000    0.000 autogenerated.py:3251(EMR_POLYDRAW)
        1    0.000    0.000    0.000    0.000 autogenerated.py:821(EMR_EXTSELECTCLIPRGN)
       10    0.000    0.000    0.000    0.000 _parser.py:83(groups)
        6    0.000    0.000    0.000    0.000 _compiler.py:31(_combine_flags)
        9    0.000    0.000    0.000    0.000 {method 'isidentifier' of 'str' objects}
        1    0.000    0.000    0.000    0.000 autogenerated.py:5681(EMR_CREATEMONOBRUSH)
        1    0.000    0.000    0.000    0.000 emfheader_ext2.py:1(<module>)
        1    0.000    0.000    0.000    0.000 random.py:876(SystemRandom)
        3    0.000    0.000    0.000    0.000 enum.py:828(__members__)
        4    0.000    0.000    0.000    0.000 {built-in method fromkeys}
        1    0.000    0.000    0.000    0.000 __init__.py:255(escape)
        1    0.000    0.000    0.000    0.000 {built-in method _sre.compile}
        1    0.000    0.000    0.000    0.000 <frozen os>:1087(__subclasshook__)
        1    0.000    0.000    0.001    0.001 {built-in method builtins.__import__}
        3    0.000    0.000    0.000    0.000 {method 'setter' of 'property' objects}
        3    0.000    0.000    0.000    0.000 enum.py:1692(_simple_enum)
        1    0.000    0.000    0.000    0.000 functools.py:65(wraps)
        1    0.000    0.000    0.000    0.000 _compiler.py:407(_generate_overlap_table)
        1    0.000    0.000    0.000    0.000 _parser.py:231(__init__)
        1    0.000    0.000    0.000    0.000 selectors.py:290(SelectSelector)
        3    0.000    0.000    0.000    0.000 enum.py:117(_iter_bits_lsb)
        1    0.000    0.000    0.000    0.000 {built-in method posix.register_at_fork}
        1    0.000    0.000    0.000    0.000 {built-in method posix.confstr}
        1    0.000    0.000    0.000    0.000 selectors.py:442(EpollSelector)
        1    0.000    0.000    0.000    0.000 selectors.py:206(_BaseSelectorImpl)
        8    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1573(<genexpr>)
        1    0.000    0.000    0.000    0.000 emf_file.py:47(EMFFile)
        5    0.000    0.000    0.000    0.000 {built-in method _sre.unicode_iscased}
        2    0.000    0.000    0.000    0.000 _compiler.py:398(_simple)
        3    0.000    0.000    0.000    0.000 {method 'items' of 'mappingproxy' objects}
        5    0.000    0.000    0.000    0.000 {built-in method sys.intern}
        1    0.000    0.000    0.000    0.000 debug.py:1(<module>)
        9    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:1014(is_package)
        1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap>:463(_lock_unlock_module)
        5    0.000    0.000    0.000    0.000 {method '__contains__' of 'frozenset' objects}
        1    0.000    0.000    0.000    0.000 selectors.py:433(PollSelector)
        5    0.000    0.000    0.000    0.000 __init__.py:429(<genexpr>)
        2    0.000    0.000    0.000    0.000 {built-in method math.log}
        1    0.000    0.000    0.000    0.000 <frozen abc>:121(__subclasscheck__)
        1    0.000    0.000    0.000    0.000 enum.py:202(__get__)
        1    0.000    0.000    0.000    0.000 {method 'translate' of 'str' objects}
        4    0.000    0.000    0.000    0.000 {built-in method builtins.any}
        1    0.000    0.000    0.000    0.000 _compiler.py:428(_get_iscased)
        4    0.000    0.000    0.000    0.000 {built-in method _sre.ascii_tolower}
        1    0.000    0.000    0.000    0.000 subprocess.py:123(SubprocessError)
        1    0.000    0.000    0.000    0.000 {built-in method sys._getframemodulename}
        4    0.000    0.000    0.000    0.000 <frozen abc>:7(abstractmethod)
        2    0.000    0.000    0.000    0.000 _compiler.py:570(isstring)
        1    0.000    0.000    0.000    0.000 _parser.py:295(seek)
        1    0.000    0.000    0.000    0.000 _parser.py:953(fix_flags)
        2    0.000    0.000    0.000    0.000 {built-in method builtins.iter}
        2    0.000    0.000    0.000    0.000 {built-in method builtins.globals}
        4    0.000    0.000    0.000    0.000 {built-in method _sre.ascii_iscased}
        1    0.000    0.000    0.000    0.000 {built-in method math.sqrt}
        1    0.000    0.000    0.000    0.000 {method 'setdefault' of 'dict' objects}
        2    0.000    0.000    0.000    0.000 enum.py:1411(<lambda>)
        1    0.000    0.000    0.000    0.000 _parser.py:77(__init__)
        1    0.000    0.000    0.000    0.000 <string>:1(<module>)
        1    0.000    0.000    0.000    0.000 enum.py:1292(value)
        1    0.000    0.000    0.000    0.000 <frozen importlib._bootstrap_external>:1408(exec_module)
        1    0.000    0.000    0.000    0.000 {method '__init_subclass__' of 'object' objects}

```

## Improving the fuzzer a bit more

Ok, so some of the records aren't documented in the way we expect with the pdf parser, this means that if we try to initiate a record of type x, we get an error. I implemented a so called "dummy record" which encompasses these records, after this I get this error:

```

Here is the size thing: 368, 368
Here is the size thing: 368, 368
Here is the size thing: 368, 368
Here is the size thing: 368, 368
Here is the size thing: 368, 368
Data was different!
Traceback (most recent call last):
  File "/home/oof/emf_custom_mutator/mutator.py", line 294, in <module>
    test_mut()
  File "/home/oof/emf_custom_mutator/mutator.py", line 281, in test_mut
    data = mutate_emf(data)
           ^^^^^^^^^^^^^^^^
  File "/home/oof/emf_custom_mutator/mutator.py", line 197, in mutate_emf
    emf_obj = parse_emf_file(emf_data)
              ^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_custom_mutator/emf_file.py", line 73, in parse_emf_file
    records = parse_records(rest_of_data) # Try to parse the records from the data.
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_custom_mutator/emf_file.py", line 34, in parse_records
    c = lookup_emr_record_class(t)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/emf_custom_mutator/emf_file.py", line 21, in lookup_emr_record_class
    return getattr(autogenerated, EMR_NAMES[t]) # autogenerated
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AttributeError: module 'autogenerated' has no attribute 'EMR_ENDPATH'. Did you mean: 'EMR_FILLPATH'?

```

Let's add a fallback for when we can not find the thing in the autogenerated stuff. There you go, now we should have it stuff.


## Getting a better corpus

Ok, so now our custom mutator is looking somewhat good, it is time to gather a better corpus... I think there is actually functionality in inkscape and other stuff, so I think we can gather a good corpus that way???

```


// RenderEMF.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <gdiplus.h>
#include <iostream>

using namespace Gdiplus;



/*
int main() {
    // Initialize GDI+
    ULONG_PTR gdiplusToken;
    GdiplusStartupInput gdiStartupInput;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiStartupInput, NULL);

    // Load EMF file
    const WCHAR* emfFilePath = L"image.emf";
    Image image(emfFilePath);

    // Create a device context (HDC) to render the EMF image
    HDC hdc = GetDC(NULL);  // Use screen's DC or create a window context
    Graphics graphics(hdc);

    // Draw the EMF file on the screen at (0,0)
    graphics.DrawImage(&image, 0, 0);

    // Release resources
    ReleaseDC(NULL, hdc);
    Gdiplus::GdiplusShutdown(gdiplusToken);

    return 0;
}
*/

















/*

#include <windows.h>
#include <gdiplus.h>
#pragma comment(lib, "gdiplus.lib")

using namespace Gdiplus;

// Global variables for the GDI+ token and the window handle
ULONG_PTR gdiplusToken;
HWND hwnd;

// Window procedure for handling messages
LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);

        // Load the EMF file
        // const WCHAR* emfFilePath = L"C:\\Users\\elsku\\source\\repos\\RenderEMF\\x64\\Debug\\image.emf";
        const WCHAR* emfFilePath = L"C:\\Users\\elsku\\image.emf";
        Image image(emfFilePath);
        if (image.GetLastStatus() != Ok) {
            printf("Failed to load EMF file.\n");
            return -1;
        }
        // Get the dimensions of the window
        RECT rect;
        GetClientRect(hWnd, &rect);

        // Create a GDI+ graphics object
        Graphics graphics(hdc);

        // Calculate the center position
        int imgWidth = image.GetWidth();
        int imgHeight = image.GetHeight();
        int x = (rect.right - imgWidth) / 2;
        int y = (rect.bottom - imgHeight) / 2;

        // Draw the image centered
        printf("%s\n", "Drawing the image");
        graphics.DrawImage(&image, x, y);

        EndPaint(hWnd, &ps);
        return 0;
    }

    case WM_TIMER: {
        // Destroy the window after the timer expires
        KillTimer(hWnd, 1);  // Stop the timer
        DestroyWindow(hWnd); // Close the window
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

int main() {
    // Initialize GDI+
    GdiplusStartupInput gdiStartupInput;
    GdiplusStartup(&gdiplusToken, &gdiStartupInput, NULL);

    // Register the window class
    const wchar_t CLASS_NAME[] = L"FullscreenWindow";
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = CLASS_NAME;
    RegisterClass(&wc);

    // Get the screen dimensions
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    // Create a borderless fullscreen window
    hwnd = CreateWindowEx(
        WS_EX_TOPMOST,               // Always on top
        CLASS_NAME,                  // Window class
        L"Render EMF",                // Window title
        WS_POPUP,                    // No borders or title bar
        0, 0,                        // Position (top-left corner)
        screenWidth, screenHeight,   // Fullscreen dimensions
        NULL, NULL, NULL, NULL
    );

    if (!hwnd) {
        printf("Failed to create window.\n");
        return -1;
    }

    // Show the window
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    SetTimer(hwnd, 1, 400, NULL);
    // Message loop
    MSG msg = {};
    
    unsigned int i = 0;

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
        i++; // Increment
        if (i == 100) {
            break;
        }
    }
    
    printf("%s\n", "Ending the stuff");
    // Cleanup GDI+
    GdiplusShutdown(gdiplusToken);

    return 0;
}








*/








#include <windows.h>
#include <gdiplus.h>
#include <string>
#include <vector>
#include <iostream>
#pragma comment(lib, "gdiplus.lib")

using namespace Gdiplus;
using namespace std;

LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static Image* currentImage = nullptr;

    switch (uMsg) {
    
    case WM_USER: {  // Custom message to update the image
        currentImage = (Image*)lParam;  // Assign the Image pointer passed via LPARAM
        InvalidateRect(hWnd, NULL, TRUE);  // Force the window to redraw
        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        printf("Oofstuff...\n");
        if (currentImage && currentImage->GetLastStatus() == Ok) {
            RECT rect;
            GetClientRect(hWnd, &rect);

            // Center the image
            Graphics graphics(hdc);
            int x = (rect.right - currentImage->GetWidth()) / 2;
            int y = (rect.bottom - currentImage->GetHeight()) / 2;
            printf("Drawing an image...\n");
            graphics.DrawImage(currentImage, x, y);
        }

        EndPaint(hWnd, &ps);
        return 0;
    }
    
    
    /*
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);

        // Load the EMF file
        // const WCHAR* emfFilePath = L"C:\\Users\\elsku\\source\\repos\\RenderEMF\\x64\\Debug\\image.emf";
        const WCHAR* emfFilePath = L"C:\\Users\\elsku\\image.emf";
        Image image(emfFilePath);
        if (image.GetLastStatus() != Ok) {
            printf("Failed to load EMF file.\n");
            return -1;
        }
        // Get the dimensions of the window
        RECT rect;
        GetClientRect(hWnd, &rect);

        // Create a GDI+ graphics object
        Graphics graphics(hdc);

        // Calculate the center position
        int imgWidth = image.GetWidth();
        int imgHeight = image.GetHeight();
        int x = (rect.right - imgWidth) / 2;
        int y = (rect.bottom - imgHeight) / 2;

        // Draw the image centered
        printf("%s\n", "Drawing the image");
        graphics.DrawImage(&image, x, y);

        EndPaint(hWnd, &ps);
        return 0;
    }
    */

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

// Function to list all files in a directory
vector<wstring> GetFilesInDirectory(const wstring& directoryPath) {
    vector<wstring> files;
    WIN32_FIND_DATA findData;

    wstring searchPath = directoryPath + L"\\*";
    HANDLE hFind = FindFirstFile(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        wcerr << L"Failed to open directory: " << directoryPath << endl;
        return files;
    }

    do {
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            files.push_back(directoryPath + L"\\" + findData.cFileName);
        }
    } while (FindNextFile(hFind, &findData));

    FindClose(hFind);
    return files;
}

int main() {
    // Initialize GDI+
    GdiplusStartupInput gdiStartupInput;
    ULONG_PTR gdiplusToken;
    GdiplusStartup(&gdiplusToken, &gdiStartupInput, NULL);

    // Register the window class
    const wchar_t CLASS_NAME[] = L"FullscreenWindow";
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = CLASS_NAME;
    RegisterClass(&wc);

    // Get the screen dimensions
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    printf("screenWidth: %d\n", screenWidth);
    printf("screenHeight: %d\n", screenHeight);
    screenWidth = 300;
    screenHeight = 300;
    // Directory containing EMF files
    wstring directoryPath = L"C:\\Users\\elsku\\outputs4\\queue";

    // Get all files in the directory
    vector<wstring> files = GetFilesInDirectory(directoryPath);
    if (files.empty()) {
        wcerr << L"No files found in directory: " << directoryPath << endl;
        GdiplusShutdown(gdiplusToken);
        return -1;
    }

    for (const auto& filePath : files) {
        // Create the window
        HWND hwnd = CreateWindowEx(
            WS_EX_TOPMOST,
            CLASS_NAME,
            L"Render EMF",
            WS_POPUP,
            0, 0,
            screenWidth, screenHeight,
            NULL, NULL, NULL, NULL
        );

        if (!hwnd) {
            wcerr << L"Failed to create window for file: " << filePath << endl;
            continue;
        }

        // Load the current image
        Image* image = new Image(filePath.c_str());
        if (image->GetLastStatus() != Ok) {
            wcerr << L"Failed to load image: " << filePath << endl;
            delete image;
            continue;
        }
        SendMessage(hwnd, WM_USER, 0, (LPARAM)image); // Send the image stuff.

        wcerr << L"Loaded this image: " << filePath << endl;
        // printf("Loaded this file: %s\n", filePath.c_str());
        // Pass the image to the window procedure
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)&image);

        // Show the window
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);

        // Render the image for 0.2 seconds
        // Sleep(100);

        // Close the window
        DestroyWindow(hwnd);
    }

    // Cleanup GDI+
    GdiplusShutdown(gdiplusToken);

    return 0;
}


















// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file


```

Ok, so let's add a script to convert a shitload of svg files to EMF files which we can then pass to the fuzzer maybe???? I added it to my github here: https://github.com/personnumber3377/emfcorpusgen

Something like this:

`inkscape wordpresslogo.svg --export-filename=output.emf`

Ok, so I think our script works quite well. I think the next step is to minimize the corpus which we have generated with cmin and then try fuzzing again maybe???


During the generation of the corpus, I actually encountered a thing:

```

'inkscape', './svg_files/hc_staff.svg', '--export-filename=./generated_emf/hc_staff.emf'

another crash here:

Error processing linked-filter-01.svg: Command '['inkscape', './svg_files/linked-filter-01.svg', '--export-filename=./generated_emf/linked-filter-01.emf']' died with <Signals.SIGSEGV: 11>.

** (org.inkscape.Inkscape:30578): WARNING **: 22:11:10.029: Unimplemented style property 7

** (org.inkscape.Inkscape:30578): WARNING **: 22:11:10.029: Unimplemented style property 7
Processed: standalone--0-0--pct-0.svg
cmd: inkscape ./svg_files/standalone--0-0--px-pct.svg --export-filename=./generated_emf/standalone--0-0--px-pct.emf

** (org.inkscape.Inkscape:30577): WARNING **: 22:11:10.034: Unimplemented style property 8

** (org.inkscape.Inkscape:30577): WARNING **: 22:11:10.034: Unimplemented style property 8

** (org.inkscape.Inkscape:30577): WARNING **: 22:11:10.034: Unimplemented style property 7

** (org.inkscape.Inkscape:30577): WARNING **: 22:11:10.034: Unimplemented style property 7
Processed: standalone--0-0--0-px.svg
cmd: inkscape ./svg_files/standalone--0-0--px-px.svg --export-filename=./generated_emf/standalone--0-0--px-px.emf
Processed: standalone--0-0--0-0.svg
cmd: inkscape ./svg_files/standalone--0-auto--0-0.svg --export-filename=./generated_emf/standalone--0-auto--0-0.emf
Processed: standalone--0-0--0-pct.svg
cmd: inkscape ./svg_files/standalone--0-auto--0-pct.svg --export-filename=./generated_emf/standalone--0-auto--0-pct.emf

** (org.inkscape.Inkscape:30583): WARNING **: 22:11:10.251: Unimplemented style property 8

** (org.inkscape.Inkscape:30583): WARNING **: 22:11:10.252: Unimplemented style property 8

** (org.inkscape.Inkscape:30583): WARNING **: 22:11:10.252: Unimplemented style property 7

** (org.inkscape.Inkscape:30583): WARNING **: 22:11:10.252: Unimplemented style property 7

** (org.inkscape.Inkscape:30583): WARNING **: 22:11:10.262: Unimplemented style property 8

** (org.inkscape.Inkscape:30583): WARNING **: 22:11:10.262: Unimplemented style property 8

** (org.inkscape.Inkscape:30583): WARNING **: 22:11:10.262: Unimplemented style property 7

** (org.inkscape.Inkscape:30583): WARNING **: 22:11:10.262: Unimplemented style property 7
Processed: standalone--0-0--pct-pct.svg
cmd: inkscape ./svg_files/standalone--0-auto--0-px.svg --export-filename=./generated_emf/standalone--0-auto--0-px.emf

** (org.inkscape.Inkscape:30605): WARNING **: 22:11:10.774: Unimplemented style property 8

** (org.inkscape.Inkscape:30605): WARNING **: 22:11:10.775: Unimplemented style property 8

** (org.inkscape.Inkscape:30605): WARNING **: 22:11:10.775: Unimplemented style property 7

** (org.inkscape.Inkscape:30605): WARNING **: 22:11:10.775: Unimplemented style property 7

** (org.inkscape.Inkscape:30605): WARNING **: 22:11:10.787: Unimplemented style property 8

** (org.inkscape.Inkscape:30605): WARNING **: 22:11:10.787: Unimplemented style property 8

** (org.inkscape.Inkscape:30605): WARNING **: 22:11:10.787: Unimplemented style property 7

** (org.inkscape.Inkscape:30605): WARNING **: 22:11:10.787: Unimplemented style property 7
Processed: standalone--0-0--pct-px.svg
cmd: inkscape ./svg_files/standalone--0-auto--pct-0.svg --export-filename=./generated_emf/standalone--0-auto--pct-0.emf
Error processing staffNS.svg: Command '['inkscape', './svg_files/staffNS.svg', '--export-filename=./generated_emf/staffNS.emf']' died with <Signals.SIGSEGV: 11>.
cmd: inkscape ./svg_files/standalone--0-auto--pct-pct.svg --export-filename=./generated_emf/standalone--0-auto--pct-pct.emf
```

## Analyzing the corpus results.

Ok, so the corpus which I got is only ten files, this hints that the inkscape software only uses a couple of methods to transform the svg to EMF files and doesn't use a lot of the more obscure record types. This got me thinking, what If we use the mutator to generate files which are valid according to gdiplus and then run that set of generated files through cmin to get a corpus????

## The results of that stuff.

Ok, so it seems that our custom mutator generated a good corpus. This is good (I think). I think we should implement smarter mutation strategies, where we place actually known good records (records with interesting values.). Also I think another strategy is to generate a better corpus by using the gdiplus library.

Here is my corpus generator:

```

#include <windows.h>
#include <gdiplus.h>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <string>

#pragma comment(lib, "gdiplus.lib")

using namespace Gdiplus;

// Some fuzzing constants here



#define MAX_FONT_STRING_SIZE 1000
#define MAX_COMMENT_STRING_SIZE 100000
#define MAX_OPERATIONS 15
#define MIN_OPERATIONS 5
#define NUM_FILES 1000
#define MAX_RANDOM_TEXT_LEN 20


std::wstring GenerateRandomString(int maxLength) {
    int length = rand() % maxLength + 1;
    std::wstring randomString;
    randomString.reserve(length);
    for (int i = 0; i < length; i++) {
        randomString += static_cast<wchar_t>(rand() % 0x7E + 0x20); // Printable ASCII range
    }
    return randomString;
}










void AddRandomComment(HDC hdc) {
    // const int maxCommentSize = 256;
    BYTE commentData[MAX_COMMENT_STRING_SIZE];

    // Generate a random comment string
    int length = rand() % (MAX_COMMENT_STRING_SIZE - 1) + 1;
    for (int i = 0; i < length; i++) {
        commentData[i] = 'A' + (rand() % 26); // Random uppercase letters
    }

    // Insert comment into the EMF file
    if (!GdiComment(hdc, length, commentData)) {
        printf("Failed to insert comment into EMF.\n");
    }
}













void GenerateRandomEMF(const wchar_t* filename) {
    GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr);

    HDC hdc = GetDC(NULL);
    // Add the random comment...
    AddRandomComment(hdc);
    Metafile* metafile = new Metafile(filename, hdc);
    Graphics* graphics = new Graphics(metafile);
    
    int numOperations = rand() % (MAX_OPERATIONS - MIN_OPERATIONS) + MIN_OPERATIONS;

    for (int i = 0; i < numOperations; i++) {
        int choice = rand() % 39;
        int x = rand() % 500, y = rand() % 500, w = rand() % 200, h = rand() % 200;

        switch (choice) {
        case 0: {
            Pen pen(Color(rand() % 256, rand() % 256, rand() % 256));
            graphics->DrawLine(&pen, x, y, x + w, y + h);
            break;
        }
        case 1: {
            SolidBrush brush(Color(rand() % 256, rand() % 256, rand() % 256));
            graphics->FillRectangle(&brush, x, y, w, h);
            break;
        }
        case 2: {
            Pen pen(Color(rand() % 256, rand() % 256, rand() % 256));
            graphics->DrawEllipse(&pen, x, y, w, h);
            break;
        }
        case 3: {
            Font font(L"Arial", rand() % 30 + 10);
            SolidBrush brush(Color(rand() % 256, rand() % 256, rand() % 256));
            graphics->DrawString(L"FuzzTest", -1, &font, PointF(x, y), &brush);
            break;
        }
        case 4: {
            graphics->RotateTransform(rand() % 360);
            graphics->ScaleTransform((rand() % 200) / 100.0, (rand() % 200) / 100.0);
            break;
        }
        case 5: {
            LinearGradientBrush brush(Rect(x, y, w, h),
                Color(rand() % 256, rand() % 256, rand() % 256),
                Color(rand() % 256, rand() % 256, rand() % 256),
                (LinearGradientMode)(rand() % 4));
            graphics->FillRectangle(&brush, x, y, w, h);
            break;
        }
        case 6: {
            GraphicsPath path;
            path.AddBezier(x, y, x + w / 2, y - h / 2, x - w / 2, y + h / 2, x + w, y + h);
            Pen pen(Color(rand() % 256, rand() % 256, rand() % 256));
            graphics->DrawPath(&pen, &path);
            break;
        }
        case 7: {
            Image image(L"test.jpg"); // Ensure a valid test.jpg exists
            graphics->DrawImage(&image, x, y, w, h);
            break;
        }
        case 8: {
            HatchBrush brush((HatchStyle)(rand() % 53),
                Color(rand() % 256, rand() % 256, rand() % 256),
                Color(rand() % 256, rand() % 256, rand() % 256));
            graphics->FillRectangle(&brush, x, y, w, h);
            break;
        }
        case 9: {
            GraphicsPath path;
            path.AddPolygon(new Point[3]{ Point(x, y), Point(x + w, y), Point(x + w / 2, y - h) }, 3);
            SolidBrush brush(Color(rand() % 256, rand() % 256, rand() % 256));
            graphics->FillPath(&brush, &path);
            break;
        }

        case 10: {
            Font font(L"Arial", rand() % 30 + 10);
            SolidBrush brush(Color(rand() % 256, rand() % 256, rand() % 256));
            std::wstring randomText = GenerateRandomString(MAX_RANDOM_TEXT_LEN);
            graphics->DrawString(randomText.c_str(), -1, &font, PointF(x, y), &brush);
            break;
        }

        case 11: {
            std::wstring randomFontText = GenerateRandomString(MAX_FONT_STRING_SIZE);
            Font font(randomFontText.c_str(), rand() % 30 + 10);
            SolidBrush brush(Color(rand() % 256, rand() % 256, rand() % 256));
            std::wstring randomText = GenerateRandomString(MAX_RANDOM_TEXT_LEN);
            graphics->DrawString(randomText.c_str(), -1, &font, PointF(x, y), &brush);
            break;
        }



        case 12: {
            // PathGradientBrush mutation
            GraphicsPath path;
            // Create a random polygon path
            path.AddPolygon(new Point[3]{
                Point(x, y),
                Point(x + w, y),
                Point(x + w / 2, y - h)
                }, 3);
            Color centerColor(rand() % 256, rand() % 256, rand() % 256);
            Color surroundColor(rand() % 256, rand() % 256, rand() % 256);
            PathGradientBrush pathGradientBrush(&path);
            pathGradientBrush.SetCenterColor(centerColor);
            int* integerthing;
            int thing = 1;
            integerthing = &thing;
            // printf("Adding the bullshit\n");
            pathGradientBrush.SetSurroundColors(&surroundColor, integerthing); // Set the surrounding color for the gradient
            graphics->FillPath(&pathGradientBrush, &path);
            break;
        }

        case 13: {
            // TextureBrush mutation
            // Use a random image file
            const wchar_t* textureFile = L"test.jpg";  // Change to a valid path if necessary
            Image textureImage(textureFile);
            TextureBrush textureBrush(&textureImage);
            graphics->FillRectangle(&textureBrush, x, y, w, h);
            break;
        }


        case 14: {
            // Pen Style Mutation: Dash style and Width
            Pen pen(Color(rand() % 256, rand() % 256, rand() % 256));

            // Random Dash Style
            DashStyle dashStyles[] = { DashStyleSolid, DashStyleDash, DashStyleDot, DashStyleDashDot, DashStyleDashDotDot };
            pen.SetDashStyle(dashStyles[rand() % 5]);

            // Random Width (Thin to very thick strokes)
            pen.SetWidth(rand() % 30 + 1);  // Random width between 1 and 30

            // Random End Cap (Round, Square, Triangle)
            int endCapChoice = rand() % 3;
            if (endCapChoice == 0)
                pen.SetStartCap(LineCapRound);
            else if (endCapChoice == 1)
                pen.SetStartCap(LineCapSquare);
            else
                pen.SetStartCap(LineCapTriangle);

            // Random Line Join (Miter, Bevel, Round)
            int lineJoinChoice = rand() % 3;
            if (lineJoinChoice == 0)
                pen.SetLineJoin(LineJoinMiter);
            else if (lineJoinChoice == 1)
                pen.SetLineJoin(LineJoinBevel);
            else
                pen.SetLineJoin(LineJoinRound);

            // Draw a line with the random Pen style
            graphics->DrawLine(&pen, x, y, x + w, y + h);
            break;
        }

        case 15: {
            // Apply random transformations to the line
            Pen pen(Color(rand() % 256, rand() % 256, rand() % 256));
            pen.SetWidth(rand() % 30 + 1);  // Random width between 1 and 30

            // Apply a random rotation
            graphics->RotateTransform(rand() % 360);  // Rotate between 0 and 360 degrees

            // Apply a random skew (using scale transform)
            graphics->ScaleTransform((rand() % 200) / 100.0, (rand() % 200) / 100.0);

            // Draw a line with random transformations
            graphics->DrawLine(&pen, x, y, x + w, y + h);
            break;
        }


        case 16: {
            // Image Drawing with Transformation (Resize, Stretch, Skew, Rotate)
            Image image(L"test.jpg");  // Ensure the image exists

            // Apply random transformations
            graphics->RotateTransform(rand() % 360);  // Rotate the image randomly between 0 and 360 degrees

            // Resize the image with random width and height
            int newWidth = rand() % 400 + 50;  // New width between 50 and 400
            int newHeight = rand() % 400 + 50;  // New height between 50 and 400
            graphics->DrawImage(&image, x, y, newWidth, newHeight);
            break;
        }

        case 17: {
            // Skew Image using Scale Transform
            Image image(L"test.jpg");  // Ensure the image exists

            // Apply random skew (using scaling)
            float scaleX = (rand() % 200) / 100.0f;  // Random horizontal scaling
            float scaleY = (rand() % 200) / 100.0f;  // Random vertical scaling
            graphics->ScaleTransform(scaleX, scaleY);

            // Draw the skewed image
            graphics->DrawImage(&image, x, y, w, h);
            break;
        }

        case 18: {
            // Apply ColorMatrix transformation to image (change colors)
            Image image(L"test.jpg");  // Ensure the image exists

            // Create a color matrix to apply a transformation
            ColorMatrix colorMatrix = {
                1.5f, 0, 0, 0, 0,  // Red channel (adjust intensity)
                0, 1.5f, 0, 0, 0,  // Green channel (adjust intensity)
                0, 0, 1.5f, 0, 0,  // Blue channel (adjust intensity)
                0, 0, 0, 1, 0,      // Alpha (no change)
                0, 0, 0, 0, 1       // No translation
            };
            ImageAttributes imageAttributes;
            imageAttributes.SetColorMatrix(&colorMatrix);

            // Draw the image with the color transformation
            // graphics->DrawImage(&image, Rect(x, y, w, h), 0, 0, image.GetWidth(), image.GetHeight(), UnitPixel, &imageAttributes);


            graphics->DrawImage(&image, Rect(x, y, w, h), 0, 0, image.GetWidth(), image.GetHeight(), UnitPixel, &imageAttributes);
            break;
        }


        case 19: {
            // Brush Variations - Randomized fills
            int brushType = rand() % 5;
            Brush* brush = nullptr;

            switch (brushType) {
            case 0: // SolidBrush
                brush = new SolidBrush(Color(rand() % 256, rand() % 256, rand() % 256, rand() % 256));
                break;
            case 1: // HatchBrush
                brush = new HatchBrush((HatchStyle)(rand() % 53),
                    Color(rand() % 256, rand() % 256, rand() % 256),
                    Color(rand() % 256, rand() % 256, rand() % 256));
                break;
            case 2: // LinearGradientBrush
                brush = new LinearGradientBrush(Rect(x, y, w, h),
                    Color(rand() % 256, rand() % 256, rand() % 256),
                    Color(rand() % 256, rand() % 256, rand() % 256),
                    (LinearGradientMode)(rand() % 4));
                break;
            case 3: { // PathGradientBrush
                GraphicsPath path;
                path.AddRectangle(Rect(x, y, w, h));
                PathGradientBrush* pgBrush = new PathGradientBrush(&path);
                pgBrush->SetCenterColor(Color(rand() % 256, rand() % 256, rand() % 256));
                Color surroundColors[] = { Color(rand() % 256, rand() % 256, rand() % 256) };
                pgBrush->SetSurroundColors(surroundColors, nullptr);
                brush = pgBrush;
                break;
            }
            case 4: { // TextureBrush
                Image image(L"texture.jpg"); // Use a valid image
                brush = new TextureBrush(&image);
                break;
            }
            }

            if (brush) {
                graphics->FillRectangle(brush, x, y, w, h);
                delete brush;
            }
            break;
        }

        case 20: {
            // Corrupt Image Handling in DrawImage
            Image image(L"corrupt_image.jpg");  // Intentionally non-existent or malformed image
            graphics->DrawImage(&image, x, y, w, h);
            break;
        }

        case 21: {
            // Overlay semi-transparent images
            Image image1(L"layer1.jpg"), image2(L"layer2.jpg");
            ImageAttributes attr;
            ColorMatrix matrix = {
                1, 0, 0, 0, 0,
                0, 1, 0, 0, 0,
                0, 0, 1, 0, 0,
                0, 0, 0, 0.5f, 0,  // 50% Transparency
                0, 0, 0, 0, 1
            };
            attr.SetColorMatrix(&matrix);
            graphics->DrawImage(&image1, x, y, w, h);
            graphics->DrawImage(&image2, x + 10, y + 10, w, h);
            break;
        }

        case 22: {
            // Randomized text with malformed Unicode & extreme fonts
            std::wstring randomText = GenerateRandomString(1000); // Malformed long text
            FontFamily fontFamily(L"Arial");
            Font font(&fontFamily, rand() % 100 + 10, rand() % 4);
            SolidBrush brush(Color(rand() % 256, rand() % 256, rand() % 256));
            StringFormat format;
            format.SetFormatFlags(rand() % 2 ? StringFormatFlagsDirectionVertical : StringFormatFlagsNoWrap);
            graphics->DrawString(randomText.c_str(), -1, &font, PointF(x, y), &format, &brush);
            break;
        }

        case 23: {
            // MeasureString Usage
            std::wstring randomText = GenerateRandomString(200);
            Font font(L"Arial", rand() % 50 + 10);
            RectF layoutRect(x, y, w, h);
            StringFormat format;
            RectF boundBox;
            graphics->MeasureString(randomText.c_str(), -1, &font, layoutRect, &format, &boundBox);
            graphics->DrawString(randomText.c_str(), -1, &font, PointF(boundBox.X, boundBox.Y), &format, new SolidBrush(Color(255, 0, 0)));
            break;
        }

        case 24: {
            // Nested Transformations
            graphics->TranslateTransform(rand() % 200, rand() % 200);
            graphics->RotateTransform(rand() % 360);
            graphics->ScaleTransform((rand() % 200) / 100.0f, (rand() % 200) / 100.0f);
            graphics->DrawRectangle(new Pen(Color(rand() % 256, rand() % 256, rand() % 256)), x, y, w, h);
            break;
        }

        case 25: {
            // Negative Scaling (flipping)
            graphics->ScaleTransform(-1, 1);  // Flip horizontally
            graphics->DrawEllipse(new Pen(Color(rand() % 256, rand() % 256, rand() % 256)), x, y, w, h);
            graphics->ScaleTransform(1, -1);  // Flip vertically
            graphics->DrawRectangle(new Pen(Color(rand() % 256, rand() % 256, rand() % 256)), x, y, w, h);
            break;
        }

        case 26: {
            // Affine Transformation Matrix
            Matrix transformMatrix;
            transformMatrix.Rotate(rand() % 360);
            transformMatrix.Shear((rand() % 200) / 100.0f, (rand() % 200) / 100.0f);
            transformMatrix.Translate(rand() % 100, rand() % 100);
            graphics->SetTransform(&transformMatrix);
            graphics->DrawRectangle(new Pen(Color(rand() % 256, rand() % 256, rand() % 256)), x, y, w, h);
            break;
        }




        case 27: {
            // Bezier Curves (Complex Curves)
            GraphicsPath path;
            path.AddBezier(x, y, x + w / 2, y - h / 2, x - w / 2, y + h / 2, x + w, y + h);
            Pen pen(Color(rand() % 256, rand() % 256, rand() % 256), rand() % 10 + 1);
            graphics->DrawPath(&pen, &path);
            break;
        }

        case 28: {
            // Polylines (Multiple connected points)
            const int numPoints = rand() % 10 + 3;  // 3 to 12 points
            Point* points = new Point[numPoints];
            for (int i = 0; i < numPoints; i++) {
                points[i] = Point(rand() % 500, rand() % 500);
            }
            Pen pen(Color(rand() % 256, rand() % 256, rand() % 256), rand() % 5 + 1);
            graphics->DrawLines(&pen, points, numPoints);
            delete[] points;
            break;
        }

        case 29: {
            // Complex Polygons (Concave & Self-Intersecting)
            const int numVertices = rand() % 10 + 3;  // 3 to 12 vertices
            Point* vertices = new Point[numVertices];
            for (int i = 0; i < numVertices; i++) {
                vertices[i] = Point(rand() % 500, rand() % 500);
            }
            GraphicsPath path;
            path.AddPolygon(vertices, numVertices);
            SolidBrush brush(Color(rand() % 256, rand() % 256, rand() % 256));
            graphics->FillPath(&brush, &path);
            delete[] vertices;
            break;
        }

        case 30: {
            // Text Outlines Converted to Paths
            std::wstring randomText = GenerateRandomString(rand() % 20 + 5);
            FontFamily fontFamily(L"Arial");
            GraphicsPath path;
            path.AddString(randomText.c_str(), -1, &fontFamily, FontStyleRegular, rand() % 50 + 10, Point(x, y), nullptr);
            Pen pen(Color(rand() % 256, rand() % 256, rand() % 256), rand() % 5 + 1);
            graphics->DrawPath(&pen, &path);
            break;
        }

        case 31: {
            // Impossible & Nested Path Structures
            GraphicsPath path;
            for (int i = 0; i < 5; i++) {
                path.AddRectangle(Rect(rand() % 500, rand() % 500, rand() % 200, rand() % 200));
            }
            Pen pen(Color(rand() % 256, rand() % 256, rand() % 256), rand() % 3 + 1);
            graphics->DrawPath(&pen, &path);
            break;
        }

        case 32: {
            // Self-Intersecting Shape (Overlapping Star)
            GraphicsPath path;
            Point points[10] = {
                {x, y}, {x + w / 3, y + h / 3}, {x + w, y}, {x + w / 2, y + h / 2},
                {x + w, y + h}, {x + w / 3, y + 2 * h / 3}, {x, y + h}, {x + w / 2, y + h / 3},
                {x, y}, {x + w / 3, y + h / 3}
            };
            path.AddPolygon(points, 10);
            Pen pen(Color(rand() % 256, rand() % 256, rand() % 256), rand() % 3 + 1);
            graphics->DrawPath(&pen, &path);
            break;
        }

        case 33: {
            // Simple Clipping Rectangle
            Rect clipRegion(rand() % 500, rand() % 500, rand() % 200 + 10, rand() % 200 + 10);
            Region region(clipRegion);
            graphics->SetClip(&region, CombineModeReplace);

            // Draw a filled rectangle within the clipped area
            SolidBrush brush(Color(rand() % 256, rand() % 256, rand() % 256));
            graphics->FillRectangle(&brush, x, y, w, h);
            break;
        }

        case 34: {
            // Complex Clipping using Non-Convex Path
            GraphicsPath path;
            path.AddPolygon(new Point[6]{
                {x, y}, {x + w / 2, y - h / 2}, {x + w, y},
                {x + w / 2, y + h / 2}, {x - w / 2, y + h / 2}, {x, y}
                }, 6);
            Region region(&path);
            graphics->SetClip(&region, CombineModeReplace);

            // Draw a gradient rectangle to show the clipped effect
            LinearGradientBrush brush(Rect(x, y, w, h),
                Color(rand() % 256, rand() % 256, rand() % 256),
                Color(rand() % 256, rand() % 256, rand() % 256),
                (LinearGradientMode)(rand() % 4));
            graphics->FillRectangle(&brush, x, y, w, h);
            break;
        }

        case 35: {
            // Clipping with Text Path
            std::wstring randomText = GenerateRandomString(rand() % 10 + 5);
            FontFamily fontFamily(L"Arial");
            GraphicsPath textPath;
            textPath.AddString(randomText.c_str(), -1, &fontFamily, FontStyleRegular, rand() % 50 + 20, Point(x, y), nullptr);

            Region region(&textPath);
            graphics->SetClip(&region, CombineModeReplace);

            // Draw a filled ellipse inside the clipped text shape
            SolidBrush brush(Color(rand() % 256, rand() % 256, rand() % 256));
            graphics->FillEllipse(&brush, x, y, w, h);
            break;
        }

        case 36: {
            // Massive Clipping Area (Almost Whole Canvas)
            Rect hugeClip(0, 0, 1000, 1000);
            Region region(hugeClip);
            graphics->SetClip(&region, CombineModeReplace);

            // Draw a pattern inside the large clipped region
            HatchBrush brush((HatchStyle)(rand() % 53),
                Color(rand() % 256, rand() % 256, rand() % 256),
                Color(rand() % 256, rand() % 256, rand() % 256));
            graphics->FillRectangle(&brush, x, y, w, h);
            break;
        }

        case 37: {
            // Tiny Clipping Region (Almost Nothing Visible)
            Rect tinyClip(x, y, rand() % 5 + 1, rand() % 5 + 1);
            Region region(tinyClip);
            graphics->SetClip(&region, CombineModeReplace);

            // Attempt to draw a filled rectangle (most will be clipped)
            SolidBrush brush(Color(rand() % 256, rand() % 256, rand() % 256));
            graphics->FillRectangle(&brush, x, y, w, h);
            break;
        }

        case 38: {
            // Clipping Against Rotated Path
            GraphicsPath path;
            path.AddEllipse(x, y, w, h);

            Matrix transform;
            transform.Rotate(rand() % 360);
            transform.Scale((rand() % 200) / 100.0f, (rand() % 200) / 100.0f);
            path.Transform(&transform);

            Region region(&path);
            graphics->SetClip(&region, CombineModeReplace);

            // Draw an image inside the clipped path
            Image image(L"test.jpg");
            graphics->DrawImage(&image, x, y, w, h);
            break;
        }









        case 39: {
            // 🎥 Metafile Recording & Playback
            HDC hdcRef = GetDC(NULL);
            Metafile* metafile = new Metafile(L"recorded.emf", hdcRef);
            Graphics metaGraphics(metafile);

            // Draw something into the metafile
            Pen pen(Color(rand() % 256, rand() % 256, rand() % 256));
            metaGraphics.DrawLine(&pen, x, y, x + w, y + h);

            delete metafile;
            Metafile playback(L"recorded.emf");
            graphics->DrawImage(&playback, x, y);
            ReleaseDC(NULL, hdcRef);
            break;
        }

        case 40: {
            // ✒ Custom Line Caps for Pens
            Pen pen(Color(rand() % 256, rand() % 256, rand() % 256), rand() % 10 + 1);
            CustomLineCap customCap(nullptr, nullptr);
            pen.SetCustomStartCap(&customCap);
            pen.SetCustomEndCap(&customCap);
            graphics->DrawLine(&pen, x, y, x + w, y + h);
            break;
        }

        case 41: {
            // 📏 DashPattern with Unusual Values
            Pen pen(Color(rand() % 256, rand() % 256, rand() % 256), rand() % 5 + 1);
            float pattern[4] = { rand() % 20, rand() % 20, rand() % 20, rand() % 20 };
            pen.SetDashPattern(pattern, 4);
            graphics->DrawLine(&pen, x, y, x + w, y + h);
            break;
        }

        case 42: {
            // 🌈 Path Gradient with Multiple Colors
            GraphicsPath path;
            path.AddEllipse(x, y, w, h);
            PathGradientBrush brush(&path);

            int colorCount = rand() % 5 + 2;
            Color* colors = new Color[colorCount];
            for (int i = 0; i < colorCount; i++)
                colors[i] = Color(rand() % 256, rand() % 256, rand() % 256);

            brush.SetSurroundColors(colors, &colorCount);
            graphics->FillPath(&brush, &path);
            delete[] colors;
            break;
        }

        case 43: {
            // 🖌 TextureBrush with Transformations
            Image image(L"texture.jpg");
            TextureBrush brush(&image);
            Matrix matrix;
            matrix.Rotate(rand() % 360);
            matrix.Scale((rand() % 200) / 100.0f, (rand() % 200) / 100.0f);
            brush.SetTransform(&matrix);
            graphics->FillRectangle(&brush, x, y, w, h);
            break;
        }

        case 44: {
            // ➿ Compound Lines & Complex Joins
            Pen pen(Color(rand() % 256, rand() % 256, rand() % 256), rand() % 10 + 1);
            float compoundArray[3] = { 0.0f, 0.3f, 1.0f };
            pen.SetCompoundArray(compoundArray, 3);
            graphics->DrawRectangle(&pen, x, y, w, h);
            break;
        }

        case 45: {
            // 📦 Graphics Container Stacking
            GraphicsContainer container = graphics->BeginContainer();
            graphics->RotateTransform(rand() % 360);
            graphics->ScaleTransform((rand() % 200) / 100.0f, (rand() % 200) / 100.0f);
            graphics->DrawRectangle(new Pen(Color(rand() % 256, rand() % 256, rand() % 256)), x, y, w, h);
            graphics->EndContainer(container);
            break;
        }

        case 46: {
            // 📝 DrawString with Extreme Spacing & Alignment
            std::wstring randomText = GenerateRandomString(rand() % 30 + 10);
            Font font(L"Arial", rand() % 100 + 10);
            SolidBrush brush(Color(rand() % 256, rand() % 256, rand() % 256));
            StringFormat format;
            format.SetAlignment((StringAlignment)(rand() % 3));
            // format.SetLineSpacing(rand() % 50 + 5, rand() % 50 + 5);
            graphics->DrawString(randomText.c_str(), -1, &font, PointF(x, y), &format, &brush);
            break;
        }

        case 47: {
            // 🎨 Image Resampling & Pixel Formats
            Bitmap bitmap(L"test.jpg");
            // bitmap.ConvertFormat(PixelFormat32bppARGB, DitherTypeErrorDiffusion, PaletteTypeOptimal, nullptr, 0);
            graphics->DrawImage(&bitmap, x, y, w, h);
            break;
        }

        case 48: {
            // 🔳 Path Clipping with Intersecting Regions
            GraphicsPath path1, path2;
            path1.AddRectangle(Rect(x, y, w, h));
            path2.AddEllipse(x + 20, y + 20, w / 2, h / 2);

            Region region(&path1);
            region.Intersect(&path2);
            graphics->SetClip(&region, CombineModeReplace);

            SolidBrush brush(Color(rand() % 256, rand() % 256, rand() % 256));
            graphics->FillRectangle(&brush, x, y, w, h);
            break;
        }


















        }
    }

    delete graphics;
    delete metafile;
    GdiplusShutdown(gdiplusToken);
    ReleaseDC(NULL, hdc);
}

int main() {
    srand(static_cast<unsigned>(time(0)));
    for (int i = 0; i < NUM_FILES; i++) {
        printf("Current: %d\n", i);
        wchar_t filename[256];
        swprintf(filename, 256, L"generated\\generated_%03d.emf", i);
        GenerateRandomEMF(filename);
    }
    return 0;
}
// Can you add the PathGradientBrush and TextureBrush to the fuzzer?




```


## Making a dictionary of good records.

Ok, so I think that we should also generate a dictionary of good records which we can take a record from during fuzzing and insert it into a file.







## TODO:

- Remove the mutable fields function, because it is useless.
- Do the benchmark.
- Support objects within optional data like and mutate these types of structures (hard).
- Add a default thing for the record types which aren't in the autogenerated stuff, because they don't follow the format.

























































