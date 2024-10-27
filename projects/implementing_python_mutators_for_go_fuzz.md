
# Implementing custom python mutators for go-fuzz




Ok, so there is this bullshit which we have to do. I already did something very similar to this while trying to add python custom mutators to cargo afl fuzz, which you can read about here:

I basically modified the source code of the rust libfuzzer library such that there is a call to the custom mutator inside libfuzzer itself and I was able to make it work that way. I think something similar to that works here.

I tried to look around at custom mutators for go-fuzz but found this: https://github.com/dvyukov/go-fuzz/issues/319 for which there was no satisfying conclusion.



Ok, so I basically decided to add python custom mutator support for go-fuzz. This should fix this issue: https://github.com/dvyukov/go-fuzz/issues/319

First of all, I actually already had a working python mutator for libfuzzer here: https://github.com/personnumber3377/libfuzzer-python-bridge . It adds a couple of small changes to the code. Now I just need to implement that to go-fuzz.

First of all, the source in `go-fuzz-build/main.go` adds a C code template which is then compiled with the libfuzzer library to give you the final binary:

```
var mainSrcLibFuzzer = template.Must(template.New("main").Parse(`
package main

import (
	"unsafe"
	"reflect"
	target "{{.Pkg}}"
	dep "go-fuzz-dep"
)

// #cgo CFLAGS: -Wall -Werror
// #ifdef __linux__
// __attribute__((weak, section("__libfuzzer_extra_counters")))
// #else
// #error Currently only Linux is supported
// #endif
// unsigned char GoFuzzCoverageCounters[65536];
import "C"

//export LLVMFuzzerInitialize
func LLVMFuzzerInitialize(argc uintptr, argv uintptr) int {
	dep.Initialize(unsafe.Pointer(&C.GoFuzzCoverageCounters[0]), 65536)
	return 0
}

//export LLVMFuzzerTestOneInput
func LLVMFuzzerTestOneInput(data uintptr, size uint64) int {
	sh := &reflect.SliceHeader{
	    Data: data,
	    Len:  int(size),
	    Cap:  int(size),
	}

	input := *(*[]byte)(unsafe.Pointer(sh))
	target.{{.DefaultFunc}}(input)

	return 0
}

func main() {
}
`))
```

We basically need to add the python bridge to this code.

This change does that:

```
diff --git a/go-fuzz-build/main.go b/go-fuzz-build/main.go
index 581cfee..fc51978 100644
--- a/go-fuzz-build/main.go
+++ b/go-fuzz-build/main.go
@@ -862,6 +862,10 @@ func main() {
 }
 `))

+// Originally the cgo flags was like this: "// #cgo CFLAGS: -Wall -Werror LDFLAGS: -lpython3.10"
+
+// CFLAGS: -Wall -Werror -I/usr/include/python3.10/
+
 var mainSrcLibFuzzer = template.Must(template.New("main").Parse(`
 package main

@@ -872,17 +876,20 @@ import (
 	dep "go-fuzz-dep"
 )

-// #cgo CFLAGS: -Wall -Werror
+// #cgo LDFLAGS: -l python3.10
+// #cgo CFLAGS: -I/usr/include/python3.10/ -I/home/oof/gitaly/
 // #ifdef __linux__
 // __attribute__((weak, section("__libfuzzer_extra_counters")))
 // #else
 // #error Currently only Linux is supported
 // #endif
 // unsigned char GoFuzzCoverageCounters[65536];
+// #include "harness.h"
 import "C"

 //export LLVMFuzzerInitialize
 func LLVMFuzzerInitialize(argc uintptr, argv uintptr) int {
+	C.LLVMFuzzerInitPythonModule()
 	dep.Initialize(unsafe.Pointer(&C.GoFuzzCoverageCounters[0]), 65536)
 	return 0
 }

```

It of course assumes that the `harness.h` file is in the `/home/oof/gitaly/` directory. I was too lazy to program any path, so I just chose that one. Of course you must replace this with your own directory. I have this fork at: https://github.com/personnumber3377/go-fuzz

I also had to add a couple of environment variables:

```
export GO111MODULE=off
export GOPATH=~/go/
```

also you need to have the code at: `~/go/src/github.com/dvyukov/go-fuzz` for it to compile succesfully. To compile, just run `go install ./go-fuzz ./go-fuzz-build/` and it should put the compiled binaries in `~/go/bin/` so remember to add that to your path

Here is the source of `harness.h`:

```


#include <Python.h>

/*

void LLVMFuzzerFinalizePythonModule();
*/


void LLVMFuzzerInitPythonModule();

PyObject* py_module = NULL;





void py_fatal_error() {
  fprintf(stderr, "The libFuzzer Python layer encountered a critical error.\n");
  fprintf(stderr, "Please fix the messages above and then restart fuzzing.\n");
  exit(1);
}


PyObject* mutator;


PyObject* otherthing;

size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);








PyObject* LLVMFuzzerMutatePyCallback(PyObject* data, PyObject* args) {
  PyObject* py_value;

  py_value = PyTuple_GetItem(args, 1);
  if (!py_value) {
    fprintf(stderr, "Error: Missing MaxSize argument to native callback.\n");
    py_fatal_error();
  }
  size_t MaxSize = PyLong_AsSize_t(py_value);
  if (MaxSize == (size_t)-1 && PyErr_Occurred()) {
    PyErr_Print();
    fprintf(stderr, "Error: Failed to convert MaxSize argument to size_t.\n");
    py_fatal_error();
  }

  py_value = PyTuple_GetItem(args, 0);
  size_t Size = (size_t)PyByteArray_Size(py_value);
  if (PyByteArray_Resize(py_value, MaxSize) < 0) {
    fprintf(stderr, "Error: Failed to resize ByteArray to MaxSize.\n");
    py_fatal_error();
  }

  size_t RetLen =
    LLVMFuzzerMutate((uint8_t *)PyByteArray_AsString(py_value), Size, MaxSize);

  if (PyByteArray_Resize(py_value, RetLen) < 0) {
    fprintf(stderr, "Error: Failed to resize ByteArray to RetLen.\n");
    py_fatal_error();
  }

  Py_RETURN_NONE;
}

PyMethodDef LLVMFuzzerMutatePyMethodDef = {
  "LLVMFuzzerMutate",
  LLVMFuzzerMutatePyCallback,
  METH_VARARGS | METH_STATIC,
  NULL
};

void LLVMFuzzerInitPythonModule() {
  Py_Initialize();
  char* module_name = getenv("LIBFUZZER_PYTHON_MODULE");

  if (module_name) {
    PyObject* py_name = PyUnicode_FromString(module_name);

    py_module = PyImport_Import(py_name);
    Py_DECREF(py_name);

    if (py_module != NULL) {
      mutator =
        PyObject_GetAttrString(py_module, "custom_mutator");
      otherthing =
        PyObject_GetAttrString(py_module, "custom_crossover");

      if (!mutator
        || !PyCallable_Check(mutator)) {
        if (PyErr_Occurred())
          PyErr_Print();
        fprintf(stderr, "Error: Cannot find/call custom mutator function in"
                        " external Python module.\n");
        py_fatal_error();
      }

      if (!otherthing
        || !PyCallable_Check(otherthing)) {
        if (PyErr_Occurred())
          PyErr_Print();
        fprintf(stderr, "Warning: Python module does not implement crossover"
                        " API, standard crossover will be used.\n");
        otherthing = NULL;
      }
    } else {
      if (PyErr_Occurred())
        PyErr_Print();
      fprintf(stderr, "Error: Failed to load external Python module \"%s\"\n",
        module_name);
      py_fatal_error();
    }
  } else {
    fprintf(stderr, "Warning: No Python module specified, using the default libfuzzer mutator (for now).\n");
    }


}


/*
PyObject mutator;


PyObject otherthing;
*/



size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
  if (!py_module) {
		return LLVMFuzzerMutate(Data, Size, MaxSize);
  }
  PyObject* py_args = PyTuple_New(4);

  PyObject* py_value = PyByteArray_FromStringAndSize((const char*)Data, Size);
  if (!py_value) {
    Py_DECREF(py_args);
    fprintf(stderr, "Error: Failed to convert buffer.\n");
    py_fatal_error();
  }
  PyTuple_SetItem(py_args, 0, py_value);

  py_value = PyLong_FromSize_t(MaxSize);
  if (!py_value) {
    Py_DECREF(py_args);
    fprintf(stderr, "Error: Failed to convert maximum size.\n");
    py_fatal_error();
  }
  PyTuple_SetItem(py_args, 1, py_value);

  py_value = PyLong_FromUnsignedLong((unsigned long)Seed);
  if (!py_value) {
    Py_DECREF(py_args);
    fprintf(stderr, "Error: Failed to convert seed.\n");
    py_fatal_error();
  }
  PyTuple_SetItem(py_args, 2, py_value);

  PyObject* py_callback = PyCFunction_New(&LLVMFuzzerMutatePyMethodDef, NULL);
  if (!py_callback) {
    fprintf(stderr, "Failed to create native callback\n");
    py_fatal_error();
  }

  PyTuple_SetItem(py_args, 3, py_callback);

  py_value = PyObject_CallObject(mutator, py_args);

  Py_DECREF(py_args);
  Py_DECREF(py_callback);

  if (py_value != NULL) {
    ssize_t ReturnedSize = PyByteArray_Size(py_value);
    if (ReturnedSize > MaxSize) {
      fprintf(stderr, "Warning: Python module returned buffer that exceeds "
                      "the maximum size. Returning a truncated buffer.\n");
      ReturnedSize = MaxSize;
    }
    memcpy(Data, PyByteArray_AsString(py_value), ReturnedSize);
    Py_DECREF(py_value);
    if (getenv("FUZZ_ONLY_CUSTOM")) {
			return ReturnedSize;
    }


    return LLVMFuzzerMutate(Data, ReturnedSize, MaxSize);

  } else {
    if (PyErr_Occurred())
      PyErr_Print();
    fprintf(stderr, "Error: Call failed\n");
    py_fatal_error();
  }
  return 0;
}


```

The original libfuzzer-python-bridge code was in c++, but cgo only supports c code so I had to modify the code.

## Linking problems

Ok, so the architecture of cgo is quite janky and you actually can not implement functions in the cgo C-code. You can only declare them. This is because otherwise you get linking errors about multiple definitions like this:

```

```

These can be solved by just ignoring them :D . (Explained below)


## How to actually compile?

So just after compiling the go-fuzz-build with all of the required modifications (adding the harness code etc) run these commands:

```
go-fuzz-build -libfuzzer -o fuzz_target_name.a ./<yourfuzztargethere>
clang -fsanitize=fuzzer fuzz_target_name.a -o fuzz_target_name # This command should actually fail with the linking errors explained below.
```

The `clang` command fails with these linker errors

```
/usr/bin/ld: rangediff_fuzzer.a(000001.o): in function `py_fatal_error':
/home/oof/gitaly/harness.h:19: multiple definition of `py_fatal_error'; rangediff_fuzzer.a(000000.o):/home/oof/gitaly/harness.h:19: first defined here
/usr/bin/ld: rangediff_fuzzer.a(000001.o): in function `LLVMFuzzerMutatePyCallback':
/home/oof/gitaly/harness.h:40: multiple definition of `LLVMFuzzerMutatePyCallback'; rangediff_fuzzer.a(000000.o):/home/oof/gitaly/harness.h:40: first defined here
/usr/bin/ld: rangediff_fuzzer.a(000001.o): in function `LLVMFuzzerInitPythonModule':
/home/oof/gitaly/harness.h:80: multiple definition of `LLVMFuzzerInitPythonModule'; rangediff_fuzzer.a(000000.o):/home/oof/gitaly/harness.h:80: first defined here
/usr/bin/ld: rangediff_fuzzer.a(000001.o):/home/oof/gitaly/harness.h:13: multiple definition of `py_module'; rangediff_fuzzer.a(000000.o):/home/oof/gitaly/harness.h:13: first defined here
/usr/bin/ld: rangediff_fuzzer.a(000001.o):/home/oof/gitaly/harness.h:26: multiple definition of `mutator'; rangediff_fuzzer.a(000000.o):/home/oof/gitaly/harness.h:26: first defined here
/usr/bin/ld: rangediff_fuzzer.a(000001.o):/home/oof/gitaly/harness.h:29: multiple definition of `otherthing'; rangediff_fuzzer.a(000000.o):/home/oof/gitaly/harness.h:29: first defined here
/usr/bin/ld: rangediff_fuzzer.a(000001.o): in function `LLVMFuzzerCustomMutator':
/home/oof/gitaly/harness.h:138: multiple definition of `LLVMFuzzerCustomMutator'; rangediff_fuzzer.a(000000.o):/home/oof/gitaly/harness.h:138: first defined here
/usr/bin/ld: rangediff_fuzzer.a(000001.o):/home/oof/gitaly/harness.h:73: multiple definition of `LLVMFuzzerMutatePyMethodDef'; rangediff_fuzzer.a(000000.o):/home/oof/gitaly/harness.h:73: first defined here
/usr/bin/ld: rangediff_fuzzer.a(000000.o): in function `LLVMFuzzerMutatePyCallback':
/home/oof/gitaly/harness.h:43: undefined reference to `PyTuple_GetItem'
/usr/bin/ld: /home/oof/gitaly/harness.h:48: undefined reference to `PyLong_AsSize_t'
/usr/bin/ld: /home/oof/gitaly/harness.h:55: undefined reference to `PyTuple_GetItem'
/usr/bin/ld: /home/oof/gitaly/harness.h:56: undefined reference to `PyByteArray_Size'
/usr/bin/ld: /home/oof/gitaly/harness.h:57: undefined reference to `PyByteArray_Resize'
/usr/bin/ld: /home/oof/gitaly/harness.h:63: undefined reference to `PyByteArray_AsString'
/usr/bin/ld: /home/oof/gitaly/harness.h:65: undefined reference to `PyByteArray_Resize'
/usr/bin/ld: rangediff_fuzzer.a(000000.o): in function `_Py_INCREF':
/usr/include/python3.10/object.h:472: undefined reference to `_Py_NoneStruct'
/usr/bin/ld: rangediff_fuzzer.a(000000.o): in function `LLVMFuzzerMutatePyCallback':
/home/oof/gitaly/harness.h:49: undefined reference to `PyErr_Occurred'
/usr/bin/ld: /home/oof/gitaly/harness.h:50: undefined reference to `PyErr_Print'
/usr/bin/ld: rangediff_fuzzer.a(000000.o): in function `LLVMFuzzerInitPythonModule':
/home/oof/gitaly/harness.h:81: undefined reference to `Py_Initialize'
/usr/bin/ld: /home/oof/gitaly/harness.h:85: undefined reference to `PyUnicode_FromString'
/usr/bin/ld: /home/oof/gitaly/harness.h:87: undefined reference to `PyImport_Import'
/usr/bin/ld: /home/oof/gitaly/harness.h:92: undefined reference to `PyObject_GetAttrString'
/usr/bin/ld: /home/oof/gitaly/harness.h:94: undefined reference to `PyObject_GetAttrString'
/usr/bin/ld: /home/oof/gitaly/harness.h:97: undefined reference to `PyCallable_Check'
/usr/bin/ld: /home/oof/gitaly/harness.h:106: undefined reference to `PyCallable_Check'
/usr/bin/ld: /home/oof/gitaly/harness.h:107: undefined reference to `PyErr_Occurred'
/usr/bin/ld: /home/oof/gitaly/harness.h:108: undefined reference to `PyErr_Print'
/usr/bin/ld: rangediff_fuzzer.a(000000.o): in function `_Py_DECREF':
/usr/include/python3.10/object.h:500: undefined reference to `_Py_Dealloc'
/usr/bin/ld: rangediff_fuzzer.a(000000.o): in function `LLVMFuzzerInitPythonModule':
/home/oof/gitaly/harness.h:114: undefined reference to `PyErr_Occurred'
/usr/bin/ld: /home/oof/gitaly/harness.h:115: undefined reference to `PyErr_Print'
/usr/bin/ld: /home/oof/gitaly/harness.h:98: undefined reference to `PyErr_Occurred'
/usr/bin/ld: /home/oof/gitaly/harness.h:99: undefined reference to `PyErr_Print'
/usr/bin/ld: rangediff_fuzzer.a(000000.o): in function `LLVMFuzzerCustomMutator':
/home/oof/gitaly/harness.h:142: undefined reference to `PyTuple_New'
/usr/bin/ld: /home/oof/gitaly/harness.h:144: undefined reference to `PyByteArray_FromStringAndSize'
/usr/bin/ld: /home/oof/gitaly/harness.h:150: undefined reference to `PyTuple_SetItem'
/usr/bin/ld: /home/oof/gitaly/harness.h:152: undefined reference to `PyLong_FromSize_t'
/usr/bin/ld: /home/oof/gitaly/harness.h:158: undefined reference to `PyTuple_SetItem'
/usr/bin/ld: /home/oof/gitaly/harness.h:160: undefined reference to `PyLong_FromUnsignedLong'
/usr/bin/ld: /home/oof/gitaly/harness.h:166: undefined reference to `PyTuple_SetItem'
/usr/bin/ld: /home/oof/gitaly/harness.h:168: undefined reference to `PyCMethod_New'
/usr/bin/ld: /home/oof/gitaly/harness.h:174: undefined reference to `PyTuple_SetItem'
/usr/bin/ld: /home/oof/gitaly/harness.h:176: undefined reference to `PyObject_CallObject'
/usr/bin/ld: /home/oof/gitaly/harness.h:182: undefined reference to `PyByteArray_Size'
/usr/bin/ld: /home/oof/gitaly/harness.h:188: undefined reference to `PyByteArray_AsString'
/usr/bin/ld: rangediff_fuzzer.a(000000.o): in function `_Py_DECREF':
/usr/include/python3.10/object.h:500: undefined reference to `_Py_Dealloc'
/usr/bin/ld: rangediff_fuzzer.a(000000.o): in function `LLVMFuzzerCustomMutator':
/home/oof/gitaly/harness.h:198: undefined reference to `PyErr_Occurred'
/usr/bin/ld: /home/oof/gitaly/harness.h:199: undefined reference to `PyErr_Print'
/usr/bin/ld: rangediff_fuzzer.a(000000.o): in function `_Py_DECREF':
/usr/include/python3.10/object.h:500: undefined reference to `_Py_Dealloc'
/usr/bin/ld: /usr/include/python3.10/object.h:500: undefined reference to `_Py_Dealloc'
/usr/bin/ld: /usr/include/python3.10/object.h:500: undefined reference to `_Py_Dealloc'
/usr/bin/ld: /usr/include/python3.10/object.h:500: undefined reference to `_Py_Dealloc'
/usr/bin/ld: /usr/include/python3.10/object.h:500: undefined reference to `_Py_Dealloc'
/usr/bin/ld: rangediff_fuzzer.a(000001.o): in function `LLVMFuzzerMutatePyCallback':
/home/oof/gitaly/harness.h:43: undefined reference to `PyTuple_GetItem'
/usr/bin/ld: /home/oof/gitaly/harness.h:48: undefined reference to `PyLong_AsSize_t'
/usr/bin/ld: /home/oof/gitaly/harness.h:55: undefined reference to `PyTuple_GetItem'
/usr/bin/ld: /home/oof/gitaly/harness.h:56: undefined reference to `PyByteArray_Size'
/usr/bin/ld: /home/oof/gitaly/harness.h:57: undefined reference to `PyByteArray_Resize'
/usr/bin/ld: /home/oof/gitaly/harness.h:63: undefined reference to `PyByteArray_AsString'
/usr/bin/ld: /home/oof/gitaly/harness.h:65: undefined reference to `PyByteArray_Resize'
/usr/bin/ld: rangediff_fuzzer.a(000001.o): in function `_Py_INCREF':
/usr/include/python3.10/object.h:472: undefined reference to `_Py_NoneStruct'
/usr/bin/ld: rangediff_fuzzer.a(000001.o): in function `LLVMFuzzerMutatePyCallback':
/home/oof/gitaly/harness.h:49: undefined reference to `PyErr_Occurred'
/usr/bin/ld: /home/oof/gitaly/harness.h:50: undefined reference to `PyErr_Print'
/usr/bin/ld: rangediff_fuzzer.a(000001.o): in function `LLVMFuzzerInitPythonModule':
/home/oof/gitaly/harness.h:81: undefined reference to `Py_Initialize'
/usr/bin/ld: /home/oof/gitaly/harness.h:85: undefined reference to `PyUnicode_FromString'
/usr/bin/ld: /home/oof/gitaly/harness.h:87: undefined reference to `PyImport_Import'
/usr/bin/ld: /home/oof/gitaly/harness.h:92: undefined reference to `PyObject_GetAttrString'
/usr/bin/ld: /home/oof/gitaly/harness.h:94: undefined reference to `PyObject_GetAttrString'
/usr/bin/ld: /home/oof/gitaly/harness.h:97: undefined reference to `PyCallable_Check'
/usr/bin/ld: /home/oof/gitaly/harness.h:106: undefined reference to `PyCallable_Check'
/usr/bin/ld: /home/oof/gitaly/harness.h:107: undefined reference to `PyErr_Occurred'
/usr/bin/ld: /home/oof/gitaly/harness.h:108: undefined reference to `PyErr_Print'
/usr/bin/ld: rangediff_fuzzer.a(000001.o): in function `_Py_DECREF':
/usr/include/python3.10/object.h:500: undefined reference to `_Py_Dealloc'
/usr/bin/ld: rangediff_fuzzer.a(000001.o): in function `LLVMFuzzerInitPythonModule':
/home/oof/gitaly/harness.h:114: undefined reference to `PyErr_Occurred'
/usr/bin/ld: /home/oof/gitaly/harness.h:115: undefined reference to `PyErr_Print'
/usr/bin/ld: /home/oof/gitaly/harness.h:98: undefined reference to `PyErr_Occurred'
/usr/bin/ld: /home/oof/gitaly/harness.h:99: undefined reference to `PyErr_Print'
/usr/bin/ld: rangediff_fuzzer.a(000001.o): in function `LLVMFuzzerCustomMutator':
/home/oof/gitaly/harness.h:142: undefined reference to `PyTuple_New'
/usr/bin/ld: /home/oof/gitaly/harness.h:144: undefined reference to `PyByteArray_FromStringAndSize'
/usr/bin/ld: /home/oof/gitaly/harness.h:150: undefined reference to `PyTuple_SetItem'
/usr/bin/ld: /home/oof/gitaly/harness.h:152: undefined reference to `PyLong_FromSize_t'
/usr/bin/ld: /home/oof/gitaly/harness.h:158: undefined reference to `PyTuple_SetItem'
/usr/bin/ld: /home/oof/gitaly/harness.h:160: undefined reference to `PyLong_FromUnsignedLong'
/usr/bin/ld: /home/oof/gitaly/harness.h:166: undefined reference to `PyTuple_SetItem'
/usr/bin/ld: /home/oof/gitaly/harness.h:168: undefined reference to `PyCMethod_New'
/usr/bin/ld: /home/oof/gitaly/harness.h:174: undefined reference to `PyTuple_SetItem'
/usr/bin/ld: /home/oof/gitaly/harness.h:176: undefined reference to `PyObject_CallObject'
/usr/bin/ld: /home/oof/gitaly/harness.h:182: undefined reference to `PyByteArray_Size'
/usr/bin/ld: /home/oof/gitaly/harness.h:188: undefined reference to `PyByteArray_AsString'
/usr/bin/ld: rangediff_fuzzer.a(000001.o): in function `_Py_DECREF':
/usr/include/python3.10/object.h:500: undefined reference to `_Py_Dealloc'
/usr/bin/ld: rangediff_fuzzer.a(000001.o): in function `LLVMFuzzerCustomMutator':
/home/oof/gitaly/harness.h:198: undefined reference to `PyErr_Occurred'
/usr/bin/ld: /home/oof/gitaly/harness.h:199: undefined reference to `PyErr_Print'
/usr/bin/ld: rangediff_fuzzer.a(000001.o): in function `_Py_DECREF':
/usr/include/python3.10/object.h:500: undefined reference to `_Py_Dealloc'
/usr/bin/ld: /usr/include/python3.10/object.h:500: undefined reference to `_Py_Dealloc'
/usr/bin/ld: /usr/include/python3.10/object.h:500: undefined reference to `_Py_Dealloc'
/usr/bin/ld: /usr/include/python3.10/object.h:500: undefined reference to `_Py_Dealloc'
/usr/bin/ld: /usr/include/python3.10/object.h:500: undefined reference to `_Py_Dealloc'
clang: error: linker command failed with exit code 1 (use -v to see invocation)

```

to solve this, get the link command from the clang command with this command: `clang -fsanitize=fuzzer rangediff_fuzzer.a -o rangediff_fuzzer -###`

For me, it outputs this:

```

Ubuntu clang version 14.0.0-1ubuntu1.1
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
 "/usr/bin/ld" "-pie" "--hash-style=both" "--build-id" "--eh-frame-hdr" "-m" "elf_x86_64" "-dynamic-linker" "/lib64/ld-linux-x86-64.so.2" "-o" "rangediff_fuzzer" "/lib/x86_64-linux-gnu/Scrt1.o" "/lib/x86_64-linux-gnu/crti.o" "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/crtbeginS.o" "-L/usr/bin/../lib/gcc/x86_64-linux-gnu/12" "-L/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../lib64" "-L/lib/x86_64-linux-gnu" "-L/lib/../lib64" "-L/usr/lib/x86_64-linux-gnu" "-L/usr/lib/../lib64" "-L/usr/lib/llvm-14/bin/../lib" "-L/lib" "-L/usr/lib" "--whole-archive" "/usr/lib/llvm-14/lib/clang/14.0.0/lib/linux/libclang_rt.fuzzer-x86_64.a" "--no-whole-archive" "--whole-archive" "/usr/lib/llvm-14/lib/clang/14.0.0/lib/linux/libclang_rt.fuzzer_interceptors-x86_64.a" "--no-whole-archive" "-lstdc++" "--whole-archive" "/usr/lib/llvm-14/lib/clang/14.0.0/lib/linux/libclang_rt.ubsan_standalone-x86_64.a" "--no-whole-archive" "--dynamic-list=/usr/lib/llvm-14/lib/clang/14.0.0/lib/linux/libclang_rt.ubsan_standalone-x86_64.a.syms" "rangediff_fuzzer.a" "--no-as-needed" "-lpthread" "-lrt" "-lm" "-ldl" "-lgcc" "--as-needed" "-lgcc_s" "--no-as-needed" "-lc" "-lgcc" "--as-needed" "-lgcc_s" "--no-as-needed" "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/crtendS.o" "/lib/x86_64-linux-gnu/crtn.o"


```

now copy that link command into a file called `link.sh` or whatever and then add `"--allow-multiple-definition"` and `"-lpython3.10"` to the link command like so:

```
 "/usr/bin/ld" "-pie" "--hash-style=both" "--build-id" "--eh-frame-hdr" "-m" "elf_x86_64" "-dynamic-linker" "/lib64/ld-linux-x86-64.so.2" "-o" "rangediff_fuzzer" "/lib/x86_64-linux-gnu/Scrt1.o" "/lib/x86_64-linux-gnu/crti.o" "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/crtbeginS.o" "-L/usr/bin/../lib/gcc/x86_64-linux-gnu/12" "-L/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../lib64" "-L/lib/x86_64-linux-gnu" "-L/lib/../lib64" "-L/usr/lib/x86_64-linux-gnu" "-L/usr/lib/../lib64" "-L/usr/lib/llvm-14/bin/../lib" "-L/lib" "-L/usr/lib" "--whole-archive" "/usr/lib/llvm-14/lib/clang/14.0.0/lib/linux/libclang_rt.fuzzer-x86_64.a" "--no-whole-archive" "--whole-archive" "/usr/lib/llvm-14/lib/clang/14.0.0/lib/linux/libclang_rt.fuzzer_interceptors-x86_64.a" "--no-whole-archive" "-lstdc++" "--whole-archive" "/usr/lib/llvm-14/lib/clang/14.0.0/lib/linux/libclang_rt.ubsan_standalone-x86_64.a" "--no-whole-archive" "--dynamic-list=/usr/lib/llvm-14/lib/clang/14.0.0/lib/linux/libclang_rt.ubsan_standalone-x86_64.a.syms" "rangediff_fuzzer.a" "--no-as-needed" "-lpthread" "-lrt" "-lm" "-ldl" "-lgcc" "--as-needed" "-lgcc_s" "--no-as-needed" "-lc" "-lgcc" "--as-needed" "-lgcc_s" "--no-as-needed" "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/crtendS.o" "/lib/x86_64-linux-gnu/crtn.o" "--allow-multiple-definition" "-lpython3.10"
```

and after that command, you should have a working fuzzer binary!!!!

## How to use custom mutator:

To actually use it, you basically need to implement a python function called `custom_mutator` which takes three arguments like so:

```
def custom_mutator(data, max_size, seed, native_mutator):
	# Modify data here.
	return data
```

for example there is an example of this at: https://github.com/MozillaSecurity/libfuzzer-python-bridge/blob/master/pymodules/example_compressed.py


Then to run the fuzzer you can use this script here:

```
#!/bin/sh

export LD_PRELOAD="/usr/lib/python3.10/config-3.10-x86_64-linux-gnu/libpython3.10.so" # You have to preload python3.10 , otherwise you get a runtime error.
export LIBFUZZER_PYTHON_MODULE="mutator" # This is the name of your python custom mutator file. For me it is mutator.py so put your custom mutator in a file called "mutator.py"
export ASAN_OPTIONS="allocator_may_return_null=1:detect_leaks=0:use_sigaltstack=0" # Some ASAN options. Feel free to modify to your liking.
export PYTHONPATH="." # Where to search for the custom mutator. (Use the current directory for now.)
while true; do
	./rangediff_fuzzer_custom -max_len=100000 -timeout=1 rangediffs/ 2>> rangediff_output.txt || true
done




```

That script outputs the fuzz output to a file called "rangediff_output.txt" of course you can play around with that script to your liking.

Please let me know if you have any questions! (File an issue, pull request etc etc) And feel free to mod this however you like. I don't really care.

Thanks for reading! :)







