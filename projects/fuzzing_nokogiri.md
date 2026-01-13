# Fuzzing nokogiri

I decided to fuzz nokogiri again, because despite not finding any bugs previously, I have now written up a custom mutator with which to play with...

My custom mutator repeats a string many times. This can be used to find Denial Of Service vulnerabilities in software.

To enable the use of my custom mutator with nokogiri, I had to apply the next patch:

{% raw %}
```
diff --git a/gumbo-parser/Makefile b/gumbo-parser/Makefile
index f29a38a3..b5ba4a9d 100644
--- a/gumbo-parser/Makefile
+++ b/gumbo-parser/Makefile
@@ -6,10 +6,10 @@ gtest_lib := googletest/make/gtest_main.a

 # make SANITIZEFLAGS='-fsanitize=undefined -fsanitize=address'
 SANITIZEFLAGS :=
-CPPFLAGS := -Isrc
-CFLAGS := -std=c99 -Os -Wall
+CPPFLAGS := -Isrc /usr/include/python3.10 -L/usr/lib/python3.10/config-3.10-x86_64-linux-gnu/ -lpython3.10 # -I/usr/include/python3.6m -lpython3.6m
+CFLAGS := -std=c99 -Os -Wall -Isrc /usr/include/python3.10 -L/usr/lib/python3.10/config-3.10-x86_64-linux-gnu/ -lpython3.10
 CXXFLAGS := -isystem googletest/include -std=c++11 -Os -Wall
-LDFLAGS := -pthread
+LDFLAGS := -pthread -Isrc /usr/include/python3.10 -L/usr/lib/python3.10/config-3.10-x86_64-linux-gnu/ -lpython3.10

 all: check

@@ -61,6 +61,8 @@ build/run_tests: $(gumbo_objs) $(test_objs) $(gtest_lib)
 check: build/run_tests
 	./build/run_tests

+# -I/usr/include/python3.6m -lpython3.6m
+
 coverage:
 	$(RM) build/{src,test}/*.gcda
 	$(RM) build/*.info
diff --git a/gumbo-parser/fuzzer/build.sh b/gumbo-parser/fuzzer/build.sh
index 849cd12f..373c3b81 100755
--- a/gumbo-parser/fuzzer/build.sh
+++ b/gumbo-parser/fuzzer/build.sh
@@ -28,8 +28,8 @@ srcdir=src-${SANITIZER}

 CC="$($LLVM_CONFIG --bindir)/clang"
 CXX="$($LLVM_CONFIG --bindir)/clang++"
-CXXFLAGS="-fsanitize=fuzzer-no-link"
-CFLAGS="-fsanitize=fuzzer-no-link"
+CXXFLAGS="-fsanitize=fuzzer-no-link -Isrc -I/usr/include/python3.10 -L/usr/lib/python3.10/config-3.10-x86_64-linux-gnu/ -lpython3.10"
+CFLAGS="-fsanitize=fuzzer-no-link -Isrc -I/usr/include/python3.10 -L/usr/lib/python3.10/config-3.10-x86_64-linux-gnu/ -lpython3.10"
 ENGINE_LINK="$(find $($LLVM_CONFIG --libdir) -name libclang_rt.fuzzer-x86_64.a | head -1)"

 if [[ "${SANITIZER}" = "ubsan" ]] ; then
diff --git a/gumbo-parser/fuzzer/parse_fuzzer.cc b/gumbo-parser/fuzzer/parse_fuzzer.cc
index 234d7b72..5d18de56 100644
--- a/gumbo-parser/fuzzer/parse_fuzzer.cc
+++ b/gumbo-parser/fuzzer/parse_fuzzer.cc
@@ -36,6 +36,247 @@ int SanityCheckPointers(const char* input, size_t input_length, const GumboNode*
   return 0;
 }

+
+
+
+// This is to use our custom python mutator type thing...
+
+
+/* This Source Code Form is subject to the terms of the Mozilla Public
+ * License, v. 2.0. If a copy of the MPL was not distributed with this
+ * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
+
+#include <Python.h>
+
+static void LLVMFuzzerFinalizePythonModule();
+static void LLVMFuzzerInitPythonModule();
+
+static PyObject* py_module = NULL;
+
+class LLVMFuzzerPyContext {
+  public:
+    LLVMFuzzerPyContext() {
+      if (!py_module) {
+        LLVMFuzzerInitPythonModule();
+      }
+    }
+    ~LLVMFuzzerPyContext() {
+      if (py_module) {
+        LLVMFuzzerFinalizePythonModule();
+      }
+    }
+};
+
+// This takes care of (de)initializing things properly
+LLVMFuzzerPyContext init;
+
+static void py_fatal_error() {
+  fprintf(stderr, "The libFuzzer Python layer encountered a critical error.\n");
+  fprintf(stderr, "Please fix the messages above and then restart fuzzing.\n");
+  exit(1);
+}
+
+enum {
+  /* 00 */ PY_FUNC_CUSTOM_MUTATOR,
+  /* 01 */ PY_FUNC_CUSTOM_CROSSOVER,
+  PY_FUNC_COUNT
+};
+
+static PyObject* py_functions[PY_FUNC_COUNT];
+
+// Forward-declare the libFuzzer's mutator callback.
+extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
+
+// This function unwraps the Python arguments passed, which must be
+//
+// 1) A bytearray containing the data to be mutated
+// 2) An int containing the maximum size of the new mutation
+//
+// The function will modify the bytearray in-place (and resize it accordingly)
+// if necessary. It returns None.
+PyObject* LLVMFuzzerMutatePyCallback(PyObject* data, PyObject* args) {
+  PyObject* py_value;
+
+  // Get MaxSize first, so we know how much memory we need to allocate
+  py_value = PyTuple_GetItem(args, 1);
+  if (!py_value) {
+    fprintf(stderr, "Error: Missing MaxSize argument to native callback.\n");
+    py_fatal_error();
+  }
+  size_t MaxSize = PyLong_AsSize_t(py_value);
+  if (MaxSize == (size_t)-1 && PyErr_Occurred()) {
+    PyErr_Print();
+    fprintf(stderr, "Error: Failed to convert MaxSize argument to size_t.\n");
+    py_fatal_error();
+  }
+
+  // Now get the ByteArray with our data and resize it appropriately
+  py_value = PyTuple_GetItem(args, 0);
+  size_t Size = (size_t)PyByteArray_Size(py_value);
+  if (PyByteArray_Resize(py_value, MaxSize) < 0) {
+    fprintf(stderr, "Error: Failed to resize ByteArray to MaxSize.\n");
+    py_fatal_error();
+  }
+
+  // Call libFuzzer's native mutator
+  size_t RetLen =
+    LLVMFuzzerMutate((uint8_t *)PyByteArray_AsString(py_value), Size, MaxSize);
+
+  if (PyByteArray_Resize(py_value, RetLen) < 0) {
+    fprintf(stderr, "Error: Failed to resize ByteArray to RetLen.\n");
+    py_fatal_error();
+  }
+
+  Py_RETURN_NONE;
+}
+
+static PyMethodDef LLVMFuzzerMutatePyMethodDef = {
+  "LLVMFuzzerMutate",
+  LLVMFuzzerMutatePyCallback,
+  METH_VARARGS | METH_STATIC,
+  NULL
+};
+
+static void LLVMFuzzerInitPythonModule() {
+  Py_Initialize();
+  char* module_name = getenv("LIBFUZZER_PYTHON_MODULE");
+
+  if (module_name) {
+    PyObject* py_name = PyUnicode_FromString(module_name);
+
+    py_module = PyImport_Import(py_name);
+    Py_DECREF(py_name);
+
+    if (py_module != NULL) {
+      py_functions[PY_FUNC_CUSTOM_MUTATOR] =
+        PyObject_GetAttrString(py_module, "custom_mutator");
+      py_functions[PY_FUNC_CUSTOM_CROSSOVER] =
+        PyObject_GetAttrString(py_module, "custom_crossover");
+
+      if (!py_functions[PY_FUNC_CUSTOM_MUTATOR]
+        || !PyCallable_Check(py_functions[PY_FUNC_CUSTOM_MUTATOR])) {
+        if (PyErr_Occurred())
+          PyErr_Print();
+        fprintf(stderr, "Error: Cannot find/call custom mutator function in"
+                        " external Python module.\n");
+        py_fatal_error();
+      }
+
+      if (!py_functions[PY_FUNC_CUSTOM_CROSSOVER]
+        || !PyCallable_Check(py_functions[PY_FUNC_CUSTOM_CROSSOVER])) {
+        if (PyErr_Occurred())
+          PyErr_Print();
+        fprintf(stderr, "Warning: Python module does not implement crossover"
+                        " API, standard crossover will be used.\n");
+        py_functions[PY_FUNC_CUSTOM_CROSSOVER] = NULL;
+      }
+    } else {
+      if (PyErr_Occurred())
+        PyErr_Print();
+      fprintf(stderr, "Error: Failed to load external Python module \"%s\"\n",
+        module_name);
+      py_fatal_error();
+    }
+  } else {
+    fprintf(stderr, "Warning: No Python module specified, using the default libfuzzer mutator (for now).\n");
+    // py_fatal_error();
+  }
+
+
+}
+
+static void LLVMFuzzerFinalizePythonModule() {
+  if (py_module != NULL) {
+    uint32_t i;
+    for (i = 0; i < PY_FUNC_COUNT; ++i)
+      Py_XDECREF(py_functions[i]);
+    Py_DECREF(py_module);
+  }
+  Py_Finalize();
+}
+
+extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
+                                          size_t MaxSize, unsigned int Seed) {
+  // First check if the custom python mutator is specified:
+  if (!py_module) { // No custom python mutator, so therefore just mutate regularly. (LLVMFuzzerMutate is the default mutator.)
+    return LLVMFuzzerMutate(Data, Size, MaxSize);
+  }
+  PyObject* py_args = PyTuple_New(4);
+
+  // Convert Data and Size to a ByteArray
+  PyObject* py_value = PyByteArray_FromStringAndSize((const char*)Data, Size);
+  if (!py_value) {
+    Py_DECREF(py_args);
+    fprintf(stderr, "Error: Failed to convert buffer.\n");
+    py_fatal_error();
+  }
+  PyTuple_SetItem(py_args, 0, py_value);
+
+  // Convert MaxSize to a PyLong
+  py_value = PyLong_FromSize_t(MaxSize);
+  if (!py_value) {
+    Py_DECREF(py_args);
+    fprintf(stderr, "Error: Failed to convert maximum size.\n");
+    py_fatal_error();
+  }
+  PyTuple_SetItem(py_args, 1, py_value);
+
+  // Convert Seed to a PyLong
+  py_value = PyLong_FromUnsignedLong((unsigned long)Seed);
+  if (!py_value) {
+    Py_DECREF(py_args);
+    fprintf(stderr, "Error: Failed to convert seed.\n");
+    py_fatal_error();
+  }
+  PyTuple_SetItem(py_args, 2, py_value);
+
+  PyObject* py_callback = PyCFunction_New(&LLVMFuzzerMutatePyMethodDef, NULL);
+  if (!py_callback) {
+    fprintf(stderr, "Failed to create native callback\n");
+    py_fatal_error();
+  }
+
+  // Pass the native callback
+  PyTuple_SetItem(py_args, 3, py_callback);
+
+  py_value = PyObject_CallObject(py_functions[PY_FUNC_CUSTOM_MUTATOR], py_args);
+
+  Py_DECREF(py_args);
+  Py_DECREF(py_callback);
+
+  if (py_value != NULL) {
+    ssize_t ReturnedSize = PyByteArray_Size(py_value);
+    if (ReturnedSize > MaxSize) {
+      fprintf(stderr, "Warning: Python module returned buffer that exceeds "
+                      "the maximum size. Returning a truncated buffer.\n");
+      ReturnedSize = MaxSize;
+    }
+    memcpy(Data, PyByteArray_AsString(py_value), ReturnedSize);
+    Py_DECREF(py_value);
+    // return ReturnedSize; // Instead of returning the python custom mutator, we should also try to use the original custom mutator too (maybe).
+    if (getenv("FUZZ_ONLY_CUSTOM")) { // Only fuzz with the custom mutator
+      return ReturnedSize;
+    }
+
+
+    return LLVMFuzzerMutate(Data, ReturnedSize, MaxSize);
+
+  } else {
+    if (PyErr_Occurred())
+      PyErr_Print();
+    fprintf(stderr, "Error: Call failed\n");
+    py_fatal_error();
+  }
+  return 0;
+}
+
+
+
+
+
+
+
+
 extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
   /* arbitrary upper size limit to avoid "out-of-memory in parse_fuzzer" reports */
   if (size < 10 | size > 25000) {
```
{% endraw %}

after doing that and compiling the fuzzers, they seem to work fine... except hold on, there is a fucking hardcoded limit to the fuzz stuff:

{% raw %}
```

  /* arbitrary upper size limit to avoid "out-of-memory in parse_fuzzer" reports */
  if (size < 10 | size > 25000) {
    return 0;
  }

```
{% endraw %}

We need to get rid of that.

















