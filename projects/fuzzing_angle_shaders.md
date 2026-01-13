# Fuzzing angle shaders.

I realized that the chromium shaders and similar components can be a lucrative fuzzing target:

## Gathering a good test corpus...

Ok, so I actually already started this project like a couple of weeks ago and now I am alrady deep in the weeds. First of all, I have developed a custom mutator for glsl code which is the code that is used to write the shaders for the angle shader compiler.

## Doing some investigation

During my development of the custom mutator and trying to fuzz the angle translator I realized that it only really supports the SPIRV output and the GLSL and HLSL output code aren't even touched. In addition, the fuzzer doesn't support compute shaders at all, so there is plenty of missed opportunities to find some juicy bugs in this code...

Checking the corpus that the unittests and the end2end tests produced, produced a neat package of 15k files of which after minimization 1.5k were interesting. During this I realized that the fuzzer doesn't even accept compute shaders at all..

## Modding libfuzzer

In addition, I also had to modify libfuzzer to only use the custom mutator, since that was missing from it. This is because the python custom mutator which I developed always kept the syntax correct, so that the fuzzer could focus on the deeper lever logic instead of simple parsing of the shader source code. Here is my current source code for the shader fuzzer:

```



```

## Why missing tests?

Now, I didn't figure out why the exclusions didn't work, when trying to gather a good corpus from the end2end tests, so I made this script to make a command line parameter automatically which lead to me losing a bunch of tests to the aether because the tests actually do not get based off of the filenames necessarily:

```


'''
    "gl_tests/ReadPixelsTest.cpp",
    "gl_tests/RenderbufferMultisampleTest.cpp",
    "gl_tests/RendererTest.cpp",
    "gl_tests/RequestExtensionTest.cpp",
    "gl_tests/RobustBufferAccessBehaviorTest.cpp",
    "gl_tests/RobustClientMemoryTest.cpp",
    "gl_tests/RobustFragmentShaderOutputTest.cpp",
    "gl_tests/RobustResourceInitTest.cpp",
    "gl_tests/S3TCTextureSizesTest.cpp",
    "gl_tests/SRGBFramebufferTest.cpp",
    "gl_tests/SRGBTextureTest.cpp",
    "gl_tests/SampleVariablesTest.cpp",
    "gl_tests/SamplersTest.cpp",
    "gl_tests/SemaphoreTest.cpp",
    "gl_tests/ShaderAlgorithmTest.cpp",
    "gl_tests/ShaderBinaryTest.cpp",
    "gl_tests/ShaderInterpTest.cpp",
    "gl_tests/ShaderMultisampleInterpolation.cpp",
    "gl_tests/ShaderNonConstGlobalInitializerTest.cpp",
    "gl_tests/ShaderOpTest.cpp",
    "gl_tests/ShaderStorageBufferTest.cpp",
    "gl_tests/ShadingRateQcomTest.cpp",
    "gl_tests/ShadowSamplerFunctionsTest.cpp",
    "gl_tests/SimpleOperationTest.cpp",
    "gl_tests/SixteenBppTextureTest.cpp",
    "gl_tests/StateChangeTest.cpp",
    "gl_tests/SwizzleTest.cpp",
    "gl_tests/TextureExternalUpdateTest.cpp",
    "gl_tests/TextureFixedRateCompressionTest.cpp",
    "gl_tests/TextureMultisampleTest.cpp",
    "gl_tests/TextureRectangleTest.cpp",
    "gl_tests/TextureTest.cpp",
    "gl_tests/TextureUploadFormatTest.cpp",
    "gl_tests/TiledRenderingTest.cpp",
    "gl_tests/TimerQueriesTest.cpp",



    "gl_tests/UniformBufferTest.cpp",
    "gl_tests/UniformTest.cpp",
    "gl_tests/UnpackAlignmentTest.cpp",
    "gl_tests/UnpackRowLength.cpp",
    "gl_tests/VertexAttributeTest.cpp",
    "gl_tests/ViewportTest.cpp",
    "gl_tests/VulkanPerformanceCounterTest.cpp",

'''


tests = [
    # "gl_tests/GetImageTest.cpp",
    # "gl_tests/GetTexLevelParameterTest.cpp",
    # "gl_tests/ImageTest.cpp",
    # "gl_tests/IncompatibleTextureTest.cpp",
    # "gl_tests/IncompleteTextureTest.cpp",
    # "gl_tests/IndexBufferOffsetTest.cpp",
    # "gl_tests/IndexedPointsTest.cpp",
    # "gl_tests/InstancingTest.cpp",
    # "gl_tests/KTXCompressedTextureTest.cpp",
    # "gl_tests/LineLoopTest.cpp",
    # "gl_tests/LinkAndRelinkTest.cpp",
    # "gl_tests/MatrixTest.cpp",
    # "gl_tests/MaxTextureSizeTest.cpp",
    # "gl_tests/MemoryBarrierTest.cpp",
    # "gl_tests/MemoryObjectTest.cpp",
    # "gl_tests/MemorySizeTest.cpp",
    # "gl_tests/MipmapTest.cpp",
    # "gl_tests/MultiDrawTest.cpp",
    # "gl_tests/MultisampleCompatibilityTest.cpp",
    # "gl_tests/MultisampleTest.cpp",
    # "gl_tests/MultisampledRenderToTextureTest.cpp",
    # "gl_tests/MultithreadingTest.cpp",
    # "gl_tests/MultiviewDrawTest.cpp",
    # "gl_tests/ObjectAllocationTest.cpp",
    # "gl_tests/OcclusionQueriesTest.cpp",
    # "gl_tests/PBOExtensionTest.cpp",
    # "gl_tests/PVRTCCompressedTextureTest.cpp",
    # "gl_tests/PackUnpackTest.cpp",
    # "gl_tests/ParallelShaderCompileTest.cpp",
    # "gl_tests/PbufferTest.cpp",
    # "gl_tests/PixelLocalStorageTest.cpp",
    # "gl_tests/PixmapTest.cpp",
    # "gl_tests/PointSpritesTest.cpp",
    # "gl_tests/PolygonModeTest.cpp",
    # "gl_tests/PolygonOffsetClampTest.cpp",
    # "gl_tests/ProgramBinaryTest.cpp",
    # "gl_tests/ProgramInterfaceTest.cpp",
    # "gl_tests/ProgramParameterTest.cpp",
    # "gl_tests/ProgramPipelineTest.cpp",
    # "gl_tests/ProvokingVertexTest.cpp",
    # "gl_tests/QueryObjectValidation.cpp",
    # "gl_tests/ReadOnlyFeedbackLoopTest.cpp",
    "gl_tests/gles1/AlphaFuncTest.cpp",
    "gl_tests/gles1/BGRATextureTest.cpp",
    "gl_tests/gles1/BasicDrawTest.cpp",
    "gl_tests/gles1/BootAnimationTest.cpp",
    "gl_tests/gles1/ClientActiveTextureTest.cpp",
    "gl_tests/gles1/ClientStateEnable.cpp",
    "gl_tests/gles1/ClipPlaneTest.cpp",
    "gl_tests/gles1/ColorMaterialTest.cpp",
    "gl_tests/gles1/CurrentColorTest.cpp",
    "gl_tests/gles1/CurrentNormalTest.cpp",
    "gl_tests/gles1/CurrentTextureCoordsTest.cpp",
    "gl_tests/gles1/DrawTextureTest.cpp",
    "gl_tests/gles1/FogTest.cpp",
    "gl_tests/gles1/FramebufferObjectTest.cpp",
    "gl_tests/gles1/LightsTest.cpp",
    "gl_tests/gles1/MaterialsTest.cpp",
    "gl_tests/gles1/MatrixBuiltinsTest.cpp",
    "gl_tests/gles1/MatrixLoadTest.cpp",
    "gl_tests/gles1/MatrixModeTest.cpp",
    "gl_tests/gles1/MatrixMultTest.cpp",
    "gl_tests/gles1/MatrixStackTest.cpp",
    "gl_tests/gles1/PalettedTextureTest.cpp",
    "gl_tests/gles1/PointParameterTest.cpp",
    "gl_tests/gles1/PointSpriteTest.cpp",
    "gl_tests/gles1/QueryTest.cpp",
    "gl_tests/gles1/ShadeModelTest.cpp",
    "gl_tests/gles1/TextureEnvTest.cpp",
    "gl_tests/gles1/TextureParameterTest.cpp",
    "gl_tests/gles1/TextureTargetEnableTest.cpp",
    "gl_tests/gles1/VertexPointerTest.cpp",
]

# tests = ["gl_tests/UniformTest.cpp"]

def suite_name(path: str) -> str:
    return path.split("/")[-1].replace(".cpp", "")

patterns = [f"{suite_name(t)}.*" for t in tests]

print("--gtest_filter=" + ":".join(patterns))

```

instead they must be got using `--gtest_list_tests`

which results in:

```

```

## Improving the custom mutator even further... by comparing against a real vulnerability

See https://issuetracker.google.com/issues/437845672

Ok, so after a ton of fiddling around I now have commit 7edea230908a2ef34650f44c405079101184e889 . The goal right now is to make the custom mutator find the previous bug.

The bug was because I wasn't actually mutating the qualifiers of struct definitions. After actually adding this code here:

```
        # 🔥 THIS IS THE IMPORTANT PART 🔥
        # if it.declarators and coin(rng, 0.35):
        if coin(rng, 0.50):
            d = rng.choice(it.declarators)

            old = list(d.qualifiers)
            dlog("stuff")
            mutate_declarator_qualifiers(
                d,
                rng,
                storage_pool=["uniform", "buffer", "const", None],
                precision_pool=PRECISION_QUALIFIERS,
            )

            # optional debug / assert-chasing hook
            if "uniform" in d.qualifiers and "uniform" not in old:
                global stop
                stop = True


        # mutate declarators
        if it.declarators and coin(rng, 0.10):
            rng.shuffle(it.declarators)
        if it.declarators and coin(rng, 0.20):
            d = it.declarators[rng.randrange(len(it.declarators))]
            if d.array_size is not None:
                d.array_size = mutate_expr(d.array_size, rng, dummy_scope, env)
```

it now rediscovers the previous bug.

## Implementing custom crossover...

Ok, so time to implement custom crossover...

So I added the custom crossover shit here:

```


// Also add the custom crossover function thing here:

extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t *Data1, size_t Size1,
                                            const uint8_t *Data2, size_t Size2,
                                            uint8_t *Out, size_t MaxOutSize,
                                            unsigned int Seed) {
  // If python module missing or python crossover missing -> fallback to default
  // NOTE: libFuzzer provides LLVMFuzzerCrossOver in some builds, but not always.
  // Safer fallback: just memcpy prefix/suffix or call LLVMFuzzerMutate on one.
  if (!py_module || !py_functions[PY_FUNC_CUSTOM_CROSSOVER]) {
    size_t n = Size1 < MaxOutSize ? Size1 : MaxOutSize;
    memcpy(Out, Data1, n);
    return n;
  }

  PyGILState_STATE gstate = PyGILState_Ensure();

  // args: (data1, data2, max_out_size, seed)
  PyObject *py_args = PyTuple_New(4);

  PyObject *py_d1 = PyByteArray_FromStringAndSize((const char *)Data1, Size1);
  PyObject *py_d2 = PyByteArray_FromStringAndSize((const char *)Data2, Size2);
  PyObject *py_max = PyLong_FromSize_t(MaxOutSize);
  PyObject *py_seed = PyLong_FromUnsignedLong((unsigned long)Seed);

  if (!py_d1 || !py_d2 || !py_max || !py_seed) {
    Py_XDECREF(py_d1); Py_XDECREF(py_d2); Py_XDECREF(py_max); Py_XDECREF(py_seed);
    Py_DECREF(py_args);
    PyGILState_Release(gstate);
    fprintf(stderr, "Error: Failed to build crossover args.\n");
    py_fatal_error();
  }

  PyTuple_SetItem(py_args, 0, py_d1);
  PyTuple_SetItem(py_args, 1, py_d2);
  PyTuple_SetItem(py_args, 2, py_max);
  PyTuple_SetItem(py_args, 3, py_seed);

  PyObject *py_value = PyObject_CallObject(py_functions[PY_FUNC_CUSTOM_CROSSOVER], py_args);
  Py_DECREF(py_args);

  if (!py_value) {
    if (PyErr_Occurred()) PyErr_Print();
    PyGILState_Release(gstate);
    fprintf(stderr, "Error: Python custom_crossover call failed\n");
    py_fatal_error();
  }

  ssize_t ReturnedSize = PyByteArray_Size(py_value);
  if (ReturnedSize < 0) ReturnedSize = 0;
  if ((size_t)ReturnedSize > MaxOutSize) ReturnedSize = (ssize_t)MaxOutSize;

  memcpy(Out, PyByteArray_AsString(py_value), (size_t)ReturnedSize);
  Py_DECREF(py_value);

  PyGILState_Release(gstate);
  return (size_t)ReturnedSize;
}


```

and then after recompiling it now calls that python function...

Let's just put this kind of thing here:

```



```










