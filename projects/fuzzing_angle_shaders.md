# Fuzzing angle shaders.

I realized that the chromium shaders and similar components can be a lucrative fuzzing target:

## Gathering a good test corpus...

Ok, so I actually already started this project like a couple of weeks ago and now I am alrady deep in the weeds. First of all, I have developed a custom mutator for glsl code which is the code that is used to write the shaders for the angle shader compiler.

## Doing some investigation

During my development of the custom mutator and trying to fuzz the angle translator I realized that it only really supports the SPIRV output and the GLSL and HLSL output code aren't even touched. In addition, the fuzzer doesn't support compute shaders at all, so there is plenty of missed opportunities to find some juicy bugs in this code...

Checking the corpus that the unittests and the end2end tests produced, produced a neat package of 15k files of which after minimization 1.5k were interesting. During this I realized that the fuzzer doesn't even accept compute shaders at all..

## Modding libfuzzer

In addition, I also had to modify libfuzzer to only use the custom mutator, since that was missing from it. This is because the python custom mutator which I developed always kept the syntax correct, so that the fuzzer could focus on the deeper lever logic instead of simple parsing of the shader source code. Here is my current source code for the shader fuzzer:

{% raw %}
```



```
{% endraw %}

## Why missing tests?

Now, I didn't figure out why the exclusions didn't work, when trying to gather a good corpus from the end2end tests, so I made this script to make a command line parameter automatically which lead to me losing a bunch of tests to the aether because the tests actually do not get based off of the filenames necessarily:

{% raw %}
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
{% endraw %}

instead they must be got using `--gtest_list_tests`

which results in:

{% raw %}
```

```
{% endraw %}

## Improving the custom mutator even further... by comparing against a real vulnerability

See https://issuetracker.google.com/issues/437845672

Ok, so after a ton of fiddling around I now have commit 7edea230908a2ef34650f44c405079101184e889 . The goal right now is to make the custom mutator find the previous bug.

The bug was because I wasn't actually mutating the qualifiers of struct definitions. After actually adding this code here:

{% raw %}
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
{% endraw %}

it now rediscovers the previous bug.

## Implementing custom crossover...

Ok, so time to implement custom crossover...

So I added the custom crossover shit here:

{% raw %}
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
{% endraw %}

and then after recompiling it now calls that python function...

Let's just put this kind of thing here:

{% raw %}
```



```
{% endraw %}

## Recompiling the stuff and then figuring out some stuff....

So I basically need to checkout the latest version and then see if a certain crash occurs on the newest version...

And it didn't. Well, that was embarrassing...

## Commenting out unneeded parts of the compiler (and doing some more research into what the fuck we are actually doing... :D)

Ok, so the compiler is now checking the AST on output, but that is just wasted time for our fuzzing purposes...

Also there is a bug in the actual fuzzing harness: https://github.com/google/angle/pull/99/commits/ff004c1b12f9cd8aad6b9834d481d129e4ba13ed which limits the code coverage stuff...

Also we should disable AST checking since that is useless for our purposes:

```
bool TCompiler::validateAST(TIntermNode *root)
{
    if (mCompileOptions.validateAST)
    {
        bool valid = ValidateAST(root, &mDiagnostics, mValidateASTOptions);

#if defined(ANGLE_ENABLE_ASSERTS)
        if (!valid)
        {
            OutputTree(root, mInfoSink.info);
            fprintf(stderr, "AST validation error(s):\n%s\n", mInfoSink.info.c_str());
        }
#endif
        // In debug, assert validation.  In release, validation errors will be returned back to the
        // application as internal ANGLE errors.
        ASSERT(valid);

        return valid;
    }
    return true;
}
```

and I set that option to false for the purposes of fuzzing. Now, this minified the corpus from 7k files to 2k. I am not sure of that is due to the difference in the version numbers of the versions of the old angle and the new angle etc, but maybe I am wrong...

## Implementing layouts and layout mutations

So the layout directives have made some interesting looking bugs recently, so I think that adding such will do some good for our project... I am currently on commit 2d6d5b95dd9a93d73364bd15643c508c87c43f62

After a bit of fiddling around, I have now implemented the layouts such that they roundtrip correctly and also the values get modified... Yay!

## Investigating performance problems some more...

So I already disabled the AST checking, but the numbers still do not add up, since when I try fuzzing with a null target, I was getting extremely large execs per second and the reason for such is because I was essentially just calling the other mutation things too in addition to the custom mutator but I do not want that...

## Adding more mutations

So there is this block of code here in TextureFunctionHLSL.cpp:

{% raw %}
```

ImmutableString TextureFunctionHLSL::useTextureFunction(const ImmutableString &name,
                                                        TBasicType samplerType,
                                                        int coords,
                                                        size_t argumentCount,
                                                        bool lod0,
                                                        sh::GLenum shaderType)
{
    TextureFunction textureFunction;
    textureFunction.sampler = samplerType;
    textureFunction.coords  = coords;
    textureFunction.method  = TextureFunction::IMPLICIT;
    textureFunction.proj    = false;
    textureFunction.offset  = false;

    if (name == "texture2D" || name == "textureCube" || name == "texture")
    {
        textureFunction.method = TextureFunction::IMPLICIT;
    }
    else if (name == "texture2DProj" || name == "textureProj")
    {
        textureFunction.method = TextureFunction::IMPLICIT;
        textureFunction.proj   = true;
    }
    else if (name == "texture2DLod" || name == "textureCubeLod" || name == "textureLod" ||
             name == "texture2DLodEXT" || name == "textureCubeLodEXT")
    {
        textureFunction.method = TextureFunction::LOD;
    }
    else if (name == "texture2DProjLod" || name == "textureProjLod" ||
             name == "texture2DProjLodEXT")
    {
        textureFunction.method = TextureFunction::LOD;
        textureFunction.proj   = true;
    }
    else if (name == "textureSize")
    {
        textureFunction.method = TextureFunction::SIZE;
    }
    else if (name == "textureOffset")
    {
        textureFunction.method = TextureFunction::IMPLICIT;
        textureFunction.offset = true;
    }
    else if (name == "textureProjOffset")
    {
        textureFunction.method = TextureFunction::IMPLICIT;
        textureFunction.offset = true;
        textureFunction.proj   = true;
    }
    else if (name == "textureLodOffset")
    {
        textureFunction.method = TextureFunction::LOD;
        textureFunction.offset = true;
    }
    else if (name == "textureProjLodOffset")
    {
        textureFunction.method = TextureFunction::LOD;
        textureFunction.proj   = true;
        textureFunction.offset = true;
    }
    else if (name == "texelFetch")
    {
        textureFunction.method = TextureFunction::FETCH;
    }
    else if (name == "texelFetchOffset")
    {
        textureFunction.method = TextureFunction::FETCH;
        textureFunction.offset = true;
    }
    else if (name == "textureGrad" || name == "texture2DGradEXT")
    {
        textureFunction.method = TextureFunction::GRAD;
    }
    else if (name == "textureGradOffset")
    {
        textureFunction.method = TextureFunction::GRAD;
        textureFunction.offset = true;
    }
    else if (name == "textureProjGrad" || name == "texture2DProjGradEXT" ||
             name == "textureCubeGradEXT")
    {
        textureFunction.method = TextureFunction::GRAD;
        textureFunction.proj   = true;
    }
    else if (name == "textureProjGradOffset")
    {
        textureFunction.method = TextureFunction::GRAD;
        textureFunction.proj   = true;
        textureFunction.offset = true;
    }
    else if (name == "textureGather")
    {
        textureFunction.method = TextureFunction::GATHER;
    }
    else if (name == "textureGatherOffset")
    {
        textureFunction.method = TextureFunction::GATHER;
        textureFunction.offset = true;
    }
    else if (name == "textureVideoWEBGL")
    {
        textureFunction.method = TextureFunction::IMPLICIT;
    }
    else
        UNREACHABLE();

    if (textureFunction.method ==
        TextureFunction::IMPLICIT)  // Could require lod 0 or have a bias argument
    {
        size_t mandatoryArgumentCount = 2;  // All functions have sampler and coordinate arguments

        if (textureFunction.offset)
        {
            mandatoryArgumentCount++;
        }

        bool bias = (argumentCount > mandatoryArgumentCount);  // Bias argument is optional

        if (lod0 || shaderType == GL_VERTEX_SHADER)
        {
            if (bias)
            {
                textureFunction.method = TextureFunction::LOD0BIAS;
            }
            else
            {
                textureFunction.method = TextureFunction::LOD0;
            }
        }
        else if (bias)
        {
            textureFunction.method = TextureFunction::BIAS;
        }
    }

    mUsesTexture.insert(textureFunction);
    return textureFunction.name();
}



```
{% endraw %}

 so I think that adding a custom mutation which stresses those texture functions explicitly would do some good. I am also thinking about how I can extract useful patterns from existing shaders for example and then use those existing patterns without having to write an explicit mutator for every even slightly more complex mutation.

In addition, I recognized that I didn't even have the custom crossover enabled, since I was running with "-cross_over=0" . I thought that it disabled only the default crossover, but it also disabled the custom crossover too, well now that that is solved, I am getting quite good coverage which is nice...

## Adding support for the full pipeline fuzzing stuff

Here is the original shader stuff:

```

angle_source_set("shader_fuzzer") {
  sources = [ "src/compiler/fuzz/shader_fuzzer.cpp" ]

  include_dirs = [
    "include",
    "src",
    ".", # Include that shit maybe???
  ]
  # Also put the custom mutator shit

  deps = [
    # ":angle_common_test_utils_shared",
    "$angle_root:angle_gl_enum_utils",
    "$angle_root:angle_image_util",
    "$angle_root:translator",
    ":translator",
    ":mutator_helper",
  ]

  # deps = [ ":translator", ":mutator_helper", ]
}

```








