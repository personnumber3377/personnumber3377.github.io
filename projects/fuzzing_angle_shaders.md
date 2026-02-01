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

## Adding some even more mutations...

Ok, so the RewriteLocalPixelStorage.cpp

```
//
// Copyright 2016 The ANGLE Project Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//

// translator_fuzzer.cpp: A libfuzzer fuzzer for the shader translator.

#ifdef UNSAFE_BUFFERS_BUILD
#    pragma allow_unsafe_buffers
#endif

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <unordered_map>

#include "angle_gl.h"
#include "anglebase/no_destructor.h"
#include "common/hash_containers.h"
#include "compiler/translator/Compiler.h"
#include "compiler/translator/util.h"

// Debugging???

#define DEBUGGING 1

using namespace sh;

namespace
{
struct TranslatorCacheKey
{
    bool operator==(const TranslatorCacheKey &other) const
    {
        return type == other.type && spec == other.spec && output == other.output;
    }

    uint32_t type   = 0;
    uint32_t spec   = 0;
    uint32_t output = 0;
};
}  // anonymous namespace

namespace std
{

template <>
struct hash<TranslatorCacheKey>
{
    std::size_t operator()(const TranslatorCacheKey &k) const
    {
        return (hash<uint32_t>()(k.type) << 1) ^ (hash<uint32_t>()(k.spec) >> 1) ^
               hash<uint32_t>()(k.output);
    }
};
}  // namespace std

struct TCompilerDeleter
{
    void operator()(TCompiler *compiler) const { DeleteCompiler(compiler); }
};


void log(const char* msg) {
    /*
    FILE* fp = fopen("/home/oof/angle_log.txt", "w");
    fwrite(msg, strlen(msg), 1, fp);
    fclose(fp);
    */
#ifdef DEBUGGING
    // fprintf(stderr, "%s", msg);
    //std::cerr << msg << "\n";
    ssize_t ret = write(2, msg, strlen(msg));
    (void)ret;
#endif
    return;
}

void log(const std::string msg) {
#ifdef DEBUGGING
    // fprintf(stderr, "%s", msg.c_str()); // Convert to cstring...
    std::cerr << msg << "\n";
#endif
    return;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ShaderDumpHeader header{};
    if (size <= sizeof(header))
    {
        log("size <= sizeof(header)\n");
        return 0;
    }

    // Make sure the rest of data will be a valid C string so that we don't have to copy it.
    if (data[size - 1] != 0)
    {
        log("data[size - 1] != 0\n");
        return 0;
    }

    memcpy(&header, data, sizeof(header));
    ShCompileOptions options{};
    memcpy(&options, &header.basicCompileOptions, offsetof(ShCompileOptions, metal));
    memcpy(&options.metal, &header.metalCompileOptions, sizeof(options.metal));
    memcpy(&options.pls, &header.plsCompileOptions, sizeof(options.pls));
    size -= sizeof(header);
    data += sizeof(header);
    uint32_t type = header.type;
    uint32_t spec = header.spec;

    if (type != GL_FRAGMENT_SHADER && type != GL_VERTEX_SHADER)
    {
        log("invalid type\n");
        return 0;
    }

    // Now for our fuzzing purposes we always want to pick the SH_WEBGL_SPEC thing...

    // spec = SH_WEBGL_SPEC;

    if (spec != SH_GLES2_SPEC && spec != SH_WEBGL_SPEC && spec != SH_GLES3_SPEC &&
        spec != SH_WEBGL2_SPEC)
    {
        log("invalid spec\n");
        return 0;
    }

    ShShaderOutput shaderOutput = static_cast<ShShaderOutput>(header.output);

    // Actually always set it to webgl output...

    /*
    shaderOutput = SH_WGSL_OUTPUT;
    */

    bool hasUnsupportedOptions = false;

    // --- BEGIN: Force-disable all options that can trip hasUnsupportedOptions ---


    /*
    options.addAndTrueToLoopCondition                 = false;
    options.unfoldShortCircuit                        = false;
    options.rewriteRowMajorMatrices                   = false;

    options.emulateAtan2FloatFunction                 = false;
    options.clampFragDepth                            = false;
    options.regenerateStructNames                     = false;
    options.rewriteRepeatedAssignToSwizzled           = false;
    options.useUnusedStandardSharedBlocks             = false;
    options.selectViewInNvGLSLVertexShader            = false;

    options.skipAllValidationAndTransforms             = false;

    options.addVulkanXfbEmulationSupportCode           = false;
    options.roundOutputAfterDithering                  = false;
    options.addAdvancedBlendEquationsEmulation         = false;

    options.expandSelectHLSLIntegerPowExpressions      = false;
    options.allowTranslateUniformBlockToStructuredBuffer = false;
    options.rewriteIntegerUnaryMinusOperator           = false;

    options.ensureLoopForwardProgress                  = false;
    */


    // --- END: Force-disable all options that can trip hasUnsupportedOptions ---

    const bool hasMacGLSLOptions = options.addAndTrueToLoopCondition ||
                                   options.unfoldShortCircuit || options.rewriteRowMajorMatrices;

    if (!IsOutputGLSL(shaderOutput) && !IsOutputESSL(shaderOutput))
    {
        hasUnsupportedOptions =
            hasUnsupportedOptions || options.emulateAtan2FloatFunction || options.clampFragDepth ||
            options.regenerateStructNames || options.rewriteRepeatedAssignToSwizzled ||
            options.useUnusedStandardSharedBlocks || options.selectViewInNvGLSLVertexShader;

        hasUnsupportedOptions = hasUnsupportedOptions || hasMacGLSLOptions;
    }
    else
    {
#if !defined(ANGLE_PLATFORM_APPLE)
        hasUnsupportedOptions = hasUnsupportedOptions || hasMacGLSLOptions;
#endif
    }
    if (!IsOutputESSL(shaderOutput))
    {
        hasUnsupportedOptions = hasUnsupportedOptions || options.skipAllValidationAndTransforms;
    }
    if (!IsOutputSPIRV(shaderOutput))
    {
        hasUnsupportedOptions = hasUnsupportedOptions || options.addVulkanXfbEmulationSupportCode ||
                                options.roundOutputAfterDithering ||
                                options.addAdvancedBlendEquationsEmulation;
    }
    if (!IsOutputHLSL(shaderOutput))
    {
        hasUnsupportedOptions = hasUnsupportedOptions ||
                                options.expandSelectHLSLIntegerPowExpressions ||
                                options.allowTranslateUniformBlockToStructuredBuffer ||
                                options.rewriteIntegerUnaryMinusOperator;
    }
    if (!IsOutputMSL(shaderOutput))
    {
        hasUnsupportedOptions = hasUnsupportedOptions || options.ensureLoopForwardProgress;
    }

    // If there are any options not supported with this output, don't attempt to run the translator.
    if (hasUnsupportedOptions)
    {
        log("hasUnsupportedOptions\n");
        return 0;
    }

    // Make sure the rest of the options are in a valid range.
    options.pls.fragmentSyncType = static_cast<ShFragmentSynchronizationType>(
        static_cast<uint32_t>(options.pls.fragmentSyncType) %
        static_cast<uint32_t>(ShFragmentSynchronizationType::InvalidEnum));

    // Force enable options that are required by the output generators.
    if (IsOutputSPIRV(shaderOutput))
    {
        options.removeInactiveVariables = true;
    }
    if (IsOutputMSL(shaderOutput))
    {
        options.removeInactiveVariables = true;
    }

    std::vector<uint32_t> validOutputs;
    validOutputs.push_back(SH_ESSL_OUTPUT);
    validOutputs.push_back(SH_GLSL_COMPATIBILITY_OUTPUT);
    validOutputs.push_back(SH_GLSL_130_OUTPUT);
    validOutputs.push_back(SH_GLSL_140_OUTPUT);
    validOutputs.push_back(SH_GLSL_150_CORE_OUTPUT);
    validOutputs.push_back(SH_GLSL_330_CORE_OUTPUT);
    validOutputs.push_back(SH_GLSL_400_CORE_OUTPUT);
    validOutputs.push_back(SH_GLSL_410_CORE_OUTPUT);
    validOutputs.push_back(SH_GLSL_420_CORE_OUTPUT);
    validOutputs.push_back(SH_GLSL_430_CORE_OUTPUT);
    validOutputs.push_back(SH_GLSL_440_CORE_OUTPUT);
    validOutputs.push_back(SH_GLSL_450_CORE_OUTPUT);
    validOutputs.push_back(SH_SPIRV_VULKAN_OUTPUT);
    validOutputs.push_back(SH_HLSL_3_0_OUTPUT);
    validOutputs.push_back(SH_HLSL_4_1_OUTPUT);
    // Add some more outputs here too...
    /*
    // Output for MSL
    SH_MSL_METAL_OUTPUT,

    // Output for WGSL
    SH_WGSL_OUTPUT,
    */

    validOutputs.push_back(SH_MSL_METAL_OUTPUT);
    validOutputs.push_back(SH_WGSL_OUTPUT);

    bool found = false;
    for (auto valid : validOutputs)
    {
        found = found || (valid == shaderOutput);
    }
    if (!found)
    {
        log("!found\n");
        return 0;
    }

    if (!sh::Initialize())
    {
        log("!sh::Initialize()\n");
        return 0;
    }

    TranslatorCacheKey key;
    key.type   = type;
    key.spec   = spec;
    key.output = shaderOutput;

    using UniqueTCompiler = std::unique_ptr<TCompiler, TCompilerDeleter>;
    static angle::base::NoDestructor<angle::HashMap<TranslatorCacheKey, UniqueTCompiler>>
        translators;

    if (translators->find(key) == translators->end())
    {
        UniqueTCompiler translator(
            ConstructCompiler(type, static_cast<ShShaderSpec>(spec), shaderOutput));

        if (translator == nullptr)
        {
            log("translator == nullptr\n");
            return 0;
        }

        ShBuiltInResources resources;
        sh::InitBuiltInResources(&resources);

        // Enable all the extensions to have more coverage
        resources.OES_standard_derivatives        = 1;
        resources.OES_EGL_image_external          = 1;
        resources.OES_EGL_image_external_essl3    = 1;
        resources.NV_EGL_stream_consumer_external = 1;
        resources.ARB_texture_rectangle           = 1;
        resources.EXT_blend_func_extended         = 1;
        resources.EXT_conservative_depth          = 1;
        resources.EXT_draw_buffers                = 1;
        resources.EXT_frag_depth                  = 1;
        resources.EXT_shader_texture_lod          = 1;
        resources.EXT_shader_framebuffer_fetch    = 1;
        resources.ARM_shader_framebuffer_fetch    = 1;
        resources.ARM_shader_framebuffer_fetch_depth_stencil = 1;
        resources.EXT_YUV_target                  = 1;
        resources.APPLE_clip_distance             = 1;
        resources.MaxDualSourceDrawBuffers        = 1;
        resources.EXT_gpu_shader5                 = 1;
        resources.MaxClipDistances                = 1;
        resources.EXT_shadow_samplers             = 1;
        resources.EXT_clip_cull_distance          = 1;
        resources.ANGLE_clip_cull_distance        = 1;
        resources.EXT_primitive_bounding_box      = 1;
        resources.OES_primitive_bounding_box      = 1;

        if (!translator->Init(resources))
        {
            return 0;
        }

        (*translators)[key] = std::move(translator);
    }

    auto &translator = (*translators)[key];

    options.limitExpressionComplexity = true;
    const char *shaderStrings[]       = {reinterpret_cast<const char *>(data)};

    // Dump the string being passed to the compiler to ease debugging.
    // The string is written char-by-char and unwanted characters are replaced with whitespace.
    // This is because characters such as \r can hide the shader contents.

    /*
    std::cerr << "\nCompile input with unprintable characters turned to whitespace:\n";
    for (const char *c = shaderStrings[0]; *c; ++c)
    {
        if (*c < ' ' && *c != '\n')
        {
            std::cerr << ' ';
        }
        else
        {
            std::cerr << *c;
        }
    }
    std::cerr << "\nEnd of compile input.\n\n";

    translator->compile(shaderStrings, options);
    */

    // Try to print out the translated source code....

    TInfoSink &infoSink      = translator->getInfoSink();

    if (translator->compile(shaderStrings, options) == 0) { // 0 means failure...
#ifdef DEBUGGING
        fprintf(stderr,
            "================= ANGLE COMPILE FAILED =================\n"
            "%s\n"
            "========================================================\n",
            infoSink.info.c_str());
#endif
        return 0;
    }

    if (!(infoSink.obj.isBinary())) {
        // Not binary, so print the source code...
#ifdef DEBUGGING
        fprintf(stderr, "==============================================\n");
        // fprintf(stderr, "WGSL:\n%s\n", infoSink.obj.c_str());
        fprintf(stderr, "%s\n", infoSink.obj.c_str());
        fprintf(stderr, "==============================================\n");
#endif
    } else {
        log("binary output...\n");
    }

    return 0;
}

```

The ANGLE_shader_pixel_local_storage isn't enabled anywhere here, therefore of course it isn't getting fuzzed as you would expect...

Also we need to check the "invalid spec" failure on the one of the files in the thing...

I added it to the resources. section and now when I run this file here:
```
HEADER: frag 3 6
#version 310 es
#extension GL_ANGLE_shader_pixel_local_storage : require

layout(binding = 0, rgba8) uniform pixelLocalANGLE pls0;

void main()
{
    vec4 v = pixelLocalLoadANGLE(pls0);
    pixelLocalStoreANGLE(pls0, v);
}``` it causes this: ```================= ANGLE COMPILE FAILED =================
ERROR: 0:4: 'pixelLocalANGLE' : No precision specified
ERROR: 0:4: 'layout qualifier' : pixel local storage binding out of range
ERROR: 0:8: '' : No precision specified for (float)

========================================================
Executed ./tests_complex_binary/local_pixel_storage.glsl.bin in 4 ms
***
*** NOTE: fuzzing was not performed, you have only
***       executed the target code on a fixed set of inputs.
***
```

It gets that... That is peculiar.

After grepping the source code for the stuff I noticed this:

```
void TParseContext::checkPixelLocalStorageBindingIsValid(const TSourceLoc &location,
                                                         const TType &type)
{
    TLayoutQualifier layoutQualifier = type.getLayoutQualifier();
    if (type.isArray())
    {
        // PLS is not allowed in arrays.
        // TODO(anglebug.com/40096838): Consider allowing this once more backends are implemented.
        error(location, "pixel local storage handles cannot be aggregated in arrays", "array");
    }
    else if (layoutQualifier.binding < 0)
    {
        error(location, "pixel local storage requires a binding index", "layout qualifier");
    }
    // TODO(anglebug.com/40096838):
    else if (layoutQualifier.binding >= mResources.MaxPixelLocalStoragePlanes)
    {
        error(location, "pixel local storage binding out of range", "layout qualifier");
    }
    else if (mPLSFormats.find(layoutQualifier.binding) != mPLSFormats.end())
    {
        error(location, "duplicate pixel local storage binding index",
              std::to_string(layoutQualifier.binding).c_str());
    }
    else
    {
```

so therefore the angle translator mutator must be improved slightly further...

Then next I got this error here:

```
oof@oof-h8-1440eo:~/shader_custom_mutator$ ./run_pixelstorage.sh
[seed] 32956562
[text→bin] tests_complex/local_pixel_storage.glsl -> tests_complex/local_pixel_storage.glsl.bin
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 4019013082
INFO: Loaded 1 modules   (107830 inline 8-bit counters): 107830 [0x55b3ace70400, 0x55b3ace8a936),
INFO: Loaded 1 PC tables (107830 PCs): 107830 [0x55b3ace8a938,0x55b3ad02fc98),
/home/oof/chromiumstuff/source/src/out/canvasfuzz/angle_translator_fuzzer: Running 1 inputs 1 time(s) each.
Running: ./tests_complex_binary/local_pixel_storage.glsl.bin
FATAL: RewritePixelLocalStorage.cpp:892 (RewritePixelLocalStorage): 	! Unreachable reached: RewritePixelLocalStorage(../../third_party/angle/src/compiler/translator/tree_ops/RewritePixelLocalStorage.cpp:892)
==331318== ERROR: libFuzzer: deadly signal
    #0 0x55b3ac267ac1 in __sanitizer_print_stack_trace (/home/oof/chromiumstuff/source/src/out/canvasfuzz/angle_translator_fuzzer+0x8b3ac1) (BuildId: b57dc503ade9246f)
    #1 0x55b3ac316e1b in fuzzer::PrintStackTrace() third_party/libFuzzer/src/FuzzerUtil.cpp:210:5
    #2 0x55b3ac2d809e in fuzzer::Fuzzer::CrashCallback() third_party/libFuzzer/src/FuzzerLoop.cpp:231:3
    #3 0x7f9f21cdb51f  (/lib/x86_64-linux-gnu/libc.so.6+0x4251f) (BuildId: 4f7b0c955c3d81d7cac1501a2498b69d1d82bfe7)
    #4 0x55b3ac61dedd in sh::RewritePixelLocalStorage(sh::TCompiler*, sh::TIntermBlock*, sh::TSymbolTable&, ShCompileOptions const&, int) third_party/angle/src/compiler/translator/tree_ops/RewritePixelLocalStorage.cpp:892:13
    #5 0x55b3ac4309ef in sh::TCompiler::checkAndSimplifyAST(sh::TIntermBlock*, sh::TParseContext const&, ShCompileOptions const&) third_party/angle/src/compiler/translator/Compiler.cpp:1008:14
    #6 0x55b3ac42c0da in sh::TCompiler::compileTreeImpl(angle::Span<char const* const, 18446744073709551615ul, char const* const*>, ShCompileOptions const&) third_party/angle/src/compiler/translator/Compiler.cpp:583:14
    #7 0x55b3ac433415 in sh::TCompiler::compile(angle::Span<char const* const, 18446744073709551615ul, char const* const*>, ShCompileOptions const&) third_party/angle/src/compiler/translator/Compiler.cpp:1413:26
    #8 0x55b3ac298027 in LLVMFuzzerTestOneInput third_party/angle/src/compiler/fuzz/translator_fuzzer.cpp:374:21
    #9 0x55b3ac2db1f6 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) third_party/libFuzzer/src/FuzzerLoop.cpp:619:13
    #10 0x55b3ac2acacd in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) third_party/libFuzzer/src/FuzzerDriver.cpp:329:6
    #11 0x55b3ac2b5af0 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) third_party/libFuzzer/src/FuzzerDriver.cpp:870:9
    #12 0x55b3ac29c055 in main third_party/libFuzzer/src/FuzzerMain.cpp:20:10
    #13 0x7f9f21cc2d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal

```

and this was solved by adding this stuff here:

```
    // Make sure the rest of the options are in a valid range.
    options.pls.fragmentSyncType = static_cast<ShFragmentSynchronizationType>(
        static_cast<uint32_t>(options.pls.fragmentSyncType) %
        static_cast<uint32_t>(ShFragmentSynchronizationType::InvalidEnum));

    // Check for the required PLS element stuff...

    // Set as default...
    if (options.pls.type == ShPixelLocalStorageType::NotSupported) {
        options.pls.type = ShPixelLocalStorageType::ImageLoadStore;
    }

```

and now it seems to compile all fine...

TODO: We should add some mutations that specifically target this functionality to our thing...


## Improving fuzzing

So, I decided to move to a non assert build of angle, since assertions are slowing us down. I basically just seeded the thing with the previous crashes that do not crash on the non assert build of the thing and then the previous corpus, minimized said corpus and then used the same exact setup as before.

























## COntinuing the actual dawn fuzzing stuff in the thing...






