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
        return -1;
    }

    // Make sure the rest of data will be a valid C string so that we don't have to copy it.
    if (data[size - 1] != 0)
    {
        log("data[size - 1] != 0\n");
        return -1;
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
        return -1;
    }

    // Now for our fuzzing purposes we always want to pick the SH_WEBGL_SPEC thing...

    // spec = SH_WEBGL_SPEC;

    if (spec != SH_GLES2_SPEC && spec != SH_WEBGL_SPEC && spec != SH_GLES3_SPEC &&
        spec != SH_WEBGL2_SPEC)
    {
        log("invalid spec\n");
        return -1;
    }

    ShShaderOutput shaderOutput = static_cast<ShShaderOutput>(header.output);

    // Actually always set it to webgl output...

    
    shaderOutput = SH_WGSL_OUTPUT;
    

    bool hasUnsupportedOptions = false;

    // --- BEGIN: Force-disable all options that can trip hasUnsupportedOptions ---


    
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
        return -1;
    }

    // Make sure the rest of the options are in a valid range.
    options.pls.fragmentSyncType = static_cast<ShFragmentSynchronizationType>(
        static_cast<uint32_t>(options.pls.fragmentSyncType) %
        static_cast<uint32_t>(ShFragmentSynchronizationType::InvalidEnum));

    // Check for the required PLS element stuff...

    // Set as default...
    if (options.pls.type == ShPixelLocalStorageType::NotSupported) {
        options.pls.type = ShPixelLocalStorageType::ImageLoadStore;
    }

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
        return -1;
    }

    if (!sh::Initialize())
    {
        log("!sh::Initialize()\n");
        return -1;
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
            return -1;
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

        // These extensions weren't here initially.

        resources.ANGLE_shader_pixel_local_storage = 1;

        resources.MaxPixelLocalStoragePlanes = 4;
        resources.MaxCombinedDrawBuffersAndPixelLocalStoragePlanes = 8;

        if (!translator->Init(resources))
        {
            return -1;
        }

        (*translators)[key] = std::move(translator);
    }

    auto &translator = (*translators)[key];

    options.limitExpressionComplexity = true;

    // Disable AST validation, because it slows down fuzzing by a lot...

    options.validateAST = false;

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
        return -1;
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
#ifdef DEBUGGING
        log("binary output...\n");
#endif
    }

    return 0;
}
