# Fuzzing webgsl shaders...


Ok, so I want to use darthshader to actually run the shaders on the thing and then hopefully find some bugs in the thing...

Let's see what happens if I just try this out without the python custom mutator alltogether... it seems to speedup...

```

```

## Trying to make darthshader into a shader library instead of standalone program...

So, the issue is that I want to call the darthshader mutator just from the libfuzzer fuzzing target and I want to just use the mutation part of darthshader to fuzz dawn.

```

error[E0599]: no variant or associated item named `from_bytes` found for enum `LayeredInput` in the current scope
   --> src/ffi.rs:29:43
    |
 29 |     let mut layered = match LayeredInput::from_bytes(input) {
    |                                           ^^^^^^^^^^ variant or associated item not found in `LayeredInput`
    |
   ::: src/layeredinput.rs:23:1
    |
 23 | pub enum LayeredInput {
    | --------------------- variant or associated item `from_bytes` not found for this enum
    |
    = help: items from traits can only be used if the trait is implemented and in scope
    = note: the following trait defines an item `from_bytes`, perhaps you need to implement it:
            candidate #1: `OsStrExt`
help: there is a method `bytes` with a similar name, but with different arguments
   --> /home/oof/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/libafl-0.11.2/src/inputs/mod.rs:127:5
    |
127 |     fn bytes(&self) -> &[u8];
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0599]: no method named `mutate` found for tuple `(ASTDeleteMutator, (ASTReplaceTokenMutator, (..., ...)))` in the current scope
   --> src/ffi.rs:41:18
    |
 41 |             muts.mutate(&mut rand, &mut layered).ok();
    |                  ^^^^^^
    |
help: there is a method `mutate_all` with a similar name, but with different arguments
   --> /home/oof/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/libafl-0.11.2/src/mutators/mod.rs:134:5
    |
134 | /     fn mutate_all(
135 | |         &mut self,
136 | |         state: &mut S,
137 | |         input: &mut I,
138 | |         stage_idx: i32,
139 | |     ) -> Result<MutationResult, Error>;
    | |_______________________________________^
    = note: the full name for the type has been written to '/home/oof/darthshader/target/release/deps/darthshader_mutator.long-type-4672211124503799903.txt'
    = note: consider using `--verbose` to print the full type name to the console
help: some of the expressions' fields have a method of the same name
    |
 41 |             muts.0.mutate(&mut rand, &mut layered).ok();
    |                  ++
 41 |             muts.1.0.mutate(&mut rand, &mut layered).ok();
    |                  ++++

error[E0599]: no method named `mutate` found for tuple `(UnaryOpMutator, (BinOpMutator, (MathFuncMutator, ...)))` in the current scope
   --> src/ffi.rs:46:18
    |
 46 |             muts.mutate(&mut rand, &mut layered).ok();
    |                  ^^^^^^
    |
help: there is a method `mutate_all` with a similar name, but with different arguments
   --> /home/oof/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/libafl-0.11.2/src/mutators/mod.rs:134:5
    |
134 | /     fn mutate_all(
135 | |         &mut self,
136 | |         state: &mut S,
137 | |         input: &mut I,
138 | |         stage_idx: i32,
139 | |     ) -> Result<MutationResult, Error>;
    | |_______________________________________^
    = note: the full name for the type has been written to '/home/oof/darthshader/target/release/deps/darthshader_mutator.long-type-14844566120080989425.txt'
    = note: consider using `--verbose` to print the full type name to the console
help: some of the expressions' fields have a method of the same name
    |
 46 |             muts.0.mutate(&mut rand, &mut layered).ok();
    |                  ++
 46 |             muts.1.0.mutate(&mut rand, &mut layered).ok();
    |                  ++++

error[E0599]: no method named `to_wgsl` found for enum `LayeredInput` in the current scope
  --> src/ffi.rs:56:29
   |
56 |     let out = match layered.to_wgsl() {
   |                             ^^^^^^^ method not found in `LayeredInput`
   |
  ::: src/layeredinput.rs:23:1
   |
23 | pub enum LayeredInput {
   | --------------------- method `to_wgsl` not found for this enum

error[E0282]: type annotations needed
  --> src/ffi.rs:57:18
   |
57 |         Ok(s) => s.into_bytes(),
   |                  ^ cannot infer type
```

with this code here:

```

use std::slice;
use std::ptr;
use std::mem;

use libafl_bolts::rands::StdRand;
use libafl::mutators::Mutator;

use crate::{
    layeredinput::LayeredInput,
    ast::mutate::ast_mutations,
    ir::mutate::ir_mutations,
};

#[no_mangle]
pub extern "C" fn darthshader_mutate(
    data: *const u8,
    size: usize,
    seed: u64,
    out_data: *mut *mut u8,
    out_size: *mut usize,
) -> i32 {
    if data.is_null() || out_data.is_null() || out_size.is_null() {
        return -1;
    }

    let input = unsafe { slice::from_raw_parts(data, size) };

    // 1) Parse input
    let mut layered = match LayeredInput::from_bytes(input) {
        Ok(v) => v,
        Err(_) => return -2,
    };

    // 2) RNG
    let mut rand = StdRand::with_seed(seed);

    // 3) Choose mutation domain
    let mutated = match &mut layered {
        LayeredInput::Ast(_) => {
            let mut muts = ast_mutations();
            muts.mutate(&mut rand, &mut layered).ok();
            true
        }
        LayeredInput::IR(_) => {
            let mut muts = ir_mutations();
            muts.mutate(&mut rand, &mut layered).ok();
            true
        }
    };

    if !mutated {
        return -3;
    }

    // 4) Serialize back to WGSL
    let out = match layered.to_wgsl() {
        Ok(s) => s.into_bytes(),
        Err(_) => return -4,
    };

    // 5) Transfer ownership to C
    let mut boxed = out.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    let len = boxed.len();

    mem::forget(boxed);

    unsafe {
        *out_data = ptr;
        *out_size = len;
    }

    0
}

#[no_mangle]
pub extern "C" fn darthshader_free(ptr: *mut u8, size: usize) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(slice::from_raw_parts_mut(ptr, size)));
    }
}

```

## Porting the darthshader stuff to a library...

So I finally managed to make a library out of darthshader and I put it on github here: https://github.com/personnumber3377/dawn_fuzzing in darthshader_lib subdirectory, now I want to just integrate it into the fuzzer which I have here:

```
// fuzz_wgsl_combo_pipeline.cpp
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

// Needed for the file communication and spawning processes...

#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <vector>
#include <sstream>

#include "dawn/dawn_proc.h"
#include "dawn/native/DawnNative.h"

#include "dawn/utils/ComboRenderPipelineDescriptor.h"
#include "dawn/utils/WGPUHelpers.h"  // utils::CreateShaderModule
#include "dawn/common/GPUInfo.h"
#include "webgpu/webgpu_cpp.h"

static std::unique_ptr<dawn::native::Instance> gInstance;

// static wgpu::Adapter gAdapter;
// static wgpu::Device gDevice;

// Start with Null backend for stability; switch later to Vulkan/D3D12/Metal.
// static constexpr wgpu::BackendType kBackend = wgpu::BackendType::Null;

// Debugging

#define DEBUGGING 1

void log(const char* msg) {
    /*
    FILE* fp = fopen("/home/oof/angle_log.txt", "w");
    fwrite(msg, strlen(msg), 1, fp);
    fclose(fp);
    */
#ifdef DEBUGGING
    // fprintf(stderr, "%s", msg);
    //std::cerr << msg << "\n";
    write(2, msg, strlen(msg));
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

const char* kDefaultVertexWGSL = R"(
@vertex
fn main(@builtin(vertex_index) i : u32)
     -> @builtin(position) vec4f {
    let pos = array(
        vec2f(-1.0, -1.0),
        vec2f( 1.0, -1.0),
        vec2f(-1.0,  1.0));
    return vec4f(pos[i], 0.0, 1.0);
}
)";

const char* kDefaultFragmentWGSL = R"(
@fragment
fn main() -> @location(0) vec4f {
    return vec4f(1.0, 0.0, 0.0, 1.0);
}
)";

const char* kDefaultComputeWGSL = R"(
@compute @workgroup_size(1)
fn main() {
}
)";

// wgpu::ShaderModule vert = dawn::utils::CreateShaderModule(gDevice, vertexWGSL); // This is the thing...

/*

static bool InitDeviceOnce() {
    gInstance = std::make_unique<dawn::native::Instance>();

    DawnProcTable procs = dawn::native::GetProcs();
    dawnProcSetProcs(&procs);


    gAdapter = wgpu::Adapter(gInstance->EnumerateAdapters()[0].Get()); // Just get the first one...

    if (!gAdapter) return false;

    wgpu::DeviceDescriptor desc = {};
    gDevice = gAdapter.CreateDevice(&desc);

    // Add error callback shit...

    // This next thing wont work...
    gDevice.SetUncapturedErrorCallback(
    [](wgpu::ErrorType type, const char* message) {
        write(2, message, strlen(message));
        write(2, "\n", 1);
    });


    gDevice.SetLoggingCallback([](wgpu::LoggingType type, wgpu::StringView message) {
        std::string_view view = {message.data, message.length};
        std::cerr << view << "\n";
    });

    return static_cast<bool>(gDevice);
}

*/


/*
static bool InitDeviceOnce() {
    gInstance = std::make_unique<dawn::native::Instance>();

    DawnProcTable procs = dawn::native::GetProcs();
    dawnProcSetProcs(&procs);

    wgpu::Adapter selected;

    for (auto& nativeAdapter : gInstance->EnumerateAdapters()) {
        wgpu::Adapter adapter(nativeAdapter.Get());

        wgpu::AdapterInfo info;
        adapter.GetInfo(&info);

        if (dawn::gpu_info::IsGoogleSwiftshader(info.vendorID, info.deviceID)) {
            selected = adapter;
            break;
        }
    }

    if (!selected) {
        return false;
    }

    gAdapter = selected;

    wgpu::DeviceDescriptor desc = {};
    gDevice = gAdapter.CreateDevice(&desc);

    gDevice.SetLoggingCallback([](wgpu::LoggingType type, wgpu::StringView message) {
        std::cerr << std::string_view{message.data, message.length} << "\n";
    });

    return static_cast<bool>(gDevice);
}
*/


static dawn::native::Instance* gInstanceRaw = nullptr;
static wgpu::Device gDevice;
static wgpu::Adapter gAdapter;

static bool InitDeviceOnce() {

    if (gInstanceRaw) return 1;

    gInstanceRaw = new dawn::native::Instance();

    DawnProcTable procs = dawn::native::GetProcs();
    dawnProcSetProcs(&procs);

    wgpu::Adapter selected;
    for (auto& nativeAdapter : gInstanceRaw->EnumerateAdapters()) {
        wgpu::Adapter adapter(nativeAdapter.Get());
        wgpu::AdapterInfo info;
        adapter.GetInfo(&info);
        if (dawn::gpu_info::IsGoogleSwiftshader(info.vendorID, info.deviceID)) {
            selected = adapter;
            break;
        }
    }
    // Delete this since otherwise we get problems...
    delete gInstanceRaw;
    gInstanceRaw = nullptr; // Also null out the pointer...
    if (!selected) return 1;
    gAdapter = selected;

    wgpu::DeviceDescriptor desc = {};
    gDevice = gAdapter.CreateDevice(&desc);
    return static_cast<bool>(gDevice);
}


struct Stages {
    bool hasVertex   = false;
    bool hasFragment = false;
    bool hasCompute  = false;
};

Stages DetectStages(const std::string& src) {
    Stages s;
    s.hasVertex   = src.find("@vertex")   != std::string::npos;
    s.hasFragment = src.find("@fragment") != std::string::npos;
    s.hasCompute  = src.find("@compute")  != std::string::npos;
    return s;
}

wgpu::ShaderModule Compile(const char* src) {
    return dawn::utils::CreateShaderModule(gDevice, src);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    log("Start...\n");

    // Try to init...
    // gDevice = InitDeviceOnce();

    InitDeviceOnce();

    if (!gDevice) return 0;
    if (size == 0 || size > (1u << 20)) return 0;

    log("Poopoo...\n");

    // Treat fuzzer input as WGSL
    std::string inputWGSL(reinterpret_cast<const char*>(data), size);

    // Detect stages
    Stages stages = DetectStages(inputWGSL);

    // Compile shader modules
    wgpu::ShaderModule inputModule =
        dawn::utils::CreateShaderModule(gDevice, inputWGSL.c_str());

    if (!inputModule) {
        log("Input WGSL failed to compile\n");
        return 0;
    }

    // Compile fallbacks (only if needed)
    wgpu::ShaderModule defaultVert, defaultFrag, defaultComp;

    if (!stages.hasVertex)
        defaultVert = Compile(kDefaultVertexWGSL);
    if (!stages.hasFragment)
        defaultFrag = Compile(kDefaultFragmentWGSL);
    if (!stages.hasCompute)
        defaultComp = Compile(kDefaultComputeWGSL);

    // -------------------------
    // COMPUTE PIPELINE
    // -------------------------
    if (stages.hasCompute) {
        wgpu::ComputePipelineDescriptor desc = {};
        desc.compute.module = inputModule;
        desc.compute.entryPoint = "main";

        wgpu::ComputePipeline pipeline =
            gDevice.CreateComputePipeline(&desc);

        if (pipeline) {
            wgpu::CommandEncoder enc = gDevice.CreateCommandEncoder();
            wgpu::ComputePassEncoder pass = enc.BeginComputePass();
            pass.SetPipeline(pipeline);
            pass.DispatchWorkgroups(1);
            pass.End();
            wgpu::CommandBuffer cb = enc.Finish();
            gDevice.GetQueue().Submit(1, &cb);
        }
    }

    // -------------------------
    // RENDER PIPELINE
    // -------------------------
    if (stages.hasVertex || stages.hasFragment) {
        dawn::utils::ComboRenderPipelineDescriptor desc;

        // Vertex is mandatory → fallback if missing
        desc.vertex.module =
            stages.hasVertex ? inputModule : defaultVert;
        desc.vertex.entryPoint = "main";

        // Fragment is optional
        if (stages.hasFragment || defaultFrag) {
            desc.cFragment.module =
                stages.hasFragment ? inputModule : defaultFrag;
            desc.cFragment.entryPoint = "main";
            desc.cTargets[0].format = wgpu::TextureFormat::RGBA8Unorm;
            desc.cFragment.targetCount = 1;
        }

        wgpu::RenderPipeline pipeline =
            gDevice.CreateRenderPipeline(&desc);

        if (pipeline) {
            // Minimal render pass (same as before)
            wgpu::TextureDescriptor texDesc = {};
            texDesc.size = {4, 4, 1};
            texDesc.format = wgpu::TextureFormat::RGBA8Unorm;
            texDesc.usage = wgpu::TextureUsage::RenderAttachment;

            wgpu::Texture tex = gDevice.CreateTexture(&texDesc);
            wgpu::TextureView view = tex.CreateView();

            wgpu::RenderPassColorAttachment ca = {};
            ca.view = view;
            ca.loadOp = wgpu::LoadOp::Clear;
            ca.storeOp = wgpu::StoreOp::Store;

            wgpu::RenderPassDescriptor rp = {};
            rp.colorAttachmentCount = 1;
            rp.colorAttachments = &ca;

            wgpu::CommandEncoder enc = gDevice.CreateCommandEncoder();
            wgpu::RenderPassEncoder pass = enc.BeginRenderPass(&rp);
            pass.SetPipeline(pipeline);
            pass.Draw(3);
            pass.End();
            wgpu::CommandBuffer cb = enc.Finish();
            gDevice.GetQueue().Submit(1, &cb);
        }
    }

    log("paskaaaaaa\n");

    gDevice.Tick();

    gDevice.Destroy();
    gDevice = nullptr; // Reset the thing...
    return 0;
}

#include <unistd.h>

#define FUZZ_BUF_SIZE 100000

unsigned char fuzz_buf[FUZZ_BUF_SIZE];

int main(int argc, char** argv) {
    // Call the thing...
    // const uint8_t*
    memset(fuzz_buf, 0x00, FUZZ_BUF_SIZE);
    ssize_t len =  read(0, fuzz_buf, FUZZ_BUF_SIZE-1);
    return LLVMFuzzerTestOneInput(fuzz_buf, len);
}

```

I am now on commit 4d6a2cfb71b6e09e3610bbc2504f7871de0f741f of the thing...

## Sorting out the stuff...

I am now getting this crash here:

```

For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.
--Type <RET> for more, q to quit, c to continue without paging--

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./dawn_webgsl_and_vulkan_backend_fuzzer...
(gdb) r
Starting program: /home/oof/dawn/out/fuzzing/dawn_webgsl_and_vulkan_backend_fuzzer -max_len=1000000 -only_ascii=0 -custom_only=1 -timeout=2 -cross_over=1 -rss_limit_mb=2048 ./corpus/
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
INFO: found LLVMFuzzerCustomMutator (0x5555565b91f0). Disabling -len_control by default.
INFO: Specified custom_only. Using only the custom mutator.
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 131642566
INFO: Loaded 1 modules   (279237 inline 8-bit counters): 279237 [0x555558208ce0, 0x55555824cfa5),
INFO: Loaded 1 PC tables (279237 PCs): 279237 [0x55555824cfa8,0x55555868fbf8),
[New Thread 0x7bfff367e640 (LWP 102617)]
INFO:        2 files found in ./corpus/
Start...
[New Thread 0x7bffe42c8640 (LWP 102618)]
[New Thread 0x7bffe3ab9640 (LWP 102619)]
[New Thread 0x7bffe2789640 (LWP 102620)]
[New Thread 0x7bffe1459640 (LWP 102621)]
[New Thread 0x7bffe0129640 (LWP 102622)]
[New Thread 0x7bffdedf9640 (LWP 102623)]
[New Thread 0x7bffde5ea640 (LWP 102624)]
[New Thread 0x7bffddddb640 (LWP 102625)]
[New Thread 0x7bffda903640 (LWP 102626)]
INFO: seed corpus: files: 2 min: 435b max: 435b total: 870b rss: 159Mb
./corpus//11e3eaf6d02cac67a4ce73b2a1c7fec7f0ab3c01Start...
[New Thread 0x7bffd954c640 (LWP 102627)]
[Thread 0x7bffda903640 (LWP 102626) exited]
Poopoo...
paskaaaaaa
[Thread 0x7bffd954c640 (LWP 102627) exited]
[Thread 0x7bffddddb640 (LWP 102625) exited]
[Thread 0x7bffde5ea640 (LWP 102624) exited]
[Thread 0x7bffdedf9640 (LWP 102623) exited]
[Thread 0x7bffe0129640 (LWP 102622) exited]
[Thread 0x7bffe1459640 (LWP 102621) exited]
[Thread 0x7bffe2789640 (LWP 102620) exited]
[Thread 0x7bffe3ab9640 (LWP 102619) exited]
[Thread 0x7bffe42c8640 (LWP 102618) exited]
./corpus//original.wgslStart...
[New Thread 0x7bffe42c8640 (LWP 102628)]
[New Thread 0x7bffe3ab9640 (LWP 102629)]
[New Thread 0x7bffe2789640 (LWP 102630)]
[New Thread 0x7bffe1459640 (LWP 102631)]
[New Thread 0x7bffe3232640 (LWP 102632)]
[New Thread 0x7bffdf626640 (LWP 102633)]
[New Thread 0x7bffdd7f3640 (LWP 102634)]
[New Thread 0x7bffdbf53640 (LWP 102635)]
[New Thread 0x7bffd955a640 (LWP 102636)]
Poopoo...
paskaaaaaa
[Thread 0x7bffd955a640 (LWP 102636) exited]
[Thread 0x7bffdbf53640 (LWP 102635) exited]
[Thread 0x7bffdd7f3640 (LWP 102634) exited]
[Thread 0x7bffdf626640 (LWP 102633) exited]
[Thread 0x7bffe3232640 (LWP 102632) exited]
[Thread 0x7bffe1459640 (LWP 102631) exited]
[Thread 0x7bffe2789640 (LWP 102630) exited]
[Thread 0x7bffe3ab9640 (LWP 102629) exited]
[Thread 0x7bffe42c8640 (LWP 102628) exited]
#3	INITED cov: 30124 ft: 31327 corp: 2/870b exec/s: 0 rss: 233Mb
[darthshader] dlopen failed: ./libdarthshader_mutator.so: undefined symbol: _ZSt20__throw_length_errorPKc
../../third_party/libc++/src/include/__vector/vector.h:411: libc++ Hardening assertion __n < size() failed: vector[] index out of bounds

Thread 1 "dawn_webgsl_and" received signal SIGABRT, Aborted.
__pthread_kill_implementation (no_tid=0, signo=6, threadid=140737343823488) at ./nptl/pthread_kill.c:44
44	./nptl/pthread_kill.c: No such file or directory.
(gdb) where
#0  __pthread_kill_implementation (no_tid=0, signo=6, threadid=140737343823488) at ./nptl/pthread_kill.c:44
#1  __pthread_kill_internal (signo=6, threadid=140737343823488) at ./nptl/pthread_kill.c:78
#2  __GI___pthread_kill (threadid=140737343823488, signo=signo@entry=6) at ./nptl/pthread_kill.c:89
#3  0x00007ffff76ba476 in __GI_raise (sig=sig@entry=6) at ../sysdeps/posix/raise.c:26
#4  0x00007ffff76a07f3 in __GI_abort () at ./stdlib/abort.c:79
#5  0x0000555557f74409 in std::__Cr::__libcpp_verbose_abort (format=<optimized out>)
    at ../../third_party/libc++/src/src/verbose_abort.cpp:62
#6  0x00005555566275b5 in std::__Cr::vector<fuzzer::MutationDispatcher::Mutator, std::__Cr::allocator<fuzzer::MutationDispatcher::Mutator> >::operator[] (this=0x7bfff4dc4058, __n=<optimized out>)
    at ../../third_party/libc++/src/include/__vector/vector.h:411
#7  fuzzer::MutationDispatcher::MutateImpl (this=0x7bfff4ac3800,
    Data=0x7ffff6c0a800 "struct Params {\n    scale : f32,\n    bias  : f32,\n};\n\n@group(0) @binding(0)\nvar<uniform--Type <RET> for more, q to quit, c to continue without paging--
> params : Params;\n\nfn transform(x : f32) -> f32 {\n    let y = x * params.scale + params.bias;\n    if (y > 1.0) {"..., Size=435, MaxSize=1000000, Mutators=...) at ../../third_party/libFuzzer/src/FuzzerMutate.cpp:569
#8  0x00005555565b9389 in LLVMFuzzerCustomMutator (Data=<optimized out>, Size=<optimized out>,
    MaxSize=<optimized out>, Seed=<optimized out>) at ../../src/dawn/fuzzers/darthshader_mutator_wrapper.cpp:82
#9  0x0000555556627474 in fuzzer::MutationDispatcher::MutateImpl (this=0x7bfff4ac3800,
    Data=0x7ffff6c0a800 "struct Params {\n    scale : f32,\n    bias  : f32,\n};\n\n@group(0) @binding(0)\nvar<uniform> params : Params;\n\nfn transform(x : f32) -> f32 {\n    let y = x * params.scale + params.bias;\n    if (y > 1.0) {"..., Size=Size@entry=435, MaxSize=MaxSize@entry=1000000, Mutators=...)
    at ../../third_party/libFuzzer/src/FuzzerMutate.cpp:570
#10 0x00005555566272d1 in fuzzer::MutationDispatcher::Mutate (this=0x190d6,
    Data=0x190d6 <error: Cannot access memory at address 0x190d6>, Size=6, Size@entry=435, MaxSize=140737344760316,
    MaxSize@entry=1000000) at ../../third_party/libFuzzer/src/FuzzerMutate.cpp:552
--Type <RET> for more, q to quit, c to continue without paging--

```


this is because the rust build system uses the different c++ thing than what the dawn shit uses...

Let's change the build.rs file in the darthshader thing:

```
use std::path::PathBuf;

fn build_wgsl() {
    let dir: PathBuf = ["tree-sitter-wgsl", "src"].iter().collect();

    println!("cargo:rerun-if-changed={}", dir.to_str().unwrap());

    cc::Build::new()
        .include(&dir)
        .file(dir.join("parser.c"))
        .file(dir.join("scanner.cc"))
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-unused-but-set-variable")
        .compile("tree-sitter-wgsl");
}

fn main() {
    build_wgsl();
}

```

to

```

```










