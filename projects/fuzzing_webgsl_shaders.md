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

















