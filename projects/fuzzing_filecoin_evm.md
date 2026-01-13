# Fuzzing filecoin EVM virtual machine

I discovered that filecoin has a bug bounty program in-place and it seems to have this EVM virtual machine which implements an EVM.

## Initial setup

I downloaded the repository which implements the VM (https://github.com/filecoin-project/builtin-actors).

So, I asked chatgpt to give me a fuzzer and it came up with this here:

{% raw %}
```
#![no_main]
use libfuzzer_sys::fuzz_target;
use builtin_actors::actors::evm::tests::util;
use fvm_shared::address::Address;
use hex_literal::hex;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return; // need at least a function selector
    }

    let bytecode = include_bytes!("../../actors/evm/tests/contracts/MCOPYTest.hex");
    let contract = Address::new_id(100);

    let rt = util::init_construct_and_verify(bytecode.to_vec(), |rt| {
        rt.actor_code_cids.borrow_mut().insert(contract, *builtin_actors::EVM_ACTOR_CODE_ID);
        rt.set_origin(contract);
    });

    let mut solidity_params = vec![];
    solidity_params.extend_from_slice(&hex!("73358055")); // function selector for "optimizedCopy(bytes)"
    solidity_params.extend_from_slice(data);

    let _ = util::invoke_contract(&rt, &solidity_params);
});
```
{% endraw %}

this is essentially just taken from the tests. After hardcoding the contents of MCOPYTest.hex, I now have this:

{% raw %}
```
#![no_main]
use libfuzzer_sys::fuzz_target;
use builtin_actors::actors::evm::tests::util;
use fvm_shared::address::Address;
use hex_literal::hex;

let bytecode: Vec<u8> = hex!(
    "6080604052348015600e575f80fd5b506103148061001c5f395ff3fe608060405234801561000f575f80fd5b50\
    60043610610029575f3560e01c8063733580551461002d575b5f80fd5b6100476004803603810190610042919061\
    0217565b61005d565b60405161005491906102be565b60405180910390f35b60605f825167ffffffffffffffff81\
    111561007b5761007a6100f3565b5b6040519080825280601f01601f1916602001820160405280156100ad578160\
    2001600182028036833780820191505090505b509050825160208401602083018282825e50505080915050919050\
    565b5f604051905090565b5f80fd5b5f80fd5b5f80fd5b5f80fd5b5f601f19601f8301169050919050565b7f4e487\
    b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b6101298261\
    00e3565b810181811067ffffffffffffffff82111715610148576101476100f3565b5b80604052505050565b5f61\
    015a6100ca565b90506101668282610120565b919050565b5f67ffffffffffffffff821115610185576101846100\
    f3565b5b61018e826100e3565b9050602081019050919050565b828183375f83830152505050565b5f6101bb6101\
    b68461016b565b610151565b9050828152602081018484840111156101d7576101d66100df565b5b6101e2848285\
    61019b565b509392505050565b5f82601f8301126101fe576101fd6100db565b5b813561020e8482602086016101\
    a9565b91505092915050565b5f6020828403121561022c5761022b6100d3565b5b5f82013567ffffffffffffffff\
    811115610249576102486100d7565b5b610255848285016101ea565b91505092915050565b5f8151905091905056\
    5b5f82825260208201905092915050565b8281835e5f83830152505050565b5f6102908261025e565b61029a8185\
    610268565b93506102aa818560208601610278565b6102b3816100e3565b840191505092915050565b5f60208201\
    90508181035f8301526102d68184610286565b90509291505056fea2646970667358221220274eb01ab194472b72\
    181214f64fcf3a1fa86680bc84eae6c8b993ede043339764736f6c634300081a0033"
).to_vec();

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return; // need at least a function selector
    }

    let contract = Address::new_id(100);

    let rt = util::init_construct_and_verify(bytecode, |rt| {
        rt.actor_code_cids.borrow_mut().insert(contract, *builtin_actors::EVM_ACTOR_CODE_ID);
        rt.set_origin(contract);
    });

    let mut solidity_params = vec![];
    solidity_params.extend_from_slice(&hex!("73358055")); // function selector for "optimizedCopy(bytes)"
    solidity_params.extend_from_slice(data);

    let _ = util::invoke_contract(&rt, &solidity_params);
});
```
{% endraw %}

but will it run? No! Here is a fixed version:

{% raw %}
```
#![no_main]
use libfuzzer_sys::fuzz_target;
// use builtin_actors::actors::evm::tests::util;
use hex_literal::hex;

// Yoinked from actors/evm/tests/util.rs


// use cid::Cid;
use fil_actor_evm as evm;
use fil_actor_evm::State;
use fil_actors_evm_shared::address::EthAddress;
use fil_actors_evm_shared::uints::U256;
use fil_actors_runtime::runtime::Runtime;
use fil_actors_runtime::{
    EAM_ACTOR_ID, INIT_ACTOR_ADDR,
    test_utils::{self, *},
};
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::ipld_block::IpldBlock;
use fvm_ipld_encoding::{BytesDe, BytesSer};
use fvm_shared::{IDENTITY_HASH, IPLD_RAW, address::Address};

use std::fmt::Debug;

#[allow(dead_code)]
pub fn construct_and_verify(initcode: Vec<u8>) -> MockRuntime {
    init_construct_and_verify(initcode, |_| {})
}

pub const CONTRACT_ADDRESS: [u8; 20] =
    hex_literal::hex!("FEEDFACECAFEBEEF000000000000000000000000");

#[allow(unused)]
pub const CONTRACT_ID: Address = Address::new_id(0);

pub fn init_construct_and_verify<F: FnOnce(&MockRuntime)>(
    initcode: Vec<u8>,
    initrt: F,
) -> MockRuntime {
    let rt = MockRuntime::default();

    // enable logging to std
    // test_utils::init_logging().ok(); // No need for logging

    // construct EVM actor
    rt.set_caller(*INIT_ACTOR_CODE_ID, INIT_ACTOR_ADDR);
    rt.expect_validate_caller_addr(vec![INIT_ACTOR_ADDR]);
    initrt(&rt);

    // first actor created is 0
    rt.set_delegated_address(0, Address::new_delegated(EAM_ACTOR_ID, &CONTRACT_ADDRESS).unwrap());
    rt.set_address_actor_type(Address::new_id(0), *EVM_ACTOR_CODE_ID);

    let params = evm::ConstructorParams {
        creator: EthAddress::from_id(fil_actors_runtime::EAM_ACTOR_ADDR.id().unwrap()),
        initcode: initcode.into(),
    };

    assert!(
        rt.call::<evm::EvmContractActor>(
            evm::Method::Constructor as u64,
            IpldBlock::serialize_cbor(&params).unwrap(),
        )
        .unwrap()
        .is_none()
    );
    let evm_st: State = rt.state().unwrap();
    let evm_code = rt.store.get(&evm_st.bytecode).unwrap().unwrap();
    // log::trace!("bytecode constructed: {}", hex::encode(evm_code));
    rt.verify();

    rt
}

#[allow(dead_code)]
pub fn invoke_contract(rt: &MockRuntime, input_data: &[u8]) -> Vec<u8> {
    rt.expect_validate_caller_any();
    let BytesDe(res) = rt
        .call::<evm::EvmContractActor>(
            evm::Method::InvokeContract as u64,
            IpldBlock::serialize_cbor(&BytesSer(input_data)).unwrap(),
        )
        .unwrap()
        .unwrap()
        .deserialize()
        .unwrap();
    res
}

#[allow(dead_code)]
pub fn invoke_contract_expect_fail(rt: &MockRuntime, input_data: &[u8]) {
    rt.expect_validate_caller_any();

    // Call the contract and check if it results in an error
    let result = rt.call::<evm::EvmContractActor>(
        evm::Method::InvokeContract as u64,
        IpldBlock::serialize_cbor(&BytesSer(input_data)).unwrap(),
    );

    // Ensure the call fails as expected
    match result {
        Ok(_) => panic!("Expected contract invocation to fail, but it succeeded"),
        Err(err) => {
            // Use accessor methods for `exit_code` and `msg`
            assert_eq!(err.exit_code().value(), 33, "Unexpected exit code");

            // Directly use `err.msg()` as it returns `&str`
            let msg = err.msg();
            assert!(msg.contains("contract reverted"), "Unexpected error message: {}", msg);
        }
    }
}

#[allow(dead_code)]
// silly to have the full word for a single byte but...
pub fn dispatch_num_word(method_num: u8) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[3] = method_num;
    word
}

#[allow(dead_code)]
pub fn id_to_vec(src: &Address) -> Vec<u8> {
    U256::from(src.id().unwrap()).to_bytes().to_vec()
}









static bytecode: [u8; 816] = hex!(
    "6080604052348015600e575f80fd5b506103148061001c5f395ff3fe608060405234801561000f575f80fd5b50\
    60043610610029575f3560e01c8063733580551461002d575b5f80fd5b6100476004803603810190610042919061\
    0217565b61005d565b60405161005491906102be565b60405180910390f35b60605f825167ffffffffffffffff81\
    111561007b5761007a6100f3565b5b6040519080825280601f01601f1916602001820160405280156100ad578160\
    2001600182028036833780820191505090505b509050825160208401602083018282825e50505080915050919050\
    565b5f604051905090565b5f80fd5b5f80fd5b5f80fd5b5f80fd5b5f601f19601f8301169050919050565b7f4e487\
    b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b6101298261\
    00e3565b810181811067ffffffffffffffff82111715610148576101476100f3565b5b80604052505050565b5f61\
    015a6100ca565b90506101668282610120565b919050565b5f67ffffffffffffffff821115610185576101846100\
    f3565b5b61018e826100e3565b9050602081019050919050565b828183375f83830152505050565b5f6101bb6101\
    b68461016b565b610151565b9050828152602081018484840111156101d7576101d66100df565b5b6101e2848285\
    61019b565b509392505050565b5f82601f8301126101fe576101fd6100db565b5b813561020e8482602086016101\
    a9565b91505092915050565b5f6020828403121561022c5761022b6100d3565b5b5f82013567ffffffffffffffff\
    811115610249576102486100d7565b5b610255848285016101ea565b91505092915050565b5f8151905091905056\
    5b5f82825260208201905092915050565b8281835e5f83830152505050565b5f6102908261025e565b61029a8185\
    610268565b93506102aa818560208601610278565b6102b3816100e3565b840191505092915050565b5f60208201\
    90508181035f8301526102d68184610286565b90509291505056fea2646970667358221220274eb01ab194472b72\
    181214f64fcf3a1fa86680bc84eae6c8b993ede043339764736f6c634300081a0033"
); // Originally had .to_vec() but can not do that with global statics

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return; // need at least a function selector
    }

    let contract = Address::new_id(100);

    let rt = init_construct_and_verify(bytecode.to_vec(), |rt| {
        rt.actor_code_cids.borrow_mut().insert(contract, *EVM_ACTOR_CODE_ID);
        rt.set_origin(contract);
    });

    let mut solidity_params = vec![];
    solidity_params.extend_from_slice(&hex!("73358055")); // function selector for "optimizedCopy(bytes)"
    solidity_params.extend_from_slice(data);

    let _ = invoke_contract(&rt, &solidity_params);
});
```
{% endraw %}

This results in this panic:

{% raw %}
```
thread '<unnamed>' panicked at fuzz/fuzz_targets/evm_actor.rs:84:10:
called `Result::unwrap()` on an `Err` value: ActorError { exit_code: ExitCode { value: 33 }, data: Some(IpldBlock { codec: 51, data: [40] }), msg: "contract reverted at 214" }
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
==173641== ERROR: libFuzzer: deadly signal
    #0 0x5578d7d65341 in __sanitizer_print_stack_trace /rustc/llvm/src/llvm-project/compiler-rt/lib/asan/asan_stack.cpp:87:3
    #1 0x5578d963622d in fuzzer::PrintStackTrace() /home/oof/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.10/libfuzzer/FuzzerUtil.cpp:210:38
    #2 0x5578d961d849 in fuzzer::Fuzzer::CrashCallback() /home/oof/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.10/libfuzzer/FuzzerLoop.cpp:231:18
    #3 0x5578d961d849 in fuzzer::Fuzzer::CrashCallback() /home/oof/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.10/libfuzzer/FuzzerLoop.cpp:226:6
    #4 0x7e6e0164532f  (/lib/x86_64-linux-gnu/libc.so.6+0x4532f) (BuildId: 282c2c16e7b6600b0b22ea0c99010d2795752b5f)
    #5 0x7e6e0169eb2b in __pthread_kill_implementation nptl/pthread_kill.c:43:17
    #6 0x7e6e0169eb2b in __pthread_kill_internal nptl/pthread_kill.c:78:10
    #7 0x7e6e0169eb2b in pthread_kill nptl/pthread_kill.c:89:10
    #8 0x7e6e0164527d in raise signal/../sysdeps/posix/raise.c:26:13
    #9 0x7e6e016288fe in abort stdlib/abort.c:79:7
    #10 0x5578d96bfa29 in std::sys::pal::unix::abort_internal::h7478b609dd18f5e2 /rustc/4d669fb34e7db6f3825d01e4c59b7996f0531431/library/std/src/sys/pal/unix/mod.rs:374:14
    #11 0x5578d96afc19 in std::process::abort::h7e1b6fd7b06cd471 /rustc/4d669fb34e7db6f3825d01e4c59b7996f0531431/library/std/src/process.rs:2374:5
    #12 0x5578d9616384 in libfuzzer_sys::initialize::_$u7b$$u7b$closure$u7d$$u7d$::ha0de486bd2a2ad11 /home/oof/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.10/src/lib.rs:94:9
    #13 0x5578d96b4827 in _$LT$alloc..boxed..Box$LT$F$C$A$GT$$u20$as$u20$core..ops..function..Fn$LT$Args$GT$$GT$::call::h92500b91b001934f /rustc/4d669fb34e7db6f3825d01e4c59b7996f0531431/library/alloc/src/boxed.rs:1984:9
    #14 0x5578d96b4827 in std::panicking::rust_panic_with_hook::h95ea5298a8d72379 /rustc/4d669fb34e7db6f3825d01e4c59b7996f0531431/library/std/src/panicking.rs:825:13
    #15 0x5578d96b44d9 in std::panicking::begin_panic_handler::_$u7b$$u7b$closure$u7d$$u7d$::h4bcd1eb83a4bace5 /rustc/4d669fb34e7db6f3825d01e4c59b7996f0531431/library/std/src/panicking.rs:690:13
    #16 0x5578d96b1fe8 in std::sys::backtrace::__rust_end_short_backtrace::h83d9e3993c9c18bc /rustc/4d669fb34e7db6f3825d01e4c59b7996f0531431/library/std/src/sys/backtrace.rs:168:18
    #17 0x5578d96b416c in rust_begin_unwind /rustc/4d669fb34e7db6f3825d01e4c59b7996f0531431/library/std/src/panicking.rs:681:5
    #18 0x5578d96fe97f in core::panicking::panic_fmt::h867f0b3642b5b349 /rustc/4d669fb34e7db6f3825d01e4c59b7996f0531431/library/core/src/panicking.rs:75:14
    #19 0x5578d96feef5 in core::result::unwrap_failed::h401147f46f095b71 /rustc/4d669fb34e7db6f3825d01e4c59b7996f0531431/library/core/src/result.rs:1699:5
    #20 0x5578d7f80c67 in core::result::Result$LT$T$C$E$GT$::unwrap::hdb8617ae740fb648 /rustc/4d669fb34e7db6f3825d01e4c59b7996f0531431/library/core/src/result.rs:1104:23
    #21 0x5578d7f80c67 in fuzz_evm::invoke_contract::he70496df4fc14325 /home/oof/builtin-actors/fuzz/fuzz_targets/evm_actor.rs:79:24
    #22 0x5578d7f824e1 in fuzz_evm::_::__libfuzzer_sys_run::h5a89243b4314164e /home/oof/builtin-actors/fuzz/fuzz_targets/evm_actor.rs:173:13
    #23 0x5578d7f81bc9 in rust_fuzzer_test_input /home/oof/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.10/src/lib.rs:276:60
    #24 0x5578d9610a0f in libfuzzer_sys::test_input_wrap::_$u7b$$u7b$closure$u7d$$u7d$::h286b007c36e66e3f /home/oof/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.10/src/lib.rs:62:9
    #25 0x5578d9610a0f in std::panicking::try::do_call::h841fee713e6d5ae0 /rustc/4d669fb34e7db6f3825d01e4c59b7996f0531431/library/std/src/panicking.rs:573:40
    #26 0x5578d96165a8 in __rust_try libfuzzer_sys.5aa5ba589cfe0464-cgu.0
    #27 0x5578d9615a0b in std::panicking::try::hf4b2556fec4518c8 /rustc/4d669fb34e7db6f3825d01e4c59b7996f0531431/library/std/src/panicking.rs:536:19
    #28 0x5578d9615a0b in std::panic::catch_unwind::hd7c3dabcf5a0bf75 /rustc/4d669fb34e7db6f3825d01e4c59b7996f0531431/library/std/src/panic.rs:358:14
    #29 0x5578d9615a0b in LLVMFuzzerTestOneInput /home/oof/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.10/src/lib.rs:60:22
    #30 0x5578d961dda8 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /home/oof/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.10/libfuzzer/FuzzerLoop.cpp:619:15
    #31 0x5578d9625429 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) /home/oof/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.10/libfuzzer/FuzzerLoop.cpp:516:22
    #32 0x5578d962653a in fuzzer::Fuzzer::MutateAndTestOne() /home/oof/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.10/libfuzzer/FuzzerLoop.cpp:765:25
    #33 0x5578d96274a7 in fuzzer::Fuzzer::Loop(std::vector<fuzzer::SizedFile, std::allocator<fuzzer::SizedFile>>&) /home/oof/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.10/libfuzzer/FuzzerLoop.cpp:910:21
    #34 0x5578d96490e1 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /home/oof/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.10/libfuzzer/FuzzerDriver.cpp:915:10
    #35 0x5578d9637c56 in main /home/oof/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.10/libfuzzer/FuzzerMain.cpp:20:30
    #36 0x7e6e0162a1c9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #37 0x7e6e0162a28a in __libc_start_main csu/../csu/libc-start.c:360:3
    #38 0x5578d7cbd954 in _start (/home/oof/builtin-actors/target/x86_64-unknown-linux-gnu/release/fuzz_evm+0x11e4954) (BuildId: a80f95e5fb4a217918ac3c762ad624995dc81b03)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 3 CrossOver-InsertByte-InsertByte-; base unit: adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
0xa,0x36,0xa,0x25,
\0126\012%
artifact_prefix='/home/oof/builtin-actors/fuzz/artifacts/fuzz_evm/'; Test unit written to /home/oof/builtin-actors/fuzz/artifacts/fuzz_evm/crash-2a5893ab81a6b962777c961ac205ad2dfba8259b
Base64: CjYKJQ==

────────────────────────────────────────────────────────────────────────────────

Failing input:

        artifacts/fuzz_evm/crash-2a5893ab81a6b962777c961ac205ad2dfba8259b

Output of `std::fmt::Debug`:

        [10, 54, 10, 37]

Reproduce with:

        cargo fuzz run fuzz_evm artifacts/fuzz_evm/crash-2a5893ab81a6b962777c961ac205ad2dfba8259b

Minimize test case with:

        cargo fuzz tmin fuzz_evm artifacts/fuzz_evm/crash-2a5893ab81a6b962777c961ac205ad2dfba8259b

────────────────────────────────────────────────────────────────────────────────

Error: Fuzz target exited with exit status: 77
```
{% endraw %}

But I think that we should do something like this here instead:

{% raw %}
```
if let Ok(res) = rt.call::<evm::EvmContractActor>(
    evm::Method::InvokeContract as u64,
    IpldBlock::serialize_cbor(&BytesSer(&solidity_params)).unwrap(),
) {
    let _ = res.unwrap().deserialize::<BytesDe>().unwrap();
} else {
    // Don't panic — contract reverted (ExitCode 33) is allowed
}
```
{% endraw %}

**A couple of hours later**

Ok, so after fiddling for a bit, it seems that the MockRuntime is not suitable for this task and is not suitable for fuzzing... Well, fuck!!!!











