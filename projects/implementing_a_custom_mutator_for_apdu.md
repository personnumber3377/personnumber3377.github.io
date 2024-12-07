
# Implementing a custom mutator for apdu

Basically this: https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit . This blog post is inspired by this post: https://secret.club/2022/05/11/fuzzing-solana.html .

Let's create it!

## Investigating the protocol being used.

There actually exists quite a helpful piece of documentation for the APDU format described here: https://github.com/rsksmart/rsk-powhsm/blob/master/firmware/src/powhsm/src/protocol.txt

There are some additionals quirks with this thing. First of all, the actual inputs which we pass to the tcpsigner binary is actually a collection of messages, not just one of these messages. You can observe the function:

```

/* This function emulates the HOST device, reading bytes from a file instead
 * @arg[in] tx_len              amount of bytes to transmit to the client
 * @arg[in] inputfd             the input file
 * @ret                         amount of bytes received from the client
 */
static unsigned short io_exchange_file(unsigned char tx, FILE *input_file) {
    // File input format: |1 byte length| |len bytes data|
    static unsigned long file_index = 0;
    LOG_HEX("Dongle => ", apdu_buffer, tx);

    // Only write? We're done
    if (io_exchange_write_only) {
        io_exchange_write_only = false;
        return 0;
    }

    unsigned char announced_rx;
    if (fread(&announced_rx, sizeof(char), 1, input_file) != 1) {
        if (feof(input_file)) {
            LOG("Server: EOF\n");
            exit(0);
        }
        LOG("Server: could not read rx size\n");
        exit(1);
    }

    // Read a capped amount of bytes to keep it reasonably realistic
    unsigned short capped_rx;
    if (announced_rx <= MAX_FUZZ_TRANSFER) {
        capped_rx = announced_rx;
    } else {
        capped_rx = MAX_FUZZ_TRANSFER;
    }

    LOG("Server: reading %d (announced: %d) bytes at index: %d\n",
        capped_rx,
        announced_rx,
        file_index);
    unsigned short rx = fread(apdu_buffer, sizeof(char), capped_rx, input_file);

    if (rx != capped_rx) {
        // if we reach EOF while reading the data portion it means
        // the announced size did not match the file
        if (feof(input_file)) {
            LOG("Server: malformed input, tried reading %d bytes but reached "
                "EOF after %d\n",
                capped_rx,
                rx);
            exit(1);
        }
        LOG("Server: Could not read %d bytes (only: %d) from input file\n",
            capped_rx,
            rx);
        exit(1);
    }

    // Move the offset to wherever the input said it should be,
    // even if we actually did not read the whole data.
    // If not, this would lead the file_index
    // interpreting data as the length.
    unsigned long index_offset = announced_rx + 1;
    if (file_index > (ULONG_MAX - index_offset)) {
        LOG("Server: input file too big, can't store offset.");
        exit(1);
    }

    file_index += index_offset;
    LOG_HEX("Dongle <= ", apdu_buffer, rx);
    return capped_rx;
}


```

also I made this quick script to run a an arbitrary file with the tcpsigner binary:

```

#!/bin/sh




HSM_ROOT="/home/oof/rsk-powhsm"

# Create main tmux session and init the fuzzer in there
# MAIN_FUZZ_CMD="afl-fuzz -x /dict -D -M main -i /testcases -o /output $CMD"

#RAW_CORES="$1"

RAW_CORES=$(nproc)



TESTCASES="$HSM_ROOT/firmware/fuzz/testcases"



OUTPUT="$HSM_ROOT/firmware/fuzz/output"


DICT="$HSM_ROOT/firmware/fuzz/dict"


COVERAGE_DIR="$HSM_ROOT/firmware/fuzz/.coverage-build"



# CMD="./tcpsigner --checkpoint $CHECKPOINT --difficulty $DIFFICULTY --network $NETWORK -r /outputthing/stuff.bin -i @@"


TEST_BULLSHIT="./shit/"

CMD="./tcpsigner -i /fuck/shit.bin" # Just run the file

# ./tcpsigner -i testcases-raw/replica-1.out

DOCKER_USER="$(id -u):$(id -g)"

SHITFUCK='docker run -ti --rm --env AFL_AUTORESUME=1 --env AFL_TESTCACHE_SIZE=500 --env AFL_PYTHON_MODULE="mutator" --env PYTHONPATH="/mutator/" --user $DOCKER_USER -w /hsm2/firmware/src/tcpsigner -v "$DICT":/dict -v "/home/oof/rsk-powhsm/firmware/fuzz/mutator":/mutator -v "./outputthing/":/outputthing/ -v "$TEST_BULLSHIT":/fuck/ -v "$OUTPUT":/output -v "$HSM_ROOT":/hsm2 "hsm:afl" /bin/bash -c "$CMD"'
echo $SHITFUCK


docker run -ti --rm --env AFL_AUTORESUME=1 --env AFL_TESTCACHE_SIZE=500 --env AFL_PYTHON_MODULE="mutator" --env PYTHONPATH="/mutator/" --user $DOCKER_USER -w /hsm2/firmware/src/tcpsigner -v "$DICT":/dict -v "/home/oof/rsk-powhsm/firmware/fuzz/mutator":/mutator -v "./outputthing/":/outputthing/ -v "$TEST_BULLSHIT":/fuck/ -v "$OUTPUT":/output -v "$HSM_ROOT":/hsm2 "hsm:afl" /bin/bash -c "$CMD"



```

which inputs an arbitrary file and shows the debug output. After running this file, we get this output from it:

```
TCPSigner starting.
Signer version: 5.2.0
Signer parameters:
Checkpoint: 0xbdcb3c17c7aee714cec8ad900341bfd987b452280220dcbd6e7191f67ea4209b
Difficulty: 0x32
Network: regtest
Block difficulty cap: 0x14
Network upgrade activation block numbers (latest takes precedence):
	Wasabi: 0
	Papyrus: 0
	Iris: 0
Loading key file 'key.secp256'
Loaded keys:
	m/44'/0'/0'/0/0: 03c7e46f3431d50332df707e0eba9b442beb0930a2d162f95fc76bc036c96b3533
	m/44'/1'/0'/0/0: 03dfc86053a1deb3dc928c17bbbc338d8164e013e9943fc71d30aff2199cdf3203
	m/44'/1'/1'/0/0: 03b13e2ee3d4a785373bc070b77ef74b2a5e19a39303172a8efc5990b794647196
	m/44'/1'/2'/0/0: 03b58570eafdf6468c7c0c68304495dc2eddc0268b7f4e5cbd8207ec78f018dbe3
	m/44'/137'/0'/0/0: 02bba2d3f6f9cb7092437570fc4f3c3ec99a6bcd06b2a55f1b6e4338d1d4b6f506
	m/44'/137'/1'/0/0: 03d269059a69f6cec4f0b2c2320db277ab6ddce85967ca9f30db8f8cbcb4c5b4f3
Seed module initialized.
Loading endorsement file 'attid.json'
Loaded attestation id:
	Public key: 02f5dbfef08539afdf22f0db648280715c50a8b31134fc4a8a1e8fb949dc2b8286
	Code hash: ade611b02b55a2af5b8eae24f81b442acc829b54e796e42f5ee92e0cb4b58129
ADMIN: Init OK.
Using file /fuck/shit.bin as input
Running signer main loop...
Dongle =>  EMPTY
Server: reading 2 (announced: 2) bytes at index: 0
Dongle <=  0x8006
Dongle =>  0x80010502009000
Server: reading 23 (announced: 23) bytes at index: 3
Dongle <=  0x8004052c00008089000080000000800000000000000000
Dongle =>  0x04bba2d3f6f9cb7092437570fc4f3c3ec99a6bcd06b2a55f1b6e4338d1d4b6f5064a292aa8af9b7b8d049a11b0a251df8889084e6b167a5c339f250b4e8f4731d09000
Server: reading 56 (announced: 56) bytes at index: 27
Dongle <=  0x800201052c00008089000080000000800000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Dongle =>  0x8002813045022100f907e4a313eeae20dffc3ea71997138ece2aef8a3a0ae69cfcf8537af4484740022021644b00260efcb0ea14f2eb3d46c0059332d5743dbf24e39ce27437f36b68359000
Server: reading 23 (announced: 23) bytes at index: 84
Dongle <=  0x8004052c00008089000080010000800000000000000000
Dongle =>  0x04d269059a69f6cec4f0b2c2320db277ab6ddce85967ca9f30db8f8cbcb4c5b4f375f9cab627f725505fc9a219a39e5872ae72774c570232ad85e6ac852a24c3db9000
Server: reading 56 (announced: 56) bytes at index: 108
Dongle <=  0x800201052c00008089000080010000800000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Dongle =>  0x80028130450221009e97bf33f77c2eea1eb8d9a3438764e47d2feef51801e7f8dfc0b3e960be373202200eebce29f193509813c88eee7a1dc83ec9e76d9995b6f269d7688d96f99f31e19000
Server: reading 23 (announced: 23) bytes at index: 165
Dongle <=  0x8004052c00008089000080000000800000000001000000
Dongle =>  0x6a8f
Server: reading 56 (announced: 56) bytes at index: 189
Dongle <=  0x800201052c00008089000080000000800000000001000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Dongle =>  0x6a8f
Server: reading 23 (announced: 23) bytes at index: 246
Dongle <=  0x8004052c00008001000080010000800000000000000000
Dongle =>  0x04b13e2ee3d4a785373bc070b77ef74b2a5e19a39303172a8efc5990b794647196314efe0eaba96bf1fdec26e1ba564638b97b792c35f21e6efe6248a505345aff9000
Server: reading 56 (announced: 56) bytes at index: 270
Dongle <=  0x800201052c00008001000080010000800000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Dongle =>  0x8002813045022100805d70343149c8719230326768e679fd03ab6105de11185fca32db93e6401b77022034e2450c7166a140c2e137cbb6a2ad993deccd632293912249002830a20d90349000
Server: reading 23 (announced: 23) bytes at index: 327
Dongle <=  0x8004052c00008001000080000000800000000001000000
Dongle =>  0x6a8f
Server: reading 56 (announced: 56) bytes at index: 351
Dongle <=  0x800201052c00008001000080000000800000000001000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Dongle =>  0x6a8f
Server: reading 23 (announced: 23) bytes at index: 408
Dongle <=  0x8004052c00008001000080020000800000000000000000
Dongle =>  0x04b58570eafdf6468c7c0c68304495dc2eddc0268b7f4e5cbd8207ec78f018dbe38fcf7b345f88e5c04714bb82fae2ed6764379c8010347e5f070e9655114602ab9000
Server: reading 56 (announced: 56) bytes at index: 432
Dongle <=  0x800201052c00008001000080020000800000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Dongle =>  0x8002813045022100fb06c986c55f754157761ce5831b9479d79e34f08b8ee66d91dd3be1d2b07fc40220416010aaa6df66b6b282d87565e75f22a5c87d38b3110b5dc25e8fbaec3f59cc9000
Server: reading 23 (announced: 23) bytes at index: 489
Dongle <=  0x8004052c00008001000080000000800000000002000000
Dongle =>  0x6a8f
Server: reading 56 (announced: 56) bytes at index: 513
Dongle <=  0x800201052c00008001000080000000800000000002000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Dongle =>  0x6a8f
Server: EOF

```

if we look at the input file itself:

```
00000000: 02 80 06 17 80 04 05 2c 00 00 80 89 00 00 80 00  .......,........
00000010: 00 00 80 00 00 00 00 00 00 00 00 1c 80 02 01 05  ................
00000020: 2c 00 00 80 89 00 00 80 00 00 00 80 00 00 00 00  ,...............
00000030: 00 00 00 00 aa aa aa aa 55 aa aa aa aa aa aa aa  ........U.......
00000040: aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa  ................
00000050: aa aa aa aa 17 80 04 05 2c 00 00 80 89 00 00 80  ........,.......
00000060: 21 00 00 80 00 00 00 00 00 19 00 00 38 80 02 01  !...........8...
00000070: 05 2c 00 00 80 89 04 00 80 01 00 00 80 00 00 00  .,..............
00000080: 00 00 00 00 00 aa aa aa aa aa aa aa aa aa 55 aa  ..............U.
00000090: aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa  ................
000000a0: aa aa aa aa aa 17 80 04 05 2c 00 00 80 89 00 00  .........,......
000000b0: a1 00 00 00 80 00 00 00 00 01 00 00 00 38 80 02  .............8..
# SNIP
```

You can see the structure.

The first byte is the amount of bytes to be read after:

```
Dongle =>  EMPTY
Server: reading 2 (announced: 2) bytes at index: 0
Dongle <=  0x8006
Dongle =>  0x80010502009000
Server: reading 23 (announced: 23) bytes at index: 3
```

So the very first message is just the bytes `80 06` . As we can see from the protocol.txt file, the 0x80 byte at the start is the CLA field of the message:

https://github.com/rsksmart/rsk-powhsm/blob/master/firmware/src/powhsm/src/protocol.txt

```
      HOST->LEDGER APDU format
          0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  ...
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ...+
      |    CLA        |      CMD      |     OP        |     DATA           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ...+
```

and then there is the CMD field which is the command (duh). If we go through the source code, the CMD field here is just `RSK_IS_ONBOARD = 0x06` , in fact, there is the entire list of them in `instructions.h`:

```

typedef enum {
    // Signing-related
    INS_SIGN = 0x02,
    INS_GET_PUBLIC_KEY = 0x04,

    // Misc
    RSK_IS_ONBOARD = 0x06,
    RSK_MODE_CMD = 0x43,

    // Advance blockchain and blockchain state
    INS_ADVANCE = 0x10,
    INS_ADVANCE_PARAMS = 0x11,
    INS_GET_STATE = 0x20,
    INS_RESET_STATE = 0x21,
    INS_UPD_ANCESTOR = 0x30,

    // Attestation
    INS_ATTESTATION = 0x50,
    INS_HEARTBEAT = 0x60,

    // Exit
    INS_EXIT = 0xff,
} apdu_instruction_t;

```

so setting the CMD field to any other than any of those is basically pointless. There is just a big switch statement in the source code which does just that:

```

    switch (APDU_CMD()) {
    // Reports the current mode (i.e., always reports signer mode)
    case RSK_MODE_CMD:
        reset_if_starting(RSK_MODE_CMD);
        SET_APDU_CMD(APP_MODE_SIGNER);
        tx = 2;
        break;

    // Reports wheter the device is onboarded and the current signer version
    case RSK_IS_ONBOARD:
        reset_if_starting(RSK_IS_ONBOARD);
        uint8_t output_index = CMDPOS;
        SET_APDU_AT(output_index++, seed_available() ? 1 : 0);
        SET_APDU_AT(output_index++, VERSION_MAJOR);
        SET_APDU_AT(output_index++, VERSION_MINOR);
        SET_APDU_AT(output_index++, VERSION_PATCH);
        tx = 5;
        break;

    // Derives and returns the corresponding public key for the given path
    case INS_GET_PUBLIC_KEY:
        REQUIRE_ONBOARDED();

        reset_if_starting(INS_GET_PUBLIC_KEY);

        // Check the received data size
        if (rx != DATA + sizeof(uint32_t) * BIP32_PATH_NUMPARTS)
            THROW(ERR_INVALID_DATA_SIZE); // Wrong buffer size

        // Check for path validity before returning the public key
        // Actual path starts at normal data pointer, but
        // is prepended by a single byte indicating the path length
        // (all paths have the same length in practice, so this should
        // be refactored in the future)
        if (!(pathRequireAuth(APDU_DATA_PTR - 1) ||
              pathDontRequireAuth(APDU_DATA_PTR - 1))) {
            // If no path match, then bail out
            THROW(ERR_INVALID_PATH); // Invalid Key Path
        }

        // Derive the public key
        SAFE_MEMMOVE(auth.path,
                     sizeof(auth.path),
                     MEMMOVE_ZERO_OFFSET,
                     APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE_OUT,
                     MEMMOVE_ZERO_OFFSET,
                     sizeof(auth.path),
                     THROW(ERR_INVALID_PATH));

        pubkey_length = communication_get_msg_buffer_size();
        if (!seed_derive_pubkey(auth.path,
                                sizeof(auth.path) / sizeof(auth.path[0]),
                                communication_get_msg_buffer(),
                                &pubkey_length)) {
            THROW(ERR_INTERNAL);
        }

        tx = pubkey_length;

        break;

    case INS_SIGN:
        REQUIRE_ONBOARDED();

        reset_if_starting(INS_SIGN);
        tx = auth_sign(rx);
        break;

    case INS_ATTESTATION:
        REQUIRE_ONBOARDED();

        reset_if_starting(INS_ATTESTATION);
        tx = get_attestation(rx, &attestation);
        break;

    case INS_HEARTBEAT:
        REQUIRE_ONBOARDED();

        reset_if_starting(INS_HEARTBEAT);
        tx = get_heartbeat(rx, &heartbeat);
        break;

    // Get blockchain state
    case INS_GET_STATE:
        REQUIRE_ONBOARDED();

        // Get blockchain state is considered part of the
        // advance blockchain operation
        reset_if_starting(INS_ADVANCE);
        tx = bc_get_state(rx);
        break;

    // Reset blockchain state
    case INS_RESET_STATE:
        REQUIRE_ONBOARDED();

        reset_if_starting(INS_RESET_STATE);
        tx = bc_reset_state(rx);
        break;

    // Advance blockchain
    case INS_ADVANCE:
        REQUIRE_ONBOARDED();

        reset_if_starting(INS_ADVANCE);
        tx = bc_advance(rx);
        break;

    // Advance blockchain precompiled parameters
    case INS_ADVANCE_PARAMS:
        REQUIRE_ONBOARDED();

        reset_if_starting(INS_ADVANCE_PARAMS);
        tx = bc_advance_get_params();
        break;

    // Update ancestor
    case INS_UPD_ANCESTOR:
        REQUIRE_ONBOARDED();

        reset_if_starting(INS_UPD_ANCESTOR);
        tx = bc_upd_ancestor(rx);
        break;

    case INS_EXIT:
        bc_backup_partial_state();
        app_exit();
        tx = TX_FOR_DATA_SIZE(0);
        break;

    default: // Unknown command
        THROW(ERR_INS_NOT_SUPPORTED);
        break;
    }

```

So I think the best way to implement a custom mutator is to just write a file parser for this file which parses each block and then after that it chooses a random message in that file to mutate, mutates it, then returns that thing. Then we can multiply messages (aka add copies of them to the file), delete them and modify them etc etc..

## Beginnings of the custom mutator

You can follow along (and suggest changes) at https://github.com/personnumber3377/apdu_custom_mutator . I implemented commit 979b5f3c58021e16419a1926846ffc6665db130e which implements the parsing of the input file.

Here is the output when I run with the original sample:

```
You should use this with AFL or libfuzzer. When running standalone, this just runs some tests. See https://aflplus.plus/docs/custom_mutators/ for details.
b'\x02\x80\x06\x17\x80\x04\x05,\x00\x00\x80\x89\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x008\x80\x02\x01\x05,\x00\x00\x80\x89\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x17\x80\x04\x05,\x00\x00\x80\x89\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x008\x80\x02\x01\x05,\x00\x00\x80\x89\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x17\x80\x04\x05,\x00\x00\x80\x89\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x01\x00\x00\x008\x80\x02\x01\x05,\x00\x00\x80\x89\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x01\x00\x00\x00\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x17\x80\x04\x05,\x00\x00\x80\x01\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x008\x80\x02\x01\x05,\x00\x00\x80\x01\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x17\x80\x04\x05,\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x01\x00\x00\x008\x80\x02\x01\x05,\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x01\x00\x00\x00\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x17\x80\x04\x05,\x00\x00\x80\x01\x00\x00\x80\x02\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x008\x80\x02\x01\x05,\x00\x00\x80\x01\x00\x00\x80\x02\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x17\x80\x04\x05,\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x02\x00\x00\x008\x80\x02\x01\x05,\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x02\x00\x00\x00\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'
```

which doesn't seem promising. There is a bug in my code here:

```


def try_parse_chunks(file_data: bytes) -> list:
	# This is a file reader type parser.
	cur_byte_idx = 0

	out = [] # Output chunks.

	while True: # Parse loop.
		# Check if we are at the end.
		if cur_byte_idx >= len(file_data):
			break
		# First get length.
		length = file_data[cur_byte_idx]
		cur_byte_idx += 1 # Advance counter
		if cur_byte_idx + length >= len(file_data): # Invalid input. Return None
			return None
		# Now read the chunk data
		chunk_data = file_data[cur_byte_idx:cur_byte_idx+length]
		cur_byte_idx += length # Advance reader.
		out.append(chunk_data)
	return out

def try_parse_input(input_stuff: bytes): # This tries to parse the input bytes...

	apdu_chunks = try_parse_chunks(input_stuff) # This carves out the apdu chunk stuff.
	if not apdu_chunks:
		return input_stuff # Just return the original input (for now).
	#print(apdu_chunks)
	return apdu_chunks

```

The bug was here: `if cur_byte_idx + length >= len(file_data):` this should actually just be this: `if cur_byte_idx + length > len(file_data):`

Now this looks better!

```
b'\x80\x06'
b'\x80\x04\x05,\x00\x00\x80\x89\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x80\x02\x01\x05,\x00\x00\x80\x89\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'
b'\x80\x04\x05,\x00\x00\x80\x89\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x80\x02\x01\x05,\x00\x00\x80\x89\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'
b'\x80\x04\x05,\x00\x00\x80\x89\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x01\x00\x00\x00'
b'\x80\x02\x01\x05,\x00\x00\x80\x89\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x01\x00\x00\x00\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'
b'\x80\x04\x05,\x00\x00\x80\x01\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x80\x02\x01\x05,\x00\x00\x80\x01\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'
b'\x80\x04\x05,\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x01\x00\x00\x00'
b'\x80\x02\x01\x05,\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x01\x00\x00\x00\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'
b'\x80\x04\x05,\x00\x00\x80\x01\x00\x00\x80\x02\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x80\x02\x01\x05,\x00\x00\x80\x01\x00\x00\x80\x02\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'
b'\x80\x04\x05,\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x02\x00\x00\x00'
b'\x80\x02\x01\x05,\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x02\x00\x00\x00\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'
```

Now the next step is to parse these bytearrays to a message object...

Let's take a look at `b'\x80\x04\x05,\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x01\x00\x00\x00'`

This message is a `INS_GET_PUBLIC_KEY = 0x04` message. The next bytes are just data.

Here in the source code:

```
    // Derives and returns the corresponding public key for the given path
    case INS_GET_PUBLIC_KEY:
        REQUIRE_ONBOARDED();

        reset_if_starting(INS_GET_PUBLIC_KEY);

        // Check the received data size
        if (rx != DATA + sizeof(uint32_t) * BIP32_PATH_NUMPARTS)
            THROW(ERR_INVALID_DATA_SIZE); // Wrong buffer size

        // Check for path validity before returning the public key
        // Actual path starts at normal data pointer, but
        // is prepended by a single byte indicating the path length
        // (all paths have the same length in practice, so this should
        // be refactored in the future)
        if (!(pathRequireAuth(APDU_DATA_PTR - 1) ||
              pathDontRequireAuth(APDU_DATA_PTR - 1))) {
            // If no path match, then bail out
            THROW(ERR_INVALID_PATH); // Invalid Key Path
        }

        // Derive the public key
        SAFE_MEMMOVE(auth.path,
                     sizeof(auth.path),
                     MEMMOVE_ZERO_OFFSET,
                     APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE_OUT,
                     MEMMOVE_ZERO_OFFSET,
                     sizeof(auth.path),
                     THROW(ERR_INVALID_PATH));

        pubkey_length = communication_get_msg_buffer_size();
        if (!seed_derive_pubkey(auth.path,
                                sizeof(auth.path) / sizeof(auth.path[0]),
                                communication_get_msg_buffer(),
                                &pubkey_length)) {
            THROW(ERR_INTERNAL);
        }

        tx = pubkey_length;

        break;
```

Here: `if (rx != DATA + sizeof(uint32_t) * BIP32_PATH_NUMPARTS)` we see that the data section must be 20 bytes, because `common/src/apdu.h:#define DATA 3` and `hal/include/hal/constants.h:#define BIP32_PATH_NUMPARTS 5` which basically means that rx must be 23. 3 bytes are the CLA CMD OP trio. If we check:

```
>>> len('\x80\x04\x05,\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x01\x00\x00\x00')
23
```

we can see that this makes sense.

With this information, we can now write a deserializer.

Maybe something like this?

```

def deserialize_to_obj(message_bytes: bytes) -> APDUMsg: # This deserializes a single message to a APDUMsg object.
	# def __init__(self, CLA, CMD, OP, cmd_data):

	header = message_bytes[:3] # Three first bytes.
	cmd_data = message_bytes[3:] # Then the rest is just data for the command.
	CLA, CMD, OP = header # Take the first three things.
	assert isinstance(CLA, int)
	assert isinstance(CMD, int)
	assert isinstance(OP, int)
	must_be_byte(CLA)
	must_be_byte(CMD)
	must_be_byte(OP)
	# Now create the object...
	msg_obj = APDUMsg(CLA, CMD, OP, cmd_data) # Create the object.
	return msg_obj



def must_be_byte(value: int) -> None: # Checks that an integer can fit in one byte. Basically only used for sanity checking.
	assert value >= 0 and value <= 255
	return

class APDUMsg:
	# https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
	def __init__(self, CLA, CMD, OP, cmd_data):
		# Instruction parameters for the command, e.g., offset into file at which to write the data
		# First some sanity checks.
		must_be_byte(CLA)
		must_be_byte(CMD)
		must_be_byte(OP)
		assert CLA == 0x80 # CLA must always be 0x80

		self.CLA = CLA
		self.CMD = CMD
		self.OP = OP
		self.data = cmd_data # This is the stuff after the 3 byte header.




```

Now we can modify the message data in the object. Then we just need to write a serializer, which also takes into account that the length of the data may change. Then we can just serialize the messages back into bytes and that is our final input to the program!!!

## Writing the deserializer...

I mean maybe it is just something like this?????

```
def serialize_to_bytes(msg: APDUMsg) -> bytes:
	return bytes([msg.CLA]) + bytes([msg.CMD]) + bytes([msg.OP]) + msg.data # Maybe something like this???

```

idk...

Then because the file input also has the length fields, we can just write a serializer with the length field like so:

```

def serialize_with_length(msg: APDUMsg) -> bytes:
	msg_bytes = serialize_to_bytes(msg)
	if len(msg_bytes) > 255:
		print("FUUUUUCCCKKKK")
		exit(1)
	return bytes([len(msg_bytes)]) + msg_bytes # Just something like this maybe???
```

let's test these functions out!!!

Like this???

```
	for chunk in chunks: # Try to parse the chunks from the input file.
		# print(chunk)
		# First deserialize to the message object:
		msg = deserialize_to_obj(chunk) # Deserialize chunk...
		# Now after that try to serialize back.
		new_bytes = serialize_to_bytes(msg)
		assert chunk == new_bytes # Should be the same
```

I had to do a couple of bugfixes, because there are messages which do not have OP or cmd_data fields:

```
class APDUMsg:
	# https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
	def __init__(self, CLA, CMD, OP, cmd_data):
		# Instruction parameters for the command, e.g., offset into file at which to write the data
		# First some sanity checks.
		must_be_byte(CLA)
		must_be_byte(CMD)
		must_be_byte(OP)
		assert CLA == 0x80 # CLA must always be 0x80

		self.CLA = CLA
		self.CMD = CMD
		self.OP = OP
		self.data = cmd_data # This is the stuff after the 3 byte header.



def bytes_or_nothing(thing): # Checks for None
	if thing == None or thing[0] == None:
		return bytes([])
	else:
		return bytes(thing)


def deserialize_to_obj(message_bytes: bytes) -> APDUMsg: # This deserializes a single message to a APDUMsg object.
	# def __init__(self, CLA, CMD, OP, cmd_data):

	header = message_bytes[:3] # Three first bytes.
	cmd_data = message_bytes[3:] # Then the rest is just data for the command.
	#print("header == "+str(header))
	#print("message_bytes == "+str(message_bytes))
	if len(header) == 3:
		CLA, CMD, OP = header # Take the first three things.
	else:
		CLA, CMD = header
		OP = None
		cmd_data = [None]
	assert isinstance(CLA, int)
	assert isinstance(CMD, int)
	assert isinstance(OP, int) or OP == None
	must_be_byte(CLA)
	must_be_byte(CMD)
	must_be_byte(OP)
	# Now create the object...
	msg_obj = APDUMsg(CLA, CMD, OP, cmd_data) # Create the object.
	return msg_obj

def serialize_to_bytes(msg: APDUMsg) -> bytes:
	return bytes_or_nothing([msg.CLA]) + bytes_or_nothing([msg.CMD]) + bytes_or_nothing([msg.OP]) + bytes_or_nothing(msg.data) # Maybe something like this???

def serialize_with_length(msg: APDUMsg) -> bytes:
	msg_bytes = serialize_to_bytes(msg)
	if len(msg_bytes) > 255:
		print("FUUUUUCCCKKKK")
		exit(1)
	return bytes([len(msg_bytes)]) + msg_bytes # Just something like this maybe???


def must_be_byte(value: int) -> None: # Checks that an integer can fit in one byte. Basically only used for sanity checking.
	if value == None:
		return # Just a quick little shorthand :D
	assert value >= 0 and value <= 255
	return





```

Now it works!

Now we can just serialize with the length and we are golden:

```

def test_mutator():
	fh = open("input.bin", "rb") # Read the file "input.bin"
	data = fh.read() # Read input data.
	fh.close()
	chunks = try_parse_input(data)
	#print(res)
	for chunk in chunks: # Try to parse the chunks from the input file.
		# print(chunk)
		# First deserialize to the message object:
		msg = deserialize_to_obj(chunk) # Deserialize chunk...
		# Now after that try to serialize back.
		new_bytes = serialize_to_bytes(msg)
		print("chunk: "+str(chunk)+" "*10+"new_bytes: "+str(new_bytes))
		assert chunk == new_bytes # Should be the same

	# Now we should get the same file input back if we deserialize with length.

	thing = bytes([])
	for chunk in chunks:

		msg = deserialize_to_obj(chunk)

		new_bytes_with_length = serialize_with_length(msg) # Just something like this maybe???

		thing += new_bytes_with_length # Add it to that.

	assert thing == data # Final check...

	print("Tests passed!!!")

	return

```

It passes!!!

## Actually mutating the data.

Now we should just actually mutate the data in the messages...

Now, to mutate the data and stuff, I am just going to use my generic mutator, which you can find here: https://github.com/personnumber3377/generic_mutator

Here is the main mutator function:

```
def mutate_contents(databytes: bytes) -> bytes: # Mutates bytes
	fh = open("input.bin", "rb") # Read the file "input.bin"
	data = fh.read() # Read input data.
	fh.close()
	chunks = try_parse_input(data)
	if chunks == None: # The original data passed to this function was invalid. Return a generic mutation
		return mutate(databytes) # Just use the generic mutator...
	# Now we should get the same file input back if we deserialize with length.
	thing = bytes([])
	messages = []
	for chunk in chunks:
		msg = deserialize_to_obj(chunk)
		messages.append(msg) # Add that message thing.
	# Ok, so now we have the messages in "messages". Select a mutation strategy and mutate.
	mutate_messages(messages) # Mutate the message objects...
	# Serialize back to bytes
	thing = bytes([])
	for msg in messages:
		new_bytes_with_length = serialize_with_length(msg) # Just something like this maybe???
		thing += new_bytes_with_length # Add it to that.
	return thing # Return the final thing
```

it first tries to deserialize the bytes to the message objects, then it mutates those objects and then after that it tries to just serialize them back to the input file thing... Now, we just need to implement mutate_messages !

Something like this???

```

def mutate_messages(messages: list) -> list: # Mutates the messages.

	mut_strat = random.randrange(3)

	if mut_strat == 0: # Mutate the data thing.
		# Select message index which to mutate.
		rand_index = random.randrange(len(messages)) # First generate a random index...
		messages[rand_index].data = mutate(messages[rand_index].data)[:255] # Use our generic mutator... we need to cap at 255 bytes, because the length field is one byte only...


```

Actually let's program a test function called `test_mutating` which takes the file contents, then mutates them like a thousand times just for the lulz...

After a couple of bugfixes, I now have commit 52177a6d6e487bc0392046d73fd53af989fa359c which now fuzzes succesfully. Great!

## Improving further.

First of all, my fuzz_count function always returns 1000 no matter what the input is. Now, one thing to do this is to check if the input is well formed, then if yes, then try to fuzz, but otherwise don't. This is to save cycles when we don't try to custom mutate corrupt data which doesn't even represent anything..

Something like this maybe?

```

def fuzz_count(buf):
	if try_parse_input(buf) != None: # The input is actually valid.
		return 1000
	else:
		return 1 # Just fuzz once, because reasons...

```

then we should also add some fuzzing strategies. For example multiplying messages seems quite promising...

Something like this????

```
	elif mut_strat == 2:
		# Copy message
		rand_index = random.randrange(len(messages))
		message_to_be_copied = messages[rand_index]
		new_msg = copy.deepcopy(message_to_be_copied)
		# Now insert it into the list at a random location...
		messages.insert(random.randrange(len(messages)), new_msg) # Add a copy of the messages to the list thing..
```

In addition, we should add instruction specific mutations, for example we look at the cmd and mutate the message based on that.

Also we sould change the instruction to some random thing that could also be plausible. In addition we should also generate completely new messages from scratch and add those to our thing..


One idea i have is to have hardcoded lengths for the data portion for some of the commands. There is this shit in the `bc_advance.c` file:

```


/*
 * Advance blockchain state.
 *
 * @arg[in] rx number of received bytes from the Host
 * @ret     number of transmited bytes to the host
 */
unsigned int bc_advance(volatile unsigned int rx) {
    uint8_t op = APDU_OP();

    // Check we are getting expected OP
    if (op != OP_ADVANCE_INIT && op != expected_state) {
        FAIL(PROT_INVALID);
    }

    // Check we are getting the expected amount of data
    if (op == OP_ADVANCE_INIT && APDU_DATA_SIZE(rx) != sizeof(uint32_t)) {
        FAIL(PROT_INVALID);
    }
    if ((op == OP_ADVANCE_HEADER_META || op == OP_ADVANCE_BROTHER_META) &&
        APDU_DATA_SIZE(rx) !=
            (sizeof(block.mm_rlp_len) + sizeof(block.cb_txn_hash))) {
        FAIL(PROT_INVALID);
    }
    if (op == OP_ADVANCE_BROTHER_LIST_META &&
        APDU_DATA_SIZE(rx) != sizeof(block.brother_count)) {
        FAIL(PROT_INVALID);
    }
    if (op == OP_ADVANCE_HEADER_CHUNK || op == OP_ADVANCE_BROTHER_CHUNK) {
        uint16_t expected_txlen =
            block.size > 0 ? MIN(block.size - block.recv, MAX_CHUNK_SIZE)
                           : MAX_CHUNK_SIZE;
        if (APDU_DATA_SIZE(rx) != expected_txlen) {
            FAIL(PROT_INVALID);
        }
    }

```


Done! I implemented these in the commit abbf014eb0be280c277255a342e9ee488b23f8d1 !

## Adding some jumbling stuff.

Ok, so looking through the documentation for custom mutators, we actually have a possibility to intertvine the testcases. Here: https://aflplus.plus/docs/custom_mutators/ "The add_buf is the contents of another queue item that can be used for splicing - or anything else - and can also be ignored." . So my idea is to extract messages from other testcases and then insert them into other testcases. Therefore we can maybe get more coverage maybe????

Done!

## Adding some support for the btc shit and stuff like that.

There is this very interesting function in trie_auth.c:

```

 * @ret             number of transmited bytes to the host
 */
unsigned int auth_sign_handle_merkleproof(volatile unsigned int rx) {
    uint8_t apdu_offset = 0;

    if (auth.state != STATE_AUTH_MERKLEPROOF) {
        LOG("[E] Expected to be in the MP state\n");
        THROW(ERR_AUTH_INVALID_STATE);
    }

    while (true) {
        // Read number of nodes (single byte)
        if (auth.trie.total_nodes == 0) {
            auth.trie.total_nodes = APDU_DATA_PTR[apdu_offset++];
            auth.trie.current_node = 0;
            auth.trie.state = AUTH_TRIE_STATE_NODE_LENGTH;

            REQUEST_MORE_IF_NEED();
        }

```

and looking at the source code this function is called from this:


```


/*
 * Implement the signing authorization protocol.
 *
 * @arg[in] rx      number of received bytes from the host
 * @ret             number of transmited bytes to the host
 */
unsigned int auth_sign(volatile unsigned int rx) {
    unsigned int tx;
    uint8_t sig_size;

    // Sanity check: tx hash size and
    // last auth signed tx hash size
    // must match
    COMPILE_TIME_ASSERT(sizeof(N_bc_state.last_auth_signed_btc_tx_hash) ==
                        sizeof(auth.tx_hash));

    // Check we receive the amount of bytes we requested
    // (this is an extra check on the legacy protocol, not
    // really adding much validation)
    if (auth.state != STATE_AUTH_START &&
        auth.state != STATE_AUTH_MERKLEPROOF &&
        APDU_DATA_SIZE(rx) != auth.expected_bytes)
        THROW(ERR_AUTH_INVALID_DATA_SIZE);

    switch (APDU_OP() & 0xF) {
    case P1_PATH:
        if ((tx = auth_sign_handle_path(rx)) == 0)
            break;
        return tx;
    case P1_BTC:
        return auth_sign_handle_btctx(rx);
    case P1_RECEIPT:
        return auth_sign_handle_receipt(rx);
    case P1_MERKLEPROOF:
        if ((tx = auth_sign_handle_merkleproof(rx)) == 0)
            break;
        return tx;
    default:
        // Invalid OP
        THROW(ERR_AUTH_INVALID_DATA_SIZE);
    }

```


so the current state must be `STETE_AUTH_MERKLEPROOF` and that is actually set in the receipt phase of the thing:

```


/*
 * Implement the RSK receipt parsing and validation portion of the signing
 * authorization protocol.
 *
 * @arg[in] rx      number of received bytes from the host
 * @ret             number of transmited bytes to the host
 */
unsigned int auth_sign_handle_receipt(volatile unsigned int rx) {
    if (auth.state != STATE_AUTH_RECEIPT) {
        LOG("[E] Expected to be in the receipt state\n");
        THROW(ERR_AUTH_INVALID_STATE);
    }

    if (!HAS_FLAG(auth.receipt.flags, IS_INIT)) {
        rlp_start(&callbacks);
        hash_keccak256_init(&auth.receipt.hash_ctx);
        SET_FLAG(auth.receipt.flags, IS_INIT);
    }

    int res = rlp_consume(APDU_DATA_PTR, APDU_DATA_SIZE(rx));
    if (res < 0) {
        LOG("[E] RLP parser returned error %d\n", res);
        THROW(ERR_AUTH_RECEIPT_RLP);
    }
    auth.receipt.remaining_bytes -= APDU_DATA_SIZE(rx);

    hash_keccak256_update(
        &auth.receipt.hash_ctx, APDU_DATA_PTR, APDU_DATA_SIZE(rx));

    if (auth.receipt.remaining_bytes == 0) {
        if (HAS_FLAG(auth.receipt.flags, IS_MATCH)) {
            // Finalize the hash calculation
            hash_keccak256_final(&auth.receipt.hash_ctx, auth.receipt_hash);

            // Log hash for debugging purposes
            LOG_HEX(
                "Receipt hash: ", auth.receipt_hash, sizeof(auth.receipt_hash));

            // Request RSK transaction receipt
            SET_APDU_OP(P1_MERKLEPROOF);
            SET_APDU_TXLEN(AUTH_MAX_EXCHANGE_SIZE);
            auth.expected_bytes = APDU_TXLEN();
            auth_transition_to(STATE_AUTH_MERKLEPROOF);
            return TX_FOR_TXLEN();
        }

        // No match
        LOG("[E] No log match found in the receipt\n");
        // To comply with the legacy implementation
        THROW(ERR_AUTH_INVALID_DATA_SIZE);
    }

```


this function then assumes that the state:

```

unsigned int auth_sign_handle_receipt(volatile unsigned int rx) {
    if (auth.state != STATE_AUTH_RECEIPT) {
        LOG("[E] Expected to be in the receipt state\n");
        THROW(ERR_AUTH_INVALID_STATE);
    }

```

is set.

It is actually then set in this function here:

```

/*
 * Implement the BTC tx parsing and calculations portion
 * of the signing authorization protocol.
 *
 * @arg[in] rx      number of received bytes from the host
 * @ret             number of transmited bytes to the host
 */
unsigned int auth_sign_handle_btctx(volatile unsigned int rx) {
    uint8_t apdu_offset = 0;

    if (auth.state != STATE_AUTH_BTCTX) {
        LOG("[E] Expected to be in the BTC tx state\n");
        THROW(ERR_AUTH_INVALID_STATE);
    }

    if (!auth.tx.segwit_processing_extradata) {
        // Read little endian TX length
        // (part of the legacy protocol, includes this length)
        if (auth.tx.remaining_bytes == 0) {
            for (uint8_t i = 0; i < BTCTX_LENGTH_SIZE; i++) {
                auth.tx.remaining_bytes += APDU_DATA_PTR[i] << (8 * i);
            }
            // BTC tx length includes the length of the length
            // and the length of the sighash computation mode and
            // extradata length
            auth.tx.remaining_bytes -=
                BTCTX_LENGTH_SIZE + SIGHASH_COMP_MODE_SIZE + EXTRADATA_SIZE;
            // Init both hash operations
            hash_sha256_init(&auth.tx.tx_hash_ctx);
            hash_sha256_init(&auth.tx.sig_hash_ctx);
            apdu_offset = BTCTX_LENGTH_SIZE;
            // Following three bytes indicate the sighash computation
            // mode (1 byte) and extradata size (2 bytes LE, for segwit)
            auth.tx.sighash_computation_mode = APDU_DATA_PTR[apdu_offset++];
            auth.tx.segwit_processing_extradata = false;
            auth.tx.segwit_extradata_size = 0;
            auth.tx.segwit_extradata_size += APDU_DATA_PTR[apdu_offset++];
            auth.tx.segwit_extradata_size += APDU_DATA_PTR[apdu_offset++] << 8;
            // Validate computation mode and init tx parsing context
            switch (auth.tx.sighash_computation_mode) {
            case SIGHASH_COMPUTE_MODE_LEGACY:
                btctx_init(&auth.tx.ctx, &btctx_cb);
                break;
            case SIGHASH_COMPUTE_MODE_SEGWIT:
                btctx_init(&auth.tx.ctx, &btctx_cb_segwit);
                if (!auth.tx.segwit_extradata_size) {
                    LOG("[E] Invalid extradata size for segwit");
                    THROW(ERR_AUTH_INVALID_EXTRADATA_SIZE);
                }
                break;
            default:
                LOG("[E] Invalid sighash computation mode\n");
                THROW(ERR_AUTH_INVALID_SIGHASH_COMPUTATION_MODE);
            }
        }

        auth.tx.remaining_bytes -= btctx_consume(
            APDU_DATA_PTR + apdu_offset, APDU_DATA_SIZE(rx) - apdu_offset);

        if (btctx_result() < 0) {
            LOG("[E] Error parsing BTC tx: %d\n", btctx_result());
            // To comply with the legacy implementation
            THROW(ERR_AUTH_TX_HASH_MISMATCH);
        }

        if (btctx_result() == BTCTX_ST_DONE) {
            if (auth.tx.remaining_bytes > 0) {
                LOG("[E] Error parsing BTC tx: more bytes reported "
                    "than actual tx bytes\n");
                // To comply with the legacy implementation
                THROW(ERR_AUTH_INVALID_DATA_SIZE);
            }

            // Finalize TX hash computation
            hash_sha256_final(&auth.tx.tx_hash_ctx, auth.tx_hash);
            hash_sha256_init(&auth.tx.tx_hash_ctx);
            hash_sha256_update(&auth.tx.tx_hash_ctx, auth.tx_hash, 32);
            hash_sha256_final(&auth.tx.tx_hash_ctx, auth.tx_hash);
            for (int j = 0; j < 16; j++) {
                uint8_t aux = auth.tx_hash[j];
                auth.tx_hash[j] = auth.tx_hash[31 - j];
                auth.tx_hash[31 - j] = aux;
            }

            // Segwit?
            if (auth.tx.sighash_computation_mode ==
                SIGHASH_COMPUTE_MODE_SEGWIT) {
                auth.tx.segwit_processing_extradata = true;
                auth.tx.remaining_bytes =
                    (uint32_t)auth.tx.segwit_extradata_size;
            } else {
                auth.tx.finalise = true;
            }
        }
    } else {
        // Hash extradata
        hash_sha256_update(
            &auth.tx.sig_hash_ctx, APDU_DATA_PTR, APDU_DATA_SIZE(rx));
        auth.tx.remaining_bytes -= APDU_DATA_SIZE(rx);
        if (auth.tx.remaining_bytes == 0) {
            auth.tx.finalise = true;
        }
    }

    if (auth.tx.finalise) {
        if (auth.tx.sighash_computation_mode == SIGHASH_COMPUTE_MODE_SEGWIT) {
            // Remaining tx items to hash for segwit
            hash_sha256_update(&auth.tx.sig_hash_ctx,
                               auth.tx.ip_seqno,
                               sizeof(auth.tx.ip_seqno));
            hash_sha256_update(&auth.tx.sig_hash_ctx,
                               auth.tx.outputs_hash,
                               sizeof(auth.tx.outputs_hash));
            hash_sha256_update(&auth.tx.sig_hash_ctx,
                               auth.tx.lock_time,
                               sizeof(auth.tx.lock_time));
        }

        // Add SIGHASH_ALL hash type at the end
        hash_sha256_update(&auth.tx.sig_hash_ctx,
                           (uint8_t[])SIGHASH_ALL_BYTES,
                           sizeof(SIGHASH_ALL_SIZE));
        hash_sha256_final(&auth.tx.sig_hash_ctx, auth.sig_hash);

        hash_sha256_init(&auth.tx.sig_hash_ctx);
        hash_sha256_update(&auth.tx.sig_hash_ctx, auth.sig_hash, 32);
        hash_sha256_final(&auth.tx.sig_hash_ctx, auth.sig_hash);

        // Log hashes for debugging purposes
        LOG_HEX("TX hash:     ", auth.tx_hash, sizeof(auth.tx_hash));
        LOG_HEX("TX sig hash: ", auth.sig_hash, sizeof(auth.sig_hash));

        // Request RSK transaction receipt
        SET_APDU_OP(P1_RECEIPT);
        SET_APDU_TXLEN(AUTH_MAX_EXCHANGE_SIZE);
        auth.expected_bytes = APDU_TXLEN();
        auth_transition_to(STATE_AUTH_RECEIPT);
        return TX_FOR_TXLEN();
    }

    if (auth.tx.remaining_bytes == 0) {
        LOG("[E] Error parsing BTC tx: no more bytes should "
            "remain but haven't finished parsing\n");
        // To comply with the legacy implementation
        THROW(ERR_AUTH_TX_HASH_MISMATCH);
    }

```

So we must call this function first.


```

/*
 * Implement the signing authorization protocol.
 *
 * @arg[in] rx      number of received bytes from the host
 * @ret             number of transmited bytes to the host
 */
unsigned int auth_sign(volatile unsigned int rx) {
    unsigned int tx;
    uint8_t sig_size;

    // Sanity check: tx hash size and
    // last auth signed tx hash size
    // must match
    COMPILE_TIME_ASSERT(sizeof(N_bc_state.last_auth_signed_btc_tx_hash) ==
                        sizeof(auth.tx_hash));

    // Check we receive the amount of bytes we requested
    // (this is an extra check on the legacy protocol, not
    // really adding much validation)
    if (auth.state != STATE_AUTH_START &&
        auth.state != STATE_AUTH_MERKLEPROOF &&
        APDU_DATA_SIZE(rx) != auth.expected_bytes)
        THROW(ERR_AUTH_INVALID_DATA_SIZE);

    switch (APDU_OP() & 0xF) {
    case P1_PATH:
        if ((tx = auth_sign_handle_path(rx)) == 0)
            break;
        return tx;
    case P1_BTC:
        return auth_sign_handle_btctx(rx);
    case P1_RECEIPT:
        return auth_sign_handle_receipt(rx);
    case P1_MERKLEPROOF:
        if ((tx = auth_sign_handle_merkleproof(rx)) == 0)
            break;
        return tx;
    default:
        // Invalid OP
        THROW(ERR_AUTH_INVALID_DATA_SIZE);
    }

```


which is also called in the auth_sign thing..

The instruction is therefore INS_SIGN which is the signing command...

Therefore we basically need to generate three messages. Actually we need to have four things... we also need the path shit.


Let's get to work!

We actually want to trigger this path: `    if (pathRequireAuth(APDU_DATA_PTR)) {`



Now looking at `authPath.c` we can see that the path:

```

"\x05\x2c\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00"

```

requires authentication

let's check the length of this path, it should be 21 I think...

```
>>> len("\x05\x2c\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00")
21

```

yeah, that checks out...

So therefore, the first bytes of the data must be some of the paths which require authentication.

This quick little program here generates the required message thing:

```
    # hal/include/hal/constants.h:#define HASH_LENGTH 32

    length = 21 + 4 # The length is either this. This is the first one
    # could also be this: # length = 21 + 32

    # the CMD is ins.INS_SIGN   the OP is basically just

    # The first 21 bytes of the data field must be "\x05\x2c\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00" or some other path which requires authentication...

    # At this point I don't know what the last 4 bytes should be, so let's just set them to b'AAAA' . :D

    handle_path_data = b"\x05\x2c\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00"+b"\x41\x41\x41"
    handle_path_data = bytes(handle_path_data)
    assert len(handle_path_data) == length
    # Now generate the handle_path_msg
    # start_msg = APDUMsg(0x80, 0x06, None, [None]) # This message is always the very first one...

    messages = []
    handle_path_msg = APDUMsg(0x80, ins.INS_SIGN, 0x01, handle_path_data) # 0x01 == P1_PATH .
    # Now at this point we should trigger the authorized path thing...
    messages.append(handle_path_msg) # Append this message to the messages...
```

Onto the next one...

The next one is the

```

    case P1_BTC:
        return auth_sign_handle_btctx(rx);

```

message.


This function here:

```

/*
 * Implement the BTC tx parsing and calculations portion
 * of the signing authorization protocol.
 *
 * @arg[in] rx      number of received bytes from the host
 * @ret             number of transmited bytes to the host
 */
unsigned int auth_sign_handle_btctx(volatile unsigned int rx) {
    uint8_t apdu_offset = 0;

    if (auth.state != STATE_AUTH_BTCTX) {
        LOG("[E] Expected to be in the BTC tx state\n");
        THROW(ERR_AUTH_INVALID_STATE);
    }

    if (!auth.tx.segwit_processing_extradata) {
        // Read little endian TX length
        // (part of the legacy protocol, includes this length)
        if (auth.tx.remaining_bytes == 0) {
            for (uint8_t i = 0; i < BTCTX_LENGTH_SIZE; i++) {
                auth.tx.remaining_bytes += APDU_DATA_PTR[i] << (8 * i);
            }
            // BTC tx length includes the length of the length
            // and the length of the sighash computation mode and
            // extradata length
            auth.tx.remaining_bytes -=
                BTCTX_LENGTH_SIZE + SIGHASH_COMP_MODE_SIZE + EXTRADATA_SIZE;
            // Init both hash operations
            hash_sha256_init(&auth.tx.tx_hash_ctx);
            hash_sha256_init(&auth.tx.sig_hash_ctx);
            apdu_offset = BTCTX_LENGTH_SIZE;
            // Following three bytes indicate the sighash computation
            // mode (1 byte) and extradata size (2 bytes LE, for segwit)
            auth.tx.sighash_computation_mode = APDU_DATA_PTR[apdu_offset++];
            auth.tx.segwit_processing_extradata = false;
            auth.tx.segwit_extradata_size = 0;
            auth.tx.segwit_extradata_size += APDU_DATA_PTR[apdu_offset++];
            auth.tx.segwit_extradata_size += APDU_DATA_PTR[apdu_offset++] << 8;
            // Validate computation mode and init tx parsing context
            switch (auth.tx.sighash_computation_mode) {
            case SIGHASH_COMPUTE_MODE_LEGACY:
                btctx_init(&auth.tx.ctx, &btctx_cb);
                break;
            case SIGHASH_COMPUTE_MODE_SEGWIT:
                btctx_init(&auth.tx.ctx, &btctx_cb_segwit);
                if (!auth.tx.segwit_extradata_size) {
                    LOG("[E] Invalid extradata size for segwit");
                    THROW(ERR_AUTH_INVALID_EXTRADATA_SIZE);
                }
                break;
            default:
                LOG("[E] Invalid sighash computation mode\n");
                THROW(ERR_AUTH_INVALID_SIGHASH_COMPUTATION_MODE);
            }
        }

        auth.tx.remaining_bytes -= btctx_consume(
            APDU_DATA_PTR + apdu_offset, APDU_DATA_SIZE(rx) - apdu_offset);

        if (btctx_result() < 0) {
            LOG("[E] Error parsing BTC tx: %d\n", btctx_result());
            // To comply with the legacy implementation
            THROW(ERR_AUTH_TX_HASH_MISMATCH);
        }

        if (btctx_result() == BTCTX_ST_DONE) {
            if (auth.tx.remaining_bytes > 0) {
                LOG("[E] Error parsing BTC tx: more bytes reported "
                    "than actual tx bytes\n");
                // To comply with the legacy implementation
                THROW(ERR_AUTH_INVALID_DATA_SIZE);
            }

            // Finalize TX hash computation
            hash_sha256_final(&auth.tx.tx_hash_ctx, auth.tx_hash);
            hash_sha256_init(&auth.tx.tx_hash_ctx);
            hash_sha256_update(&auth.tx.tx_hash_ctx, auth.tx_hash, 32);
            hash_sha256_final(&auth.tx.tx_hash_ctx, auth.tx_hash);
            for (int j = 0; j < 16; j++) {
                uint8_t aux = auth.tx_hash[j];
                auth.tx_hash[j] = auth.tx_hash[31 - j];
                auth.tx_hash[31 - j] = aux;
            }

            // Segwit?
            if (auth.tx.sighash_computation_mode ==
                SIGHASH_COMPUTE_MODE_SEGWIT) {
                auth.tx.segwit_processing_extradata = true;
                auth.tx.remaining_bytes =
                    (uint32_t)auth.tx.segwit_extradata_size;
            } else {
                auth.tx.finalise = true;
            }
        }
    } else {
        // Hash extradata
        hash_sha256_update(
            &auth.tx.sig_hash_ctx, APDU_DATA_PTR, APDU_DATA_SIZE(rx));
        auth.tx.remaining_bytes -= APDU_DATA_SIZE(rx);
        if (auth.tx.remaining_bytes == 0) {
            auth.tx.finalise = true;
        }
    }

    if (auth.tx.finalise) {
        if (auth.tx.sighash_computation_mode == SIGHASH_COMPUTE_MODE_SEGWIT) {
            // Remaining tx items to hash for segwit
            hash_sha256_update(&auth.tx.sig_hash_ctx,
                               auth.tx.ip_seqno,
                               sizeof(auth.tx.ip_seqno));
            hash_sha256_update(&auth.tx.sig_hash_ctx,
                               auth.tx.outputs_hash,
                               sizeof(auth.tx.outputs_hash));
            hash_sha256_update(&auth.tx.sig_hash_ctx,
                               auth.tx.lock_time,
                               sizeof(auth.tx.lock_time));
        }

        // Add SIGHASH_ALL hash type at the end
        hash_sha256_update(&auth.tx.sig_hash_ctx,
                           (uint8_t[])SIGHASH_ALL_BYTES,
                           sizeof(SIGHASH_ALL_SIZE));
        hash_sha256_final(&auth.tx.sig_hash_ctx, auth.sig_hash);

        hash_sha256_init(&auth.tx.sig_hash_ctx);
        hash_sha256_update(&auth.tx.sig_hash_ctx, auth.sig_hash, 32);
        hash_sha256_final(&auth.tx.sig_hash_ctx, auth.sig_hash);

        // Log hashes for debugging purposes
        LOG_HEX("TX hash:     ", auth.tx_hash, sizeof(auth.tx_hash));
        LOG_HEX("TX sig hash: ", auth.sig_hash, sizeof(auth.sig_hash));

        // Request RSK transaction receipt
        SET_APDU_OP(P1_RECEIPT);
        SET_APDU_TXLEN(AUTH_MAX_EXCHANGE_SIZE);
        auth.expected_bytes = APDU_TXLEN();
        auth_transition_to(STATE_AUTH_RECEIPT);
        return TX_FOR_TXLEN();
    }

    if (auth.tx.remaining_bytes == 0) {
        LOG("[E] Error parsing BTC tx: no more bytes should "
            "remain but haven't finished parsing\n");
        // To comply with the legacy implementation
        THROW(ERR_AUTH_TX_HASH_MISMATCH);
    }

    SET_APDU_TXLEN(MIN(auth.tx.remaining_bytes, AUTH_MAX_EXCHANGE_SIZE));
    auth.expected_bytes = APDU_TXLEN();
    return TX_FOR_TXLEN();
}

```


basically does that. I have no fucking clue as to how this works. Let's just try it with some random data and see what happens????

## Getting the testcases from the source code.

There exists a utility called `extract-inputs-from-tests` which seems very interesting imo.. The testcases that come with the source originally don't really do anything, since some stuff is different and it makes them not work with the newest version or something idk..





