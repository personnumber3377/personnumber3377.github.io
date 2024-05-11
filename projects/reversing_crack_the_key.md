
# Reversing "crack the key"

I found this nice little crack me: https://crackmes.one/crackme/65ed01ee7b0f7ceced2c5afb and I decided to give it a crack (get it?) .

## The usual start

If I run the binary, I get this message:

```
cyberhacker@cyberhacker-h8-1131sc:~/Asioita/Hakkerointi/www.crackmes.one/crack the key$ ./ctf_1 
Error opening file: No such file or directory
```

so it tries to load a file for some reason.

Here is the decompilation of the main function:

```

undefined4 main(void)

{
  size_t sVar1;
  char local_73 [11];
  size_t local_68;
  undefined8 local_60;
  undefined4 local_58;
  undefined4 local_50;
  undefined4 uStack76;
  undefined4 local_48;
  byte local_41 [9];
  size_t local_38;
  int local_2c;
  char *local_28;
  int local_1c;
  FILE *local_18;
  undefined4 local_10;
  int local_c;
  
  local_10 = 0;
  strcpy(local_73,finh);
  local_18 = fopen(local_73,"r");
  if (local_18 == (FILE *)0x0) {
    perror("Error opening file");
    local_10 = 0xffffffff;
  }
  else {
    fseek(local_18,0,2);
    local_38 = ftell(local_18);
    rewind(local_18);
    local_28 = (char *)malloc(local_38 + 1);
    if (local_28 == (char *)0x0) {
      perror("Error allocating memory");
      fclose(local_18);
      local_10 = 0xffffffff;
    }
    else {
      local_68 = fread(local_28,1,local_38,local_18);
      if (local_68 == local_38) {
        fclose(local_18);
        local_28[local_38] = '\0';
        sVar1 = strlen(local_28);
        if (sVar1 == 8) {
          local_50 = 8;
          uStack76 = 0x20;
          local_48 = 0x30;
          local_1c = 0;
          local_2c = 1;
          strcpy((char *)local_41,local_28);
          local_c = 0;
          while (local_c < 8) {
            local_1c = local_1c + 1;
            fkey[local_c] = fkey[local_c] ^ local_41[local_c];
            local_41[local_c] = local_41[local_c] ^ key[local_c + 1];
            if (local_41[local_c] != *(byte *)((long)&skey + (long)local_c)) {
              local_2c = 0;
              break;
            }
            local_c = local_c + 1;
          }
          if (local_2c == 1) {
            local_60 = CONCAT44(uStack76,local_50);
            local_58 = local_48;
            giveFlag(local_1c,local_60,local_48);
          }
        }
        free(local_28);
        local_10 = 0;
      }
      else {
        perror("Error reading file");
        fclose(local_18);
        local_10 = 0xffffffff;
      }
    }
  }
  return local_10;
}


```

Here is the finh variable:

```
                             finh                                            XREF[1]:     main:00101433(*)  
        00104070 73 65 63        ds         "secret_flag"
                 72 65 74 
                 5f 66 6c 

```

so it tries to read a file called secret_flag .

Now, when I run the binary, the program just (seem to) exit.

The interesting part of the program is this:

```

        fclose(local_18);
        local_28[local_38] = '\0';
        sVar1 = strlen(local_28);
        if (sVar1 == 8) {
          local_50 = 8;
          uStack76 = 0x20;
          local_48 = 0x30;
          local_1c = 0;
          local_2c = 1;
          strcpy((char *)local_41,local_28);
          local_c = 0;
          while (local_c < 8) {
            local_1c = local_1c + 1;
            fkey[local_c] = fkey[local_c] ^ local_41[local_c];
            local_41[local_c] = local_41[local_c] ^ key[local_c + 1];
            if (local_41[local_c] != *(byte *)((long)&skey + (long)local_c)) {
              local_2c = 0;
              break;
            }
            local_c = local_c + 1;
          }
          if (local_2c == 1) {
            local_60 = CONCAT44(uStack76,local_50);
            local_58 = local_48;
            giveFlag(local_1c,local_60,local_48);
          }
        }

```

here is the checking part of the function:

```
          while (indexcounter < 8) {
            counter = counter + 1;
            fkey[indexcounter] = fkey[indexcounter] ^ key_input[indexcounter];
            key_input[indexcounter] = key_input[indexcounter] ^ key[indexcounter + 1];
            if (key_input[indexcounter] != *(byte *)((long)&skey + (long)indexcounter)) {
              local_2c = 0;
              break;
            }
            indexcounter = indexcounter + 1;
          }
```

this part: `while (indexcounter < 8)` tells me that the stuff inside our "secret_flag" must be eight characters. Or it can be more than that but subsequent bytes are ignored.

skey is this here: `76216053849c6279`


and the key variable is this: `0005541036f6f10317` , now notice that we add one to the indexcounter, we actually skip the very first null byte.

The key_input variable is just our input to the program from the secret_flag file.

Notice that fkey isn't actually even used in the comparison and it doesn't really affect the key checking.

To get the correct input, we just need to xor skey with key and we get the correct input.

Just use python3:

```
#!/bin/python3

skey = 0x76216053849c6279
key = 0x05541036f6f10317


res = hex(skey ^ key)[2:]

bytes_list = bytes.fromhex(res)

for char in list(bytes_list):
	print(chr(char), end="")
print("\n", end="")

```

and the solution is `superman` . Put that into the secret_flag file and tada! We solved it!



















