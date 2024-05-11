
# Reverse engineering nano challenge.

Hi! Okay so I decided to do some reverse engineering. I actually have an account on crackmes.one , but I haven't logged on in a long while. I searched up some crackme and found this: https://crackmes.one/crackme/65e5f417199e6a5d372a4045 .

Let's download it and see what we can do!

# Reversing the flag creation.

Ok, so if you just run the binary you get this:

```
cyberhacker@cyberhacker-h8-1131sc:~/Asioita/Hakkerointi/www.crackmes.one/nano$ ./nano 
usage: ./nano <flag>
```

so it takes an argument from argv and compares it to the flag probably.

Let's open up ghidra!

Here is the main function in ghidra:

```

undefined8 main(int param_1,undefined8 *param_2,undefined8 param_3,char param_4)

{
  char *pcVar1;
  byte *pbVar2;
  char cVar3;
  int iVar4;
  char *pcVar5;
  undefined4 *puVar6;
  long lVar7;
  uint *__stat_loc;
  int *piVar8;
  bool bVar9;
  undefined uVar10;
  undefined auStack264 [24];
  ulong uStack240;
  long lStack136;
  uint local_24;
  undefined *puStack32;
  byte local_11;
  __pid_t local_10;
  int iStack12;
  
  iStack12 = 0;
  if (param_1 != 2) {
    printf("usage: %s <flag>\n",*param_2);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  local_10 = fork();
  bVar9 = local_10 == 0;
  if (bVar9) {
    if ((!bVar9) && (bVar9)) {
      pcVar5 = (char *)func_0x00d7da2c();
      cVar3 = (char)pcVar5;
      *pcVar5 = *pcVar5 + cVar3;
      pcVar1 = pcVar5 + -0x75;
      *pcVar1 = *pcVar1 + param_4;
      bVar9 = *pcVar1 == '\0';
      if (!bVar9) {
        *pcVar5 = *pcVar5 + cVar3;
        *pcVar5 = *pcVar5 + cVar3;
        bVar9 = *pcVar5 == '\0';
      }
    }
    if ((!bVar9) && (bVar9)) {
      puVar6 = (undefined4 *)func_0x00d2da3c();
      *(char *)puVar6 = *(char *)puVar6 + (char)puVar6;
      *(char *)((long)puVar6 + -0x39) = *(char *)((long)puVar6 + -0x39) + param_4;
      *puVar6 = *puVar6;
      *(char *)puVar6 = *(char *)puVar6 + (char)puVar6;
    }
    func_00101189();
    iVar4 = check(param_2[1]);
    if (iVar4 == 0) {
      puts("yes");
    }
    else {
      puts("no");
    }
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  func_0xfffffffff8859e9f();
  func_00101189();
  do {
    do {
      __stat_loc = &local_24;
      waitpid(local_10,(int *)__stat_loc,0);
      cVar3 = (char)__stat_loc;
      if ((local_24 & 0x7f) == 0) {
        return 0;
      }
    } while (local_24 == 0xffff);
    uVar10 = (local_24 & 0xff) == 0x7f;
    if (((bool)uVar10) && (uVar10 = (local_24 & 0xff00) == 0xb00, (bool)uVar10)) {
      iStack12 = iStack12 + 1;
      local_11 = ((char)iStack12 * '\b' ^ 0xcaU | (byte)(iStack12 >> 5)) ^ 0xfe;
      bVar9 = local_11 == 0;
      if ((!bVar9) && (bVar9)) {
        func_0x0095a135();
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      puStack32 = auStack264;
      piVar8 = (int *)0xc;
      if ((!bVar9) && (bVar9)) {
        lVar7 = func_0x000d89fb();
        *piVar8 = *piVar8 + -1;
        *(char *)(lVar7 + 9) = *(char *)(lVar7 + 9) + (char)puStack32;
        pbVar2 = (byte *)(lVar7 + -0x77);
        *pbVar2 = *pbVar2 >> 1 | *pbVar2 << 7;
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      func_00101189(0xc,CONCAT44(iStack12,local_10),0);
      cVar3 = (char)puStack32;
      uStack240 = (ulong)local_11 | 0x7ffc9286a800;
      lStack136 = lStack136 + 8;
      uVar10 = lStack136 == 0;
      puStack32 = auStack264;
      if ((!(bool)uVar10) && ((bool)uVar10)) {
        pcVar5 = (char *)func_0x0dd7db94();
        *pcVar5 = *pcVar5 + (char)pcVar5;
        pcVar1 = pcVar5 + -0x75;
        *pcVar1 = *pcVar1 + cVar3;
        uVar10 = *pcVar1 == '\0';
        if (!(bool)uVar10) {
          uVar10 = ((uint)pcVar5 | 0x48000000) == 0;
        }
      }
      if (((bool)uVar10) || (!(bool)uVar10)) {
        cVar3 = (char)puStack32;
      }
      func_0xffffffffe85d9fab();
      func_00101189();
    }
    if ((!(bool)uVar10) && ((bool)uVar10)) {
      puVar6 = (undefined4 *)func_0x00d2dbc4(7,CONCAT44(iStack12,local_10));
      *(char *)puVar6 = *(char *)puVar6 + (char)puVar6;
      *(char *)((long)puVar6 + -0x39) = *(char *)((long)puVar6 + -0x39) + cVar3;
      *puVar6 = *puVar6;
      *(char *)puVar6 = *(char *)puVar6 + (char)puVar6;
    }
    func_00101189();
  } while( true );
}

```

The interesting part is this:

```

  local_10 = fork();
  bVar9 = local_10 == 0;
  if (bVar9) {
    if ((!bVar9) && (bVar9)) {
      pcVar5 = (char *)func_0x00d7da2c();
      cVar3 = (char)pcVar5;
      *pcVar5 = *pcVar5 + cVar3;
      pcVar1 = pcVar5 + -0x75;
      *pcVar1 = *pcVar1 + param_4;
      bVar9 = *pcVar1 == '\0';
      if (!bVar9) {
        *pcVar5 = *pcVar5 + cVar3;
        *pcVar5 = *pcVar5 + cVar3;
        bVar9 = *pcVar5 == '\0';
      }
    }
    if ((!bVar9) && (bVar9)) {
      puVar6 = (undefined4 *)func_0x00d2da3c();
      *(char *)puVar6 = *(char *)puVar6 + (char)puVar6;
      *(char *)((long)puVar6 + -0x39) = *(char *)((long)puVar6 + -0x39) + param_4;
      *puVar6 = *puVar6;
      *(char *)puVar6 = *(char *)puVar6 + (char)puVar6;
    }
    func_00101189();
    iVar4 = check(param_2[1]);
    if (iVar4 == 0) {
      puts("yes");
    }
    else {
      puts("no");
    }

```

now, thankfully the author included debug information so we can see that there is a check function, which checks our flag if it is correct.

Here is the decompilation of that:

```
undefined4 check(char *param_1)

{
  size_t sVar1;
  byte local_1d;
  undefined4 local_1c;
  
  sVar1 = strlen(param_1);
  local_1c = 0;
  local_1d = 0;
  while( true ) {
    if (0x23 < local_1d) {
      return local_1c;
    }
    if ((int)sVar1 < (int)(uint)local_1d) break;
    if ((char)(KEY[(int)(uint)local_1d] ^ param_1[local_1d]) != flag[(int)(uint)local_1d]) {
      local_1c = 1;
    }
    local_1d = local_1d + 1;
  }
  return 1;
}

```

ok, so local_1d is an iterator which is an index into our flag function.

This here: `(char)(KEY[(int)(uint)local_1d] ^ param_1[local_1d])` we xor our input with the stuff at KEY and then compare that against the flag.

Because `a XOR b XOR b == a`, then to get the correct input which we need to feed the program, we need to xor the flag with the KEY to get the correct input to the program.

I could do it manually, but I am going to actually just use python. I am just going to copy the KEY from the executable and the flag and then xor.

To copy the data, just highlight by painting over it and then "Copy Special->Byte string (No spaces)" and tada!

Then copy the FLAG too.

Here is a script:

```

# 7b3d144301435e2f276a474a1b1053f6acbfbc93b6dedeceb4b3c9fc9bc7c1102e4e2a39
KEY = 0x7b3d144301435e2f276a474a1b1053f6acbfbc93b6dedeceb4b3c9fc9bc7c1102e4e2a39
FLAG = 0x0c5c60206963640f4f1e333a682a7cd9d5d0c9e7c3f0bcab9bd7988bafb0f84749164968


print("Result: "+str(hex(KEY ^ FLAG)))


```

and tada:

```
Result: 0x7761746368203a2068747470733a2f2f796f7574752e62652f6451773477395767586351
```

then convert to ascii and the result is this: `watch : https://youtu.be/dQw4w9WgXcQ` I am not going to watch that. I recognize that url!

Passing this to the program actually doesn't give the `yes` answer which we want. Let's break out gdb.

If I set the follow mode to follow forks, then there is a sigsegv on the check function. This is because there is this:

```
                             LAB_00101206                                    XREF[1]:     001011fd(j)  
        00101206 0f b6 45 eb     MOVZX      EAX,byte ptr [RBP + local_1d]
        0010120a 48 98           CDQE
        0010120c 48 8d 15        LEA        RDX,[KEY]                                        = 
                 8d 2e 00 00
        00101213 0f b6 04 10     MOVZX      EAX,byte ptr [RAX + RDX*0x1]=>KEY                = 
        00101217 0f b6 c0        MOVZX      EAX,AL
        0010121a 41 89 c4        MOV        R12D,EAX
        0010121d 4c 8b 1c        MOV        R11,qword ptr [DAT_00000000]
                 25 00 00 
                 00 00

```

Block which actually doesn't appear in the decompilation anywhere.

So the guy actually has some anti debugging stuff going on.

## Reading some other solution.

Ok, so cnathansmith had a good writeup of this: https://crackmes.one/user/cnathansmith reversing challenge.

In the main function there was a lot of fork stuff going on. Then there is also a call to ptrace. Now, the check function is called as a subprocess.

Here is a script to generate the actual key which we are comparing against:

```
#!/bin/sh

strace -e 'trace=ptrace' ./nano 00000000001111111111222222222212345 2>&1 | grep PTRACE_SETREGS | tee key.trace
cut -d ',' -f 6 key.trace | tee field.txt

sed 's/^.*\(.\{2\}\)/\1/' field.txt | sed '{:q;N;s/\n//g;t q}' | sed 's/^//'


```

then pass the output of that to this program as KEY:

```
KEY = 0x3c242c141c040c747c646c545c444cb4bca4ac949c848cf4fce4ecd4dcc4cc353d252d15

FLAG = 0x0c5c60206963640f4f1e333a682a7cd9d5d0c9e7c3f0bcab9bd7988bafb0f84749164968


print("Result: "+str(hex(KEY ^ FLAG)))
```

and then pass the output to an hex to ascii converter and tada: `0xL4ugh{3z_n4n0mites_t0_g3t_st4rt3d}` we found the flag!!

Thank you for reading!
































