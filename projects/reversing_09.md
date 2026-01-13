
# Reversing 09

Ok, so I am going to continue on my reverse engineering journey. I found this crackme: https://crackmes.one/crackme/657630dd35240bf986f1004f which seems fine.

Here is the ghidra decompilation of the main function:

{% raw %}
```
undefined8 UndefinedFunction_00401090(void)

{
  int iVar1;
  char acStack84 [30];
  char acStack54 [38];
  
  puts("\n *** enjoy the crackme ***\n");
  FUN_00401294(acStack84,0x76,0x5c,0x4a,0x40,0x50,0x50,0x4c,0x12,0x65,0x52,0x4b,0x41,0x42,0x5c,0x4a,
               0x56,0x14);
  printf("Enter the password: ");
  fgets(acStack54,0x1e,stdin);
  FUN_00401325(acStack54);
  FUN_0040124a(acStack84,acStack54);
  iVar1 = FUN_00401274(acStack84);
  if (iVar1 != 0x666) {
    wrongpassword();
  }
  puts(acStack84);
  return 0;
}
```
{% endraw %}

This line here: `FUN_00401294(acStack84,0x76,0x5c,0x4a,0x40,0x50,0x50,0x4c,0x12,0x65,0x52,0x4b,0x41,0x42,0x5c,0x4a,0x56,0x14);` basically sets up the acStack84 variable which we compare against.

Here is the source code:

{% raw %}
```
/* WARNING: Could not reconcile some variable overlaps */

void FUN_00401294(char *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6)

{
  ulong uVar1;
  char *pcVar2;
  uint local_60;
  char *local_58;
  char local_48 [8];
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  
  local_58 = &stack0x00000008;
  local_60 = 0x10;
  local_40._0_1_ = (char)param_2;
  local_40 = param_2;
  local_38 = param_3;
  local_30 = param_4;
  local_28 = param_5;
  local_20 = param_6;
  while ((char)local_40 != '\0') {
    sprintf(param_1,"%s%c",param_1);
    if (local_60 < 0x30) {
      uVar1 = (ulong)local_60;
      local_60 = local_60 + 8;
      pcVar2 = local_48 + uVar1;
    }
    else {
      pcVar2 = local_58;
      local_58 = local_58 + 8;
    }
    local_40._0_1_ = *pcVar2;
  }
  return;
}

```
{% endraw %}

Notice that this function is completely independent of our input. Therefore we can just drop into a debugger and then get the output value ourselves.

Here is some of the disassembly in gdb of the main function:

{% raw %}
```
   0x4010a2:	lea    rbx,[rsp+0x4]
   0x4010a7:	push   0x14
   0x4010a9:	xor    eax,eax
   0x4010ab:	push   0x56
   0x4010ad:	mov    r9d,0x50
   0x4010b3:	mov    ecx,0x4a
   0x4010b8:	mov    rdi,rbx
   0x4010bb:	push   0x4a
   0x4010bd:	mov    r8d,0x40
   0x4010c3:	mov    edx,0x5c
   0x4010c8:	mov    esi,0x76
   0x4010cd:	push   0x5c
   0x4010cf:	push   0x42
   0x4010d1:	push   0x41
   0x4010d3:	push   0x4b
   0x4010d5:	push   0x52
   0x4010d7:	push   0x65
   0x4010d9:	push   0x12
   0x4010db:	push   0x4c
   0x4010dd:	push   0x50
   0x4010df:	call   0x401294
   0x4010e4:	add    rsp,0x60
   0x4010e8:	lea    rdi,[rip+0xf44]        # 0x402033
   0x4010ef:	xor    eax,eax
   0x4010f1:	call   0x401050 <printf@plt>
   0x4010f6:	lea    rbp,[rsp+0x22]
   0x4010fb:	mov    esi,0x1e
   0x401100:	mov    rdx,QWORD PTR [rip+0x2f29]        # 0x404030
   0x401107:	mov    rdi,rbp
   0x40110a:	call   0x401060 <fgets@plt>
   0x40110f:	mov    rdi,rbp
   0x401112:	call   0x401325
   0x401117:	mov    rdi,rbx
   0x40111a:	mov    rsi,rbp
   0x40111d:	call   0x40124a
   0x401122:	mov    rdi,rbx
   0x401125:	call   0x401274
   0x40112a:	cmp    eax,0x666
   0x40112f:	je     0x401136
   0x401131:	call   0x401236
   0x401136:	mov    rdi,rbx
   0x401139:	call   0x401030 <puts@plt>
   0x40113e:	add    rsp,0x48
   0x401142:	xor    eax,eax
   0x401144:	pop    rbx
   0x401145:	pop    rbp
   0x401146:	ret    

```
{% endraw %}

We call the scrambling function here: `0x4010df:	call   0x401294`

After the call, the result of the "scrambling" is pointed to by the rbx register.

Let's set a breakpoint to after the returning from the scrambling function:

{% raw %}
```
(gdb) x/10wx $rbx
0x7fffffffda14:	0x404a5c76	0x124c5050	0x414b5265	0x564a5c42
```
{% endraw %}

and this is actually completely independent of our input, therefore we can just write this down somewhere.

So `acStack84 == 0x124c5050404a5c76	0x564a5c42414b5265  and 0x14`

Here is the corresponding python code:

{% raw %}
```

def as_hex(list_of_ints: list) -> None:
	for integer in list_of_ints:
		res = hex(integer)[2:]
		if len(res) == 1: # Special case for stuff from zero to 0xf
			res = "0"+res
		print(res, end="")
	print("\n", end="")
	return


as_hex([0xff, 0xfe])

acStack84 = bytes.fromhex("124c5050404a5c76")
acStack84 = list(acStack84)

acStack84 = list(reversed(acStack84)) # This is because of endiannesss

other_part = bytes.fromhex("14564a5c42414b5265")
other_part = list(other_part)

other_part = list(reversed(other_part))

acStack84 = acStack84 + other_part

print(acStack84)
as_hex(acStack84)

```
{% endraw %}

therefore `765c4a4050504c1265524b41425c4a5614` is the scrambled stuff.

Then this line: `FUN_00401325(acStack54);` gets rid of the newline character and replaces it with a null byte.

## Figuring out what FUN_0040124a(acStack84,acStack54) does

The `FUN_0040124a(acStack84,acStack54);` is basically the checking function I assume.

Here:

{% raw %}
```

undefined8 FUN_0040124a(char *param_1,long param_2,undefined8 param_3)

{
  size_t sVar1;
  long lVar2;
  
  sVar1 = strlen(param_1);
  lVar2 = 0;
  while ((int)(uint)lVar2 < (int)sVar1) {
    param_1[lVar2] = param_1[lVar2] ^ *(byte *)(param_2 + (ulong)((uint)lVar2 & 3));
    lVar2 = lVar2 + 1;
  }
  return param_3;
}


```
{% endraw %}

remember that param_1 is  acStack84 which is 765c4a4050504c1265524b41425c4a5614 .

This line here: `param_1[lVar2] = param_1[lVar2] ^ *(byte *)(param_2 + (ulong)((uint)lVar2 & 3));`

We actually cycle over the first four bytes of our input, because here: `lVar2 & 3` we get an index into our input string into the range 0-3 inclusive, therefore the only bytes that matter in our input are the four first bytes.

So basically we cyclically xor our four byte input with the scrambled stuff to get the result.

Then, we pass the result of this cyclic xor operation to this function:

{% raw %}
```

int FUN_00401274(char *param_1)

{
  char *pcVar1;
  int iVar2;
  size_t sVar3;
  long lVar4;
  
  sVar3 = strlen(param_1);
  lVar4 = 0;
  iVar2 = 0;
  while ((int)lVar4 < (int)sVar3) {
    pcVar1 = param_1 + lVar4;
    lVar4 = lVar4 + 1;
    iVar2 = iVar2 + *pcVar1;
  }
  return iVar2;
}

```
{% endraw %}

This function basically just sums up the bytes of the result of the cyclic xor. and then this value should be 0x666

Because we loop every four bytes, we can create groups:

{% raw %}
```
def generate_groups() -> list:
	byte_stuff = bytes.fromhex("765c4a4050504c1265524b41425c4a5614")
	groups = [[],[],[],[]]
	for i, x in enumerate(byte_stuff):
		groups[i&3].append(x)
	return groups
```
{% endraw %}

`groups[0]` is the numbers which are xored with the first input byte, then `groups[1]` is the bytes which are xored with the second byte and so on.

## Bruteforcing the solution.

Ok, so because the correct flag is assumedly ascii, we can just bruteforce the answer. (I think).

Here is my bruteforcing algorithm:

{% raw %}
```

alphabet = "0123456789"

count = 1000

while True:

	count_as_string = str(count)
	print("count_as_string == "+str(count_as_string))
	# Get random value for a, b, c and then check if they are less than 0x666
	a = ord(count_as_string[0])
	b = ord(count_as_string[1])
	c = ord(count_as_string[2])
	d = ord(count_as_string[3])
	#print("a == "+str(a))
	#print("b == "+str(b))
	#print("c == "+str(c))
	# Now go over the groups and then subtract them from the 0x666 value.
	print("group_bytes == "+str(group_bytes))
	a_sum = sum([a ^ x for x in group_bytes[0]])
	b_sum = sum([b ^ x for x in group_bytes[1]])
	c_sum = sum([c ^ x for x in group_bytes[2]])
	d_sum = sum([d ^ x for x in group_bytes[2]])
	total_sum = a_sum + b_sum + c_sum + d_sum
	count += 1
	if total_sum == 0x666:
		print("ooof")
		break

	what_should_d_result_to = 0x666 - total_sum
	if what_should_d_result_to < 0:
		continue
	# Now try to figure out d

	for char in alphabet:
		d = ord(char)
		# Now see if we satisfy the equation.
		d_sum = sum([d ^ x for x in group_bytes[2]])

		print("Difference: "+str(hex(abs(d_sum - what_should_d_result_to))))

		if d_sum == what_should_d_result_to:
			print("Success!")
			print("Here is the solution: "+str(chr(a)+chr(b)+chr(c)+chr(d)))
			break

	count += 1 # Move on to the next possible solution


```
{% endraw %}

but it doesn't work. I don't really understand why.

That is because I use the wrong index here: `d_sum = sum([d ^ x for x in group_bytes[2]])` that two should be a three. After changing it now it works.

Let's print the solution too:

{% raw %}
```
	if total_sum == 0x666:
		print("ooof")
		print(chr(a)+chr(b)+chr(c)+chr(d))
		break
```
{% endraw %}

Tada:

{% raw %}
```
ooof
1180
```
{% endraw %}

Now, it is the moment of truth... is this the solution??? Yes it is!

Thank you for reading this writeup!












