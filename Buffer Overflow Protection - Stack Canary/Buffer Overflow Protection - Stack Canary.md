# Buffer Overflow Protection - Stack Canary

Stack canaries or security cookies are randomly assigned or tell-tale parts added to binary. It aims to protect from changing/manipulating critical stack values like “Return Address Pointer”.

![Untitled](assets/canaries_png_by_dalidas_art_db041pb-250t.png)

One way to prevent the stack-based buffer overflow above from being successful, is introducing a stack canary just before the SFP and the RP. This token value will be added by the compiler and serve as a warning that SFP and RET may be written.

![Untitled](assets/Untitled.png)

If there is a stack-base buffer overflow happens, buffer iniflates and write the remaining values over the other stack elements in order like this: Buffer → Canary → SFP → RET. Here we will assume that we  are attacking a program which have a stack with stack canary like this:

![Untitled](assets/Untitled%201.png)

There is a vulnerability gives us advantage to overflow the buffer and overwrite the return address. We think we can simply write our code, find the buffer size, write the exploit then done. We try it with our exploit but program gives us an error “**stack smashing detected**”.

![Untitled](assets/Untitled%202.png)

Because we overwrite “Canary” with bunch of “A”s. Program checks “Canary” before “Return Pointer” and if “Canary” is changed program knows that buffer overflow happened and have to abort the process to protect program.

Check GDB output given below. We wrote our exploit and execute with our exploit.

![Untitled](assets/Untitled%203.png)

First 100 byte of this program is **buffer** part of stack which is filled by “A” (hex: 41), next 4 byte is **Canary** which is filled with “C” (hex:43), next 12 byte is **SFP** which is filled with “D” (hex:44) and next 4 byte is **Return Pointer** which is filled with “B” (hex: 42). We changed our **Canary** value and when program checks canary value before jump, program will be aborted. Because our compiler added **Canary check** before  **Return Pointer** **like this:**

![Untitled](assets/Untitled%204.png)

If Canary value changed program calls __stack_chk_fail; if Canary value is same program continues.

# How does stackguard actually work

Compilers implement this feature by selecting appropriate functions, storing the stack canary during the function prologue, checking the value in the epilogue, and invoking a failure handler if it was changed. For example consider the following code:

```
void function1 (const char* str){
        char buffer[16];
        strcpy(buffer, str);
        }
```

StackGuard automatically converts this code to:

```
extern uintptr_t __stack_chk_guard;
noreturn void __stack_chk_fail(void);
void function1(const char* str){
        uintptr_t canary = __stack_chk_guard;
        char buffer[16];
        strcpy(buffer, str);
        if ( (canary = canary ^ __stack_chk_guard) != 0 )
                __stack_chk_fail();}
```

# Stack canary bypasses

There are multiple ways to bypass stack canaries. If we want to bypass stack canaries, we have to know its value so somehow we have to leak stack canary value. Format string vulnerabilities are excellent for this purpose. This can work against all types of canaries. And also we can bruteforce the values of stack, this is trying every single hex value for each byte of canary.

**Format string vulnerability:** Program takes input and directly, without controlling print it back. Here is programmer doesn’t specify format specifier we can provide our own format specifier to leak values from the stack.

When we give input like this: “%p%p%p%p%p%p%p%p%p%p” we can find exact order of canary value. With this input we say “Hey, can you give me your stack values, please?”, because format string vulnerability gives us this advantage. As you can see in given example, attacker found canary value at 55. location and prints it with ”%55$p”.

![Untitled](assets/Untitled%205.png)

Bruteforce: The canary is determined when the program starts up for the first time which means that if the program forks, it keeps the same stack cookie in the child process. This means that if the input that can overwrite the canary is sent to the child, we can use whether it crashes as an oracle and brute-force 1 byte at a time!

This method can be used on fork-and-accept servers where connections are spun off to child processes, but only under certain conditions such as when the input accepted by the program does not append a NULL byte (**read** or **recv**).

> Buffer (N Bytes)               ?? ?? ?? ?? ?? ?? ?? ??               RBP               RIP
> 

Fill the buffer N Bytes + 0x00 results in no crash

> Buffer (N Bytes)               00 ?? ?? ?? ?? ?? ?? ??               RBP               RIP
> 

Fill the buffer N Bytes + 0x00 + 0x00 results in a crash

N Bytes + 0x00 + 0x01 results in a crash

N Bytes + 0x00 + 0x02 results in a crash

...

N Bytes + 0x00 + 0x51 results in no crash

> Buffer (N Bytes)               00 51 ?? ?? ?? ?? ?? ??               RBP               RIP
> 

Repeat this bruteforcing process for 6 more bytes...

> Buffer (N Bytes)               00 51 FE 0A 31 D2 7B 3C          RBP               RIP
> 

Now that we have the stack canary value.

Resources:

[https://www.sans.org/blog/stack-canaries-gingerly-sidestepping-the-cage/](https://www.sans.org/blog/stack-canaries-gingerly-sidestepping-the-cage/)

[https://ctf101.org/binary-exploitation/stack-canaries/](https://ctf101.org/binary-exploitation/stack-canaries/)

[https://www.redhat.com/en/blog/security-technologies-stack-smashing-protection-stackguard](https://www.redhat.com/en/blog/security-technologies-stack-smashing-protection-stackguard)