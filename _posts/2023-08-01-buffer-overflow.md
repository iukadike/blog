---
layout: post
title: Buffer Overflow - Part 1
excerpt:
categories: [assembly, shellcode]
---

In this post, I aim to document my findings and observations while performing a SEED Lab.


A shellcode is a piece of code that is used to spawn a command shell or execute specific commands. It is usually written in assembly (a low-level programming language that is specific to a particular computer architecture or processor). Because computers can either be 32-bit or 64-bit, shellcodes will have to be written for specific architectures, however, 64bit computers can always run 32-bit shellcodes.


Given an assembly code `test.s`, such code can be compiled using nasm 

- on linux:

  - `nasm -f elf32 test.s -o test.o` (for 32-bit)
 
  - `ld -m elf_i386 test.o -o test` (for 32-bit)
 
  - `nasm -f elf32 test.s -o test.o` (for 64-bit)
 
  - `ld -m elf_x86_64 test.o -o test` (for 64-bit)

- on windows:

  - `nasm -f win32 test.s -o test.o` (for 32-bit)
 
  - `nasm -f win64 test.s -o test.o` (for 64-bit)
 
  - `gcc test.obj -o test.exe`


In a buffer overflow attack, we need to make use of the machine code, not the assembly code or executable as we need to include the shellcode in our attacking
code. Thus we need to extract the machine code from the executable file or the object file. One way is to use the objdump command.

- `objdump -Mintel --disassemble test.o`

To make it easy to copy the machine code, we can perform further processing on the output.

- `objdump -Mintel --disassemble test.o | cut -f2 | sed 's/ //g' | tr -d '\n'`


### Using the shellcode in attacking code.

In many cases of buffer-overflow, the vulnerability is caused by the strcpy() function. For the strcpy() function, zero is considered as the end of the string. Therefore, if there is a zero in the middle of the shellcode, the strcpy() fuction will end abruptly, causing the attack to fail. It is therefore necessary that there is no zero in the machine code.

There are many techniques that can get rid of zeros from the shellcode:

- xoring the 32-bit registers and pushing it to the stack

  ```
  xor eax eax
  push eax
  ```

- assigning an 8-bit number to one of the 8-bits registers

  ```
  xor eax eax
  mov al, 0x99
  push eax
  ```

- using bit-shift to replace filler characters i.e. to turn "xyz#" into "xyz\0"

  ```
  ;for computers that are little endian i.e. like reading from right to left
  mov eax "xyz#"
  shl eax, 8
  shr eax, 8
  push eax

  ;for computers that are big endian i.e. like reading from left to right
  mov eax "xyz#"
  shr eax, 8
  shl eax, 8
  push eax
  ```

####  Providing Arguments for System Calls

Linux provides the programmer with system calls that can be easily executed from assembly. These system calls are triggered by using interrupts. `int 0x80` is used to tell the linux kernel to use the EAX, EBX, ECX, and EDX registers to call a function.

When making a system call the 32-bit registers are interpreted as follows:
EAX: this is used to store the function to be called
EBX: this is used to store the first argument to the function
ECX: this is used to store the second argument to the function
EDX: this is used to store the third argument to the function

So in the case of execve we have the function definition as

```
execve(const char *pathname, char *const _Nullable argv[],
                  char *const _Nullable envp[])
```

This means EAX would store the execve function itself (execve has a system call number of 11), EBX would store the pathname (which in this case is /bin/sh), ECX would store argv[] (which includes the pathname, the arguments, and a null terminator), and EDX would store envp[] (which is the environment variables).




## include book code

## include my solution

