---
layout: post
title: Buffer Overflow
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


In a buffer overflow attack, we need to make use of the machine code, not the assembly code or executable as need to include the shellcode in our attacking
code. Thus we need to extract the machine code from the executable file or the object file. One way is to use the objdump command.

- `objdump -Mintel --disassemble test.o`



Using the shellcode in attacking code. In actual attacks, we need to include the shellcode in our attacking
code, such as a Python or C program. We usually store the machine code in an array, but converting the
machine code printed above to the array assignment in Python and C programs is quite tedious if done
manually, especially if we need to perform this process many times in the lab. We wrote the following
Python code to help this process. Just copy whatever you get from the xxd command (only the shellcode
part) and paste it to the following code, between the lines marked by """. The code can be downloaded
from the lab’s website.



