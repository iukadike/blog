---
layout: post
title: Pseudo Random Number Generation
excerpt: A pseudo-random number is a number that appears to be random but is generated using algorithms. These algorithms use a starting value called a seed and perform mathematical operations on it to produce a sequence of seemingly random numbers. Pseudo-random number generators (PRNGs) are widely used in computer science and simulations to mimic random behavior. Though efficient, it is important to remember that pseudo-random numbers are predictable because you always get the same value when you use the same seed value and algorithm.
categories: [crypto, prng]
---

A pseudo-random number is a number that appears to be random but is generated using algorithms. These algorithms use a starting value called a seed and perform mathematical operations on it to produce a sequence of seemingly random numbers. Pseudo-random number generators (PRNGs) are widely used in computer science and simulations to mimic random behavior. Though efficient, it is important to remember that pseudo-random numbers are predictable because you always get the same value when you use the same seed value and algorithm.

It's important to note that pseudo-random numbers should not be used for tasks that require true randomness, such as cryptographic purposes, as they can be potentially exploited by attackers who can predict the sequence based on the algorithm and seed used.

<details>
<summary><b>SeedLabs: Pseudo Random Number Generation Lab</b></summary>
<div markdown="1">

- [MD5 Collision Attack Lab](https://seedsecuritylabs.org/Labs_20.04/Files/Crypto_Random_Number/Crypto_Random_Number.pdf)

___
</div></details>


<br>

### Generate Encryption Key in a Wrong Way

To generate good pseudo-random numbers, we need to start with something that is random; otherwise, the outcome will be quite predictable. The below program uses the current time (epoch time) as a seed for the pseudo-random number generator.

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define KEYSIZE 16

void main()
{
    char key[KEYSIZE];
    
    printf("epoch time = %lld\n", (long long) time(NULL));
    //srand (time(NULL));
    
    printf("pseudo-random number = ");
    for (int i = 0; i< KEYSIZE; i++){
        key[i] = rand()%256;
        printf("%.2x", (unsigned char)key[i]);
    }
    printf("\n");
}
```

After compiling the code and running the program, I observed the following:
- Each time I run the program, the seed that is used (epoch time) differs.
- Each time I run the program, the pseudo-random number that is generated is significantly different.

![task-1-a](https://github.com/iukadike/blog/assets/58455326/de7764ae-2f6a-4e65-868e-8a69e39ce20d)

However, when I comment out `srand(time(NULL))`, I observed the following:
- Each time I run the program, the same seed is used because I do not provide a seed via `srand()`. This becomes equivalent to using `srand(0)`
- Each time I run the program, the pseudo-random number that is generated is the same; it never changes.

![task-1-b](https://github.com/iukadike/blog/assets/58455326/0ec035a0-8789-469f-8364-4f6c6fb3bd1c)

After creating and running a number of additional tests, I can conclude that:
- every time rand() is called in a running program/session, it will produce the same output for the same number of iterations.
- to determine the seed that rand() uses when creating pseudo-random numbers, I can make use of srand() to set the seed.
- srand() has to be set exactly once outside of the loop, else it will always keep initializing.
- time() is used as the seed provided to `srand()` because every time the program is run, epoch time will be different. This ensures that the value used during `srand()` initializations is always different.


<br>

### Guessing the Key

__Task Background:__

On April 17, 2018, Alice finished her tax return, and she saved the return (a PDF file) on her disk. To protect the file, she encrypted the PDF file using a key generated from the program in the previous task. She wrote down the key in a notebook, which is securely stored in a safe. A few months later, Bob broke into her computer and got a copy of the encrypted tax return. Since Alice is the CEO of a big company, this file is very valuable.

Bob cannot get the encryption key, but by looking around Alice’s computer, he sees the key-generation program and suspects that Alice’s encryption key may be generated by the program. He also noticed the timestamp of the encrypted file, which is "2018-04-17 23:08:49". He guessed that the key may be generated within a two-hour window before the file was created.

Since the file is a PDF file, which has a header. The beginning part of the header is always the version number. Around the time when the file was created, PDF-1.5 was the most common version, i.e., the header starts with "%PDF-1.5", which is 8 bytes of data. The next 8 bytes of the data are quite easy to predict as well. Therefore, Bob easily got the first 16 bytes of the plaintext. Based on the metadata of the encrypted file, he knows that the file is encrypted using aes-128-cbc. Since AES is a 128-bit cipher, the 16-byte plaintext consists of one block of plaintext, so Bob knows a block of plaintext and its matching ciphertext.

Moreover, Bob also knows the Initial Vector (IV) from the encrypted file (IV is never encrypted). Thus Bob knows the following:

```
Plaintext:  255044462d312e350a25d0d4c5d80a34
Ciphertext: d06bf9d0dab8e8ef880660d2af65aa82
IV:         09080706050403020100A2B2C2D2E2F2
```

The purpose of this task is to help Bob find Alice’s encryption key (by writing a program to try all the possible keys), so I can decrypt the entire document. If the key was generated correctly, this task will not be possible. However, since Alice used time() to seed her random number generator, I should be able to find out her key easily.

Before trying to crack the encryption, Bob needs to get the encryption key. We have access to the key-generation program, and we know Bob suspects that the key was generated between "2018-04-17 21:08:49" and "2018-04-17 23:08:49". 

The first step is to enumerate all the possible encryption keys that could have been generated within that two-hour window. The lower and upper bounds of the seed used will be:
- `$ date -d "2018-04-17 21:08:49" +%s` = 1523995729
- `$ date -d "2018-04-17 21:08:49" +%s` = 1523999329

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define KEYSIZE 16

// initialize functions
void keygen(int epochtime);

// Set the epoch time boundaries
int lowerBound = 1524013729;
int upperBound = 1524020929;

void main()
{
    for (int i = lowerBound; i<= upperBound; i++){
        keygen(i);
        i++;
    }   
}

void keygen(int epochtime)
{
    char key[KEYSIZE];
    srand (epochtime);
    
    for (int i = 0; i< KEYSIZE; i++){
        key[i] = rand()%256;
        printf("%.2x", (unsigned char)key[i]);
    }
    printf("\n");
}
```

After compiling the code, I run it and redirect its output to a text file for later use in another program.

![task-2-a](https://github.com/iukadike/blog/assets/58455326/4f4a7b0e-62cd-4c98-ad97-9e846180dbdb)

The output of the above are possible keys that Alice could have used to encrypt the PDF file. However, to know which one was actually used, I would need to write a program that tries every key generated against the cipher text and compare the decrypted text with the known plain text. Python can be used to achieve this:

```python
#!/usr/bin/env python3

from Crypto.Cipher import AES

# convert the hex to python byte array
plaintext  = bytearray.fromhex("255044462d312e350a25d0d4c5d80a34")
ciphertext = bytearray.fromhex("d06bf9d0dab8e8ef880660d2af65aa82")
iv         = bytearray.fromhex("09080706050403020100A2B2C2D2E2F2")

# Open the possible-keys file for reading
with open("possible_keys.txt", "r") as f:
    keys = f.readlines()

# Iterate over the keys
def main():
    for _ in keys:
        decrypt(ciphertext, _.strip())

# Decrypt the cipher text
def decrypt(ciphertext, key):
    key = bytearray.fromhex(key)
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    plain = cipher.decrypt(ciphertext)
    if plain == plaintext:
        print(f"Encryption Key Found: {key.hex()}")
        

if __name__ == '__main__':
    main()  
```

After running the program I was able to obtain Alice's encryption key.

![task-2-b](https://github.com/iukadike/blog/assets/58455326/27bddc67-e139-4daa-81f7-56e3e142373e)


<br>

### Measure the Entropy of Kernel

Using software alone makes it hard to create random numbers, thus most systems use physical signals to create the randomness. Randomness is measured using entropy, which simply means how many bits of random numbers the system currently has. Linux gains the randomness from:
- void add_keyboard_randomness(unsigned char scancode);
- void add_mouse_randomness(__u32 mouse_data);
- void add_interrupt_randomness(int irq);
- void add_blkdev_randomness(int major);

The below code can find out how much entropy the kernel has at the current moment,

```bash
$ watch -n .1 cat /proc/sys/kernel/random/entropy_avail
```

While the above code is running, I notice the following:
- moving my mouse: this increases the entropy significantly
- clicking my mouse: this increases the entropy slightly
- typing some things with the keyboard: this increases the entropy slightly
- reading a large file: this increases the entropy significantly
- visiting a website: this increases the entropy significantly


<br>

###  Get Pseudo Random Numbers from /dev/random

Linux stores the random data collected from the physical resources in a random pool and then uses two devices to turn the randomness into pseudo-random numbers. One of these two devices is/dev/random.

The /dev/random device is a blocking device. This means that every time a random number is given out by this device, the entropy of the randomness pool will be decreased. When the entropy reaches zero, /dev/random will block until it gains enough randomness.

__Experiment to observe the behavior of the /dev/random device__

- use the cat command to keep reading pseudo-random numbers from /dev/random and pipe the output to hexdump for nice printing.
  ```
  $ cat /dev/random | hexdump
  ```

- monitor how much entropy the kernel has at the current moment.
  ```bash
  $ watch -n .1 cat /proc/sys/kernel/random/entropy_avail
  ```

After running the above command, I observed the following:
- if there is already data in the randomness pool, /dev/random uses this data to generate pseudo-random numbers until there is no more data in the randomness pool
- if I do not move my mouse or type anything, the entropy level increases at a steady rate of one per second. When it gets to 64, /dev/random generates pseudo-random numbers from the randomness pool.
- when I randomly move my mouse, the entropy level increases significantly. When it gets to 64, /dev/random generates pseudo-random numbers from the randomness pool.

If a server uses /dev/random to generate the random session key with a client. An attacker would keep querying the server to establish connections till the server runs out of entropy to use with the /dev/random device.


<br>

### Get Random Numbers from /dev/urandom

Linux stores the random data collected from the physical resources in a random pool and then uses two devices to turn the randomness into pseudo-random numbers. One of these two devices is/dev/urandom.

The /dev/urandom device is a non-blocking device. This means that when the entropy is not sufficient, unlike /dev/random that pauses, /dev/urandom keeps generating new numbers. The data in the pool can be thought as the seed used to generate pseudo-random numbers.

__Experiment to observe the behavior of the /dev/random device__

- use the cat command to keep reading pseudo-random numbers from /dev/random and pipe the output to hexdump for nice printing.
  ```
  $ cat /dev/urandom | hexdump
  ```

- monitor how much entropy the kernel has at the current moment.
  ```bash
  $ watch -n .1 cat /proc/sys/kernel/random/entropy_avail
  ```

After running the above command, I observed the following:
- /dev/urandom generates pseudo-random numbers at a significantly fast rate.
- the entropy level has no effect on the rate at which pseudo-random numbers are generated
- the entropy level does not decrease with each new pseudo-random number generated.

__Test to measure the quality of the random number generated by /dev/random__

- we use `ent` to measure the quality of the random number generated.
- first generate 1 MB of pseudo-random number from /dev/urandom and save them in a file.
  ```bash
  $ head -c 1M /dev/urandom > output.bin
  ```
  
- then run ent on the file
  ```bash
  $ ent output.bin
  ```
  
The following can be observed from the outcome of running the above command.

![task-5-a](https://github.com/iukadike/blog/assets/58455326/8dd08b36-5f82-4b9c-92ce-56a97c1b885e)

- __Entropy__: This is the information density of the contents of the file, expressed as a number of bits per character. From the screenshot above, it is observed that the file is extremely dense in information. Compressing the file would not reduce the file size. — essentially random
- __chi-square distribution__: this is  the  most commonly used test for the randomness of data, and is extremely sensitive to errors in pseudorandom sequence generators. The percentage is interpreted as the degree to which the sequence tested is suspected of being non-random.
  - __n% > 99%__:       the sequence is almost certainly not random.
  - __n% < 1%__:        the sequence is almost certainly not random.
  - __95% < n% < 99%__: the sequence is suspect.
  - __1% < n% < 5%__:   the sequence is suspect.
  - __90% < n% < 95%__: the sequence is "almost suspect".
  - __5% < n% < 10%__:  the sequence is "almost suspect".

  From the screenshot above, it is observed that the file has a chi-square distribution of 12.68%. — essentially random

- __Arithmetic mean__: If the data is close to random, this value should be about 127.5. From the screenshot above, it is observed that the file has an arithmetic mean of  127.1861. — essentially random
- __Monte Carlo Value for Pi__: This measures how close the value calculated using the sequence of bytes from the file approaches the correct value of Pi. The closer the value calculated to the actual value of Pi, the more random the data is. From the screenshot above, it is observed that the file has an error of 0.09%. — essentially random
- __Serial Correlation Coefficient__: This quantity measures the extent to which each byte in the file depends upon the previous byte. For random sequences, this value (-1 <= n <= 1) will be close to zero. From the screenshot above, it is observed that the file has a serial correlation coefficient of 0.001820%. — essentially random

From the above analysis and observations, I can conclude that the quality of the random numbers generated is good.


Due to the blocking behavior of /dev/random, it can lead to denial of service attacks. Thus, it is recommended to use /dev/urandom to get random numbers. Doing so in a  program is as simple as reading directly from the /dev/urandom device file.

The following code generates a 256-bit encryption key:

```c
#include <stdio.h>
#include <stdlib.h>

#define KEYSIZE 32  // 256 bits

void enckey(unsigned char* key);

int main()
{
    unsigned char* key = (unsigned char*) malloc(sizeof(unsigned char)*KEYSIZE);
    FILE* random = fopen("/dev/urandom", "r");
    fread(key, sizeof(unsigned char)*KEYSIZE, 1, random);
    fclose(random);
    enckey(key);
}

void enckey(unsigned char* key)
{
    for (int i = 0; i< KEYSIZE; i++){
        printf("%.2x", (unsigned char)key[i]);
    }
    printf("\n");
}
```

When the code is compiled and run, the screenshot below shows the output.

![task-5-b](https://github.com/iukadike/blog/assets/58455326/ab2a3007-a984-49b2-98d8-f6a1eba546f9)


<br>

Thanks for reading...

<details>
<summary><b>References</b></summary>
<div markdown="1">

[ent man page](https://manpages.ubuntu.com/manpages/trusty/man1/ent.1.html)
</div></details>
