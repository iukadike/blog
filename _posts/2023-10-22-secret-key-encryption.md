---
layout: post
title: Secret-Key Encryption
excerpt: Encryption is the process of converting plain text or data into a coded form that is unreadable to unauthorized users. It is used to protect sensitive information during transmission or storage. There are two types of encryption: secret-key encryption, which uses the same key for encryption and decryption, and public-key encryption, which uses different keys for encryption and decryption.
categories: [crypto, des, aes]
---

Encryption is the process of converting plain text or data into a coded form that is unreadable to unauthorized users. It is used to protect sensitive information during transmission or storage.

There are two types of encryption.
- Secret-key encryption: this uses the same key for encryption and decryption, so it is called symmetric encryption.
- Public-key encryption: this uses different keys for encryption and decryption, so it is called asymmetric encryption.

Examples of secret-key encryption include:
- Advanced Encryption Standard (AES)
- Data Encryption Standard (DES)
- Triple Data Encryption Standard (3DES)
- RC4
- Blowfish
- Twofish

Examples of public-key encryption include:
- RSA (Rivest-Shamir-Adleman)
- Diffie-Hellman Key Exchange
- ElGamal
- DSA (Digital Signature Algorithm)
- ECC (Elliptic Curve Cryptography)
- PGP (Pretty Good Privacy)
- GPG (GNU Privacy Guard)
- PkiRSA (Public Key Infrastructure RSA)
- X.509

<details>
<summary><b>SeedLabs: Secret-Key Encryption Lab</b></summary>
<div markdown="1">

- [Secret-Key Encryption](https://seedsecuritylabs.org/Labs_20.04/Files/Crypto_Encryption/Crypto_Encryption.pdf)

___
</div></details>


<br>

###  Frequency Analysis

In classical cryptography, there are primarily two types of ciphers:
- transposition ciphers: letters are rearranged, but the identity of the letters is not changed.
- substitution ciphers: letters are changed, but their positions do not change.

There are two typical substitution ciphers: monoalphabetic and polyalphabetic. A monoalphabetic cipher uses a fixed substitution over the entire message, whereas a polyalphabetic cipher uses a number of substitutions at different positions in the message.

Since the monoalphabetic substitution cipher uses a fixed mapping table, the same letter in the plaintext is always mapped to a fixed letter in the ciphertext. This means that if a letter appears 50 times in the plaintext, the letter it maps to will appear 50 times in the ciphertext. This opens a door for frequency analysis.

Frequency analysis is based on the observation that certain letters or characters occur more frequently than others in a given language. If the size of a text is large enough, the frequencies of the letters and some of the combinations follow a characteristic distribution that can be obtained from the sample texts of that language.

In this task, I am given a cipher text that is encrypted using a monoalphabetic cipher and required to find the original text using frequency analysis. The original text is an English article.

```
ytn xqavhq yzhu  xu qzupvd ltmat qnncq vgxzy hmrty vbynh ytmq ixur qyhvurn
vlvhpq yhme ytn gvrrnh bnniq imsn v uxuvrnuvhmvu yxx

ytn vlvhpq hvan lvq gxxsnupnp gd ytn pncmqn xb tvhfnd lnmuqynmu vy myq xzyqny
vup ytn veevhnuy mceixqmxu xb tmq bmic axcevud vy ytn nup vup my lvq qtvenp gd
ytn ncnhrnuan xb cnyxx ymcnq ze givasrxlu eximymaq vhcavupd vaymfmqc vup
v uvymxuvi axufnhqvymxu vq ghmnb vup cvp vq v bnfnh phnvc vgxzy ltnytnh ytnhn
xzrty yx gn v ehnqmpnuy lmubhnd ytn qnvqxu pmpuy ozqy qnnc nkyhv ixur my lvq
nkyhv ixur gnavzqn ytn xqavhq lnhn cxfnp yx ytn bmhqy lnnsnup mu cvhat yx
vfxmp axubimaymur lmyt ytn aixqmur anhncxud xb ytn lmuynh xidcemaq ytvusq
ednxuratvur

xun gmr jznqymxu qzhhxzupmur ytmq dnvhq vavpncd vlvhpq mq txl xh mb ytn
anhncxud lmii vpphnqq cnyxx nqenamviid vbynh ytn rxipnu rixgnq ltmat gnavcn
v ozgmivuy axcmurxzy evhyd bxh ymcnq ze ytn cxfncnuy qenvhtnvpnp gd 
exlnhbzi txiidlxxp lxcnu ltx tnienp hvmqn cmiimxuq xb pxiivhq yx bmrty qnkzvi
tvhvqqcnuy vhxzup ytn axzuyhd

qmruvimur ytnmh qzeexhy rxipnu rixgnq vyynupnnq qlvytnp ytncqnifnq mu givas
qexhynp iveni emuq vup qxzupnp xbb vgxzy qnkmqy exlnh mcgvivuanq bhxc ytn hnp
avheny vup ytn qyvrn xu ytn vmh n lvq aviinp xzy vgxzy evd munjzmyd vbynh
myq bxhcnh vuatxh avyy qvpinh jzmy xuan qtn invhunp ytvy qtn lvq cvsmur bvh
inqq ytvu v cvin axtxqy vup pzhmur ytn anhncxud uvyvimn exhycvu yxxs v gizuy
vup qvymqbdmur pmr vy ytn viicvin hxqynh xb uxcmuvynp pmhnayxhq txl axzip
ytvy gn yxeenp

vq my yzhuq xzy vy invqy mu ynhcq xb ytn xqavhq my ehxgvgid lxuy gn

lxcnu mufxifnp mu ymcnq ze qvmp ytvy viytxzrt ytn rixgnq qmrumbmnp ytn
mumymvymfnq ivzuat ytnd unfnh muynupnp my yx gn ozqy vu vlvhpq qnvqxu
avcevmru xh xun ytvy gnavcn vqqxamvynp xuid lmyt hnpavheny vaymxuq muqynvp
v qexsnqlxcvu qvmp ytn rhxze mq lxhsmur gntmup aixqnp pxxhq vup tvq qmuan
vcvqqnp  cmiimxu bxh myq inrvi pnbnuqn bzup ltmat vbynh ytn rixgnq lvq
bixxpnp lmyt ytxzqvupq xb pxuvymxuq xb  xh inqq bhxc enxein mu qxcn 
axzuyhmnq


ux avii yx lnvh givas rxluq lnuy xzy mu vpfvuan xb ytn xqavhq ytxzrt ytn
cxfncnuy lmii vicxqy anhyvmuid gn hnbnhnuanp gnbxhn vup pzhmur ytn anhncxud 
nqenamviid qmuan fxavi cnyxx qzeexhynhq imsn vqtind ozpp ivzhv pnhu vup
umaxin smpcvu vhn qatnpzinp ehnqnuynhq

vuxytnh bnvyzhn xb ytmq qnvqxu ux xun hnviid suxlq ltx mq rxmur yx lmu gnqy
emayzhn vhrzvgid ytmq tveenuq v ixy xb ytn ymcn muvhrzvgid ytn uvmigmynh
uvhhvymfn xuid qnhfnq ytn vlvhpq tden cvatmun gzy xbynu ytn enxein bxhnavqymur
ytn hvan qxaviinp xqavhxixrmqyq avu cvsn xuid npzavynp rznqqnq

ytn lvd ytn vavpncd yvgzivynq ytn gmr lmuunh pxnquy tnie mu nfnhd xytnh
avynrxhd ytn uxcmunn lmyt ytn cxqy fxynq lmuq gzy mu ytn gnqy emayzhn
avynrxhd fxynhq vhn vqsnp yx imqy ytnmh yxe cxfmnq mu ehnbnhnuymvi xhpnh mb v
cxfmn rnyq cxhn ytvu  enhanuy xb ytn bmhqyeivan fxynq my lmuq ltnu ux
cxfmn cvuvrnq ytvy ytn xun lmyt ytn bnlnqy bmhqyeivan fxynq mq nimcmuvynp vup
myq fxynq vhn hnpmqyhmgzynp yx ytn cxfmnq ytvy rvhunhnp ytn nimcmuvynp gviixyq
qnaxupeivan fxynq vup ytmq axuymuznq zuymi v lmuunh ncnhrnq

my mq vii ynhhmgid axubzqmur gzy veevhnuyid ytn axuqnuqzq bvfxhmyn axcnq xzy
vtnvp mu ytn nup ytmq cnvuq ytvy nupxbqnvqxu vlvhpq atvyynh mufvhmvgid
mufxifnq yxhyzhnp qenazivymxu vgxzy ltmat bmic lxzip cxqy imsnid gn fxynhq
qnaxup xh ytmhp bvfxhmyn vup ytnu njzviid yxhyzhnp axuaizqmxuq vgxzy ltmat
bmic cmrty ehnfvmi

mu  my lvq v yxqqze gnylnnu gxdtxxp vup ytn nfnuyzvi lmuunh gmhpcvu
mu  lmyt ixyq xb nkenhyq gnyymur xu ytn hnfnuvuy xh ytn gmr qtxhy ytn
ehmwn lnuy yx qexyimrty ivqy dnvh unvhid vii ytn bxhnavqynhq pnaivhnp iv
iv ivup ytn ehnqzceymfn lmuunh vup bxh ylx vup v tvib cmuzynq ytnd lnhn
axhhnay gnbxhn vu nufnixen quvbz lvq hnfnvinp vup ytn hmrtybzi lmuunh
cxxuimrty lvq ahxlunp

ytmq dnvh vlvhpq lvyatnhq vhn zunjzviid pmfmpnp gnylnnu ythnn gmiigxvhpq
xzyqmpn nggmur cmqqxzhm ytn bvfxhmyn vup ytn qtven xb lvynh ltmat mq
ytn gvrrnhq ehnpmaymxu lmyt v bnl bxhnavqymur v tvmi cvhd lmu bxh rny xzy

gzy vii xb ytxqn bmicq tvfn tmqyxhmavi xqavhfxymur evyynhuq vrvmuqy ytnc ytn
qtven xb lvynh tvq  uxcmuvymxuq cxhn ytvu vud xytnh bmic vup lvq viqx
uvcnp ytn dnvhq gnqy gd ytn ehxpzanhq vup pmhnayxhq rzmipq dny my lvq uxy
uxcmuvynp bxh v qahnnu vayxhq rzmip vlvhp bxh gnqy nuqncgin vup ux bmic tvq
lxu gnqy emayzhn lmytxzy ehnfmxzqid ivupmur vy invqy ytn vayxhq uxcmuvymxu
qmuan ghvfntnvhy mu  ytmq dnvh ytn gnqy nuqncgin qvr nupnp ze rxmur yx
ythnn gmiigxvhpq ltmat mq qmrumbmavuy gnavzqn vayxhq cvsn ze ytn vavpncdq
ivhrnqy ghvuat ytvy bmic ltmin pmfmqmfn viqx lxu ytn gnqy phvcv rxipnu rixgn
vup ytn gvbyv gzy myq bmiccvsnh cvhymu capxuvrt lvq uxy uxcmuvynp bxh gnqy
pmhnayxh vup vevhy bhxc vhrx cxfmnq ytvy ivup gnqy emayzhn lmytxzy viqx
nvhumur gnqy pmhnayxh uxcmuvymxuq vhn bnl vup bvh gnylnnu
```

Given a section of the English language, E, T, A, and O are the most common, while Z, Q, X, and J are rare. Likewise, TH, ER, ON, and AN are the most common pairs of letters, and SS, EE, TT, and FF are the most common repeats.

Since the ciphertext is in lowercase letters, each plaintext guess would be in uppercase letters to differentiate between the ciphertext and plaintext.

From the frequency analysis performed on the cipher text, I observed the following:
- "n" occurs the most. Given that "E" is the most common letter in the English language, I can infer n --> E
- "yt" occurs the most. Given that "TH" is the most common bigram in the English language, I can infer yt --> TH
- "ytn" occurs the most. Given that "THE" is the most common trigram in the English language, I can infer ytn --> THE
- "y" is the second most common letter in the ciphertext. However, y has been accounted for, y --> T
- "v" is the third most common letter in the ciphertext. Since the two most common letters on English Language, "E" and "T" have been accounted for, I can infer that v --> A

So far, I have the following: "nytv" --> "ETHA". The next step is to change these letters in the ciphertext to their corresponding plaintext equivalent.

```bash
$ tr 'nytv' 'ETHA' < ciphertext.txt > plaintext.txt
$ cat plaintext.txt
```

Using these initial guesses, I can spot patterns that confirm my choices and observe other patterns that suggest further guesses.
- "mT" might be "IT", which would mean m --> I
- "THmq" might be "THIS", which would mean q --> S
- "lmTH" might be "WITH", which would mean l --> w
- "THAu" might be "THAN", which would mean u --> N
- "THhEE" might be "THREE", which would mean h --> R

So far, I have the following: "nytvmqluh" --> "ETHAISWNR". The next step is to change these letters in the ciphertext to their corresponding plaintext equivalent.

```bash
$ tr 'nytvmqluh' 'ETHAISWNR' < ciphertext.txt > plaintext.txt
$ cat plaintext.txt
```

Using these new guesses, I can spot patterns that confirm my choices and observe other patterns that suggest further guesses.
- "WHIaH" might be "WHICH", which would mean a --> C
- "RIrTH" might be "RIGHT", which would mean r --> G
- "AbTER" might be "AFTER", which would mean b --> F
- "AWARpS" might be "AWARDS", which would mean p --> D
- "SHAeEp" might be "SHAPED", which would mean e --> P
- "EkTRA" might be "EXTRA", which would mean k --> X
- "HARASScENT" might be "HARASSMENT", which would mean c --> M
- "ARxzNp" might be "AROUND", which would mean xz --> OU

So far, I have the following: "nytvmqluharbpekcxz" --> "ETHAISWNRCGFDPXMOU". The next step is to change these letters in the ciphertext to their corresponding plaintext equivalent.

```bash
$ tr 'nytvmqluharbpekcxz' 'ETHAISWNRCGFDPXMOU' < ciphertext.txt > plaintext.txt
$ cat plaintext.txt
```

At this point, most of the ciphertext is already decoded, I need to apply one final round of transformation to get the entire plaintext. Using these new guesses, I can spot patterns that confirm my choices and observe other patterns that suggest further guesses.
- "SUNDAd" might be "SUNDAY", which would mean d --> Y
- "AgOUT" might be "ABOUT", which would mean g --> B
- "WHIaH" might be "WHICH", which would mean a --> C
- "FEEiS" might be "FEELS", which would mean i --> L
- "IisE" might be "LIKE", which would mean s --> K
- "ACTIfISM" might be "ACTIVISM", which would mean f --> V
- "jUESTION" might be "QUESTION", which would mean j --> Q
- with 25 letters accounted for, I match the last letter which would mean o --> J

So far, I have the following: "nytvmqluharbpekcxzdgaisfjo" --> "ETHAISWNRCGFDPXMOUYBCLKVQJ". The next step is to change these letters in the ciphertext to their corresponding plaintext equivalent.

```bash
$ tr 'nytvmqluharbpekcxzdgaisfjo' 'ETHAISWNRCGFDPXMOUYBCLKVQJ' < ciphertext.txt > plaintext.txt
$ cat plaintext.txt
```

At last, the ciphertext is fully decoded.


<br>

### Encryption using Different Ciphers and Modes

If two plaintext blocks are the same, their corresponding ciphertext blocks will also be the same. If they are different in just one bit, we will not be able to tell how closely related the two plaintext blocks are from the ciphertext alone.

If an encryption algorithm cannot satisfy the above requirement, it is not acceptable. 

A typical block cipher algorithm has two inputs: the plaintext block and the encryption key (which is typically the same for all blocks). If we want to make the output different for two identical blocks, we have to make one of the inputs different using encryption modes. Encryption modes are techniques used to apply encryption algorithms to plaintext data in a secure and effective manner. These modes determine how encryption is performed and how the encryption algorithm functions over multiple blocks of data. Common encryption modes include:

- __Electronic Codebook (ECB)__: each block of plaintext is encrypted independently, resulting in identical ciphertext blocks if the same plaintext is encrypted multiple times.
- __Cipher Block Chaining (CBC)__: each plaintext block is combined with the ciphertext of the previous block before encryption. This creates a dependency between blocks and provides better security than ECB. Initialization Vector (IV) is used in CBC to encrypt the first block and also to ensure different ciphertexts even for the same plaintext. When using CBC mode, decryption can be parallelized but encryption cannot be conducted in parallel.
- __Cipher Feedback (CFB)__: the previous ciphertext block is fed to the encryption algorithm and then XORed with the plaintext to generate the actual ciphertext block. When using the CFB mode, decryption be parallelized, while encryption can only be conducted sequentially.
- __Output Feedback (OFB)__: The OFB mode is very similar to the CFB mode. The main difference is what data is fed into the next block. In the CFB mode, the data after the XOR operation is fed into the next block, while in the OFB mode, it is the data before the XOR operation. When using the OFB mode, both decryption and encryption can be parallelized.
- __Counter (CTR)__: each block of the plaintext is treated as a counter and generates a keystream by encrypting this counter value. The resulting keystream is then XORed with the plaintext to produce the ciphertext. CTR mode allows parallel encryption and decryption and is considered highly secure and efficient.
- __Galois/Counter Mode (GCM)__: GCM mode combines the counter mode (CTR) with the Galois/Counter Mode Authentication (GMAC) to provide both encryption and authentication. It uses a unique IV for each message and provides data integrity and authenticity in addition to confidentiality.

This task deals with trying out various encryption algorithms and modes using the `openssl enc` command to encrypt/decrypt a file. To know the modes that `openssl enc` supports, run `$ openssl enc --list`


#### Encrypting a file using EBC mode

```bash
$ openssl enc -des-ecb -e -in plain.txt -out des-cipher.bin -K  00112233445566778889aabbccddeeff
$ openssl enc -des-ede-ecb -e -in plain.txt -out des-ede-cipher.bin -K  00112233445566778889aabbccddeeff
$ openssl enc -des-ede3-ecb -e -in plain.txt -out des-ede3-cipher.bin -K  00112233445566778889aabbccddeeff
```

**image**


#### Encrypting a file using CBC mode

```bash
$ openssl enc -aes-128-cbc -e -in plain.txt -out aes-cipher.bin -K  00112233445566778889aabbccddeeff -iv 0102030405060708
$ openssl enc -bf-cbc -e -in plain.txt -out bf-cipher.bin -K  00112233445566778889aabbccddeeff -iv 0102030405060708
$ openssl enc -camellia-128-cbc -e -in plain.txt -out camellia-cipher.bin -K  00112233445566778889aabbccddeeff -iv 0102030405060708
```

**image**


#### Encrypting a file using CFB mode

```bash
$ openssl enc -aria-128-cfb -e -in plain.txt -out aria-cipher.bin -K  00112233445566778889aabbccddeeff -iv 0102030405060708
$ openssl enc -cast5-cfb -e -in plain.txt -out cast5-cipher.bin -K  00112233445566778889aabbccddeeff -iv 0102030405060708
$ openssl enc -seed-cfb -e -in plain.txt -out seed-cipher.bin -K  00112233445566778889aabbccddeeff -iv 0102030405060708
```

**image**


#### Encrypting a file using OFB mode

```bash
$ openssl enc -aes-192-ofb -e -in plain.txt -out aes-192-cipher.bin -K  00112233445566778889aabbccddeeff -iv 0102030405060708
$ openssl enc -rc2-ofb -e -in plain.txt -out rc2-cipher.bin -K  00112233445566778889aabbccddeeff -iv 0102030405060708
$ openssl enc -sm4-ofb -e -in plain.txt -out sm4-cipher.bin -K  00112233445566778889aabbccddeeff -iv 0102030405060708
```

**image**


#### Encrypting a file using CTR mode

```bash
$ openssl enc -aes-128-ctr -e -in plain.txt -out aes-128-cipher.bin -K  00112233445566778889aabbccddeeff -iv 0102030405060708
$ openssl enc -aria-128-ctr -e -in plain.txt -out aria-128-cipher.bin -K  00112233445566778889aabbccddeeff -iv 0102030405060708
$ openssl enc -camellia-128-ctr -e -in plain.txt -out camellia-128-cipher.bin -K  00112233445566778889aabbccddeeff -iv 0102030405060708
```

**image**


<br>

### ECB Encryption Mode CBC Encryption Mode

This task involves encrypting a picture "original.bmp" so people without the encryption keys cannot know what is in the picture.

First, encrypt the file using the ECB (Electronic Code Book) and CBC (Cipher Block Chaining) modes:

```bash
openssl enc -aes-128-ecb -e -in pic_original.bmp -out pic_encrypted_ecb.bin -K  00112233445566778889aabbccddeeff
openssl enc -aes-128-cbc -e -in pic_original.bmp -out pic_encrypted_cbc.bin -K  00112233445566778889aabbccddeeff -iv 01020304050607080102030405060708
```

Next, then do the following

- We will attempt to view the encrypted picture using picture-viewing software. For the .bmp file, the first 54 bytes contain the header information about the picture, we have to set it correctly, so the encrypted file can be treated as a legitimate .bmp file.
- To do this, we will replace the header of the encrypted picture with that of the original picture.

```bash
$ head -c 54 pic_original.bmp > modified_ebc.bmp
$ tail -c +55 pic_encrypted_ecb.bin >> modified_ebc.bmp
```







<br>

Thanks for reading.

<details>
<summary><b>References</b></summary>
<div markdown="1">

- [Frequencies for a typical English plaintext](https://en.wikipedia.org/wiki/Frequency_analysis)
- [Bigram frequency](https://en.wikipedia.org/wiki/Bigram)
- [Trigram frequency](https://en.wikipedia.org/wiki/Trigram)

</div></details>
