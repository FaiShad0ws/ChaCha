# ChaCha Encryption Algorithm
ChaCha20 is a secure, quick, and simple encryption algorithm. Developed originally by Daniel J. Bernstein. It's a keyed ARX-based Algorithm running in counter mode.

Its core is a pseudo-random number generator for two values, the key and the nonce. The key is 32 bytes. And the nonce is 12 bytes. In my implementation, I used getentropy() to generate them. 

<br>

The ChaCha20 block is a 4×4 matrix of 32-bit integers represented as follows:  

```
block[ 0]: "expa"    block[ 8]: key[4]
block[ 1]: "nd 3"    block[ 9]: key[5]
block[ 2]: "2-by"    block[10]: key[6]
block[ 3]: "te k"    block[11]: key[7]
block[ 4]: key[0]    block[12]: counter
block[ 5]: key[1]    block[13]: nonce[0]
block[ 6]: key[2]    block[14]: nonce[1]
block[ 7]: key[3]    block[15]: nonce[2]
```

<br>

Operations on the block is an ARX based design (Addition, Rotation, Xor) which performed 20 times (column by column & diagonal by diagonal) for each column or diagonal, the operations is as follows:


```
define QUARTERROUND(a, b, c, d)  
a += b;  d ^= a;  d <<<= 16;
c += d;  b ^= c;  b <<<= 12;
a += b;  d ^= a;  d <<<=  8;
c += d;  b ^= c;  b <<<=  7;
```

After 20 rounds, Finaly add the original block to the scrambled block, and use that as the pseudo-random block in both encryption and decryption processes



<br>

**Encryption**
```
cipher_text = plain_text XOR pseudoRandomBlock(key, nonce)

```

**Decryption**
```
plain_text = cipher_text XOR pseudoRandomBlock(key, nonce)

```


<br>

## Instructions 
unzip the file, cd to the directory and compile it with gcc 

```
gcc -O3 ChaCha.c ChaCha.h -o ChaCha
```

<br>

## Usage 
```
./ChaCha -e plain.txt -d plain.enc.txt  
```
**Example**

```
$ ./ChaCha -e plain.txt -d plain.enc.txt

[1] Key And Nonce generation
    [===============================================================================] 100%

    Random key: 3FDDA3BC5BB05EC50D94628A05212A90D724BE07CAC66B12747DA3F26B5D143F
    Random nonce: 8BAD7596A6C824DC58E4CF05

    NOTE: This is top-secret information. maintain them in a secure location 

[2] Encryption Process 
    [2.1] Block Initialization
          [===============================================================================] 100%
    [2.2] Block Operations
          [===============================================================================] 100%
    [2.3] Generating The Encrypted File
          [===============================================================================] 100%

    NOTE: Encrypted File is Written to plain.txt-Encrypted

[3] Decryption Process 
    [3.1] Reversing block Operations
          [===============================================================================] 100%
    [3.2] Generating The Decrypted File
          [===============================================================================] 100%

    NOTE: Decrypted File is Written to plain.enc.txt-Original

```

<br>

## Disclaimer!
This is part of my Cryptography and Network security course project, Do NOT use the algorithm in real-world projects without proper code review










