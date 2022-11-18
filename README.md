# ChaCha
ChaCha20 is a secure, quick, and simple encryption algorithm. Developed originally by Daniel J. Bernstein. It's a keyed ARX-based Algorithm running in counter mode.

Its core is a pseudo-random number generator for two values, the key and the nonce. The key is 32 bytes. And the nonce is 12 bytes. In my implementation, I used getentropy() to generate them. 

