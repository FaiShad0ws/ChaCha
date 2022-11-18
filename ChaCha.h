#ifndef CHACHA_H
#define CHACHA_H


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <limits.h>
  


/*  -----TODO-----
    1. Apply authintication, maybe via poly1305? 
    2. padding?
*/


// Bitwise rotate a 32-bit number to the left 
#define ROT_L32(x, n) x = (x << n) | (x >> (32 - n))



// Load unaligned 32-bit integer (little-endian encoding)
#define LE32(p) ( \
    ((uint32_t)(((uint8_t *)(p))[0]) << 0)   | \
    ((uint32_t)(((uint8_t *)(p))[1]) << 8)   | \
    ((uint32_t)(((uint8_t *)(p))[2]) << 16)  | \
    ((uint32_t)(((uint8_t *)(p))[3]) << 24))



// ChaCha quarter round using ARX (Add, Rotate, XOR)
#define quarterRound(a, b, c, d)       \
    a += b;  d ^= a;  ROT_L32(d, 16);  \
    c += d;  b ^= c;  ROT_L32(b, 12);  \
    a += b;  d ^= a;  ROT_L32(d,  8);  \
    c += d;  b ^= c;  ROT_L32(b,  7)



// global Variables
uint8_t byteKey[32] = {0};
uint8_t byteNonce[12] = {0};

uint8_t plainText[65536] = {0};
uint8_t cipherText[65536] = {0}; 

uint32_t initialBlock[65536] = {0}; 
uint32_t initialBlockTemp[65536] = {0};


int i = 0;
int j = 0;
int k = 0;


void help(){


    printf("usage: ./ChaCha -e <plainText>  OR  ./ChaCha -d <cipherText> \n\n");
    printf("Basic options:\n");
    printf("-e                    specify the path to the plaintext file for encryption\n");
    printf("-d                    specify the path to the ciphertext file for decryption\n\n");
    printf("informative options:\n");
    printf("-h                    display usage\n");   
    
}


void ProgressBar() {


    printf("[");

    for(int i = 0; i <= 10; i++){

        printf("========");
        printf("> ");

        // to hide the cursor - ANSI codesheet 
        printf("\e[?25l");

        printf("] %d%%", i*10);
        printf("\b\b\b\b\b\b\b\b");

        fflush(stdout);

        usleep(150000);
    }

 
    printf("==", 100);

    printf("\n");

}



char *binToHex(const uint8_t byteArray[], const size_t byteArrayLen){


    const char hex[17] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', '\0'};
    char temp[3] = {0x00, 0x00, '\0'};


    // allocate multiple blocks of memory having the same size
    char *outputHex = (char*)calloc((byteArrayLen * 2) + 1, sizeof(char));


    outputHex[0] = '\0';


    for(size_t i = 0; i < byteArrayLen; i++){

        // first half of the hex value
        // bitwise then, shift 
        temp[0] = hex[(byteArray[i] & 0xF0) >> 4];

        // second half of the hex value 
        // bitwise
        temp[1] = hex[(byteArray[i] & 0x0F)];


        // Concatenate them back together 
        strcat(outputHex, temp);
    }

    return outputHex;

}



void KeyAndNonceGeneration(){


    // hold the status for generating the key & nonce
    int keyStatus;
    int nonceStatus;


    // generate random valus to fill byteKey, byteNonce with random bytes using getentropy
    keyStatus =  getentropy(byteKey, 32);
    nonceStatus = getentropy(byteNonce, 12);


    // Error code from getentropy
    if( keyStatus == -1 || nonceStatus == -1){
    
       printf("Error: Can't Generate Random Key or Random Nonce\n");
       printf("Quitting...\n");

    }

    printf("\n[1] Key And Nonce generation\n    ");
    ProgressBar();

    // otherwise         
    printf("\n    Random key: %s\n", binToHex(byteKey, 32));
    printf("    Random nonce: %s\n", binToHex(byteNonce, 12));

    printf("\n    NOTE: This is top-secret information. maintain them in a secure location \n\n");

    
}



void BlockInitialization(uint32_t counter){
     

    // static  value of "expand 32-byte k" in hex 
    initialBlock[0] =  0x61707865; //[expa]
    initialBlock[1] =  0x3320646e; //[nd 3]
    initialBlock[2] =  0x79622d32; //[2-by]
    initialBlock[3] =  0x6b206574; //[te k]


    // input words 4 through 11 are taken from the 256-bit key, by reading
    // the bytes in little-endian order, in 4-byte chunks

    initialBlock[4]  = LE32(byteKey);
    initialBlock[5]  = LE32(byteKey + 4);
    initialBlock[6]  = LE32(byteKey + 8);
    initialBlock[7]  = LE32(byteKey + 12);
    initialBlock[8]  = LE32(byteKey + 16);
    initialBlock[9]  = LE32(byteKey + 20);
    initialBlock[10] = LE32(byteKey + 24);
    initialBlock[11] = LE32(byteKey + 28);

    initialBlock[12] = counter;


    // input words 13 through 15 are taken from the 96-bit nonce, by reading
    // the bytes in little-endian order, in 4-byte chunks
    initialBlock[13]  = LE32(byteNonce);
    initialBlock[14]  = LE32(byteNonce + 4);
    initialBlock[15]  = LE32(byteNonce + 8);


    // save the initial block State to Add it the final block later
    for (int i = 0; i < 16; i++ ) {

        initialBlockTemp[i] = *(initialBlock + i);

    }
   
}



void BlockOperation(uint32_t counter){
    
    
    // total of 20 rounds | 10 diagonal-wise for even rounds | 10 column-wise for odd rounds
    for(int round = 0; round < 20; round++){

        // even Rounds 
        if(round %2 == 0){
            
        BlockInitialization(counter);  
        quarterRound(initialBlock[0], initialBlock[5], initialBlock[10], initialBlock[15]);
        quarterRound(initialBlock[1], initialBlock[6], initialBlock[11], initialBlock[12]);
        quarterRound(initialBlock[2], initialBlock[7], initialBlock[8], initialBlock[13]);
        quarterRound(initialBlock[3], initialBlock[4], initialBlock[9], initialBlock[14]);

        }

        // odd Rounds
        else{

        BlockInitialization(counter); 
        quarterRound(initialBlock[0], initialBlock[4], initialBlock[8], initialBlock[12]);
        quarterRound(initialBlock[1], initialBlock[5], initialBlock[9], initialBlock[13]);
        quarterRound(initialBlock[2], initialBlock[6], initialBlock[10], initialBlock[14]);
        quarterRound(initialBlock[3], initialBlock[7], initialBlock[11], initialBlock[15]);

        }

        counter ++;
    }


    // Add the final rounded bolck to the original block
    for (int i = 0; i < 16; i++ ) {

        initialBlock[i] += *(initialBlockTemp + i);

    }

}



void EncryptPlainTextFile(char* plainTextFile){

    
    // open the plain text file in read mode as binary 
    FILE *readBinaryFile;
    readBinaryFile = fopen(plainTextFile,"rb");


    if(readBinaryFile == NULL){

        printf("Could not open %s\n", plainTextFile);
        printf("Quitting...\n");
        _exit(1);

    }


    // read the palin text 
    while(!feof(readBinaryFile)){

        fscanf(readBinaryFile, "%c\n", &plainText[i]);
        i++;
    }


    // generate the cipher text by XORing the final generated block with the plain text 
    while(i > j){
 
        plainText[j] = plainText[j] ^ initialBlock[j];
        j++;
    }


    fclose(readBinaryFile);




    strcat(plainTextFile, "-Encrypted");


    // open the cipher text file in write mode as binary 
    FILE *writeBinaryFile;
    writeBinaryFile = fopen(plainTextFile, "wb");


    if(writeBinaryFile == NULL){
        printf("Could not create encrypted file %s \n",plainTextFile);
        printf("Quitting...\n");
        _exit(1);
    }

    printf("[2] Encryption Process \n");

    printf("    [2.1] Block Initialization\n\t  ");
    ProgressBar();

    printf("    [2.2] Block Operations\n\t  ");
    ProgressBar();

    printf("    [2.3] Generating The Encrypted File\n\t  ");
    ProgressBar();

    fputs(binToHex(plainText, j), writeBinaryFile);
    fclose(writeBinaryFile);


    printf("\n    NOTE: Encrypted File is Written to %s\n", plainTextFile);
    printf("\n");

}




void DecryptPlainTextFile(char* cipherTextFile){
   

    // decrypt the cipher text by XORing the final generated block with the cipher text
    while( i > k ){
 
        plainText[k] = plainText[k] ^ initialBlock[k];
        k++;
    }


    strcat(cipherTextFile, "-Original");
    

    FILE *writeBinaryFilePlain;
    writeBinaryFilePlain = fopen(cipherTextFile, "wb");


    printf("[3] Decryption Process \n");
    printf("    [3.1] Reversing block Operations\n\t  ");
    ProgressBar();

    printf("    [3.2] Generating The Decrypted File\n\t  ");
    ProgressBar();

    fputs(binToHex(plainText, k), writeBinaryFilePlain);
    fclose(writeBinaryFilePlain);


    printf("\n    NOTE: Decrypted File is Written to %s\n", cipherTextFile);

}


#endif