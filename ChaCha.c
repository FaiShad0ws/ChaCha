
#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <stdint.h>

#include "ChaCha.h"



int main(int argc, char* argv[]){
    

    int option;
    char plainTextFile[256];
    char cipherTextFile[256];
    uint32_t counter = 1;

    while( (option = getopt(argc, argv, ":hed"))  != -1) 
    { 

        switch(option) 
        { 
            case 'h':                         
                help();
                break;

            case 'e':
                KeyAndNonceGeneration();
                BlockInitialization(counter);
                BlockOperation(counter);

                strncpy(plainTextFile, argv[2], 255);
                EncryptPlainTextFile(plainTextFile);  
                break;

            case 'd':
                
                strncpy(cipherTextFile, argv[4], 255);
                DecryptPlainTextFile(cipherTextFile);
                break;

            default:
                printf("Unrecognized option\n\n");
                printf("Try -h for more informations");

        } 
        
    } 
      
   
    return 0;
}