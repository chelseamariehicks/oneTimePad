/**********************************************************************************
 * Name: Chelsea Marie Hicks
 * 
 * Description: Program creates a key file of a specified length. The characters 
 *      in the file are of 27 allowable values, the 26 letters of the alphabet 
 *      capitalized and a space.
***********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

int main(int argc, char* argv[]) {
    //Generate random seed
    srand(time(NULL));
    
    //Print error when no key length provided
    if(argc < 2) {
        fprintf(stderr, "Error: key length not provided \n");
        exit(1);
    }

    //Variable for holding the key length and generating random characters
    int keyLength = atoi(argv[1]);
    char randVal;

    //Array to hold the entire key, including newline char
    char key[keyLength+1];

    //Select a random letter from the values and set that slot in the key to the letter
    int i;
    for(i = 0; i < keyLength; i++) {
        randVal = "ABCDEFGHIJKLMNOPQRSTUVWXYZ " [rand() % 27];
        key[i] = randVal;
    }

    //Newline at the end of the key
    key[keyLength] = '\n';

    printf("%s", key);

    return 0;
}
