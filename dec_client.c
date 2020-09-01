/**********************************************************************************
 * Name: Chelsea Marie Hicks
 * 
 * Description: Program connects to dec_server and has dec_server perform a one-
 *      time pad style decryption using an alphashift method. This program provides
 *      the server with the encrypted ciphertext file, key, and port that should connect
 *      to dec_server. The dec_server will send back decrypted text and dec_client will
 *      output this via stdout. Program is essentially the same as enc_client.
***********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

// Error function used for reporting issues
void error(const char *message, int errNum) { 
  fprintf(stderr, "%s\n", message); 
  exit(errNum); 
}

int main(int argc, char *argv[]) {

    //Setup variables to be used
    int socketFD, portNum, charsRead, charsWritten;
    int i, j;
    struct sockaddr_in serverAddress;
    struct hostent* hostInfo;
    char buffer[200000];
    char keyBuffer[200000];
    int textLen, keyLen;

    //Check usage and args
    if(argc < 3) {
        fprintf(stderr, "Usage: %s ciphertext key port \n", argv[0]);
        exit(1);
    }

    //Get input from ciphertext/encrypted file
    //Clear out the buffer array
    memset(buffer, '\0', sizeof(buffer));
    //Open the ciphertext file passed in as argument for reading
    FILE *enctext = fopen(argv[1], "r");
    if(enctext == 0) {
        error("Error: could not open encrypted file", 1);
    }
    //Get input from ciphertext, truncate to buffer -1 leaving \0
    while(fgets(buffer, sizeof(buffer)-1, enctext));
    //Close ciphertext file
    fclose(enctext);

    //Variables used to check that all values in key and plaintext are valid
    char values[29] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ \n";
    int valid;

    //Loop through all of the chars in the buffer to check
    for(i = 0; buffer[i] != '\0'; i++) {
        //Set tracker to false
        valid = 0;

        //If the value in the buffer array matches an accepted value
        //then valid is set to true
        for(j = 0; values[j] != '\0'; j++) {
            if(buffer[i] == values[j]) {
                valid = 1;
            }
        }
        //If valid isn't true, than a bad char was entered and print error
        if(!valid) {
            error("Error: file contains bad character", 1);
        }
    }

    //Remove trailing \n that fgets adds and replace with tracking sign
    buffer[strcspn(buffer, "\n")] = '~';

    //Get input from key
    //Clear out the key buffer array
    memset(keyBuffer, '\0', sizeof(keyBuffer));
    //Open the key file passed in as an argument for reading
    FILE *keyFile = fopen(argv[2], "r");
    if(keyFile == 0) {
        error("Error: could not open key file", 1);
    }
    //Get input from key file, truncate to buffer -1 leaving \0
    while(fgets(keyBuffer, sizeof(keyBuffer)-1, keyFile));
    //Close key file
    fclose(keyFile);

    //Check if any bad chars were entered in key file
    //Loop through all of the chars in the key buffer to check
    for(i = 0; keyBuffer[i] != '\0'; i++) {
        //Set tracker to false
        valid = 0;

        //If the value in the key buffer array matches an accepted value
        //then valid is set to true
        for(j = 0; values[j] != '\0'; j++) {
            if(keyBuffer[i] == values[j]) {
                valid = 1;
            }
        }
        //If valid isn't true, than a bad char was entered and print error
        if(!valid) {
            error("Error: key file contains bad character", 1);
        }
    }

    //Remove trailing \n that fgets adds and replace with !
    keyBuffer[strcspn(keyBuffer, "\n")] = '!';

    //Check if key length is shorter than plaintext file length
    textLen = strlen(buffer);
    keyLen = strlen(keyBuffer);
    //Print error if shorter
    if(keyLen < textLen) {
        error("Error: key is shorter than plaintext file", 1);
    }

    //Setup server address struct
    //Clear out the address struct
    memset((char*)&serverAddress, '\0', sizeof(serverAddress));
    //Get port number from program arguments
    portNum = atoi(argv[3]);
    //Address should be network capable
    serverAddress.sin_family = AF_INET;
    //Store the port number
    serverAddress.sin_port = htons(portNum);
    //Get the machine name entered as IP address
    hostInfo = gethostbyname("localhost");
    if(hostInfo == NULL) {
        error("Error: no such host", 1);
    }
    //Copy in the address
    memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)hostInfo->h_addr, hostInfo->h_length);

    //Create a socket
    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if(socketFD < 0) {
        error("Error: opening socket", 1);
    }

    //Connect to server
    if(connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        error("Error: connecting", 2);
    }

    //Send signal that this is for decrypting not encrypting
    do {
        charsWritten = send(socketFD, "d:", strlen("d:"), 0);
        if(charsWritten < 0) {
            error("Error: writing to socket", 1);
        }
    } while(charsWritten < strlen("d:"));
    
    //Send plaintext to server
    do {
        charsWritten = send(socketFD, buffer, strlen(buffer), 0);
        if(charsWritten < 0) {
            error("Error: writing to socket", 1);
        }
    } while(charsWritten < strlen(buffer)); 

    //Send key to server
    do {
        charsWritten = send(socketFD, keyBuffer, strlen(keyBuffer), 0);
        if(charsWritten < 0) {
            error("Error: writing to socket", 1);
        }
    } while(charsWritten < strlen(keyBuffer));

    //Get return message from the server and display
    //Clear out the buffer
    memset(buffer, '\0', sizeof(buffer));
    //Trackers for chars read and buffer length
    int bufLen;
    int bufcount = 0;
    //Read in what server sent over until terminating sign encountered
    do {
        //Read in message  in chunks
        charsRead = recv(socketFD, &buffer[bufcount], 100, 0);
        //Continue counting up the bufcount based on characters read
        bufcount += charsRead;
        //Get length of string in buffer
        bufLen = strlen(buffer);

        if(charsRead < 0) {
            error("Error: reading from socket", 1);
        }
    } while(buffer[bufLen-1] != '!'); 

    //Replace terminating sign with null value
    buffer[bufLen-1] = '\0';

    //Report error if cannot connect to server
    if(buffer[0] == '$') {
        fprintf(stderr, "Error: could not connect to dec_server on port %d\n", portNum);
        exit(2);
    }

    //Output decrypted plaintext
    printf("%s\n", buffer);

    //Close the socket
    close(socketFD);

    return 0;
}
