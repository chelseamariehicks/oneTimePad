/**********************************************************************************
 * Name: Chelsea Marie Hicks
 * 
 * Description: Program to decrypt an encrypted text file according to the unique key
 *      file provided as an argument. Program listens on a particular assigned port
 *      and when connection is made and verified, the program will receive an
 *      encrypted ciphertext file and key and write back the plaintext to the
 *      dec_clinet connnected to the same socket.
***********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

//Error function to report any issues
void error(const char *message) {
    perror(message);
    exit(1);
}

//Function receives message from client and send decrypted message back
void makeConnection(int connectionFD) {
    //Setup variables for holding text
    char buffer[600000];
    char textBuffer[200001];
    char keyBuffer[200001];
    char decBuffer[600000];
    int charsRead, charsWritten;

    //Clear all buffers
    memset(buffer, '\0', sizeof(buffer));
    memset(textBuffer, '\0', sizeof(textBuffer));
    memset(keyBuffer, '\0', sizeof(keyBuffer));
    memset(decBuffer, '\0', sizeof(decBuffer));

    //Get message from the client to display
    //Trackers for chars read and buffer length
    int bufLen;
    int bufcount = 0;
    //Read in what client sent over until terminating sign encountered
    do {
        //Read in message from socket
        charsRead = recv(connectionFD, &buffer[bufcount], 1000, 0);
        //Continue counting up the bufcount based on characters read
        bufcount += charsRead;
        //Get length of string in buffer
        bufLen = strlen(buffer);

        if(charsRead < 0) {
            error("Error: reading from socket");
        }
    } while(buffer[bufLen-1] != '!');

    //Confirm that correct client is connecting
    if(buffer[0] != 'd' || buffer[1] != ':') {
        charsWritten = send(connectionFD, "$!", strlen("$!"), 0);
        if(charsWritten < 0) {
            error("Error: writing to socket");
        } 
        close(connectionFD);
        exit(1);       
    }

    //Split the buffer into the message to be translated and the key
    //using the special characters
    //Create tracker for type of text encountered, 0 is nothing, 1 is ciphertext
    //2 is key text
    int textType = 0;
    //Trackers for the textbuffer and key buffer array positions
    int i = 0;
    int j = 0;
    int k = 0;
    for(i = 0; buffer[i] != '!'; i++) {

        //Once : is encountered, begin to save text message
        if(buffer[i] == ':') {
            //Set textType to 1 since what follows is from ciphertext
            textType = 1;
            //Advance to the next char which will be part of message
            i++;
        }

        //Once ~ is encountered, we know the following text is the key
        if(buffer[i] == '~') {
            //Set textType to 2 since what follows is from key text
            textType = 2;
            //Advance to the next char which will be part of message
            i++;
        }

        //Start to write to the text buffer what's in the buffer
        if(textType == 1) {
            textBuffer[j] = buffer[i];
            j++;
        }

        //Start to write to the key buffer
        if(textType == 2) {
            keyBuffer[k] = buffer[i];
            k++;
        }
    }

    //Variables used for decryption
    int textVal = 0;
    int keyVal = 0;
    int difVal = 0;
    
    char validChars[29] = "$ABCDEFGHIJKLMNOPQRSTUVWXYZ ";
    //Use the key to decrypt the ciphertext
    for(i = 0; textBuffer[i] != '\0'; i++) {

        //Obtain the value of the char
        for(j = 1; validChars[j] != '\0'; j++) {
            if(textBuffer[i] == validChars[j]) {
                //Set text val equal to char position in validChars array
                textVal = j;
            }
        }

        //Obtain the value of the char for the key
        for(j = 1; validChars[j] != '\0'; j++) {
            if(keyBuffer[i] == validChars[j]) {
                //Set keyVal equal to char position in valid chars array
                keyVal = j;
            }
        }

        //Find the difference of the textVal and keyVal
        difVal = textVal - keyVal;

        //Add 27 to find the character to be used when difval is less than 1
        while(difVal < 1) {
            difVal += 27;
        }

        //Decrypt current char of ciphertext
        for(j = 1; validChars[j] != '\0'; j++) {
            if(difVal == j) {
                decBuffer[i] = validChars[j];
            }
        }
    }

    //Send the decrypted text back to client
    int decLen = strlen(decBuffer);

    do {
        charsWritten = send(connectionFD, decBuffer, decLen, 0);
        if(charsWritten < 0) {
            error("Error: writing to socket");
        }

    } while(charsWritten < decLen);

    //Ensure final character is !
    do {
        charsWritten = send(connectionFD, "!", strlen("!"), 0);
        if(charsWritten < 0) {
            error("Error: writing to socket");
        }
    } while(charsWritten < strlen("!"));
    
    //Close socket
    close(connectionFD);
}


int main(int argc, char *argv[]) {

    //Setup variables to be used
    int listenSocketFD, connectionSocketFD, portNum;
    struct sockaddr_in serverAddress, clientAddress;
    socklen_t sizeOfClientInfo;
    pid_t childPid;
    int childCount = 0;
    int childExit = -5;

    //Check usage and args
    if(argc < 2) {
        fprintf(stderr, "Usage: %s port \n", argv[0]);
        exit(1);
    }

    //Set up the address struct for the server socket
    //Clear out the address struct
    memset((char *)&serverAddress, '\0', sizeof(serverAddress));
    //Get the port number and convert to int
    portNum = atoi(argv[1]);
    //Ensure it's network capable
    serverAddress.sin_family = AF_INET;
    //Store the port number
    serverAddress.sin_port = htons(portNum);
    //Allow a client at any address to connect
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    //Create the socket that will listen for connections
    listenSocketFD = socket(AF_INET, SOCK_STREAM, 0);
    if(listenSocketFD < 0) {
        error("Error opening socket");
    }

    //Associate the socket to the port and enable it to listen
    if(bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        error("Error: on binding");
    }

    //Start listening for connections and allow up to 5 connections to be received at one time
    listen(listenSocketFD, 5);

    //Continue to listen and accept a connection
    while(1) {
        
        //Check if any children have died and adjust count
        while((childPid = waitpid(-1, &childExit, WNOHANG)) > 0) {
            childCount -= 1;
        }

        //Only create a connection is there are less than 5 currently
        if(childCount < 5) {
            //Obtain the size of the address
            sizeOfClientInfo = sizeof(clientAddress);
            //Accept a connection, blocking if one is not available
            connectionSocketFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo);

            if(connectionSocketFD < 0) {
                error("Error: on accept");
            }

            //Fork the connection
            pid_t spawnPid = -5;
            spawnPid = fork();

            //Reuse code from program 2 for checking if in parent or child
            switch(spawnPid) {
                case -1:
                    perror("Error: fork() failed\n");
                    exit(1);
                    break;
                
                //Child process
                case 0:
                    //Call function to receive message from client and handle decryption 
                    makeConnection(connectionSocketFD);

                //Parent process
                default:
                    //Increase the number of children
                    childCount += 1;            
            }
        }
        else {
            //Wait until a child process is completed to decrement count and allow for another
            if((childPid = waitpid(-1, &childExit, 0)) > 0) {
                childCount -= 1;
            }
        }
    }

    return 0;
}
