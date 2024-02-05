#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sting.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>

#define INCOMING_PORT "69"
#define OUTGOING_PORT "42069"

#define MAX_BUFFER_LENGTH 1024

#define GETADDRINFO_FAILURE 1
#define BIND_FAILURE 2

typedef struct addrinfo addrinfo;

int createAndBindSocket(
    const addrinfo hints,
    const char* host, 
    const char* port
);

int main() {

    int inSocketDescriptor;  // port 69
    int outSocketDescriptor; // port 42069
    
    addrinfo hints;

    // Get address info for inSocket
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    inSocketDescriptor = createAndBindSocket(hints, NULL, INCOMING_PORT);
    printf("Successfully created inSocket\n");
    outSocketDescriptor = createAndBindSocket(hints, NULL, OUTGOING_PORT);
    printf("Successfully created outSocket\n");

    int maxfd = (inSocketDescriptor > outSocketDescriptor) ? inSocketDescriptor : outSocketDescriptor;
    fd_set readfds;
    fd_set writefds;

    FD_ZERO(&readfds);
    FD_SET(inSocketDescriptor, &readfds);

    // main loop
    while(true) {
        int returnCode = select(inSocketDescriptor+1, &readfds, NULL, NULL, NULL);
        if(returnCode == -1) {
            // crash lol
        }

        if(FD_ISSET(inSocketDescriptor, &readfds)) {
            
        }
    }

    close(inSocketDescriptor);
    close(outSocketDescriptor);
    
    return 0;
}

// Creates a new socket and binds it to the given port
int createAndBindSocket(
    const addrinfo* hints,
    const char* host, 
    const char* port
) {
    int socketDescriptor;
    addrinfo* addressInfoList;
    addrinfo* addressInfo;

    int returnCode = getaddrinfo(host, port, hints, &addressInfoList);
    if(returnCode != 0) {
        printf("getaddrinfo: %s\n", gai_strerror(returnCode));
        exit(GETADDRINFO_FAILURE);
    }

    // iterate thru addressInfoList and use first valid entry to create socket
    for(addressInfo = addressInfoList; addressInfo != NULL; addressInfo = addressInfo->ai_next) {
        socketDescriptor = socket(addressInfo->ai_family, addressInfo->ai_socktype, addressInfo->ai_protocol);
        if(inSocketDescriptor == -1) {
            printf("call to socket() failed\n");
            continue;
        }

        returnCode = bind(socketDescriptor, addressInfo->ai_addr, addressInfo->ai_addrlen);
        if(returnCode == -1) {
            close(socketDescriptor);
            printf("call to bind() failed\n");
            continue;
        }

        break;
    }

    if(addressInfo == NULL) {
        printf("failed to bind socket on port: %s\n", port);
        exit(BIND_FAILURE);
    }

    freeaddrinfo(addressInfoList);

    return socketDescriptor;
}