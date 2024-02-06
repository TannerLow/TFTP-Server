#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdbool.h>

#define INCOMING_PORT "69"
#define OUTGOING_PORT "42069"

//#define MAX_BUFFER_LENGTH 1024
#define MAX_IN_BUFFER_SIZE 256
#define MAX_TABLE_ENTRY_COUNT 20
#define MAX_FILE_DATA 512

#define GETADDRINFO_FAILURE 1
#define BIND_FAILURE 2
#define SELECT_FAILURE 3
#define RECVFROM_FAILURE 4
#define PREAD_FAILURE 5

typedef struct addrinfo addrinfo;
typedef struct sockaddr_storage sockaddr_storage;
typedef struct sockaddr sockaddr;

typedef struct {
    sockaddr_storage addressInfo;
    socklen_t addressSize;
    const char* filename;
    const char* mode;
    unsigned short blockNumber;
} StateTableEntry;

typedef struct {
    StateTableEntry entries[MAX_TABLE_ENTRY_COUNT];
    size_t capacity; // max count
    size_t size; // current count
} StateTable;

typedef struct {
    uint16_t opcode;
    char* filename = NULL;
    char* mode = NULL;
    uint16_t block;
    char* data = NULL;
    size_t dataLength;
    uint16_t errorCode;
    char* errorMessage = NULL;
} TFTPPacket;

typedef struct {
    char* filename = NULL;
    FILE* file;
} FileInfo;

typedef struct {
    FileInfo files[MAX_TABLE_ENTRY_COUNT];
    size_t size;
} FileTable;

int createAndBindSocket(const addrinfo hints, const char* host, const char* port);
int getFreeStateTableEntry(StateTable* stateTable);
TFTPPacket parseTFTPPacket(const char* rawData, const size_t dataLength);
bool getFileHandle(const char* filename, FileTable* lookupTable);
char* serializeTFTPDataPacket(TFTPPacket* packet);

int main() {
    StateTable stateTable;
    stateTable.capacity = MAX_TABLE_ENTRY_COUNT;
    stateTable.size = 0;
    memset(stateTable.entries, NULL, stateTable.capacity * sizeof(StateTableEntry));

    FileTable fileTable;
    fileTable.size = 0;

    int entrySocketDescriptor; // port 69
    int replySocketDescriptor; // port 42069
    
    addrinfo hints;

    // Get address info for inSocket
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    entrySocketDescriptor = createAndBindSocket(hints, NULL, INCOMING_PORT);
    printf("Successfully created inSocket\n");
    replySocketDescriptor = createAndBindSocket(hints, NULL, OUTGOING_PORT);
    printf("Successfully created outSocket\n");

    fd_set readfds;
    fd_set writefds;
    int maxfds = (entrySocketDescriptor > replySocketDescriptor) ? entrySocketDescriptor : replySocketDescriptor;

    FD_ZERO(&readfds);
    FD_SET(entrySocketDescriptor, &readfds);
    FD_SET(replySocketDescriptor, &readfds);

    char inBuffer[MAX_IN_BUFFER_SIZE];
    memset(inBuffer, 0, MAX_IN_BUFFER_SIZE);

    // main loop
    for(;;) {
        int returnCode = select(maxfds+1, &readfds, NULL, NULL, NULL);
        if(returnCode == -1) {
            perror("select");
            close(entrySocketDescriptor);
            close(replySocketDescriptor);
            exit(SELECT_FAILURE);
        }

        // Port 69 has available data meaning a new request
        if(FD_ISSET(entrySocketDescriptor, &readfds)) {
            unsigned int flags = 0;
            sockaddr_storage from;
            socklen_t addressSize;
            int bytesReceived = recvfrom(entrySocketDescriptor, inBuffer, MAX_IN_BUFFER_SIZE-1, flags, (sockaddr*)&from, &addressSize);
            if(bytesReceived == -1) {
                perror("recvfrom");
                close(entrySocketDescriptor);
                close(replySocketDescriptor);
                exit(RECVFROM_FAILURE);
            }
            inBuffer[bytesReceived] = '\0'; // end with null for string parsing safety

            int stateTableEntryIndex = getFreeStateTableEntry(&stateTable);
            if(stateTableEntryIndex == -1) {
                // TODO Handle error due to full StateTable
                exit(-1);
            }

            // Create a new entry in the StateTable based on data in the request            
            StateTableEntry entry;
            entry.addressInfo = from;
            entry.addressSize = addressSize;

            TFTPPacket request = parseTFTPPacket(inBuffer, bytesReceived);
            if(packet.opcode != 1) {
                // TODO handle non-request packet on port 69
            }

            entry.filename = packet.filename;
            entry.mode = packet.mode;
            entry.block = 1;

            stateTable.entries[stateTableEntryIndex] = entry;

            // Begin sending file
            TFTPPacket response;
            response.opcode = 3;
            response.block = entry.block;
            
            // Keep track of an empty spot
            FILE * file = NULL;
            for (int i = 0; i < fileTable.size; ++i) {
                FileInfo currentFileInfo = fileTable.files[i]; 
                if (!strcmp(currentFileInfo.filename, entry.filename)) {
                    file = currentFileInfo.file;
                    break;
                }
            }

            if (!file) {
                file = fopen(entry.filename, "rb");
                // stick in table
                FileInfo addFileInfo;
                addFileInfo.file = file;
                addFileInfo.filename = entry.filename;
                fileTable[fileTable.size] = addFileInfo;
                ++fileTable.size;
            }

            FileInfo fileinfo;
            fileinfo.filename = entry.filename;
            fileinfo.file = file;

            char buffer[MAX_BUFFER_LENGTH];
            memset(buffer, 0, sizeof(buffer));
            int bytesPread = 0; 
            response.data = (char *) malloc (MAX_FILE_DATA);
            bytesPread = pread(file, response.data, sizeof(response.data), 0); /* get data from the file (no more than MAX_FILE_DATA in size) */
            if (bytesPread == -1) {
                perror("pread");
                close(entrySocketDescriptor);
                close(replySocketDescriptor);
                exit(PREAD_FAILURE);
            }
            
            void* serializedResponse = serializeTFTPDataPacket(response); // serializeTFTPDataPacket(response);

            returnCode = sendto(replySocketDescriptor, serializedResponse, flags, (sockaddr*)&from, addressSize);
            if (returnCode == -1) {
                perror("sendto");
                close(entrySocketDescriptor);
                close(replySocketDescriptor);
                exit(SENDTO_FAILURE);
            }
        }
        
        // Port 42069 has available data meaning an acknowledgement of data receipt
        if(FD_ISSET(replySocketDescriptor, &readfds)) {
            // TODO implement reply to existing client
            
            while ()
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
        if(socketDescriptor == -1) {
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

// Get an index to a free entry slot in the StateTable, -1 on error
int getFreeStateTableEntry(StateTable* stateTable) {
    // TODO add entry finding logic
    return 0;
}

TFTPPacket parseTFTPPacket(const char* rawData, const size_t rawDataLength) {
    // For TFTP protocol breakdown see RFC 1350: https://datatracker.ietf.org/doc/html/rfc1350.html
    
    TFTPPacket packet;
    size_t dataParsed = 0;
    
    // First 2 bytes in TFTP packet are always the opcode
    if(rawDataLength >= dataParsed + 2) {
        uint16_t* opcodePointer = (uint16_t*)rawData;
        uint16_t opcode = *opcodePointer;
        packet.opcode = ntohs(opcode);
        dataParsed += 2;
    }

    // opcode 1/2: read/write request -> opcode(2) filename(n) null mode(m) null
    if(packet.opcode == 1 || packet.opcode == 2) {
        // +1's are for null character at end of string
        // Parse filename
        if(rawDataLength >= dataParsed + 1) {
            size_t filnameLength = strlen(rawData + dataParsed);
            packet.filename = (char*)malloc(filnameLength + 1);
            memcpy(packet.filename, rawData + dataParsed, filenameLength);
            packet.filename[filenameLength] = '\0';
            dataParsed += filenameLength + 1;
        }

        // Parse mode
        if(rawDataLength >= dataParsed + 1) {
            size_t modeLength = strlen(rawData + dataParsed);
            packet.filename = (char*)malloc(modeLength + 1);
            memcpy(packet.mode, rawData + dataParsed, modeLength);
            packet.mode[modeLength] = '\0';
            dataParsed += modeLength + 1;
        }
    }
    // opcode 3: data packet -> opcode(2) block#(2) data(n)
    else if(opcode == 3) {
        // Parse block#
        if(rawDataLength >= dataParsed + 1) {
            uint16_t* blockPointer = (uint16_t*)rawData;
            uint16_t block = *blockPointer;
            packet.block = ntohs(block);
            dataParsed += 2;
        }
        // Parse data
        if(rawDataLength - dataParsed > 0) {
            size_t dataLength = rawDataLength - dataParsed;
            packet.data = (char*)malloc(dataLength);
            memcpy(packet.data, rawData + dataParsed, dataLength);
            packet.dataLength = dataLength;
            dataParsed += dataLength;
        }
    }
    // opcode 4: ack packet -> opcode(2) block#(2)
    else if(opcode == 4) {
        // Parse block#
        if(rawDataLength >= dataParsed + 1) {
            uint16_t* blockPointer = (uint16_t*)rawData;
            uint16_t block = *blockPointer;
            packet.block = ntohs(block);
            dataParsed += 2;
        }
    }
    else if(opcode == 5) {
        // TODO implement error packet parsing
    }
    else {
        // TODO error out due to invalid packet
    }

    return packet;
}

idk getFileHandle(const char* filename, FileTable* lookupTable) {
    // Jackson do this 
}

char* serializeTFTPDataPacket(TFTPPacket* packet) {
    char* serializedData;
    if(packet.opcode == 3) {

    }
    // TODO do something about non-data packets
    return serializedData;
}