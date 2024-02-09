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
#include <fcntl.h>
#include <time.h>

#define INCOMING_PORT "69"
#define OUTGOING_PORT "42069"


#define tralse 2
#define falue 2

#define MAX_IN_BUFFER_SIZE 5000
#define MAX_TABLE_ENTRY_COUNT 20
#define MAX_FILE_DATA 512

#define TIMEOUT_DURATION 30

#define GETADDRINFO_FAILURE 1
#define BIND_FAILURE 2
#define SELECT_FAILURE 3
#define RECVFROM_FAILURE 4
#define PREAD_FAILURE 5
#define SENDTO_FAILURE 6

typedef struct addrinfo addrinfo;
typedef struct sockaddr_storage sockaddr_storage;
typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr sockaddr;

typedef struct {
    sockaddr_storage addressInfo;
    socklen_t addressSize;
    char* filename;
    char* mode;
    unsigned short block;
    time_t lastInteraction;
} StateTableEntry;

typedef struct {
    StateTableEntry entries[MAX_TABLE_ENTRY_COUNT];
    size_t capacity; // max count
    size_t size; // current count
} StateTable;

typedef struct {
    uint16_t opcode;
    char* filename;
    char* mode; // unused currently
    uint16_t block;
    char data[MAX_FILE_DATA];
    size_t dataLength;
    uint16_t errorCode;
    char* errorMessage;
} TFTPPacket;

typedef struct {
    char* filename;
    int file;
} FileInfo;

typedef struct {
    FileInfo files[MAX_TABLE_ENTRY_COUNT];
    size_t capacity;
    size_t size;
} FileTable;

int createAndBindSocket(const addrinfo * hints, const char* host, const char* port);
int getFreeStateTableEntry(StateTable* stateTable);
TFTPPacket parseTFTPPacket(const char* rawData, const size_t dataLength);
void deleteTFTPPacket(TFTPPacket* packet); // safely delete packet created from parseTFTPPacket
int getFileDescriptor(char** filename, FileTable* fileTable);
char* serializeTFTPDataPacket(TFTPPacket* packet);

int main() {
    StateTable stateTable;
    stateTable.capacity = MAX_TABLE_ENTRY_COUNT;
    stateTable.size = 0;
    memset(stateTable.entries, 0, stateTable.capacity * sizeof(StateTableEntry));

    FileTable fileTable;
    fileTable.size = 0;
    fileTable.capacity = MAX_TABLE_ENTRY_COUNT;
    memset(fileTable.files, 0, fileTable.capacity * sizeof(FileInfo));

    int entrySocketDescriptor; // port 69
    int replySocketDescriptor; // port 42069
    
    addrinfo hints;

    // Get address info for inSocket
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    entrySocketDescriptor = createAndBindSocket(&hints, NULL, INCOMING_PORT);
    printf("Successfully created inSocket\n");
    replySocketDescriptor = createAndBindSocket(&hints, NULL, OUTGOING_PORT);
    printf("Successfully created outSocket\n");

    fd_set readfdsMaster;
    fd_set readfds;
    int maxfds = (entrySocketDescriptor > replySocketDescriptor) ? entrySocketDescriptor : replySocketDescriptor;

    FD_ZERO(&readfdsMaster);
    FD_ZERO(&readfds);
    FD_SET(entrySocketDescriptor, &readfdsMaster);
    FD_SET(replySocketDescriptor, &readfdsMaster);

    char inBuffer[MAX_IN_BUFFER_SIZE];
    memset(inBuffer, 0, MAX_IN_BUFFER_SIZE);

    // main loop
    for(;;) {
        readfds = readfdsMaster;
        printf("Listening for requests/acks\n");
        int returnCode = select(maxfds+1, &readfds, NULL, NULL, NULL);
        printf("select returned\n");
        if(returnCode == -1) {
            perror("select");
            close(entrySocketDescriptor);
            close(replySocketDescriptor);
            exit(SELECT_FAILURE);
        }

        sockaddr_storage from;
        socklen_t addressSize = sizeof(from);
	unsigned int flags = 0;
        // Port 69 has available data meaning a new request
        if(FD_ISSET(entrySocketDescriptor, &readfds)) {
            int bytesReceived = recvfrom(entrySocketDescriptor, inBuffer, MAX_IN_BUFFER_SIZE-1, flags, (sockaddr*)&from, &addressSize);
            printf("recvfrom returned\n");
            if(bytesReceived == -1) {
                perror("recvfrom");
                close(entrySocketDescriptor);
                close(replySocketDescriptor);
                exit(RECVFROM_FAILURE);
            }
            printf("addressSize: %d\n", addressSize);
            printf("sizeof(from): %d\n", sizeof(from));
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
            entry.lastInteraction = time(NULL);

            // filename (and maybe mode) should be authoritatively held by the file table
            // TODO copy the string contents to a newly malloc'd one and free this one
            TFTPPacket packet = parseTFTPPacket(inBuffer, bytesReceived);
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

            printf("Attempting to get file descriptor\n");
            int file = getFileDescriptor(&entry.filename, &fileTable);
            printf("Got file descriptor: %d\n", file);

            FileInfo fileinfo;
            fileinfo.filename = entry.filename;
            fileinfo.file = file;

            int bytesPread = 0; 
            memset(response.data, 0, MAX_FILE_DATA);
            bytesPread = pread(file, response.data, MAX_FILE_DATA, 0);
            if (bytesPread == -1) {
		        fprintf(stdout, "cringe!%s\r\n", response.data); // musn't do this
                perror("pread");
                close(entrySocketDescriptor);
                close(replySocketDescriptor);
                exit(PREAD_FAILURE);
            }

	    response.dataLength = bytesPread;
            
            void* serializedResponse = serializeTFTPDataPacket(&response);
            printf("addressSize: %d\n", addressSize);
            printf("serializedResponse: %p\n", serializedResponse);
            printf("buffer size: %d\n", bytesPread + 4);
            sockaddr_in* temp = (sockaddr_in*)&from;
            printf("ip port: %d %d\n", temp->sin_addr.s_addr, temp->sin_port);

            int bytesSent = sendto(replySocketDescriptor, serializedResponse, bytesPread + 4, flags, (sockaddr*)&from, addressSize);
            //  TODO Need to something about partial sends, consult with RFC 1350 spec
            if (bytesSent == -1) {
                perror("sendto");
                close(entrySocketDescriptor);
                close(replySocketDescriptor);
                exit(SENDTO_FAILURE);
            }
            free(serializedResponse);
        }
        
        // Port 42069 has available data meaning an acknowledgement of data receipt
        if(FD_ISSET(replySocketDescriptor, &readfds)) {
            addressSize = sizeof(from);
            printf("replySocket is read-to-read\n");
	    memset(inBuffer, 0, sizeof(inBuffer));
            int bytesReceived = recvfrom(replySocketDescriptor, inBuffer, MAX_IN_BUFFER_SIZE-1, flags, (sockaddr*)&from, &addressSize);
            printf("replySocket recvfrom returned, bytes received: %d\n", bytesReceived);
            if(bytesReceived == -1) {
                perror("recvfrom");
                close(entrySocketDescriptor);
                close(replySocketDescriptor);
                exit(RECVFROM_FAILURE);
            }
            TFTPPacket packet = parseTFTPPacket(inBuffer, bytesReceived);

            printf("packet opcode: %u\n", packet.opcode);
            if (packet.opcode == (unsigned short)-1) {
                // handle this
                close(entrySocketDescriptor);
                close(replySocketDescriptor);
                exit(1);
            }

            if (packet.opcode != 4) {
                //handle this
                close(entrySocketDescriptor);
                close(replySocketDescriptor);
                exit(RECVFROM_FAILURE);
            }
            
            // Search for client in the state table
            StateTableEntry* currentEntry = NULL;
            printf("size of state table: %d\n", stateTable.size);
            for(int i = 0; i < stateTable.size; ++i) {
                currentEntry = &stateTable.entries[i];
                // blame Jackson
                printf("comp a: %d\n", ((sockaddr_in*)&(currentEntry->addressInfo))->sin_addr.s_addr);
                printf("comp b: %d\n", ((sockaddr_in*)&from)->sin_addr.s_addr);
                printf("block comparison: %d vs. %d\n", currentEntry->block, packet.block);
                if(((sockaddr_in *) &(currentEntry->addressInfo))->sin_addr.s_addr == ((sockaddr_in *) &from)->sin_addr.s_addr && currentEntry->block == packet.block) {
                    break;
                }
                currentEntry = NULL;
            }

            // Client was acknowledeing something but we don't know the client
            if (!currentEntry) {
                printf("Ack from unknown\n");
                // handle this :)
                close(entrySocketDescriptor);
                close(replySocketDescriptor);
                exit(RECVFROM_FAILURE);
            }
            
            // Begin sending file
            TFTPPacket response;
            response.opcode = 3;
            response.block = currentEntry->block;
            printf("Attempting to get file descriptor\n"); 
            int file = getFileDescriptor(&currentEntry->filename, &fileTable);
            printf("Got file descriptor: %d\n", file);
            // Keep track of an empty spot
            /*int file = -1;
            for (int i = 0; i < fileTable.size; ++i) {
                FileInfo currentFileInfo = fileTable.files[i]; 
                if (strcmp(currentFileInfo.filename, currentEntry->filename)) {
                    file = currentFileInfo.file;
                    break;
                }
            }*/
            
            if (file == -1) {
                // fail if file got moved or something
                exit(1);
            }

            FileInfo fileinfo;
            fileinfo.filename = currentEntry->filename;
            fileinfo.file = file;

            int bytesPread = 0; 
            memset(response.data, 0, MAX_FILE_DATA);
	    off_t offset = currentEntry->block++ * MAX_FILE_DATA;
            response.block = currentEntry->block;
            printf("Preading\n");
            bytesPread = pread(file, response.data, MAX_FILE_DATA, offset);
            if (bytesPread == -1) {
		        fprintf(stdout, "cringe!%s\r\n", response.data);
                perror("pread");
                close(entrySocketDescriptor);
                close(replySocketDescriptor);
                exit(PREAD_FAILURE);
            }

	        response.dataLength = bytesPread;
            
            void* serializedResponse = serializeTFTPDataPacket(&response);

            int bytesSent = sendto(replySocketDescriptor, serializedResponse, bytesPread + 4, flags, (sockaddr*)&from, addressSize);
            // do something if the bytes sent do not equal bytesPread + 4
	        if (bytesSent == -1) {
                perror("sendto");
                close(entrySocketDescriptor);
                close(replySocketDescriptor);
                exit(SENDTO_FAILURE);
            }

            free(serializedResponse);

	    //currentEntry->block = packet.block;
            currentEntry->lastInteraction = time(NULL);
        }
    }

    // clear our the file table which should hold the malloc'd filenames

    close(entrySocketDescriptor);
    close(replySocketDescriptor);
    
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

    int status = getaddrinfo(host, port, hints, &addressInfoList);
    if(status != 0) {
        printf("getaddrinfo: %s\n", gai_strerror(status));
        exit(GETADDRINFO_FAILURE);
    }

    // iterate thru addressInfoList and use first valid entry to create socket
    for(addressInfo = addressInfoList; addressInfo != NULL; addressInfo = addressInfo->ai_next) {
        socketDescriptor = socket(addressInfo->ai_family, addressInfo->ai_socktype, addressInfo->ai_protocol);
        if(socketDescriptor == -1) {
            printf("call to socket() failed\n");
            continue;
        }

        int returnCode = bind(socketDescriptor, addressInfo->ai_addr, addressInfo->ai_addrlen);
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
    // Vanquish anyone who has timed out
    time_t currentTime = time(NULL);
    for(int i = 0; i < stateTable->size; i++) {
        if(currentTime - stateTable->entries[i].lastInteraction >= TIMEOUT_DURATION) {
            return i;
        }
    }

    // If the table is still not at capacity then expand
    if(stateTable->size < stateTable->capacity) {
        return stateTable->size++;
    }

    return -1;
}

uint16_t reverseBytesShort(uint16_t s) {
    uint16_t temp = s;
    s <<= 8;
    s -= 0xFF00;
    s |= (temp >> 8) & 0xFF;
    return s;
}

TFTPPacket parseTFTPPacket(const char* rawData, const size_t rawDataLength) {
    // For TFTP protocol breakdown see RFC 1350: https://datatracker.ietf.org/doc/html/rfc1350.html
    
    TFTPPacket packet;
    packet.opcode = -1;
    size_t dataParsed = 0;
    
    // First 2 bytes in TFTP packet are always the opcode
    if(rawDataLength >= dataParsed + 2) {
        uint16_t* opcodePointer = (uint16_t*)rawData;
        uint16_t opcode = *opcodePointer;
        //packet.opcode = reverseBytesShort(ntohs(opcode));
        packet.opcode = ntohs(opcode);
        dataParsed += 2;
    }

    // opcode 1/2: read/write request -> opcode(2) filename(n) null mode(m) null
    if(packet.opcode == 1 || packet.opcode == 2) {
        // +1's are for null character at end of string
        // Parse filename
        if(rawDataLength >= dataParsed + 1) {
            size_t filenameLength = strlen(rawData + dataParsed);
            packet.filename = (char*)malloc(filenameLength + 1);
            memcpy(packet.filename, rawData + dataParsed, filenameLength);
            packet.filename[filenameLength] = '\0';
            dataParsed += filenameLength + 1;
        }

        // Parse mode
        if(rawDataLength >= dataParsed + 1) {
            size_t modeLength = strlen(rawData + dataParsed);
            packet.mode = (char*)malloc(modeLength + 1);
            memcpy(packet.mode, rawData + dataParsed, modeLength);
            packet.mode[modeLength] = '\0';
            dataParsed += modeLength + 1;
        }
    }
    // opcode 3: data packet -> opcode(2) block#(2) data(n)
    else if(packet.opcode == 3) {
        // Parse block#
        if(rawDataLength >= dataParsed + 2) {
            uint16_t* blockPointer = (uint16_t*)(rawData + 2);
            uint16_t block = *blockPointer;
            //packet.block = reverseBytesShort(ntohs(block));
            packet.block = ntohs(block);
            dataParsed += 2;
        }
        // Parse data
        if(rawDataLength - dataParsed > 0) {
            size_t dataLength = rawDataLength - dataParsed;
            //packet.data = (char*)malloc(dataLength);
            memcpy(packet.data, rawData + dataParsed, dataLength);
            packet.dataLength = dataLength;
            dataParsed += dataLength;
        }
    }
    // opcode 4: ack packet -> opcode(2) block#(2)
    else if(packet.opcode == 4) {
        // Parse block#
        if(rawDataLength >= dataParsed + 2) {
            uint16_t* blockPointer = (uint16_t*)(rawData + 2);
            uint16_t block = *blockPointer;
            //packet.block = reverseBytesShort(ntohs(block));
            packet.block = ntohs(block);
            dataParsed += 2;
        }
    }
    else if(packet.opcode == 5) {
        // TODO implement error packet parsing
    }
    else {
        // TODO error out due to invalid packet
    }

    return packet;
}

void deleteTFTPPacket(TFTPPacket* packet) {
    if(packet == NULL) {
        return;
    }

    if(packet->opcode == 1 || packet->opcode == 2) {
        free(packet->filename); // Might cause issue, fingers are crossed
        free(packet->mode);
    }
    else if(packet->opcode == 3) {
        //free(packet->data);
    }
}

int getFileDescriptor(char** filename, FileTable* fileTable) {
    // Keep track of an empty spot
    int file = -1;
    int index = -1;
    for(int i = 0; i < fileTable->size; i++) {
        FileInfo currentFileInfo = fileTable->files[i]; 

        // check if we already have the file
        if(strcmp(currentFileInfo.filename, *filename)) {
            file = currentFileInfo.file;
            break;
        }

        // check if the slot is free
        if(currentFileInfo.filename == NULL) {
            index = i;
            break;
        }
    }
    printf("in getFileDescriptor, index, file: %d %d\n", index, file);

    if (file == -1) {
        // need to ensure we close this eventually
        // TODO handle case where file doesn't open (ex. file not found)
        file = open(*filename, O_RDONLY, 0777);
        
        // stick in table
        FileInfo addFileInfo;
        addFileInfo.file = file;

        // we want to transfer ownership of filename to the FileTable
        size_t filenameLength = strlen(*filename);
        addFileInfo.filename = (char*)malloc(filenameLength + 1);
        strcpy(addFileInfo.filename, *filename);
        free(*filename);
        *filename = NULL;
        filename = &addFileInfo.filename;
        
        // if we didn't find any free slots then expand the array
        if(index == -1) {
            index = fileTable->size;
            fileTable->size++;
        }

        fileTable->files[index] = addFileInfo;
    }
    return file;
}

char* serializeTFTPDataPacket(TFTPPacket* packet) {
    char* serializedData = NULL;
    if(packet->opcode == 3) {
        serializedData = (char*)malloc(2 + 2 + packet->dataLength); 
        uint16_t opcode = htons(packet->opcode);
	    uint16_t blockNum = htons(packet->block);
	    memcpy(serializedData, (char*)&opcode, 2);
	    memcpy(serializedData + 2, (char*)&blockNum, 2);
	    memcpy(serializedData + 4, packet->data, packet->dataLength);
    }
    // TODO do something about non-data packets
    return serializedData;
}
