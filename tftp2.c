/* The TFTP protocol originates from RFC 1350 however it has received updates 
 * at some point. See "Updated by" links for details about extensions such as
 * options and option acknowledgements. 
 * RFC 1350: https://datatracker.ietf.org/doc/html/rfc1350
 */

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
#define STATE_TABLE_ERROR 7
#define UNEXPECTED_OPCODE 8
#define FILE_IO_ERROR 9

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
    char* filename; // should be null terminated
    char* mode; // unused currently // should be null terminated
    uint16_t block;
    char data[MAX_FILE_DATA];
    size_t dataLength;
    uint16_t errorCode;
    char* errorMessage; // should be null terminated
} TFTPPacket;

typedef struct {
    char* filename;
    int file;
    time_t lastInteraction;
} FileInfo;

typedef struct {
    FileInfo files[MAX_TABLE_ENTRY_COUNT];
    size_t capacity;
    size_t size;
} FileTable;

int createAndBindSocket(const addrinfo* hints, const char* host, const char* port);
int getFreeStateTableEntry(StateTable* stateTable);
TFTPPacket parseTFTPPacket(const char* rawData, const size_t dataLength);
void deleteTFTPPacket(TFTPPacket* packet); // safely delete packet created from parseTFTPPacket
int getFileDescriptor(char* filename, FileTable* fileTable);
char* serializeTFTPPacket(TFTPPacket* packet, size_t* byteCount);
TFTPPacket createErrorPacket(unsigned short errorCode, char* errorMessage);
void _crash(int errorCode, const char* erroredFunction, int* socketDescriptors, int socketDescriptorCount, FileTable* fileTable, const char* file, int line);
int sendErrorPacket(unsigned short errorCode, char* errorMessage, int socket, sockaddr* recipient, socklen_t addressSize);

#define crash(errorCode, erroredFunction, socketDescriptors, socketDescriptorCount, fileTable) \
    _crash(errorCode, erroredFunction, socketDescriptors, socketDescriptorCount, fileTable, __FILE__, __LINE__)

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
    int socketDescriptors[] = {entrySocketDescriptor, replySocketDescriptor};
    int socketDescriptorCount = 2;

    fd_set readfdsMaster; // read-only set for copying each iteration
    fd_set readfds;
    int maxfd = (entrySocketDescriptor > replySocketDescriptor) ? entrySocketDescriptor : replySocketDescriptor;

    FD_ZERO(&readfdsMaster);
    FD_ZERO(&readfds);
    FD_SET(entrySocketDescriptor, &readfdsMaster);
    FD_SET(replySocketDescriptor, &readfdsMaster);

    char inBuffer[MAX_IN_BUFFER_SIZE];
    memset(inBuffer, 0, MAX_IN_BUFFER_SIZE);

    // main loop
    while(true) {
        readfds = readfdsMaster;
        printf("Listening for requests/acks\n");
        int returnCode = select(maxfd+1, &readfds, NULL, NULL, NULL);
        printf("select returned\n");
        if(returnCode == -1) {
            crash(SELECT_FAILURE, "select", socketDescriptors, socketDescriptorCount, &fileTable);
        }

        sockaddr_storage from;
        socklen_t addressSize = sizeof(from);
	    unsigned int flags = 0;

        // Port 69 has available data meaning a new request
        if(FD_ISSET(entrySocketDescriptor, &readfds)) {
            int bytesReceived = recvfrom(entrySocketDescriptor, inBuffer, MAX_IN_BUFFER_SIZE-1, flags, (sockaddr*)&from, &addressSize);
            printf("recvfrom returned\n");
            
            if(bytesReceived == -1) {
                crash(RECVFROM_FAILURE, "recvfrom", socketDescriptors, socketDescriptorCount, &fileTable);
            }
            printf("addressSize: %d\n", addressSize);
            printf("sizeof(from): %d\n", sizeof(from));

            inBuffer[bytesReceived] = '\0'; // end with null for string parsing safety

            int stateTableEntryIndex = getFreeStateTableEntry(&stateTable);
            if(stateTableEntryIndex == -1) {
                // Send out an error packet and crash
                char* errorMessage = "No state table entry found. Table may be full.";
                int bytesSent = sendErrorPacket(0, errorMessage, replySocketDescriptor, (sockaddr*)&from, addressSize);
                if (bytesSent == -1) {
                    crash(SENDTO_FAILURE, "sendto", socketDescriptors, socketDescriptorCount, &fileTable);
                }

                printf("No state table entry found. Table may be full: table size: %d\n", stateTable.size);
                crash(STATE_TABLE_ERROR, NULL, socketDescriptors, socketDescriptorCount, &fileTable);
            }

            // Create a new entry in the StateTable based on data in the request            
            StateTableEntry entry;
            entry.addressInfo = from;
            entry.addressSize = addressSize;
            entry.lastInteraction = time(NULL);

            TFTPPacket packet = parseTFTPPacket(inBuffer, bytesReceived);
            if(packet.opcode != 1) {
                // Send out an error packet and crash
                char* errorMessage = "Received opcode other than 1 on port 69.";
                int bytesSent = sendErrorPacket(0, errorMessage, replySocketDescriptor, (sockaddr*)&from, addressSize);
                if (bytesSent == -1) {
                    crash(SENDTO_FAILURE, "sendto", socketDescriptors, socketDescriptorCount, &fileTable);
                }
                
                crash(UNEXPECTED_OPCODE, NULL, socketDescriptors, socketDescriptorCount, &fileTable);
            }

            entry.filename = packet.filename;
            entry.mode = packet.mode;
            entry.block = 1;

            stateTable.entries[stateTableEntryIndex] = entry;

            // Begin sending file
            TFTPPacket response;
            response.opcode = 3;
            response.block = entry.block;

            printf("filename pointer check 1, entry vs packet: %p %p\n", entry.filename, packet.filename);

            printf("Attempting to get file descriptor\n");
            int file = getFileDescriptor(entry.filename, &fileTable);
            printf("Got file descriptor: %d\n", file);

            printf("filename pointer check 2, entry vs packet: %p %p\n", entry.filename, packet.filename);

            int bytesPread = 0; 
            memset(response.data, 0, MAX_FILE_DATA);
            bytesPread = pread(file, response.data, MAX_FILE_DATA, 0);
            if (bytesPread == -1) {
                // Send out an error packet and crash
                char* errorMessage = "Failure in call to pread.";
                int bytesSent = sendErrorPacket(0, errorMessage, replySocketDescriptor, (sockaddr*)&from, addressSize);
                if (bytesSent == -1) {
                    crash(SENDTO_FAILURE, "sendto", socketDescriptors, socketDescriptorCount, &fileTable);
                }
                
                crash(PREAD_FAILURE, "pread", socketDescriptors, socketDescriptorCount, &fileTable);
            }

	        response.dataLength = bytesPread;
            
            void* serializedResponse = serializeTFTPPacket(&response, NULL);

            printf("addressSize: %d\n", addressSize);
            printf("serializedResponse: %p\n", serializedResponse);
            printf("buffer size: %d\n", bytesPread + 4);
            sockaddr_in* temp = (sockaddr_in*)&from; // just for print debugging purposes
            printf("ip port: %d %d\n", temp->sin_addr.s_addr, temp->sin_port);

            int bytesSent = sendto(replySocketDescriptor, serializedResponse, bytesPread + 4, flags, (sockaddr*)&from, addressSize);
            //  TODO Need to do something about partial sends, consult with RFC 1350 spec
            if (bytesSent == -1) {
                // Send out an error packet and crash
                char* errorMessage = "Failure in sending response to initial request.";
                int bytesSent = sendErrorPacket(0, errorMessage, replySocketDescriptor, (sockaddr*)&from, addressSize);
                if (bytesSent == -1) {
                    crash(SENDTO_FAILURE, "sendto", socketDescriptors, socketDescriptorCount, &fileTable);
                }
                
                crash(SENDTO_FAILURE, "sendto", socketDescriptors, socketDescriptorCount, &fileTable);
            }
            free(serializedResponse);
        }
        
        // Port 42069 has available data meaning an acknowledgement of data receipt
        if(FD_ISSET(replySocketDescriptor, &readfds)) {
            printf("replySocket is read-to-read\n");

            addressSize = sizeof(from);
	        memset(inBuffer, 0, sizeof(inBuffer));
            int bytesReceived = recvfrom(replySocketDescriptor, inBuffer, MAX_IN_BUFFER_SIZE-1, flags, (sockaddr*)&from, &addressSize);
            printf("replySocket recvfrom returned, bytes received: %d\n", bytesReceived);
            if(bytesReceived == -1) {
                // Send out an error packet and crash
                char* errorMessage = "Encountered error when receiving data.";
                int bytesSent = sendErrorPacket(0, errorMessage, replySocketDescriptor, (sockaddr*)&from, addressSize);
                if (bytesSent == -1) {
                    crash(SENDTO_FAILURE, "sendto", socketDescriptors, socketDescriptorCount, &fileTable);
                }
                
                crash(RECVFROM_FAILURE, "recvfrom", socketDescriptors, socketDescriptorCount, &fileTable);
            }

            TFTPPacket packet = parseTFTPPacket(inBuffer, bytesReceived);

            printf("packet opcode: %u\n", packet.opcode);
            if (packet.opcode == (unsigned short)-1) {
                // Send out an error packet and crash
                char* errorMessage = "Received packet with unexpected opcode. Failure parsing packet.";
                int bytesSent = sendErrorPacket(0, errorMessage, replySocketDescriptor, (sockaddr*)&from, addressSize);
                if (bytesSent == -1) {
                    crash(SENDTO_FAILURE, "sendto", socketDescriptors, socketDescriptorCount, &fileTable);
                }
                
                crash(UNEXPECTED_OPCODE, NULL, socketDescriptors, socketDescriptorCount, &fileTable);
            }

            if (packet.opcode != 4) {
                printf("ReplySocket received with opcode other than 4\n");
                // Send out an error packet and crash
                char* errorMessage = "Received packet with unexpected opcode.";
                int bytesSent = sendErrorPacket(0, errorMessage, replySocketDescriptor, (sockaddr*)&from, addressSize);
                if (bytesSent == -1) {
                    crash(SENDTO_FAILURE, "sendto", socketDescriptors, socketDescriptorCount, &fileTable);
                }
                
                crash(UNEXPECTED_OPCODE, NULL, socketDescriptors, socketDescriptorCount, &fileTable);
            }
            
            // Search for client in the state table
            // client is identified by a matching IP and Port
            printf("Searching state table. Size of state table: %d\n", stateTable.size);
            StateTableEntry* currentEntry = NULL;
            for(int i = 0; i < stateTable.size; ++i) {
                currentEntry = &stateTable.entries[i];
                printf("comp a: %d\n", ((sockaddr_in*)&(currentEntry->addressInfo))->sin_addr.s_addr);
                printf("comp b: %d\n", ((sockaddr_in*)&from)->sin_addr.s_addr);
                printf("block comparison: %d vs. %d\n", currentEntry->block, packet.block);
                // blame Jackson
                if(((sockaddr_in *) &(currentEntry->addressInfo))->sin_addr.s_addr == ((sockaddr_in *) &from)->sin_addr.s_addr && currentEntry->block == packet.block) {
                    printf("Found matching entry, filename, mode: %s, %s\n", currentEntry->filename, currentEntry->mode);
                    break;
                }
                currentEntry = NULL;
            }

            // Client was acknowledeing something but we don't know the client
            if (!currentEntry) {
                printf("Ack from unknown\n");
                printf("Couldn't find client in StateTable\n");
                // Send out an error packet and crash
                char* errorMessage = "Client not found in state table.";
                int bytesSent = sendErrorPacket(0, errorMessage, replySocketDescriptor, (sockaddr*)&from, addressSize);
                if (bytesSent == -1) {
                    crash(SENDTO_FAILURE, "sendto", socketDescriptors, socketDescriptorCount, &fileTable);
                }
                
                crash(STATE_TABLE_ERROR, NULL, socketDescriptors, socketDescriptorCount, &fileTable);
            }
            
            // Sending file contents
            TFTPPacket response;
            response.opcode = 3;
            response.block = currentEntry->block;
            printf("Attempting to get file descriptor. Looking for: %s\n", currentEntry->filename); 
            int file = getFileDescriptor(currentEntry->filename, &fileTable);
            printf("Got file descriptor: %d\n", file);
            
            if (file == -1) {
                // fail if file got moved or something
                printf("File descriptor is invalid\n");

                // Send out an error packet and crash
                char* errorMessage = "Encountered file I/O error.";
                int bytesSent = sendErrorPacket(0, errorMessage, replySocketDescriptor, (sockaddr*)&from, addressSize);
                if (bytesSent == -1) {
                    crash(SENDTO_FAILURE, "sendto", socketDescriptors, socketDescriptorCount, &fileTable);
                }
                
                crash(FILE_IO_ERROR, NULL, socketDescriptors, socketDescriptorCount, &fileTable);
            }

            int bytesPread = 0; 
            memset(response.data, 0, MAX_FILE_DATA);
	        off_t offset = currentEntry->block++ * MAX_FILE_DATA;
            response.block = currentEntry->block;
            printf("Preading\n");
            bytesPread = pread(file, response.data, MAX_FILE_DATA, offset);
            if (bytesPread == -1) {
                // Send out an error packet and crash
                char* errorMessage = "Failure in call to pread.";
                int bytesSent = sendErrorPacket(0, errorMessage, replySocketDescriptor, (sockaddr*)&from, addressSize);
                if (bytesSent == -1) {
                    crash(SENDTO_FAILURE, "sendto", socketDescriptors, socketDescriptorCount, &fileTable);
                }
                
                crash(PREAD_FAILURE, "pread", socketDescriptors, socketDescriptorCount, &fileTable);
            }

	        response.dataLength = bytesPread;
            void* serializedResponse = NULL;
            if(response.dataLength != 0) { 
                serializedResponse = serializeTFTPPacket(&response, NULL);

                int bytesSent = sendto(replySocketDescriptor, serializedResponse, bytesPread + 4, flags, (sockaddr*)&from, addressSize);
                // do something if the bytes sent do not equal bytesPread + 4
	            if (bytesSent == -1) {
                    crash(SENDTO_FAILURE, "sendto", socketDescriptors, socketDescriptorCount, &fileTable);
                }
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
        packet.opcode = -1;
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

int getFileDescriptor(char* filename, FileTable* fileTable) {
    // Keep track of an empty spot
    printf("Attempting to get file: %s\n", filename);
    printf("FileTable contents:\n");
    for(int i = 0; i < fileTable->size; i++) {
        printf("FileInfo: %d %s\n", fileTable->files[i].file, fileTable->files[i].filename);
    }
    int file = -1;
    int index = -1;
    for(int i = 0; i < fileTable->size; i++) {
        FileInfo currentFileInfo = fileTable->files[i]; 

        // check if we already have the file
	    if(strcmp(currentFileInfo.filename, filename) == 0) {
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
        file = open(filename, O_RDONLY, 0777);
        
        // stick in table
        FileInfo addFileInfo;
        addFileInfo.file = file;
        addFileInfo.filename = filename;
        
        // if we didn't find any free slots then expand the array
        if(index == -1) {
            index = fileTable->size;
            fileTable->size++;
        }

        fileTable->files[index] = addFileInfo;
    }
    return file;
}

char* serializeTFTPPacket(TFTPPacket* packet, size_t* byteCount) {
    char* serializedData = NULL;
    size_t serializedSize = 0;
    if(packet->opcode == 3) {
        serializedSize = 2 + 2 + packet->dataLength;
        serializedData = (char*)malloc(serializedSize); 
        uint16_t opcode = htons(packet->opcode);
	    uint16_t blockNum = htons(packet->block);
	    memcpy(serializedData, (char*)&opcode, 2);
	    memcpy(serializedData + 2, (char*)&blockNum, 2);
	    memcpy(serializedData + 4, packet->data, packet->dataLength);
    }
    else if(packet->opcode == 5) {
        size_t errorMessageLength = strlen(packet->errorMessage) + 1;
        size_t serializedSize = 2 + 2 + errorMessageLength;
        serializedData = (char*)malloc(serializedSize);
        uint16_t opcode = htons(packet->opcode);
        uint16_t errorCode = htons(packet->errorCode);
        memcpy(serializedData, (char*)&opcode, 2);
        memcpy(serializedData + 2, (char*)&errorCode, 2);
        memcpy(serializedData + 4, packet->errorMessage, errorMessageLength);
    }

    // TODO do something about unimplemented opcode packets

    if(byteCount != NULL) {
        *byteCount = serializedSize;
    }
    return serializedData;
}

TFTPPacket createErrorPacket(unsigned short errorCode, char* errorMessage) {
    TFTPPacket packet;
    packet.opcode = 5;
    packet.errorCode = errorCode;
    packet.errorMessage = errorMessage;
}

void _crash(int errorCode, const char* erroredFunction, int* socketDescriptors, int socketDescriptorCount, FileTable* fileTable, const char* file, int line) {
    if(erroredFunction != NULL) {
        perror(erroredFunction);
    }

    if(file != NULL) {
        printf("[ERROR] (%s, %d)\n", file, line);
    }

    if(socketDescriptors != NULL) {
        for(int i = 0; i < socketDescriptorCount; i++) {
            close(socketDescriptors[i]);
        }
    }

    if(fileTable != NULL) {
        // TODO gracefully clean up file handles
    }

    exit(errorCode);
}

int sendErrorPacket(unsigned short errorCode, char* errorMessage, int socket, sockaddr* recipient, socklen_t addressSize) {
    TFTPPacket errorPacket = createErrorPacket(errorCode, errorMessage);
    size_t packetByteCount;
    void* serializedPacket = serializeTFTPPacket(&errorPacket, &packetByteCount);
    int flags = 0;
    return sendto(socket, serializedPacket, packetByteCount, flags, recipient, addressSize);
}