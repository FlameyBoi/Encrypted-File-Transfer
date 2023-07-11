#define _CRT_SECURE_NO_WARNINGS
#include <stdexcept>
#include <cstdint>
#include <string.h>
#include "defs.hpp"


//Note that no error handling should be handled here - validity of arguments should be checked by the calling function
// generate payload for register request
std::string registerRequest(void* args, unsigned int argc) // Register request used in case me.info doesn't exist or has incomplete info
{
	if (argc != 1) throw std::invalid_argument("Number of arguments doesn't match request type");
	char temparr[NAME_SIZE];
	strncpy(temparr, (*(char**)args), NAME_SIZE); // strncpy handles 0 padding unless copied string was longer
	temparr[NAME_SIZE - 1] = '\0'; // Make sure name is null terminated
	std::string request(&temparr[0], &temparr[0] + NAME_SIZE); // This guarantees NAME_SIZE chars are copied
	return request;
}

//generate payload for send key request
std::string keyRequest(void* args, unsigned int argc) // Key request includes client name and public key that will be used to encrypt the private key
{
	if (argc != 2) throw std::invalid_argument("Number of arguments doesn't match request type");
	char temparr1[NAME_SIZE];
	char temparr2[KEY_SIZE];
	memcpy(temparr1, (*(char**)args), NAME_SIZE);
	memcpy(temparr2 , (*((char**)args + 1)), KEY_SIZE);
	temparr1[NAME_SIZE - 1] = '\0'; // make sure name is null terminated
	std::string request(&temparr1[0],&temparr1[0] + NAME_SIZE); // This guarantees NAME_SIZE chars are copied
	request.append(std::string(& temparr2[0], &temparr2[0] + KEY_SIZE));
	return request;
}

//generate payload for reconnect request
std::string connectRequest(void* args, unsigned int argc) // Equivalent to registering in terms of payload
{
	return registerRequest(args, argc);
}

//generate payload for send file request
std::string fileRequest(void* args, unsigned int argc) // File itself is handled separately
{
	if (argc != 2) throw std::invalid_argument("Number of arguments doesn't match request type");
	char temparr[SIZE_SIZE + NAME_SIZE]; 
	memcpy(temparr, (*(char**)args), SIZE_SIZE);  // memcpy used to ignore null values
	memcpy(temparr + SIZE_SIZE, (*((char**)args + 1)), NAME_SIZE); // memcpy used to ignore null values
	temparr[SIZE_SIZE + NAME_SIZE - 1] = '\0'; // make sure name is null terminated
	std::string request(&temparr[0], &temparr[0] + SIZE_SIZE + NAME_SIZE); // copy all ignoring nulls
	return request;
}

 std::string ackRequest(void* args, unsigned int argc) // Equivalent to registering in terms of payload
{
	return registerRequest(args, argc);
}

std::string nackRequest(void* args, unsigned int argc) // Equivalent to registering in terms of payload
{
	return registerRequest(args, argc);
}

std::string failRequest(void* args, unsigned int argc) // Equivalent to registering in terms of payload
{
	return registerRequest(args, argc);
}

//picks correct request generation function based on code
std::string generateRequest(uint16_t code, void* args, unsigned int argc)
{
	switch (code)
	{
	case REGISTER:
		return registerRequest(args, argc);
	case SEND_KEY:
		return keyRequest(args, argc);
	case RECONNECT:
		return connectRequest(args, argc);
	case SEND_FILE:
		return fileRequest(args, argc);
	case CRC_ACK:
		return ackRequest(args, argc);
	case CRC_NACK:
		return nackRequest(args, argc);
	case CRC_FAIL:
		return failRequest(args, argc);
	default:
		throw std::invalid_argument("Invalid request code");
	}
}
#undef _CRT_SECURE_NO_WARNINGS