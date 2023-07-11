
#define _CRT_SECURE_NO_WARNINGS
#include "HeaderHandler.hpp"
#include <string.h>

// creates Client Header with given params
Header generateHeader(const char* UID, uint16_t code, uint32_t size)
{
	Header header;
	strncpy(header.UID, UID, UID_SIZE);
	header.code = code;
	header.size = size;
	header.version = CLIENT_VER;
	return header;
}
#undef _CRT_SECURE_NO_WARNINGS