
#include <cstdint>
#include "defs.hpp"
#include <memory>


// both structs are defined as unpadded so that no undesired padding gets into packets
#pragma pack(push,1)
struct Header
{
	char UID[16];
	uint8_t version : 8;
	uint16_t code : 16;
	uint32_t size : 32;
};

struct ServerHeader
{
	uint8_t version : 8;
	uint16_t code : 16;
	uint32_t size : 32;
};
#pragma pack(pop)

Header generateHeader(const char*, uint16_t , uint32_t);