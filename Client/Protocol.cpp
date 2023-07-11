
#define _CRT_SECURE_NO_WARNINGS
#include "defs.hpp"
#include "boost/lambda/lambda.hpp"
#include "Request.hpp"
#include "Packer.hpp"
#include "Session.hpp"
#include <map>
#include <limits>
#include "rijndael.h"
#include "files.h"
#include "modes.h"
#include "osrng.h"
#include "rsa.h"
#include "hex.h"

#define RETRIES 3
#define PERROR -2000
// Macros used for comm function calling
#define TRY(LABEL,FUNC)\
	LABEL:try\
	{\
		FUNC(s);\
	}\
	catch (std::exception const& error)\
	{\
		std::cout << error.what();\
		throw error;\
	}

#define READ(LABEL,FUNC) \
	try\
	{\
		FUNC(s);\
	}\
	catch (std::exception const& error)\
	{\
		if(retry)\
		{\
			std::cout << "Server responded with error:" << error.what() << std::endl;\
			retry--;\
			goto LABEL;\
		}\
		std::cout << "Fatal error: too many fails giving up:" << error.what() << std::endl;\
		throw error;\
	}


using boost::lambda::var;
using boost::lambda::_1;
using namespace boost::posix_time;

// code map - contains mapping of request to respone and response to next request
// negative responses use the default behavior of retrying hence they aren't mapped
std::map<int, int> codes{ {REGISTER, REGISTER_GOOD}, {RECONNECT, RECONNECT_GOOD}, {SEND_KEY, GOOD_KEY }, {SEND_FILE, GET_CRC},
	{GET_CRC, CRC_ACK},  {REGISTER_GOOD, SEND_KEY}, {RECONNECT_GOOD, SEND_FILE}, {CRC_ACK, ACK}, {GOOD_KEY, SEND_FILE}, {ACK, END} };

std::map<int, int> errcodes{ {REGISTER, REGISTER_BAD}, {RECONNECT, RECONNECT_BAD}, {SEND_KEY, GENERIC_ERROR }, {SEND_FILE, GENERIC_ERROR} };

int packingIndex = 0; // used by packer template

void connect(Session*);
void reconnect(Session*);
void reconnectAck(Session*);
void sendCRCAck(Session*);
void connectAck(Session*);
void sendKey(Session*);
void sendKeyAck(Session*);
void sendFile(Session*);
void sendFileAck(Session*);
void sendCRC(Session*);
inline CryptoPP::lword FileSize(const CryptoPP::FileSource&);

// driving function of protocol, handles retries calling the sequence of comm functions
void runProtocol(Session* s)
{
	Client c = Client(s); 
	s->to = &c;
	unsigned char retry = RETRIES;
	// Macro blocks that handle retries in case of a timeout - if the error is not a timeout it is rethrown
	// Write timeouts are handled by the server's read timing out which is why a sleep is added to the retry handling
	if (s->getConfig()->getFlag())
	{
		TRY(L_RECONNECT,reconnect);
		READ(L_RECONNECT,reconnectAck);
		if (s->getConfig()->getFlag()) goto SENDFILE;
	}
	TRY(CONNECT,connect);
	READ(CONNECT,connectAck);
	TRY(SENDKEY,sendKey);
	READ(SENDKEY,sendKeyAck);
	TRY(SENDFILE,sendFile);
	READ(SENDFILE,sendFileAck);
	TRY(SENDCRC,sendCRC);
	if (s->getRetry()) goto SENDFILE; // Bad Cksum - try re-sending the file
	READ(SENDCRC,sendCRCAck);
}

// Ack functions read response
// Non-Ack functions do the writing

// connect and send registration request
void connect(Session* s)
{
	std::cout << "Attempting to register" << std::endl;
	s->to->connect();
	char UID[UID_SIZE] = { '\0' }; // using an array initialized to 0 just in case
	Header header = generateHeader(UID, REGISTER, NAME_SIZE);
	memcpy(s->getHeaderSent(), &header, HEADER_SIZE);
	char name[NAME_SIZE];
	strncpy(name, s->getConfig()->getName().data(), NAME_SIZE); // guaranteed to be NULL padded
	void* args[REGISTER_ARGS];
	packArgs(args, REGISTER_ARGS, name);
	std::string request = generateRequest(REGISTER, args, REGISTER_ARGS);
	std::vector<boost::asio::mutable_buffer> buffers; // Vector of buffers used to avoid copying overhead needed to combine header and payload into one buffer
	buffers.push_back(boost::asio::buffer(&header, HEADER_SIZE));
	buffers.push_back(boost::asio::buffer(request, NAME_SIZE));
	s->to->write(buffers);
}

// connect and send reconnect request
void reconnect(Session* s)
{
	std::cout << "Attempting to reconnect" << std::endl;
	s->to->connect();
	Header header = generateHeader(s->getConfig()->getUID().data(), RECONNECT, NAME_SIZE);
	memcpy(s->getHeaderSent(), &header, HEADER_SIZE);
	char name[NAME_SIZE];
	strncpy(name, s->getConfig()->getName().data(), NAME_SIZE); // guaranteed to be NULL padded
	void* args[REGISTER_ARGS];
	packArgs(args, REGISTER_ARGS, name);
	std::string request = generateRequest(RECONNECT , args, REGISTER_ARGS);
	std::vector<boost::asio::mutable_buffer> buffers; // Vector of buffers used to avoid copying overhead needed to combine header and payload into one buffer
	buffers.push_back(boost::asio::buffer(&header, HEADER_SIZE));
	buffers.push_back(boost::asio::buffer(request, NAME_SIZE));
	s->to->write(buffers);
}

// get response to reconnect request - if successful set key otherwise attempt registration instead
void reconnectAck(Session* s)
{
	try
	{
		s->to->readHeader();
		if (s->getHeaderRecieved()->code == errcodes[s->getHeaderSent()->code])
		{
			size_t rem = s->getSocket()->available();
			while (rem)
			{
				size_t req = std::min(rem, (size_t)MAX_SIZE);
				s->to->flush(req);
				rem -= req;
			}
			s->getConfig()->flipFlag();
			s->getSocket()->close();
			return;
		}
		if (s->getHeaderRecieved()->code == GENERIC_ERROR) throw std::runtime_error("Server responded with generic error");
		if (s->getHeaderRecieved()->code != codes[s->getHeaderSent()->code]) throw std::runtime_error("Unexpected code in header");
		if (s->getHeaderRecieved()->size > SIZE_MAX) throw std::runtime_error("Bad messasge size");
		s->to->readPayload();
		const char* name = s->getBuffer()->data();
		if (strncmp(name, s->getConfig()->getUID().data(), UID_SIZE)) throw std::runtime_error("Wrong UID");
		s->getConfig()->setUID(*(s->getBuffer())); //Set UID to value recieved from server
		const char* key = s->getBuffer()->data() + UID_SIZE;
		CryptoPP::SecByteBlock block(reinterpret_cast<const CryptoPP::byte*>(key), s->getHeaderRecieved()->size - UID_SIZE);
		s->setAES(block);
		std::cout << "Reconnect success" << std::endl;
	}
	catch (std::exception const& error)
	{
		size_t rem = s->getSocket()->available();
		while (rem)
		{
			size_t req = std::min(rem, (size_t)MAX_SIZE);
			s->to->flush(req);
			rem -= req;
		}
		throw error;
	}
}

// get response to registration request - if successful set UID otherwise retry 3 times (if registration error die)
void connectAck(Session* s)
{
	try
	{
		s->to->readHeader();
		if (s->getHeaderRecieved()->code == errcodes[s->getHeaderSent()->code])
		{
			std::cout << "Fatal error: Server responded with registration error, program terminating" << std::endl;
			exit(-1);
		}
		if (s->getHeaderRecieved()->code == GENERIC_ERROR) throw std::runtime_error("Server responded with generic error");
		if (s->getHeaderRecieved()->code != codes[s->getHeaderSent()->code]) throw std::runtime_error("Unexpected code in header");
		if (s->getHeaderRecieved()->size != UID_SIZE) throw std::runtime_error("Bad messasge size");
		s->to->readPayload();
		s->getConfig()->setUID(*(s->getBuffer())); //Set UID to value recieved from server
		std::cout << "Register success" << std::endl;
	}
	catch (std::exception const& error)
	{
		size_t rem = s->getSocket()->available();
		while (rem)
		{
			size_t req = std::min(rem, (size_t)MAX_SIZE);
			s->to->flush(req);
			rem -= req;
		}
		throw error;
	}
}

// generate RSA public private key pair and send public key to server
void sendKey(Session* s)
{
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rng, RSA_SIZE);
	CryptoPP::RSA::PrivateKey privateKey(params);
	CryptoPP::RSA::PublicKey publicKey(params);
	s->getConfig()->setKey(privateKey); // set private key
	std::string spki;
	CryptoPP::StringSink ss(spki);
	// Use Save to DER encode the Subject Public Key Info (SPKI)
	publicKey.DEREncode(ss);
	std::cout << "Generating RSA and sending it over to server" << std::endl;
	Header header = generateHeader(s->getConfig()->getUID().data(), SEND_KEY, NAME_SIZE + KEY_SIZE);
	memcpy(s->getHeaderSent(), &header, HEADER_SIZE);
	char name[NAME_SIZE];
	strncpy(name, s->getConfig()->getName().data(), NAME_SIZE); // guaranteed to be NULL padded
	void* args[SEND_KEY_ARGS];
	char* spki_cstr = new char[spki.length()];
	try
	{
		memcpy(spki_cstr, spki.data(), spki.length());
		packArgs(args, SEND_KEY_ARGS, name, spki_cstr);
		std::string request = generateRequest(SEND_KEY, args, SEND_KEY_ARGS);
		std::vector<boost::asio::mutable_buffer> buffers; // Vector of buffers used to avoid copying overhead needed to combine header and payload into one buffer
		buffers.push_back(boost::asio::buffer(&header, HEADER_SIZE));
		buffers.push_back(boost::asio::buffer(request, NAME_SIZE + KEY_SIZE));
		s->to->write(buffers);
	}
	catch (std::exception const& error) // dispose of dynamic allocation and rethrow exception
	{
		delete[] spki_cstr;
		spki_cstr = NULL;
		throw error;
	}
	delete[] spki_cstr;
}

// receive encrypted AES key decrypt and save it
void sendKeyAck(Session* s)
{
	try
	{
		s->to->readHeader();
		if (s->getHeaderRecieved()->code == GENERIC_ERROR) throw std::runtime_error("Server responded with generic error");
		if (s->getHeaderRecieved()->code != codes[s->getHeaderSent()->code]) throw std::runtime_error("Unexpected code in header");
		if (s->getHeaderRecieved()->size > SIZE_MAX) throw std::runtime_error("Bad messasge size");
		s->to->readPayload();
		const char* name = s->getBuffer()->data();
		if(strncmp(name, s->getConfig()->getUID().data(), UID_SIZE)) throw std::runtime_error("Wrong UID");
		const char* key = s->getBuffer()->data() + UID_SIZE;
		CryptoPP::SecByteBlock block(reinterpret_cast<const CryptoPP::byte*>(key), s->getHeaderRecieved()->size - UID_SIZE);
		s->setAES(block);
		s->getConfig()->keySuccess();
		std::cout << "Got AES, keys successfully generated" << std::endl;
	}
	catch (std::exception const& error)
	{
		size_t rem = s->getSocket()->available();
		while (rem)
		{
			size_t req = std::min(rem, (size_t)MAX_SIZE);
			s->to->flush(req);
			rem -= req;
		}
		throw error;
	}
}

void encryptFile(CryptoPP::SecByteBlock, std::ifstream&);
bool crcCmp(Session* s);

// encrypt file using AES key and send it to server
void sendFile(Session* s)
{
	std::ifstream f;
	f.open(s->getConfig()->getPath(), std::ios::binary | std::ios::in);
	std::string error = "Couldn't open file:" + s->getConfig()->getPath();
	if (!f.is_open()) throw std::runtime_error(error.c_str());
	encryptFile(s->getAES(), f);
	f.close();
	f.open("out.info", std::ios::binary | std::ios::in);
	size_t len = FileSize(CryptoPP::FileSource(f, false)); // calculate file length after encryption
	if (len > (MAX_FILE_SIZE - NAME_SIZE - SIZE_SIZE)) throw std::runtime_error("File is larger than the allowed maximum (4Gb)");
	if (!f.is_open()) throw std::runtime_error("Couldn't read output file");
	s->setLen(len);
	Header header = generateHeader(s->getConfig()->getUID().data(), SEND_FILE, SIZE_SIZE + NAME_SIZE + len);
	memcpy(s->getHeaderSent(), &header, HEADER_SIZE);
	char name[NAME_SIZE];
	size_t pos = s->getConfig()->getPath().find_last_of('\\'); // find beginning of filename
	if (pos == std::string::npos) pos = -1; // if file is in current directory - path is name
	strncpy(name, s->getConfig()->getPath().data() + pos + 1, NAME_SIZE);
	s->setFname(name);
	void* args[SEND_FILE_ARGS];
	packArgs(args, SEND_FILE_ARGS, &len, name);
	std::string request = generateRequest(SEND_FILE, args, SEND_FILE_ARGS);
	std::vector<boost::asio::mutable_buffer> buffers; // Vector of buffers used to avoid copying overhead needed to combine header and payload into one buffer
	buffers.push_back(boost::asio::buffer(&header, HEADER_SIZE));
	buffers.push_back(boost::asio::buffer(request, SIZE_SIZE + NAME_SIZE));
	s->to->write(buffers);
	char out[MAX_SIZE] = { '\0' };
	CryptoPP::FileSource fs(f, false);
	CryptoPP::lword remaining = FileSize(fs); // recalculate FileSize of file after encryption
	std::cout << "Sending file with size:" << remaining << std::endl;
	while (remaining && !f.eof()) // send over file in chunks of at most 1Kb
	{
		unsigned int req = std::min(remaining, (CryptoPP::lword)MAX_SIZE);
		f.read(out, req);
		remaining -= req;
		s->to->write_some(out, req);
	}
	f.close();
}

// read server response to sent file
void sendFileAck(Session* s)
{
	try
	{
		s->to->readHeader();
		if (s->getHeaderRecieved()->code == GENERIC_ERROR) throw std::runtime_error("Server responded with generic error");
		if (s->getHeaderRecieved()->code != codes[s->getHeaderSent()->code]) throw std::runtime_error("Unexpected code in header");
		if (s->getHeaderRecieved()->size != UID_SIZE + SIZE_SIZE + NAME_SIZE + CRC_SIZE) throw std::runtime_error("Bad messasge size");
		s->to->readPayload();
		const char* name = s->getBuffer()->data();
		if (strncmp(name, s->getConfig()->getUID().data(), UID_SIZE)) throw std::runtime_error("Wrong UID");
		size_t size = *(size_t*)(s->getBuffer()->data() + UID_SIZE);
		if (size != s->getLen()) throw std::runtime_error("Wrong file size");
		const char* fname = s->getBuffer()->data() + UID_SIZE + SIZE_SIZE;
	}
	catch (std::exception const& error)
	{
		size_t rem = s->getSocket()->available();
		while (rem)
		{
			size_t req = std::min(rem, (size_t)MAX_SIZE);
			s->to->flush(req);
			rem -= req;
		}
		throw error;
	}
}


// calculate CRC and compare it to the CRC sent by the server - send CRC_ACK if they are equal, CRC_NACK if not
// if sending the file is retried too many times CRC_FAIL
void sendCRC(Session* s)
{
	if (memcmp(s->getConfig()->getUID().data(), s->getBuffer()->data(), UID_SIZE)) throw std::runtime_error("UID mismatch");
	// The following line compares in packet length field to the length of the file sent to the server
	if (s->getLen() != *((int*)(s->getBuffer()->data() + UID_SIZE))) throw std::runtime_error("Length mismatch");
	int pos = s->getConfig()->getPath().find_last_of('\\'); // find beginning of filename
	if (pos == std::string::npos) pos = -1; // if file is in current directory - path is name
	char name[NAME_SIZE];
	strcpy(name, s->getConfig()->getPath().data() + pos + 1);
	if (strncmp(s->getConfig()->getPath().data(), s->getBuffer()->data() + UID_SIZE + SIZE_SIZE, NAME_SIZE)) throw std::runtime_error("File name mismatch");
	std::cout << "Calculating cksum" << std::endl;
	uint16_t success = crcCmp(s) ? CRC_ACK : CRC_NACK ; // cmp Cksum
	if (success == CRC_NACK)
	{
		std::cout << "Error: Server CRC mismatch" << std::endl;
		s->decFail();
		if (s->getFail() == 0)
		{
			std::cout << "Fatal error: 4th bad CRC, terminating" << std::endl;
			success = CRC_FAIL;
			s->setRetry(FALSE);
		}
		else
			s->setRetry(TRUE);
	}
	else std::cout << "Alert: CRC match" << std::endl;
	Header header = generateHeader(s->getConfig()->getUID().data(), success , NAME_SIZE);
	memcpy(s->getHeaderSent(), &header, HEADER_SIZE);
	void* args[SEND_CRC_ARGS];
	packArgs(args, SEND_CRC_ARGS, name);
	std::string request = generateRequest(success, args, REGISTER_ARGS);
	std::vector<boost::asio::mutable_buffer> buffers; // Vector of buffers used to avoid copying overhead needed to combine header and payload into one buffer
	buffers.push_back(boost::asio::buffer(&header, HEADER_SIZE));
	buffers.push_back(boost::asio::buffer(request,NAME_SIZE));
	s->to->write(buffers);
}

// Read server's final message
// it is effectively ignored unless CRC_ACK was last sent in which case we check that server sent ACK
void sendCRCAck(Session* s)
{
	try
	{
		s->to->readHeader();
		if (s->getHeaderRecieved()->code == GENERIC_ERROR) throw std::runtime_error("Server responded with generic error");
		if (s->getHeaderRecieved()->code != codes[s->getHeaderSent()->code]) throw std::runtime_error("Unexpected code in header");
		if (s->getHeaderRecieved()->size != UID_SIZE) throw std::runtime_error("Bad messasge size");
		s->to->readPayload();
		const char* name = s->getBuffer()->data();
		if (strncmp(name, s->getConfig()->getUID().data(), UID_SIZE)) throw std::runtime_error("Wrong UID");
		std::cout << "Got final ack, file is verified" << std::endl;
	}
	catch (std::exception const& error)
	{
		size_t rem = s->getSocket()->available();
		while (rem)
		{
			size_t req = std::min(rem, (size_t)MAX_SIZE);
			s->to->flush(req);
			rem -= req;
		}
		throw error;
	}
}

// util function used for AES encrypting a given file with a given key
void encryptFile(CryptoPP::SecByteBlock key, std::ifstream& fin)
{
	std::ofstream fout;
	fout.open("out.info", std::ios::out | std::ios::binary);
	if (!fout.is_open()) throw std::runtime_error("Couldn't generate output file");
	char zero[CryptoPP::AES::BLOCKSIZE] = { '\0' }; // zeroed iv
	CryptoPP::SecByteBlock iv(reinterpret_cast<const CryptoPP::byte*>(&zero[0]), CryptoPP::AES::BLOCKSIZE);
	CryptoPP::CBC_Mode< CryptoPP::AES >::Encryption e;
	e.SetKeyWithIV(key, key.size(), iv);
	CryptoPP::byte encrypted[CryptoPP::AES::BLOCKSIZE] = { '\0' }; // zero plain text just in case
	// Setting up pipeline from read text to encrypted and encoded text in file
	CryptoPP::FileSource fs(fin, false);
	CryptoPP::StreamTransformationFilter encryptor(e,
		new CryptoPP::FileSink(fout), // mid buffer
		CryptoPP::StreamTransformationFilter::DEFAULT_PADDING); // padding style;
	fs.Attach(new CryptoPP::Redirector(encryptor));
	CryptoPP::lword remaining = FileSize(fs);
	std::cout << "Encrypting file with size:" << remaining << std::endl;
	while (remaining && !fs.SourceExhausted())
	{
		unsigned int req = CryptoPP::STDMIN(remaining, (CryptoPP::lword)CryptoPP::AES::BLOCKSIZE);
		fs.Pump(CryptoPP::AES::BLOCKSIZE);
		encryptor.Flush(false);
		remaining -= req;
	}
	encryptor.MessageEnd();
	fout.close();
}

unsigned long memcrc(std::ifstream& fin);
//Calculate POSIX compliant Cksum and compare to value received from server
bool crcCmp(Session* s)
{
	std::ifstream fin(s->getConfig()->getPath(), std::ios::in | std::ios::binary);
	unsigned long res = memcrc(fin);
	std::cout << "Checksum is:" << res << std::endl;
	return *(unsigned int*)(s->getBuffer()->data() + UID_SIZE + SIZE_SIZE + NAME_SIZE) == res;
}

// start of implementation of POSIX cksum
static unsigned long crctab[] = {
0x00000000,
0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b,
0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f, 0x2f8ad6d6,
0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9, 0x5f15adac,
0x5bd4b01b, 0x569796c2, 0x52568b75, 0x6a1936c8, 0x6ed82b7f,
0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3, 0x709f7b7a,
0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5, 0xbe2b5b58,
0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033,
0xa4ad16ea, 0xa06c0b5d, 0xd4326d90, 0xd0f37027, 0xddb056fe,
0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1, 0xe13ef6f4,
0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077, 0x30476dc0,
0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5,
0x2ac12072, 0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca, 0x7897ab07,
0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb, 0x6f52c06c,
0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1,
0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b,
0xbb60adfc, 0xb6238b25, 0xb2e29692, 0x8aad2b2f, 0x8e6c3698,
0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044, 0x902b669d,
0x94ea7b2a, 0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2, 0xc6bcf05f,
0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34,
0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59, 0x608edb80,
0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f, 0x5c007b8a,
0x58c1663d, 0x558240e4, 0x51435d53, 0x251d3b9e, 0x21dc2629,
0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5, 0x3f9b762c,
0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623, 0xf12f560e,
0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65,
0xeba91bbc, 0xef68060b, 0xd727bbb6, 0xd3e6a601, 0xdea580d8,
0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7, 0xae3afba2,
0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6, 0x9ff77d71,
0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74,
0x857130c3, 0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c, 0x7b827d21,
0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd, 0x6c47164a,
0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e, 0x18197087,
0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d,
0x2056cd3a, 0x2d15ebe3, 0x29d4f654, 0xc5a92679, 0xc1683bce,
0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb,
0xdbee767c, 0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4, 0x89b8fd09,
0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662,
0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06, 0xa6322bdf,
0xa2f33668, 0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};


unsigned long memcrc(std::ifstream& fin)
{
	register unsigned i, c, s = 0;
	int pos;
	fin.seekg(-1, std::ios::end);
	pos = fin.tellg();
	fin.seekg(0);
	size_t n = (size_t)pos + 1;
	char arr[12093];
	fin.read(arr, 12093);
	char* b = arr;
	int count = 0;
	for (i = n; i > 0; --i) {
		count++;
		c = (unsigned char)(*b++);
		s = (s << 8) ^ crctab[(s >> 24) ^ c];
	}


	/* Extend with the length of the string. */
	while (n != 0) {
		c = n & 0377;
		n >>= 8;
		s = (s << 8) ^ crctab[(s >> 24) ^ c];
	}


	return ~s;
}
// end of implementation of POSIX cksum

// util function that calculates filesize
inline CryptoPP::lword FileSize(const CryptoPP::FileSource& file)
{
	std::istream* stream = const_cast<CryptoPP::FileSource&>(file).GetStream();

	std::ifstream::pos_type old = stream->tellg();
	std::ifstream::pos_type end = stream->seekg(0, std::ios_base::end).tellg();
	stream->seekg(old);

	return static_cast<CryptoPP::lword>(end);
}
#undef _CRT_SECURE_NO_WARNINGS