#define _CRT_SECURE_NO_WARNINGS
#include <boost/asio.hpp>
#include "defs.hpp"
#include "Session.hpp"
#include "osrng.h"

using boost::asio::ip::tcp;

//init all session vars
Session::Session(ConfigHandler* conf) : io_context(), socket(io_context), resolver(io_context)
{
	config = conf;
	buffer = "";
	address = NULL;
	port = NULL;
	headerSent = new Header();
	headerRecieved = new ServerHeader();
	fileLen = 0;
	crcFail = 4; // number of retries in case of bad crc
}

void Session::run()
{
	runProtocol(this);
}

//after protocol cleanup
Session::~Session()
{
	delete headerSent; // dynamically allocated structs
	delete headerRecieved;
}

//socket getter
boost::asio::ip::tcp::socket* Session::getSocket()
{
	return &socket;
}

//serverheader getter
ServerHeader* Session::getHeaderRecieved()
{
	return headerRecieved;
}

//clientheader getter
Header* Session::getHeaderSent()
{
	return headerSent;
}

//io_context getter
boost::asio::io_context* Session::getIOContext()
{
	return &io_context;
}

//resolver getter
boost::asio::ip::tcp::resolver* Session::getResolver()
{
	return &resolver;
}

//confighandler getter
ConfigHandler* Session::getConfig()
{
	return config;
}

//payload buffer getter
std::string* Session::getBuffer()
{
	return &buffer;
}

//AES (unwrapped) getter
CryptoPP::SecByteBlock Session::getAES()
{
	return AES;
}

//AES setter (gets encrypted AES as arg and handles decryption)
void Session::setAES(CryptoPP::SecByteBlock AES)
{
	std::string decrypted;
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::RSAES_OAEP_SHA_Decryptor d(this->getConfig()->getKey());
	CryptoPP::ArraySource as(AES.data(), AES.size(), true,
		new CryptoPP::PK_DecryptorFilter(rng, d, new CryptoPP::StringSink(decrypted)));
	this->AES = CryptoPP::SecByteBlock((CryptoPP::byte*)decrypted.data(), decrypted.length());
}

//filelen setter
void Session::setLen(int len)
{
	fileLen = len;
}

//filelen getter
int Session::getLen()
{
	return fileLen;
}

//retry getter
bool Session::getRetry()
{
	return retry;
}

//retry setter
void Session::setRetry(bool b)
{
	retry = b;
}

//crcfail getter
int Session::getFail()
{
	return crcFail;
}

//dec crcfail var (counts fails until giveup)
void Session::decFail()
{
	crcFail--;
}

//fname setter
void Session::setFname(const char* name)
{
	fname = std::string(&name[0],&name[0] + NAME_SIZE);
}

//fname getter
std::string* Session::getFname()
{
	return &fname;
}
#undef _CRT_SECURE_NO_WARNINGS