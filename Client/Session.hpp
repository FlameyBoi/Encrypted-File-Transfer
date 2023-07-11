
#define _CRT_SECURE_NO_WARNINGS
#include <fstream>
#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <memory>
#include "defs.hpp"
#include <cryptlib.h>
#include "HeaderHandler.hpp"
#include "ConfigHandler.hpp"
#include "Protocol.hpp"
#include "Client.hpp"
#define R_ONLY "r"
#define R_W "rw"
#define W_ONLY "w"
// Consider using smart pointers instead of regular ones
class Client;
class Session
{
	friend class Client;
private:
	boost::asio::io_context io_context;
	boost::asio::ip::tcp::socket socket;
	boost::asio::ip::tcp::resolver resolver;
	std::string buffer;
	std::string fname;
	char* address;
	char* port;
	ServerHeader* headerRecieved; // Last Recieved header
	Header* headerSent; // Last Sent header
	ConfigHandler* config;
	CryptoPP::SecByteBlock AES;
	int fileLen;
	int crcFail;
	bool retry;
public:
	Session(ConfigHandler* conf);
	~Session();
	Client* to;
	void run();
	boost::asio::ip::tcp::socket* getSocket();
	ServerHeader* getHeaderRecieved();
	Header* getHeaderSent();
	boost::asio::ip::tcp::resolver* getResolver();
	boost::asio::io_context* getIOContext();
	ConfigHandler* getConfig();
	std::string* getBuffer();
	CryptoPP::SecByteBlock getAES();
	void setAES(CryptoPP::SecByteBlock AES);
	void setFname(const char* name);
	std::string* getFname();
	int getLen();
	void setLen(int len);
	void setRetry(bool retry);
	bool getRetry();
	void decFail();
	int getFail();
};
#undef _CRT_SECURE_NO_WARNINGS