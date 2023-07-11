#include "ConfigHandler.hpp"
#include <stdexcept>
#include "defs.hpp"
#include "boost/asio.hpp"
#include "cryptlib.h"
#include <base64.h>
#include <cstdio>

unsigned char hexToUID(unsigned char);
bool FileExists(const std::string&);

// sets up all config info
ConfigHandler::ConfigHandler()
{
	HandleTransfer(); // Extract prime config from transfer.info
	if (!FileExists("me.info"))
	{
		keyFlag = false;
		regFlag = false; // Need to register
		return;
	}
	regFlag = true; // Possibly registered
	try // Try extracting rest of config from me.info
	{
		std::ifstream fin;
		fin.open("me.info", std::ios::in | std::ios::binary);
		if (!fin.is_open()) throw std::exception("Couldn't open me.info");
		fin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Name from me.info ignored
		if(fin.eof()) throw std::exception("Bad file format");
		std::string hex;
		hex.reserve(UID_SIZE * 2);
		std::getline(fin, hex);
		if (fin.eof()) throw std::exception("Bad file format");
		if (!(hex.length() == UID_SIZE * 2)) throw std::exception("Bad UID format");
		for (int i =0; i < UID_SIZE; i++)
		{
			unsigned char c = hexToUID(hex[i*2]);
			c = (c << 4) + hexToUID(hex[i*2+1]);
			UID.push_back(c);
		}
		std::string key;
		std::string line;
		while (!fin.eof())
		{
			std::getline(fin, line);
			key.append(line);
		}
		CryptoPP::Base64Decoder d;
		d.Put((CryptoPP::byte*)key.data(), key.size());
		d.MessageEnd();
		CryptoPP::RSA::PrivateKey k;
		k.Load(d);
		setKey(k);
		keyFlag = true;
	}

	catch (std::exception const& error)
	{
		if (strcmp(error.what(), "Couldn't open me.info") 
			and strcmp(error.what(), "Bad UID format")
			and strcmp(error.what(), "Bad key format")
			and strcmp(error.what(), "Bad file format")) throw error; // rethrow unexpected exception
		regFlag = false; // proceed with registration if couldn't get me.info
		keyFlag = false;
	}
}

// util function converts hex to UID
unsigned char hexToUID(unsigned char c)
{
	if ('0' <= c && c <= '9')
		return c - '0';
	else if ('a' <= c && c <= 'f')
		return c - 'a' + 10;
	else if ('A' <= c && c <= 'F')
		return c - 'A' + 10;
	else throw std::exception("Bad UID format");
}

// util function converts UID to hex representation
void UIDToHex(const char* UID, std::string& hex)
{
	for (int i = 0; i < UID_SIZE; i++)
	{
		unsigned char c = UID[i], lo;
		lo = c % 16;
		if (lo < 10) lo += '0';
		else lo = lo + 'A' - 10;
		c /= 16;
		if (c < 10) c += '0';
		else c = c + 'A' - 10;
		hex.push_back(c);
		hex.push_back(lo);
	}
}

// writeback to me.info if registration and key exchange succeed
ConfigHandler::~ConfigHandler()
{
	
	if (keyFlag)
	{
		std::cout << "Attempting to create me.info file" << std::endl;
		std::ofstream out;
		out.open("me.info", std::ios::out | std::ios::trunc | std::ios::binary);
		if (!out.is_open()) // can't write me.info
		{
			std::cout << "Failed to open me.info" << std::endl;
			try
			{
				std::remove("me.info"); // Try to cleanup file so next run is more smooth
			}
			catch (std::exception const& e)
			{
				std::cout << "Failed to delete me.info file" << std::endl;
			}
			throw std::exception("Non-fatal: Couldn't write registration info back to me.info");
		}
		out.write(this->getName().data(), this->getName().length()); // null char isn't written
		out.write("\n", 1);
		std::string hex;
		UIDToHex(this->getUID().data(), hex);
		out.write(hex.data(), hex.length());
		out.write("\n", 1);
		std::string key;
		std::string encoded;
		CryptoPP::Base64Encoder e;
		CryptoPP::StringSink ss(key);
		this->getKey().Save(ss);
		e.Attach(new CryptoPP::StringSink(encoded));
		e.Put((CryptoPP::byte*)key.data(), key.size());
		e.MessageEnd();
		out.write(encoded.data(), encoded.length());
		std::cout << "Successfully created me.info file" << std::endl;
	}
}

//util used to convert port as string to integer
int str2int(int& i, char const* s, int base = 0)
{
	char* end;
	long  l;
	errno = 0;
	l = strtol(s, &end, base);
	if ((errno == ERANGE && l == LONG_MAX) || l > INT_MAX) {
		return -1;
	}
	if ((errno == ERANGE && l == LONG_MIN) || l < INT_MIN) {
		return -1;
	}
	if (*s == '\0' || *end != '\0') {
		return -1;
	}
	i = l;
	return 0;
}

// handles parsing of transfer.info config file and setting config vars accordingly
void ConfigHandler::HandleTransfer()
{
	transfer.open("transfer.info");
	if (!transfer.is_open()) throw std::runtime_error("Local Failure: Couldn't open transfer.info");
	std::getline(transfer, IP, ':');
	boost::asio::ip::address addr = boost::asio::ip::make_address(IP);
	if (!addr.is_v4()) throw std::invalid_argument("IPV6 is not supported");
	std::getline(transfer, port);
	int num;
	if (str2int(num,port.data()) or num > MAX_PORT or num < 0) throw std::invalid_argument("Invalid port");
	std::getline(transfer, name);
	if (name.length() >= NAME_SIZE - 1)
	{
		std::string err = ("Name too long, should be at most " + NAME_SIZE - 1);
		err += " characters long";
		throw std::invalid_argument(err);
	}
	std::getline(transfer, path);
	transfer.close();
}

// ip getter
std::string ConfigHandler::getIP() const
{
	return IP;
}

// port getter
std::string ConfigHandler::getPort() const
{
	return port;
}

// name getter
std::string ConfigHandler::getName() const
{
	return name;
}

// UID getter
std::string ConfigHandler::getUID() const
{
	return UID;
}

// path getter
std::string ConfigHandler::getPath() const
{
	return path;
}

// privkey getter
CryptoPP::RSA::PrivateKey ConfigHandler::getKey() const
{
	return privKey;
}

// regFlag - represents successful registeration (or reconnect)
bool ConfigHandler::getFlag() const
{
	return regFlag;
}

// flip bool value of regflag
void ConfigHandler::flipFlag()
{
	regFlag = !regFlag;
}

// UID setter
void ConfigHandler::setUID(const std::string& UID)
{
	this->UID = std::string(UID.data(), UID.data() + UID_SIZE);
}

// privkey setter
void ConfigHandler::setKey(CryptoPP::RSA::PrivateKey k)
{
	privKey = CryptoPP::RSA::PrivateKey(k);
}

// sets keyFlag - key exchange success
void ConfigHandler::keySuccess()
{
	keyFlag = true;
}

// util used to check for file existence
bool FileExists(const std::string& filename)
{
	FILE* file;
	if (!fopen_s(&file, filename.data(), "r")) {
		fclose(file);
		return true;
	}
	else {
		return false;
	}
}

