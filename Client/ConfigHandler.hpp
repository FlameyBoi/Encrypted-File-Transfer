
#include <fstream>
#include <iostream>
#include <string>
#include "cryptlib.h"
#include "rsa.h"

class Session;

class ConfigHandler
{
	friend class Session;
private:
	std::ifstream transfer;
	std::fstream me;
	std::string IP;
	std::string name;
	std::string path;
	std::string port;
	std::string UID;
	CryptoPP::RSA::PrivateKey privKey;

	bool regFlag;
	bool keyFlag;
	void HandleTransfer();
public:
	ConfigHandler();
	~ConfigHandler();
	std::string getName() const;
	std::string getIP() const;
	std::string getPort() const;
	std::string getPath() const;
	std::string getUID() const;
	CryptoPP::RSA::PrivateKey getKey() const;
	void setKey(CryptoPP::RSA::PrivateKey);
	bool getFlag() const;
	void flipFlag();
	void setUID(const std::string&);
	void keySuccess();
};
