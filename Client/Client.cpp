// implements all timeout functionality of socket reading

#include "boost/asio.hpp"
#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>
#include "defs.hpp"
#include "Session.hpp"
#ifdef _WIN32
#include <windows.h>
#define sleep(x) Sleep(1000*x)
#else
#include <unistd.h>
#endif

class ServerHeader;
Client::Client(Session* s)
{
	this->s = s; // attach to session
}

void Client::connect()
{
	try
	{
		boost::asio::connect(*(s->getSocket()), (*(s->getResolver())).resolve(s->getConfig()->getIP(), s->getConfig()->getPort()));
	}
	catch (std::exception const& error) // nothing to be done if server is unreachable
	{
		std::cout << "Fatal Error:" << error.what() << std::endl;
		std::cout << "Program will now terminate" << std::endl;
		exit(-1);
	}
}

// reads header from socket into session member
void Client::readHeader()
{
	int patience = 5;
	while (s->getSocket()->available() < SERVER_HEADER_SIZE and patience > 0)
	{
		patience--;
		sleep(1);
	}
	if (patience == 0) throw std::exception("timeout");
	boost::asio::streambuf buffer;
	size_t transferred = boost::asio::read(*(s->getSocket()), buffer, boost::asio::transfer_exactly(SERVER_HEADER_SIZE));
	std::string buf;
	buf.resize(transferred);
	buffer.sgetn(&buf[0], buf.size()); // transfer header into string
	memcpy(s->getHeaderRecieved(), buf.data(), SERVER_HEADER_SIZE); // transfer header from string to headerReceived session member
}

// reads paayload into session buffer
void Client::readPayload()
{
	int patience = 5;
	size_t size = s->getHeaderRecieved()->size;
	while (s->getSocket()->available() < size and patience > 0)
	{
		patience--;
		sleep(1);
	}
	if (patience == 0) throw std::exception("timeout");
	boost::asio::streambuf buffer;
	size_t transferred = boost::asio::read(*(s->getSocket()), buffer, boost::asio::transfer_exactly(size));
	(s->getBuffer())->resize(transferred);
	buffer.sgetn(&(*(s->getBuffer()))[0], s->getBuffer()->size()); // transfer payload into session buffer
}

// flushes socket contents
void Client::flush(size_t b_count)
{
	int patience = 5;
	while (s->getSocket()->available() < b_count and patience > 0)
	{
		patience--;
		sleep(1);
	}
	if (patience == 0) throw std::exception("timeout");
	boost::asio::streambuf buffer;
	boost::asio::read(*(s->getSocket()), buffer, boost::asio::transfer_exactly(b_count));
}


// write vector of buffers into socket
void Client::write(std::vector<boost::asio::mutable_buffer> out)
{
	//Note that client will crash due to win exception if server dies here
	boost::asio::write(*(s->getSocket()), out);
}

// unused
void Client::write_some(const char* data, size_t size)
{
	boost::asio::write(*(s->getSocket()), boost::asio::buffer(data,size));
}