class Session;
class Client
{
public:
    Session* s;
    Client(Session* s);
    void connect();
    void readHeader();
    void readPayload();
    void flush(size_t b_count);
    void write(std::vector<boost::asio::mutable_buffer> out);
    void write_some(const char*, size_t);
};