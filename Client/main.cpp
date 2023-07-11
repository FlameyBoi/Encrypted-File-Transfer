
// BckUp_Client : Implements a file backup system using a remote host for storage
#define LOCAL_FAILURE -1
#define REMOTE_FAILURE -2
#include "Session.hpp"

int main()
{
    try 
    {
        ConfigHandler conf; // init configuration
        Session session(&conf); // init session with given configuration
        session.run(); // run protocol
    }
    catch (std::exception const& error)
    {
        std::cout << "Fatal error:" << error.what() << std::endl;
        return LOCAL_FAILURE;
    }
    return 0;
}
