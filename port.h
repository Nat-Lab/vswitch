#ifndef PORT_H
#define PORT_H

#include <unistd.h>
#include <stdint.h>

class Port {
public:
    Port();

    // create a port that binds to file descriptor fd
    Port(int fd); 

    // read implementation
    virtual ssize_t Read(uint8_t *buffer, size_t len);

    // write implementation
    virtual ssize_t Write(const uint8_t *buffer, size_t len);

    // close implementation
    virtual int Close();

    // get a unique port id
    virtual int GetId(void) const;
    virtual ~Port() {}
private:
    int port_fd;
};

#endif // PORT_H