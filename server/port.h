#ifndef PORT_H
#define PORT_H

#include <unistd.h>
#include <stdint.h>

class Port {
public:
    Port();

    // create a port that binds to file descriptor fd
    Port(int fd); 

    // read implementation, returns bytes read, returns negative if error
    virtual ssize_t Read(uint8_t *buffer, size_t len);

    // write implementation, returns bytes written, returns negative if error
    virtual ssize_t Write(const uint8_t *buffer, size_t len);

    // open implementation, returns true if success, false otherwise
    virtual bool Open();

    // close implementation, returns 0 on success, -1 otherwise.
    virtual int Close();

    // get a unique port id
    virtual int GetId(void) const;
    virtual ~Port() {}
private:
    int port_fd;
};

#endif // PORT_H