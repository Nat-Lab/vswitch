#ifndef PORT_H
#define PORT_H

#include <unistd.h>
#include <stdint.h>

class Port {
public:
    Port();
    Port(int fd); 
    virtual ssize_t Read(uint8_t *buffer, size_t len);
    virtual ssize_t Write(const uint8_t *buffer, size_t len);
    virtual int Close();
    virtual int GetId(void) const;
    virtual ~Port() {}
private:
    int port_fd;
};

#endif // PORT_H