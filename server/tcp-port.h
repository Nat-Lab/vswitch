#ifndef TCP_PORT_H
#define TCP_PORT_H

#include "port.h"

// TcpPort adds a 16 bits unsigned interger to head of buffer - since TCP is a
// streaming protocol, we will need payload length.
class TcpPort : public Port {
public:
    TcpPort(int sock_fd);
    ssize_t Read(uint8_t *buffer, size_t len);
    ssize_t Write(const uint8_t *buffer, size_t len);
    int Close();
    int GetId(void) const;
    ~TcpPort();
private:
    int sock_fd;
    uint8_t *send_buffer;
};

#endif // TCP_PORT_H