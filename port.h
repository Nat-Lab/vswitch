#ifndef PORT_H
#define PORT_H

#include <unistd.h>
#include <stdint.h>

class Port {
public:
    virtual ssize_t Read(uint8_t *buffer, size_t len) = 0;
    virtual ssize_t Write(const uint8_t *buffer, size_t len) = 0;
    virtual int Close() = 0;
    virtual int GetId(void) const = 0;
    virtual ~Port() {}
};

#endif // PORT_H