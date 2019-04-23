#include "port.h"
#include "unistd.h"

Port::Port() {
    port_fd = -1;
}

Port::Port(int fd) {
    port_fd = fd;
}

ssize_t Port::Read(uint8_t *buffer, size_t len) {
    return read(port_fd, buffer, len);
}

ssize_t Port::Write(const uint8_t *buffer, size_t len) {
    return write(port_fd, buffer, len);
}

int Port::Close() {
    return close(port_fd);
}

int Port::GetId(void) const {
    return port_fd;
}