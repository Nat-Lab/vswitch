#include "tcp-port.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

TcpPort::TcpPort (int sock_fd) {
    this->sock_fd = sock_fd;
    send_buffer = (uint8_t *) malloc(65536);
}

TcpPort::~TcpPort () {
    delete send_buffer;
}

ssize_t TcpPort::Read(uint8_t *buffer, size_t len) {
    ssize_t read_len = read(sock_fd, buffer, 2);
    if (read_len <= 0) return read_len;
    if (read_len < 2) {
        fprintf(stderr, "[WARN] TcpPort::Read: invalid header.\n");
        errno = EINVAL;
        return -1;
    }

    uint16_t payload_len = *((uint16_t *) buffer);
    uint16_t tot_read_len = 0;

    if (len < payload_len) {
        fprintf(stderr, "[WARN] TcpPort::Read: buffer too small.\n");
        errno = EINVAL;
        return -1;
    }

    while (payload_len - tot_read_len != 0) {
        read_len = read(sock_fd, buffer, payload_len - tot_read_len);
        if (read_len <= 0) return read_len;
        buffer += read_len;
        tot_read_len += read_len;
    }
    return payload_len;
}

ssize_t TcpPort::Write (const uint8_t *buffer, size_t len) {
    memcpy(send_buffer, &len, 2);
    memcpy(send_buffer + 2, buffer, len);

    return write(sock_fd, buffer, len + 2) - 2;
}

int TcpPort::Close() {
    return close(sock_fd);
}

int TcpPort::GetId(void) const {
    return sock_fd;
}