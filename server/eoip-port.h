#ifndef EOIP_PORT_H
#define EOIP_PORT_H

#include "port.h"

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PROTO_EOIP 47
#define EOIP_MAGIC "\x20\x01\x64\x00"

class EoipPort : public Port {
public:
    EoipPort(uint16_t tunnel_id, const char *bind_address, const char *peer_address);
    bool Open();
    ssize_t Read(uint8_t *buffer, size_t len);
    ssize_t Write(const uint8_t *buffer, size_t len);
    int Close();
    int GetId(void) const;
    ~EoipPort();
private:
    struct EoipHeader {
        uint32_t magic;
        uint16_t payload_len;
        uint16_t tunnel_id;
    };

    int this_fd;
    char *bind_address;
    char *peer_address;
    struct EoipHeader this_header;
    struct sockaddr_in this_bind;
    struct sockaddr_in peer_addr;

    uint8_t *read_buf;
    uint8_t *write_buf;
};

#endif // EOIP_PORT_H