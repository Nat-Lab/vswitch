#ifndef EOIP6_PORT_H
#define EOIP6_PORT_H
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "port.h"

#define PROTO_EOIP6 97

class Eoip6Port : public Port {
public:
    Eoip6Port(uint16_t tunnel_id, const char *bind_address, const char *peer_address);
    bool Open();
    ssize_t Read(uint8_t *buffer, size_t len);
    ssize_t Write(const uint8_t *buffer, size_t len);
    int Close();
    int GetId(void) const;
    ~Eoip6Port();
private:
    struct Eoip6Header {
        uint8_t version: 4;
        uint16_t tunnel_id: 12;
            
        void serialize() { 
            uint8_t *bit = (uint8_t *) this;
            uint16_t *bits = (uint16_t *) this;
            *bits = htons(version << 12 | tunnel_id);
            *bit = ((*bit & 0xf0) >> 4) | ((*bit & 0x0f) << 4);
        }      
    };
    
    int this_fd;
    char *bind_address;
    char *peer_address;
    struct Eoip6Header this_header;
    struct sockaddr_in6 this_bind;
    struct sockaddr_in6 peer_addr;

    uint8_t *read_buf;
    uint8_t *write_buf;
    uint16_t this_tid;
};

#endif 