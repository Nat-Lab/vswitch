#include "eoip6-port.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

Eoip6Port::Eoip6Port(uint16_t tunnel_id, const char *bind_address, const char *peer_address) {
    this_tid = tunnel_id;
    memset(&this_bind, 0, sizeof(struct sockaddr_in6));
    this_bind.sin6_family = AF_INET6;
    this_bind.sin6_port = htons(PROTO_EOIP6);
    memset(&peer_addr, 0, sizeof(struct sockaddr_in6));
    memset(&this_header, 0, sizeof(struct Eoip6Header));
    this->bind_address = (char *) malloc(strlen(bind_address) + 1);
    this->peer_address = (char *) malloc(strlen(peer_address) + 1);
    strcpy(this->bind_address, bind_address);
    strcpy(this->peer_address, peer_address);
    read_buf = (uint8_t *) malloc(65536);
    write_buf = (uint8_t *) malloc(65536);
    memcpy(write_buf, &this_header, sizeof(struct Eoip6Header));
}

bool Eoip6Port::Open() {
    fprintf(stderr, "[INFO] Eoip6Port::Open: spinning up...\n");

    if (this_tid > 4095) {
        fprintf(stderr, "[CRIT] Eoip6Port::Open: invalid tunnel id.\n");
        return false;
    }

    this_header.version = 3;
    this_header.tunnel_id = this_tid;
    this_header.serialize();

    memcpy(write_buf, &this_header, sizeof(struct Eoip6Header));

    int pton_ret = inet_pton(AF_INET6, bind_address, &(this_bind.sin6_addr));

    if (pton_ret < 0) {
        fprintf(stderr, "[CRIT] Eoip6Port::Open: inet_pton(): %s\n", strerror(errno));
        return false;
    }

    pton_ret = inet_pton(AF_INET6, peer_address, &(peer_addr.sin6_addr));

    if (pton_ret < 0) {
        fprintf(stderr, "[CRIT] Eoip6Port::Open: inet_pton(): %s\n", strerror(errno));
        return false;
    }

    this_fd = socket(AF_INET6, SOCK_RAW, PROTO_EOIP6);

    if (this_fd < 0) {
        fprintf(stderr, "[CRIT] Eoip6Port::Open: socket(): %s\n", strerror(errno));
        return false;
    }

    int bind_ret = bind(this_fd, (struct sockaddr *) &this_bind, sizeof(struct sockaddr_in6));

    if (bind_ret < 0) {
        fprintf(stderr, "[CRIT] Eoip6Port::Open: bind(): %s\n", strerror(errno));
        return false;
    }

    fprintf(stderr, "[INFO] Eoip6Port::Open: port opened, id: %d\n", this_fd);
    return true;
}

ssize_t Eoip6Port::Read(uint8_t *buffer, size_t outbuf_len) {
    char ip_str[INET6_ADDRSTRLEN];
    struct sockaddr_in6 peer_saddr;
    socklen_t peer_saddr_len = sizeof(struct sockaddr_in6);

    while (true) {
        ssize_t len = recvfrom(this_fd, read_buf, 65535, 0, (struct sockaddr *) &peer_saddr, &peer_saddr_len);

        if (len < 0) {
            fprintf(stderr, "[WARN] Eoip6Port::Read: recvfrom(): %s\n", strerror(errno));
            return len;
        }

        if (len == 0) {
            fprintf(stderr, "[WARN] Eoip6Port::Read: recvfrom() returned 0.\n");
            return 0;
        }

        if (memcmp(
            &((struct sockaddr_in6 *) &peer_saddr)->sin6_addr.s6_addr, 
            &((struct sockaddr_in6 *) &peer_addr)->sin6_addr.s6_addr,
            16
        )) continue;

        if ((size_t) len <= sizeof(struct Eoip6Header)) {
            inet_ntop(AF_INET6, &(peer_saddr.sin6_addr), ip_str, INET6_ADDRSTRLEN);
            fprintf(stderr, "[WARN] Eoip6Port::Read: got invalid packet (too small) from source: %s\n", ip_str);
            continue;
        }

        uint8_t *read_buf_ptr = read_buf;
        struct Eoip6Header *header_ptr = (struct Eoip6Header *) read_buf;

        if (memcmp(header_ptr, &this_header, sizeof(struct Eoip6Header)) != 0) {
            inet_ntop(AF_INET6, &(peer_saddr.sin6_addr), ip_str, INET6_ADDRSTRLEN);
            fprintf(stderr, "[WARN] Eoip6Port::Read: got invalid packet (header mismatch) from source: %s\n", ip_str);
            continue;
        }

        read_buf_ptr += sizeof(struct Eoip6Header);
        len -= sizeof(struct Eoip6Header);

        if (outbuf_len < (size_t) len) {
            fprintf(stderr, "[WARN] Eoip6Port::Read: dst buffer too small.\n");
            continue;
        }

        memcpy(buffer, read_buf_ptr, len);

        return len;
    }
}

ssize_t Eoip6Port::Write(const uint8_t *buffer, size_t len) {
    if (len > 65535 - sizeof(struct Eoip6Header)) {
        fprintf(stderr, "[WARN] Eoip6Port::Write: packet too big.\n");
        return -1;
    }

    uint8_t *payload_ptr = write_buf + sizeof(struct Eoip6Header);
    memcpy(payload_ptr, buffer, len);
    return sendto(this_fd, write_buf, len + sizeof(struct Eoip6Header), 0, (struct sockaddr *) &peer_addr, sizeof(struct sockaddr_in6)) - sizeof(struct Eoip6Header);
}

int Eoip6Port::Close() {
    return close(this_fd);
}

int Eoip6Port::GetId(void) const {
    return this_fd;
}

Eoip6Port::~Eoip6Port() {
    Close();
    delete bind_address;
    delete peer_address;
    delete read_buf;
    delete write_buf;
}