#include "eoip-port.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <netinet/ip.h>

EoipPort::EoipPort(uint16_t tunnel_id, const char *bind_address, const char *peer_address) {
    this_fd = -1;
    memset(&this_bind, 0, sizeof(struct sockaddr_in));
    memset(&peer_addr, 0, sizeof(struct sockaddr_in));
    memset(&this_header, 0, sizeof(struct EoipHeader));
    memcpy(&(this_header.magic), EOIP_MAGIC, 4);
    this_header.tunnel_id = tunnel_id;
    this->bind_address = (char *) malloc(strlen(bind_address) + 1);
    this->peer_address = (char *) malloc(strlen(peer_address) + 1);
    strcpy(this->bind_address, bind_address);
    strcpy(this->peer_address, peer_address);
    read_buf = (uint8_t *) malloc(65536);
    write_buf = (uint8_t *) malloc(65536);
    memcpy(write_buf, &this_header, sizeof(struct EoipHeader));
}

EoipPort::~EoipPort() {
    Close();
    delete bind_address;
    delete peer_address;
    delete read_buf;
    delete write_buf;
}

bool EoipPort::Open() {
    fprintf(stderr, "[INFO] EoipPort::Open: spinning up...\n");

    this_bind.sin_family = AF_INET;
    this_bind.sin_port = htons(PROTO_EOIP);
    int pton_ret = inet_pton(AF_INET, bind_address, &(this_bind.sin_addr));

    if (pton_ret < 0) {
        fprintf(stderr, "[CRIT] EoipPort::Open: inet_pton(): %s\n", strerror(errno));
        return false;
    }

    pton_ret = inet_pton(AF_INET, peer_address, &(peer_addr.sin_addr));

    if (pton_ret < 0) {
        fprintf(stderr, "[CRIT] EoipPort::Open: inet_pton(): %s\n", strerror(errno));
        return false;
    }

    this_fd = socket(AF_INET, SOCK_RAW, PROTO_EOIP);

    if (this_fd < 0) {
        fprintf(stderr, "[CRIT] EoipPort::Open: socket(): %s\n", strerror(errno));
        return false;
    }

    int bind_ret = bind(this_fd, (struct sockaddr *) &this_bind, sizeof(struct sockaddr_in));

    if (bind_ret < 0) {
        fprintf(stderr, "[CRIT] EoipPort::Open: bind(): %s\n", strerror(errno));
        return false;
    }

    fprintf(stderr, "[INFO] EoipPort::Open: port opened, id: %d\n", this_fd);
    return true;
}

ssize_t EoipPort::Read(uint8_t *buffer, size_t outbuf_len) {
    char ip_str[INET_ADDRSTRLEN];
    struct sockaddr_in peer_saddr;
    socklen_t peer_saddr_len = sizeof(struct sockaddr_in);

    while (true) {
        ssize_t len = recvfrom(this_fd, read_buf, 65535, 0, (struct sockaddr *) &peer_saddr, &peer_saddr_len);

        if (len < 0) {
            fprintf(stderr, "[WARN] EoipPort::Read: recvfrom(): %s\n", strerror(errno));
            return len;
        }

        if (len == 0) {
            fprintf(stderr, "[WARN] EoipPort::Read: recvfrom() returned 0.\n");
            return 0;
        }

        if (((struct sockaddr_in *) &peer_saddr)->sin_addr.s_addr != peer_addr.sin_addr.s_addr) {
            continue;
        }

        uint8_t *read_buf_ptr = read_buf;
        struct ip *ip_hdr = (struct ip *) read_buf;

        read_buf_ptr += ip_hdr->ip_hl * 4;
        len -= ip_hdr->ip_hl * 4;

        if ((size_t) len <= sizeof(struct EoipHeader)) {
            inet_ntop(AF_INET, &(peer_saddr.sin_addr), ip_str, INET_ADDRSTRLEN);
            fprintf(stderr, "[WARN] EoipPort::Read: got invalid packet (too small) from source: %s\n", ip_str);
            continue;
        }

        len -= sizeof(struct EoipHeader);
        struct EoipHeader *recv_hdr = (struct EoipHeader *) read_buf_ptr;

        if (recv_hdr->magic != this_header.magic) {
            inet_ntop(AF_INET, &(peer_saddr.sin_addr), ip_str, INET_ADDRSTRLEN);
            fprintf(stderr, "[WARN] EoipPort::Read: got invalid packet (invalid magic) from source: %s\n", ip_str);
            continue;
        }

        uint16_t payload_len = ntohs(recv_hdr->payload_len);

        if (len != payload_len) {
            inet_ntop(AF_INET, &(peer_saddr.sin_addr), ip_str, INET_ADDRSTRLEN);
            fprintf(stderr, "[WARN] EoipPort::Read: got invalid packet (payload length mismatch: expected=%li, got=%d) from source: %s\n", len, payload_len, ip_str);
            continue;
        }

        if (this_header.tunnel_id != recv_hdr->tunnel_id) {
            inet_ntop(AF_INET, &(peer_saddr.sin_addr), ip_str, INET_ADDRSTRLEN);
            fprintf(stderr, "[WARN] EoipPort::Read: got invalid packet (tid mismatch (remote = %d)) from source: %s\n", recv_hdr->tunnel_id, ip_str);
            continue;
        }

        read_buf_ptr += sizeof(struct EoipHeader);

        if (outbuf_len < (size_t) len) {
            fprintf(stderr, "[WARN] EoipPort::Read: dst buffer too small.\n");
            continue;
        }

        memcpy(buffer, read_buf_ptr, outbuf_len);

        return len;
    }
}

ssize_t EoipPort::Write (const uint8_t *buffer, size_t len) {
    if (len > 65535 - sizeof(struct EoipHeader)) {
        fprintf(stderr, "[WARN] EoipPort::Write: packet too big.\n");
        return -1;
    }

    struct EoipHeader *eoip_hdr_ptr = (struct EoipHeader *) write_buf;
    uint8_t *payload_ptr = write_buf + sizeof(struct EoipHeader);
    eoip_hdr_ptr->payload_len = htons(len);
    memcpy(payload_ptr, buffer, len);
    return sendto(this_fd, write_buf, len + sizeof(struct EoipHeader), 0, (struct sockaddr *) &peer_addr, sizeof(struct sockaddr_in)) - sizeof(struct EoipHeader);
}

int EoipPort::Close() {
    return close(this_fd);
}

int EoipPort::GetId(void) const {
    return this_fd;
};