#include "tcp-port-enumerator.h"
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

TcpPortEnumerator::TcpPortEnumerator(const char *server_addr, in_port_t port) {
    memset(&listen_addr, 0, sizeof(struct sockaddr_in));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(port);
    inet_pton(AF_INET, server_addr, &(listen_addr.sin_addr));
    master_fd = -1;
    this_name = (char *) malloc(64);
    sprintf(this_name, "TcpPortEnumerator@%s:%d", server_addr, port);
}

bool TcpPortEnumerator::Start () {
    char ip_str[INET_ADDRSTRLEN];

    master_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (master_fd < 0) {
        fprintf(stderr, "[CRIT] TcpPortEnumerator::Start: socket(): %s.\n", strerror(errno));
        Stop();
        return false;
    }

    if (bind(master_fd, (struct sockaddr *) &listen_addr, sizeof(struct sockaddr_in)) < 0) {
        fprintf(stderr, "[CRIT] TcpPortEnumerator::Start: bind(): %s.\n", strerror(errno));
        Stop();
        return false;
    }

    if (listen(master_fd, TCP_QUEUE_LEN) < 0) {
        fprintf(stderr, "[CRIT] TcpPortEnumerator::Start: listen(): %s.\n", strerror(errno));
        Stop();
        return false;
    }

    inet_ntop(AF_INET, &(listen_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
    fprintf(stderr, "[INFO] TcpPortEnumerator::Start: listening on %s:%d.\n", ip_str, ntohs(listen_addr.sin_port));

    return true;
}

bool TcpPortEnumerator::Stop () {
    for (auto port = ports.begin(); port != ports.end(); port++) {
        (*port)->Close();
        delete *port;
    }
    ports.clear();

    if (close(master_fd) == 0) return true;
    fprintf(stderr, "[INFO] TcpPortEnumerator::Stop: close(): %s.\n", strerror(errno));
    return false;
}

Port* TcpPortEnumerator::GetPort(void) {
    char ip_str[INET_ADDRSTRLEN];
    struct sockaddr_in remote_addr;
    socklen_t remote_addr_len = sizeof(struct sockaddr_in);

    int client_fd = accept(master_fd, (struct sockaddr *) &remote_addr, &remote_addr_len);

    if (client_fd < 0) {
        fprintf(stderr, "[CRIT] TcpPortEnumerator::GetPort: accept(): %s.\n", strerror(errno));
        Stop();
        return 0;
    }

    inet_ntop(AF_INET, &(remote_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
    fprintf(stderr, "[INFO] TcpPortEnumerator::GetPort: new port: src: %s:%d (fd = %d).\n", ip_str, ntohs(remote_addr.sin_port), client_fd);

    TcpPort *p = new TcpPort(client_fd);
    ports.push_back(p);

    return p;
}

const char* TcpPortEnumerator::GetName(void) {
    return this_name;
}

TcpPortEnumerator::~TcpPortEnumerator() {
    delete this_name;
    Stop();
}