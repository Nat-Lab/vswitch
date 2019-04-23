#ifndef TCP_PORT_ENUM_H
#define TCP_PORT_ENUM_H
#define TCP_QUEUE_LEN 16

#include "port-enumerator.h"
#include <vector>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

class TcpPortEnumerator : PortEnumerator {
public:
    TcpPortEnumerator(const char *server_addr, in_port_t port);
    bool Start();
    bool Stop();
    Port* GetPort(void);
    const char* GetName(void);
    ~TcpPortEnumerator();

private:
    int master_fd;
    struct sockaddr_in listen_addr;
    std::vector<Port *> ports;
};

#endif // TCP_PORT_ENUM_H