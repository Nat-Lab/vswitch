#ifndef TLS_PORT_ENUM_H
#define TLS_PORT_ENUM_H
#define TCP_QUEUE_LEN 16

#include "port-enumerator.h"
#include "tls-port.h"
#include <vector>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

class TlsPortEnumerator : public PortEnumerator {
public:
    TlsPortEnumerator(const char *ca_path, const char *server_crt, const char *server_key,
                      const char *bind_addr, in_port_t bind_port);
    bool Start();
    bool Stop();
    Port* GetPort(void);
    const char* GetName(void);
    ~TlsPortEnumerator();
private:
    SSL_CTX *ssl_ctx;
    int master_fd;
    struct sockaddr_in listen_addr;
    char *this_name;
    std::vector<TlsPort *> ports;
    bool ssl_ready;
};

#endif // TLS_PORT_ENUM_H