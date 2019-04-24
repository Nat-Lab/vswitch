#ifndef TLS_PORT_H
#define TLS_PORT_H

#include "port.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

class TlsPort : public Port {
public:
    TlsPort(SSL *ssl, int id);
    ssize_t Read(uint8_t *buffer, size_t len);
    ssize_t Write(const uint8_t *buffer, size_t len);
    int Close();
    int GetId(void) const;
    ~TlsPort();
private:
    SSL *ssl;
    int id;
    uint8_t *send_buffer;
};

#endif // TLS_PORT_H