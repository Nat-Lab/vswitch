#include "tls-port.h"

TlsPort::TlsPort (SSL *ssl, int id) {
    this->id = id;
    this->ssl = ssl;
}

ssize_t TlsPort::Read(uint8_t *buffer, size_t len) {
    int ret = SSL_read(ssl, buffer, len);
    if (ret <= 0) {
        fprintf(stderr, "[CRIT] TlsPort::Read: SSL_read() error:\n");
        ERR_print_errors_fp(stderr);
    }
    return ret;
}

ssize_t TlsPort::Write(const uint8_t *buffer, size_t len) {
    int ret = SSL_write(ssl, buffer, len);
    if (ret <= 0) {
        fprintf(stderr, "[CRIT] TlsPort::Write: SSL_write() error:\n");
        ERR_print_errors_fp(stderr);
    }
    return ret;
}

int TlsPort::Close() {
    int ret = SSL_shutdown(ssl);
    if (ret <= 0) {
        fprintf(stderr, "[CRIT] TlsPort::Close: SSL_shutdown() error:\n");
        ERR_print_errors_fp(stderr);
    }
    return ret;
}

int TlsPort::GetId(void) const {
    return id;
}

TlsPort::~TlsPort() {
   Close();
}