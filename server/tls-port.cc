#include "tls-port.h"

TlsPort::TlsPort (SSL *ssl, int id) {
    this->id = id;
    this->ssl = ssl;
    send_buffer = (uint8_t *) malloc(65536);
}

ssize_t TlsPort::Read(uint8_t *buffer, size_t len) {
    int read_len = SSL_read(ssl, buffer, 2);
    if (read_len <= 0) {
        fprintf(stderr, "[CRIT] TlsPort::Read: SSL_read() error:\n");
        ERR_print_errors_fp(stderr);
        return read_len;
    }
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
        read_len = SSL_read(ssl, buffer, payload_len - tot_read_len);
        if (read_len <= 0) {
            fprintf(stderr, "[CRIT] TlsPort::Read: SSL_read() error:\n");
            ERR_print_errors_fp(stderr);
            return read_len;
        }
        buffer += read_len;
        tot_read_len += read_len;
    }
    return payload_len;
}

ssize_t TlsPort::Write(const uint8_t *buffer, size_t len) {
    memcpy(send_buffer, &len, 2);
    memcpy(send_buffer + 2, buffer, len);

    int ret = SSL_write(ssl, send_buffer, len + 2) - 2;
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
    close(id);
    return ret;
}

int TlsPort::GetId(void) const {
    return id;
}

TlsPort::~TlsPort() {
    free(send_buffer);
    SSL_free(ssl);
    Close();
}