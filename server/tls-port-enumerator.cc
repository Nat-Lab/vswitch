#include "tls-port-enumerator.h"
#include <arpa/inet.h>
#include <stdio.h>

TlsPortEnumerator::TlsPortEnumerator (
const char *ca_path, const char *server_crt, const char *server_key,
const char *bind_addr, in_port_t bind_port) {
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    auto ssl_method = (SSL_METHOD *) TLSv1_2_method();
    ssl_ctx = SSL_CTX_new(ssl_method);

    if (!SSL_CTX_use_certificate_file(ssl_ctx, server_crt, SSL_FILETYPE_PEM)) {
        fprintf(stderr, "[CRIT] SSL_CTX_use_certificate_file error:\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    if (!SSL_CTX_use_PrivateKey_file(ssl_ctx, server_key, SSL_FILETYPE_PEM)) {
        fprintf(stderr, "[CRIT] SSL_CTX_use_PrivateKey_file error:\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    if (!SSL_CTX_load_verify_locations(ssl_ctx, ca_path, NULL)) {
        fprintf(stderr, "[CRIT] SSL_CTX_load_verify_locations error:\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    memset(&listen_addr, 0, sizeof(struct sockaddr_in));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(bind_port);
    inet_pton(AF_INET, bind_addr, &(listen_addr.sin_addr));
    master_fd = -1;
    this_name = (char *) malloc(64);
    sprintf(this_name, "TlsPortEnumerator@%s:%d", bind_addr, bind_port);
}

bool TlsPortEnumerator::Start() {
    char ip_str[INET_ADDRSTRLEN];

    master_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (master_fd < 0) {
        fprintf(stderr, "[CRIT] TlsPortEnumerator::Start: socket(): %s.\n", strerror(errno));
        Stop();
        return false;
    }

    if (bind(master_fd, (struct sockaddr *) &listen_addr, sizeof(struct sockaddr_in)) < 0) {
        fprintf(stderr, "[CRIT] TlsPortEnumerator::Start: bind(): %s.\n", strerror(errno));
        Stop();
        return false;
    }

    if (listen(master_fd, TCP_QUEUE_LEN) < 0) {
        fprintf(stderr, "[CRIT] TlsPortEnumerator::Start: listen(): %s.\n", strerror(errno));
        Stop();
        return false;
    }

    inet_ntop(AF_INET, &(listen_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
    fprintf(stderr, "[INFO] TlsPortEnumerator::Start: listening on %s:%d.\n", ip_str, ntohs(listen_addr.sin_port));

    return true;
}

bool TlsPortEnumerator::Stop () {
    for (auto port = ports.begin(); port != ports.end(); port++) {
        (*port)->Close();
        delete *port;
    }
    ports.clear();

    if (close(master_fd) == 0) return true;
    fprintf(stderr, "[INFO] TlsPortEnumerator::Stop: close(): %s.\n", strerror(errno));
    return false;
}

Port* TlsPortEnumerator::GetPort(void) {
    char ip_str[INET_ADDRSTRLEN];
    struct sockaddr_in remote_addr;
    socklen_t remote_addr_len = sizeof(struct sockaddr_in);

    while (true) {
        int client_fd = accept(master_fd, (struct sockaddr *) &remote_addr, &remote_addr_len);

        if (client_fd < 0) {
            fprintf(stderr, "[CRIT] TlsPortEnumerator::GetPort: accept(): %s.\n", strerror(errno));
            Stop();
            return 0;
        }

        inet_ntop(AF_INET, &(remote_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
        fprintf(stderr, "[INFO] TlsPortEnumerator::GetPort: new port: src: %s:%d (fd = %d).\n", ip_str, ntohs(remote_addr.sin_port), client_fd);

        SSL *ssl = SSL_new(ssl_ctx);
        if (ssl == 0) {
            fprintf(stderr, "[CRIT] TlsPortEnumerator::GetPort: SSL_new() error:\n");
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            return 0;
        }

        if(!SSL_set_fd(ssl, client_fd)) {
            fprintf(stderr, "[CRIT] TlsPortEnumerator::GetPort: SSL_set_fd() error:\n");
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            return 0;
        }

        int accept_ret = SSL_accept(ssl);

        if (accept_ret == 0) {
            fprintf(stderr, "[WARN] TlsPortEnumerator::GetPort: SSL_accept() auth failed:\n");
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            continue;
        }

        if (accept_ret < 0) {
            fprintf(stderr, "[CRIT] TlsPortEnumerator::GetPort: SSL_accept() fatal error:\n");
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            return 0;
        }

        fprintf(stderr, "[INFO] TlsPortEnumerator::GetPort: TLS session established.\n");
        X509 *cert = SSL_get_peer_certificate(ssl);
        char *line;
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        fprintf(stderr, "[INFO] TlsPortEnumerator::GetPort: subject_name: %s.\n", line);
        OPENSSL_free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        fprintf(stderr, "[INFO] TlsPortEnumerator::GetPort: issuer: %s.\n", line);
        OPENSSL_free(line);

        TlsPort *p = new TlsPort(ssl, client_fd);
        ports.push_back(p);

        return p;
    }

}

const char* TlsPortEnumerator::GetName(void) {
    return this_name;
}

TlsPortEnumerator::~TlsPortEnumerator() {
    Stop();
}