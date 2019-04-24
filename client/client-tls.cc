#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/limits.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <thread>

#define MAX_PAYLOAD 65536

typedef struct payload_t {
    uint16_t payload_len;
    uint8_t payload[MAX_PAYLOAD];
} payload_t;

int do_verify (int ok, X509_STORE_CTX *x509_ctx) {
    char cn[255];
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), cn, 255);
    fprintf(stderr, "[INFO] remote CN: %s\n", cn);
    return ok;
}

SSL* ssl_init (const char *ca_path, const char *cert_path, const char *key_path, const char *server_cn) {
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

	SSL_METHOD *method = (SSL_METHOD *) TLSv1_2_method();
	SSL_CTX* ctx = SSL_CTX_new(method);

	if (!SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM)) {
		fprintf(stderr, "[CRIT] SSL_CTX_use_certificate_file() error:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}
	if (!SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM)) {
		fprintf(stderr, "[CRIT] SSL_CTX_use_PrivateKey_file() error:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}
	if (!SSL_CTX_load_verify_locations(ctx, ca_path, NULL)) {
		fprintf(stderr, "[CRIT] SSL_CTX_load_verify_locations() error:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, do_verify);
	SSL *ssl = SSL_new(ctx);
	X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
	if (!X509_VERIFY_PARAM_set1_host(vpm, server_cn, 0)) {
		fprintf(stderr, "[CRIT] X509_VERIFY_PARAM_set1_host() failed.\n");
		return 0;
	};
	return ssl;
}

int tap_alloc (char *dev_name) {
    const char *tun_dev = "/dev/net/tun";
    
    int fd = open(tun_dev, O_RDWR);
    if (fd < 0) return fd;

    struct ifreq ifr;
    memset (&ifr, 0, sizeof(struct ifreq));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);

    int ioctl_ret = ioctl(fd, TUNSETIFF, (void *) &ifr);
    if (ioctl_ret < 0) return ioctl_ret;

    strcpy(dev_name, ifr.ifr_name);

    return fd;
}

int server_connect (char *addr, in_port_t port) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(struct sockaddr_in));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    int inet_pton_ret = inet_pton(AF_INET, addr, &server_addr.sin_addr);
    if (inet_pton_ret < 0) return inet_pton_ret;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return fd;

    int conn_ret = connect(fd, (struct sockaddr *) &server_addr, sizeof(struct sockaddr_in));
    if (conn_ret < 0) return conn_ret;

    return fd;
}

void tap_to_sock (int tap_fd, SSL *ssl) {
    payload_t *payload = (payload_t *) malloc(sizeof(payload_t));
    ssize_t len, wr_len;
    while ((len = read(tap_fd, &(payload->payload), 65536)) > 0) {
        payload->payload_len = len;
        wr_len = SSL_write(ssl, payload, (size_t) len + 2);
        if (wr_len != len + 2) {
            fprintf(stderr, "[CRIT] tap_to_sock: written != len.\n");
            return;
        }
    }
    fprintf(stderr, "[CRIT] tap_to_sock: read returned <= 0.\n");
}

void sock_to_tap (int tap_fd, SSL *ssl) {
    payload_t *payload = (payload_t *) malloc(sizeof(payload_t));
    ssize_t len, wr_len;
    while ((len = SSL_read(ssl, payload, 2)) > 0) {
        uint16_t payload_len = payload->payload_len;
        size_t buffered = 0;
        uint8_t *payload_ptr = payload->payload;
        while (buffered < payload_len) {
            len = SSL_read(ssl, payload_ptr + buffered, payload_len - buffered);
            if (len < 0) break;
            buffered += len;
        }
        wr_len = write(tap_fd, payload_ptr, buffered);
        if (wr_len < 0) {
            fprintf(stderr, "[CRIT] sock_to_tap: read returned <= 0.\n");
            return;
        }
        if ((size_t) wr_len != buffered) {
            fprintf(stderr, "[CRIT] sock_to_tap: written != buffered.\n");
            return;
        }
    }
    fprintf(stderr, "[CRIT] sock_to_tap: read returned <= 0.\n");
}

void print_help (const char *me) {
    fprintf (stderr, "usage: %s -s server -p port -n server_name -d device_name -C ca_path -c cert_path -k cert_key_path [-u uid] [-g gid]\n", me);
}

int main (int argc, char **argv) {
    char *tap_name = (char *) malloc(IFNAMSIZ);
    char *server_addr = (char *) malloc(16);
	char *ca_path = (char *) malloc(PATH_MAX);
	char *cert_path = (char *) malloc(PATH_MAX);
	char *cert_key_path = (char *) malloc(PATH_MAX);
	char *server_name = (char *) malloc(64);
    in_port_t server_port = 0;

    uid_t uid = 65534;
    gid_t gid = 65534;

    bool s = false; 
    bool p = false;
    bool c = false;
	bool C = false;
    bool d = false;
	bool n = false;
	bool k = false;

    char opt;
    while ((opt = getopt(argc, argv, "s:p:d:u:g:C:c:k:n:")) != -1) {
        switch (opt) {
            case 's':
                s = true;
                strncpy(server_addr, optarg, 12);
                break;
            case 'p':
                p = true;
                server_port = atoi (optarg);
                break;
            case 'd':
                d = true;
                strncpy(tap_name, optarg, IFNAMSIZ);
                break;
            case 'u':
                uid = atoi (optarg);
                break;
            case 'g':
                gid = atoi (optarg);
                break;
			case 'C':
				C = true;
				strncpy(ca_path, optarg, PATH_MAX);
                break;
			case 'c':
				c = true;
				strncpy(cert_path, optarg, PATH_MAX);
                break;
			case 'k':
				k = true;
				strncpy(cert_key_path, optarg, PATH_MAX);
                break;
			case 'n':
				n = true;
				strncpy(server_name, optarg, 64);
                break;
            default:
                print_help (argv[0]);
                return 1;
        }
    }

    if (!s || !p || !d || !k || !n || !c || !C) {
        print_help (argv[0]);
        return 1;
    }

    int tap_fd = tap_alloc(tap_name);
    if (tap_fd < 0) {
        fprintf(stderr, "[CRIT] tap_alloc: %s.\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "[INFO] tap_alloc: allocated: %s.\n", tap_name);

	SSL *ssl = ssl_init(ca_path, cert_path, cert_key_path, server_name);
	if (ssl == 0) {
		fprintf(stderr, "[CRIT] ssl_init error.\n");
        return 1;
	}

    if (setgid (gid) != 0) {
        fprintf(stderr, "[CRIT] setgid(): %s.\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "[INFO] gid is now: %d.\n", gid);

    if (setuid (uid) != 0) {
        fprintf(stderr, "[CRIT] setuid(): %s.\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "[INFO] uid is now: %d.\n", uid);

    int sock_fd = server_connect(server_addr, server_port);
    if (sock_fd < 0) {
        fprintf(stderr, "[CRIT] server_connect: %s.\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "[INFO] server_connect: connected.\n");

	SSL_set_fd(ssl, sock_fd);
	int conn_ret = SSL_connect(ssl);
	if (conn_ret <= 0) {
		fprintf(stderr, "[CRIT] SSL_connect: error:\n");
		ERR_print_errors_fp(stderr);
		return 1;
	}
	fprintf(stderr, "[INFO] SSL_connect: TLS session established, cipher: %s.\n", SSL_get_cipher(ssl));

    std::thread s2t (sock_to_tap, tap_fd, ssl);
    std::thread t2s (tap_to_sock, tap_fd, ssl);

    s2t.join();
    t2s.join();

    return 0;
}