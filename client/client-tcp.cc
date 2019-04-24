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

#include <thread>

#define MAX_PAYLOAD 65536

typedef struct payload_t {
    uint16_t payload_len;
    uint8_t payload[MAX_PAYLOAD];
} payload_t;

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

void tap_to_sock (int tap_fd, int sock_fd) {
    payload_t *payload = (payload_t *) malloc(sizeof(payload_t));
    ssize_t len, wr_len;
    while ((len = read(tap_fd, &(payload->payload), 65536)) > 0) {
        payload->payload_len = len;
        wr_len = write(sock_fd, payload, (size_t) len + 2);
        if (wr_len != len + 2) {
            fprintf(stderr, "[CRIT] tap_to_sock: written != len.\n");
            return;
        }
    }
    fprintf(stderr, "[CRIT] tap_to_sock: read returned <= 0.\n");
}

void sock_to_tap (int tap_fd, int sock_fd) {
    payload_t *payload = (payload_t *) malloc(sizeof(payload_t));
    ssize_t len, wr_len;
    while ((len = read(sock_fd, payload, 2)) > 0) {
        uint16_t payload_len = payload->payload_len;
        size_t buffered = 0;
        uint8_t *payload_ptr = payload->payload;
        while (buffered < payload_len) {
            len = read(sock_fd, payload_ptr + buffered, payload_len - buffered);
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
    fprintf (stderr, "usage: %s -s server -p port -d device_name [-u uid] [-g gid]\n", me);
}

int main (int argc, char **argv) {
    char *tap_name = (char *) malloc(IFNAMSIZ);
    char *server_addr = (char *) malloc(12);
    in_port_t server_port = 0;

    uid_t uid = 65534;
    gid_t gid = 65534;

    bool s = false; 
    bool p = false;
    bool d = false;

    char opt;
    while ((opt = getopt(argc, argv, "s:p:d:u:g:")) != -1) {
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
            default:
                print_help (argv[0]);
                return 1;
        }
    }

    if (!s || !p || !d) {
        print_help (argv[0]);
        return 1;
    }

    int tap_fd = tap_alloc(tap_name);
    if (tap_fd < 0) {
        fprintf(stderr, "[CRIT] tap_alloc: %s.\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "[INFO] tap_alloc: allocated: %s.\n", tap_name);

    if (setgid (gid) != 0) {
        fprintf(stderr, "[CRIT] failed to drop root privilege: setgid(): %s.\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "[INFO] gid is now: %d.\n", gid);

    if (setuid (uid) != 0) {
        fprintf(stderr, "[CRIT] failed to drop root privilege: setuid(): %s.\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "[INFO] uid is now: %d.\n", uid);

    int sock_fd = server_connect(server_addr, server_port);
    if (sock_fd < 0) {
        fprintf(stderr, "[CRIT] server_connect: %s.\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "[INFO] server_connect: connected.\n");

    std::thread s2t (sock_to_tap, tap_fd, sock_fd);
    std::thread t2s (tap_to_sock, tap_fd, sock_fd);

    s2t.join();
    t2s.join();

    return 0;
}