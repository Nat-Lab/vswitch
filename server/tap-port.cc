#include "tap-port.h"

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

#include <linux/if.h>
#include <linux/if_tun.h>

TapPort::TapPort(const char *dev_name) {
    tap_name = (char *) malloc(IFNAMSIZ);
    strcpy(tap_name, dev_name);
}

ssize_t TapPort::Read(uint8_t *buffer, size_t len) {
    return read(tap_fd, buffer, len);
}

ssize_t TapPort::Write(const uint8_t *buffer, size_t len) {
    return write(tap_fd, buffer, len);
}

bool TapPort::Open() {
    const char *tun_dev = "/dev/net/tun";
    
    tap_fd = open(tun_dev, O_RDWR);
    if (tap_fd < 0) {
        fprintf(stderr, "[CRTT] TapPort::TapPort: open(): %s\n", strerror(errno));
        return false;
    }

    struct ifreq ifr;
    memset (&ifr, 0, sizeof(struct ifreq));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, tap_name, IFNAMSIZ);

    int ioctl_ret = ioctl(tap_fd, TUNSETIFF, (void *) &ifr);
    if (ioctl_ret < 0) {
        fprintf(stderr, "[CRTT] TapPort::TapPort: ioctl(): %s\n", strerror(errno));
        return false;
    }

    strcpy(tap_name, ifr.ifr_name);
    fprintf(stderr, "[INFO] TapPort::TapPort: tap '%s' allocated, fd=%d\n", tap_name, tap_fd);

    return true;
}

int TapPort::Close() {
    return close(tap_fd);
}

int TapPort::GetId(void) const {
    return tap_fd;
}

const char* TapPort::GetTapName(void) const {
    return tap_name;
}

TapPort::~TapPort() {
    close(tap_fd);
}