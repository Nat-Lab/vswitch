#include "switch.h"
#include "port.h"
#include "port-enumerator.h"

#include "tap-port.h"
#include "tcp-port-enumerator.h"
#include "tls-port-enumerator.h"

#include <getopt.h>

void do_list_port () {
    fprintf(stderr, "avaliable port types and arguments:\n");
    fprintf(stderr, "port tap (port): arg: --dev dev_name\n");
    fprintf(stderr, "port tcp (port-enum): arg: --bind server_address --port server_port\n");
    fprintf(stderr, "port tls (port-enum): arg: --ca ca_path --cert cert_path --key cert_key_path --bind server_address --port server_port\n");
}

void do_help (const char *me) {
    fprintf(stderr, "%s --help\n", me);
    fprintf(stderr, "%s --list-ports\n", me);
    fprintf(stderr, "%s [--add-port type [args...]] ...\n", me);
}

bool do_parse_tap_port (int argc, char** argv, std::vector<Port *> &ports) {
    static struct option tap_options[] = {
        {"dev", required_argument, 0, 'd'},
        {"add-port", required_argument, 0, 'A'},
        {0, 0, 0, 0}
    };

    int opt_idx = -1;
    char opt = getopt_long(argc, argv, "d:", tap_options, &opt_idx);

    if (opt == ':') return false;
    if (opt == '?') return false;
    if (opt == 'A' || opt == -1) {
        fprintf(stderr, "%s: tap-port: missing arguments.\n", argv[0]);
        return false;
    }

    TapPort *tap = new TapPort(optarg);
    ports.push_back(tap);
    
    return true;
}

bool do_parse_tcp_ports (int argc, char** argv, std::vector<PortEnumerator *> &enums) {
    static struct option tls_options[] = {
        {"bind", required_argument, 0, 'b'},
        {"port", required_argument, 0, 'p'},
        {"add-port", required_argument, 0, 'A'},
        {0, 0, 0, 0}
    };

    char *bind_addr = (char *) malloc(16);
    in_port_t port = 0;
    bool b = false;
    bool p = false;

    int opt_idx = 0;
    char opt;
    while ((opt = getopt_long(argc, argv, "b:p:", tls_options, &opt_idx)) >= 0) {
        switch (opt) {
            case -1:
                goto tcp_do_check;
            case 'A':
                optind -= 2;
                goto tcp_do_check;
            case ':':
            case '?':
                return false;
            case 'b':
                b = true;
                strncpy(bind_addr, optarg, 16);
                break;
            case 'p':
                p = true;
                port = atoi(optarg);
                break;
        }
    }

tcp_do_check:
    if (!b || !p) {
        fprintf(stderr, "%s: tcp-port-enum: missing arguments.\n", argv[0]);
        return false;
    }
    TcpPortEnumerator *tcp_port_enum = new TcpPortEnumerator (bind_addr, port);
    enums.push_back(tcp_port_enum);
    return true;
}

bool do_parse_tls_ports (int argc, char** argv, std::vector<PortEnumerator *> &enums) {
    static struct option tls_options[] = {
        {"ca", required_argument, 0, 'C'},
        {"cert", required_argument, 0, 'c'},
        {"key", required_argument, 0, 'k'},
        {"bind", required_argument, 0, 'b'},
        {"port", required_argument, 0, 'p'},
        {"add-port", required_argument, 0, 'A'},
        {0, 0, 0, 0}
    };

    char *bind_addr = (char *) malloc(16);
    char *ca_path = (char *) malloc(PATH_MAX);
    char *cert_path = (char *) malloc(PATH_MAX);
    char *cert_key_path = (char *) malloc(PATH_MAX);
    in_port_t port = 0;

    bool C = false;
    bool c = false;
    bool k = false;
    bool b = false;
    bool p = false;

    int opt_idx = 0;
    char opt;
    while ((opt = getopt_long(argc, argv, "C:c:k:b:p:", tls_options, &opt_idx)) >= 0) {
        switch (opt) {
            case -1:
                goto tls_do_check;
            case 'A':
                optind -= 2;
                goto tls_do_check;
            case ':':
            case '?':
                return false;
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
            case 'b':
                b = true;
                strncpy(bind_addr, optarg, 16);
                break;
            case 'p':
                p = true;
                port = atoi(optarg);
                break;
        }
    }

tls_do_check:
    if (!c || !C || !k || !b || !p) {
        fprintf(stderr, "%s: tls-port-enum: missing arguments.\n", argv[0]);
        return false;
    }
    TlsPortEnumerator *tls_port_enum = new TlsPortEnumerator (ca_path, cert_path, cert_key_path, bind_addr, port);
    enums.push_back(tls_port_enum);
    return true;
}

int main (int argc, char** argv) {
    std::vector<PortEnumerator *> port_enums;
    std::vector<Port *> ports;

    static struct option main_options[] = {
        {"add-port", required_argument, 0, 'a'},
        {"list-ports", no_argument, 0, 'l'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt_idx = 0;
    char opt;
    while ((opt = getopt_long(argc, argv, "a:", main_options, &opt_idx)) >= 0) {
        if (opt == 'a') {
            if (memcmp("tap", optarg, 3) == 0) {
                if (!do_parse_tap_port(argc, argv, ports)) return 1;
                continue;
            }
            if (memcmp("tls", optarg, 3) == 0) {
                if (!do_parse_tls_ports(argc, argv, port_enums)) return 1;
                continue;
            }
            if (memcmp("tcp", optarg, 3) == 0) {
                if (!do_parse_tcp_ports(argc, argv, port_enums)) return 1;
                continue;
            }
        }

        if (opt == 'h') {
            do_help(argv[0]);
            return 0;
        }

        if (opt == 'l') {
            do_list_port();
            return 0;
        }

        if (opt == ':') return 1;
    }

    if (port_enums.size() == 0 && ports.size() == 0) {
        do_help(argv[0]);
        return 0;
    }

    Switch sw;

    for (auto &e : port_enums) sw.AddPortEnumerator(e);
    for (auto &p : ports) sw.Plug(p);

    sw.Join();
    return 0;
}