#include "switch.h"
#include "port.h"
#include "port-enumerator.h"

#include "eoip-port.h"
#include "eoip6-port.h"
#include "tap-port.h"
#include "tcp-port-enumerator.h"
#include "tls-port-enumerator.h"

#include <getopt.h>

void do_list_port () {
    fprintf(stderr, "avaliable port types and arguments:\n");
    fprintf(stderr, "port eoip (port): arg: --local local_addr --peer peer_addr --id tunnel_id\n");
    fprintf(stderr, "port eoip6 (port): arg: --local local_addr --peer peer_addr --id tunnel_id\n");
    fprintf(stderr, "port tap (port): arg: --dev dev_name\n");
    fprintf(stderr, "port tcp (port-enum): arg: --bind server_address --port server_port\n");
    fprintf(stderr, "port tls (port-enum): arg: --ca ca_path --cert cert_path --key cert_key_path --bind server_address --port server_port --mode {userpass|cert}\n");
}

void do_help (const char *me) {
    fprintf(stderr, "%s --help\n", me);
    fprintf(stderr, "%s --list-ports\n", me);
    fprintf(stderr, "%s [--add-port type [args...]] ...\n", me);
}

bool do_parse_eoip_port (int argc, char** argv, std::vector<Port *> &ports) {
    static struct option eoip_options[] = {
        {"local", required_argument, 0, 'l'},
        {"peer", required_argument, 0, 'p'},
        {"id", required_argument, 0, 'i'},
        {"add-port", required_argument, 0, 'A'},
        {0, 0, 0, 0}
    };

    char *local_addr = (char *) malloc(17);
    char *peer_addr = (char *) malloc(17);
    uint16_t tid = 0;

    bool l = false;
    bool i = false;
    bool p = false;

    int opt_idx = 0;
    char opt;
    while ((opt = getopt_long(argc, argv, "l:p:i:", eoip_options, &opt_idx)) >= 0) {
        switch (opt) {
            case -1:
                goto eoip_do_check;
            case 'A':
                optind -= 2;
                goto eoip_do_check;
            case ':':
            case '?':
                return false;
            case 'l':
                l = true;
                strncpy(local_addr, optarg, 17);
                break;
            case 'p':
                p = true;
                strncpy(peer_addr, optarg, 17);
                break;
            case 'i':
                i = true;
                tid = atoi(optarg);
                break;
        }
    }

eoip_do_check:
    if (!l || !i || !p) {
        fprintf(stderr, "%s: eoip-port: missing arguments.\n", argv[0]);
        return false;
    }

    EoipPort *eoip = new EoipPort (tid, local_addr, peer_addr);
    ports.push_back(eoip);

    return true;
}

bool do_parse_eoip6_port (int argc, char** argv, std::vector<Port *> &ports) {
    static struct option eoip_options[] = {
        {"local", required_argument, 0, 'l'},
        {"peer", required_argument, 0, 'p'},
        {"id", required_argument, 0, 'i'},
        {"add-port", required_argument, 0, 'A'},
        {0, 0, 0, 0}
    };

    char *local_addr = (char *) malloc(17);
    char *peer_addr = (char *) malloc(17);
    uint16_t tid = 0;

    bool l = false;
    bool i = false;
    bool p = false;

    int opt_idx = 0;
    char opt;
    while ((opt = getopt_long(argc, argv, "l:p:i:", eoip_options, &opt_idx)) >= 0) {
        switch (opt) {
            case -1:
                goto eoip6_do_check;
            case 'A':
                optind -= 2;
                goto eoip6_do_check;
            case ':':
            case '?':
                return false;
            case 'l':
                l = true;
                strncpy(local_addr, optarg, 17);
                break;
            case 'p':
                p = true;
                strncpy(peer_addr, optarg, 17);
                break;
            case 'i':
                i = true;
                tid = atoi(optarg);
                break;
        }
    }

eoip6_do_check:
    if (!l || !i || !p) {
        fprintf(stderr, "%s: eoip6-port: missing arguments.\n", argv[0]);
        return false;
    }

    Eoip6Port *eoip = new Eoip6Port (tid, local_addr, peer_addr);
    ports.push_back(eoip);

    return true;
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

    char *bind_addr = (char *) malloc(17);
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
                strncpy(bind_addr, optarg, 17);
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
        {"mode", required_argument, 0, 'm'},
        {0, 0, 0, 0}
    };

    char *bind_addr = (char *) malloc(17);
    char *ca_path = (char *) malloc(PATH_MAX);
    char *cert_path = (char *) malloc(PATH_MAX);
    char *cert_key_path = (char *) malloc(PATH_MAX);
    in_port_t port = 0;
    TlsPortEnumerator::AuthMode mode = TlsPortEnumerator::AuthMode::CERTIFICATE;

    bool C = false;
    bool c = false;
    bool k = false;
    bool b = false;
    bool p = false;
    bool m = false;

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
                strncpy(bind_addr, optarg, 17);
                break;
            case 'p':
                p = true;
                port = atoi(optarg);
                break;
            case 'm':
                m = true;
                if (memcmp("userpass", optarg, 8) == 0) {
                    mode = TlsPortEnumerator::AuthMode::USERPASS;
                } else mode = TlsPortEnumerator::AuthMode::CERTIFICATE;
                break;
        }
    }

tls_do_check:
    if (!c || !C || !k || !b || !p || !m) {
        fprintf(stderr, "%s: tls-port-enum: missing arguments.\n", argv[0]);
        return false;
    }
    TlsPortEnumerator *tls_port_enum = new TlsPortEnumerator (ca_path, cert_path, cert_key_path, bind_addr, port, mode);
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
            if (strcmp("eoip", optarg) == 0) {
                if (!do_parse_eoip_port(argc, argv, ports)) return 1;
                continue;
            }
            if (strcmp("eoip6", optarg) == 0) {
                if (!do_parse_eoip6_port(argc, argv, ports)) return 1;
                continue;
            }
            if (strcmp("tap", optarg) == 0) {
                if (!do_parse_tap_port(argc, argv, ports)) return 1;
                continue;
            }
            if (strcmp("tls", optarg) == 0) {
                if (!do_parse_tls_ports(argc, argv, port_enums)) return 1;
                continue;
            }
            if (strcmp("tcp", optarg) == 0) {
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

    for (auto &e : port_enums) sw.Plug(e);
    for (auto &p : ports) sw.Plug(p);

    sw.Join();
    return 0;
}