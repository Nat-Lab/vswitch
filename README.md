vSwitch
---

vSwitch is a simple multi-protocol virtual switch that switches ethernet traffic between different Layer 2 tunneling protocols.

vSwitch abstract different protocol as `Port` and do L2 switching among connected ports. There are two types of port: `Port` and `PortEnumerator`. A `Port` is an abstraction of a single "tunnel." It can be a TAP interface on the vSwitch host, a socket file descriptor, or anything that act likes a file descriptor. A `PortEnumerator` is an abstraction of a switch extension. `PortEnumerator` generate ports dynamically while running. `PortEnumerator` could be something like a connection-based socket (e.g., TCP), that will constantly create new port as the client connects.

Currently, the following `Port`s and `PortEnumerator`s are available:

|Name|Type|Arguments|
--|--|--
eoip|`port`|`--local local_addr --peer peer_addr --id tunnel_id`
tap|`port`|`--dev dev_name`
tcp|`portenum`|`--bind server_address --port server_port`
tls|`portenum`|`--ca ca_path --cert cert_path --key cert_key_path --bind server_address --port server_port --mode mode`

`tls` is a port that accepts TLS TCP connection. There are two modes available: `cert` and `userpass`. Cert authenticates the client with CA (i.e., the client needs to have a valid certificate signed by CA), and `userpass` authenticates the client with PAM authentication with username/password pair provided by the client.

The TLS port client, `client-tls` also authenticate server with CA. In addition to that, `client-tls` will also check for the server's common name and will refuse to connect if the common name does not match.

The other ports do what you expect them to do. Their argument should be pretty self-explanatory.

### Installation

Dependency: `libssl`

Download and build vSwitch with the following command:

```
$ git clone https://github.com/magicnat/vswitch
$ cd vswitch
$ make -j
```

If the build succeeded, you should find vSwitch server & client binaries under `vswitch/bin/`.

### Usage

```
./vswitch --help
./vswitch --list-ports
./vswitch [--add-port type [args...]] ...
```

`./vswitch --help` prints the help message above, `./vswitch --list-ports` lists all available `Port`s and `PortEnumerator`s. Lunching `vswitch` with one or more `--add-port` arguments will start the switch with ports you specified. 

For example, to start a vSwitch that open a TAP interface on vSwitch host with name `tap-vswitch`, and a TLS switch extersion with certificate mode, use the following argument:

```
# ./vswitch --add-port tap --dev tap-vswitch --add-port tls --ca certs/ca.crt --cert certs/server.crt --key certs/server.key --bind 0.0.0.0 --port 1443 --mode cert
```

To connect to the TLS switch extension with `client-tls`, use the following argument (assume server is at `172.30.0.1` and has CN `server-name.local`): 

```
# ./client-tls -d tap-client -s 172.30.0.1 -p 1443 -n server-name.local -C certs/ca.crt -c certs/client.crt -k certs/client.key -m cert
```

### Development

Adding new protocol support to vSwitch is simple. What you need is to implement a `Port` and/or a `PortEnumerator`. The definition of these two interfaces can be found in `server/port-enumerator.h` and `server/port.h`. 

Once you have your `Port` or `PortEnumerator` created, you can use it with vSwitch. The `vswitch` binary is just a CLI wrapper. To create a vSwitch programmatically, create a `Switch` instance, then use `Switch::Plug` to have `PortEnumerator` or `Port` install to the switch. 

Here's an example that creates a simple vSwitch with TCP and TAP port:

```C++
#include "switch.h"
#include "tap-port.h"
#include "tcp-port-enumerator.h"

int main (int argc, char **argv) {
    Switch s;
    TapPort tap ("dev-vswitch");
    TcpPortEnumerator tcp ("0.0.0.0", 1234);

    // plug tcp extersion switch into main switch
    s.Plug(&tcp);

    // plug tap interface into main switch
    s.Plug(&tap);

    // join the switching thread.
    s.Join();

    return 0;
}
```

### License

MIT