#ifndef SWITCH_H
#define SWITCH_H

#include <stdint.h>
#include <vector>
#include <mutex>
#include <thread>

#include "fdb-entry.h"
#include "port.h"
#include "port-enumerator.h"

class Switch {
public:
    // plug a port into switch
    void Plug(Port *port);

    // unplug a port from switch
    void Unplug(Port *port);

    // add a port enumerator to switch
    void AddPortEnumerator(PortEnumerator *penum);

    // unplug all ports & stop
    void Shutdown();

    // join switch thread
    void Join();
private:
    // forward traffic to other ports
    void Forward(Port *src_port, const uint8_t *buffer, size_t buf_len);

    // listen on a port for incoming traffic
    void Listener(Port *port);

    // handle port add for PortEnumerator.
    void EnumeratorHandler (PortEnumerator *penum);

    std::vector<std::thread> listener_threads;
    std::vector<std::thread> enum_threads;
    std::vector<PortEnumerator *> enums;
    std::vector<FdbEntry> fdb;
    std::mutex mtx;
};

#endif // SWITCH_H