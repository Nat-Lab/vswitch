#ifndef SWITCH_H
#define SWITCH_H

#include <stdint.h>
#include <vector>
#include <mutex>

#include "fdb-entry.h"
#include "port.h"

class Switch {
public:
    // plug a port into switch
    void Plug(Port *port);

    // unplug a port from switch
    void Unplug(Port *port);
private:
    // forward traffic to other ports
    void Forward(Port *src_port, const uint8_t *buffer, size_t buf_len);

    // listen on a port for incoming traffic
    void Listener(Port *port);
    std::vector<FdbEntry> fdb;
    std::mutex mtx;
};

#endif // SWITCH_H