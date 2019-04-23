#ifndef SWITCH_H
#define SWITCH_H

#include <stdint.h>
#include <vector>
#include <mutex>

#include "fdb-entry.h"
#include "port.h"

class Switch {
public:
    void Plug(Port *port);
    void Unplug(Port *port);
private:
    void Forward(Port *src_port, const uint8_t *buffer, size_t buf_len);
    void Listener(Port *port);
    std::vector<FdbEntry> fdb;
    std::mutex mtx;
};

#endif // SWITCH_H