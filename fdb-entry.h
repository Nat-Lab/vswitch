#ifndef FDB_ENTRY_H
#define FDB_ENTRY_H

#include <net/ethernet.h>
#include <string.h>
#include "port.h"

class FdbEntry {
public:
    FdbEntry (Port *port, const struct ether_addr *addr);
    bool DestinationIs (const struct ether_addr *addr) const;
    Port* GetPort (void) const;
    const struct ether_addr* GetAddr (void) const;
    bool operator== (const FdbEntry &other) const;

private:
    Port *port;
    struct ether_addr addr;
};

#endif // FDB_ENTRY_H 