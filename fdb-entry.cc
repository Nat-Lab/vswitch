#include "fdb-entry.h"

FdbEntry::FdbEntry (Port *port, const struct ether_addr *addr) {
    this->port = port;
    memcpy(&(this->addr), addr, sizeof(struct ether_addr));
}

bool FdbEntry::DestinationIs (const struct ether_addr *addr) const {
    return memcmp(addr, &(this->addr), sizeof(struct ether_addr)) == 0;
}

Port* FdbEntry::GetPort (void) const {
    return port;
}

const struct ether_addr* FdbEntry::GetAddr (void) const {
    return &addr;
}

bool FdbEntry::operator== (const FdbEntry &other) const {
    return port == other.port && DestinationIs(&(other.addr));
}