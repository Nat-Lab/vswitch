#include "switch.h"
#include <thread>
#include <stdio.h>
#include <unistd.h>

void Switch::Plug(Port *port) {
    fprintf(stderr, "[INFO] Switch::Forward: plugging in port %d.\n", port->GetId());
    std::thread listener_thread (&Switch::Listener, this, port);
    listener_thread.detach();
}

void Switch::Unplug(Port *port) {
    port->Close();
    mtx.lock();
    auto fdb_it = fdb.begin();
    while (fdb_it != fdb.end()) {
        if (fdb_it->GetPort() == port) fdb.erase(fdb_it);
        else fdb_it++;
    }
    mtx.unlock();
    fprintf(stderr, "[INFO] Switch::Unplug: unplugged port %d.\n", port->GetId());
}

void Switch::AddPortEnumerator(PortEnumerator *penum) {
    fprintf(stderr, "[INFO] Switch::AddPortEnumerator: adding '%s'.\n", penum->GetName());
    penum->Start();
    std::thread enum_thread (&Switch::EnumeratorHandler, this, penum);
    enum_thread.detach();
}

void Switch::Forward(Port *src_port, const uint8_t *buffer, size_t buf_len) {
    auto eth_hdr = (const struct ether_header *) buffer;
    auto eth_addr = (const uint16_t *) eth_hdr->ether_dhost;

    if (eth_addr[0] == 0xFFFF && eth_addr[1] == 0xFFFF && eth_addr[2] == 0xFFFF) {
        // dst = broadcast
        mtx.lock();
        auto fdb_it = fdb.begin();
        while (fdb_it != fdb.end()) {
            Port *port = fdb_it->GetPort();
            if (port != src_port) {
                ssize_t len = port->Write(buffer, buf_len);
                if ((size_t) len != buf_len) {
                    fprintf(stderr, "[WARN] Switch::Forward: writing to port %d failed, remove from fdb.\n", port->GetId());
                    fdb.erase(fdb_it);
                } else fdb_it++;
            }
        }
        mtx.unlock();
        return;
    }

    mtx.lock();
    auto fdb_it = fdb.begin();
    while (fdb_it != fdb.end()) {
        if (fdb_it->DestinationIs((struct ether_addr *) eth_hdr->ether_dhost)) {
            Port *port = fdb_it->GetPort();
            ssize_t len = port->Write(buffer, buf_len);
            if ((size_t) len != buf_len) {
                fprintf(stderr, "[WARN] Switch::Forward: writing to port %d failed, remove from fdb.\n", port->GetId());
                fdb.erase(fdb_it);
            } else fdb_it++;
        }
    }
    mtx.unlock();
}

void Switch::Listener(Port *port) {
    ssize_t len = -1;
    uint8_t *buffer = (uint8_t *) malloc(65536);
    while ((len = port->Read(buffer, 65535)) > 0) {
        if (len <= 0) {
            fprintf(stderr, "[WARN] Switch::Listener: reading from port %d failed, unplug.\n", port->GetId());
            Unplug(port);
            return;
        }

        auto eth_hdr = (const struct ether_header *) buffer;
        auto eth_addr = (const struct ether_addr *) eth_hdr->ether_shost;
        FdbEntry new_entry (port, eth_addr);
        for (auto &fdb_entry : fdb) {
            if (fdb_entry == new_entry) goto forward;
        }

        mtx.lock();
        fdb.push_back(new_entry);
        mtx.unlock();

forward:
        Forward(port, buffer, (size_t) len);
    }
}

void Switch::EnumeratorHandler(PortEnumerator *pe) {
    Port *p = 0;
    while ((p = pe->GetPort()) != 0) Plug(p);
}