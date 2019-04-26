#include "switch.h"
#include <stdio.h>
#include <unistd.h>
#include <netinet/ether.h>

void Switch::Plug(Port *port) {
    if (port->Open()) {
        fprintf(stderr, "[INFO] Switch::Plug: plugging in port %d.\n", port->GetId());
        ports.push_back(port);
        listener_threads.push_back(std::thread(&Switch::Listener, this, port));
    } else {
        fprintf(stderr, "[WARN] Switch::Plug: failed to open port %d.\n", port->GetId());
    }
    
}

void Switch::Plug(PortEnumerator *penum) {
    fprintf(stderr, "[INFO] Switch::AddPortEnumerator: adding '%s'.\n", penum->GetName());
    if(penum->Start()) enum_threads.push_back(std::thread(&Switch::EnumeratorHandler, this, penum));
    else fprintf(stderr, "[INFO] Switch::AddPortEnumerator: failed to start '%s'.\n", penum->GetName());
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
            } else fdb_it++;
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
        } else fdb_it++;
    }
    mtx.unlock();
}

void Switch::Listener(Port *port) {
    ssize_t len = -1;
    uint8_t *buffer = (uint8_t *) malloc(65536);
    char* addr_str;
    while ((len = port->Read(buffer, 65535)) > 0) {
        auto eth_hdr = (const struct ether_header *) buffer;
        auto eth_addr = (const struct ether_addr *) eth_hdr->ether_shost;
        FdbEntry new_entry (port, eth_addr);
        for (auto &fdb_entry : fdb) {
            if (fdb_entry == new_entry) goto forward;
        }

        mtx.lock();
        fdb.push_back(new_entry);
        mtx.unlock();

        addr_str = ether_ntoa(eth_addr);
        fprintf(stderr, "[INFO] Switch::Listener: new host: %s @ port %d.\n", addr_str, port->GetId());

forward:
        Forward(port, buffer, (size_t) len);
    }

    fprintf(stderr, "[WARN] Switch::Listener: reading from port %d failed, unplug.\n", port->GetId());
    Unplug(port);
}

void Switch::EnumeratorHandler(PortEnumerator *pe) {
    Port *p = 0;
    while ((p = pe->GetPort()) != 0) Plug(p);
    fprintf(stderr, "[WARN] Switch::EnumeratorHandler: Enumerator '%s' stopped.\n", pe->GetName());
}

void Switch::Shutdown() {
    for (auto &e : enums) {
        e->Stop();
    }
    for (auto &p : ports) {
        p->Close();
    }
}

void Switch::Join() {
    for (auto &t : listener_threads) {
        if (t.joinable()) t.join();
    }
    for (auto &t : enum_threads) {
        if (t.joinable()) t.join();
    }
}