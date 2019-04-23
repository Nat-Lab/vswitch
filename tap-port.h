#ifndef TAP_PORT_H
#define TAP_PORT_H

#include "port.h"

class TapPort : public Port {
public:
    TapPort(char *dev_name);
    ssize_t Read(uint8_t *buffer, size_t len);
    ssize_t Write(const uint8_t *buffer, size_t len);
    int Close();
    int GetId(void) const;
    const char* GetTapName(void) const;
    ~TapPort();
private:
    int tap_fd;
    char *tap_name;
};

#endif // TAP_PORT_H