CFLAGS=-std=c++11 -O3 -Wall -lpthread -lssl -lcrypto
OBJS_SERVER=server/fdb-entry.o server/port.o server/switch.o server/tap-port.o server/tcp-port.o server/tcp-port-enumerator.o server/tls-port.o server/tls-port-enumerator.o server/vswitch.o
TARGETS=bin/vswitch bin/client-tcp bin/client-tls
CC=g++

.PHONY: all
all: $(TARGETS)

bin:
	mkdir -p bin

bin/client-tcp: bin
	$(CC) -o bin/client-tcp client/client-tcp.cc $(CFLAGS)

bin/client-tls: bin
	$(CC) -o bin/client-tls client/client-tls.cc $(CFLAGS)

bin/vswitch: bin $(OBJS_SERVER)
	$(CC) -o bin/vswitch $(OBJS_SERVER) $(CFLAGS)

%.o: %.cc
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean
clean:
	rm -fr bin
	rm -f */*.o
