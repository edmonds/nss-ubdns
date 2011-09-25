CC = gcc
CFLAGS = --std=gnu99 -fPIC -O2 -g -ggdb -Wall
LDFLAGS = -lunbound

BINS = libnss_ubdns.so.2

all: $(BINS)

UBDNS_OBJS = arpa.o domain_to_str.o lookup.o ubdns.o

libnss_ubdns.so.2: $(UBDNS_OBJS)
	$(CC) -fPIC -shared -Wl,-h,libnss_ubdns.so.2 -Wl,--version-script,nss_ubdns.map -o $@ $(LDFLAGS) $^

clean:
	rm -f $(BINS) $(UBDNS_OBJS)

.PHONY: all clean
