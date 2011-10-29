DESTDIR ?=
NSSDIR ?= /usr/lib

LIBUNBOUND ?= unbound
LIBDIRS ?=

CC = gcc
CFLAGS = --std=gnu99 -fPIC -O2 -g -ggdb -Wall
LDFLAGS = -l$(LIBUNBOUND) $(LIBDIRS)
STATIC_LDFLAGS = -Wl,-Bstatic -l$(LIBUNBOUND) -lldns -Wl,-Bdynamic -lcrypto -lpthread $(LIBDIRS)

MODULE = libnss_ubdns.so.2

BINS = $(MODULE)

all: $(BINS)

OBJS = arpa.o domain_to_str.o lookup.o nss-ubdns.o

ifdef STATIC_LIBUNBOUND
$(MODULE): $(OBJS)
	$(CC) -fPIC -shared -Wl,-h,$(MODULE) -Wl,--version-script,nss_ubdns.map -o $@ $^ $(STATIC_LDFLAGS)
else
$(MODULE): $(OBJS)
	$(CC) -fPIC -shared -Wl,-h,$(MODULE) -Wl,--version-script,nss_ubdns.map -o $@ $^ $(LDFLAGS)
endif

clean:
	rm -f $(BINS) $(OBJS)

install:
	mkdir -p $(DESTDIR)$(NSSDIR)
	install -m 0644 $(MODULE) $(DESTDIR)$(NSSDIR)/$(MODULE)

.PHONY: all clean install
