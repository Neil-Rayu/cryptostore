CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -I../include

all: cryptoctl

cryptoctl: cryptoctl.c ../include/cryptostore_ioctl.h ../include/cryptostore_regs.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f cryptoctl

.PHONY: all clean
