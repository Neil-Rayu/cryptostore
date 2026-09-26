CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -I../include

all: pcie_hello_ctl cryptoctl

pcie_hello_ctl: pcie_hello_ctl.c ../include/pcie_hello_ioctl.h
	$(CC) $(CFLAGS) -o $@ $<

cryptoctl: cryptoctl.c ../include/cryptostore_ioctl.h ../include/cryptostore_regs.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f pcie_hello_ctl cryptoctl

.PHONY: all clean
