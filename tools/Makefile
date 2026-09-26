CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -I../include

pcie_hello_ctl: pcie_hello_ctl.c ../include/pcie_hello_ioctl.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f pcie_hello_ctl

.PHONY: clean
