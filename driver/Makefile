# Out-of-tree build of the CryptoStore guest drivers.
#   make                 build against the running kernel
#   make KDIR=/path      build against another kernel tree
obj-m := cryptostore.o cryptorecovery.o
ccflags-y := -I$(src)/../include

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: all clean
