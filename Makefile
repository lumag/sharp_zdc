obj-m := sharpzdc_cs.o
EXTRA_CFLAGS=-g3

modules clean:
	$(MAKE) -C /lib/modules/`uname -r`/build M=$(PWD) $@
