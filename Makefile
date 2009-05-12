obj-m := sharpzdc_cs.o
sharpzdc_cs-objs = sharpzdc-card.o sharpzdc-v4l.o
EXTRA_CFLAGS=-g3

modules clean:
	$(MAKE) -C /lib/modules/`uname -r`/build M=$(PWD) $@
