CONFIG_SHARPZDC = m
EXTRA_CFLAGS=-g3

obj-$(CONFIG_SHARPZDC) += sharpzdc_cs.o
sharpzdc_cs-objs = sharpzdc-card.o sharpzdc-v4l.o
fw-shipped-$(CONFIG_SHARPZDC) += cis/CE-AG06.cis

modules clean modules_install:
	$(MAKE) -C /lib/modules/`uname -r`/build M=$(PWD) $@
