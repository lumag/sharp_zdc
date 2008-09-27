obj-m := sharpzdc_cs.o

modules clean:
	$(MAKE) -C /lib/modules/`uname -r`/build M=$(PWD) $@
