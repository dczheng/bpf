obj-m := uprobe.o
KERNELBUILD :=/lib/modules/$(shell uname -r)/build

uprobe:
	make -C $(KERNELBUILD) M=${PWD}

clean:
	make -C $(KERNELBUILD) M=${PWD} clean

help:
	make -C $(KERNELBUILD) M=${PWD} help

test:
	gcc test.c -o test
