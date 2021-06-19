TARGET_KDIR := /home/book/source_code/imx6ull_sdk_100ask/Linux-4.9.88
#HOST_KDIR := /lib/modules/5.4.0-74-generic/build
HOST_KDIR := /usr/src/linux-headers-5.4.0-74-generic/

TARGET_DIR := target
HOST_DIR := host

O_FILES := *.ko *.o *.mod* *.symvers *.order

ifneq ($(KERNELRELEASE),)                                                                                                                                                             

ccflags-y += -O -g
 
obj-m := eth_drv.o
 
else

unexport CROSS_COMPILE
unexport ARCH
all:
	echo $$CROSS_COMPILE
	echo $$ARCH
	@if [ ! -d $(TARGET_DIR) ]; then mkdir target; fi
	@if [ ! -d $(HOST_DIR) ]; then mkdir host; fi
	make -C $(TARGET_KDIR) M=$(PWD) ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- modules
	./move_file.sh $(TARGET_DIR) $(O_FILES)
	arm-linux-gnueabihf-gcc ./socket_daemon.c -g -pthread -o socket_daemon_target -std=c99
	mv socket_daemon_target $(TARGET_DIR)

	make -C $(HOST_KDIR) M=$(PWD) modules
	./move_file.sh  $(HOST_DIR) $(O_FILES) 
	gcc ./socket_daemon.c -g -pthread -o socket_daemon_host -std=c99
	mv socket_daemon_host $(HOST_DIR)
	
clean:
ifneq ($(wildcard $(TARGET_DIR)), )
	rm -rf $(TARGET_DIR)
endif

ifneq ($(wildcard $(HOST_DIR)), )
	rm -rf $(HOST_DIR)
endif
 
endif
