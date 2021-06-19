# uart_eth

This is a virtual ethernet driver that generate a eth%d node. 
Users can use it to connect to another computer which insmod the same module and run a daemon through a uart interface. 

Usage:
1. make
  This step will gererate driver module and daemon program in host(executable on x86) and target(executable on arm)

2.insmod eth_drv.ko and execute ./socket_daemon_xxx /dev/char_eth /dev/ttyUSB* & both in two computers which connected by uart.

3.assign ip address for eth%d by executing ifconfig eth%d 192.168.x.x

4.the module works properly, if the ping command between two computers can execute success.
