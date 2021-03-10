all:	tools
.PHONY:	tools

tools:
	cd dpdk; $(MAKE)
	cd kernel; $(MAKE)
	
install:
	cd dpdk; $(MAKE) install
	cd kernel; $(MAKE) install	

clean:
	cd dpdk; $(MAKE) clean
	cd kernel; $(MAKE) clean

