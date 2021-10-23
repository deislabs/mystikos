DIRS = cpiorootfs ext2rootfs

.PHONY: run clean

run clean:
	for dir in $(DIRS); do \
    	$(MAKE) -C $$dir -f Makefile $@; \
  	done
