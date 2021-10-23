DIRS = helloworld docker_aks 

.PHONY: run clean

run clean:
	for dir in $(DIRS); do \
    	$(MAKE) -C $$dir -f Makefile $@; \
  	done
