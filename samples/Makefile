DIRS = docker_aks helloworld java_hello_world rust tensorflow_lite TEE_aware/dotnet TEE_aware/gencreds confidential_ml

.PHONY: run clean

run clean:
	for dir in $(DIRS); do \
    	$(MAKE) -C $$dir -f Makefile $@ || exit 1;\
  	done
