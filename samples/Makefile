DIRS = helloworld docker_aks java_hello_world rust pytorch_onnx_inference tensorflow_lite 

.PHONY: run clean

run clean:
	for dir in $(DIRS); do \
    	$(MAKE) -C $$dir -f Makefile $@; \
  	done
