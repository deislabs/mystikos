DIRS = helloworld docker_aks java_hello_world rust tensorflow_lite TEE_aware/dotNET TEE_aware/gencreds pytorch_onnx_inference

.PHONY: run clean

run clean:
	for dir in $(DIRS); do \
    	$(MAKE) -C $$dir -f Makefile $@; \
  	done
