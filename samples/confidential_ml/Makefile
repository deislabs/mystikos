APP_NAME      = python3

APP_PATH      = /usr/local/bin/python3
PACKAGE  = myst/bin/$(APP_NAME)

QUERY_INTERVAL = 2
SHUTDOWN_WAIT = 2 

all: $(PACKAGE)

appdir:
	@myst-appbuilder -m -d Dockerfile

$(PACKAGE): appdir package.pem
	@myst mkext2 appdir rootfs
	@myst fssig --roothash rootfs > roothash
	@myst package-sgx --roothash=roothash package.pem config.json

server:
	./$(PACKAGE) --rootfs=rootfs

# IMPORTANT: 
# Before running this option, please set the RESOURCE_GROUP and CLUSTER_NAME options in the confml_aks_demo.sh file
# You may also need to set the required keys in the env vars of the confml_server.yaml file
aks-demo: 
	docker build -t <your-docker-registry>/confml:0.1 -f AKSDockerfile .
	docker push <your-docker-registry>/confml:0.1
	./confml_aks_demo.sh

# running both service and client in one recipe
run: $(PACKAGE)
	./kill.sh $(PACKAGE) $(APP_PATH)
	@echo "\n------Starting Pytorch Inference Service(package mode)------\n"
	$(PACKAGE) --rootfs=rootfs &
	./wait.sh

	./client.sh test_samples/dog.jpg
	@sleep $(QUERY_INTERVAL)
	./client.sh test_samples/automotive.jpg
	@sleep $(QUERY_INTERVAL)
	./client.sh test_samples/strawberries.jpg

	@sleep $(QUERY_INTERVAL)
	./client.sh test_samples/dog.jpg.encrypted
	@sleep $(QUERY_INTERVAL)
	./client.sh test_samples/automotive.jpg.encrypted
	@sleep $(QUERY_INTERVAL)
	./client.sh test_samples/strawberries.jpg.encrypted

	@sleep $(SHUTDOWN_WAIT)
	@echo "\n------Terminating Pytorch Inference Service------\n"
	./kill.sh $(PACKAGE) $(APP_PATH)
	
package.pem:
	./gen_pkey.sh package.pem

clean:
	rm -rf appdir myst package.pem rootfs roothash
