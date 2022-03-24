# The Docker and AKS Sample

This sample enables you to run a natively built helloworld C binary in the mystikos runtime for Trusted Execution Environments(TEEs) 
from docker locally or in Azure Kubernetes Service.

The helloworld sample [here](hello.c) is built using gcc, and wrapped up into a CPIO rootfs(root filesystem) for execution in mystikos. 
Then, the rootfs, config.json and private key are packaged together by the mystikos package command for execution in the enclave. 

Read more about basic concepts [here](https://github.com/deislabs/mystikos/blob/main/doc/user-getting-started.md#getting-started---general-concepts) \
Read more about package mode [here](https://github.com/deislabs/mystikos/blob/7fb5cfb9f0f30f83af9561a99495f58a82c06059/doc/sign-package.md#packaging-your-application-for-sgx-enclave-packaging)

The corresponding docker image was published in Docker Hub. Details for the Dockerfile are available [here](Dockerfile).

You can use the myst-helloworld yaml [here](myst-helloworld.yaml) for your Azure Kubernetes Service job, it will deploy one job (myst-helloworld).

## To run this sample step by step: 

1. Compile the helloworld C program and create the appdir, then build the docker container which packages the binary
```bash
make appdir
```

2. 
    a. To run test in a local instance of docker: 

        ```bash
        make run
        ```

    b. To run on AKS:

        ```bash
        docker tag mystikos-hello:latest <docker-registry>/<container-name>:<version>
        docker push <docker-registry>/<container-name>:<version>
        ```

        Then put this container name in myst-hellworld.yaml [here](myst-helloworld.yaml)
        Deploy the job on AKS: 
        
        ```bash
        kubectl apply -f myst-helloworld.yaml
        kubectl get pods
        kubectl logs <podname>
        ```

### Note: 

This part of the job yaml is most important for ensuring that it has access to EPC memory and that sgx capabilities can be used 
```yaml
        volumeMounts:
        - name: var-run-aesmd
          mountPath: /var/run/aesmd
        resources:
          limits:
            kubernetes.azure.com/sgx_epc_mem_in_MiB: 10
          requests:
            kubernetes.azure.com/sgx_epc_mem_in_MiB: 10
      volumes:
      - name: var-run-aesmd
        hostPath:
          path: /var/run/aesmd
```
