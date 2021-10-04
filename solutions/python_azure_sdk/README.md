# About
Python SDK tests use pre-built docker images. To rebuild images, run

1. keyvault, identity
```bash
docker build --build-arg TAG=azure-mgmt-keyvault_9.1.0 --build-arg PACKAGES=keyvault_identity/packages.txt .
```
2. storage
```bash
docker build --build-arg TAG=azure-mgmt-storage_19.0.0 --build-arg PACKAGES=storage/packages.txt .
```
3. storage-blob
```bash
docker build --build-arg TAG=azure-storage-blob_12.8.1 --build-arg PACKAGES=storage-blob/packages.txt .
```

**Substitute tags with newer versions*