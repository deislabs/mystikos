## Machine Learning Inference sample with Mystikos

### Functionality 
This sample downloads AlexNet in `.pt` format and exports it to `.onnx`
format. This is executed outside the enclave (`src/download_pretrained_model.py`).

A server is launched inside the enclave with the packaged model files.
A client sends image files to the server, which processes it through the
inferencing service running inside the enclave and returns the inference results
to the client.

The server will return the inference results for both PyTorch and ONNX Runtime.

### Running the sample

Use `make run` to launch both the server and the local client that will
send images located inside `test_samples` for inferencing.

