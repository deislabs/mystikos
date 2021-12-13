# Mystikos Support and Limitations for Python

## Verified/Supported python versions
As stated in our [Getting started with Python](user-getting-started-docker-python.md) document, we recommend building your containerized python application using python 3.8.11 and 3.9.7. Note that if possible, try pin your python to a specific version like 3.8.11 instead of 3.8.

### Install position independent python executable
If you run `apt install python3.8` when building a Ubuntu-based docker image, the installed python3.8 (or python3.9) executable is not a position independent executable (PIE). `myst exec <cmd>` requires the cmd to be a PIE. To overcome this, either install python using miniconda (reference our [python_webserver](../solutions/python_webserver/Dockerfile) example), or use a Debian base image instead. For example,
```Dockerfile
FROM python:3.9-slim
```

### Third-party library
In generally, choose the latest versions of third-party libraries. As we usually test Mystikos against the latest versions.

## Known Limitations
### Standard library
To get a rough idea of whether your Python application can be run in Mystikos, you can take a look at our recorded CPython test failures on [v3.8.11](../tests/cpython-tests/test_config_v3.8.11/tests.failed) and [v3.9.7](../tests/cpython-tests/test_config_v3.9.7/tests.failed). Here are several noteworthy modules we either won't support or haven't implemented yet:
- `os`
  - `os.fork` - fork is not supported in Mystikos
  - `os.spawn*` - please note that `os.posix_spawn IS supported
  - `os.exec*`
  - `os.system`
  - `os.openpty` - `/dev/pty` is not supported in Mytikos (yet)
  - `os.memfd_create`
- `multiprocessing`
  - `multiprocessing.shared_memory` - shared memory is not supported in Mytikos (yet)
- `subprocess` - some parameters of `subprocess.run`/`subprocess.Popen` are not supported
  - `preexec_fn`
  - `shell=True` - as Ubuntu/Debian's default shell `dash` is not supported in Mystikos, setting parameter `shell=True` may require changing the default shell, such as by adding `RUN ln -sf /bin/bash /bin/sh` in the Dockerfile
  - Python3.8 does not use vfork, the option `"ForkMode": "pseudo_wait_for_exit_exec"` is required in config.json to support most `subprocess` APIs.
 - `threading.Lock` - unsupported (yet)
- `curses` - not supported
- `tkinter` - not supported

### NumPy
| Supported | Known Limitations & Caveats | Sample/Tests |
| :---: | :--- | :--- |
| Yes | Not supporting tests based on mmap, rng. | [solutions/numpy_core_tests](https://github.com/deislabs/mystikos/tree/main/solutions/numpy_core_tests) |

### Pandas
| Supported | Known Limitations & Caveats | Sample |
| :---: | :--- | :--- |
| Partial | Some tests in files listed in tests.partially_passed fail/ error out on execution.<br>These failures and error are caused by one of below:<br>1. pypaper linux specific errors, documented<br>here - https://pyperclip.readthedocs.io/en/latest/#not-implemented-error<br>2. s3fs error (which is currently an optional file handling mechanism in pandas)<br>https://bleepcoder.com/evalml/557744402/unit-test-fails-after-upgrading-to-pandas-1-0-0 | [solutions/pandas_tests](https://github.com/deislabs/mystikos/tree/main/solutions/pandas_tests) |


### TensorFlow Lite
| Supported | Known Limitations & Caveats | Sample |
| :---: | :--- | :--- |
| Limited | numpy installed with python3-tflite-runtime is broken.<br>Remove it to use pip-intalled version | [solutions/tensorflow_lite](https://github.com/deislabs/mystikos/tree/main/solutions/tensorflow_lite) |

### PyTorch
| Supported | Known Limitations & Caveats | Sample/Tests |
| :---: | :--- | :--- |
| Limited | We have only tested limited samples.<br>More thorough testing is in progress. | [solutions/pytorch_inference](https://github.com/deislabs/mystikos/tree/main/solutions/pytorch_inference) |


### Flask
| Supported | Known Limitations & Caveats | Sample/Tests |
| :---: | :--- | :--- |
| Yes | In nginx.conf, set master_process off to avoid using syscall SYS_rt_sigsuspend() which is not hanlded by Mystikos yet<br>`master_process off;`<br>The following pytest would fail for now because of issue #503.<br>`test_instance_config.py::test_egg_installed_paths` | [solutions/python_flask_tests](https://github.com/deislabs/mystikos/tree/main/solutions/python_flask_tests) |

### Azure SDK for Python
| Supported | Packages that | Sample/Tests |
| :---: | :--- | :--- |
| Yes | The following packages have been verified:<br> - azure-keyvault-administration<br> - azure-keyvault-certificates<br> - azure-keyvault-keys<br> - azure-keyvault-secrets<br> - azure-mgmt-keyvault<br> - azure-identity<br> - azure-storage-file-datalake<br> - azure-storage-file-share<br> - azure-storage-queue<br> - azure-mgmt-storage<br> - azure-mgmt-storagesync<br> - azure-storage-blob | [solutions/python_azure_sdk](https://github.com/deislabs/mystikos/tree/main/solutions/python_azure_sdk) |
