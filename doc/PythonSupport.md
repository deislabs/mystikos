# Mystikos Support for Python

## Known Limitations (Not Supported in Mystikos)
To get a rough idea of whether your Python application can be run in Mystikos, you can take a look at our recorded CPython test failures on [v3.8.11](../tests/cpython-tests/test_config_v3.8.11/tests.failed) and [v3.9.7](../tests/cpython-tests/test_config_v3.9.7/tests.failed). Here are several noteworthy modules we either won't support or haven't implemented yet:
- `os`
  - `os.fork` - fork is not supported in Mystikos
  - `os.spawn*` - please note that `os.posix_spawn IS supported
  - `os.exec*`
  - `os.system`?
  - `os.openpty` - `/dev/pty` is not supported in Mytikos (yet)
  - `os.memfd_create`
- `multiprocessing`
  - `multiprocessing.shared_memory` - shared memory is not supported in Mytikos (yet)
- `subprocess` - some parameters of `subprocess.run`/`subprocess.Popen` are not supported
  - `preexec_fn`
  - `shell=True` - as Ubuntu/Debian's default shell `dash` is not supported in Mystikos, setting parameter `shell=True` may require changing the default shell, such as by adding `RUN ln -sf /bin/bash /bin/sh` in the Dockerfile
  - Python3.8 does not use vfork, the option `"ForkMode": "pseudo_wait_for_exit_exec"` is required in config.json to support most `subprocess` APIs.
 - `threading.Lock`
- `curses`
- `tkinter`

### Python version
Python 3.8, 3.9 are recommended.

### Base OS version
Note that the combination of Ubuntu 18.04 (bionic) + python3 is not supported by Mystikos. Since bionic python3 executable is no-PIE while Mystikos requires PIE.
Please use Debian based `python:3.9-slim` as OS base image in your Dockerfile.
```Dockerfile
FROM python:3.9-slim
```

### Third-party Library Versions
When validating Mystikos against third-party libraries, our tests ran with the latest stable version of these libraries.

## Standard Library
| Package | Supported | Known Limitations & Caveats | Sample/Tests |
| :---: | :---: | :--- | :--- |
| subprocess | Yes | TBD | [tests/cpython-tests](https://github.com/deislabs/mystikos/tree/main/tests/cpython-tests) |

## CPython
| Supported | Known Limitations & Caveats | Sample/Tests |
| :---: | :--- | :--- |
| Paritial | We are in-progress of testing it full functionalities. | [tests/cpython-tests](https://github.com/deislabs/mystikos/tree/main/tests/cpython-tests) |


## NumPy
| Supported | Known Limitations & Caveats | Sample/Tests |
| :---: | :--- | :--- |
| Yes | Not supporting tests based on mmap, rng. | [solutions/numpy_core_tests](https://github.com/deislabs/mystikos/tree/main/solutions/numpy_core_tests) |

## Pandas
| Supported | Known Limitations & Caveats | Sample |
| :---: | :--- | :--- |
| Partial | Some tests in files listed in tests.partially_passed fail/ error out on execution.<br>These failures and error are caused by one of below:<br>1. pypaper linux specific errors, documented<br>here - https://pyperclip.readthedocs.io/en/latest/#not-implemented-error<br>2. s3fs error (which is currently an optional file handling mechanism in pandas)<br>https://bleepcoder.com/evalml/557744402/unit-test-fails-after-upgrading-to-pandas-1-0-0 | [solutions/pandas_tests](https://github.com/deislabs/mystikos/tree/main/solutions/pandas_tests) |


## TensorFlow Lite
| Supported | Known Limitations & Caveats | Sample |
| :---: | :--- | :--- |
| Limited | numpy installed with python3-tflite-runtime is broken.<br>Remove it to use pip-intalled version | [solutions/tensorflow_lite](https://github.com/deislabs/mystikos/tree/main/solutions/tensorflow_lite) |

## PyTorch
| Supported | Known Limitations & Caveats | Sample/Tests |
| :---: | :--- | :--- |
| Limited | We have only tested limited samples.<br>More thorough testing is in progress. | [solutions/pytorch_inference](https://github.com/deislabs/mystikos/tree/main/solutions/pytorch_inference) |


## Flask
| Supported | Known Limitations & Caveats | Sample/Tests |
| :---: | :--- | :--- |
| Yes | In nginx.conf, set master_process off to avoid using syscall SYS_rt_sigsuspend() which is not hanlded by Mystikos yet<br>`master_process off;`<br>The following pytest would fail for now because of issue #503.<br>`test_instance_config.py::test_egg_installed_paths` | [solutions/python_flask_tests](https://github.com/deislabs/mystikos/tree/main/solutions/python_flask_tests) |

## Azure SDK for Python
| Supported | Packages that | Sample/Tests |
| :---: | :--- | :--- |
| Yes | The following packages have been verified:<br> - azure-keyvault-administration<br> - azure-keyvault-certificates<br> - azure-keyvault-keys<br> - azure-keyvault-secrets<br> - azure-mgmt-keyvault<br> - azure-identity<br> - azure-storage-file-datalake<br> - azure-storage-file-share<br> - azure-storage-queue<br> - azure-mgmt-storage<br> - azure-mgmt-storagesync<br> - azure-storage-blob | [solutions/python_azure_sdk](https://github.com/deislabs/mystikos/tree/main/solutions/python_azure_sdk) |
