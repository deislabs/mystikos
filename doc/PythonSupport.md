# Mystikos Support for Python

Python3.8, 3.9 are recommended.

Ubuntu 18.04 (bionic) python3 executable is no-pie, which is currently not supported by Mystikos. So instead of `ubuntu:18.04`, please use `python:3.6-slim-buster` as Dockerfile base image.
```Dockerfile
FROM python:3.9-slim
```

By default, Mystikos has been tested against latest version.

## Standard Library
| Package | Supported | Known Limitations & Caveats | Sample |
| :---: | :---: | :--- | :--- |
| subprocess | Yes | TBD | [tests/cpython-tests](https://github.com/deislabs/mystikos/tree/main/tests/cpython-tests) |

## CPython
| Supported | Known Limitations & Caveats | Sample |
| :---: | :--- | :--- |
| Paritial | TBD | [tests/cpython-tests](https://github.com/deislabs/mystikos/tree/main/tests/cpython-tests) |


## NumPy
| Supported | Known Limitations & Caveats | Sample |
| :---: | :--- | :--- |
| Yes | Not supporting tests based on mmap, rng. | [solutions/numpy_core_tests](https://github.com/deislabs/mystikos/tree/main/solutions/numpy_core_tests) |

## Pandas
| Supported | Known Limitations & Caveats | Sample |
| :---: | :--- | :--- |
| Partial | Some tests in files listed in tests.partially_passed fail/ error out on execution.<br>These failures and error are caused by one of below:<br>1. pypaper linux specific errors, documented<br>here - https://pyperclip.readthedocs.io/en/latest/#not-implemented-error<br>2. s3fs error (which is currently an optional file handling mechanism in pandas)<br>https://bleepcoder.com/evalml/557744402/unit-test-fails-after-upgrading-to-pandas-1-0-0 | [solutions/pandas_tests](https://github.com/deislabs/mystikos/tree/main/solutions/pandas_tests) |


## TensorFlow Lite
| Supported | Known Limitations & Caveats | Sample |
| :---: | :--- | :--- |
| Paritial | numpy installed with python3-tflite-runtime is broken. Remove it to use pip-intalled version | [solutions/tensorflow_lite](https://github.com/deislabs/mystikos/tree/main/solutions/tensorflow_lite) |

## PyTorch
| Supported | Known Limitations & Caveats | Sample |
| :---: | :--- | :--- |
| Paritial | TBD | [solutions/pytorch_inference](https://github.com/deislabs/mystikos/tree/main/solutions/pytorch_inference) |


## Flask
| Supported | Known Limitations & Caveats | Sample |
| :---: | :--- | :--- |
| Yes | In nginx.conf, set master_process off to avoid using syscall SYS_rt_sigsuspend() which is not hanlded by Mystikos yet<br>`master_process off;`<br>The following pytest would fail for now because of issue #503.<br>`test_instance_config.py::test_egg_installed_paths` | [solutions/python_flask_tests](https://github.com/deislabs/mystikos/tree/main/solutions/python_flask_tests) |

## Azure SDK for Python
| Supported | Known Limitations & Caveats | Sample |
| :---: | :--- | :--- |
| Yes | - | [solutions/python_azure_sdk](https://github.com/deislabs/mystikos/tree/main/solutions/python_azure_sdk) |