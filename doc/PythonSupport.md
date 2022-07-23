# Mystikos Support and Limitations for Python
**NOTE**: this is a living document that is continually updated.

## 1. Standard library
As stated in our [Getting started with Python](user-getting-started-docker-python.md)
document, we recommend building containerized python applications using python
3.8.11 or 3.9.7. If your docker image is built from a base image, we recommend
using a specific image tag like 3.8.11, instead of 3.8. This is because tags
like 3.8 may be updated to a newer version, for example 3.8.12, which hasn't
been fully tested by us against Mystikos yet. We will do our best to support
latest Python versions.

### 1.1. Install python as PIE
If you run, "`apt install python3.8`" e.g., when building a Ubuntu-based docker
image, the installed python executable is non-PIE (position independent
executable). Whereas "`myst exec <cmd>`" requires the cmd to be a PIE. We are
aware of three methods to overcome this:
- (Option 1) Install python using miniconda (reference our
[python_webserver](../solutions/python_webserver/Dockerfile) example)
- (Option 2) Use a Debian base image instead. For example,
```Dockerfile
FROM python:3.9.7-slim
```
- (Option 3) Build CPython from source. Follow instructions
https://github.com/python/cpython#build-instructions

### 1.2. Known limitations
To get a rough idea of whether your Python application can be run in Mystikos,
you can reference our known CPython test failures in Mystikos, with
[v3.8.11](../tests/cpython-tests/test_config_v3.8.11/tests.failed) and
[v3.9.7](../tests/cpython-tests/test_config_v3.9.7/tests.failed) respectively.
Here are several noteworthy modules we haven't supported yet:
- `os`
  - `os.fork` - fork is not supported in Mystikos
  - `os.spawn*` - please note that `os.posix_spawn` IS supported
  - `os.exec*` - not supported
  - `os.openpty` - some cpython tests have not passed (yet)
  - `os.memfd_create`
- `multiprocessing.shared_memory` - shared memory is not supported in Mystikos (yet)
- `subprocess` - some parameters of `subprocess.run`/`subprocess.Popen` are not supported
  - `preexec_fn`
  - `shell=True` - as Ubuntu/Debian's default shell `dash` is not supported in Mystikos, setting parameter `shell=True` may require changing the default shell, such as by adding `RUN ln -sf /bin/bash /bin/sh` in the Dockerfile
  - Python3.8 does not use vfork, the option `"ForkMode": "pseudo_wait_for_exit_exec"` is required in config.json to support most `subprocess` APIs.
 - `threading.Lock` - unsupported (yet)
- `curses` - not supported
- `tkinter` - not supported
- `locale` - musl libc [has very limited locale support](https://wiki.musl-libc.org/open-issues.html). Python programs running in Mystikos would suffer the same limitations, since Mystikos bases its C-runtime on musl.
  * The exact missing functionality related to locate in Python is not deteremined, however you can refer to failed Python unit tests for a rough understanding.
  * For example, musl doesn't support `LC_COLLATE`, failing the following Python unit tests:
    * [`test_strcoll_with_diacritic, test_strxfrm_with_diacritic`](https://github.com/python/cpython/blob/f4c03484da59049eb62a9bf7777b963e2267d187/Lib/test/test_locale.py#L374-L382)
  * Other failed unit tests related to locale:
    * [`test_locale_caching`](https://github.com/python/cpython/blob/f4c03484da59049eb62a9bf7777b963e2267d187/Lib/test/test_re.py#L1895), [`test_locale_compiled`](https://github.com/python/cpython/blob/f4c03484da59049eb62a9bf7777b963e2267d187/Lib/test/test_re.py#L1931)
    * [`test_PYTHONCOERCECLOCALE_not_set, test_PYTHONCOERCECLOCALE_not_zero, test_PYTHONCOERCECLOCALE_set_to_warn, test_PYTHONCOERCECLOCALE_set_to_zero`](https://github.com/python/cpython/blob/f4c03484da59049eb62a9bf7777b963e2267d187/Lib/test/test_c_locale_coercion.py#L361-L389)
- `resource`
  - `getrusage`: only supports option `RUSAGE_SELF`

**Caveat**: Any third-party Python library that calls into the unsupported
standard Python APIs are not supported neither. Sometimes they can produce
unpredictable errors which are tricky to root cause.

## 2. Third-party Python libraries
A rule of thumb is to choose the latest versions of third-party libraries. As
we usually test Mystikos against the latest versions.

### 2.1. NumPy
| Supported | Known Limitations & Caveats | Sample/Tests |
| :---: | :--- | :--- |
| Yes | Not supporting tests based on mmap, rng. | [solutions/numpy_core_tests](https://github.com/deislabs/mystikos/tree/main/solutions/numpy_core_tests) |

### 2.2. Pandas
| Supported | Known Limitations & Caveats | Sample |
| :---: | :--- | :--- |
| Partial | Some tests in files listed in tests.partially_passed fail/ error out on execution.<br>These failures and error are caused by one of below:<br>1. pypaper linux specific errors, documented<br>here - https://pyperclip.readthedocs.io/en/latest/#not-implemented-error<br>2. s3fs error (which is currently an optional file handling mechanism in pandas)<br>https://bleepcoder.com/evalml/557744402/unit-test-fails-after-upgrading-to-pandas-1-0-0 | [solutions/pandas_tests](https://github.com/deislabs/mystikos/tree/main/solutions/pandas_tests) |


### 2.3. TensorFlow Lite
| Supported | Known Limitations & Caveats | Sample |
| :---: | :--- | :--- |
| Limited | numpy installed with python3-tflite-runtime is broken.<br>Remove it to use pip-intalled version | [solutions/tensorflow_lite](https://github.com/deislabs/mystikos/tree/main/solutions/tensorflow_lite) |

### 2.4. PyTorch
| Supported | Known Limitations & Caveats | Sample/Tests |
| :---: | :--- | :--- |
| Limited | We have tested the core functions.<br>More thorough testing is in progress. | [solutions/pytorch_tests](https://github.com/deislabs/mystikos/tree/main/solutions/pytorch_tests) |


### 2.5. Flask
| Supported | Known Limitations & Caveats | Sample/Tests |
| :---: | :--- | :--- |
| Yes | In nginx.conf, set master_process off to avoid using syscall SYS_rt_sigsuspend() which is not hanlded by Mystikos yet<br>`master_process off;`<br>The following pytest would fail for now because of issue #503.<br>`test_instance_config.py::test_egg_installed_paths` | [solutions/python_flask_tests](https://github.com/deislabs/mystikos/tree/main/solutions/python_flask_tests) |

### 2.6. Azure SDK for Python
| Supported | Packages | Sample/Tests |
| :---: | :--- | :--- |
| Yes | The following packages have been verified:<br> - azure-keyvault-administration<br> - azure-keyvault-certificates<br> - azure-keyvault-keys<br> - azure-keyvault-secrets<br> - azure-mgmt-keyvault<br> - azure-identity<br> - azure-storage-file-datalake<br> - azure-storage-file-share<br> - azure-storage-queue<br> - azure-mgmt-storage<br> - azure-mgmt-storagesync<br> - azure-storage-blob | [solutions/python_azure_sdk](https://github.com/deislabs/mystikos/tree/main/solutions/python_azure_sdk) |

### 2.7. Other popular Python packages
We haven't verified the full test suites of the following packages. Their support status are based on our experience of running applications that call these packages.
| Packages | Supported |
| :--- | :--- |
| **logzero** | Yes |
| **pycrypto** | Yes |
| **pyjwt** | Yes |
| **nose** | Yes |
| **redis** | Yes |
| **pyodbc** | Yes |
| **sqlalchemy** | only works with SQL AE |
| **pycurl** | Yes |
| **authlib** | Yes |
| **gunicorn** | No, it requires full fork() support.<br>It does not work with fork/exec. |
| **fabric** | No (Reason to be found) |
