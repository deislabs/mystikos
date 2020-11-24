"""helper and util function being used by other modules in test framework

"""

import os, sys
scripts_root = sys.path[0]
sys.path.insert(1, os.path.join(scripts_root, '..'))
import config
import subprocess
import logging


def generate_path(*paths) -> str:
    """join path with given list.
    
    encapsulation for system function.
    """
    return os.path.join(*paths)


def generate_abs_path(*paths) -> str:
    """join and generate absolute path with given list.
    
    encapsulation for system function.
    """
    return os.path.abspath(generate_path(*paths))


def exec_shell_command(command: str) -> (str, str):
    """execute given shell command string in subprocess.
    
    encapsulation for system function. 
    """
    sbp = subprocess.Popen(command,
                           subprocess.PIPE,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           shell=True)
    std_out, std_err = sbp.communicate()
    return std_out, std_err


def exists_dir(path) -> bool:
    """check given path is a valid directory
    
    encapsulation for system function.
    """
    return os.path.isdir(path)


def list_dir(path) -> str:
    """list all files/directories under given directory path
    
    encapsulation for system function.
    """
    return os.listdir(path)


### config default path values based on project codebase location
if not config.PRJ_ROOT:
    config.PRJ_ROOT = os.path.abspath(
        generate_abs_path(scripts_root, "..", ".."))

if not config.UNIT_TEST_SRC_ROOT:
    config.UNIT_TEST_SRC_ROOT = os.path.abspath(
        generate_abs_path(config.PRJ_ROOT, "tests"))

if not config.LIBC_TEST_ROOT:
    config.LIBC_TEST_ROOT = os.path.abspath(
        generate_abs_path(config.PRJ_ROOT, "tests", "libc"))

if not config.LOG_FILE_PATH:
    config.LOG_FILE_PATH = generate_abs_path(config.PRJ_ROOT, "_testing.log")
