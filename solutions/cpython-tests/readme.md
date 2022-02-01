# cpython-tests

This test would run cpython unit tests from 3 different versions: 3.8.11, 3.9.7 and 3.10.0 .

## Skipped unit tests
Some test files are skipped because they contain unittests that couldn't pass on Mystikos, those files are listed in `test_config/tests.failed`.

For thoes test files that are listed in `test_config/tests.passed`, some of the unit tests are manually disabled by adding `@unittest.skip("Temporarily disabled in Mystikos")`, because either 1) they use unsupported feature of Mystikos (like `fork`), or 2) there are bugs pending investigation (like socket issue in `test_logging:UnixSocketHandlerTest`). To skip those unit tests, a patch file is manually generated and applied to cpython repo. 

## Quick guide on patch file
Unit tests are skipped by manually adding `@unittest.skip("Temporarily disabled in Mystikos")` at function/class level. To make modification to patch file (for example you want to skip more unit tests), you should 1) apply the existing patch file by using `make apply-patch` 2) modify the cpython source code to skip/unskip unittests 3) generate a new patch file by using `make gen-patch` 4) `git commit` the new patch file

Here is a list of all the skipped individual unit tests

### v3.8

* test_cmd_line
    * _test_no_stdio
* test_logging
    * test_post_fork_child_no_deadlock
    * UnixSocketHandlerTest
    * DatagramHandlerTest
    * UnixDatagramHandlerTest
    * UnixSysLogHandlerTest
* test_mailbox
    * test_lock_conflict
* test_pty
    * test_fork
* test_random
    * test_after_fork
* test_ssl
    * test_random_fork
    * test_keylog_defaults
* test_support
    * test_temp_dir__forked_child
    * test_reap_children
* test_tempfile
    * test_process_awareness
    * test_noinherit
* test_thread
    * test_forkinthread
* test_tracemalloc
    * test_fork
    * test_sys_xoptions_invalid
* test_uuid
    * testIssue8621
* test_posix
  * test_setresuid
  * test_setresgid
  * test_fexecve
  * test_waitid
  * test_register_at_fork
  * test_mkfifo
  * test_mknod
  * test_mknod_dir_fd
  * test_mkfifo_dir_fd
  * test_sched_rr_get_interval
  * test_sched_priority

### v3.9

* test_cmd_line
    * _test_no_stdio
* test_logging
    * test_post_fork_child_no_deadlock
    * UnixSocketHandlerTest
    * DatagramHandlerTest
    * UnixSysLogHandlerTest
* test_mailbox
    * test_lock_conflict
* test_pty
    * test_fork
* test_random
    * test_after_fork
* test_support
    * test_ignored_deprecations_are_silent
    * test_temp_dir__forked_child
    * test_reap_children
* test_thread
    * test_forkinthread
* test_tracemalloc
    * test_fork
    * test_env_var_invalid
    * test_sys_xoptions_invalid
* test_uuid
    * testIssue8621
* test_posix
  * test_setresuid
  * test_setresgid
  * test_fexecve
  * test_waitid
  * test_register_at_fork
  * test_mkfifo
  * test_mknod
  * test_mknod_dir_fd
  * test_mkfifo_dir_fd
  * test_sched_rr_get_interval
  * test_sched_priority


### v3.10

* test_cmd_line
    * _test_no_stdio
* test_logging
    * test_post_fork_child_no_deadlock
    * UnixSocketHandlerTest
    * DatagramHandlerTest
    * UnixSysLogHandlerTest
    * test_multiprocessing
* test_mailbox
    * test_lock_conflict
* test_pty
    * test_fork
    * test_spawn_doesnt_hang
    * test_master_read
    * test_openpty
* test_random
    * test_after_fork
* test_support
    * test_ignored_deprecations_are_silent
    * test_temp_dir__forked_child
    * test_reap_children
* test_thread
    * test_forkinthread
* test_tracemalloc
    * test_fork
    * test_env_var_invalid
    * test_sys_xoptions_invalid
* test_uuid
    * testIssue8621
* test_posix
  * test_setresuid: fail in Pipeline but pass on local
  * test_setresgid: fail in Pipeline but pass on local
  * test_fexecve
  * test_waitid
  * test_register_at_fork
  * test_mkfifo
  * test_mknod
  * test_mknod_dir_fd
  * test_mkfifo_dir_fd
  * test_sched_rr_get_interval
  * test_sched_priority
