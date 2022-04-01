## Overview
PyTorch validation are run against the Python [Unit Tests](https://github.com/pytorch/pytorch/blob/master/CONTRIBUTING.md#unit-testing) in PyTorch github repo. Currently, five test suites are enabled, namely `test_autograd`, `test_modules`, `test_nn`, `test_ops`, and `test_torch`. They were chosen based on the definition of `CORE_TEST_LIST` in PyTorch [test script](https://github.com/pytorch/pytorch/blob/8b20dde93240642b3fce14b304e2d5e6d09d9891/test/run_test.py).

## Summary of Test Results
### 1. test_torch.py - Basic tests for PyTorch functionality.
- **host**: 696 passed, 527 skipped, 98 warnings
- **myst**: 3 failed, 693 passed, 527 skipped, 98 warnings

| #  | NAME  | ROOT CAUSE  |
|---|---|---|
| 1  | test_RNG_after_pickle  | abstract namespace uds support  |
| 2  | test_from_file  | **tmpfs**  |
| 3  | test_torch_from_file  | **tmpfs**  |

### 2. test_autograd.py - Tests for non-NN automatic differentiation support.
- **host**: 1 failed, 404 passed, 68 skipped, 2 deselected, 1 xfailed, 28 warnings
- **myst**: 4 failed, 401 passed, 68 skipped, 2 deselected, 1 xfailed, 28 warnings

| #  | NAME  | ROOT CAUSE  |
|---|---|---|
| 1  | test_deep_reentrant  | **thread stack size limit**  |
| 2  | test_no_grad_copy_sparse  | **coredump - needs further investigation**  |
| 3  | test_profiler_seq_nr  | **requires nanosecond time precision**  |
| 4  | test_record_function  | **unknown asmjit issues**  |
| *5  | test_thread_shutdown  |  **can only run as single test, also failed on host**  |

### 3. test_nn.py - Tests for NN operators and their automatic differentiation.
- **host**: 1361 passed, 1441 skipped, 3 xfailed, 138 warnings
- **myst**: 29 failed, 1324 passed, 1437 skipped, 41 deselected, 3 xfailed, 138 warnings

| #  | NAME  | ROOT CAUSE  |
|---|---|---|
| 1-24  | test_EmbeddingBag_empty_per_sample_weights_and_offsets_cpu_int32_int32_float32</br>test_EmbeddingBag_empty_per_sample_weights_and_offsets_cpu_int32_int64_float32</br>test_EmbeddingBag_empty_per_sample_weights_and_offsets_cpu_int64_int32_float32</br>test_EmbeddingBag_empty_per_sample_weights_and_offsets_cpu_int64_int64_float32</br>test_EmbeddingBag_per_sample_weights_and_new_offsets_cpu_int32_int32_float32</br>test_EmbeddingBag_per_sample_weights_and_new_offsets_cpu_int32_int64_float32</br>test_EmbeddingBag_per_sample_weights_and_new_offsets_cpu_int64_int32_float32</br>test_EmbeddingBag_per_sample_weights_and_new_offsets_cpu_int64_int64_float32</br>test_EmbeddingBag_per_sample_weights_and_no_offsets_cpu_int64_float32</br>test_EmbeddingBag_per_sample_weights_and_no_offsets_cpu_int32_float32</br>test_EmbeddingBag_per_sample_weights_and_offsets_cpu_int32_int32_float32</br>test_EmbeddingBag_per_sample_weights_and_offsets_cpu_int32_int32_float32</br>test_EmbeddingBag_per_sample_weights_and_offsets_cpu_int32_int64_float32</br>test_EmbeddingBag_per_sample_weights_and_offsets_cpu_int64_int32_float32</br>test_EmbeddingBag_per_sample_weights_and_offsets_cpu_int64_int32_float32</br>test_EmbeddingBag_per_sample_weights_and_offsets_cpu_int64_int64_float32</br>test_embedding_bag_device_cpu_int32_int32_float32</br>test_embedding_bag_device_cpu_int32_int64_float32</br>test_embedding_bag_device_cpu_int64_int32_float32</br>test_embedding_bag_device_cpu_int64_int64_float32</br>test_embedding_bag_non_contiguous_weight_cpu_int32_int32_float32</br>test_embedding_bag_non_contiguous_weight_cpu_int32_int64_float32</br>test_embedding_bag_non_contiguous_weight_cpu_int64_int32_float32</br>test_embedding_bag_non_contiguous_weight_cpu_int64_int64_float32</br>  | **float precision error - needs further investigation**  |
| 25-28  | test_EmbeddingBag_discontiguous</br>test_EmbeddingBag_mean</br>test_EmbeddingBag_sparse</br>test_EmbeddingBag_sum</br>  | **Segmentation fault - needs further investigation**  |
