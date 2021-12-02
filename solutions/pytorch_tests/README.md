### 1. test/test_torch.py - Basic tests for PyTorch functionality.
- 3 failed cases

| #  | NAME  | ROOT CAUSE  |
|---|---|---|
| 1  | test_RNG_after_pickle  | lacking **shm** support  |
| 2  | test_from_file  | **tmpfs**  |
| 3  | test_torch_from_file  | **tmpfs**  |

### 2. test_autograd.py - Tests for non-NN automatic differentiation support.

| #  | NAME  | ROOT CAUSE  |
|---|---|---|
| 1  | test_deep_reentrant  | **thread stack size limit**  |
| 2  | test_no_grad_copy_sparse  | **coredump - needs further investigation**  |
| 3  | test_profiler_seq_nr  | **requires nanosecond time precision**  |
| 4  | test_record_function  | **unknown asmjit issues**  |
| 5  | test_thread_shutdown  |  **can only run as single test**  |

### 3. test_nn.py - Tests for NN operators and their automatic differentiation.

| #  | NAME  | ROOT CAUSE  |
|---|---|---|
| 1-24  | test_EmbeddingBag_empty_per_sample_weights_and_offsets_cpu_int32_int32_float32</br>test_EmbeddingBag_empty_per_sample_weights_and_offsets_cpu_int32_int64_float32</br>test_EmbeddingBag_empty_per_sample_weights_and_offsets_cpu_int64_int32_float32</br>test_EmbeddingBag_empty_per_sample_weights_and_offsets_cpu_int64_int64_float32</br>test_EmbeddingBag_per_sample_weights_and_new_offsets_cpu_int32_int32_float32</br>test_EmbeddingBag_per_sample_weights_and_new_offsets_cpu_int32_int64_float32</br>test_EmbeddingBag_per_sample_weights_and_new_offsets_cpu_int64_int32_float32</br>test_EmbeddingBag_per_sample_weights_and_new_offsets_cpu_int64_int64_float32</br>test_EmbeddingBag_per_sample_weights_and_no_offsets_cpu_int64_float32</br>test_EmbeddingBag_per_sample_weights_and_no_offsets_cpu_int32_float32</br>test_EmbeddingBag_per_sample_weights_and_offsets_cpu_int32_int32_float32</br>test_EmbeddingBag_per_sample_weights_and_offsets_cpu_int32_int32_float32</br>test_EmbeddingBag_per_sample_weights_and_offsets_cpu_int32_int64_float32</br>test_EmbeddingBag_per_sample_weights_and_offsets_cpu_int64_int32_float32</br>test_EmbeddingBag_per_sample_weights_and_offsets_cpu_int64_int32_float32</br>test_EmbeddingBag_per_sample_weights_and_offsets_cpu_int64_int64_float32</br>test_embedding_bag_device_cpu_int32_int32_float32</br>test_embedding_bag_device_cpu_int32_int64_float32</br>test_embedding_bag_device_cpu_int64_int32_float32</br>test_embedding_bag_device_cpu_int64_int64_float32</br>test_embedding_bag_non_contiguous_weight_cpu_int32_int32_float32</br>test_embedding_bag_non_contiguous_weight_cpu_int32_int64_float32</br>test_embedding_bag_non_contiguous_weight_cpu_int64_int32_float32</br>test_embedding_bag_non_contiguous_weight_cpu_int64_int64_float32</br>  | **float precision error - needs further investigation**  |
| 25-28  | test_EmbeddingBag_discontiguous</br>test_EmbeddingBag_mean</br>test_EmbeddingBag_sparse</br>test_EmbeddingBag_sum</br>  | **Segmentation fault - needs further investigation**  |
| 29  | test_share_memory  | lacking **shm** support  |