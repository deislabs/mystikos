// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#include <myst/thread.h>

void test_myst_thread_queue_push_and_pop_bitset(void)
{
    int n = 5;
    myst_thread_t thread[n];
    myst_thread_queue_t tq = {NULL, NULL};

    for (int i = 0; i < n; i++)
    {
        myst_thread_queue_push_back_bitset(&tq, &(thread[i]), i + 1);
    }

    uint32_t bitset;

    for (int i = 0; i < n; i++)
    {
        myst_thread_t* cur_t = myst_thread_queue_pop_front_bitset(&tq, &bitset);
        assert(cur_t == &(thread[i]));
        assert(bitset == i + 1);
    }

    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_myst_thread_queue_push_and_pop(void)
{
    int n = 5;
    myst_thread_t thread[n];
    myst_thread_queue_t tq = {NULL, NULL};

    for (int i = 0; i < n; i++)
    {
        myst_thread_queue_push_back(&tq, &(thread[i]));
    }

    for (int i = 0; i < n; i++)
    {
        myst_thread_t* cur_t = myst_thread_queue_pop_front(&tq);
        assert(cur_t == &(thread[i]));
    }

    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_myst_thread_queue_empty(void)
{
    myst_thread_t thread1;
    myst_thread_t thread2;
    myst_thread_t thread3;
    myst_thread_queue_t tq = {NULL, NULL};

    assert(myst_thread_queue_empty(&tq));
    myst_thread_queue_push_back(&tq, &thread1);
    assert(!myst_thread_queue_empty(&tq));
    myst_thread_queue_push_back(&tq, &thread2);
    assert(!myst_thread_queue_empty(&tq));
    myst_thread_queue_push_back(&tq, &thread3);
    assert(!myst_thread_queue_empty(&tq));
    myst_thread_queue_pop_front(&tq);
    assert(!myst_thread_queue_empty(&tq));
    myst_thread_queue_pop_front(&tq);
    assert(!myst_thread_queue_empty(&tq));
    myst_thread_queue_pop_front(&tq);
    assert(myst_thread_queue_empty(&tq));

    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_myst_thread_queue_size(void)
{
    myst_thread_t thread1;
    myst_thread_t thread2;
    myst_thread_t thread3;
    myst_thread_queue_t tq = {NULL, NULL};

    assert(myst_thread_queue_size(&tq) == 0);
    myst_thread_queue_push_back(&tq, &thread1);
    assert(myst_thread_queue_size(&tq) == 1);
    myst_thread_queue_push_back(&tq, &thread2);
    assert(myst_thread_queue_size(&tq) == 2);
    myst_thread_queue_push_back(&tq, &thread3);
    assert(myst_thread_queue_size(&tq) == 3);
    myst_thread_queue_pop_front(&tq);
    assert(myst_thread_queue_size(&tq) == 2);
    myst_thread_queue_pop_front(&tq);
    assert(myst_thread_queue_size(&tq) == 1);
    myst_thread_queue_pop_front(&tq);
    assert(myst_thread_queue_size(&tq) == 0);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_myst_thread_queue_search_remove_bitset_remove_all(void)
{
    int n = 5;
    myst_thread_t thread[n];
    myst_thread_queue_t tq = {NULL, NULL};

    for (int i = 0; i < n; i++)
    {
        myst_thread_queue_push_back_bitset(&tq, &(thread[i]), 1);
    }

    myst_thread_queue_t waiters = {NULL, NULL};
    long int ret = myst_thread_queue_search_remove_bitset(&tq, &waiters, n, 1);
    assert(ret == n);
    assert(myst_thread_queue_empty(&tq));

    uint32_t bitset = 0;
    ;
    for (int i = 0; i < n; i++)
    {
        myst_thread_t* cur_t =
            myst_thread_queue_pop_front_bitset(&waiters, &bitset);
        assert(cur_t == &(thread[i]));
        assert(bitset == 1);
        bitset = 0;
    }
    assert(myst_thread_queue_empty(&waiters));

    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_myst_thread_queue_search_remove_bitset_remove_some(void)
{
    int n = 5;
    int n_remove = 3; // less than n
    myst_thread_t thread[n];
    myst_thread_queue_t tq = {NULL, NULL};

    for (int i = 0; i < n; i++)
    {
        myst_thread_queue_push_back_bitset(&tq, &(thread[i]), 1);
    }

    myst_thread_queue_t waiters = {NULL, NULL};
    long int ret =
        myst_thread_queue_search_remove_bitset(&tq, &waiters, n_remove, 1);
    assert(ret == n_remove);
    assert(myst_thread_queue_size(&tq) == n - n_remove);
    assert(myst_thread_queue_size(&waiters) == n_remove);

    uint32_t bitset = 0;
    for (int i = 0; i < n_remove; i++)
    {
        assert(myst_thread_queue_pop_front_bitset(&waiters, &bitset));
        assert(bitset == 1);
        bitset = 0;
    }
    assert(myst_thread_queue_empty(&waiters));

    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_myst_thread_queue_search_remove_bitset_remove_none(void)
{
    int n = 5;
    myst_thread_t thread[n];
    myst_thread_queue_t tq = {NULL, NULL};

    for (int i = 0; i < n; i++)
    {
        myst_thread_queue_push_back_bitset(&tq, &(thread[i]), 1);
    }

    myst_thread_queue_t waiters = {NULL, NULL};
    long int ret = myst_thread_queue_search_remove_bitset(&tq, &waiters, n, 2);
    assert(ret == 0);
    assert(myst_thread_queue_empty(&waiters));
    assert(myst_thread_queue_size(&tq) == n);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_myst_thread_queue_search_remove_bitset_some_match(void)
{
    int n = 6;
    myst_thread_t thread[n];
    myst_thread_queue_t tq = {NULL, NULL};

    int num_odd = 0;

    for (int i = 0; i < n; i++)
    {
        uint32_t bitset = (i % 2) + 1; // 2 if odd, 1 if even
        num_odd += i % 2;
        myst_thread_queue_push_back_bitset(&tq, &(thread[i]), bitset);
    }

    myst_thread_queue_t waiters = {NULL, NULL};
    long int ret = myst_thread_queue_search_remove_bitset(&tq, &waiters, n, 2);
    assert(ret == num_odd);
    assert(myst_thread_queue_size(&tq) == n - num_odd);
    assert(myst_thread_queue_size(&waiters) == num_odd);

    uint32_t bitset = 0;
    for (int i = 0; i < num_odd; i++)
    {
        assert(myst_thread_queue_pop_front_bitset(&waiters, &bitset));
        assert(bitset == 2);
        bitset = 0;
    }
    assert(myst_thread_queue_empty(&waiters));

    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_myst_thread_remove_single(void)
{
    myst_thread_queue_t tq = {NULL, NULL};
    myst_thread_t thread;
    myst_thread_queue_push_back(&tq, &thread);
    assert(myst_thread_queue_remove_thread(&tq, &thread) == 0);
    assert(myst_thread_queue_empty(&tq));
    assert(myst_thread_queue_remove_thread(&tq, &thread) == -1);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_myst_thread_remove_front(void)
{
    myst_thread_queue_t tq = {NULL, NULL};
    myst_thread_t thread1;
    myst_thread_t thread2;
    myst_thread_queue_push_back(&tq, &thread1);
    myst_thread_queue_push_back(&tq, &thread2);
    assert(myst_thread_queue_remove_thread(&tq, &thread1) == 0);
    assert(!myst_thread_queue_empty(&tq));
    assert(myst_thread_queue_remove_thread(&tq, &thread2) == 0);
    assert(myst_thread_queue_empty(&tq));
    assert(myst_thread_queue_remove_thread(&tq, &thread1) == -1);
    assert(myst_thread_queue_remove_thread(&tq, &thread2) == -1);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_myst_thread_remove_back(void)
{
    myst_thread_queue_t tq = {NULL, NULL};
    myst_thread_t thread1;
    myst_thread_t thread2;
    myst_thread_queue_push_back(&tq, &thread1);
    myst_thread_queue_push_back(&tq, &thread2);
    assert(myst_thread_queue_remove_thread(&tq, &thread2) == 1);
    assert(!myst_thread_queue_empty(&tq));
    assert(myst_thread_queue_remove_thread(&tq, &thread1) == 0);
    assert(myst_thread_queue_empty(&tq));
    assert(myst_thread_queue_remove_thread(&tq, &thread1) == -1);
    assert(myst_thread_queue_remove_thread(&tq, &thread2) == -1);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    test_myst_thread_queue_push_and_pop_bitset();
    test_myst_thread_queue_push_and_pop();
    test_myst_thread_queue_size();
    test_myst_thread_queue_empty();
    test_myst_thread_queue_search_remove_bitset_remove_all();
    test_myst_thread_queue_search_remove_bitset_remove_none();
    test_myst_thread_queue_search_remove_bitset_remove_some();
    test_myst_thread_queue_search_remove_bitset_some_match();
    test_myst_thread_remove_single();
    test_myst_thread_remove_front();
    test_myst_thread_remove_back();
    return 0;
}
