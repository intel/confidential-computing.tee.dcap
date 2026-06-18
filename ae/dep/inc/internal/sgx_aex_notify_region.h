/*
 * Copyright(c) 2011 - 2026 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#ifndef _SGX_AEX_NOTIFY_REGION_
#define _SGX_AEX_NOTIFY_REGION_

#include <stdint.h>
#include <sgx_trts_exception.h>
#include <sgx_trts_aex.h>
#include <atomic>

/*
 * SGX_REPEAT_AEX_REGION(BLOCK)
 *
 * Example:
 *   SGX_REPEAT_AEX_REGION({
 *       do_work();
 *   });
 *
 * Guarantees per attempt:
 *   1) uint64_t _rs_start = (START_REGION);
 *   2) Executes BLOCK exactly once
 *   3) uint64_t _rs_end   = (END_REGION);
 *   4) If (_rs_end - _rs_start) > AEX_THRESHOLD, repeat the attempt
 *
 * Control flow notes:
 *   - 'break'/'continue' used inside BLOCK won't skip the end check; they only
 *     affect the inner do{...}while(0) guard.
 *   - 'return' inside BLOCK will exit the function immediately.
 */
#define AEX_THRESHOLD (0) /* Don't allow any AEX inside the region */
#define SGX_REPEAT_AEX_REGION(BLOCK)                                             \
    do                                                                           \
    {                                                                            \
        for (;;)                                                                 \
        {                                                                        \
            const uint64_t _rs_start = (uint64_t)(g_aex_region_count);           \
            /* Guard BLOCK so break/continue don't escape the retry loop */      \
            do                                                                   \
            {                                                                    \
                BLOCK                                                            \
            } while (0);                                                         \
            const uint64_t _rs_end = (uint64_t)(g_aex_region_count);             \
            if ((_rs_end - _rs_start) > (uint64_t)(AEX_THRESHOLD))               \
            {                                                                    \
                continue; /* Retry the entire region */                          \
            }                                                                    \
            break; /* Within threshold: exit retry loop */                       \
        }                                                                        \
    } while (0)

#ifdef __cplusplus
    // This header file relies on C++-only features, such as std::atomic and C++17 inline variables.

    inline std::atomic<uint64_t> g_aex_region_count{0};
    inline sgx_aex_mitigation_node_t g_aex_node;

    static void sgx_aex_region_handler(const sgx_exception_info_t *info, const void *args)
    {
        (void)info;
        (void)args;
        g_aex_region_count++;
    }

    static sgx_status_t sgx_register_aex_region_handler(void)
    {
        return sgx_register_aex_handler(&g_aex_node, sgx_aex_region_handler, (const void *)NULL);
    }

    static sgx_status_t sgx_unregister_aex_region_handler(void)
    {
        return sgx_unregister_aex_handler(sgx_aex_region_handler);
    }

#else
    #error "This header is C++-only; a C++ compiler is required."
#endif

#endif /* _SGX_AEX_NOTIFY_REGION_ */
