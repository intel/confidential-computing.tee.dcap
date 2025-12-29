/**
 * Copyright (c) 2011-2025, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Intel Corporation nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "opa_builtins.h"
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include "qal_common.h"
#ifndef BUILD_QAE
#include <cpuid.h>
#include "se_trace.h"
#else
#include "sgx_error.h"
#include "qae_t.h"
#include "sgx_trts.h"
#endif

__thread time_t g_current_time = 0;
uint64_t get_now_ns()
{
    return (uint64_t)g_current_time * 1000000000;
}

uint64_t get_ns_since_epoch(std::string str)
{
    // Assume str format is "\"2020-07-01T00:00:00:Z\""
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    if (strptime(str.c_str(), "\"%Y-%m-%dT%H:%M:%SZ\"", &tm) == NULL)
    {
        se_trace(SE_TRACE_ERROR, "\033[0;31mERROR:\033[0m The format of \"%s\" is not correct. It should be UCT with format \"YYYY-MM-DDThh:mm:ssZ\"\n", str.c_str());
        return UINT64_MAX;
    }
    time_t t = mktime(&tm);
    struct tm epoch_tm;
    memset(&epoch_tm, 0, sizeof(epoch_tm));
    epoch_tm.tm_mday = 1;
    epoch_tm.tm_mon = 0;
    epoch_tm.tm_year = 70;
    epoch_tm.tm_isdst = -1;
    time_t basetime = mktime(&epoch_tm);

    double nsecs = difftime(t, basetime);

    return (uint64_t)(nsecs * 1000000000);
}

#ifndef BUILD_QAE
#define RDRAND_MASK 0x40000000
static int rdrand_cpuid()
{
    /* Are we on an Intel processor? */
    unsigned int eax, ebx, ecx, edx;
    __get_cpuid(0, &eax, &ebx, &ecx, &edx);

    if (memcmp(&ebx, "Genu", 4) != 0 ||
        memcmp(&edx, "ineI", 4) != 0 ||
        memcmp(&ecx, "ntel", 4) != 0)
    {
        return 0;
    }

    /* Do we have RDRAND? */
    __get_cpuid(1, &eax, &ebx, &ecx, &edx);
    if ((ecx & RDRAND_MASK) == RDRAND_MASK)
        return 1;
    else
        return 0;
}

static int g_rdrand_supported = -1;
uint64_t get_rand_n(std::string str, uint64_t n)
{
    (void)(str);
    if (g_rdrand_supported == -1)
    {
        g_rdrand_supported = rdrand_cpuid();
    }
    if (g_rdrand_supported == 1)
    {
        uint64_t val = 0;
        __asm__ volatile(
            "1: rdrand %0\n"
            "   jnc 1b\n"
            : "=r"(val));
        return (val % n);
    }
    else
    {
        se_trace(SE_TRACE_ERROR, "\033[0;31mERROR:\033[0m RDRAND instruction is required to be supported...\n");
        abort();
    }
}

#else

uint64_t get_rand_n(std::string str, uint64_t n)
{
    (void)(str);
    uint64_t num = 0;
    if (sgx_read_rand((uint8_t *)&num, sizeof(num)) != SGX_SUCCESS)
    {
        // RDRAND returns failure, we have no idea to return the error code
        abort();
    }
    return num % n;
}

#endif // #ifndef BUILD_QAE