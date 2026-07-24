/*
 * Copyright (C) 2011-2022 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _SERVTD_UTILS_H_
#define _SERVTD_UTILS_H_

#include <stddef.h>
#include <stdint.h>

/* used to eliminate `unused variable' warning */
#define UNUSED(val) (void)(val)

#if defined(__cplusplus)
extern "C"
{
#endif

void __attribute__((noreturn)) abort(void);

int* get_errno_addr(void);

/* Heap base accessor required by tlibc's malloc bounds check (ok_heap_range()
 * in tlibc/stdlib/malloc.c). The SDK's own heap_base is private, so this is
 * backed by a DCAP-owned shadow set in init_heap(). Prototype also declared in
 * the SGX SDK's trts/trts_util.h, which malloc.c includes. */
void* get_heap_base(void);

int apply_EPC_pages(void* start_address, size_t page_count);

int trim_EPC_pages(void* start_address, size_t page_count);

void __attribute__((noreturn)) __stack_chk_fail(void);

void* get_enclave_base(void);

int mm_commit(void* addr, size_t size);

int mm_uncommit(void* addr, size_t size);

#if defined(__cplusplus)
}
#endif

#endif