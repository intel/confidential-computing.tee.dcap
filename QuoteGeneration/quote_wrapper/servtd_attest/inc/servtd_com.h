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

#ifndef _SERVTD_COMMON_H_
#define _SERVTD_COMMON_H_

#include <stdint.h>
#include <time.h>
#include "sgx_quote_5.h"
#include "sgx_attributes.h"
#include "sgx_qve_def.h"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr)          {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

#pragma pack(push, 1)

/* TD Quote status codes */
#define GET_QUOTE_SUCCESS 0
#define GET_QUOTE_IN_FLIGHT 0xffffffffffffffff
#define GET_QUOTE_ERROR 0x8000000000000000
#define GET_QUOTE_SERVICE_UNAVAILABLE 0x8000000000000001
#define MISCSELECTMASK_LEN 4
#define ATTRIBUTESELECTMASK_LEN 16
#define TCB_STATUS_LEN  32

struct servtd_tdx_quote_hdr {
    /* Quote version, filled by TD */
    uint64_t version;
    /* Status code of Quote request, filled by VMM */
    uint64_t status;
    /* Length of TDREPORT, filled by TD */
    uint32_t in_len;
    /* Length of Quote, filled by VMM */
    uint32_t out_len;
    /* Actual Quote data or TDREPORT on input */
    uint64_t data[0];
};

struct servtd_tdx_quote_suppl_data {
        sgx_report2_body_t         quote_body;           /*     0   584 */
        uint8_t                    fmspc[FMSPC_SIZE];             /*   584     6 */
        uint8_t                    tdx_tcb_components[TEE_TCB_SVN_SIZE]; /*   590    16 */
        uint16_t                   pce_svn;              /*   606     2 */
        uint8_t                    sgx_tcb_components[TEE_TCB_SVN_SIZE]; /*   608    16 */
        uint8_t                    tdx_module_major_ver; /*   624     1 */
        uint8_t                    tdx_module_svn;       /*   625     1 */
        sgx_misc_select_t          misc_select;          /*   626     4 */
        uint8_t                    misc_select_mask[MISCSELECTMASK_LEN];     /*   630     4 */
        sgx_attributes_t           attributes;           /*   634    16 */
        uint8_t                    attributes_mask[ATTRIBUTESELECTMASK_LEN];  /*   650    16 */
        sgx_measurement_t          mr_enclave;           /*   666    32 */
        sgx_measurement_t          mr_signer;            /*   698    32 */
        sgx_prod_id_t              isv_prod_id;          /*   730     2 */
        sgx_isv_svn_t              isv_svn;              /*   732     2 */
        time_t                     tcb_date;             /*   734     64 */
        char                       tcb_status[TCB_STATUS_LEN];           /*   798     32 */
        time_t                     qe_tcb_date;          /*   830     64 */
        char                       qe_tcb_status[TCB_STATUS_LEN];        /*   894     32 */
};

static const unsigned SERVTD_HEADER_SIZE = 4;
static const uint32_t SERVTD_REQ_BUF_SIZE = 16 * 4 * 1024; // 16 pages

#pragma pack(pop)

#endif
