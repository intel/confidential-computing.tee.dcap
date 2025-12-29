/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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

#ifndef _SGX_QVE_DEF_H_
#define _SGX_QVE_DEF_H_

#include "sgx_ql_quote.h"
#include "sgx_report.h"
#include "sgx_quote.h"


#ifndef DEBUG_MODE
#define DEBUG_MODE 0
#endif //DEBUG_MODE

#define TEE_SGX_PALTFORM_TOKEN_UUID "3123ec35-8d38-4ea5-87a5-d6c48b567570"
#define TEE_SGX_ENCLAVE_TOKEN_UUID "bef7cb8c-31aa-42c1-854c-10db005d5c41"
#define TEE_SGX_PLATFORM_TOKEN_VER "1.0"
#define TEE_SGX_ENCLAVE_TOKEN_VER "1.0"
#define TEE_SGX_PLATFORM_DESCRIPTION "SGX Platform TCB"
#define TEE_SGX_ENCLAVE_DESCRIPTION "SGX Platform TCB"

#define TEE_TDX10_PALTFORM_TOKEN_UUID "9eec018b-7481-4b1c-8e1a-9f7c0c8c777f"
#define TEE_TDX15_PALTFORM_TOKEN_UUID "f708b97f-0fb2-4e6b-8b03-8a5bcd1221d3"
#define TEE_TDX_QE_IDENTITY_TOKEN_UUID "3769258c-75e6-4bc7-8d72-d2b0e224cad2"
#define TEE_TDX_TD10_IDENTITY_TOKEN_UUID "a1e4ee9c-a12e-48ac-bed0-e3f89297f687"
#define TEE_TDX_TD15_IDENTITY_TOKEN_UUID "45b734fc-aa4e-4c3d-ad28-e43d08880e68"
#define TEE_TDX_PLATFORM_TOKEN_VER "1.0"
#define TEE_TDX_QE_IDENTITY_TOKEN_VER "1.0"
#define TEE_TDX_TD_IDENTITY_TOKEN_VER "1.0"
#define TEE_TDX_PLATFORM_DESCRIPTION "TDX Platform TCB"
#define TEE_TDX_QE_IDENTITY_DESCRIPTION "RAW TDX QE Report"
#define TEE_TDX_TD_IDENTITY_DESCRIPTION "Application TD TCB"
#define QUOTE_HASH_ALGO "SHA384"
#define SGX_QUOTE_TYPE 0x0
#define TDX_QUOTE_TYPE 0x81
#define REQUEST_ID_LEN 16
#define TIME_STR_LEN 24
#define SHA384_LEN 48

typedef enum _tee_evidence_type_t{
    SGX_EVIDENCE = 0,
    TDX_EVIDENCE,
    UNKNOWN_QUOTE_TYPE
} tee_evidence_type_t;

typedef enum _tee_qv_report_type_t{
    UNKNOWN_REPORT_TYPE = 0,
    SGX_REPORT,
    TDX10_REPORT,
    TDX15_REPORT,
    TDX20_REPORT
} tee_qv_report_type_t;


#define SUPPLEMENTAL_DATA_VERSION 3
#define LEGACY_SUPPLEMENTAL_MINOR_VERSION 0
#define SUPPLEMENTAL_V3_LATEST_MINOR_VERSION 3
#define QVE_COLLATERAL_VERSION1 0x1
#define QVE_COLLATERAL_VERSION3 0x3
#define QVE_COLLATERAL_VERSOIN31 0x00010003
#define QVE_COLLATERAL_VERSION4 0x4
#define FMSPC_SIZE 6
#define CA_SIZE 10
#define SGX_CPUSVN_SIZE   16
//
#define QUOTE_MIN_SIZE 1020
#define QUOTE_CERT_TYPE 5
#define CRL_MIN_SIZE 300
#define PROCESSOR_ISSUER "Processor"
#define PLATFORM_ISSUER "Platform"
#define PROCESSOR_ISSUER_ID "processor"
#define PLATFORM_ISSUER_ID "platform"
#define PEM_CRL_PREFIX "-----BEGIN X509 CRL-----"
#define PEM_CRL_PREFIX_SIZE 24

#define UNUSED_PARAM(x) (void)(x)
#define CHECK_MANDATORY_PARAMS(param, param_size) (param == NULL || param_size == 0)
#define CHECK_OPT_PARAMS(param, param_size) ((param == NULL && param_size != 0) || (param != NULL && param_size == 0))

#define NULL_POINTER(x) x==NULL
#define NULL_BREAK(x) if (x == NULL) {break;}
#define BREAK_ERR(x) {if (x != STATUS_OK) break;}
#define SGX_ERR_BREAK(x) {if (x != SGX_SUCCESS) break;}
#ifndef CLEAR_FREE_MEM
#include <string.h>
#define CLEAR_FREE_MEM(address, size) {             \
    if (address != NULL) {                          \
        if (size > 0) {                             \
            (void)memset_s(address, size, 0, size); \
        }                                           \
        free(address);                              \
     }                                              \
}
#endif //CLEAR_FREE_MEM

#define EXPECTED_CERTIFICATE_COUNT_IN_PCK_CHAIN 3

// Nameless struct generates C4201 warning in MS compiler, but it is allowed in c++ 11 standard
// Should remove the pragma after Microsoft fixes this issue
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4201)
#endif

//Quote verfication supplemental data version
//Use for checking and assigning supplemental data version
typedef union _supp_ver_t{
    uint32_t version;
    struct {
        uint16_t major_version;      
        uint16_t minor_version;
    };
} supp_ver_t;

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif //_SGX_QVE_DEF_H_
