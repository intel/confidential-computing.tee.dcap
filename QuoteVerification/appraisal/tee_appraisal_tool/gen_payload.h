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

#pragma once

#include <string>
#include "tee_appraisal_tool.h"
#include "metadata.h"

typedef enum _ftype_t
{
    UNKNOWN_FILE = 0,
    SGX_ENCLAVE,
    TDX_REPORT_V10,
    TDX_REPORT_V15,
    TDX_REPORT_V20,
} ftype_t;

#define TEE_TYPE_TDX 0x00000081L
#define TEE_TYPE_SGX 0x00000000L
#define BODY_TD_REPORT10_TYPE 2
#define BODY_TD_REPORT15_TYPE 3
#define BODY_TD_REPORT15EX_TYPE 4

#define TD_REPORT10_BYTE_LEN 584
#define TD_REPORT15_BYTE_LEN 648


#define TDX_DEFAULT_ATTRIBUTES_MASK    0xFFFFFFFFFFFFFFFFULL
#define TDX_DEFAULT_XFAM_MASK         0xFFFFFFFFFFFFFFFFULL

#define TD_REPORT_ATTRIBUTES_TUD_DEBUG 0x00000001
#define ATTRIBUTES_HAS_DEBUG_BIT(x) (((x) & TD_REPORT_ATTRIBUTES_TUD_DEBUG) != 0)

class CInput
{
public:
    CInput(){};
    virtual ~CInput(){};
    virtual std::string generate_payload() = 0;

private:
    CInput(const CInput &);
    CInput &operator=(const CInput &);
};

class CInputEnclave : public CInput
{
public:
    CInputEnclave(const char *file);
    ~CInputEnclave();
    std::string generate_payload();

private:
    bool get_metadata_from_file(metadata_t &metadata);
    bool get_meta_offset(const uint8_t *start_addr, uint64_t &meta_offset);
    const char *m_file;
    const std::string m_class_id;
};

class CInputTDReport : public CInput
{
public:
    CInputTDReport(const uint8_t *inbuf, size_t bsize, ftype_t ft);
    ~CInputTDReport();
    std::string generate_payload();

private:
    const void *m_report;
    size_t m_size;
    ftype_t m_ftype;
    const std::string m_class_id_v4;
    const std::string m_class_id_v5;
};

class CPayloadGen
{
public:
    CPayloadGen(const char *file);
    ~CPayloadGen();
    std::string generate_payload();

private:
    ftype_t check_file_type(const uint8_t *inbuf, size_t bsize);

    ftype_t is_tdx_report(const uint8_t *inbuf, size_t bsize);
    bool is_sgx_enclave(const uint8_t *inbuf, size_t bsize);
    const char *m_file;
};
