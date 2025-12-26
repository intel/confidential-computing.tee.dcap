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

 /*
 * Quote Verification Enclave (QvE)
 * An architectural enclave for quote verification.
 */
#ifndef SERVTD_ATTEST
#ifndef SGX_TRUSTED
#define get_fmspc_ca_from_quote qvl_get_fmspc_ca_from_quote
#define sgx_qve_verify_quote sgx_qvl_verify_quote
#define sgx_qve_get_quote_supplemental_data_size sgx_qvl_get_quote_supplemental_data_size
#define sgx_qve_get_quote_supplemental_data_version sgx_qvl_get_quote_supplemental_data_version
#define tee_qve_verify_quote_qvt tee_qvl_verify_quote_qvt
#include "sgx_dcap_qv_internal.h"
#define memset_s(a,b,c,d) memset(a,c,d)
#define memcpy_s(a,b,c,d) (memcpy(a,c,b) && 0)
#define sgx_is_within_enclave(a,b) (1)
#else //SGX_TRUSTED
#include "qve_t.h"
#include <mbusafecrt.h>
#include <sgx_tcrypto.h>
#include <sgx_trts.h>
#include <sgx_utils.h>
#endif //SGX_TRUSTED
#else //SERVTD_ATTEST
#include "sgx_dcap_qv_internal.h"
#include "sgx_quote_4.h"
#include "sgx_quote_5.h"
#define memset_s(a,b,c,d) memset(a,c,d)
#define memcpy_s(a,b,c,d) (memcpy(a,c,b) && 0)
#endif //SERVTD_ATTEST

#ifdef SERVTD_ATTEST
#ifndef SGX_TRUSTED
#define SGX_TRUSTED
#include "TimeUtils.h"
#include <algorithm>
#endif
#include "servtd_utils.h"
#include "servtd_qve_utils.h"
#include "tdx_verify.h"
#include "servtd_com.h"
#define memset_s(a,b,c,d) memset(a,c,d)
#define memcpy_s(a,b,c,d) (memcpy(a,c,b) && 0)
#define sgx_is_within_enclave(a,b) (1)
#define EXPORT_API __attribute__ ((visibility("default")))
#define SGX_TD_VERIFY_ERROR(x)              (0x000000FF&(x))
#endif //SGX_TRUSTED

#define __STDC_WANT_LIB_EXT1__ 1
#include <string>
#include <cstring>
#include <array>
#include <algorithm>
#include <vector>
#include "Verifiers/EnclaveIdentityParser.h"
#include "Verifiers/EnclaveIdentityV2.h"
#include "QuoteVerification/Quote.h"
#include "PckParser/CrlStore.h"
#include "CertVerification/CertificateChain.h"
#include "CertVerification/X509Constants.h"
#include "Utils/TimeUtils.h"
#include "SgxEcdsaAttestation/AttestationParsers.h"
#include "sgx_qve_header.h"
#include "sgx_qve_def.h"

#include <openssl/provider.h>

static int SGXSSL_init(void)
{
    // Given QvE is single-threaded, this function isn't protected by any
    // synchronzation mechanism

    static int error_code = 1;
    if (error_code <= 0)
        return error_code;

#ifdef SGXSSL_FIPS
    static const char fips_provider_name[] = "fips";

    auto entry = sgx_get_ossl_fips_sym("OSSL_provider_init");
    if (!entry)
        return error_code = -1;

    if (!OSSL_PROVIDER_add_builtin(NULL, fips_provider_name, (OSSL_provider_init_fn*)entry))
        return error_code = -2;

    if (!OSSL_PROVIDER_available(NULL, fips_provider_name))
        return error_code = -3;

    auto prov = OSSL_PROVIDER_load(NULL, fips_provider_name);
    if (!prov)
        return error_code = -4;

    if (!OSSL_PROVIDER_self_test(prov))
        return error_code = -5;

    if (!OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, NULL))
        return error_code = -6;
#endif

    return error_code = 0;
}

using namespace intel::sgx::dcap;
using namespace intel::sgx::dcap::parser;
using namespace intel::sgx::dcap::constants;

//Intel Root Public Key
//
const uint8_t INTEL_ROOT_PUB_KEY[] = {
    0x04, 0x0b, 0xa9, 0xc4, 0xc0, 0xc0, 0xc8, 0x61, 0x93, 0xa3, 0xfe, 0x23, 0xd6, 0xb0, 0x2c,
    0xda, 0x10, 0xa8, 0xbb, 0xd4, 0xe8, 0x8e, 0x48, 0xb4, 0x45, 0x85, 0x61, 0xa3, 0x6e, 0x70,
    0x55, 0x25, 0xf5, 0x67, 0x91, 0x8e, 0x2e, 0xdc, 0x88, 0xe4, 0x0d, 0x86, 0x0b, 0xd0, 0xcc,
    0x4e, 0xe2, 0x6a, 0xac, 0xc9, 0x88, 0xe5, 0x05, 0xa9, 0x53, 0x55, 0x8c, 0x45, 0x3f, 0x6b,
    0x09, 0x04, 0xae, 0x73, 0x94
};

/**
 * Check if a given status code is an expiration error or not.
 *
 * @param status_err[IN] - Status error code.
 *
 * @return 1: Status indicates an expiration error.
 * @return 0: Status indicates error other than expiration error.
*
 **/
static bool is_nonterminal_error(Status status_err) {
    switch (status_err)
    {
    case STATUS_TCB_OUT_OF_DATE:
    case STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED:
    case STATUS_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE:
    case STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE:
    case STATUS_QE_IDENTITY_OUT_OF_DATE:
    case STATUS_SGX_TCB_INFO_EXPIRED:
    case STATUS_SGX_PCK_CERT_CHAIN_EXPIRED:
    case STATUS_SGX_CRL_EXPIRED:
    case STATUS_SGX_SIGNING_CERT_CHAIN_EXPIRED:
    case STATUS_SGX_ENCLAVE_IDENTITY_EXPIRED:
    case STATUS_TCB_CONFIGURATION_NEEDED:
    case STATUS_TCB_SW_HARDENING_NEEDED:
    case STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED:
    case STATUS_TCB_TD_RELAUNCH_ADVISED:
    case STATUS_TCB_TD_RELAUNCH_ADVISED_CONFIGURATION_NEEDED:
        return true;
    default:
        return false;
    }
}

/**
 * Check if a given status code is an expiration error or not.
 *
 * @param status_err[IN] - Status error code.
 *
 * @return 1: Status indicates an expiration error.
 * @return 0: Status indicates error other than expiration error.
*
 **/
static bool is_expiration_error(Status status_err) {
    switch (status_err)
    {
    case STATUS_SGX_TCB_INFO_EXPIRED:
    case STATUS_SGX_PCK_CERT_CHAIN_EXPIRED:
    case STATUS_SGX_CRL_EXPIRED:
    case STATUS_SGX_SIGNING_CERT_CHAIN_EXPIRED:
    case STATUS_SGX_ENCLAVE_IDENTITY_EXPIRED:
        return true;
    default:
        return false;
    }
}

/**
 * Map Status error code to quote3_error_t error code.
 *
 * @param status_err[IN] - Status error code.
 *
 * @return quote3_error_t that matches status_err.
*
 **/
static quote3_error_t status_error_to_quote3_error(Status status_err) {

    switch (status_err)
    {
    case STATUS_OK:
    case STATUS_TCB_TD_RELAUNCH_ADVISED:
    case STATUS_TCB_TD_RELAUNCH_ADVISED_CONFIGURATION_NEEDED:
        return SGX_QL_SUCCESS;
    case STATUS_MISSING_PARAMETERS:
        return SGX_QL_ERROR_INVALID_PARAMETER;
    case STATUS_UNSUPPORTED_QUOTE_FORMAT:
        return SGX_QL_QUOTE_FORMAT_UNSUPPORTED;
    case STATUS_INVALID_QE_REPORT_SIGNATURE:
        return SGX_QL_QE_REPORT_INVALID_SIGNATURE;
    case STATUS_SGX_ENCLAVE_REPORT_UNSUPPORTED_FORMAT:
        return SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT;
    case STATUS_UNSUPPORTED_PCK_CERT_FORMAT:
    case STATUS_UNSUPPORTED_CERT_FORMAT:
        return SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT;
    case STATUS_INVALID_PCK_CERT:
    case STATUS_SGX_PCK_CERT_CHAIN_UNTRUSTED:
    case STATUS_SGX_ROOT_CA_UNTRUSTED:
        return SGX_QL_PCK_CERT_CHAIN_ERROR;
    case STATUS_UNSUPPORTED_TCB_INFO_FORMAT:
    case STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT:
    case STATUS_SGX_TCB_INFO_INVALID:
        return SGX_QL_TCBINFO_UNSUPPORTED_FORMAT;
    case STATUS_TCB_NOT_SUPPORTED:
        return SGX_QL_TCB_NOT_SUPPORTED;
    case STATUS_TCB_INFO_MISMATCH:
        return SGX_QL_TCBINFO_MISMATCH;
    case STATUS_SGX_QE_IDENTITY_UNSUPPORTED_FORMAT:
        return SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT;
    case STATUS_SGX_QE_IDENTITY_INVALID:
    case STATUS_QE_IDENTITY_MISMATCH:
    case STATUS_SGX_ENCLAVE_REPORT_MISCSELECT_MISMATCH:
    case STATUS_SGX_ENCLAVE_REPORT_ATTRIBUTES_MISMATCH:
    case STATUS_SGX_ENCLAVE_REPORT_MRENCLAVE_MISMATCH:
    case STATUS_SGX_ENCLAVE_REPORT_MRSIGNER_MISMATCH:
    case STATUS_SGX_ENCLAVE_REPORT_ISVPRODID_MISMATCH:
        return SGX_QL_QEIDENTITY_MISMATCH;
    case STATUS_TCB_OUT_OF_DATE:
        return SGX_QL_TCB_OUT_OF_DATE;
    case STATUS_TCB_CONFIGURATION_NEEDED:
        return SGX_QL_TCB_CONFIGURATION_NEEDED;
    case STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED:
        return SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED;
    case STATUS_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE:
        return SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE;
    case STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE:
        return SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE;
    case STATUS_QE_IDENTITY_OUT_OF_DATE:
        return SGX_QL_QE_IDENTITY_OUT_OF_DATE;
    case STATUS_SGX_TCB_INFO_EXPIRED:
        return SGX_QL_SGX_TCB_INFO_EXPIRED;
    case STATUS_SGX_PCK_CERT_CHAIN_EXPIRED:
        return SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED;
    case STATUS_SGX_CRL_EXPIRED:
        return SGX_QL_SGX_CRL_EXPIRED;
    case STATUS_SGX_SIGNING_CERT_CHAIN_EXPIRED:
        return SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED;
    case STATUS_SGX_ENCLAVE_IDENTITY_EXPIRED:
        return SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED;
    case STATUS_PCK_REVOKED:
    case STATUS_SGX_PCK_REVOKED:
    case STATUS_SGX_INTERMEDIATE_CA_REVOKED:
    case STATUS_SGX_TCB_SIGNING_CERT_REVOKED:
        return SGX_QL_PCK_REVOKED;
    case STATUS_TCB_REVOKED:
    case STATUS_SGX_ENCLAVE_REPORT_ISVSVN_REVOKED:
        return SGX_QL_TCB_REVOKED;
    case STATUS_UNSUPPORTED_QE_CERTIFICATION:
    case STATUS_UNSUPPORTED_QE_CERTIFICATION_DATA_TYPE:
        return SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED;
    case STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_FORMAT:
    case STATUS_SGX_ENCLAVE_IDENTITY_INVALID:
    case STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_VERSION:
    case STATUS_UNSUPPORTED_QE_IDENTITY_FORMAT:
    case STATUS_SGX_ENCLAVE_IDENTITY_INVALID_SIGNATURE:
        return SGX_QL_QEIDENTITY_CHAIN_ERROR;
    case STATUS_TCB_INFO_INVALID_SIGNATURE:
    case STATUS_SGX_TCB_SIGNING_CERT_CHAIN_UNTRUSTED:
        return SGX_QL_TCBINFO_CHAIN_ERROR;
    case STATUS_TCB_SW_HARDENING_NEEDED:
        return SGX_QL_TCB_SW_HARDENING_NEEDED;
    case STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED:
        return SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED;
    case STATUS_TDX_MODULE_MISMATCH:
        return SGX_QL_TDX_MODULE_MISMATCH;
    case STATUS_INVALID_QUOTE_SIGNATURE:
    case STATUS_SGX_CRL_INVALID_SIGNATURE:
    case STATUS_SGX_QE_IDENTITY_INVALID_SIGNATURE:
        return SGX_QL_RESULT_INVALID_SIGNATURE;
    default:
        return SGX_QL_ERROR_UNEXPECTED;
    }
}

/**
 * Map Status error code to sgx_ql_qv_result_t.
 *
 * @param status_err[IN] - Status error code.
 *
 * @return sgx_ql_qv_result_t that matches status_err.
 *
 **/
static sgx_ql_qv_result_t status_error_to_ql_qve_result(Status status_err) {
    switch (status_err)
    {
    case STATUS_OK:
        return SGX_QL_QV_RESULT_OK;
    case STATUS_SGX_ENCLAVE_IDENTITY_INVALID_SIGNATURE:
    case STATUS_SGX_QE_IDENTITY_INVALID_SIGNATURE:
    case STATUS_INVALID_QUOTE_SIGNATURE:
    case STATUS_INVALID_QE_REPORT_SIGNATURE:
    case STATUS_SGX_CRL_INVALID_SIGNATURE:
    case STATUS_TCB_INFO_INVALID_SIGNATURE:
        return SGX_QL_QV_RESULT_INVALID_SIGNATURE;
    case STATUS_PCK_REVOKED:
    case STATUS_TCB_REVOKED:
    case STATUS_SGX_TCB_SIGNING_CERT_REVOKED:
    case STATUS_SGX_PCK_REVOKED:
    case STATUS_SGX_INTERMEDIATE_CA_REVOKED:
        return SGX_QL_QV_RESULT_REVOKED;
    case STATUS_TCB_CONFIGURATION_NEEDED:
        return SGX_QL_QV_RESULT_CONFIG_NEEDED;
    case STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED:
        return SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED;
    case STATUS_TCB_OUT_OF_DATE:
    case STATUS_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE:
    case STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE:
    case STATUS_QE_IDENTITY_OUT_OF_DATE:
        return SGX_QL_QV_RESULT_OUT_OF_DATE;
    case STATUS_TCB_SW_HARDENING_NEEDED:
        return SGX_QL_QV_RESULT_SW_HARDENING_NEEDED;
    case STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED:
        return SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED;
    case STATUS_TCB_TD_RELAUNCH_ADVISED:
        return TEE_QV_RESULT_TD_RELAUNCH_ADVISED;
    case STATUS_TCB_TD_RELAUNCH_ADVISED_CONFIGURATION_NEEDED:
        return TEE_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED;
    default:
        return SGX_QL_QV_RESULT_UNSPECIFIED;
    }
}

/**
 * Check the CRL is PEM encoding or not
 *
 **/
static bool check_pem_crl(char *crl, uint32_t size)
{
    if (crl == NULL || size < CRL_MIN_SIZE)
        return false;

    if (strncmp(crl, PEM_CRL_PREFIX, PEM_CRL_PREFIX_SIZE) == 0)
        return true;

    return false;
}

/**
 * Check the CRL is hex string or not
 *
 **/
static bool check_hex_crl(char *crl, uint32_t size)
{
    if (crl == NULL || size < CRL_MIN_SIZE)
        return false;

    //only check length = size-1, as the last item may be nul terminator
    for (uint32_t i = 0; i < size - 1; i++) {
        if (!isxdigit(crl[i])) {
            return false;
        }
    }

    return true;
}

/**
 * Convert char to hex string
 *
 **/
static std::string byte_to_hexstring(const uint8_t* data, size_t len, bool big_endian)
{
    if(data == NULL || len == 0){
       return {};
    }
    std::vector<uint8_t> tmp_vec(data, data + len);
    if(big_endian){
        reverse(tmp_vec.begin(), tmp_vec.end());    //align the endian in the appraisal
    }
    return bytesToHexString(tmp_vec);

}

#define TCB_COMPONENT_LEN   16

static bool isTdxTcbHigherOrEqual(const Quote& quote,
                           const parser::json::TcbLevel& tcbLevel)
{
    const auto& teeTcbSvn = quote.getTeeTcbSvn();
    uint32_t index = 0;
    if (quote.getHeader().version > constants::QUOTE_VERSION_3 && teeTcbSvn[1] > 0)
    {
        index = 2;
    }
    for(; index < TCB_COMPONENT_LEN; ++index)
    {
        const auto componentValue = teeTcbSvn[index];
        const auto& otherComponentValue = tcbLevel.getTdxTcbComponent(index);
        if(componentValue < otherComponentValue.getSvn())
        {
            // If *ANY* TCB component SVN is lower than TCB level is considered lower
            return false;
        }
    }
    // but for TCB level to be considered higher it requires *EVERY* SVN to be higher or equal
    return true;
}

static bool isTcbComponentSvnHigherOrEqual(const parser::x509::PckCertificate& pckCert,
                           const parser::json::TcbLevel& tcbLevel)
{
    for(uint32_t index = 0; index < TCB_COMPONENT_LEN; ++index)
    {
        const auto componentValue = pckCert.getTcb().getSgxTcbComponentSvn(index);
        const auto otherComponentValue = tcbLevel.getSgxTcbComponentSvn(index);
        if(componentValue < otherComponentValue)
        {
            // If *ANY* TCB component SVN is lower than TCB component SVN is considered lower
            return false;
        }
    }
    // but for TCB component SVN to be considered higher it requires that *EVERY* TCB component SVN to be higher or equal
    return true;
}

const json::TcbLevel& getMatchingTcbLevel(const json::TcbInfo *tcbInfo,
                            const x509::PckCertificate &pckCert,
                            const Quote &quote)
{
    const auto &tcbs = tcbInfo->getTcbLevels();
    const auto certPceSvn = pckCert.getTcb().getPceSvn();

    for (const auto& tcb : tcbs)
    {
        if(isTcbComponentSvnHigherOrEqual(pckCert, tcb) && certPceSvn >= tcb.getPceSvn())
        {
            if (tcbInfo->getVersion() >= 3 &&
                tcbInfo->getId() == parser::json::TcbInfo::TDX_ID &&
                quote.getHeader().teeType == constants::TEE_TYPE_TDX)
            {
                if (isTdxTcbHigherOrEqual(quote, tcb))
                {
                    return tcb;
                }
            }
            else
            {
                return tcb;
            }
        }
    }

    throw SGX_QL_TCBINFO_UNSUPPORTED_FORMAT;
}

#ifdef SERVTD_ATTEST

int getTdxModuleTcblevel(const json::TcbInfo* tcbInfo,
    const Quote& quote, uint8_t& tcbLevel)
{
    const auto& tdxModuleVersion = quote.getTeeTcbSvn()[1];
    const auto& tdxModuleIsvSvn = quote.getTeeTcbSvn()[0];
    tcbLevel = 0;

    if (quote.getHeader().version > constants::QUOTE_VERSION_3 && tdxModuleVersion == 0)
    {
        return 0;
    }

    const std::string tdxModuleIdentityId = "TDX_" + bytesToHexString({ tdxModuleVersion });

    const auto& found = std::find_if(tcbInfo->getTdxModuleIdentities().begin(),
        tcbInfo->getTdxModuleIdentities().end(),
        [&](const auto& tdxModuleIdentity)
        {
            std::string id = tdxModuleIdentity.getId();
            std::transform(id.begin(), id.end(), id.begin(),
                ::toupper); // convert to uppercase
            return (id == tdxModuleIdentityId);
        });
    if (found == std::end(tcbInfo->getTdxModuleIdentities())) {
        return -1;
    }
    const auto& foundTdxModuleTcbLevel = std::find_if(found->getTcbLevels().begin(),
        found->getTcbLevels().end(),
        [&](const auto& tdxModuleTcbLevel)
        {
            return tdxModuleIsvSvn >= tdxModuleTcbLevel.getTcb().getIsvSvn();
        });
    if (foundTdxModuleTcbLevel == std::end(found->getTcbLevels()))
    {
        return -1;
    }
    tcbLevel = static_cast<uint8_t>(foundTdxModuleTcbLevel->getTcb().getIsvSvn());
    return 0;
}
#endif

/**
 * Given a quote with cert type 5, extract PCK Cert chain and return it.
 * @param p_quote[IN] - Pointer to a quote buffer.
 * @param quote_size[IN] - Size of input quote buffer.
 * @param p_pck_cert_chain_size[OUT] - Pointer to a extracted chain size.
 * @param pp_pck_cert_chain[OUT] - Pointer to a pointer to a buffer to write PCK Cert chain to.
 *
 * @return quote3_error_t code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT
 *      - SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED
 *      - SGX_QL_ERROR_UNEXPECTED
 **/
static quote3_error_t extract_chain_from_quote(const uint8_t *p_quote,
    uint32_t quote_size,
    uint32_t* p_pck_cert_chain_size,
    uint8_t** pp_pck_cert_chain) {

    if (p_quote == NULL || quote_size < QUOTE_MIN_SIZE || p_pck_cert_chain_size == NULL || pp_pck_cert_chain == NULL || *pp_pck_cert_chain != NULL) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    Status pck_res = STATUS_MISSING_PARAMETERS;
    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;
    uint16_t p_pck_cert_chain_type = 0;
    do {
        //get certification data size
        //
        pck_res = sgxAttestationGetQECertificationDataSize(
            p_quote,
            quote_size,
            p_pck_cert_chain_size);
        if (pck_res != STATUS_OK) {
            ret = status_error_to_quote3_error(pck_res);
            break;
        }
        //for some reason sgxAttestationGetQECertificationDataSize successfully returned, with chain_size == 0
        //
        if (*p_pck_cert_chain_size == 0) {
            break;
        }

        //verify quote format, allocate memory for certification data, then fill it with the certification data from the quote
        //sgxAttestationGetQECertificationDataSize doesn't calculate the value with '\0',
        //hence we need to allocate p_pck_cert_chain_size + 1 (+1 for '\0')
        //
        *pp_pck_cert_chain = (uint8_t*)malloc(1 + *p_pck_cert_chain_size);
        if (*pp_pck_cert_chain == NULL) {
            ret = SGX_QL_ERROR_OUT_OF_MEMORY;
            break;
        }

        //sgxAttestationGetQECertificationData expects p_pck_cert_chain_size to be exactly as returned
        //from sgxAttestationGetQECertificationDataSize
        //
        pck_res = sgxAttestationGetQECertificationData(
            p_quote,
            quote_size,
            *p_pck_cert_chain_size,
            *pp_pck_cert_chain,
            &p_pck_cert_chain_type);
        if (pck_res != STATUS_OK) {
            ret = status_error_to_quote3_error(pck_res);
            break;
        }
        (*pp_pck_cert_chain)[(*p_pck_cert_chain_size)] = '\0';

        //validate quote certification type
        //
        if (p_pck_cert_chain_type != QUOTE_CERT_TYPE) {
            ret = SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED;
            break;
        }

        ret = SGX_QL_SUCCESS;
    } while (0);

    if (ret != SGX_QL_SUCCESS) {
        if (*pp_pck_cert_chain != NULL) {
            free(*pp_pck_cert_chain);
            *pp_pck_cert_chain = NULL;
        }
    }
    return ret;
}

/**
 * Extract FMSPc and CA from a given quote with cert type 5.
 * @param p_quote[IN] - Pointer to a quote buffer.
 * @param quote_size[IN] - Size of input quote buffer.
 * @param p_fmsp_from_quote[OUT] - Pointer to a buffer to write fmsp to.
 * @param fmsp_from_quote_size[IN] - Size of fmsp buffer.
 * @param p_ca_from_quote[OUT] - Pointer to a buffer to write CA to.
 * @param ca_from_quote_size[IN] - Size of CA buffer.
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_ATT_KEY_CERT_DATA_INVALID
 *      - SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED
 *      - SGX_QL_ERROR_UNEXPECTED
 **/
quote3_error_t get_fmspc_ca_from_quote(const uint8_t* p_quote, uint32_t quote_size,
    unsigned char* p_fmsp_from_quote, uint32_t fmsp_from_quote_size,
    unsigned char* p_ca_from_quote, uint32_t ca_from_quote_size) {

    if (SGXSSL_init())
        return SGX_QL_SERVICE_UNAVAILABLE;

    if (p_quote == NULL ||
        quote_size < QUOTE_MIN_SIZE ||
        !sgx_is_within_enclave(p_quote, quote_size) ||
        p_fmsp_from_quote == NULL || fmsp_from_quote_size < FMSPC_SIZE ||
        !sgx_is_within_enclave(p_fmsp_from_quote, fmsp_from_quote_size) ||
        p_ca_from_quote == NULL || ca_from_quote_size < CA_SIZE ||
        !sgx_is_within_enclave(p_ca_from_quote, ca_from_quote_size))
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;
    uint32_t pck_cert_chain_size = 0;
    uint8_t* p_pck_cert_chain = NULL;

    do {
        ret = extract_chain_from_quote(p_quote, quote_size, &pck_cert_chain_size, &p_pck_cert_chain);
        if (ret != SGX_QL_SUCCESS || p_pck_cert_chain == NULL || pck_cert_chain_size == 0) {
            break;
        }

        //convert certification data to string
        //
        CertificateChain chain;
        if (chain.parse((reinterpret_cast<const char*>(p_pck_cert_chain))) != STATUS_OK || chain.length() != EXPECTED_CERTIFICATE_COUNT_IN_PCK_CHAIN) {
            ret = SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT;
            break;
        }
        //extract data from certificates
        //
        auto topmost_cert = chain.getTopmostCert();
        x509::PckCertificate topmost_pck_cert;
        //compare to nullptr (C++ way of comparing pointers to NULL), otherwise gcc will report a compilation warning
        //
        if (topmost_cert == nullptr) {
            ret = SGX_QL_PCK_CERT_CHAIN_ERROR;
            break;
        }
        try {
            topmost_pck_cert = x509::PckCertificate(*topmost_cert);
        }
        catch (...) {
            ret = SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT;
            break;
        }

        auto fmspc_from_cert = topmost_pck_cert.getFmspc();
        auto issuer = topmost_cert->getIssuer().getCommonName();
        if (issuer.find(PROCESSOR_ISSUER) != std::string::npos) {
            if (memcpy_s(p_ca_from_quote, sizeof(PROCESSOR_ISSUER_ID), PROCESSOR_ISSUER_ID, sizeof(PROCESSOR_ISSUER_ID)) != 0) {
                ret = SGX_QL_ERROR_UNEXPECTED;
                break;
            }
        }
        else if (issuer.find(PLATFORM_ISSUER) != std::string::npos) {
            if (memcpy_s(p_ca_from_quote, sizeof(PLATFORM_ISSUER_ID), PLATFORM_ISSUER_ID, sizeof(PLATFORM_ISSUER_ID)) != 0) {
                ret = SGX_QL_ERROR_UNEXPECTED;
                break;
            }
        }
        else {
            ret = SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT;
            break;
        }
        if (memcpy_s(p_fmsp_from_quote, fmsp_from_quote_size,
            fmspc_from_cert.data(), fmspc_from_cert.size()) != 0) {
            ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }

        ret = SGX_QL_SUCCESS;
    } while (0);

    //free allocated memory
    //
    if (p_pck_cert_chain != NULL) {
        free(p_pck_cert_chain);
    }

    return ret;
}

static time_t getEarliestIssueDate(const CertificateChain* chain) {
    time_t min_issue_date = 0;
    auto certs = chain->getCerts();
    if (!certs.empty()) {
        min_issue_date = certs.front()->getValidity().getNotBeforeTime();
        for (auto const& cert : certs) {
            if (cert->getValidity().getNotBeforeTime() < min_issue_date) {
                min_issue_date = cert->getValidity().getNotBeforeTime();
            }
        }
    }

    return min_issue_date;
}

static time_t getEarliestExpirationDate(const CertificateChain* chain) {
    time_t min_expiration_date = 0;
    auto certs = chain->getCerts();

    if (!certs.empty()) {
        min_expiration_date = certs.front()->getValidity().getNotAfterTime();
        for (auto const& cert : certs) {
            if (cert->getValidity().getNotAfterTime() < min_expiration_date) {
                min_expiration_date = cert->getValidity().getNotAfterTime();
            }
        }
    }

    return min_expiration_date;
}

static time_t getLatestIssueDate(const CertificateChain* chain) {
    time_t max_issue_date = 0;
    auto certs = chain->getCerts();
    if (!certs.empty()) {
        max_issue_date = certs.front()->getValidity().getNotBeforeTime();
        for (auto const& cert : certs) {
            if (cert->getValidity().getNotBeforeTime() > max_issue_date) {
                max_issue_date = cert->getValidity().getNotBeforeTime();
            }
        }
    }
    return max_issue_date;
}

static time_t getLatestExpirationDate(const CertificateChain* chain) {
    time_t max_expiration_date = 0;
    auto certs = chain->getCerts();
    if (!certs.empty()) {
        max_expiration_date = certs.front()->getValidity().getNotAfterTime();
        for (auto const& cert : certs) {
            if (cert->getValidity().getNotAfterTime() > max_expiration_date) {
                max_expiration_date = cert->getValidity().getNotAfterTime();
            }
        }
    }
    return max_expiration_date;
}


/**
 * Helper function to return earliest & latest issue date and expiration date comparing all collaterals.
 * @param p_cert_chain_obj[IN] - Pointer to CertificateChain object containing PCK Cert chain (for quote with cert type 5, this should be extracted from the quote).
 * @param p_tcb_info_obj[IN] - Pointer to TcbInfo object.
 * @param p_quote_collateral[IN] - Pointer to _sgx_ql_qve_collateral_t struct.
 * @param p_earliest_issue_date[OUT] - Pointer to store the value of the earliest issue date of all input data in quote verification collaterals.
 * @param p_earliest_expiration_date[OUT] - Pointer to store the value of the earliest expiration date of all collaterals used in quote verification collaterals.
 * @param p_latest_issue_date[OUT] - Pointer to store the value of the latest issue date of all input data in quote verification collaterals.
 * @param p_latest_expiration_date[OUT] - Pointer to store the value of the latest expiration date of all collaterals used in quote verification collaterals.
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_ATT_KEY_CERT_DATA_INVALID
 *      - SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED
 *      - SGX_QL_ERROR_UNEXPECTED
 **/
static quote3_error_t qve_get_collateral_dates(const CertificateChain* p_cert_chain_obj, const json::TcbInfo* p_tcb_info_obj,
    const struct _sgx_ql_qve_collateral_t *p_quote_collateral, const char *crls[],
    time_t* p_earliest_issue_date, time_t* p_earliest_expiration_date,
    time_t* p_latest_issue_date, time_t* p_latest_expiration_date,
    time_t* p_qe_iden_earliest_issue_date, time_t* p_qe_iden_latest_issue_date,
    time_t* p_qe_iden_earliest_expiration_date) {

    quote3_error_t ret = SGX_QL_ERROR_INVALID_PARAMETER;
    int version = 0;

    do {
        if (p_cert_chain_obj == NULL ||
            p_tcb_info_obj == NULL ||
            p_quote_collateral == NULL ||
            p_earliest_issue_date == NULL ||
            p_earliest_expiration_date == NULL ||
            p_latest_issue_date == NULL ||
            p_latest_expiration_date == NULL ||
            p_qe_iden_earliest_issue_date == NULL ||
            p_qe_iden_latest_issue_date == NULL ||
            p_qe_iden_earliest_expiration_date == NULL ||
            crls == NULL ||
            crls[0] == NULL ||
            crls[1] == NULL) {
            break;
        }
        *p_earliest_issue_date = 0;
        *p_earliest_expiration_date = 0;
        *p_latest_issue_date = 0;
        *p_latest_expiration_date = 0;
        *p_qe_iden_earliest_issue_date = 0;
        *p_qe_iden_latest_issue_date = 0;
        *p_qe_iden_earliest_expiration_date = 0;

        CertificateChain qe_identity_issuer_chain;
        if (qe_identity_issuer_chain.parse((reinterpret_cast<const char*>(p_quote_collateral->qe_identity_issuer_chain))) != STATUS_OK) {
            ret = SGX_QL_PCK_CERT_CHAIN_ERROR;
            break;
        }
        CertificateChain tcb_info_issuer_chain;
        if (tcb_info_issuer_chain.parse((reinterpret_cast<const char*>(p_quote_collateral->tcb_info_issuer_chain))) != STATUS_OK) {
            ret = SGX_QL_PCK_CERT_CHAIN_ERROR;
            break;
        }

        EnclaveIdentityParser parser;
        std::unique_ptr<EnclaveIdentityV2> enclaveIdentity;
        try
        {
            enclaveIdentity = parser.parse(p_quote_collateral->qe_identity);
        }
        catch (...)
        {
            ret = SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT;
            break;
        }
        //supports only EnclaveIdentity V2 and V3
        //
        version = enclaveIdentity->getVersion();
        if (version != 2 && version != 3) {
            ret = SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT;
            break;
        }

        //supports only TCBInfo V2 and V3
        //
        version = p_tcb_info_obj->getVersion();
        if (version != 2 && version != 3) {
            ret = SGX_QL_TCBINFO_UNSUPPORTED_FORMAT;
            break;
        }

        pckparser::CrlStore root_ca_crl;
        if (root_ca_crl.parse(crls[0]) != true) {
            ret = SGX_QL_CRL_UNSUPPORTED_FORMAT;
            break;
        }

        pckparser::CrlStore pck_crl;
        if (pck_crl.parse(crls[1]) != true) {
            ret = SGX_QL_CRL_UNSUPPORTED_FORMAT;
            break;
        }

        CertificateChain pck_crl_issuer_chain;
        if (pck_crl_issuer_chain.parse((reinterpret_cast<const char*>(p_quote_collateral->pck_crl_issuer_chain))) != STATUS_OK) {
            ret = SGX_QL_PCK_CERT_CHAIN_ERROR;
            break;
        }

        //Earliest issue date
        //
        std::array <time_t, 8> earliest_issue;
        std::array <time_t, 8> earliest_expiration;
        std::array <time_t, 8> latest_issue;
        std::array <time_t, 8> latest_expiration;

        earliest_issue[0] = root_ca_crl.getValidity().notBeforeTime;
        earliest_issue[1] = pck_crl.getValidity().notBeforeTime;
        earliest_issue[2] = getEarliestIssueDate(&pck_crl_issuer_chain);
        earliest_issue[3] = getEarliestIssueDate(p_cert_chain_obj);
        earliest_issue[4] = getEarliestIssueDate(&tcb_info_issuer_chain);
        earliest_issue[5] = getEarliestIssueDate(&qe_identity_issuer_chain);
        earliest_issue[6] = p_tcb_info_obj->getIssueDate();
        earliest_issue[7] = enclaveIdentity->getIssueDate();

        earliest_expiration[0] = root_ca_crl.getValidity().notAfterTime;
        earliest_expiration[1] = pck_crl.getValidity().notAfterTime;
        earliest_expiration[2] = getEarliestExpirationDate(&pck_crl_issuer_chain);
        earliest_expiration[3] = getEarliestExpirationDate(p_cert_chain_obj);
        earliest_expiration[4] = getEarliestExpirationDate(&tcb_info_issuer_chain);
        earliest_expiration[5] = getEarliestExpirationDate(&qe_identity_issuer_chain);
        earliest_expiration[6] = p_tcb_info_obj->getNextUpdate();
        earliest_expiration[7] = enclaveIdentity->getNextUpdate();

        latest_issue[0] = root_ca_crl.getValidity().notBeforeTime;
        latest_issue[1] = pck_crl.getValidity().notBeforeTime;
        latest_issue[2] = getLatestIssueDate(&pck_crl_issuer_chain);
        latest_issue[3] = getLatestIssueDate(p_cert_chain_obj);
        latest_issue[4] = getLatestIssueDate(&tcb_info_issuer_chain);
        latest_issue[5] = getLatestIssueDate(&qe_identity_issuer_chain);
        latest_issue[6] = p_tcb_info_obj->getIssueDate();
        latest_issue[7] = enclaveIdentity->getIssueDate();
        latest_expiration[0] = root_ca_crl.getValidity().notAfterTime;
        latest_expiration[1] = pck_crl.getValidity().notAfterTime;
        latest_expiration[2] = getLatestExpirationDate(&pck_crl_issuer_chain);
        latest_expiration[3] = getLatestExpirationDate(p_cert_chain_obj);
        latest_expiration[4] = getLatestExpirationDate(&tcb_info_issuer_chain);
        latest_expiration[5] = getLatestExpirationDate(&qe_identity_issuer_chain);
        latest_expiration[6] = p_tcb_info_obj->getNextUpdate();
        latest_expiration[7] = enclaveIdentity->getNextUpdate();


        //p_earliest_issue_date
        //
        *p_earliest_issue_date = *std::min_element(earliest_issue.begin(), earliest_issue.end());

        //p_earliest_expiration_date
        //
        *p_earliest_expiration_date = *std::min_element(earliest_expiration.begin(), earliest_expiration.end());

        //p_latest_issue_date
        //
        *p_latest_issue_date = *std::max_element(latest_issue.begin(), latest_issue.end());

        //p_latest_expiration_date
        //
        *p_latest_expiration_date = *std::max_element(latest_expiration.begin(), latest_expiration.end());

        *p_qe_iden_earliest_issue_date = earliest_issue[5];
        *p_qe_iden_latest_issue_date = latest_issue[5];
        *p_qe_iden_earliest_expiration_date = earliest_expiration[5];

        if (*p_earliest_issue_date == 0 || *p_earliest_expiration_date == 0 ||
            *p_latest_issue_date == 0 || *p_latest_expiration_date == 0 ||
            *p_qe_iden_earliest_issue_date == 0 || *p_qe_iden_latest_issue_date == 0 ||
            *p_qe_iden_earliest_expiration_date == 0) {
            ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }

        ret = SGX_QL_SUCCESS;

    } while (0);

    return ret;
}
#ifdef SERVTD_ATTEST

constexpr const char* tcbStatusToString(TcbStatus status)
{
    switch (status) {
        case TcbStatus::UpToDate:                     return "UpToDate";
        case TcbStatus::ConfigurationNeeded:          return "ConfigurationNeeded";
        case TcbStatus::OutOfDate:                    return "OutOfDate";
        case TcbStatus::OutOfDateConfigurationNeeded: return "OutOfDateConfigurationNeeded";
        case TcbStatus::Revoked:                      return "Revoked";
        default:                                      return "Unknown";
    }
}

/**
    * @brief Get the matching QE TCB level based on ISVSVN
    * @param enclaveIdentity The QE identity
    * @param quote The quote object containing ISVSVN information
    * @return The matching TCB level object if found, otherwise throws an exception
*/
const TCBLevel getMatchingQETcbLevel(std::unique_ptr<EnclaveIdentityV2>& enclaveIdentity, const Quote& quote) {

    // Get matching QE identity TCB levels.
    const auto& qe_identity_tcb_levels = enclaveIdentity->getTcbLevels();

    // Ensure the QE identity has at least one TCBLevel.
    if (qe_identity_tcb_levels.empty()) {
        throw SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT;
    }

    const TCBLevel * matchingTCBLevel = NULL;

    // The premise of this code is that the server returns a sequence ordered from top to bottom, and
    // we need to find the largest TCB level among the TCB Levels smaller than ours based on ISVSVN.
    for (const auto& tcbLevel : qe_identity_tcb_levels) {
        if (tcbLevel.getIsvsvn() <= quote.getQeReport().isvSvn) {
            matchingTCBLevel = &tcbLevel;
            break;
        }
    }
    if (matchingTCBLevel){
        return *matchingTCBLevel;
    }

    throw SGX_QL_TCBINFO_UNSUPPORTED_FORMAT;
}
/**
 * @brief Return supplemental data for TD Migration
 *
 * @param quote [IN]  Pointer to quote buffer
 * @param pckCert [IN] Pointer to the platform certificate (PCK)
 * @param tcb_info_obj [IN] Pointer to TcbInfo object that contains the TCB
 * information for this quote generation request
 * @param p_fmspc [IN] Pointer to a buffer containing the FMSPC for this quote
 * generation request
 * @param p_fmspc_size [IN] Size of fmspc
 * @param qe_tcb_info [IN]  Pointer to a buffer containing qe tcb info
 * @param enclaveIdentity The QE identity
 * @param p_servtd_supplemental_data [IN/OUT] Pointer to a data buffer. Must be
 * allocated by caller
 * @param p_servtd_supplemental_data_size [IN/OUT] Pointer to size of buffer
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_TCBINFO_UNSUPPORTED_FORMAT
 */
static quote3_error_t servtd_set_quote_supplemental_data(
    const Quote &quote, const x509::PckCertificate &pckCert,
    const json::TcbInfo *tcb_info_obj, uint8_t *p_fmspc, size_t p_fmspc_size,
    const TCBLevel &qe_tcb_info, std::unique_ptr<EnclaveIdentityV2>& enclaveIdentity, uint8_t *p_servtd_supplemental_data,
    uint32_t *p_servtd_supplemental_data_size) {

    if (tcb_info_obj == NULL) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    if (p_fmspc == NULL || p_fmspc_size != FMSPC_SIZE) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    if (p_servtd_supplemental_data == NULL ||
        p_servtd_supplemental_data_size == NULL) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    if ((*p_servtd_supplemental_data_size) <
        sizeof(struct servtd_tdx_quote_suppl_data)) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    if (quote.getHeader().teeType != constants::TEE_TYPE_TDX) {
        return status_error_to_quote3_error(STATUS_UNSUPPORTED_QUOTE_FORMAT);
    }
    struct servtd_tdx_quote_suppl_data *p_servtd_suppl_data =
        reinterpret_cast<struct servtd_tdx_quote_suppl_data *>(
            p_servtd_supplemental_data);

    // Hint: Always return sgx_report2_body_t(584 bytes) per design
    // For V4 quote return sgx_report2_body_t directly, for V5 quote return
    // report body w/o mr_servicetd & tee_tcb_svn2

    if (memcpy_s(reinterpret_cast<uint8_t *>(p_servtd_suppl_data),
                 sizeof(sgx_report2_body_t),
                 reinterpret_cast<const uint8_t *>(&(quote.getTdReport10())),
                 constants::TD_REPORT10_BYTE_LEN) != 0) {
        return SGX_QL_ERROR_UNEXPECTED;
    }

    if (memcpy_s(p_servtd_suppl_data->fmspc, FMSPC_SIZE, p_fmspc,
                 p_fmspc_size) != 0) {
        return SGX_QL_ERROR_UNEXPECTED;
    }
    // get platform TCB date and TCB level in TCB Info
    //
    auto tcb = getMatchingTcbLevel(tcb_info_obj, pckCert, quote);
    auto tdx_svn = tcb.getTdxTcbComponents();
    if (tdx_svn.size() == SGX_CPUSVN_SIZE) {
        for (size_t i = 0; i < SGX_CPUSVN_SIZE; i++) {
            p_servtd_suppl_data->tdx_tcb_components[i] = tdx_svn[i].getSvn();
        }
    }
    p_servtd_suppl_data->pce_svn = static_cast<uint16_t>(tcb.getPceSvn());
    auto sgx_svn = tcb.getSgxTcbComponents();
    if (sgx_svn.size() == SGX_CPUSVN_SIZE) {
        for (size_t i = 0; i < SGX_CPUSVN_SIZE; i++) {
            p_servtd_suppl_data->sgx_tcb_components[i] = sgx_svn[i].getSvn();
        }
    }

    p_servtd_suppl_data->tcb_date = tcb.getTcbDate();

    auto st = tcb.getStatus();
    size_t len = st.length();

    if (len > TCB_STATUS_LEN - 1)
        return SGX_QL_ERROR_UNEXPECTED;

    std::copy_n(st.c_str(), len, p_servtd_suppl_data->tcb_status);
    p_servtd_suppl_data->tcb_status[len] = '\0';

    // Get QE TCB date and TCB status
    struct tm qe_date = qe_tcb_info.getTcbDate();
    p_servtd_suppl_data->qe_tcb_date = ::mktime(&qe_date);
    if (p_servtd_suppl_data->qe_tcb_date == -1) {
        return SGX_QL_ERROR_UNEXPECTED;
    }

    auto qe_st = qe_tcb_info.getTcbStatus();
    const char* qe_status_str = tcbStatusToString(qe_st);
    size_t qe_status_len = strlen(qe_status_str);

    if (qe_status_len > TCB_STATUS_LEN - 1) {
        return SGX_QL_ERROR_UNEXPECTED;
    }

    std::copy_n(qe_status_str, qe_status_len, p_servtd_suppl_data->qe_tcb_status);

    p_servtd_suppl_data->qe_tcb_status[qe_status_len] = '\0';

    // Get Tdx Module major version
    p_servtd_suppl_data->tdx_module_major_ver = quote.getTeeTcbSvn()[1];
    uint8_t matchedTcbLevel = 0;
    auto ret = getTdxModuleTcblevel(tcb_info_obj, quote, matchedTcbLevel);
    // For the quote with TDX module major is 0, fill svn with 0
    if (ret == 0) {
        p_servtd_suppl_data->tdx_module_svn = matchedTcbLevel;
    }
    else {
        return SGX_QL_TDX_MODULE_MISMATCH;
    }
    auto qe_report = quote.getQeReport();
    p_servtd_suppl_data->misc_select = qe_report.miscSelect;
    auto misc_mask = enclaveIdentity->getMiscselectMask();
    if(misc_mask.size() == MISCSELECTMASK_LEN) {
        std::copy(misc_mask.begin(), misc_mask.end(), p_servtd_suppl_data->misc_select_mask);
    }
    if (memcpy_s(&(p_servtd_suppl_data->attributes),
                 sizeof(p_servtd_suppl_data->attributes),
                 qe_report.attributes.data(),
                 sizeof(qe_report.attributes)) != 0) {
        return SGX_QL_ERROR_UNEXPECTED;
    }

    auto attr_mask = enclaveIdentity->getAttributesMask();
    if(attr_mask.size() == ATTRIBUTESELECTMASK_LEN) {
        std::copy(attr_mask.begin(), attr_mask.end(), p_servtd_suppl_data->attributes_mask);
    }

    if (memcpy_s(p_servtd_suppl_data->mr_enclave.m,
                 sizeof(p_servtd_suppl_data->mr_enclave.m),
                 qe_report.mrEnclave.data(),
                 sizeof(qe_report.mrEnclave)) != 0) {
        return SGX_QL_ERROR_UNEXPECTED;
    }
    if (memcpy_s(p_servtd_suppl_data->mr_signer.m,
                 sizeof(p_servtd_suppl_data->mr_signer.m),
                 qe_report.mrSigner.data(), sizeof(qe_report.mrSigner)) != 0) {
        return SGX_QL_ERROR_UNEXPECTED;
    }
    p_servtd_suppl_data->isv_prod_id = qe_report.isvProdID;
    p_servtd_suppl_data->isv_svn =
        static_cast<uint16_t>(qe_tcb_info.getIsvsvn());
    *p_servtd_supplemental_data_size =
        sizeof(struct servtd_tdx_quote_suppl_data);
    return SGX_QL_SUCCESS;
}
#endif
/**
 * Setup supplemental data.
 * @param quote[IN] - Pointer to quote buffer.
 * @param chain[IN] - Pointer to CertificateChain object containing PCK Cert chain (for quote with cert type 5, this should be extracted from the quote).
 * @param tcb_info_obj[IN] - Pointer to TcbInfo object.
 * @param p_quote_collateral[IN] - Pointer to _sgx_ql_qve_collateral_t struct.
 * @param crls[IN] - X.509 certificate CRL chain.
 * @param earliest_issue_date[IN] - value of the earliest issue date of all collaterals used in quote verification.
 * @param latest_issue_date[IN] - value of the latest issue date of all collaterals used in quote verification.
 * @param earliest_expiration_date[IN] - value of the earliest expiration date of all collaterals used in quote verification.
 * @param qe_iden_earliest_issue_date[IN] - value of the earliest issue date of QE Identity used in quote verification.
 * @param qe_iden_latest_issue_date[IN] - value of the latest issue date of QE Identity used in quote verification.
 * @param qe_iden_earliest_expiration_date[IN] - value of the earliest expiration date of QE Identity used in quote verification.
 * @param p_supplemental_data[IN/OUT] - Pointer to a supplemental data buffer. Must be allocated by caller (untrusted code).

 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_TCBINFO_UNSUPPORTED_FORMAT
 *      - SGX_QL_PCK_CERT_CHAIN_ERROR
 *      - SGX_QL_ATT_KEY_CERT_DATA_INVALID
 *      - SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED
 *      - SGX_QL_ERROR_UNEXPECTED
 **/
static quote3_error_t qve_set_quote_supplemental_data(const Quote &quote,
                                            const CertificateChain *chain,
                                            const json::TcbInfo *tcb_info_obj,
                                            const struct _sgx_ql_qve_collateral_t *p_quote_collateral,
                                            const char *crls[],
                                            time_t earliest_issue_date,
                                            time_t latest_issue_date,
                                            time_t earliest_expiration_date,
                                            time_t qe_iden_earliest_issue_date,
                                            time_t qe_iden_latest_issue_date,
                                            time_t qe_iden_earliest_expiration_date,
                                            uint8_t *p_supplemental_data) {
    if (chain == NULL ||
        tcb_info_obj == NULL ||
        p_quote_collateral == NULL ||
        crls == NULL ||
        crls[0] == NULL ||
        crls[1] == NULL ||
        p_supplemental_data == NULL) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    quote3_error_t ret = SGX_QL_ERROR_INVALID_PARAMETER;
    int version = 0;
    uint32_t supp_ver = 0;
    sgx_ql_qv_supplemental_t* supplemental_data = reinterpret_cast<sgx_ql_qv_supplemental_t*> (p_supplemental_data);

    // the input supplemental data version should never be 0
    if (supplemental_data->version == 0) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    else {
        // clear the memory
        supp_ver = supplemental_data->version;
        memset_s(supplemental_data, sizeof(sgx_ql_qv_supplemental_t), 0, sizeof(sgx_ql_qv_supplemental_t));
    }

    //Set default values
    supplemental_data->version = supp_ver;
    supplemental_data->dynamic_platform = PCK_FLAG_UNDEFINED;
    supplemental_data->cached_keys = PCK_FLAG_UNDEFINED;
    supplemental_data->smt_enabled = PCK_FLAG_UNDEFINED;

    time_t qe_identity_date = 0;
    //Start collecting supplemental data
    //
    do {
        EnclaveIdentityParser parser;
        EnclaveIdentityV2* qe_identity_v2 = NULL;

        //some of the required supplemental data exist only on V2 & V3 TCBInfo, validate TCBInfo version.
        //
        version = tcb_info_obj->getVersion();
        if (version != 2 && version != 3) {
            ret = SGX_QL_TCBINFO_UNSUPPORTED_FORMAT;
            break;
        }

        //parse qe_identity and validate its version
        //
        std::unique_ptr<EnclaveIdentityV2> qe_identity_obj;
        try
        {
            qe_identity_obj = parser.parse(p_quote_collateral->qe_identity);
        }
        catch (...)
        {
            ret = SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT;
            break;
        }
        if (qe_identity_obj == nullptr) {
            ret = SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT;
            break;
        }

        version = qe_identity_obj->getVersion();
        if (version == 2 || version == 3) {
            qe_identity_v2 = dynamic_cast<EnclaveIdentityV2*>(qe_identity_obj.get());
        }
        else {
            ret = SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT;
            break;
        }

        Status qe_identity_status = STATUS_UNSUPPORTED_QE_IDENTITY_FORMAT;
        qe_identity_status = qe_identity_v2->getStatus();
        supplemental_data->qe_iden_status = status_error_to_ql_qve_result(qe_identity_status);

        pckparser::CrlStore root_ca_crl;
        if (root_ca_crl.parse(crls[0]) != true) {
            ret = SGX_QL_ERROR_INVALID_PARAMETER;
            break;
        }

        pckparser::CrlStore pck_crl;
        if (pck_crl.parse(crls[1]) != true) {
            ret = SGX_QL_ERROR_INVALID_PARAMETER;
            break;
        }

        //get certificates objects from chain
        //
        auto chain_root_ca_cert = chain->getRootCert();
        auto chain_pck_cert = chain->getPckCert();

        //compare to nullptr (C++ way of comparing pointers to NULL), otherwise gcc will report a compilation warning
        //
        if (chain_root_ca_cert == nullptr || chain_pck_cert == nullptr) {
            ret = SGX_QL_PCK_CERT_CHAIN_ERROR;
            break;
        }
        auto pck_cert_tcb = chain_pck_cert->getTcb();

        //version should be set in wrapper functions
        //
        supplemental_data->earliest_issue_date = earliest_issue_date;
        supplemental_data->latest_issue_date = latest_issue_date;
        supplemental_data->earliest_expiration_date = earliest_expiration_date;
        supplemental_data->qe_iden_earliest_issue_date = qe_iden_earliest_issue_date;
        supplemental_data->qe_iden_latest_issue_date = qe_iden_latest_issue_date;
        supplemental_data->qe_iden_earliest_expiration_date = qe_iden_earliest_expiration_date;
        supplemental_data->tcb_level_date_tag = 0;
        supplemental_data->qe_iden_tcb_level_date_tag = 0;

        //get matching QE identity TCB level
        //
        try {
            //get matching QE identity TCB level
            //
            auto qe_identity_tcb_levels = qe_identity_v2->getTcbLevels();

            //make sure QE identity has at least one TCBLevel
            //
            if (qe_identity_tcb_levels.empty()) {
                ret = SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT;
                break;
            }
            for (const auto & tcbLevel : qe_identity_tcb_levels) {
                if (tcbLevel.getIsvsvn() <= quote.getQeReport().isvSvn) {
                    tm matching_qe_identity_tcb_date = tcbLevel.getTcbDate();
                    qe_identity_date = intel::sgx::dcap::mktime(&matching_qe_identity_tcb_date);
                    break;
                }
            }
            //get TCB date of TCB level in TCB Info
            //
            auto tcb = getMatchingTcbLevel(tcb_info_obj, *chain_pck_cert, quote);
            auto matching_tcb_info_tcb_date = tcb.getTcbDate();

            auto sa_list = tcb.getAdvisoryIDs();

            //set SA list when version >= 3.1
            //
            if (supplemental_data->major_version >= SUPPLEMENTAL_DATA_VERSION &&
                supplemental_data->minor_version >= SUPPLEMENTAL_V3_LATEST_MINOR_VERSION) {

                if (!sa_list.empty()) {
                    uint32_t sa_size = 0;
                    const char comma = ',';
                    const char terminator = '\0';
                    char *p_sa = supplemental_data->sa_list;

                    // SA quantity should not larger than MAX_SA_NUMBER_PER_TCB for each TCB
                    if (sa_list.size() > MAX_SA_NUMBER_PER_TCB) {
                        ret = SGX_QL_ERROR_UNEXPECTED;
                        break;
                    }

                    for (std::string sa : sa_list) {
                        // each SA length should not larger than 20
                        if (sa.size() > MAX_SA_SIZE) {
                            ret = SGX_QL_ERROR_UNEXPECTED;
                            break;
                        }

                        sa_size += (uint32_t)sa.length() + 1;

                        // sanity check
                        if (sa_size > MAX_SA_LIST_SIZE) {
                            ret = SGX_QL_ERROR_UNEXPECTED;
                            break;
                        }
                        memcpy_s(p_sa, sa.length(), sa.c_str(), sa.length());
                        // add comma for each sa
                        if (memcpy_s(p_sa + sa.length(), 1, &comma, 1) != 0) {
                            ret = SGX_QL_ERROR_UNEXPECTED;
                            break;
                        }
                        p_sa += sa.length() + 1;
                    }

                    // add null terminator in the end
                    memset_s(p_sa - 1, 1, terminator, 1);
                }
            }

            //sanity check for TCB dates
            //
            if (qe_identity_date < 0 || matching_tcb_info_tcb_date < 0) {
                ret = SGX_QL_ERROR_UNEXPECTED;
                break;
            }
            //QE identity TCB level date
            supplemental_data->qe_iden_tcb_level_date_tag = qe_identity_date;
            //TCB info TCB level date
            supplemental_data->tcb_level_date_tag = matching_tcb_info_tcb_date;

        }

        catch(...) {
            ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }

        //make sure that long int value returned in getCrlNum doesn't overflow
        //
        long tmp_crl_num = pck_crl.getCrlNum();
        if (tmp_crl_num > UINT32_MAX || tmp_crl_num < 0) {
            ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }
        supplemental_data->pck_crl_num = (uint32_t)tmp_crl_num;

        //make sure that long int value returned in getCrlNum doesn't overflow
        //
        tmp_crl_num = root_ca_crl.getCrlNum();
        if (tmp_crl_num > UINT32_MAX || tmp_crl_num < 0) {
            ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }

        supplemental_data->root_ca_crl_num = (uint32_t)tmp_crl_num;
        supplemental_data->qe_iden_tcb_eval_ref_num = qe_identity_v2->getTcbEvaluationDataNumber();

        if (qe_identity_v2->getTcbEvaluationDataNumber() <= tcb_info_obj->getTcbEvaluationDataNumber()) {
            supplemental_data->tcb_eval_ref_num = qe_identity_v2->getTcbEvaluationDataNumber();
        }
        else {
            supplemental_data->tcb_eval_ref_num = tcb_info_obj->getTcbEvaluationDataNumber();
        }
        // generates SHA-384 hash of CERT chain root CA's public key
        //
        const uint8_t* root_pub_key = chain_root_ca_cert->getPubKey().data();
        size_t root_pub_key_size = chain_root_ca_cert->getPubKey().size();
        if (SHA384((const unsigned char *)root_pub_key, root_pub_key_size, supplemental_data->root_key_id) == NULL) {
            ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }

        //get PPID value from PCK Cert
        //
        auto pck_cert_ppid = chain_pck_cert->getPpid();

        //validate PPID buffer size
        //
        if (sizeof(sgx_key_128bit_t) != pck_cert_ppid.size()) {
            ret = SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT;
            break;
        }

        //copy PPID value into supplemental data buffer
        //
        if (memcpy_s(supplemental_data->pck_ppid, sizeof(sgx_key_128bit_t),
            pck_cert_ppid.data(), pck_cert_ppid.size()) != 0) {
            ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }

        //get CpuSvn value from PCK Cert
        //
        auto pck_cert_tcb_cpusvn = pck_cert_tcb.getCpuSvn();

        //validate CpuSvn buffer size
        //
        if (sizeof(supplemental_data->tcb_cpusvn.svn) != pck_cert_tcb_cpusvn.size()) {
            ret = SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT;
            break;
        }

        //copy CpuSvn value into supplemental data buffer
        //
        if (memcpy_s(supplemental_data->tcb_cpusvn.svn, sizeof(supplemental_data->tcb_cpusvn.svn),
            pck_cert_tcb_cpusvn.data(), pck_cert_tcb_cpusvn.size()) != 0) {
            ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }

        //make sure unsigned int value returned in getPceSvn matches uint16_t size, prevent overflow
        //
        unsigned int tmp_pce_svn = pck_cert_tcb.getPceSvn();
        if (tmp_pce_svn > UINT16_MAX) {
            ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }

        supplemental_data->tcb_pce_isvsvn = (sgx_isv_svn_t)pck_cert_tcb.getPceSvn();
        supplemental_data->pce_id = *(chain_pck_cert->getPceId().data());

        x509::SgxType tmp_sgx_type = chain_pck_cert->getSgxType();
        if (tmp_sgx_type > UINT8_MAX) {
            ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }

        supplemental_data->sgx_type = (uint8_t)tmp_sgx_type;


        //try to get flags for multi-package platforms
        //
        if (supplemental_data->sgx_type == x509::Scalable || supplemental_data->sgx_type == x509::ScalableWithIntegrity) {
            try {
                auto pck_cert = chain->getTopmostCert();
                auto platform_cert = x509::PlatformPckCertificate(*pck_cert);


                //get platform instance ID from PCK Cert
                //
                auto platform_instance_id = platform_cert.getPlatformInstanceId();

                //copy platform instance ID value into supplemental data buffer
                //
                if (memcpy_s(supplemental_data->platform_instance_id, 16,
                    platform_instance_id.data(), platform_instance_id.size()) != 0) {
                    ret = SGX_QL_ERROR_UNEXPECTED;
                    break;
                }

                //get configuration data from PCK Cert
                //
                auto sgx_configuration = platform_cert.getConfiguration();

                if (sgx_configuration.isDynamicPlatform())
                    supplemental_data->dynamic_platform = PCK_FLAG_TRUE;

                if (sgx_configuration.isCachedKeys())
                    supplemental_data->cached_keys = PCK_FLAG_TRUE;

                if (sgx_configuration.isSmtEnabled())
                    supplemental_data->smt_enabled = PCK_FLAG_TRUE;
                else
                    supplemental_data->smt_enabled = PCK_FLAG_FALSE;
            }
            catch (...) {
                ret = SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT;
                break;
            }
        }

        ret = SGX_QL_SUCCESS;
    } while (0);

    if (ret != SGX_QL_SUCCESS) {
        memset_s(supplemental_data, sizeof(*supplemental_data), 0, sizeof(*supplemental_data));
        supplemental_data->dynamic_platform = PCK_FLAG_UNDEFINED;
        supplemental_data->cached_keys = PCK_FLAG_UNDEFINED;
        supplemental_data->smt_enabled = PCK_FLAG_UNDEFINED;
    }

    return ret;
}


#ifndef SERVTD_ATTEST
/**
 * Get supplemental data required size.
 * @param p_data_size[OUT] - Pointer to hold the size of the buffer in bytes required to contain all of the supplemental data.
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 **/
quote3_error_t sgx_qve_get_quote_supplemental_data_size(
    uint32_t *p_data_size) {
    if (SGXSSL_init())
        return SGX_QL_SERVICE_UNAVAILABLE;

    if (p_data_size == NULL ||
        (sgx_is_within_enclave(p_data_size, sizeof(*p_data_size)) == 0)) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    *p_data_size = sizeof(sgx_ql_qv_supplemental_t);
    return SGX_QL_SUCCESS;
}


/**
 * Get supplemental data version.
 * @param p_version[OUT] - Pointer to hold the version of the supplemental data.
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 **/
quote3_error_t sgx_qve_get_quote_supplemental_data_version(
    uint32_t *p_version) {
    if (SGXSSL_init())
        return SGX_QL_SERVICE_UNAVAILABLE;

    if (p_version == NULL ||
        (sgx_is_within_enclave(p_version, sizeof(*p_version)) == 0)) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    supp_ver_t tmp;
    tmp.major_version = SUPPLEMENTAL_DATA_VERSION;
    tmp.minor_version = SUPPLEMENTAL_V3_LATEST_MINOR_VERSION;

    *p_version = tmp.version;
    return SGX_QL_SUCCESS;
}
#endif


#ifdef SGX_TRUSTED
#ifndef SERVTD_ATTEST
/**
 * Generate enclave report with:
 * SHA256([nonce || quote || expiration_check_date || expiration_status || verification_result || supplemental_data] || 32 - 0x00s)
 *
 * @param p_quote[IN] - Pointer to an SGX Quote.
 * @param quote_size[IN] - Size of the buffer pointed to by p_quote (in bytes).
 * @param expiration_check_date[IN] - This is the date that the QvE will use to determine if any of the inputted collateral have expired.
 * @param p_collateral_expiration_status[IN] - Address of the outputted expiration status.
 * @param p_quote_verification_result[IN] - Address of the outputted quote verification result.
 * @param p_qve_report_info[IN/OUT] - QvE will generate a report using the target_info provided in the sgx_ql_qe_report_info_t structure, and store it in qe_report.
 * @param supplemental_data_size[IN] - Size of the buffer pointed to by p_supplemental_data (in bytes).
 * @param p_supplemental_data[IN] - Buffer containing supplemental data.
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_UNABLE_TO_GENERATE_REPORT
 **/
static quote3_error_t sgx_qve_generate_report(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data)
{

    //validate parameters
    //
    if (p_quote == NULL ||
        quote_size < QUOTE_MIN_SIZE ||
        p_collateral_expiration_status == NULL ||
        p_qve_report_info == NULL ||
        expiration_check_date == 0 ||
        p_quote_verification_result == NULL ||
        CHECK_OPT_PARAMS(p_supplemental_data, supplemental_data_size)) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t sgx_status = SGX_ERROR_UNEXPECTED;
    quote3_error_t ret = SGX_QL_UNABLE_TO_GENERATE_REPORT;
    sgx_sha_state_handle_t sha_handle = NULL;
    sgx_report_data_t report_data = { 0 };


    do {
        //Create QvE report
        //
        //report_data = SHA256([nonce || quote || expiration_check_date || expiration_status || verification_result || supplemental_data]) || 32 - 0x00s
        //
        sgx_status = sgx_sha256_init(&sha_handle);
        SGX_ERR_BREAK(sgx_status);

        //nonce
        //
        sgx_status = sgx_sha256_update((p_qve_report_info->nonce.rand), sizeof(p_qve_report_info->nonce.rand), sha_handle);
        SGX_ERR_BREAK(sgx_status);

        //quote
        //
        sgx_status = sgx_sha256_update(p_quote, quote_size, sha_handle);
        SGX_ERR_BREAK(sgx_status);

        //expiration_check_date
        //
        sgx_status = sgx_sha256_update((const uint8_t*)&expiration_check_date, sizeof(expiration_check_date), sha_handle);
        SGX_ERR_BREAK(sgx_status);

        //p_collateral_expiration_status
        //
        sgx_status = sgx_sha256_update((const uint8_t*)p_collateral_expiration_status, sizeof(*p_collateral_expiration_status), sha_handle);
        SGX_ERR_BREAK(sgx_status);


        //p_quote_verification_result
        //
        sgx_status = sgx_sha256_update((uint8_t *)const_cast<sgx_ql_qv_result_t *>(p_quote_verification_result), sizeof(*p_quote_verification_result), sha_handle);
        SGX_ERR_BREAK(sgx_status);


        //p_supplemental_data
        //
        if (p_supplemental_data) {
            sgx_status = sgx_sha256_update(p_supplemental_data, supplemental_data_size, sha_handle);
            SGX_ERR_BREAK(sgx_status);
        }

        //get the hashed report_data
        //
        sgx_status = sgx_sha256_get_hash(sha_handle, reinterpret_cast<sgx_sha256_hash_t *>(&report_data));
        SGX_ERR_BREAK(sgx_status);

        //create QVE report with report_data embedded
        //
        sgx_status = sgx_create_report(&(p_qve_report_info->app_enclave_target_info), &report_data, &(p_qve_report_info->qe_report));
        SGX_ERR_BREAK(sgx_status);

        ret = SGX_QL_SUCCESS;
    } while (0);

    //clear data in report_data (it's a local variable, no need for free).
    //
    memset_s(&report_data, sizeof(sgx_report_data_t), 0, sizeof(sgx_report_data_t));
    if (sha_handle != NULL) {
        sgx_sha256_close(sha_handle);
    }
    return ret;
}
#endif //SERVTD_ATTEST
#endif //SGX_TRUSTED

#define IS_IN_ENCLAVE_POINTER(p, size) (p && (strnlen(p, size) == size - 1) && sgx_is_within_enclave(p, size))

//CRL may DER encoding, so don't use to strnlen to check the length
static bool is_collateral_deep_copied(const struct _sgx_ql_qve_collateral_t *p_quote_collateral) {
    if (IS_IN_ENCLAVE_POINTER(p_quote_collateral->pck_crl_issuer_chain, p_quote_collateral->pck_crl_issuer_chain_size) &&
        IS_IN_ENCLAVE_POINTER(p_quote_collateral->tcb_info_issuer_chain, p_quote_collateral->tcb_info_issuer_chain_size) &&
        IS_IN_ENCLAVE_POINTER(p_quote_collateral->tcb_info, p_quote_collateral->tcb_info_size) &&
        IS_IN_ENCLAVE_POINTER(p_quote_collateral->qe_identity_issuer_chain, p_quote_collateral->qe_identity_issuer_chain_size) &&
        IS_IN_ENCLAVE_POINTER(p_quote_collateral->qe_identity, p_quote_collateral->qe_identity_size) &&
        sgx_is_within_enclave(p_quote_collateral->root_ca_crl, p_quote_collateral->root_ca_crl_size) &&
        sgx_is_within_enclave(p_quote_collateral->pck_crl, p_quote_collateral->pck_crl_size)) {
        return true;
    }
    else {
        return false;
    }
}
/**
 * Perform quote verification.
 *
 * @param p_quote[IN] - Pointer to an SGX Quote.
 * @param quote_size[IN] - Size of the buffer pointed to by p_quote (in bytes).
 * @param p_quote_collateral[IN] - This is a pointer to the Quote Certification Collateral provided by the caller.
 * @param expiration_check_date[IN] - This is the date that the QvE will use to determine if any of the inputted collateral have expired.
 * @param p_collateral_expiration_status[OUT] - Address of the outputted expiration status.  This input must not be NULL.
 * @param p_quote_verification_result[OUT] - Address of the outputted quote verification result.
 * @param p_qve_report_info[IN/OUT] - This parameter is optional.  If not NULL, the QvE will generate a report with using the target_info provided in the sgx_ql_qe_report_info_t structure.
 * @param supplemental_data_size[IN] - Size of the buffer pointed to by p_supplemental_data (in bytes).
 * @param p_supplemental_data[IN/OUT] - The parameter is optional.  If it is NULL, supplemental_data_size must be 0.
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_QUOTE_FORMAT_UNSUPPORTED
 *      - SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED
 *      - SGX_QL_UNABLE_TO_GENERATE_REPORT
 *      - SGX_QL_CRL_UNSUPPORTED_FORMAT
 *      - SGX_QL_ERROR_UNEXPECTED
 **/
quote3_error_t sgx_qve_verify_quote(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const struct _sgx_ql_qve_collateral_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data
#ifdef SERVTD_ATTEST
    ,const uint8_t* root_pub_key,
    uint32_t root_pub_key_size,
    uint8_t *p_td_report_body,
	uint32_t *p_td_report_body_size) {
#else
    ) {
#endif

    if (SGXSSL_init())
        return SGX_QL_SERVICE_UNAVAILABLE;

    //validate result parameter pointers and set default values
    //in case of any invalid result parameter, set outputs_set = 0 and then return invalid (after setting
    //default values of valid result parameters)
    //
    bool outputs_set = 1;
    if (p_collateral_expiration_status &&
        sgx_is_within_enclave(p_collateral_expiration_status, sizeof(*p_collateral_expiration_status))) {
        *p_collateral_expiration_status = 1;
    }
    else {
        outputs_set = 0;
    }

    if (p_quote_verification_result &&
        sgx_is_within_enclave(p_quote_verification_result, sizeof(*p_quote_verification_result))) {
        *p_quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    }
    else {
        outputs_set = 0;
    }

    //check if supplemental data required, and validate its size matches sgx_ql_qv_supplemental_t struct. if so, set it to 0 before
    //
    if (p_supplemental_data) {
        if (supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t) &&
            sgx_is_within_enclave(p_supplemental_data, supplemental_data_size)) {
        }
        else {
            outputs_set = 0;
        }
    }
    if (outputs_set == 0) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
#ifdef SERVTD_ATTEST
    if (p_td_report_body == NULL || root_pub_key == NULL || p_td_report_body_size == NULL || (*p_td_report_body_size) < sizeof(servtd_tdx_quote_suppl_data) || root_pub_key_size < 0)  {
           return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    unsigned char fmspc_from_quote[FMSPC_SIZE] = { 0 };
    unsigned char ca_from_quote[CA_SIZE] = { 0 };
    bool collateral_flag = false;

    if (SGX_QL_SUCCESS != get_fmspc_ca_from_quote(p_quote, quote_size, fmspc_from_quote, FMSPC_SIZE, ca_from_quote, CA_SIZE)) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    if(p_quote_collateral == NULL) {
        tdx_verify_error_t coll_ret = tdx_att_get_collateral((const uint8_t *) fmspc_from_quote, FMSPC_SIZE, (const char *)ca_from_quote, (tdx_ql_qve_collateral_t**)&p_quote_collateral);
        if(coll_ret != TDX_VERIFY_SUCCESS)
        {
            return SGX_QL_UNABLE_TO_GET_COLLATERAL;
        }

        collateral_flag = true;

    }

#endif

    //validate parameters
    //
    if (p_quote == NULL ||
        quote_size < QUOTE_MIN_SIZE ||
        !sgx_is_within_enclave(p_quote, quote_size) ||
        p_quote_collateral == NULL ||
        !sgx_is_within_enclave(p_quote_collateral, sizeof(*p_quote_collateral)) ||
        !is_collateral_deep_copied(p_quote_collateral) ||
        expiration_check_date <= 0 ||
        (p_qve_report_info != NULL && !sgx_is_within_enclave(p_qve_report_info, sizeof(*p_qve_report_info))) ||
        (p_supplemental_data == NULL && supplemental_data_size != 0)) {

#ifdef SERVTD_ATTEST
        if(p_quote_collateral != NULL && collateral_flag) {
			tdx_att_free_collateral((tdx_ql_qve_collateral_t*)p_quote_collateral);
			p_quote_collateral = NULL;
	    }
#endif
        //one or more invalid parameters
        //
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    //validate collateral version
    //
    if (p_quote_collateral->version != QVE_COLLATERAL_VERSION1 &&
         p_quote_collateral->version != QVE_COLLATERAL_VERSION3 &&
         p_quote_collateral->version != QVE_COLLATERAL_VERSOIN31 &&
         p_quote_collateral->version != QVE_COLLATERAL_VERSION4) {

#ifdef SERVTD_ATTEST
        if(p_quote_collateral != NULL && collateral_flag) {
			tdx_att_free_collateral((tdx_ql_qve_collateral_t*)p_quote_collateral);
			p_quote_collateral = NULL;
	    }
#endif

        return SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED;
    }

    //define local variables
    //
    time_t earliest_expiration_date = 0;
    time_t earliest_issue_date = 0;
    time_t latest_expiration_date = 0;
    time_t latest_issue_date = 0;
    time_t qe_iden_earliest_issue_date = 0;
    time_t qe_iden_latest_issue_date = 0;
    time_t qe_iden_earliest_expiration_date = 0;
    Status collateral_verification_res = STATUS_SGX_ENCLAVE_REPORT_MRSIGNER_MISMATCH;
    quote3_error_t ret = SGX_QL_ERROR_INVALID_PARAMETER;
    uint32_t pck_cert_chain_size = 0;
    uint8_t *p_pck_cert_chain = NULL;
    time_t set_time = 0;
    CertificateChain chain;
    json::TcbInfo tcb_info_obj;
    std::vector<uint8_t> hardcode_root_pub_key;
    std::string root_cert_str;
    std::string root_crl;
    std::string pck_crl;

    //start the verification operation
    //
    do {
        //setup expiration check date to verify against (trusted time)
        //
        set_time = intel::sgx::dcap::getCurrentTime(&expiration_check_date);

        // defense-in-depth to make sure current time is set as expected.
        //
        if (set_time != expiration_check_date) {
            ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }

        //extract PCK Cert chain from the given quote
        //
        ret = extract_chain_from_quote(p_quote, quote_size, &pck_cert_chain_size, &p_pck_cert_chain);
        if (ret != SGX_QL_SUCCESS || !p_pck_cert_chain) {
            break;
        }

        try
        {
            //parse tcbInfo JSON string into TcbInfo object
            //
            tcb_info_obj = json::TcbInfo::parse(p_quote_collateral->tcb_info);
        }
        catch (...)
        {
            //unable to parse tcbInfo JSON, return an error
            //
            ret = status_error_to_quote3_error(STATUS_SGX_TCB_INFO_INVALID);
            break;
        }

        //parse PCK Cert chain into CertificateChain object. return error in case of failure
        //
        if (chain.parse((reinterpret_cast<const char*>(p_pck_cert_chain))) != STATUS_OK ||
            chain.length() != EXPECTED_CERTIFICATE_COUNT_IN_PCK_CHAIN) {
            ret = SGX_QL_PCK_CERT_CHAIN_ERROR;
            break;
        }

        //if user provide DER encoding Root CA CRL, try to convert it to hex encoding
        //
        if (!check_pem_crl(p_quote_collateral->root_ca_crl, p_quote_collateral->root_ca_crl_size)) {
            if (!check_hex_crl(p_quote_collateral->root_ca_crl, p_quote_collateral->root_ca_crl_size)) {

                root_crl = byte_to_hexstring(reinterpret_cast<const uint8_t*>(p_quote_collateral->root_ca_crl), p_quote_collateral->root_ca_crl_size, false);

                if (root_crl.empty())
                    break;
            }
        }

        //if user provide DER encoding PCK CRL, try to convert it to hex encoding
        //
        if (!check_pem_crl(p_quote_collateral->pck_crl, p_quote_collateral->pck_crl_size)) {
            if (!check_hex_crl(p_quote_collateral->pck_crl, p_quote_collateral->pck_crl_size)) {

                pck_crl = byte_to_hexstring(reinterpret_cast<const uint8_t*>(p_quote_collateral->pck_crl), p_quote_collateral->pck_crl_size, false);

                if (pck_crl.empty())
                    break;
            }
        }

        //create CRLs combined array
        //
        std::array<const char*, 2> crls;

        if (!root_crl.empty())
            crls[0] = root_crl.c_str();
        else
            crls[0] = p_quote_collateral->root_ca_crl;

        if (!pck_crl.empty())
            crls[1] = pck_crl.c_str();
        else
            crls[1] = p_quote_collateral->pck_crl;


        //extract root CA from PCK cert chain in quote
        auto root_cert = chain.getRootCert();
        x509::Certificate root_cert_x509;

        //compare to nullptr (C++ way of comparing pointers to NULL), otherwise gcc will report a compilation warning
        //
        if (root_cert == nullptr) {
            ret = SGX_QL_PCK_CERT_CHAIN_ERROR;
            break;
        }

        try {
            root_cert_x509 = x509::Certificate(*root_cert);
        }
        catch (...) {
            ret = SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT;
            break;
        }

        auto root_pub_key_from_cert = root_cert_x509.getPubKey();
#ifdef SERVTD_ATTEST
        std::copy(root_pub_key, root_pub_key + root_pub_key_size, std::back_inserter(hardcode_root_pub_key));
#else
        std::copy(std::begin(INTEL_ROOT_PUB_KEY), std::end(INTEL_ROOT_PUB_KEY), std::back_inserter(hardcode_root_pub_key));
#endif

        //check root public key
        //
        if (hardcode_root_pub_key != root_pub_key_from_cert) {
            ret = SGX_QL_PCK_CERT_CHAIN_ERROR;
            break;
        }

        //convert root cert to string
        //
        root_cert_str = root_cert_x509.getPem();
        if (root_cert_str.empty()) {
            ret = SGX_QL_PCK_CERT_CHAIN_ERROR;
            break;
        }

        ret = qve_get_collateral_dates(&chain, &tcb_info_obj,
            p_quote_collateral, crls.data(),
            &earliest_issue_date, &earliest_expiration_date,
            &latest_issue_date, &latest_expiration_date,
            &qe_iden_earliest_issue_date,
            &qe_iden_latest_issue_date,
            &qe_iden_earliest_expiration_date);
        if (ret != SGX_QL_SUCCESS) {
            break;
        }

	//set the expiration_check_data to pass validation, since in migration, we don't care time
#ifdef SERVTD_ATTEST
        time_t * _p_expiration_check_date = const_cast<time_t *>(&expiration_check_date);
	    *_p_expiration_check_date = (latest_issue_date + earliest_expiration_date) / 2;
        set_time = *_p_expiration_check_date;
#endif
        //update collateral expiration status
        //
        if (earliest_expiration_date <= expiration_check_date) {
            *p_collateral_expiration_status = 1;
        }
        else {
            *p_collateral_expiration_status = 0;
        }

        //parse and verify PCK certificate chain
        //
        collateral_verification_res = sgxAttestationVerifyPCKCertificate((const char*)p_pck_cert_chain, crls.data(), root_cert_str.c_str(), &expiration_check_date);
        if (collateral_verification_res != STATUS_OK) {
            if (is_expiration_error(collateral_verification_res)) {
                *p_collateral_expiration_status = 1;
            }
            else {
                ret = status_error_to_quote3_error(collateral_verification_res);
                break;
            }
        }

        //parse and verify TCB info
        //
        collateral_verification_res = sgxAttestationVerifyTCBInfo(p_quote_collateral->tcb_info, p_quote_collateral->tcb_info_issuer_chain, crls[0], root_cert_str.c_str(), &expiration_check_date);
        if (collateral_verification_res != STATUS_OK) {
            if (is_expiration_error(collateral_verification_res)) {
                *p_collateral_expiration_status = 1;
            }
            else {
                ret = status_error_to_quote3_error(collateral_verification_res);
                break;
            }
        }

        //parse and verify QE identity
        //
        collateral_verification_res = sgxAttestationVerifyEnclaveIdentity(p_quote_collateral->qe_identity, p_quote_collateral->qe_identity_issuer_chain, crls[0], root_cert_str.c_str(), &expiration_check_date);
        if (collateral_verification_res != STATUS_OK) {
            if (is_expiration_error(collateral_verification_res)) {
                *p_collateral_expiration_status = 1;
            }
            else {
                ret = status_error_to_quote3_error(collateral_verification_res);
                break;
            }
        }

        //parse and verify the quote, update verification results
        //
        collateral_verification_res = sgxAttestationVerifyQuote(p_quote, quote_size, chain.getPckCert()->getPem().c_str(), crls[1], p_quote_collateral->tcb_info, p_quote_collateral->qe_identity);
        *p_quote_verification_result = status_error_to_ql_qve_result(collateral_verification_res);

        if (is_nonterminal_error(collateral_verification_res)) {
            ret = SGX_QL_SUCCESS;
        }
        else {
            ret = status_error_to_quote3_error(collateral_verification_res);
        }

        // collect supplemental data if required, only if verification completed with non-terminal status
        //
        if (ret == SGX_QL_SUCCESS)
        {
            // We totaly trust user on this, it should be explicitly and clearly
            // mentioned in doc, is there any max quote len other than numeric_limit<uint32_t>::max() ?
            const std::vector<uint8_t> vecQuote(p_quote, std::next(p_quote, quote_size));

            Quote quote;
            if (!quote.parse(vecQuote))
            {
                ret = status_error_to_quote3_error(STATUS_UNSUPPORTED_QUOTE_FORMAT);
            }
            if (p_supplemental_data)
            {
                ret = qve_set_quote_supplemental_data(quote,
                                                      &chain,
                                                      &tcb_info_obj,
                                                      p_quote_collateral,
                                                      crls.data(),
                                                      earliest_issue_date,
                                                      latest_issue_date,
                                                      earliest_expiration_date,
                                                      qe_iden_earliest_issue_date,
                                                      qe_iden_latest_issue_date,
                                                      qe_iden_earliest_expiration_date,
                                                      p_supplemental_data);
                if (ret != SGX_QL_SUCCESS)
                {
                    break;
                }
            }
#ifdef SERVTD_ATTEST
            memset(p_td_report_body, 0, *p_td_report_body_size);
            intel::sgx::dcap::EnclaveIdentityParser parser;
            std::unique_ptr<EnclaveIdentityV2> enclaveIdentity;
            try
            {
                enclaveIdentity = parser.parse(p_quote_collateral->qe_identity);
                // Get the TCB level matching the ISVSVN in the quote.
                auto qe_tcb = getMatchingQETcbLevel(enclaveIdentity, quote);

                auto chain_pck_cert = chain.getPckCert();
                auto p_pckCert = chain_pck_cert.get();
                ret = servtd_set_quote_supplemental_data(
                    quote, *p_pckCert, &tcb_info_obj, fmspc_from_quote,
                    FMSPC_SIZE, qe_tcb, enclaveIdentity, p_td_report_body,
                    p_td_report_body_size);
                if (ret != SGX_QL_SUCCESS)
                {
                    memset(p_td_report_body, 0, *p_td_report_body_size);
                    break;
                }
            }
            catch (const std::exception &e)
            {
                ret = SGX_QL_ERROR_UNEXPECTED;
                break;
            }
#endif
        }

    } while (0);


#ifdef SGX_TRUSTED

    //defense-in-depth: validate that input current_time still returned by getCurrentTime
    //
    if (ret == SGX_QL_SUCCESS && set_time != getCurrentTime(&expiration_check_date)) {
        ret = SGX_QL_ERROR_UNEXPECTED;
    }

    //check if report is required
    //
#ifndef SERVTD_ATTEST
    if (p_qve_report_info != NULL && ret == SGX_QL_SUCCESS) {

        quote3_error_t generate_report_ret = SGX_QL_ERROR_INVALID_PARAMETER;

        //generate a report with the verification result and input collaterals
        //
        generate_report_ret = sgx_qve_generate_report(
            p_quote,
            quote_size,
            expiration_check_date,
            p_collateral_expiration_status,
            p_quote_verification_result,
            p_qve_report_info,
            supplemental_data_size,
            p_supplemental_data);
        if (generate_report_ret != SGX_QL_SUCCESS) {
            ret = generate_report_ret;
            memset_s(&(p_qve_report_info->qe_report), sizeof(p_qve_report_info->qe_report), 0, sizeof(p_qve_report_info->qe_report));
        }
    }
#else
	if(p_quote_collateral != NULL && collateral_flag) {
			tdx_att_free_collateral((tdx_ql_qve_collateral_t*)p_quote_collateral);
			p_quote_collateral = NULL;
	}
#endif // SERVTD_ATTEST
 #endif //SGX_TRUSTED

    //clear and free allocated memory
    //
    if (p_pck_cert_chain) {
        CLEAR_FREE_MEM(p_pck_cert_chain, pck_cert_chain_size);
    }

    //if any check or operation failed (e.g. generating report, or supplemental data)
    //set p_quote_verification_result to SGX_QL_QV_RESULT_UNSPECIFIED
    //
    if (ret != SGX_QL_SUCCESS) {
        *p_quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    }

    return ret;
}

#ifdef SERVTD_ATTEST
extern "C" EXPORT_API
uint8_t do_verify_quote_integrity(
		const uint8_t *p_quote,
		uint32_t quote_size,
		const uint8_t * root_pub_key,
		uint32_t root_pub_key_size,
        const tdx_ql_qv_collateral_t *p_quote_collateral,
		uint8_t *p_td_report_body,
		uint32_t * p_td_report_body_size) {

	uint32_t collateral_expiration_status;
	sgx_ql_qv_result_t quote_verification_result;

  // 3 report types supported, minimum size is TD_REPORT10_BYTE_LEN. The input size should be larger than the minimum size
	if (p_td_report_body == NULL || root_pub_key == NULL || p_td_report_body_size == NULL || (*p_td_report_body_size) < TD_REPORT10_BYTE_LEN || root_pub_key_size < 0)  {
		return SGX_TD_VERIFY_ERROR(SGX_QL_ERROR_INVALID_PARAMETER);
	}


	quote3_error_t ret = sgx_qve_verify_quote(
                            p_quote,
                            quote_size,
                            p_quote_collateral,
                            1, //expiration_check_date, just set to 1 to pass sanity check
                            &collateral_expiration_status,
                            &quote_verification_result,
                            NULL, // qve report
                            0,    // supplemental data size
                            NULL, // supplemental data
                            root_pub_key,
                            root_pub_key_size,
                            p_td_report_body,
                            p_td_report_body_size);

			return SGX_TD_VERIFY_ERROR(ret);
}

#endif

#ifndef _MSC_VER
#ifndef SERVTD_ATTEST
#include "jwt-cpp/jwt.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "rapidjson/document.h"

#include "openssl/rand.h"
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <time.h>

#include "QuoteVerification/Quote.h"
#include "sgx_quote_4.h"
#include "sgx_quote_5.h"
#include "OpensslHelpers/Bytes.h"
#include "sgx_base64.h"
#include "ec_key.h"

using namespace rapidjson;

/*
•	SGX_QL_QV_RESULT_OK: “UpToDate”
•	SGX_QL_QV_RESULT_SW_HARDENING_NEEDED: “UpToDate”, “SWHardeningNeeded”
•	SGX_QL_QV_RESULT_CONFIG_NEEDED: “UpToDate”, “ConfigurationNeeded”
•	SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED: “UpToDate”, “SWHardeningNeeded”, “ConfigurationNeeded”
•	SGX_QL_QV_RESULT_OUT_OF_DATE: “OutOfDate”
•	SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED: “OutOfDate”, “ConfigurationNeeded”
•	SGX_QL_QV_RESULT_INVALID_SIGNATURE: No Platform TCB Report Generated
•	SGX_QL_QV_RESULT_REVOKED: “Revoked”
•	SGX_QL_QV_RESULT_UNSPECIFIED: No Platform TCB Report Generated
*/

static void qv_result_tcb_status_map(std::vector<std::string>& tcb_status, sgx_ql_qv_result_t qv_result){
    switch (qv_result){
    case TEE_QV_RESULT_OK:
        tcb_status.push_back("UpToDate");
        break;
    case TEE_QV_RESULT_SW_HARDENING_NEEDED:
        tcb_status.push_back("UpToDate");
        tcb_status.push_back("SWHardeningNeeded");
        break;
    case TEE_QV_RESULT_CONFIG_NEEDED:
        tcb_status.push_back("UpToDate");
        tcb_status.push_back("ConfigurationNeeded");
        break;
    case TEE_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
        tcb_status.push_back("UpToDate");
        tcb_status.push_back("SWHardeningNeeded");
        tcb_status.push_back("ConfigurationNeeded");
        break;
    case TEE_QV_RESULT_OUT_OF_DATE:
        tcb_status.push_back("OutOfDate");
        break;
    case TEE_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        tcb_status.push_back("OutOfDate");
        tcb_status.push_back("ConfigurationNeeded");
        break;
    case TEE_QV_RESULT_TD_RELAUNCH_ADVISED:
        tcb_status.push_back("TDRelaunchAdvised");
        break;
    case TEE_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED:
        tcb_status.push_back("TDRelaunchAdvised");
        tcb_status.push_back("ConfigurationNeeded");
        break;
    case TEE_QV_RESULT_INVALID_SIGNATURE:
        break;
    case TEE_QV_RESULT_REVOKED:
        tcb_status.push_back("Revoked");
        break;
    case TEE_QV_RESULT_UNSPECIFIED:
        break;
    default:
        break;
}
    return;
}

static void advisory_id_vec(std::vector<std::string>& vec_ad_id, std::string s_ad_id)
{
    std::stringstream stream_ad;
    stream_ad << s_ad_id;
    std::string temp;

    while(getline(stream_ad, temp, ','))
    {
        vec_ad_id.push_back(temp);
    }
    return;
}



//time transfer to ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ)
static void time_to_string(time_t time_before, char* time_str, size_t len)
{
    if(time_str==NULL){
        return;
    }
    struct tm *nowtm;
    //transfer to UTC to gmtime
    nowtm = intel::sgx::dcap::gmtime(&time_before);

    //transfer to ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ)
    strftime(time_str, len,"%Y-%m-%dT%H:%M:%SZ", nowtm);
    return;
}

static std::string char_to_base64(unsigned char const* raw_char, size_t len)
{
    if(raw_char == NULL){
       return {};
    }

    std::string s_ret;

    //remove '\0'
    if(len == strlen(reinterpret_cast<const char *>(raw_char)) + 1){
        len--;
    }
    char* tmp_str = base64_encode(reinterpret_cast<const char *>(raw_char), (int)len);
    if(tmp_str == NULL)
    {
        return {};
    }
    s_ret = tmp_str;
    free(tmp_str);
    return s_ret;
}

static quote3_error_t token_genrator_internal(std::string json_data, uint8_t **jwt_data, uint32_t *jwt_size)
{

#ifndef SGX_TRUSTED
	auto token = jwt::create()
					 .set_issuer("qvl")
					 .set_type("JWT")
					 .set_payload_claim("qvl_result", jwt::claim(json_data))
					 .sign(jwt::algorithm::none());
#else
    std::string jwk, priv_key;
    if(generate_ec384_keys(jwk, priv_key) != 0)
    {
        // Retry to generate ec key pair in case key generation fails randomly
        if(generate_ec384_keys(jwk, priv_key) != 0)
        {
            return SGX_QL_ERROR_UNEXPECTED;
        }
    }

    auto token = jwt::create()
                     .set_type("JWT")
                     .set_issuer("qve")
                     .set_header_claim("jwk", jwt::claim(jwk))
                     .set_payload_claim("qvl_result", jwt::claim(json_data))
                     .sign(jwt::algorithm::es384("", priv_key, "", ""));
    priv_key.clear();
#endif
    if(token.empty())
    {
        return TEE_ERROR_UNEXPECTED;
    }

    *jwt_data = (uint8_t *)malloc(token.length() + 1);
    if (*jwt_data == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    memset(*jwt_data, 0, token.length() + 1);
    memcpy_s(*jwt_data, token.length() + 1, token.c_str(), token.length());
    *jwt_size = (uint32_t)token.length();
    return TEE_SUCCESS;
}

static void audit_generator(
    const char *request_id,
    time_t verification_date,
    rapidjson::Value &obj,
    rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator> &allocator)
{
    Value obj_plat_audit(kObjectType);
    Value str_requestid(kStringType);

    std::string s_request_id = char_to_base64((reinterpret_cast<unsigned char const*>(request_id)), REQUEST_ID_LEN);
    str_requestid.SetString(s_request_id.c_str(), (unsigned int)(s_request_id.length()), allocator);
    if(str_requestid.GetStringLength() != 0){
        obj_plat_audit.AddMember("request_id", str_requestid, allocator);
    }

    char verifytime_str[TIME_STR_LEN] = {0};
    time_to_string(verification_date, verifytime_str, sizeof(verifytime_str));
    Value str_ver_date(kStringType);
    str_ver_date.SetString(verifytime_str, (unsigned int)strlen(verifytime_str), allocator);
    if(str_ver_date.GetStringLength() != 0){
        obj_plat_audit.AddMember("verification_time", str_ver_date, allocator);
    }

    obj.AddMember("audit", obj_plat_audit, allocator);
    return;
}

static quote3_error_t quote_hash_generator(
    const uint8_t *p_quote,
    const uint32_t quote_size,
    rapidjson::Value &obj,
    rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator> &allocator)
{
    // generates SHA-384 hash of input QUOTE
    Value obj_quote_hash(kObjectType);
    uint8_t quote_hash[SHA384_LEN] = { 0 };
    if (SHA384((const unsigned char *)p_quote, quote_size, quote_hash) == NULL) {
            return TEE_ERROR_UNEXPECTED;
    }
    Value str_quote_hash(kStringType);
    std::string s_quote_hash = byte_to_hexstring(quote_hash, SHA384_LEN, true);
    str_quote_hash.SetString(s_quote_hash.c_str(), (unsigned int)s_quote_hash.length(), allocator);
    if(str_quote_hash.GetStringLength() != 0){
        obj_quote_hash.AddMember("quote_hash", str_quote_hash, allocator);
        std::string hash_algo = QUOTE_HASH_ALGO;
        Value str_quote_hash_algo(kStringType);
        str_quote_hash_algo.SetString(hash_algo.c_str(), (unsigned int)hash_algo.length(), allocator);
        obj_quote_hash.AddMember("algo", str_quote_hash_algo, allocator);
        obj.PushBack(obj_quote_hash, allocator);
    }
    return TEE_SUCCESS;
}

//generate platform tcb
static quote3_error_t tee_platform_tcb_generator(
    const char *plat_type,
    const char* platform_desc,
    const char *request_id,
    sgx_ql_qv_result_t qv_result,
    time_t verification_date,
    const uint8_t *p_user_data,
    uint32_t user_data_size,
    const sgx_ql_qv_supplemental_t *p_supplemental_data,
    const uint8_t *p_quote,
    const uint32_t quote_size,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    rapidjson::Value &obj,
    rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator> &allocator)
{
    quote3_error_t dcap_ret = TEE_SUCCESS;

    Value obj_user_data(kObjectType);
    if(p_user_data != NULL && user_data_size != 0)
    {
        Value str_user_val(kStringType);
        str_user_val.SetString((reinterpret_cast<const char *>(p_user_data)), user_data_size, allocator);
        if(str_user_val.GetStringLength() != 0){
            obj_user_data.AddMember("user_data", str_user_val, allocator);
            obj.PushBack(obj_user_data, allocator);
        }
    }

    // generates SHA-384 hash of input QUOTE
    dcap_ret = quote_hash_generator(p_quote, quote_size, obj, allocator);
    if(dcap_ret != TEE_SUCCESS){
        return dcap_ret;
    }
    Value obj_platform(kObjectType);
    Value obj_plat_header(kObjectType);

    //Generate platform_tcb
    Value str_type_val(kStringType);
    str_type_val.SetString(plat_type, (unsigned int)strlen(plat_type), allocator);
    if(str_type_val.GetStringLength() != 0){
        obj_plat_header.AddMember("class_id", str_type_val, allocator);
    }
    str_type_val.SetString(platform_desc, (unsigned int)(strlen(platform_desc)), allocator);
    if(str_type_val.GetStringLength() != 0){
        obj_plat_header.AddMember("description", str_type_val, allocator);
    }

    obj_platform.AddMember("environment", obj_plat_header, allocator);

    Value obj_plat_tcb(kObjectType);
    Value tcb_status_array(kArrayType);
    Value str_tcb_status(kStringType);

    std::vector<std::string> tcb_status;
    qv_result_tcb_status_map(tcb_status, qv_result);
    if(!tcb_status.empty())
    {
        for(size_t i=0; i<tcb_status.size(); i++){
            str_tcb_status.SetString(tcb_status[i].c_str(), (unsigned int)(tcb_status[i].length()), allocator);
            tcb_status_array.PushBack(str_tcb_status, allocator);
        }
        obj_plat_tcb.AddMember("tcb_status", tcb_status_array, allocator);
    }

    if(p_supplemental_data != NULL){
        char time_str[TIME_STR_LEN] = {0};
        Value str_date(kStringType);
        auto Add_Mem = [&](char *str_m, rapidjson::GenericValue<rapidjson::ASCII<> >::StringRefType mem_name){str_date.SetString(str_m, (unsigned int)strlen(str_m), allocator);
                            if(str_date.GetStringLength() != 0){obj_plat_tcb.AddMember(mem_name, str_date, allocator);}};

        time_to_string(p_supplemental_data->earliest_issue_date, time_str, sizeof(time_str));
        Add_Mem(time_str, "earliest_issue_date");

        time_to_string(p_supplemental_data->latest_issue_date, time_str, sizeof(time_str));
        Add_Mem(time_str, "latest_issue_date");

        time_to_string(p_supplemental_data->earliest_expiration_date, time_str, sizeof(time_str));
        Add_Mem(time_str, "earliest_expiration_date");

        time_to_string(p_supplemental_data->tcb_level_date_tag, time_str, sizeof(time_str));
        Add_Mem(time_str, "tcb_level_date_tag");

        obj_plat_tcb.AddMember("pck_crl_num", p_supplemental_data->pck_crl_num, allocator);
        obj_plat_tcb.AddMember("root_ca_crl_num", p_supplemental_data->root_ca_crl_num, allocator);
        obj_plat_tcb.AddMember("tcb_eval_num", p_supplemental_data->tcb_eval_ref_num, allocator);

        //TODO
        //obj_plat_tcb.AddMember("platform_provider_id", , allocator);

        obj_plat_tcb.AddMember("sgx_types", p_supplemental_data->sgx_type, allocator);

        if(p_supplemental_data->dynamic_platform != PCK_FLAG_UNDEFINED){
            Value dynamic_plat;
            dynamic_plat.SetBool(p_supplemental_data->dynamic_platform);
            obj_plat_tcb.AddMember("is_dynamic_platform", dynamic_plat, allocator);
        }


        if(p_supplemental_data->cached_keys != PCK_FLAG_UNDEFINED){
            Value cached_keys;
            cached_keys.SetBool(p_supplemental_data->cached_keys);
            obj_plat_tcb.AddMember("is_cached_keys_policy", cached_keys, allocator);
        }

        if(p_supplemental_data->smt_enabled != PCK_FLAG_UNDEFINED){
            Value smt_enabled;
            smt_enabled.SetBool(p_supplemental_data->smt_enabled);
            obj_plat_tcb.AddMember("is_smt_enabled", smt_enabled, allocator);
        }

        Value advisory_id_array(kArrayType);
        Value str_advisory_id(kStringType);
        if (p_supplemental_data->version > 3 && strlen(p_supplemental_data->sa_list) > 0) {
            std::string s_ad_id(p_supplemental_data->sa_list);
            std::vector<std::string> vec_ad_id;
            advisory_id_vec(vec_ad_id, s_ad_id);
            if(!vec_ad_id.empty())
            {
                for(size_t i=0; i<vec_ad_id.size(); i++){
                    str_advisory_id.SetString(vec_ad_id[i].c_str(), (unsigned int)(vec_ad_id[i].length()), allocator);
                    advisory_id_array.PushBack(str_advisory_id, allocator);
                }
            obj_plat_tcb.AddMember("advisory_ids", advisory_id_array, allocator);
            }
        }
        Value str_keyid(kStringType);
        std::string s_root_key_id = byte_to_hexstring(p_supplemental_data->root_key_id, ROOT_KEY_ID_SIZE, true);
        str_keyid.SetString(s_root_key_id.c_str(), (unsigned int)(s_root_key_id.length()), allocator);
        if(str_keyid.GetStringLength() != 0){
            obj_plat_tcb.AddMember("root_key_id", str_keyid, allocator);
        }
    }

    //get fmpsc from quote
    unsigned char fmspc_from_quote[FMSPC_SIZE] = {0};
    unsigned char ca_from_quote[CA_SIZE] = {0};

    dcap_ret = get_fmspc_ca_from_quote(
        p_quote,
        quote_size,
        fmspc_from_quote,
        FMSPC_SIZE,
        ca_from_quote,
        CA_SIZE);

    if(dcap_ret == TEE_SUCCESS)
    {
        Value str_fmspc(kStringType);
        std::string sfmspc((char* )fmspc_from_quote, FMSPC_SIZE);
        std::reverse(sfmspc.begin(), sfmspc.end()); //endian align
        std::string s_fmspc = byte_to_hexstring((const uint8_t *)sfmspc.c_str(), FMSPC_SIZE, true);
        str_fmspc.SetString(s_fmspc.c_str(), (unsigned int)s_fmspc.length(), allocator);
        if(str_fmspc.GetStringLength() != 0)
        {
            obj_plat_tcb.AddMember("fmspc", str_fmspc, allocator);
        }
    }

    obj_platform.AddMember("measurement", obj_plat_tcb, allocator);

    /*
    "pck_crl_issuer_chain" : base64 encoding,
    "root_ca_crl" : base64 encoding,
    "pck_crl" : base64 encoding,
    "tcb_info_issuer_chain" : base64 encoding,
    "tcb_info" : base64 encoding,
    "qe_identity_issuer_chain" : base64 encoding,
    "qe_identity" : base64 encoding
    */
    //Generate endorsement
    if(p_quote_collateral != NULL){
        Value obj_collateral(kObjectType);
        Value str_collateral(kStringType);
        auto Add_Mem = [&](std::string str_m, rapidjson::GenericValue<rapidjson::ASCII<> >::StringRefType mem_name){str_collateral.SetString(str_m.c_str(), (unsigned int)(str_m.length()), allocator);
                            if(str_collateral.GetStringLength() != 0){obj_collateral.AddMember(mem_name, str_collateral, allocator);}};
        if(p_quote_collateral->pck_crl_issuer_chain != NULL && p_quote_collateral->pck_crl_issuer_chain_size > 0){
            std::string s_pck_crl_issue_chain = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->pck_crl_issuer_chain)), p_quote_collateral->pck_crl_issuer_chain_size);
            Add_Mem(s_pck_crl_issue_chain, "pck_crl_issuer_chain");
        }
        if(p_quote_collateral->root_ca_crl != NULL && p_quote_collateral->root_ca_crl_size > 0){
            std::string s_root_ca_crl = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->root_ca_crl)), p_quote_collateral->root_ca_crl_size);
            Add_Mem(s_root_ca_crl, "root_ca_crl");
        }

        if(p_quote_collateral->pck_crl != NULL && p_quote_collateral->pck_crl_size > 0){
            std::string s_pck_crl = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->pck_crl)), p_quote_collateral->pck_crl_size);
            Add_Mem(s_pck_crl, "pck_crl");
        }

        if(p_quote_collateral->tcb_info_issuer_chain != NULL && p_quote_collateral->tcb_info_issuer_chain_size > 0){
            std::string s_tcb_info_issuer_chain = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->tcb_info_issuer_chain)), p_quote_collateral->tcb_info_issuer_chain_size);
            Add_Mem(s_tcb_info_issuer_chain, "tcb_info_issuer_chain");
        }

        if(p_quote_collateral->tcb_info != NULL && p_quote_collateral->tcb_info_size > 0){
            std::string s_tcb_info = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->tcb_info)), p_quote_collateral->tcb_info_size);
            Add_Mem(s_tcb_info, "tcb_info");
        }

        if(p_quote_collateral->qe_identity_issuer_chain != NULL && p_quote_collateral->qe_identity_issuer_chain_size > 0){
            std::string s_qe_identity_issuer_chain = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->qe_identity_issuer_chain)), p_quote_collateral->qe_identity_issuer_chain_size);
            Add_Mem(s_qe_identity_issuer_chain, "qe_identity_issuer_chain");
        }

        if(p_quote_collateral->qe_identity != NULL && p_quote_collateral->qe_identity_size > 0){
            std::string s_qe_identity = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->qe_identity)), p_quote_collateral->qe_identity_size);
            Add_Mem(s_qe_identity, "qe_identity");
        }
        obj_platform.AddMember("certification_data", obj_collateral, allocator);
    }

    audit_generator(request_id, verification_date, obj_platform, allocator);

    obj.PushBack(obj_platform, allocator);
    return TEE_SUCCESS;
}

//Generate enclave_tcb
static quote3_error_t sgx_enclave_tcb_generator(
    const char *enclave_type,
    const char *request_id,
    time_t verification_date,
    uint16_t quote_ver,
    const uint8_t *p_quote,
    rapidjson::Value &obj,
    rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator> &allocator)
{
    Value obj_enclave(kObjectType);
    Value obj_enclave_header(kObjectType);
    Value obj_enclave_tcb(kObjectType);
    std::string enclave_desc = TEE_SGX_ENCLAVE_DESCRIPTION;

    Value str_enclave_type_val(kStringType);
    str_enclave_type_val.SetString(enclave_type, (unsigned int)strlen(enclave_type), allocator);
    if(str_enclave_type_val.GetStringLength() != 0){
        obj_enclave_header.AddMember("class_id", str_enclave_type_val, allocator);
    }
    str_enclave_type_val.SetString(enclave_desc.c_str(), (unsigned int)(enclave_desc.length()), allocator);
    if(str_enclave_type_val.GetStringLength() != 0){
        obj_enclave_header.AddMember("description", str_enclave_type_val, allocator);
    }

    obj_enclave.AddMember("environment", obj_enclave_header, allocator);

    if(p_quote != NULL){
        sgx_report_body_t sgx_report;
        memset(&sgx_report, 0, sizeof(sgx_report_body_t));
        if(quote_ver == QUOTE_VERSION_3)
        {
            const sgx_quote3_t *p_tmp_quote3 = reinterpret_cast<const sgx_quote3_t *> (p_quote);
            memcpy(&sgx_report, (void *)&(p_tmp_quote3->report_body), sizeof(sgx_report_body_t));
        }
        else if(quote_ver == QUOTE_VERSION_5)
        {
            const sgx_quote5_t *p_tmp_quote5 = reinterpret_cast<const sgx_quote5_t *> (p_quote);
            memcpy(&sgx_report, p_tmp_quote5->body, sizeof(sgx_report_body_t));
        }
        else {
            return TEE_ERROR_INVALID_PARAMETER;
        }

        Value str_encl(kStringType);
        auto Add_Mem = [&](std::string str_m, rapidjson::GenericValue<rapidjson::ASCII<> >::StringRefType mem_name){str_encl.SetString(str_m.c_str(), (unsigned int)(str_m.length()), allocator);
                            if(str_encl.GetStringLength() != 0){obj_enclave_tcb.AddMember(mem_name, str_encl, allocator);}};

        std::string s_miscselect = byte_to_hexstring((uint8_t *) &(sgx_report.misc_select), sizeof(sgx_misc_select_t), true);
        Add_Mem(s_miscselect, "sgx_miscselect");

        std::string s_attributes = byte_to_hexstring((uint8_t *) &(sgx_report.attributes), sizeof(sgx_attributes_t), true);
        Add_Mem(s_attributes, "sgx_attributes");

        std::string s_mrenclave = byte_to_hexstring((uint8_t *) &(sgx_report.mr_enclave.m), sizeof(sgx_measurement_t), true);
        Add_Mem(s_mrenclave, "sgx_mrenclave");

        std::string s_mrsigner = byte_to_hexstring(sgx_report.mr_signer.m, sizeof(sgx_measurement_t), true);
        Add_Mem(s_mrsigner, "sgx_mrsigner");

        obj_enclave_tcb.AddMember("sgx_isvprodid", sgx_report.isv_prod_id, allocator);
        obj_enclave_tcb.AddMember("sgx_isvsvn", sgx_report.isv_svn, allocator);

        std::string s_configid = byte_to_hexstring(sgx_report.config_id, SGX_CONFIGID_SIZE, true);
        Add_Mem(s_configid, "sgx_configid");

        obj_enclave_tcb.AddMember("sgx_configsvn", sgx_report.config_svn, allocator);

        std::string s_isvexprodid = byte_to_hexstring(sgx_report.isv_ext_prod_id, SGX_ISVEXT_PROD_ID_SIZE, true);
        Add_Mem(s_isvexprodid, "sgx_isvextprodid");

        std::string s_isvfamilyid = byte_to_hexstring(sgx_report.isv_family_id, SGX_ISV_FAMILY_ID_SIZE, true);
        Add_Mem(s_isvfamilyid, "sgx_isvfamilyid");

        std::string s_reportdata = byte_to_hexstring(sgx_report.report_data.d, sizeof(sgx_report_data_t), true);
        Add_Mem(s_reportdata, "sgx_reportdata");

        obj_enclave.AddMember("measurement", obj_enclave_tcb, allocator);
    }

    audit_generator(request_id, verification_date, obj_enclave, allocator);

    obj.PushBack(obj_enclave, allocator);
    return TEE_SUCCESS;
}
static quote3_error_t sgx_jwt_generator_internal(const char *plat_type,
    const char *plat_version,
    const char *enclave_type,
    const char *enclave_version,
    uint16_t quote_ver,
    const char *request_id,
    sgx_ql_qv_result_t qv_result,
    time_t verification_date,
    const uint8_t *p_user_data,
    uint32_t user_data_size,
    const sgx_ql_qv_supplemental_t *p_supplemental_data,
    const uint8_t *p_quote,
    const uint32_t quote_size,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    uint32_t *jwt_size,
    uint8_t **jwt_data)
{
    if(CHECK_MANDATORY_PARAMS(p_quote, quote_size) || quote_size < QUOTE_MIN_SIZE ||
    plat_version == NULL || enclave_type == NULL || enclave_version == NULL ||
    request_id == NULL || p_quote_collateral == NULL || p_supplemental_data == NULL)
    {
        return TEE_ERROR_INVALID_PARAMETER;
    }
    if(quote_ver != QUOTE_VERSION_5 && quote_ver != QUOTE_VERSION_3)
    {
        return TEE_ERROR_INVALID_PARAMETER;
    }

    Document JWT;
    JWT.SetObject();
    quote3_error_t dcap_ret = TEE_SUCCESS;

    Document::AllocatorType &allocator = JWT.GetAllocator();

    Value sgx_jwt_array(kArrayType);

    dcap_ret = tee_platform_tcb_generator(
                plat_type,
                TEE_SGX_PLATFORM_DESCRIPTION,
                request_id,
                qv_result,
                verification_date,
                p_user_data,
                user_data_size,
                p_supplemental_data,
                p_quote,
                quote_size,
                p_quote_collateral,
                sgx_jwt_array,
                allocator);
    if(dcap_ret != TEE_SUCCESS){
        return dcap_ret;
    }

    //Generate enclave_tcb
    dcap_ret = sgx_enclave_tcb_generator(
                enclave_type,
                request_id,
                verification_date,
                quote_ver,
                p_quote,
                sgx_jwt_array,
                allocator);
    if(dcap_ret != TEE_SUCCESS){
        return dcap_ret;
    }

    JWT.AddMember("qvl_result", sgx_jwt_array, allocator);

    rapidjson::StringBuffer str_buff;
    rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(str_buff);
    JWT.Accept(writer);
    std::string raw_data = str_buff.GetString();
    if(raw_data.empty())
    {
        return TEE_ERROR_UNEXPECTED;
    }

    dcap_ret = token_genrator_internal(raw_data, jwt_data, jwt_size);

    return dcap_ret;
}

//genrate qe identity
static void tdx_qe_identity_generator(
    const char *request_id,
    time_t verification_date,
    const sgx_ql_qv_supplemental_t *p_supplemental_data,
    rapidjson::Value &obj,
    rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator> &allocator)
{
    Value obj_qe_identity(kObjectType);
    Value obj_qe_iden_header(kObjectType);
    Value obj_qe_iden_tcb(kObjectType);
    Value str_qe_type_val(kStringType);
    std::string identity_desc = TEE_TDX_QE_IDENTITY_DESCRIPTION;
    str_qe_type_val.SetString(TEE_TDX_QE_IDENTITY_TOKEN_UUID, (unsigned int)strlen(TEE_TDX_QE_IDENTITY_TOKEN_UUID));
    if(str_qe_type_val.GetStringLength() != 0){
        obj_qe_iden_header.AddMember("class_id", str_qe_type_val, allocator);
    }
    str_qe_type_val.SetString(identity_desc.c_str(), (unsigned int)(identity_desc.length()), allocator);
    if(str_qe_type_val.GetStringLength() != 0){
        obj_qe_iden_header.AddMember("Description", str_qe_type_val, allocator);
    }

    obj_qe_identity.AddMember("environment", obj_qe_iden_header, allocator);

    if(p_supplemental_data != NULL){
        Value qe_tcb_status_array(kArrayType);
        Value qe_str_tcb_status(kStringType);
        std::vector<std::string> qe_tcb_status;
        qv_result_tcb_status_map(qe_tcb_status, p_supplemental_data->qe_iden_status);
        if(!qe_tcb_status.empty())
        {
            for(size_t i=0; i<qe_tcb_status.size(); i++){
                qe_str_tcb_status.SetString(qe_tcb_status[i].c_str(), (unsigned int)(qe_tcb_status[i].length()), allocator);
                qe_tcb_status_array.PushBack(qe_str_tcb_status, allocator);
            }
            obj_qe_iden_tcb.AddMember("tcb_status", qe_tcb_status_array, allocator);
        }

        char time_str[TIME_STR_LEN] = {0};
        Value str_date(kStringType);

        auto Add_Mem = [&](char *str_m, rapidjson::GenericValue<rapidjson::ASCII<> >::StringRefType mem_name){str_date.SetString(str_m, (unsigned int)strlen(str_m), allocator);
                            if(str_date.GetStringLength() != 0){obj_qe_iden_tcb.AddMember(mem_name, str_date, allocator);}};

        time_to_string(p_supplemental_data->qe_iden_tcb_level_date_tag, time_str, sizeof(time_str));
        Add_Mem(time_str, "tcb_level_date_tag");

        time_to_string(p_supplemental_data->qe_iden_earliest_issue_date, time_str, sizeof(time_str));
        Add_Mem(time_str, "earliest_issue_date");

        time_to_string(p_supplemental_data->qe_iden_latest_issue_date, time_str, sizeof(time_str));
        Add_Mem(time_str, "latest_issue_date");

        time_to_string(p_supplemental_data->qe_iden_earliest_expiration_date, time_str, sizeof(time_str));
        Add_Mem(time_str, "earliest_expiration_date");

        obj_qe_iden_tcb.AddMember("tcb_eval_num", p_supplemental_data->qe_iden_tcb_eval_ref_num, allocator);

        Value str_keyid(kStringType);
        std::string s_root_key_id = byte_to_hexstring(p_supplemental_data->root_key_id, ROOT_KEY_ID_SIZE, true);
        str_keyid.SetString(s_root_key_id.c_str(), (unsigned int)(s_root_key_id.length()), allocator);
        if(str_keyid.GetStringLength() != 0){
            obj_qe_iden_tcb.AddMember("root_key_id", str_keyid, allocator);
        }
        //root key id, SHA-384 hash of CERT chain root CA's public key
    }

    obj_qe_identity.AddMember("measurement", obj_qe_iden_tcb, allocator);
    audit_generator(request_id, verification_date, obj_qe_identity, allocator);
    obj.PushBack(obj_qe_identity, allocator);
    return;
}

//Generate TD report
static void tdx_td_report_generator(
    uint16_t quote_ver,
    uint16_t report_type,
    const char *request_id,
    time_t verification_date,
    const uint8_t *p_quote,
    rapidjson::Value &obj,
    rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator> &allocator)
{
    Value obj_td_report(kObjectType);
    Value obj_td_rep_header(kObjectType);
    Value obj_td_rep_tcb(kObjectType);

    Value str_td_type_val(kStringType);
    std::string tdtcb_desc = TEE_TDX_TD_IDENTITY_DESCRIPTION;
    if(report_type == TDX10_REPORT)
        str_td_type_val.SetString(TEE_TDX_TD10_IDENTITY_TOKEN_UUID, (unsigned int)strlen(TEE_TDX_TD10_IDENTITY_TOKEN_UUID), allocator);
    else
        str_td_type_val.SetString(TEE_TDX_TD15_IDENTITY_TOKEN_UUID, (unsigned int)strlen(TEE_TDX_TD15_IDENTITY_TOKEN_UUID), allocator);
    if(str_td_type_val.GetStringLength() != 0){
        obj_td_rep_header.AddMember("class_id", str_td_type_val, allocator);
    }
    str_td_type_val.SetString(tdtcb_desc.c_str(), (unsigned int)(tdtcb_desc.length()), allocator);
    if(str_td_type_val.GetStringLength() != 0){
        obj_td_rep_header.AddMember("Description", str_td_type_val, allocator);
    }

    obj_td_report.AddMember("environment", obj_td_rep_header, allocator);

    if(p_quote != NULL){
        sgx_report2_body_v1_5_t tmp_report;     //always transfer to tdx1.5 report
        memset(&tmp_report, 0, sizeof(sgx_report2_body_v1_5_t));
        if(quote_ver == QUOTE_VERSION_4)
        {
            const sgx_quote4_t *tmp_quote4 = reinterpret_cast<const sgx_quote4_t *> (p_quote);
            memcpy(&tmp_report, (void *)&(tmp_quote4->report_body), sizeof(sgx_report2_body_t));
        }
        if(quote_ver == QUOTE_VERSION_5)
        {
            const sgx_quote5_t *tmp_quote5 = reinterpret_cast<const sgx_quote5_t *> (p_quote);
            memcpy(&tmp_report, tmp_quote5->body, sizeof(sgx_report2_body_v1_5_t));
        }

        Value str_td(kStringType);
        auto Add_Mem = [&](std::string str_m, rapidjson::GenericValue<rapidjson::ASCII<> >::StringRefType mem_name){str_td.SetString(str_m.c_str(), (unsigned int)(str_m.length()), allocator);
                            if(str_td.GetStringLength() != 0){obj_td_rep_tcb.AddMember(mem_name, str_td, allocator);}};

        std::string s_td_attributes = byte_to_hexstring((uint8_t *) &(tmp_report.td_attributes), sizeof(tee_attributes_t), true);
        Add_Mem(s_td_attributes, "tdx_attributes");

        std::string s_tdx_xfam = byte_to_hexstring((uint8_t *) &(tmp_report.xfam), sizeof(tee_attributes_t), true);
        Add_Mem(s_tdx_xfam, "tdx_xfam");

        std::string s_tdx_mrconfigid = byte_to_hexstring((uint8_t *) &(tmp_report.mr_config_id), sizeof(tee_measurement_t), true);
        Add_Mem(s_tdx_mrconfigid, "tdx_mrconfigid");

        std::string s_tdx_mrowner = byte_to_hexstring((uint8_t *) &(tmp_report.mr_owner), sizeof(tee_measurement_t), true);
        Add_Mem(s_tdx_mrowner, "tdx_mrowner");

        std::string s_tdx_mrownerconfig = byte_to_hexstring((uint8_t *) &(tmp_report.mr_owner_config), sizeof(tee_measurement_t), true);
        Add_Mem(s_tdx_mrownerconfig, "tdx_mrownerconfig");

        std::string s_tdx_mrtd = byte_to_hexstring((uint8_t *) &(tmp_report.mr_td), sizeof(tee_measurement_t), true);
        Add_Mem(s_tdx_mrtd, "tdx_mrtd");

        std::string s_tdx_rtmr0 = byte_to_hexstring((uint8_t *) &(tmp_report.rt_mr[0]), sizeof(tee_measurement_t), true);
        Add_Mem(s_tdx_rtmr0, "tdx_rtmr0");

        std::string s_tdx_rtmr1 = byte_to_hexstring((uint8_t *) &(tmp_report.rt_mr[1]), sizeof(tee_measurement_t), true);
        Add_Mem(s_tdx_rtmr1, "tdx_rtmr1");

        std::string s_tdx_rtmr2 = byte_to_hexstring((uint8_t *) &(tmp_report.rt_mr[2]), sizeof(tee_measurement_t), true);
        Add_Mem(s_tdx_rtmr2, "tdx_rtmr2");

        std::string s_tdx_rtmr3 = byte_to_hexstring((uint8_t *) &(tmp_report.rt_mr[3]), sizeof(tee_measurement_t), true);
        Add_Mem(s_tdx_rtmr3, "tdx_rtmr3");

        std::string s_tdx_reportdata  = byte_to_hexstring((uint8_t *) &(tmp_report.report_data), sizeof(tee_report_data_t), true);
        Add_Mem(s_tdx_reportdata, "tdx_reportdata");
        //only quote version 5: tdx_mrservicetd
        if(quote_ver == QUOTE_VERSION_5)
        {
            std::string s_mr_servicetd  = byte_to_hexstring((uint8_t *) &(tmp_report.mr_servicetd), sizeof(tee_measurement_t), true);
            Add_Mem(s_mr_servicetd, "tdx_mrservicetd");
        }
    }
    obj_td_report.AddMember("measurement", obj_td_rep_tcb, allocator);
    audit_generator(request_id, verification_date, obj_td_report, allocator);
    obj.PushBack(obj_td_report, allocator);
    return;
}

static quote3_error_t tdx_jwt_generator_internal(uint16_t quote_ver,
    uint16_t report_type,
    const char *plat_version,
    const char *qe_identity_version,
    const char *td_identity_version,
    const char *request_id,
    sgx_ql_qv_result_t qv_result,
    time_t verification_date,
    const uint8_t *p_user_data,
    uint32_t user_data_size,
    const sgx_ql_qv_supplemental_t *p_supplemental_data,
    const uint8_t *p_quote,
    const uint32_t quote_size,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    uint32_t *jwt_size,
    uint8_t **jwt_data)
{
    if(CHECK_MANDATORY_PARAMS(p_quote, quote_size) || quote_size < QUOTE_MIN_SIZE ||
    plat_version == NULL || qe_identity_version == NULL || td_identity_version == NULL ||
    request_id == NULL || p_supplemental_data == NULL || p_quote_collateral == NULL){
        return TEE_ERROR_INVALID_PARAMETER;
    }
    if(report_type < TDX10_REPORT){
        return TEE_ERROR_INVALID_PARAMETER;
    }
    const sgx_quote4_t *quote4 = reinterpret_cast<const sgx_quote4_t *> (p_quote);
    if(quote4->header.tee_type != TEE_TYPE_TDX){
        return TEE_ERROR_INVALID_PARAMETER;
    }

    Document JWT;
    JWT.SetObject();
    quote3_error_t dcap_ret = TEE_SUCCESS;

    Document::AllocatorType &allocator = JWT.GetAllocator();

    Value tdx_jwt_array(kArrayType);

    if(report_type == TDX10_REPORT){
        dcap_ret = tee_platform_tcb_generator(
        TEE_TDX10_PALTFORM_TOKEN_UUID,
        TEE_TDX_PLATFORM_DESCRIPTION,
        request_id,
        qv_result,
        verification_date,
        p_user_data,
        user_data_size,
        p_supplemental_data,
        p_quote,
        quote_size,
        p_quote_collateral,
        tdx_jwt_array,
        allocator);
    }
    else{
        dcap_ret = tee_platform_tcb_generator(
        TEE_TDX15_PALTFORM_TOKEN_UUID,
        TEE_TDX_PLATFORM_DESCRIPTION,
        request_id,
        qv_result,
        verification_date,
        p_user_data,
        user_data_size,
        p_supplemental_data,
        p_quote,
        quote_size,
        p_quote_collateral,
        tdx_jwt_array,
        allocator);
    }

    if(dcap_ret != TEE_SUCCESS){
        return dcap_ret;
    }

    //Generate QE Identity
    tdx_qe_identity_generator(
        request_id,
        verification_date,
        p_supplemental_data,
        tdx_jwt_array,
        allocator);

    //Generate TD report
    tdx_td_report_generator(
        quote_ver,
        report_type,
        request_id,
        verification_date,
        p_quote,
        tdx_jwt_array,
        allocator);

    JWT.AddMember("qvl_result", tdx_jwt_array, allocator);

    rapidjson::StringBuffer str_buff;
    rapidjson::Writer<rapidjson::StringBuffer> writer(str_buff);
    JWT.Accept(writer);

    std::string raw_data = str_buff.GetString();
    if(raw_data.empty())
    {
        return TEE_ERROR_UNEXPECTED;
    }
    dcap_ret = token_genrator_internal(raw_data, jwt_data, jwt_size);

    return dcap_ret;
}

#ifdef SGX_TRUSTED
/**
 * Generate enclave report with:
 * SHA384([jwt || user_data] || 32 - 0x00s)
 *
 * @param p_token[IN] - Pointer to a tee JWT token.
 * @param token_size[IN] - Size of the buffer pointed to by p_token (in bytes).
 * @param p_user_data[IN] - Pointer to a user data.
 * @param user_data_size[IN] - Size of the buffer pointed to by p_user_data (in bytes).
 * @param p_qve_report_info[IN/OUT] - QvE will generate a report using the target_info provided in the sgx_ql_qe_report_info_t structure, and store it in qe_report.
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_UNABLE_TO_GENERATE_REPORT
 **/
static quote3_error_t sgx_qve_token_generate_report(
    const uint8_t *p_token,
    uint32_t token_size,
    sgx_ql_qe_report_info_t *p_qve_report_info)
{

    //validate parameters
    //
    if (p_token == NULL ||
        token_size == 0) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t sgx_status = SGX_ERROR_UNEXPECTED;
    quote3_error_t ret = SGX_QL_UNABLE_TO_GENERATE_REPORT;
    sgx_sha_state_handle_t sha_handle = NULL;
    sgx_report_data_t report_data = { 0 };


    do {
        //Create QvE report
        //
        //report_data =  SHA384([jwt] || 32 - 0x00s)
        //
        sgx_status = sgx_sha384_init(&sha_handle);
        SGX_ERR_BREAK(sgx_status);

        //jwt token
        //
        sgx_status = sgx_sha384_update((p_token), token_size, sha_handle);
        SGX_ERR_BREAK(sgx_status);

        //get the hashed report_data
        //
        sgx_status = sgx_sha384_get_hash(sha_handle, reinterpret_cast<sgx_sha384_hash_t *>(&report_data));
        SGX_ERR_BREAK(sgx_status);

        //create QVE report with report_data embedded
        //
        sgx_status = sgx_create_report(&(p_qve_report_info->app_enclave_target_info), &report_data, &(p_qve_report_info->qe_report));
        SGX_ERR_BREAK(sgx_status);

        ret = SGX_QL_SUCCESS;
    } while (0);

    //clear data in report_data (it's a local variable, no need for free).
    //
    memset_s(&report_data, sizeof(sgx_report_data_t), 0, sizeof(sgx_report_data_t));
    if (sha_handle != NULL) {
        sgx_sha384_close(sha_handle);
    }
    return ret;
}
#endif //SGX_TRUSTED

static quote3_error_t user_report_verify_internal(
    const uint8_t *p_quote,
    const uint8_t *p_user_data,
    uint32_t user_data_size
)
{
    //parse quote header to get tee type, only support SGX and TDX by now
    tee_evidence_type_t tee_type = UNKNOWN_QUOTE_TYPE;

    // check quote type
    uint32_t *p_type = (uint32_t *) (p_quote + sizeof(uint16_t) * 2);
    if (*p_type == SGX_QUOTE_TYPE)
        tee_type = SGX_EVIDENCE;
    else if (*p_type == TDX_QUOTE_TYPE)
        tee_type = TDX_EVIDENCE;
    else{
        //quote type is not supported
        return TEE_ERROR_INVALID_PARAMETER;
    }
    uint16_t quote_ver = 0;
    const uint8_t *p_tmp_quote = p_quote;
    memcpy(&quote_ver, p_tmp_quote, sizeof(uint16_t));

    if(tee_type == SGX_EVIDENCE && p_user_data){
        sgx_report_body_t sgx_report;
        memset(&sgx_report, 0, sizeof(sgx_report_body_t));
        if(quote_ver == QUOTE_VERSION_3)
        {
            const sgx_quote3_t *p_tmp_quote3 = reinterpret_cast<const sgx_quote3_t *> (p_quote);
            memcpy(&sgx_report, (void *)&(p_tmp_quote3->report_body), sizeof(sgx_report_body_t));
        }
        else if(quote_ver == QUOTE_VERSION_5)
        {
            const sgx_quote5_t *p_tmp_quote5 = reinterpret_cast<const sgx_quote5_t *> (p_quote);
            memcpy(&sgx_report, p_tmp_quote5->body, sizeof(sgx_report_body_t));
        }
        else {
            return TEE_ERROR_INVALID_PARAMETER;
        }
        if(strlen(reinterpret_cast<const char*>(sgx_report.report_data.d)) > SHA384_LEN){
            return TEE_ERROR_REPORT;
        }
        uint8_t data_hash[SHA384_LEN] = { 0 };
        if (SHA384((const unsigned char *)p_user_data, user_data_size, data_hash) == NULL) {
            return TEE_ERROR_UNEXPECTED;
        }
        if (memcmp(&sgx_report.report_data.d, data_hash, SHA384_LEN) != 0) {
            return TEE_ERROR_REPORT;
        }
    }

    return TEE_SUCCESS;
}

quote3_error_t  tee_qve_verify_quote_qvt(
    const uint8_t *p_quote,
    uint32_t quote_size,
    time_t current_time,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    const uint8_t *p_user_data,
    uint32_t user_data_size,
    uint32_t *p_verification_result_token_buffer_size,
    uint8_t **p_verification_result_token
)
{
    if (SGXSSL_init())
        return SGX_QL_SERVICE_UNAVAILABLE;

    if( p_quote == NULL ||
        quote_size < QUOTE_MIN_SIZE ||
        !sgx_is_within_enclave(p_quote, quote_size) ||
        p_quote_collateral == NULL ||
        !sgx_is_within_enclave(p_quote_collateral, sizeof(*p_quote_collateral)) ||
        !is_collateral_deep_copied(p_quote_collateral) ||
        current_time <= 0 ||
        (p_qve_report_info != NULL && !sgx_is_within_enclave(p_qve_report_info, sizeof(*p_qve_report_info))) ||
        p_verification_result_token_buffer_size == 0 || p_verification_result_token == NULL)
    {
        return TEE_ERROR_INVALID_PARAMETER;
    }

    quote3_error_t dcap_ret = TEE_ERROR_UNEXPECTED;
    if(p_user_data){
        if (user_data_size == 0 || !sgx_is_within_enclave(p_user_data, user_data_size))
        {
            return TEE_ERROR_INVALID_PARAMETER;
        }
        dcap_ret = user_report_verify_internal(p_quote, p_user_data, user_data_size);
        if(dcap_ret != TEE_SUCCESS){
            return dcap_ret;
        }
    }

    uint32_t collateral_expiration_status = 1;

    tee_supp_data_descriptor_t supp_data;
    memset(&supp_data, 0, sizeof(tee_supp_data_descriptor_t));
    sgx_ql_qv_result_t quote_verification_result = TEE_QV_RESULT_UNSPECIFIED;

    //get supplemental data size
    dcap_ret = sgx_qve_get_quote_supplemental_data_size(&supp_data.data_size);

    if (dcap_ret == TEE_SUCCESS && supp_data.data_size == sizeof(sgx_ql_qv_supplemental_t)) {
        supp_data.p_data = (uint8_t*)malloc(supp_data.data_size);
        if (supp_data.p_data != NULL) {
            memset(supp_data.p_data, 0, supp_data.data_size);
        }
        else {
            return TEE_ERROR_OUT_OF_MEMORY;
        }
    }
    else {
        if (dcap_ret != TEE_SUCCESS){
            return dcap_ret;
        }

        if (supp_data.data_size != sizeof(sgx_ql_qv_supplemental_t)){
            return SGX_QL_SUPPLEMENTAL_DATA_VERSION_NOT_SUPPORTED;
        }
    }

    // set supplemental version if necessary
    if (supp_data.p_data != NULL && supp_data.data_size > 0) {
        try {
            // set version in supplemental data
            reinterpret_cast<sgx_ql_qv_supplemental_t*> (supp_data.p_data)->major_version = SUPPLEMENTAL_DATA_VERSION;
            reinterpret_cast<sgx_ql_qv_supplemental_t*> (supp_data.p_data)->minor_version = SUPPLEMENTAL_V3_LATEST_MINOR_VERSION;
        }

        catch(...) {
            // cannot access p_supplemental_data field
            if(supp_data.p_data != NULL){
                free(supp_data.p_data);
            }
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
    }
    dcap_ret =  sgx_qve_verify_quote(
    p_quote,
    quote_size,
    p_quote_collateral,
    current_time,
    &collateral_expiration_status,
    &quote_verification_result,
    p_qve_report_info,
    supp_data.data_size,
    supp_data.p_data
    );

    if (dcap_ret == TEE_SUCCESS) {
        switch (quote_verification_result)
        {
        case TEE_QV_RESULT_OK:
            break;
        case TEE_QV_RESULT_CONFIG_NEEDED:
        case TEE_QV_RESULT_OUT_OF_DATE:
        case TEE_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case TEE_QV_RESULT_SW_HARDENING_NEEDED:
        case TEE_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
        case TEE_QV_RESULT_TD_RELAUNCH_ADVISED:
        case TEE_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED:
            break;
        //Will not generate JWT when critical error occurred
        default:
            if(supp_data.p_data != NULL){
                free(supp_data.p_data);
            }
            return TEE_ERROR_UNEXPECTED;
        }
    }
    else {
        if(supp_data.p_data != NULL){
            free(supp_data.p_data);
        }
        return dcap_ret;
    }

    unsigned char rand_nonce[REQUEST_ID_LEN] = {0};
    if(!RAND_bytes(rand_nonce, REQUEST_ID_LEN))
    {
        if(supp_data.p_data != NULL){
            free(supp_data.p_data);
        }
        return TEE_ERROR_UNEXPECTED;
    }

    //parse quote header to get tee type, only support SGX and TDX by now
    tee_evidence_type_t tee_type = UNKNOWN_QUOTE_TYPE;

    // check quote type
    uint32_t *p_type = (uint32_t *) (p_quote + sizeof(uint16_t) * 2);
    if (*p_type == SGX_QUOTE_TYPE)
        tee_type = SGX_EVIDENCE;
    else if (*p_type == TDX_QUOTE_TYPE)
        tee_type = TDX_EVIDENCE;
    else{
        if(supp_data.p_data != NULL){
            free(supp_data.p_data);
        }
        //quote type is not supported
        return TEE_ERROR_INVALID_PARAMETER;
    }
    uint16_t quote_ver = 0;
    uint16_t report_type = 0;
    const uint8_t *p_tmp_quote = p_quote;
    memcpy(&quote_ver, p_tmp_quote, sizeof(uint16_t));
    if(quote_ver == QUOTE_VERSION_4){
        sgx_quote4_t *p_tmp_quote4 = (sgx_quote4_t *)p_tmp_quote;
        uint16_t major_ver = p_tmp_quote4->report_body.tee_tcb_svn.tcb_svn[1];
        switch (major_ver)
        {
            case 0:
                report_type = TDX10_REPORT;
                break;
            case 1:
                report_type = TDX15_REPORT;
                break;
            case 3:
                report_type = TDX20_REPORT;
                break;
            default:    //others not support yet
                report_type = UNKNOWN_REPORT_TYPE;
                break;
        }
    }
    if(quote_ver == QUOTE_VERSION_5)
    {
        sgx_quote5_t *p_tmp_quote_5 = (sgx_quote5_t *)p_tmp_quote;
        report_type = p_tmp_quote_5->type;
    }
    uint8_t *tmp_result_token = NULL;
    try
    {
        if(tee_type == SGX_EVIDENCE){
            dcap_ret = sgx_jwt_generator_internal(
                TEE_SGX_PALTFORM_TOKEN_UUID, TEE_SGX_PLATFORM_TOKEN_VER,
                TEE_SGX_ENCLAVE_TOKEN_UUID, TEE_SGX_ENCLAVE_TOKEN_VER,
                quote_ver,
                reinterpret_cast<const char*>(rand_nonce),
                quote_verification_result,
                current_time,
                p_user_data,
                user_data_size,
                reinterpret_cast<const sgx_ql_qv_supplemental_t*>(supp_data.p_data),
                p_quote,
                quote_size,
                p_quote_collateral,
                p_verification_result_token_buffer_size,
                &tmp_result_token);
        }
        else if(tee_type == TDX_EVIDENCE){
            dcap_ret = tdx_jwt_generator_internal(
                quote_ver, report_type,
                TEE_TDX_PLATFORM_TOKEN_VER,
                TEE_TDX_QE_IDENTITY_TOKEN_VER,
                TEE_TDX_TD_IDENTITY_TOKEN_VER,
                reinterpret_cast<const char*>(rand_nonce),
                quote_verification_result,
                current_time,
                p_user_data,
                user_data_size,
                reinterpret_cast<const sgx_ql_qv_supplemental_t*>(supp_data.p_data),
                p_quote,
                quote_size,
                p_quote_collateral,
                p_verification_result_token_buffer_size,
                &tmp_result_token);
        }
    }
    catch (...)
    {
        if(supp_data.p_data != NULL){
            free(supp_data.p_data);
        }
        if(tmp_result_token != NULL){
            free(tmp_result_token);
        }
        return TEE_ERROR_UNEXPECTED;
    }

#ifdef SGX_TRUSTED
    if (p_qve_report_info != NULL && dcap_ret == TEE_SUCCESS) {

        quote3_error_t generate_report_ret = TEE_ERROR_INVALID_PARAMETER;
        //clear original data
        memset_s(&(p_qve_report_info->qe_report), sizeof(p_qve_report_info->qe_report), 0, sizeof(p_qve_report_info->qe_report));
        //generate a report with the verification result and input collaterals
        //
        generate_report_ret = sgx_qve_token_generate_report(
            (const uint8_t *)tmp_result_token,
            *p_verification_result_token_buffer_size,
            p_qve_report_info);
        if (generate_report_ret != TEE_SUCCESS) {
            dcap_ret = generate_report_ret;
            memset_s(&(p_qve_report_info->qe_report), sizeof(p_qve_report_info->qe_report), 0, sizeof(p_qve_report_info->qe_report));
        }
    }

    if(dcap_ret == TEE_SUCCESS){
        ocall_qvt_token_malloc(*p_verification_result_token_buffer_size + 1, p_verification_result_token);
        if(*p_verification_result_token != NULL){
            memcpy(*p_verification_result_token, tmp_result_token, *p_verification_result_token_buffer_size);
        }
        else{
            if(tmp_result_token != NULL){
                free(tmp_result_token);
            }
            if(supp_data.p_data != NULL){
                free(supp_data.p_data);
            }
            return TEE_ERROR_OUT_OF_MEMORY;
        }
    }
    if(tmp_result_token != NULL){
        free(tmp_result_token);
    }
#else
    *p_verification_result_token = tmp_result_token;
#endif //SGX_TRUSTED

    if(supp_data.p_data != NULL){
        free(supp_data.p_data);
    }
    return dcap_ret;
}

#endif
#endif
