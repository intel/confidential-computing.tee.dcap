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

#include "tdx_verify.h"
#include "servtd_com.h"
#include "servtd_external.h"
#include "qgs_msg_lib.h"

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#ifdef SERVTD_ATTEST
#include <mbusafecrt.h>  //For strncpy_s 
#endif

tdx_verify_error_t tdx_att_get_collateral(
        const uint8_t *fmspc, uint16_t fmspc_size, const char *pck_ca,
        tdx_ql_qve_collateral_t **pp_verification_collateral)
{
    uint32_t in_msg_size = 0;
    tdx_verify_error_t ret = TDX_VERIFY_ERROR_UNEXPECTED;
    struct servtd_tdx_quote_hdr *p_get_quote_blob = NULL;
    uint8_t *p_blob_payload = NULL;
    uint32_t msg_size = 0;
    int servtd_get_collateral_ret = 0;
    qgs_msg_error_t qgs_msg_ret = QGS_MSG_SUCCESS;
    qgs_msg_header_t *p_header = NULL;
    uint8_t *p_req = NULL;
    uint16_t major_version = 0;
    uint16_t minor_version = 0;
    uint32_t tee_type = 0x81;
    const uint8_t *p_pck_crl_issuer_chain = NULL;
    uint32_t pck_crl_issuer_chain_size;
    const uint8_t *p_root_ca_crl = NULL;
    uint32_t root_ca_crl_size = 0;
    const uint8_t *p_pck_crl = NULL;
    uint32_t pck_crl_size = 0;
    const uint8_t *p_tcb_info_issuer_chain = NULL;
    uint32_t tcb_info_issuer_chain_size = 0;
    const uint8_t *p_tcb_info = NULL;
    uint32_t tcb_info_size = 0;
    const uint8_t *p_qe_identity_issuer_chain = NULL;
    uint32_t qe_identity_issuer_chain_size = 0;
    const uint8_t *p_qe_identity = NULL;
    uint32_t qe_identity_size = 0;

    if (NULL == fmspc || 0 == fmspc_size || NULL == pck_ca || NULL == pp_verification_collateral) {
        ret = TDX_VERIFY_ERROR_INVALID_PARAMETER;
        return ret;
    }

    p_get_quote_blob = (struct servtd_tdx_quote_hdr *)malloc(SERVTD_REQ_BUF_SIZE);
    if (!p_get_quote_blob) {
        ret = TDX_VERIFY_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }
    
    qgs_msg_ret = qgs_msg_gen_get_collateral_req(fmspc, (uint32_t)fmspc_size,
        (const uint8_t *)pck_ca, (uint32_t)strlen(pck_ca) + 1, &p_req, &msg_size);
    if (QGS_MSG_SUCCESS != qgs_msg_ret) {
        ret = TDX_VERIFY_ERROR_UNEXPECTED;
        goto ret_point;
    }

    if (msg_size > SERVTD_REQ_BUF_SIZE - sizeof(struct servtd_tdx_quote_hdr) - SERVTD_HEADER_SIZE) {
        ret = TDX_VERIFY_ERROR_NOT_SUPPORTED;
        goto ret_point;
    }

    p_blob_payload = (uint8_t *)&p_get_quote_blob->data;
    p_blob_payload[0] = (uint8_t)((msg_size >> 24) & 0xFF);
    p_blob_payload[1] = (uint8_t)((msg_size >> 16) & 0xFF);
    p_blob_payload[2] = (uint8_t)((msg_size >> 8) & 0xFF);
    p_blob_payload[3] = (uint8_t)(msg_size & 0xFF);

    // Serialization
    memcpy(p_blob_payload + SERVTD_HEADER_SIZE, p_req, msg_size);

    p_get_quote_blob->version = 1;
    p_get_quote_blob->status = 0;
    p_get_quote_blob->in_len = SERVTD_HEADER_SIZE + msg_size;
    p_get_quote_blob->out_len = 0;

    servtd_get_collateral_ret = servtd_get_quote(p_get_quote_blob, SERVTD_REQ_BUF_SIZE);
    if (servtd_get_collateral_ret) {
        ret = TDX_VERIFY_ERROR_QUOTE_FAILURE;
        goto ret_point;
    }

    /* VMM-authored: upper-bound out_len against the trusted allocation before any
     * derived arithmetic.  Check status and lower bound first, then upper bound. */
    if (p_get_quote_blob->status
        || p_get_quote_blob->out_len <= SERVTD_HEADER_SIZE) {
        if (GET_QUOTE_IN_FLIGHT == p_get_quote_blob->status) {
            ret = TDX_VERIFY_ERROR_BUSY;
        } else if (GET_QUOTE_SERVICE_UNAVAILABLE == p_get_quote_blob->status) {
            ret = TDX_VERIFY_ERROR_NOT_SUPPORTED;
        } else {
            ret = TDX_VERIFY_ERROR_UNEXPECTED;
        }
        goto ret_point;
    }

    if (p_get_quote_blob->out_len >
            SERVTD_REQ_BUF_SIZE - sizeof(struct servtd_tdx_quote_hdr)) {
        ret = TDX_VERIFY_ERROR_UNEXPECTED;
        goto ret_point;
    }

    /* Derive in_msg_size from the trusted out_len (not from the VMM-written
     * 4-byte header which was previously computed and then immediately discarded). */
    in_msg_size = (uint32_t)p_get_quote_blob->out_len - SERVTD_HEADER_SIZE;

    qgs_msg_ret = qgs_msg_inflate_get_collateral_resp(
        p_blob_payload + SERVTD_HEADER_SIZE, in_msg_size,
        &major_version, &minor_version, 
        &p_pck_crl_issuer_chain, &pck_crl_issuer_chain_size,
        &p_root_ca_crl, &root_ca_crl_size,
        &p_pck_crl, &pck_crl_size,
        &p_tcb_info_issuer_chain, &tcb_info_issuer_chain_size,
        &p_tcb_info, &tcb_info_size,
        &p_qe_identity_issuer_chain, &qe_identity_issuer_chain_size,
        &p_qe_identity, &qe_identity_size);
    if (QGS_MSG_SUCCESS != qgs_msg_ret) {
        ret = TDX_VERIFY_ERROR_UNEXPECTED;
        goto ret_point;
    }

    // We've called qgs_msg_inflate_get_collateral_resp, the message type should be GET_COLLATERAL_RESP
    p_header = (qgs_msg_header_t *)(p_blob_payload + SERVTD_HEADER_SIZE);
    if (p_header->error_code != 0) {
        ret = TDX_VERIFY_ERROR_UNEXPECTED;
        goto ret_point;
    }

    // sizeof(tdx_ql_qve_collateral_t) + 
    (*pp_verification_collateral) = (tdx_ql_qve_collateral_t *)malloc(sizeof(tdx_ql_qve_collateral_t));
    if (NULL == (*pp_verification_collateral))
    {
        ret = TDX_VERIFY_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }
    memset_s(*pp_verification_collateral, sizeof(tdx_ql_qve_collateral_t), 0, sizeof(tdx_ql_qve_collateral_t));

    // major_version
    (*pp_verification_collateral)->major_version = major_version;

    // minor_version
    (*pp_verification_collateral)->minor_version = minor_version;

    // TBD: tee_type is not passed
    (*pp_verification_collateral)->tee_type = tee_type;

    // pck_crl_issuer_chain
    (*pp_verification_collateral)->pck_crl_issuer_chain = (char *)malloc(pck_crl_issuer_chain_size);
    if (NULL == (*pp_verification_collateral)->pck_crl_issuer_chain)
    {
        ret = TDX_VERIFY_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }

    // FIXME(pre-existing): strncpy_s(dest, size, src, size) with destsz==count is technically
    // a C11 Annex K constraint violation (count should be destsz-1). In practice this is safe:
    // QCNL allocate_and_copy() NUL-terminates all buffers and sizes include the NUL (the
    // combined buffers use embedded '\0' separators which survive QPL split_buffer()). So
    // strncpy_s hits the NUL before reaching count==destsz. Ideally should use memcpy_s.
    // The (const char *) cast on p_* is benign — data originates as char* PEM/JSON in QPL,
    // round-trips through QGS message layer as uint8_t*.
    strncpy_s((*pp_verification_collateral)->pck_crl_issuer_chain,
            pck_crl_issuer_chain_size,
            (const char *)p_pck_crl_issuer_chain,
            pck_crl_issuer_chain_size);
    (*pp_verification_collateral)->pck_crl_issuer_chain_size = pck_crl_issuer_chain_size;

    // root_ca_crl
    (*pp_verification_collateral)->root_ca_crl = (char *)malloc(root_ca_crl_size);
    if (NULL == (*pp_verification_collateral)->root_ca_crl)
    {
        ret = TDX_VERIFY_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }
    strncpy_s((*pp_verification_collateral)->root_ca_crl,
            root_ca_crl_size,
            (const char *)p_root_ca_crl,  // FIXME: <--Same strncpy_s caveat as above
            root_ca_crl_size);
    (*pp_verification_collateral)->root_ca_crl_size = root_ca_crl_size;

    // pck_crl
    (*pp_verification_collateral)->pck_crl = (char *)malloc(pck_crl_size);
    if (NULL == (*pp_verification_collateral)->pck_crl)
    {
        ret = TDX_VERIFY_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }
    strncpy_s((*pp_verification_collateral)->pck_crl,
            pck_crl_size,
            (const char *)p_pck_crl,  // FIXME: <--Same strncpy_s caveat as above
            pck_crl_size);
    (*pp_verification_collateral)->pck_crl_size = pck_crl_size;

    // tcb_info_issuer_chain
    (*pp_verification_collateral)->tcb_info_issuer_chain = (char *)malloc(tcb_info_issuer_chain_size);
    if (NULL == (*pp_verification_collateral)->tcb_info_issuer_chain)
    {
        ret = TDX_VERIFY_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }
    strncpy_s((*pp_verification_collateral)->tcb_info_issuer_chain,
            tcb_info_issuer_chain_size,
            (const char *)p_tcb_info_issuer_chain,  // FIXME: <--Same strncpy_s caveat as above
            tcb_info_issuer_chain_size);
    (*pp_verification_collateral)->tcb_info_issuer_chain_size = tcb_info_issuer_chain_size;
    
    // tcb_info
    (*pp_verification_collateral)->tcb_info = (char *)malloc(tcb_info_size);
    if (NULL == (*pp_verification_collateral)->tcb_info)
    {
        ret = TDX_VERIFY_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }
    strncpy_s((*pp_verification_collateral)->tcb_info,
            tcb_info_size,
            (const char *)p_tcb_info,  // FIXME: <--Same strncpy_s caveat as above
            tcb_info_size);
    (*pp_verification_collateral)->tcb_info_size = tcb_info_size;

    // qe_identity_issuer_chain
    (*pp_verification_collateral)->qe_identity_issuer_chain = (char *)malloc(qe_identity_issuer_chain_size);
    if (NULL == (*pp_verification_collateral)->qe_identity_issuer_chain)
    {
        ret = TDX_VERIFY_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }
    strncpy_s((*pp_verification_collateral)->qe_identity_issuer_chain,
            qe_identity_issuer_chain_size,
            (const char *)p_qe_identity_issuer_chain,  // FIXME: <--Same strncpy_s caveat as above
            qe_identity_issuer_chain_size);
    (*pp_verification_collateral)->qe_identity_issuer_chain_size = qe_identity_issuer_chain_size;
    
    // qe_identity
    (*pp_verification_collateral)->qe_identity = (char *)malloc(qe_identity_size);
    if (NULL == (*pp_verification_collateral)->qe_identity)
    {
        ret = TDX_VERIFY_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }
    strncpy_s((*pp_verification_collateral)->qe_identity,
            qe_identity_size,
            (const char *)p_qe_identity,
            qe_identity_size);
    (*pp_verification_collateral)->qe_identity_size = qe_identity_size;

    ret = TDX_VERIFY_SUCCESS;

ret_point:
    qgs_msg_free(p_req);
    SAFE_FREE(p_get_quote_blob);

    if ((ret != TDX_VERIFY_SUCCESS) && (NULL != pp_verification_collateral) && (NULL != (*pp_verification_collateral)))
    {
        SAFE_FREE((*pp_verification_collateral)->pck_crl_issuer_chain);
        SAFE_FREE((*pp_verification_collateral)->root_ca_crl);
        SAFE_FREE((*pp_verification_collateral)->pck_crl);
        SAFE_FREE((*pp_verification_collateral)->tcb_info_issuer_chain);
        SAFE_FREE((*pp_verification_collateral)->tcb_info);
        SAFE_FREE((*pp_verification_collateral)->qe_identity_issuer_chain);
        SAFE_FREE((*pp_verification_collateral)->qe_identity);
        SAFE_FREE(*pp_verification_collateral);
    }
    return ret;
}


tdx_verify_error_t tdx_att_free_collateral(
    tdx_ql_qve_collateral_t *p_verification_collateral)
{
    if (p_verification_collateral)
    {
        SAFE_FREE(p_verification_collateral->pck_crl_issuer_chain);
        SAFE_FREE(p_verification_collateral->root_ca_crl);
        SAFE_FREE(p_verification_collateral->pck_crl);
        SAFE_FREE(p_verification_collateral->tcb_info_issuer_chain);
        SAFE_FREE(p_verification_collateral->tcb_info);
        SAFE_FREE(p_verification_collateral->qe_identity_issuer_chain);
        SAFE_FREE(p_verification_collateral->qe_identity);
        SAFE_FREE(p_verification_collateral);
    }
    return TDX_VERIFY_SUCCESS;
}
