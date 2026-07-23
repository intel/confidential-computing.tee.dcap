/*
 * Copyright(c) 2025-2026 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifdef SERVTD_ATTEST
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wredundant-decls"  // FIXME(pre-existing): mbsnrtowcs()/wcsnrtombs() decls in CrlStore.h conflict with std headers under servtd_attest
#endif
#include "PckParser/CrlStore.h"
#ifdef SERVTD_ATTEST
#pragma GCC diagnostic pop
#endif
#include "qve_logic.h"

namespace {
    constexpr uint32_t kTcbComponentLen = 16;
}

time_t getEarliestIssueDate(const CertificateChain &chain) {
    auto certs = chain.getCerts();
    auto comp_certs_issue_date = [](const std::shared_ptr<const Certificate> &ca, const std::shared_ptr<const Certificate> &cb) {
        return ca->getValidity().getNotBeforeTime() < cb->getValidity().getNotBeforeTime();
    };
    return (certs.empty()) ? time_t{0} : (*std::min_element(certs.begin(), certs.end(), comp_certs_issue_date))->getValidity().getNotBeforeTime();
}

time_t getLatestIssueDate(const CertificateChain &chain) {
    auto certs = chain.getCerts();
    auto comp_certs_issue_date = [](const std::shared_ptr<const Certificate> &ca, const std::shared_ptr<const Certificate> &cb) {
        return ca->getValidity().getNotBeforeTime() < cb->getValidity().getNotBeforeTime();
    };
    return (certs.empty()) ? time_t{0} : (*std::max_element(certs.begin(), certs.end(), comp_certs_issue_date))->getValidity().getNotBeforeTime();
}

time_t getEarliestExpirationDate(const CertificateChain &chain) {
    auto certs = chain.getCerts();
    auto comp_certs_exp_date = [](const std::shared_ptr<const Certificate> &ca, const std::shared_ptr<const Certificate> &cb) {
        return ca->getValidity().getNotAfterTime() < cb->getValidity().getNotAfterTime();
    };
    return (certs.empty()) ? time_t{0} : (*std::min_element(certs.begin(), certs.end(), comp_certs_exp_date))->getValidity().getNotAfterTime();
}

quote3_error_t qve_get_collateral_dates(const CertificateChain &cert_chain_obj,
                                        const json::TcbInfo &tcb_info_obj,
                                        const json::EnclaveIdentity &qe_identity_obj,
                                        const CertificateChain &qe_identity_issuer_chain,
                                        const CertificateChain &tcb_info_issuer_chain,
                                        const CertificateChain &pck_crl_issuer_chain,
                                        const CrlStore &root_ca_crl_store,
                                        const CrlStore &pck_crl_store,
                                        supplemental_dates_t &supplemental_dates) {

    //supports only EnclaveIdentity V2 and V3
    //
    uint32_t version = qe_identity_obj.getVersion();
    if (version != 2 && version != 3) {
        return SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT;
    }

    //supports only TCBInfo V2 and V3
    //
    version = tcb_info_obj.getVersion();
    if (version != 2 && version != 3) {
        return SGX_QL_TCBINFO_UNSUPPORTED_FORMAT;
    }

    std::array <time_t, NUMBER_OF_DATES_TO_COMPARE> earliest_issue;
    std::array <time_t, NUMBER_OF_DATES_TO_COMPARE> earliest_expiration;
    std::array <time_t, NUMBER_OF_DATES_TO_COMPARE> latest_issue;

    earliest_issue[0] = root_ca_crl_store.getValidity().notBeforeTime;
    earliest_issue[1] = pck_crl_store.getValidity().notBeforeTime;
    earliest_issue[2] = getEarliestIssueDate(pck_crl_issuer_chain);
    earliest_issue[3] = getEarliestIssueDate(cert_chain_obj);
    earliest_issue[4] = getEarliestIssueDate(tcb_info_issuer_chain);
    earliest_issue[5] = getEarliestIssueDate(qe_identity_issuer_chain);
    earliest_issue[6] = tcb_info_obj.getIssueDate();
    earliest_issue[7] = qe_identity_obj.getIssueDate();

    earliest_expiration[0] = root_ca_crl_store.getValidity().notAfterTime;
    earliest_expiration[1] = pck_crl_store.getValidity().notAfterTime;
    earliest_expiration[2] = getEarliestExpirationDate(pck_crl_issuer_chain);
    earliest_expiration[3] = getEarliestExpirationDate(cert_chain_obj);
    earliest_expiration[4] = getEarliestExpirationDate(tcb_info_issuer_chain);
    earliest_expiration[5] = getEarliestExpirationDate(qe_identity_issuer_chain);
    earliest_expiration[6] = tcb_info_obj.getNextUpdate();
    earliest_expiration[7] = qe_identity_obj.getNextUpdate();

    latest_issue[0] = root_ca_crl_store.getValidity().notBeforeTime;
    latest_issue[1] = pck_crl_store.getValidity().notBeforeTime;
    latest_issue[2] = getLatestIssueDate(pck_crl_issuer_chain);
    latest_issue[3] = getLatestIssueDate(cert_chain_obj);
    latest_issue[4] = getLatestIssueDate(tcb_info_issuer_chain);
    latest_issue[5] = getLatestIssueDate(qe_identity_issuer_chain);
    latest_issue[6] = tcb_info_obj.getIssueDate();
    latest_issue[7] = qe_identity_obj.getIssueDate();

    supplemental_dates.earliest_issue_date = *std::min_element(earliest_issue.begin(), earliest_issue.end());
    supplemental_dates.earliest_expiration_date = *std::min_element(earliest_expiration.begin(), earliest_expiration.end());
    supplemental_dates.latest_issue_date = *std::max_element(latest_issue.begin(), latest_issue.end());

    // 5th element contains dates from QE Identity Issuer chain
    supplemental_dates.qe_iden_earliest_issue_date = (earliest_issue[5] < qe_identity_obj.getIssueDate()) ? earliest_issue[5] : qe_identity_obj.getIssueDate();
    supplemental_dates.qe_iden_latest_issue_date = (latest_issue[5] > qe_identity_obj.getIssueDate()) ? latest_issue[5] : qe_identity_obj.getIssueDate();
    supplemental_dates.qe_iden_earliest_expiration_date = (earliest_expiration[5] < qe_identity_obj.getNextUpdate()) ? earliest_expiration[5] : qe_identity_obj.getNextUpdate();

    if (supplemental_dates.earliest_issue_date == 0 ||
        supplemental_dates.earliest_expiration_date == 0 ||
        supplemental_dates.latest_issue_date == 0 ||
        supplemental_dates.qe_iden_earliest_issue_date == 0 ||
        supplemental_dates.qe_iden_latest_issue_date == 0 ||
        supplemental_dates.qe_iden_earliest_expiration_date == 0) {
        return SGX_QL_ERROR_UNEXPECTED;
    }

    return SGX_QL_SUCCESS;
}

quote3_error_t deserializeVerCollatInfo(const std::vector<uint8_t> &bytes, verification_collateral_info_t &info) {
    // The v2 verification collateral info is a fixed-size record. The producer
    // emits at least sizeof(verification_collateral_info_t) bytes; any trailing
    // bytes beyond the record are ignored.
    if (bytes.empty() ||
        bytes.size() < sizeof(verification_collateral_info_t)) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    using Data = verification_collateral_info_t;

    // Helper to copy a fixed-size char array field from the byte buffer.
    // Always forces a NUL terminator in the last byte so later use as a
    // C-string cannot over-read past the field if the serialized data lacks
    // a terminator.
    auto copyCharField = [&bytes](char *dst, size_t size, size_t offset) {
        for (size_t i = 0; i < size; ++i) {
            dst[i] = static_cast<char>(bytes[offset + i]);
        }
        dst[size - 1] = '\0';
    };

    info.id = parseBytesLE<decltype(Data::id)>(bytes.data());
    size_t offset = sizeof(Data::id);

    info.version = parseBytesLE<decltype(Data::version)>(bytes.data(), offset);
    offset += sizeof(Data::version);

    info.issue_date_min = parseBytesLE<decltype(Data::issue_date_min)>(bytes.data(), offset);
    offset += sizeof(Data::issue_date_min);

    info.issue_date_max = parseBytesLE<decltype(Data::issue_date_max)>(bytes.data(), offset);
    offset += sizeof(Data::issue_date_max);

    info.expiration_date_min = parseBytesLE<decltype(Data::expiration_date_min)>(bytes.data(), offset);
    offset += sizeof(Data::expiration_date_min);

    info.tcb_eval_data_num = parseBytesLE<decltype(Data::tcb_eval_data_num)>(bytes.data(), offset);
    offset += sizeof(Data::tcb_eval_data_num);

    info.launch_tcb_date = parseBytesLE<decltype(Data::launch_tcb_date)>(bytes.data(), offset);
    offset += sizeof(Data::launch_tcb_date);

    info.current_tcb_date = parseBytesLE<decltype(Data::current_tcb_date)>(bytes.data(), offset);
    offset += sizeof(Data::current_tcb_date);

    copyCharField(info.launch_advisory_ids, sizeof(Data::launch_advisory_ids), offset);
    offset += sizeof(Data::launch_advisory_ids);

    copyCharField(info.current_advisory_ids, sizeof(Data::current_advisory_ids), offset);
    offset += sizeof(Data::current_advisory_ids);

    copyCharField(info.launch_tcb_status, sizeof(Data::launch_tcb_status), offset);
    offset += sizeof(Data::launch_tcb_status);

    copyCharField(info.current_tcb_status, sizeof(Data::current_tcb_status), offset);
    offset += sizeof(Data::current_tcb_status);

    return SGX_QL_SUCCESS;
}

bool isTdxTcbHigherOrEqual(const Quote& quote,
                           const parser::json::TcbLevel& tcbLevel)
{
    const auto& teeTcbSvn = quote.getTeeTcbSvn();
    uint32_t index = 0;
    if (quote.getHeader().version > intel::sgx::dcap::constants::QUOTE_VERSION_3 && teeTcbSvn[1] > 0)
    {
        index = 2;
    }
    for(; index < kTcbComponentLen; ++index)
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

bool isTcbComponentSvnHigherOrEqual(const parser::x509::PckCertificate& pckCert,
                           const parser::json::TcbLevel& tcbLevel)
{
    for(uint32_t index = 0; index < kTcbComponentLen; ++index)
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
                quote.getHeader().teeType == intel::sgx::dcap::constants::TEE_TYPE_TDX)
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

    throw SGX_QL_TCBINFO_UNSUPPORTED_FORMAT;  // FIXME(pre-existing): throws raw quote3_error_t, not a descendant of std::exception
}
