/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "PckParser/CrlStore.h"
#include "qve_logic.h"


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
    if (bytes.empty() ||
        bytes.size() < offsetof(verification_collateral_info_t, sa_list) ||
        bytes.size() > (offsetof(verification_collateral_info_t, sa_list) + MAX_SA_LIST_SIZE)) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    using Data = verification_collateral_info_t;

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

    info.tcb_date_min = parseBytesLE<decltype(Data::tcb_date_min)>(bytes.data(), offset);
    offset += sizeof(Data::tcb_date_min);

    for (size_t i = offset, j = 0; i < bytes.size(); ++i, ++j) {
        info.sa_list[j] = static_cast<char>(bytes[i]);
    }

    return SGX_QL_SUCCESS;
}
