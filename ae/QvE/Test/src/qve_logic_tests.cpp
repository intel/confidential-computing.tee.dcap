/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <gtest/gtest.h>
#include <cstdint>
#include <cstddef>
#include <vector>

#include "SgxEcdsaAttestation/QuoteVerification.h"
#include "SgxEcdsaAttestation/AttestationParsers.h"
#include "qve_logic.h"
#include "MockValidity.h"
#include "MockCertificate.h"
#include "MockCertificateChain.h"
#include "MockEnclaveIdentity.h"
#include "MockTcbInfo.h"
#include "MockCrlStore.h"

using namespace intel::sgx::dcap;
using namespace intel::sgx::dcap::parser;
using namespace intel::sgx::dcap::parser::x509;
using namespace intel::sgx::dcap::parser::json;
using namespace intel::sgx::dcap::pckparser;
using namespace testing;


TEST(QveUtilsTest, IsNonterminalError) {
    EXPECT_TRUE(is_nonterminal_error(STATUS_TCB_OUT_OF_DATE));
    EXPECT_TRUE(is_nonterminal_error(STATUS_SGX_TCB_INFO_EXPIRED));
    EXPECT_FALSE(is_nonterminal_error(static_cast<Status>(999))); // Unknown status
}

TEST(QveUtilsTest, IsExpirationError) {
    EXPECT_TRUE(is_expiration_error(STATUS_SGX_TCB_INFO_EXPIRED));
    EXPECT_TRUE(is_expiration_error(STATUS_SGX_PCK_CERT_CHAIN_EXPIRED));
    EXPECT_FALSE(is_expiration_error(STATUS_TCB_OUT_OF_DATE));
    EXPECT_FALSE(is_expiration_error(static_cast<Status>(999))); // Unknown status
}

TEST(StatusErrorToQlQveResultTest, ReturnsCorrectResult) {
    EXPECT_EQ(status_error_to_ql_qve_result(json::TcbStatus::UpToDate), SGX_QL_QV_RESULT_OK);
    EXPECT_EQ(status_error_to_ql_qve_result(json::TcbStatus::Revoked), SGX_QL_QV_RESULT_REVOKED);
    EXPECT_EQ(status_error_to_ql_qve_result(json::TcbStatus::OutOfDate), SGX_QL_QV_RESULT_OUT_OF_DATE);
    EXPECT_EQ(status_error_to_ql_qve_result(json::TcbStatus::OutOfDateConfigurationNeeded), SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED);
    EXPECT_EQ(status_error_to_ql_qve_result(json::TcbStatus::ConfigurationNeeded), SGX_QL_QV_RESULT_CONFIG_NEEDED);
    EXPECT_EQ(status_error_to_ql_qve_result(static_cast<json::TcbStatus>(-1)), SGX_QL_QV_RESULT_UNSPECIFIED);
}

TEST(ParseBytesLETest, ParseUint16) {
    // given
    uint8_t raw[] = {0x34, 0x12}; // Little-endian representation of 0x1234

    // when
    uint16_t result = parseBytesLE<uint16_t>(raw);

    // then
    EXPECT_EQ(result, 0x1234);
}

TEST(ParseBytesLETest, ParseUint32) {
    // given
    uint8_t raw[] = {0x78, 0x56, 0x34, 0x12}; // Little-endian representation of 0x12345678

    // when
    uint32_t result = parseBytesLE<uint32_t>(raw);

    // then
    EXPECT_EQ(result, 0x12345678);
}

TEST(ParseBytesLETest, ParseUint64) {
    // given
    uint8_t raw[] = {0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01}; // Little-endian representation of 0x0123456789ABCDEF

    // when
    uint64_t result = parseBytesLE<uint64_t>(raw);

    // then
    EXPECT_EQ(result, 0x0123456789ABCDEF);
}

TEST(ParseBytesLETest, ParseWithOffset) {
    // given
    uint8_t raw[] = {0x00, 0x00, 0x78, 0x56, 0x34, 0x12}; // Offset to 0x12345678

    // when
    uint32_t result = parseBytesLE<uint32_t>(raw, 2);

    // then
    EXPECT_EQ(result, 0x12345678);
}

TEST(DeserializeVerCollatInfoTest, ValidInput) {
    // given
    std::vector<uint8_t> input = {
            0x01, 0x00,                                        // id = 1
            0x02, 0x00,                                        // version = 2
            0x4A, 0x7E, 0xBE, 0x68, 0x00, 0x00, 0x00, 0x00,    // issue_date_min = 0x5ED460 (Unix timestamp)
            0x01, 0x88, 0xBE, 0x68, 0x00, 0x00, 0x00, 0x00,    // issue_date_max = 0x5ED470
            0x80, 0xD4, 0x5E, 0x00, 0x00, 0x00, 0x00, 0x00,    // expiration_date_min = 0x5ED480
            0x03, 0x00, 0x00, 0x00,                            // tcb_eval_data_num = 3
            0x90, 0xD4, 0x5E, 0x00, 0x00, 0x00, 0x00, 0x00,    // tcb_date_min = 0x5ED490
            'A', 'B', 'C', '\0',                               // sa_list = "ABC"
            0x00                                               // Padding for MAX_SA_LIST_SIZE
    };
    verification_collateral_info_t verification_collateral_info;

    // when
    quote3_error_t ret = deserializeVerCollatInfo(input, verification_collateral_info);

    // then
    EXPECT_EQ(ret, SGX_QL_SUCCESS);
    EXPECT_EQ(verification_collateral_info.id, 1);
    EXPECT_EQ(verification_collateral_info.version, 2);
    EXPECT_EQ(verification_collateral_info.issue_date_min, 0x68BE7E4A);
    EXPECT_EQ(verification_collateral_info.issue_date_max, 0x68BE8801);
    EXPECT_EQ(verification_collateral_info.expiration_date_min, 0x5ED480);
    EXPECT_EQ(verification_collateral_info.tcb_eval_data_num, 3);
    EXPECT_EQ(verification_collateral_info.tcb_date_min, 0x5ED490);
    EXPECT_STREQ(verification_collateral_info.sa_list, "ABC");
}

TEST(DeserializeVerCollatInfoTest, EmptyInput) {
    // given
    std::vector<uint8_t> input;
    verification_collateral_info_t verification_collateral_info;

    // when
    quote3_error_t ret = deserializeVerCollatInfo(input, verification_collateral_info);

    // then
    EXPECT_EQ(ret, SGX_QL_ERROR_INVALID_PARAMETER);
}

TEST(DeserializeVerCollatInfoTest, InsufficientData) {
    // given
    std::vector<uint8_t> input = {0x01, 0x00}; // Only partial data, `id` only.
    verification_collateral_info_t verification_collateral_info;

    // when
    quote3_error_t ret = deserializeVerCollatInfo(input, verification_collateral_info);

    // then
    EXPECT_EQ(ret, SGX_QL_ERROR_INVALID_PARAMETER);
}

TEST(DeserializeVerCollatInfoTest, DataTooLarge) {
    // given
    std::vector<uint8_t> input(offsetof(verification_collateral_info_t, sa_list) + MAX_SA_LIST_SIZE + 1, 0); // exceeds max size.
    verification_collateral_info_t verification_collateral_info;

    // when
    quote3_error_t ret = deserializeVerCollatInfo(input, verification_collateral_info);

    // then
    EXPECT_EQ(ret, SGX_QL_ERROR_INVALID_PARAMETER);
}

TEST(DeserializeVerCollatInfoTest, MaxSaListSize) {
    // given
    std::vector<uint8_t> input(offsetof(verification_collateral_info_t, sa_list) + MAX_SA_LIST_SIZE, 0);
    input[offsetof(verification_collateral_info_t, sa_list)] = 'X';
    input[offsetof(verification_collateral_info_t, sa_list) + MAX_SA_LIST_SIZE - 1] = '\0';
    verification_collateral_info_t verification_collateral_info;

    // when
    quote3_error_t ret = deserializeVerCollatInfo(input, verification_collateral_info);

    // then
    EXPECT_EQ(ret, SGX_QL_SUCCESS);
    EXPECT_EQ(verification_collateral_info.sa_list[0], 'X');
    EXPECT_EQ(verification_collateral_info.sa_list[MAX_SA_LIST_SIZE - 1], '\0');
}

TEST(GetEarliestIssueDateTest, EmptyChain) {
    // given
    MockCertificateChain certificate_chain_mock;
    EXPECT_CALL(certificate_chain_mock, getCerts()).WillOnce(Return(std::vector<std::shared_ptr<const Certificate>>{}));

    // when
    time_t result = getLatestIssueDate(certificate_chain_mock);

    // then
    EXPECT_EQ(result, 0);
}

TEST(GetEarliestIssueDateTest, SingleCertificate) {
    // given
    MockCertificateChain certificate_chain_mock;
    auto cert_mock = std::make_shared<MockCertificate>();
    MockValidity validity_mock;
    time_t not_before_time = 1735686000; // 2025-01-01 00:00:00 UTC

    EXPECT_CALL(*cert_mock, getValidity()).WillRepeatedly(ReturnRef(validity_mock));
    EXPECT_CALL(validity_mock, getNotBeforeTime()).WillRepeatedly(Return(not_before_time));
    EXPECT_CALL(certificate_chain_mock, getCerts()).WillOnce(Return(std::vector<std::shared_ptr<const ::Certificate>>{cert_mock}));

    // when
    time_t result = getLatestIssueDate(certificate_chain_mock);

    // then
    EXPECT_EQ(result, not_before_time);
}

TEST(GetEarliestIssueDateTest, MultipleCertificates) {
    // given
    MockCertificateChain certificate_chain_mock;
    auto cert_mock1 = std::make_shared<MockCertificate>();
    auto cert_mock2 = std::make_shared<MockCertificate>();
    auto cert_mock3 = std::make_shared<MockCertificate>();
    MockValidity validity_mock1;
    MockValidity validity_mock2;
    MockValidity validity_mock3;

    time_t not_before_earliest = 1735686000; // 2025-01-01 00:00:00 UTC
    time_t no_before_middle = 1751320800;   // 2025-07-01 00:00:00 UTC
    time_t not_before_latest = 1759269600;   // 2025-10-01 00:00:00 UTC

    EXPECT_CALL(*cert_mock1, getValidity()).WillRepeatedly(ReturnRef(validity_mock1));
    EXPECT_CALL(*cert_mock2, getValidity()).WillRepeatedly(ReturnRef(validity_mock2));
    EXPECT_CALL(*cert_mock3, getValidity()).WillRepeatedly(ReturnRef(validity_mock3));
    EXPECT_CALL(validity_mock1, getNotBeforeTime()).WillRepeatedly(Return(not_before_earliest));
    EXPECT_CALL(validity_mock2, getNotBeforeTime()).WillRepeatedly(Return(no_before_middle));
    EXPECT_CALL(validity_mock3, getNotBeforeTime()).WillRepeatedly(Return(not_before_latest));
    EXPECT_CALL(certificate_chain_mock, getCerts()).WillOnce(Return(std::vector<std::shared_ptr<const Certificate>>{cert_mock1, cert_mock2, cert_mock3}));

    // when
    time_t result = getEarliestIssueDate(certificate_chain_mock);

    // then
    EXPECT_EQ(result, not_before_earliest);
}

TEST(GetEarliestExpirationDateTest, EmptyChain) {
    // given
    MockCertificateChain certificate_chain_mock;
    EXPECT_CALL(certificate_chain_mock, getCerts()).WillOnce(Return(std::vector<std::shared_ptr<const Certificate>>{}));

    // when
    time_t result = getEarliestExpirationDate(certificate_chain_mock);

    // then
    EXPECT_EQ(result, 0);
}

TEST(GetEarliestExpirationDateTest, SingleCertificate) {
    // given
    MockCertificateChain certificate_chain_mock;
    auto cert = std::make_shared<MockCertificate>();
    MockValidity mockValidity;
    time_t notAfterTime = 1735686000; // 2025-01-01 00:00:00 UTC

    EXPECT_CALL(*cert, getValidity()).WillRepeatedly(ReturnRef(mockValidity));
    EXPECT_CALL(mockValidity, getNotAfterTime()).WillRepeatedly(Return(notAfterTime));
    EXPECT_CALL(certificate_chain_mock, getCerts()).WillOnce(Return(std::vector<std::shared_ptr<const Certificate>>{cert}));

    // when
    time_t result = getEarliestExpirationDate(certificate_chain_mock);

    // then
    EXPECT_EQ(result, notAfterTime);
}

TEST(GetEarliestExpirationDateTest, MultipleCertificates) {
    // given
    MockCertificateChain certificate_chain_mock;
    auto cert_mock1 = std::make_shared<MockCertificate>();
    auto cert_mock2 = std::make_shared<MockCertificate>();
    auto cert_mock3 = std::make_shared<MockCertificate>();
    MockValidity validity_mock1;
    MockValidity validity_mock2;
    MockValidity validity_mock3;

    time_t notAfterEarliest = 1735686000; // 2025-01-01 00:00:00 UTC
    time_t notAfterMiddle = 1751320800;   // 2025-07-01 00:00:00 UTC
    time_t notAfterLatest = 1759269600;   // 2025-10-01 00:00:00 UTC

    EXPECT_CALL(*cert_mock1, getValidity()).WillRepeatedly(ReturnRef(validity_mock1));
    EXPECT_CALL(*cert_mock2, getValidity()).WillRepeatedly(ReturnRef(validity_mock2));
    EXPECT_CALL(*cert_mock3, getValidity()).WillRepeatedly(ReturnRef(validity_mock3));
    EXPECT_CALL(validity_mock1, getNotAfterTime()).WillRepeatedly(Return(notAfterEarliest));
    EXPECT_CALL(validity_mock2, getNotAfterTime()).WillRepeatedly(Return(notAfterMiddle));
    EXPECT_CALL(validity_mock3, getNotAfterTime()).WillRepeatedly(Return(notAfterLatest));
    EXPECT_CALL(certificate_chain_mock, getCerts()).WillOnce(Return(std::vector<std::shared_ptr<const Certificate>>{cert_mock1, cert_mock2, cert_mock3}));

    // when
    time_t result = getEarliestExpirationDate(certificate_chain_mock);

    // then
    EXPECT_EQ(result, notAfterEarliest);
}

TEST(GetLatestIssueDateTest, EmptyChain) {
    // given
    MockCertificateChain certificate_chain_mock;
    EXPECT_CALL(certificate_chain_mock, getCerts()).WillOnce(Return(std::vector<std::shared_ptr<const Certificate>>{}));

    // when
    time_t result = getLatestIssueDate(certificate_chain_mock);

    // then
    EXPECT_EQ(result, 0);
}

TEST(GetLatestIssueDateTest, SingleCertificate) {
    // given
    MockCertificateChain certificate_chain_mock;
    auto cert = std::make_shared<MockCertificate>();
    MockValidity mockValidity;
    time_t notBeforeTime = 1735686000; // 2025-01-01 00:00:00 UTC

    EXPECT_CALL(*cert, getValidity()).WillRepeatedly(ReturnRef(mockValidity));
    EXPECT_CALL(mockValidity, getNotBeforeTime()).WillRepeatedly(Return(notBeforeTime));
    EXPECT_CALL(certificate_chain_mock, getCerts()).WillOnce(Return(std::vector<std::shared_ptr<const Certificate>>{cert}));

    // when
    time_t result = getLatestIssueDate(certificate_chain_mock);

    // then
    EXPECT_EQ(result, notBeforeTime);
}

TEST(GetLatestIssueDateTest, MultipleCertificates) {
    // given
    MockCertificateChain certificate_chain_mock;
    auto cert_mock1 = std::make_shared<MockCertificate>();
    auto cert_mock2 = std::make_shared<MockCertificate>();
    auto cert_mock3 = std::make_shared<MockCertificate>();
    MockValidity validity_mock1;
    MockValidity validity_mock2;
    MockValidity validity_mock3;

    time_t not_before_earliest = 1735686000; // 2025-01-01 00:00:00 UTC
    time_t not_before_middle = 1751320800;   // 2025-07-01 00:00:00 UTC
    time_t not_before_latest = 1759269600;   // 2025-10-01 00:00:00 UTC

    EXPECT_CALL(*cert_mock1, getValidity()).WillRepeatedly(ReturnRef(validity_mock1));
    EXPECT_CALL(*cert_mock2, getValidity()).WillRepeatedly(ReturnRef(validity_mock2));
    EXPECT_CALL(*cert_mock3, getValidity()).WillRepeatedly(ReturnRef(validity_mock3));
    EXPECT_CALL(validity_mock1, getNotBeforeTime()).WillRepeatedly(Return(not_before_earliest));
    EXPECT_CALL(validity_mock2, getNotBeforeTime()).WillRepeatedly(Return(not_before_middle));
    EXPECT_CALL(validity_mock3, getNotBeforeTime()).WillRepeatedly(Return(not_before_latest));
    EXPECT_CALL(certificate_chain_mock, getCerts()).WillOnce(Return(std::vector<std::shared_ptr<const Certificate>>{cert_mock1, cert_mock2, cert_mock3}));

    // when
    time_t result = getLatestIssueDate(certificate_chain_mock);

    // then
    EXPECT_EQ(result, not_before_latest);
}

class QveGetCollateralDates : public ::testing::Test {
protected:
    MockCertificateChain cert_chain_mock;
    MockTcbInfo tcb_info_mock;
    MockEnclaveIdentity qe_identity_mock;
    MockCertificateChain qe_identity_issuer_chain_mock;
    MockCertificateChain tcb_info_issuer_chain_mock;
    MockCertificateChain pck_crl_issuer_chain_mock;
    MockCrlStore root_ca_crl_store_mock;
    MockCrlStore pck_crl_store_mock;
    supplemental_dates_t supplemental_dates;

    void SetUp() override {
        // Initialize test data
        supplemental_dates = {};
    }
};

TEST_F(QveGetCollateralDates, UnsupportedEnclaveIdentityVersion_ReturnsError) {
    // given
    EXPECT_CALL(qe_identity_mock, getVersion()).WillOnce(Return(1)); // Unsupported version

    // when
    quote3_error_t result = qve_get_collateral_dates(
            cert_chain_mock,
            tcb_info_mock,
            qe_identity_mock,
            qe_identity_issuer_chain_mock,
            tcb_info_issuer_chain_mock,
            pck_crl_issuer_chain_mock,
            root_ca_crl_store_mock,
            pck_crl_store_mock,
            supplemental_dates
    );

    // then
    EXPECT_EQ(result, SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT);
}

TEST_F(QveGetCollateralDates, UnsupportedTcbInfoVersion_ReturnsError) {
    // given
    EXPECT_CALL(qe_identity_mock, getVersion()).WillOnce(Return(2));
    EXPECT_CALL(tcb_info_mock, getVersion()).WillOnce(Return(1)); // Unsupported version

    // when
    quote3_error_t result = qve_get_collateral_dates(
            cert_chain_mock,
            tcb_info_mock,
            qe_identity_mock,
            qe_identity_issuer_chain_mock,
            tcb_info_issuer_chain_mock,
            pck_crl_issuer_chain_mock,
            root_ca_crl_store_mock,
            pck_crl_store_mock,
            supplemental_dates
    );

    // then
    EXPECT_EQ(result, SGX_QL_TCBINFO_UNSUPPORTED_FORMAT);
}

TEST_F(QveGetCollateralDates, ValidInputs_ReturnsSuccess) {
    // given
    auto p_cert_chain_cert = std::make_shared<MockCertificate>();
    auto pck_crl_issuer_cert = std::make_shared<MockCertificate>();
    auto tcb_info_issuer_cert = std::make_shared<MockCertificate>();
    auto qe_identity_cert = std::make_shared<MockCertificate>();

    MockValidity cert_chain_cert_validity;
    MockValidity pck_crl_issuer_cert_validity;
    MockValidity tcb_info_issuer_cert_validity;
    MockValidity qe_identity_cert_validity;
    pckparser::Validity root_ca_crl_validity;
    pckparser::Validity pck_crl_validity;

    time_t p_cert_chain_cert_not_before = 1735686000; // 2025-01-01 00:00:00 UTC
    time_t p_cert_chain_cert_not_after = 1767222000;  // 2026-01-01 00:00:00 UTC
    time_t pck_crl_issuer_cert_not_before = 1738298000; // 2025-02-01 00:00:00 UTC
    time_t pck_crl_issuer_cert_not_after = 1769834000;  // 2026-02-01 00:00:00 UTC
    time_t tcb_info_issuer_cert_not_before = 1740976400; // 2025-03-01 00:00:00 UTC
    time_t tcb_info_issuer_cert_not_after = 1772512400;  // 2026-03-01 00:00:00 UTC
    time_t qe_identity_cert_not_before = 1743568400; // 2025-04-01 00:00:00 UTC
    time_t qe_identity_cert_not_after = 1775094400;  // 2026-04-01 00:00:00 UTC
    time_t tcb_info_issue_date = 1746150400; // 2025-05-01 00:00:00 UTC
    time_t tcb_info_next_update = 1777676400; // 2026-05-01 00:00:00 UTC
    time_t qe_identity_issue_date = 1748832000; // 2025-06-01 00:00:00 UTC
    time_t qe_identity_next_update = 1780358000; // 2026-06-01 00:00:00 UTC
    root_ca_crl_validity.notBeforeTime = 1733107200; // 2024-12-01 00:00:00 UTC
    root_ca_crl_validity.notAfterTime = 1791014400;  // 2027-12-01 00:00:00 UTC
    pck_crl_validity.notBeforeTime = 1735700400; // 2025-01-01 04:00:00 UTC
    pck_crl_validity.notAfterTime = 1767236400;  // 2026-01-01 04:00:00 UTC

    EXPECT_CALL(qe_identity_mock, getVersion()).WillOnce(Return(2));
    EXPECT_CALL(tcb_info_mock, getVersion()).WillOnce(Return(2));

    EXPECT_CALL(cert_chain_mock, getCerts()).WillRepeatedly(Return(std::vector<std::shared_ptr<const Certificate>>{p_cert_chain_cert}));
    EXPECT_CALL(pck_crl_issuer_chain_mock, getCerts()).WillRepeatedly(Return(std::vector<std::shared_ptr<const Certificate>>{pck_crl_issuer_cert}));
    EXPECT_CALL(tcb_info_issuer_chain_mock, getCerts()).WillRepeatedly(Return(std::vector<std::shared_ptr<const Certificate>>{tcb_info_issuer_cert}));
    EXPECT_CALL(qe_identity_issuer_chain_mock, getCerts()).WillRepeatedly(Return(std::vector<std::shared_ptr<const Certificate>>{qe_identity_cert}));

    EXPECT_CALL(*p_cert_chain_cert, getValidity()).WillRepeatedly(ReturnRef(cert_chain_cert_validity));
    EXPECT_CALL(*pck_crl_issuer_cert, getValidity()).WillRepeatedly(ReturnRef(pck_crl_issuer_cert_validity));
    EXPECT_CALL(*tcb_info_issuer_cert, getValidity()).WillRepeatedly(ReturnRef(tcb_info_issuer_cert_validity));
    EXPECT_CALL(*qe_identity_cert, getValidity()).WillRepeatedly(ReturnRef(qe_identity_cert_validity));

    EXPECT_CALL(root_ca_crl_store_mock, getValidity()).WillRepeatedly(ReturnRef(root_ca_crl_validity));
    EXPECT_CALL(pck_crl_store_mock, getValidity()).WillRepeatedly(ReturnRef(pck_crl_validity));

    EXPECT_CALL(cert_chain_cert_validity, getNotBeforeTime()).WillRepeatedly(Return(p_cert_chain_cert_not_before));
    EXPECT_CALL(cert_chain_cert_validity, getNotAfterTime()).WillRepeatedly(Return(p_cert_chain_cert_not_after));
    EXPECT_CALL(pck_crl_issuer_cert_validity, getNotBeforeTime()).WillRepeatedly(Return(pck_crl_issuer_cert_not_before));
    EXPECT_CALL(pck_crl_issuer_cert_validity, getNotAfterTime()).WillRepeatedly(Return(pck_crl_issuer_cert_not_after));
    EXPECT_CALL(tcb_info_issuer_cert_validity, getNotBeforeTime()).WillRepeatedly(Return(tcb_info_issuer_cert_not_before));
    EXPECT_CALL(tcb_info_issuer_cert_validity, getNotAfterTime()).WillRepeatedly(Return(tcb_info_issuer_cert_not_after));
    EXPECT_CALL(qe_identity_cert_validity, getNotBeforeTime()).WillRepeatedly(Return(qe_identity_cert_not_before));
    EXPECT_CALL(qe_identity_cert_validity, getNotAfterTime()).WillRepeatedly(Return(qe_identity_cert_not_after));

    EXPECT_CALL(tcb_info_mock, getIssueDate()).WillRepeatedly(Return(tcb_info_issue_date));
    EXPECT_CALL(tcb_info_mock, getNextUpdate()).WillRepeatedly(Return(tcb_info_next_update));
    EXPECT_CALL(qe_identity_mock, getIssueDate()).WillRepeatedly(Return(qe_identity_issue_date));
    EXPECT_CALL(qe_identity_mock, getNextUpdate()).WillRepeatedly(Return(qe_identity_next_update));


    // when
    quote3_error_t result = qve_get_collateral_dates(
            cert_chain_mock,
            tcb_info_mock,
            qe_identity_mock,
            qe_identity_issuer_chain_mock,
            tcb_info_issuer_chain_mock,
            pck_crl_issuer_chain_mock,
            root_ca_crl_store_mock,
            pck_crl_store_mock,
            supplemental_dates
    );

    // then
    EXPECT_EQ(result, SGX_QL_SUCCESS);
    EXPECT_EQ(supplemental_dates.earliest_issue_date, 1733107200);
    EXPECT_EQ(supplemental_dates.earliest_expiration_date, 1767222000);
    EXPECT_EQ(supplemental_dates.latest_issue_date, 1748832000);
    EXPECT_EQ(supplemental_dates.qe_iden_earliest_issue_date, 1743568400);
    EXPECT_EQ(supplemental_dates.qe_iden_latest_issue_date, 1748832000);
    EXPECT_EQ(supplemental_dates.qe_iden_earliest_expiration_date, 1775094400);
}
