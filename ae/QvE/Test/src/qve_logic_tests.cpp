/*
 * Copyright(c) 2025-2026 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <gtest/gtest.h>
#include <cstdint>
#include <cstddef>
#include <vector>

#include "SgxEcdsaAttestation/QuoteVerification.h"
#include "SgxEcdsaAttestation/AttestationParsers.h"
#include "qve_logic.h"
#include "QuoteVerification/QuoteConstants.h"
#include "QuoteVerification/Quote.h"
#include "QuoteVerification/QuoteStructures.h"
#include "MockValidity.h"
#include "MockCertificate.h"
#include "MockCertificateChain.h"
#include "MockEnclaveIdentity.h"
#include "MockTcbInfo.h"
#include "MockCrlStore.h"
#include "MockPckCertificate.h"
#include "mock/TestQuote.h"

using namespace intel::sgx::dcap;
using namespace intel::sgx::dcap::constants;
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

TEST(TcbStatusStringToQlQveResultTest, MapsKnownStrings) {
    EXPECT_EQ(tcb_status_string_to_ql_qve_result("UpToDate"), SGX_QL_QV_RESULT_OK);
    EXPECT_EQ(tcb_status_string_to_ql_qve_result("OutOfDate"), SGX_QL_QV_RESULT_OUT_OF_DATE);
    EXPECT_EQ(tcb_status_string_to_ql_qve_result("OutOfDateConfigurationNeeded"), SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED);
    EXPECT_EQ(tcb_status_string_to_ql_qve_result("ConfigurationNeeded"), SGX_QL_QV_RESULT_CONFIG_NEEDED);
    EXPECT_EQ(tcb_status_string_to_ql_qve_result("ConfigurationAndSWHardeningNeeded"), SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED);
    EXPECT_EQ(tcb_status_string_to_ql_qve_result("SWHardeningNeeded"), SGX_QL_QV_RESULT_SW_HARDENING_NEEDED);
    EXPECT_EQ(tcb_status_string_to_ql_qve_result("Revoked"), SGX_QL_QV_RESULT_REVOKED);
    EXPECT_EQ(tcb_status_string_to_ql_qve_result("TDRelaunchAdvised"), TEE_QV_RESULT_TD_RELAUNCH_ADVISED);
    EXPECT_EQ(tcb_status_string_to_ql_qve_result("TDRelaunchAdvisedConfigurationNeeded"), TEE_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED);
}

TEST(TcbStatusStringToQlQveResultTest, NullReturnsUnspecified) {
    EXPECT_EQ(tcb_status_string_to_ql_qve_result(nullptr), SGX_QL_QV_RESULT_UNSPECIFIED);
}

TEST(TcbStatusStringToQlQveResultTest, UnknownOrMiscasedReturnsUnspecified) {
    EXPECT_EQ(tcb_status_string_to_ql_qve_result(""), SGX_QL_QV_RESULT_UNSPECIFIED);
    EXPECT_EQ(tcb_status_string_to_ql_qve_result("uptodate"), SGX_QL_QV_RESULT_UNSPECIFIED); // case-sensitive
    EXPECT_EQ(tcb_status_string_to_ql_qve_result("NotAStatus"), SGX_QL_QV_RESULT_UNSPECIFIED);
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
    std::vector<uint8_t> input(sizeof(verification_collateral_info_t), 0);
    size_t off = 0;
    auto put16 = [&](uint16_t v){ for (int i = 0; i < 2; ++i) input[off + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xff); off += 2; };
    auto put32 = [&](uint32_t v){ for (int i = 0; i < 4; ++i) input[off + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xff); off += 4; };
    // Time fields are serialized as sizeof(time_t) bytes; match that here so
    // the buffer layout stays correct on platforms where time_t isn't 8 bytes.
    auto putTime = [&](uint64_t v){ for (size_t i = 0; i < sizeof(time_t); ++i) input[off + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xff); off += sizeof(time_t); };
    auto putStr = [&](const char* s, size_t field){ for (size_t i = 0; i < field && s[i] != '\0'; ++i) input[off + i] = static_cast<uint8_t>(s[i]); off += field; };

    put16(1);            // id
    put16(2);            // version
    putTime(0x68BE7E4A); // issue_date_min
    putTime(0x68BE8801); // issue_date_max
    putTime(0x5ED480);   // expiration_date_min
    put32(3);            // tcb_eval_data_num
    putTime(0x5ED490);   // launch_tcb_date
    putTime(0x5ED4A0);   // current_tcb_date
    putStr("ABC", VER_COLLAT_ADVISORY_IDS_SIZE);      // launch_advisory_ids
    putStr("DEF", VER_COLLAT_ADVISORY_IDS_SIZE);      // current_advisory_ids
    putStr("UpToDate", VER_COLLAT_TCB_STATUS_SIZE);   // launch_tcb_status
    putStr("OutOfDate", VER_COLLAT_TCB_STATUS_SIZE);  // current_tcb_status

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
    EXPECT_EQ(verification_collateral_info.launch_tcb_date, 0x5ED490);
    EXPECT_EQ(verification_collateral_info.current_tcb_date, 0x5ED4A0);
    EXPECT_STREQ(verification_collateral_info.launch_advisory_ids, "ABC");
    EXPECT_STREQ(verification_collateral_info.current_advisory_ids, "DEF");
    EXPECT_STREQ(verification_collateral_info.launch_tcb_status, "UpToDate");
    EXPECT_STREQ(verification_collateral_info.current_tcb_status, "OutOfDate");
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

TEST(DeserializeVerCollatInfoTest, ExtraTrailingBytesIgnored) {
    // given: buffer larger than the fixed-size record; trailing bytes are ignored.
    std::vector<uint8_t> input(sizeof(verification_collateral_info_t) + 16, 0);
    verification_collateral_info_t verification_collateral_info;

    // when
    quote3_error_t ret = deserializeVerCollatInfo(input, verification_collateral_info);

    // then
    EXPECT_EQ(ret, SGX_QL_SUCCESS);
}

TEST(DeserializeVerCollatInfoTest, AdvisoryIdsBoundary) {
    // given: exact-size buffer with content at the current_advisory_ids boundaries.
    std::vector<uint8_t> input(sizeof(verification_collateral_info_t), 0);
    const size_t currentAdvOffset = offsetof(verification_collateral_info_t, current_advisory_ids);
    input[currentAdvOffset] = 'X';
    input[currentAdvOffset + VER_COLLAT_ADVISORY_IDS_SIZE - 1] = '\0';
    verification_collateral_info_t verification_collateral_info;

    // when
    quote3_error_t ret = deserializeVerCollatInfo(input, verification_collateral_info);

    // then
    EXPECT_EQ(ret, SGX_QL_SUCCESS);
    EXPECT_EQ(verification_collateral_info.current_advisory_ids[0], 'X');
    EXPECT_EQ(verification_collateral_info.current_advisory_ids[VER_COLLAT_ADVISORY_IDS_SIZE - 1], '\0');
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

TEST(getEarlierDateTest, ReturnsOlderDate) {
    // Test when date1 is older
    time_t date1 = 1735686000; // 2025-01-01 00:00:00 UTC
    time_t date2 = 1767222000; // 2026-01-01 00:00:00 UTC
    EXPECT_EQ(getEarlierDate(date1, date2), date1);

    // Test when date2 is older
    EXPECT_EQ(getEarlierDate(date2, date1), date1);

    // Test with very close dates (1 second difference)
    time_t date3 = 1735686001; // 2025-01-01 00:00:01 UTC
    EXPECT_EQ(getEarlierDate(date1, date3), date1);
}

TEST(getEarlierDateTest, HandlesEqualDates) {
    time_t date = 1735686000; // 2025-01-01 00:00:00 UTC
    EXPECT_EQ(getEarlierDate(date, date), date);
}

TEST(getEarlierDateTest, HandlesZeroValues) {
    time_t date = 1735686000; // 2025-01-01 00:00:00 UTC
    time_t zero_date = 0;

    // Test with date1 as zero
    EXPECT_EQ(getEarlierDate(zero_date, date), zero_date);

    // Test with date2 as zero
    EXPECT_EQ(getEarlierDate(date, zero_date), zero_date);

    // Test with both dates as zero
    EXPECT_EQ(getEarlierDate(zero_date, zero_date), zero_date);
}

// Unit tests for isTdxTcbHigherOrEqual
TEST(IsTdxTcbHigherOrEqualTest, AllComponentsEqual) {
    // given: Quote with all TDX TCB components equal to TcbLevel components
    TestQuote quote;
    quote.setHeaderVersion(QUOTE_VERSION_3);
    quote.setTdReport10TeeTcbSvn({5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5});

    std::vector<TcbComponent> tdx_components(16, TcbComponent(5));

    TcbLevel tcb_level("", {}, tdx_components, 0, "UpToDate", 0, {});

    // when
    bool result = isTdxTcbHigherOrEqual(quote, tcb_level);

    // then
    EXPECT_TRUE(result);
}

TEST(IsTdxTcbHigherOrEqualTest, AllComponentsHigher) {
    // given: Quote with all TDX TCB components higher than TcbLevel components
    TestQuote quote;
    quote.setHeaderVersion(QUOTE_VERSION_3);
    quote.setTdReport10TeeTcbSvn({10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10});

    std::vector<TcbComponent> tdx_components(16, TcbComponent(5));

    TcbLevel tcbLevel("", {}, tdx_components, 0, "UpToDate", 0, {});

    // when
    bool result = isTdxTcbHigherOrEqual(quote, tcbLevel);

    // then
    EXPECT_TRUE(result);
}

TEST(IsTdxTcbHigherOrEqualTest, OneComponentLower) {
    // given: Quote with one TDX TCB component lower than TcbLevel
    TestQuote quote;
    quote.setHeaderVersion(QUOTE_VERSION_4);
    quote.setTdReport10TeeTcbSvn({10, 10, 10, 10, 10, 3, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10});

    std::vector<TcbComponent> tdx_components(16, TcbComponent(5));

    TcbLevel tcbLevel("", {}, tdx_components, 0, "UpToDate", 0, {});

    // when
    bool result = isTdxTcbHigherOrEqual(quote, tcbLevel);

    // then
    EXPECT_FALSE(result);
}

TEST(IsTdxTcbHigherOrEqualTest, QuoteVersion3WithZeroIndex1) {
    // given: Quote version 3 with teeTcbSvn[1] == 0, should start from index 0
    TestQuote quote;
    quote.setHeaderVersion(QUOTE_VERSION_3);
    quote.setTdReport10TeeTcbSvn({5, 0, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5});

    std::vector<TcbComponent> tdxComponents = {
        TcbComponent(5), TcbComponent(0), TcbComponent(5), TcbComponent(5),
        TcbComponent(5), TcbComponent(5), TcbComponent(5), TcbComponent(5),
        TcbComponent(5), TcbComponent(5), TcbComponent(5), TcbComponent(5),
        TcbComponent(5), TcbComponent(5), TcbComponent(5), TcbComponent(5)
    };
    TcbLevel tcbLevel("", {}, tdxComponents, 0, "UpToDate", 0, {});

    // when
    bool result = isTdxTcbHigherOrEqual(quote, tcbLevel);

    // then
    EXPECT_TRUE(result);
}

TEST(IsTdxTcbHigherOrEqualTest, QuoteVersion4WithNonZeroIndex1) {
    // given: Quote version 4 with teeTcbSvn[1] > 0, should start from index 2
    TestQuote quote;
    quote.setHeaderVersion(QUOTE_VERSION_4);
    quote.setTdReport10TeeTcbSvn({0, 1, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10});

    std::vector<TcbComponent> tdx_components(16, TcbComponent(5));

    TcbLevel tcbLevel("", {}, tdx_components, 0, "UpToDate", 0, {});

    // when
    bool result = isTdxTcbHigherOrEqual(quote, tcbLevel);

    // then: Index 0 and 1 are skipped, so even though they are 0, the result should be true
    EXPECT_TRUE(result);
}

TEST(IsTdxTcbHigherOrEqualTest, MaxValues) {
    // given: Quote with maximum uint8_t values
    TestQuote quote;
    quote.setHeaderVersion(QUOTE_VERSION_3);
    quote.setTdReport10TeeTcbSvn({255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255});

    std::vector<TcbComponent> tdx_components(16, TcbComponent(255));

    TcbLevel tcbLevel("", {}, tdx_components, 0, "UpToDate", 0, {});

    // when
    bool result = isTdxTcbHigherOrEqual(quote, tcbLevel);

    // then
    EXPECT_TRUE(result);
}

// Unit tests for isTcbComponentSvnHigherOrEqual
TEST(IsTcbComponentSvnHigherOrEqualTest, AllComponentsEqual) {
    // given: PCK certificate and TcbLevel with all components equal
    MockPckCertificate pckCert;
    Tcb tcb({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
            {5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5}, 0);

    std::vector<TcbComponent> sgx_components(16, TcbComponent(5));

    TcbLevel tcbLevel("", sgx_components, {}, 0, "UpToDate", 0, {});

    EXPECT_CALL(pckCert, getTcb()).WillRepeatedly(ReturnRef(tcb));

    // when
    bool result = isTcbComponentSvnHigherOrEqual(pckCert, tcbLevel);

    // then
    EXPECT_TRUE(result);
}

TEST(IsTcbComponentSvnHigherOrEqualTest, AllComponentsHigher) {
    // given: PCK certificate with all components higher than TcbLevel
    MockPckCertificate pckCert;
    Tcb tcb({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
            {10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10}, 0);

    std::vector<TcbComponent> sgx_components(16, TcbComponent(5));

    TcbLevel tcbLevel("", sgx_components, {}, 0, "UpToDate", 0, {});

    EXPECT_CALL(pckCert, getTcb()).WillRepeatedly(ReturnRef(tcb));

    // when
    bool result = isTcbComponentSvnHigherOrEqual(pckCert, tcbLevel);

    // then
    EXPECT_TRUE(result);
}

TEST(IsTcbComponentSvnHigherOrEqualTest, OneComponentLower) {
    // given: PCK certificate with middle component (index 8) lower than TcbLevel
    MockPckCertificate pckCert;
    Tcb tcb({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
            {10, 10, 10, 10, 10, 10, 10, 10, 2, 10, 10, 10, 10, 10, 10, 10}, 0);

    std::vector<TcbComponent> sgx_components(16, TcbComponent(5));

    TcbLevel tcbLevel("", sgx_components, {}, 0, "UpToDate", 0, {});

    EXPECT_CALL(pckCert, getTcb()).WillRepeatedly(ReturnRef(tcb));

    // when
    bool result = isTcbComponentSvnHigherOrEqual(pckCert, tcbLevel);

    // then: Should return false because one component is lower
    EXPECT_FALSE(result);
}

TEST(IsTcbComponentSvnHigherOrEqualTest, MixedHigherAndEqual) {
    // given: PCK certificate with some components higher and some equal
    MockPckCertificate pckCert;
    Tcb tcb({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
            {10, 5, 15, 5, 10, 5, 20, 5, 10, 5, 10, 5, 10, 5, 10, 5}, 0);

    std::vector<TcbComponent> sgx_components(16, TcbComponent(5));

    TcbLevel tcbLevel("", sgx_components, {}, 0, "UpToDate", 0, {});

    EXPECT_CALL(pckCert, getTcb()).WillRepeatedly(ReturnRef(tcb));

    // when
    bool result = isTcbComponentSvnHigherOrEqual(pckCert, tcbLevel);

    // then: Should return true because all are >= (none are lower)
    EXPECT_TRUE(result);
}

TEST(IsTcbComponentSvnHigherOrEqualTest, AllComponentsMaxValue) {
    // given: PCK certificate and TcbLevel with all components at max (255)
    MockPckCertificate pckCert;
    Tcb tcb({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
            {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}, 0);

    std::vector<TcbComponent> sgx_components(16, TcbComponent(255));

    TcbLevel tcbLevel("", sgx_components, {}, 0, "UpToDate", 0, {});

    EXPECT_CALL(pckCert, getTcb()).WillRepeatedly(ReturnRef(tcb));

    // when
    bool result = isTcbComponentSvnHigherOrEqual(pckCert, tcbLevel);

    // then: Should return true
    EXPECT_TRUE(result);
}

// Unit tests for getMatchingTcbLevel
TEST(GetMatchingTcbLevelTest, SGX_MatchFirstTcbLevel) {
    // given: SGX quote with PCK cert matching first TCB level
    MockTcbInfo tcb_info;
    MockPckCertificate pck_cert;
    TestQuote quote;

    // Setup TCB info for SGX (version 2)
    EXPECT_CALL(tcb_info, getVersion()).WillRepeatedly(Return(2));
    EXPECT_CALL(tcb_info, getId()).WillRepeatedly(Return("SGX"));

    // Setup PCK cert TCB
    Tcb cert_tcb({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
                {10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10}, 5);
    EXPECT_CALL(pck_cert, getTcb()).WillRepeatedly(ReturnRef(cert_tcb));

    // Setup TCB levels - first level should match
    std::vector<TcbComponent> sgx_components(16, TcbComponent(5));

    TcbLevel level1("", sgx_components, {}, 3, "UpToDate", 0, {});
    TcbLevel level2("", sgx_components, {}, 1, "OutOfDate", 0, {});

    std::set<TcbLevel, std::greater<TcbLevel>> tcb_levels;
    tcb_levels.insert(level1);
    tcb_levels.insert(level2);

    EXPECT_CALL(tcb_info, getTcbLevels()).WillRepeatedly(ReturnRef(tcb_levels));

    // when
    const TcbLevel& result = getMatchingTcbLevel(&tcb_info, pck_cert, quote);

    // then: Should return the first matching level
    EXPECT_EQ(result.getPceSvn(), 3);
    EXPECT_EQ(result.getStatus(), "UpToDate");
}

TEST(GetMatchingTcbLevelTest, SGX_MatchSecondTcbLevel) {
    // given: SGX quote with PCK cert matching second TCB level (not first)
    MockTcbInfo tcb_info;
    MockPckCertificate pck_cert;
    TestQuote quote;

    EXPECT_CALL(tcb_info, getVersion()).WillRepeatedly(Return(2));
    EXPECT_CALL(tcb_info, getId()).WillRepeatedly(Return("SGX"));

    // PCK cert has lower TCB components - will match second level
    Tcb cert_tcb({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
                {3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}, 2);
    EXPECT_CALL(pck_cert, getTcb()).WillRepeatedly(ReturnRef(cert_tcb));

    // First level requires higher TCB
    std::vector<TcbComponent> sgx_components_1(16, TcbComponent(5));
    TcbLevel level1("", sgx_components_1, {}, 3, "UpToDate", 0, {});

    // Second level has lower requirements
    std::vector<TcbComponent> sgx_components_2(16, TcbComponent(2));
    TcbLevel level2("", sgx_components_2, {}, 1, "OutOfDate", 0, {});

    std::set<TcbLevel, std::greater<TcbLevel>> tcb_levels;
    tcb_levels.insert(level1);
    tcb_levels.insert(level2);

    EXPECT_CALL(tcb_info, getTcbLevels()).WillRepeatedly(ReturnRef(tcb_levels));

    // when
    const TcbLevel& result = getMatchingTcbLevel(&tcb_info, pck_cert, quote);

    // then: Should return the second level
    EXPECT_EQ(result.getPceSvn(), 1);
    EXPECT_EQ(result.getStatus(), "OutOfDate");
}

TEST(GetMatchingTcbLevelTest, SGX_NoMatchThrowsException) {
    // given: SGX quote with PCK cert that doesn't match any TCB level
    MockTcbInfo tcb_info;
    MockPckCertificate pck_cert;
    TestQuote quote;

    EXPECT_CALL(tcb_info, getVersion()).WillRepeatedly(Return(2));
    EXPECT_CALL(tcb_info, getId()).WillRepeatedly(Return("SGX"));

    // PCK cert has very low TCB that won't match any level
    Tcb cert_tcb({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
                {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 0);
    EXPECT_CALL(pck_cert, getTcb()).WillRepeatedly(ReturnRef(cert_tcb));

    // All levels require higher TCB
    std::vector<TcbComponent> sgx_components(16, TcbComponent(5));
    TcbLevel level1("", sgx_components, {}, 3, "UpToDate", 0, {});

    std::set<TcbLevel, std::greater<TcbLevel>> tcb_levels;
    tcb_levels.insert(level1);

    EXPECT_CALL(tcb_info, getTcbLevels()).WillRepeatedly(ReturnRef(tcb_levels));

    // when/then: Should throw exception
    EXPECT_THROW(getMatchingTcbLevel(&tcb_info, pck_cert, quote), quote3_error_t);
}

TEST(GetMatchingTcbLevelTest, SGX_PceSvnTooLow) {
    // given: SGX quote with PCK cert that has matching TCB components but PCE SVN too low
    MockTcbInfo tcb_info;
    MockPckCertificate pck_cert;
    TestQuote quote;

    EXPECT_CALL(tcb_info, getVersion()).WillRepeatedly(Return(2));
    EXPECT_CALL(tcb_info, getId()).WillRepeatedly(Return("SGX"));

    // PCK cert has matching TCB components but low PCE SVN
    Tcb cert_tcb({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
                {10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10}, 2);
    EXPECT_CALL(pck_cert, getTcb()).WillRepeatedly(ReturnRef(cert_tcb));

    // Level requires higher PCE SVN
    std::vector<TcbComponent> sgx_components(16, TcbComponent(5));
    TcbLevel level1("", sgx_components, {}, 5, "UpToDate", 0, {});

    std::set<TcbLevel, std::greater<TcbLevel>> tcb_levels;
    tcb_levels.insert(level1);

    EXPECT_CALL(tcb_info, getTcbLevels()).WillRepeatedly(ReturnRef(tcb_levels));

    // when/then: Should throw exception because PCE SVN is too low
    EXPECT_THROW(getMatchingTcbLevel(&tcb_info, pck_cert, quote), quote3_error_t);
}

TEST(GetMatchingTcbLevelTest, TDX_Version3_TdxTcbTooLow) {
    // given: TDX quote (version 3) with TDX TCB too low
    MockTcbInfo tcb_info;
    MockPckCertificate pck_cert;
    TestQuote quote;

    // Setup for TDX
    quote.setHeaderVersion(QUOTE_VERSION_4);
    quote.setTeeType(TEE_TYPE_TDX);
    // TDX TCB is too low (3 < 5)
    quote.setTdReport10TeeTcbSvn({0, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3});

    EXPECT_CALL(tcb_info, getVersion()).WillRepeatedly(Return(3));
    EXPECT_CALL(tcb_info, getId()).WillRepeatedly(Return(TcbInfo::TDX_ID));

    // PCK cert TCB is fine
    Tcb cert_tcb({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
                {10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10}, 5);
    EXPECT_CALL(pck_cert, getTcb()).WillRepeatedly(ReturnRef(cert_tcb));

    // TDX components require higher values
    std::vector<TcbComponent> sgx_components(16, TcbComponent(5));
    std::vector<TcbComponent> tdx_components(16, TcbComponent(5));
    TcbLevel level1(TcbInfo::TDX_ID, sgx_components, tdx_components, 3, "UpToDate", 0, {});

    std::set<TcbLevel, std::greater<TcbLevel>> tcb_levels;
    tcb_levels.insert(level1);

    EXPECT_CALL(tcb_info, getTcbLevels()).WillRepeatedly(ReturnRef(tcb_levels));

    // when/then: Should throw because TDX TCB is too low
    EXPECT_THROW(getMatchingTcbLevel(&tcb_info, pck_cert, quote), quote3_error_t);
}

TEST(GetMatchingTcbLevelTest, TDX_Version3_TdxTcbSufficient) {
    // given: TDX quote (version 3) with sufficient TDX TCB
    MockTcbInfo tcb_info;
    MockPckCertificate pck_cert;
    TestQuote quote;

    // Setup for TDX
    quote.setHeaderVersion(QUOTE_VERSION_4);
    quote.setTeeType(TEE_TYPE_TDX);

    // TDX TCB is sufficient (5 >= 5)
    quote.setTdReport10TeeTcbSvn({5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5});
    EXPECT_CALL(tcb_info, getVersion()).WillRepeatedly(Return(3));
    EXPECT_CALL(tcb_info, getId()).WillRepeatedly(Return(TcbInfo::TDX_ID));

   // PCK cert TCB is fine
    Tcb cert_tcb({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
                 {10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10}, 5);
    EXPECT_CALL(pck_cert, getTcb()).WillRepeatedly(ReturnRef(cert_tcb));

    // TDX components require value 5, which the quote meets
    std::vector<TcbComponent> sgx_components(16, TcbComponent(5));
    std::vector<TcbComponent> tdx_components(16, TcbComponent(5));
    TcbLevel level1(TcbInfo::TDX_ID, sgx_components, tdx_components, 3, "UpToDate", 0, {});
    std::set<TcbLevel, std::greater<TcbLevel>> tcb_levels;
    tcb_levels.insert(level1);

    EXPECT_CALL(tcb_info, getTcbLevels()).WillRepeatedly(ReturnRef(tcb_levels));

    // when/then: Should not throw because TDX TCB is sufficient
    EXPECT_NO_THROW(getMatchingTcbLevel(&tcb_info, pck_cert, quote));
}

TEST(GetMatchingTcbLevelTest, SGX_TeeType_WithTdxId_SkipsTdxCheck) {
    // given: SGX tee type (not TDX) with TDX ID should skip TDX check
    MockTcbInfo tcb_info;
    MockPckCertificate pck_cert;
    TestQuote quote;

    quote.setHeaderVersion(QUOTE_VERSION_4);
    quote.setTeeType(TEE_TYPE_SGX); // SGX type

    EXPECT_CALL(tcb_info, getVersion()).WillRepeatedly(Return(3));
    EXPECT_CALL(tcb_info, getId()).WillRepeatedly(Return(TcbInfo::TDX_ID)); // TDX ID but SGX tee type

    // PCK cert TCB
    Tcb cert_tcb({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
                {10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10}, 5);
    EXPECT_CALL(pck_cert, getTcb()).WillRepeatedly(ReturnRef(cert_tcb));

    std::vector<TcbComponent> sgx_components(16, TcbComponent(5));
    std::vector<TcbComponent> tdx_components(16, TcbComponent(5));
    TcbLevel level1(TcbInfo::TDX_ID, sgx_components, tdx_components, 3, "UpToDate", 0, {});

    std::set<TcbLevel, std::greater<TcbLevel>> tcb_levels;
    tcb_levels.insert(level1);

    EXPECT_CALL(tcb_info, getTcbLevels()).WillRepeatedly(ReturnRef(tcb_levels));

    // when
    const TcbLevel& result = getMatchingTcbLevel(&tcb_info, pck_cert, quote);

    // then: Should match without TDX check (because teeType is SGX)
    EXPECT_EQ(result.getPceSvn(), 3);
}

TEST(GetMatchingTcbLevelTest, MultipleLevels_ReturnsFirstMatch) {
    // given: Multiple TCB levels, should return first matching one
    MockTcbInfo tcb_info;
    MockPckCertificate pck_cert;
    TestQuote quote;

    EXPECT_CALL(tcb_info, getVersion()).WillRepeatedly(Return(2));
    EXPECT_CALL(tcb_info, getId()).WillRepeatedly(Return("SGX"));

    // PCK cert with high TCB - matches both levels
    Tcb cert_tcb({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
                {10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10}, 10);
    EXPECT_CALL(pck_cert, getTcb()).WillRepeatedly(ReturnRef(cert_tcb));

    // Create multiple levels - both would match
    std::vector<TcbComponent> sgx_components_1(16, TcbComponent(8));
    std::vector<TcbComponent> sgx_components_2(16, TcbComponent(3));
    TcbLevel level1("", sgx_components_1, {}, 9, "UpToDate", 0, {});
    TcbLevel level2("", sgx_components_2, {}, 2, "OutOfDate", 0, {});

    std::set<TcbLevel, std::greater<TcbLevel>> tcb_levels;
    tcb_levels.insert(level1);
    tcb_levels.insert(level2);

    EXPECT_CALL(tcb_info, getTcbLevels()).WillRepeatedly(ReturnRef(tcb_levels));

    // when
    const TcbLevel& result = getMatchingTcbLevel(&tcb_info, pck_cert, quote);

    // then: Should return first matching level (highest PCE SVN)
    EXPECT_EQ(result.getPceSvn(), 9);
}
