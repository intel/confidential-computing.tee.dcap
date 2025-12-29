/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MOCK_ENCLAVE_IDENTITY_H
#define MOCK_ENCLAVE_IDENTITY_H

#include <gmock/gmock.h>
#include "SgxEcdsaAttestation/AttestationParsers.h"
using namespace intel::sgx::dcap::parser::json;

class MockEnclaveIdentity : public EnclaveIdentity {
public:
    MOCK_METHOD(uint32_t, getVersion, (), (const, override));
    MOCK_METHOD(time_t, getIssueDate, (), (const, override));
    MOCK_METHOD(time_t, getNextUpdate, (), (const, override));
    MOCK_METHOD(uint32_t, getTcbEvaluationDataNumber, (), (const, override));
    MOCK_METHOD(const std::vector<uint8_t>&, getMrsigner, (), (const, override));
    MOCK_METHOD(const std::vector<uint8_t>&, getAttributes, (), (const, override));
    MOCK_METHOD(const std::vector<uint8_t>&, getAttributesMask, (), (const, override));
    MOCK_METHOD(const std::vector<uint8_t>&, getMiscselect, (), (const, override));
    MOCK_METHOD(const std::vector<uint8_t>&, getMiscselectMask, (), (const, override));
    MOCK_METHOD(uint32_t, getIsvProdId, (), (const, override));
    MOCK_METHOD((const std::set<IdentityTcbLevel, std::greater<IdentityTcbLevel>>&), getIdentityTcbLevels, (), (const, override));
    MOCK_METHOD(const std::vector<uint8_t>&, getBody, (), (const, override));
    MOCK_METHOD(const std::vector<uint8_t>&, getSignature, (), (const, override));
};

#endif // MOCK_ENCLAVE_IDENTITY_H
