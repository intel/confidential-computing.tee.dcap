/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MOCK_TCB_INFO_H
#define MOCK_TCB_INFO_H

#include <gmock/gmock.h>
#include "SgxEcdsaAttestation/AttestationParsers.h"

using namespace intel::sgx::dcap::parser::json;

class MockTcbInfo : public TcbInfo {
public:
    MOCK_METHOD(std::string, getId, (), (const, override));
    MOCK_METHOD(uint32_t, getVersion, (), (const, override));
    MOCK_METHOD(std::time_t, getIssueDate, (), (const, override));
    MOCK_METHOD(std::time_t, getNextUpdate, (), (const, override));
    MOCK_METHOD(const std::vector<uint8_t>&, getFmspc, (), (const, override));
    MOCK_METHOD(const std::vector<uint8_t>&, getPceId, (), (const, override));
    MOCK_METHOD((const std::set<TcbLevel, std::greater<TcbLevel>>&), getTcbLevels, (), (const, override));
    MOCK_METHOD(const std::vector<uint8_t>&, getSignature, (), (const, override));
    MOCK_METHOD(const std::vector<uint8_t>&, getInfoBody, (), (const, override));
    MOCK_METHOD(int, getTcbType, (), (const, override));
    MOCK_METHOD(uint32_t, getTcbEvaluationDataNumber, (), (const, override));
    MOCK_METHOD(const intel::sgx::dcap::parser::json::TdxModule&, getTdxModule, (), (const, override));
    MOCK_METHOD(const std::vector<intel::sgx::dcap::parser::json::TdxModuleIdentity>&, getTdxModuleIdentities, (), (const, override));
};

#endif // MOCK_TCB_INFO_H
