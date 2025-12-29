/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _MOCK_CRLSTORE_H
#define _MOCK_CRLSTORE_H

#include <gmock/gmock.h>
#include "SgxEcdsaAttestation/AttestationParsers.h"

#include "PckParser/CrlStore.h"

class MockCrlStore : public pckparser::CrlStore {
public:
    MOCK_METHOD(bool, parse, (const std::string& crlData), (override));
    MOCK_METHOD(const intel::sgx::dcap::pckparser::Validity&, getValidity, (), (const, override));
};

#endif //_MOCK_CRLSTORE_H
