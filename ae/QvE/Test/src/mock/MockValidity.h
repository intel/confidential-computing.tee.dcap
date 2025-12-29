/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _MOCK_VALIDITY_H
#define _MOCK_VALIDITY_H

#include <gmock/gmock.h>
#include "SgxEcdsaAttestation/AttestationParsers.h"

namespace intel { namespace sgx { namespace dcap { namespace parser { namespace x509 {

class MockValidity : public Validity {
public:

    MOCK_METHOD(time_t, getNotBeforeTime, (), (const, override));
    MOCK_METHOD(time_t, getNotAfterTime, (), (const, override));
};

}}}}} // namespace intel::sgx::dcap::parser::x509

#endif // _MOCK_VALIDITY_H
