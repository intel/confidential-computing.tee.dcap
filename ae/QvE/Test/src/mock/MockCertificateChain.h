/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _MOCK_CERTIFICATECHAIN_H
#define _MOCK_CERTIFICATECHAIN_H


#include <gmock/gmock.h>
#include "SgxEcdsaAttestation/AttestationParsers.h"

#include <CertVerification/CertificateChain.h>

namespace intel { namespace sgx { namespace dcap {

class MockCertificateChain : public CertificateChain {
public:
    MOCK_METHOD(Status, parse, (const std::string& pemCertChain), (override));
    MOCK_METHOD(size_t, length, (), (const, override));
    MOCK_METHOD(std::shared_ptr<const dcap::parser::x509::Certificate>, get, (const dcap::parser::x509::DistinguishedName &subject), (const, override));
    MOCK_METHOD(std::shared_ptr<const dcap::parser::x509::Certificate>, getIntermediateCert, (), (const, override));
    MOCK_METHOD(std::shared_ptr<const dcap::parser::x509::Certificate>, getRootCert, (), (const, override));
    MOCK_METHOD(std::shared_ptr<const dcap::parser::x509::Certificate>, getTopmostCert, (), (const, override));
    MOCK_METHOD(std::shared_ptr<const dcap::parser::x509::PckCertificate>, getPckCert, (), (const, override));
    MOCK_METHOD(std::vector<std::shared_ptr<const dcap::parser::x509::Certificate>>, getCerts, (), (const, override));
};

}}} // namespace intel::sgx::dcap

#endif //_MOCK_CERTIFICATECHAIN_H
