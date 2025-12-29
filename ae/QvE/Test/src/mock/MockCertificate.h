/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _MOCK_CERTIFICATE_H
#define _MOCK_CERTIFICATE_H

#include <gmock/gmock.h>
#include <vector>
#include "SgxEcdsaAttestation/AttestationParsers.h"

#include "MockValidity.h"

namespace intel { namespace sgx { namespace dcap {

    class MockCertificate : public parser::x509::Certificate {
    public:
        MOCK_METHOD(parser::x509::Validity&, getValidity, (), (const, override));
        MOCK_METHOD(uint32_t , getVersion, (), (const, override));
        MOCK_METHOD(std::vector<uint8_t>&, getSerialNumber, (), (const, override));
        MOCK_METHOD(const parser::x509::DistinguishedName&, getSubject, (), (const, override));
        MOCK_METHOD(const parser::x509::DistinguishedName&, getIssuer, (), (const, override));
        MOCK_METHOD(const std::vector<parser::x509::Extension>&, getExtensions, (), (const, override));
        MOCK_METHOD(const std::string&, getPem, (), (const, override));
        MOCK_METHOD(const std::vector<uint8_t>&, getInfo, (), (const, override));
        MOCK_METHOD(const parser::x509::Signature&, getSignature, (), (const, override));
        MOCK_METHOD(const std::vector<uint8_t>&, getPubKey, (), (const, override));
        MOCK_METHOD(const std::string &, getCrlDistributionPoint, (), (const, override));
    };

}}} // namespace intel::sgx::dcap


#endif //_MOCK_CERTIFICATE_H
