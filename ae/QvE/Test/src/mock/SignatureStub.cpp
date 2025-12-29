/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "SgxEcdsaAttestation/AttestationParsers.h"

namespace intel { namespace sgx { namespace dcap { namespace parser { namespace x509 {

    Signature::Signature(): _rawDer{},
                            _r{},
                            _s{}
    {}

    Signature::Signature(const std::vector<uint8_t>& rawDer,
                         const std::vector<uint8_t>& r,
                         const std::vector<uint8_t>& s):
            _rawDer(rawDer),
            _r(r),
            _s(s)
    {}

    bool Signature::operator==(const Signature& other) const
    {
        return _rawDer == other._rawDer &&
               _r == other._r &&
               _s == other._s;
    }

    const std::vector<uint8_t>& Signature::getRawDer() const
    {
        return _rawDer;
    }

    const std::vector<uint8_t>& Signature::getR() const
    {
        return _r;
    }

    const std::vector<uint8_t>& Signature::getS() const
    {
        return _s;
    }

}}}}} // namespace intel { namespace sgx { namespace dcap { namespace parser { namespace x509 {
