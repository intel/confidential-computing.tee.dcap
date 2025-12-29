/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "SgxEcdsaAttestation/AttestationParsers.h"

#include <chrono>

namespace intel { namespace sgx { namespace dcap { namespace parser { namespace x509 {

    Validity::Validity(std::time_t notBeforeTime,
                       std::time_t notAfterTime) :
            _notBeforeTime(notBeforeTime),
            _notAfterTime(notAfterTime)
    {}

    std::time_t Validity::getNotBeforeTime() const
    {
        return _notBeforeTime;
    }

    std::time_t Validity::getNotAfterTime() const
    {
        return _notAfterTime;
    }

    bool Validity::operator==(const Validity &other) const
    {
        return _notBeforeTime == other._notBeforeTime &&
               _notAfterTime == other._notAfterTime;
    }

}}}}} // namespace intel { namespace sgx { namespace dcap { namespace parser { namespace x509 {
