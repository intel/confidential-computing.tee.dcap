/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "SgxEcdsaAttestation/AttestationParsers.h"

namespace intel { namespace sgx { namespace dcap { namespace parser { namespace json {

    IdentityTcbLevel::IdentityTcbLevel(
            const uint32_t isvSvn,
            const time_t tcbDate,
            const TcbStatus tcbStatus,
            const std::vector<std::string>& advisoryIds)
            : _isvSvn(isvSvn),
              _tcbDate(tcbDate),
              _tcbStatus(tcbStatus),
              _advisoryIds(advisoryIds) {}

    uint32_t IdentityTcbLevel::getIsvsvn() const
    {
        return _isvSvn;
    }

    time_t IdentityTcbLevel::getTcbDate() const
    {
        return _tcbDate;
    }

    TcbStatus IdentityTcbLevel::getTcbStatus() const
    {
        return _tcbStatus;
    }

    const std::vector<std::string>& IdentityTcbLevel::getAdvisoryIds() const
    {
        return _advisoryIds;
    }

    IdentityTcbLevel::IdentityTcbLevel(const ::rapidjson::Value &tcbLevel)
    {

    }

    bool IdentityTcbLevel::operator>(const IdentityTcbLevel &other) const {
        return (_isvSvn == other._isvSvn) ? _tcbDate > other._tcbDate : _isvSvn > other._isvSvn;
    }
}}}}}
