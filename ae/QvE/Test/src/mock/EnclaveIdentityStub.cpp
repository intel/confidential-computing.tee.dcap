/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "SgxEcdsaAttestation/AttestationParsers.h"


namespace intel { namespace sgx { namespace dcap { namespace parser { namespace json {

    EnclaveID EnclaveIdentity::getID() const
    {
        return _id;
    }

    uint32_t EnclaveIdentity::getVersion() const
    {
        return _version;
    }

    time_t EnclaveIdentity::getIssueDate() const
    {
        return _issueDate;
    }

    time_t EnclaveIdentity::getNextUpdate() const
    {
        return _nextUpdate;
    }

    uint32_t EnclaveIdentity::getTcbEvaluationDataNumber() const
    {
        return _tcbEvaluationDataNumber;
    }

    const std::vector<uint8_t>& EnclaveIdentity::getMrsigner() const
    {
        return _mrSigner;
    }

    const std::vector<uint8_t>& EnclaveIdentity::getAttributes() const
    {
        return _attributes;
    }

    const std::vector<uint8_t>& EnclaveIdentity::getAttributesMask() const
    {
        return _attributesMask;
    }

    const std::vector<uint8_t>& EnclaveIdentity::getMiscselect() const
    {
        return _miscselect;
    }

    const std::vector<uint8_t>& EnclaveIdentity::getMiscselectMask() const
    {
        return _miscselectMask;
    }

    uint32_t EnclaveIdentity::getIsvProdId() const
    {
        return _isvProdId;
    }

    const std::set<IdentityTcbLevel, std::greater<IdentityTcbLevel>>& EnclaveIdentity::getIdentityTcbLevels() const
    {
        return _identityTcbLevels;
    }

    const std::vector<uint8_t>& EnclaveIdentity::getBody() const
    {
        return _body;
    }

    const std::vector<uint8_t>& EnclaveIdentity::getSignature() const
    {
        return _signature;
    }

    EnclaveIdentity EnclaveIdentity::parse(const std::string& jsonString)
    {
        return EnclaveIdentity();
    }

    IdentityTcbLevel EnclaveIdentity::getTcbLevel(uint32_t p_isvSvn) const
    {
        return IdentityTcbLevel(0, 0, TcbStatus::UpToDate, std::vector<std::string>{});
    }
}}}}}
