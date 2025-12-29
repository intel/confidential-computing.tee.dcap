/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "SgxEcdsaAttestation/AttestationParsers.h"

namespace intel { namespace sgx { namespace dcap { namespace parser { namespace json {

    TcbInfo TcbInfo::parse(const std::string &json) {
        return TcbInfo();
    }

    std::string TcbInfo::getId() const {
        return _id;
    }

    uint32_t TcbInfo::getVersion() const {
        return static_cast<uint32_t>(_version);
    }

    std::time_t TcbInfo::getIssueDate() const {
        return _issueDate;
    }

    std::time_t TcbInfo::getNextUpdate() const {
        return _nextUpdate;
    }

    const std::vector <uint8_t> &TcbInfo::getFmspc() const {
        return _fmspc;
    }

    const std::vector <uint8_t> &TcbInfo::getPceId() const {
        return _pceId;
    }

    const std::set <TcbLevel, std::greater<TcbLevel>> &TcbInfo::getTcbLevels() const {
        return _tcbLevels;
    }

    const std::vector <uint8_t> &TcbInfo::getSignature() const {
        return _signature;
    }

    const std::vector <uint8_t> &TcbInfo::getInfoBody() const {
        return _infoBody;
    }

    int TcbInfo::getTcbType() const {
        return _tcbType;
    }

    uint32_t TcbInfo::getTcbEvaluationDataNumber() const {
        return _tcbEvaluationDataNumber;
    }

    const TdxModule &TcbInfo::getTdxModule() const {
        return _tdxModule;
    }

    const std::vector <TdxModuleIdentity> &TcbInfo::getTdxModuleIdentities() const {
        return _tdxModuleIdentities;
    }

}}}}}
