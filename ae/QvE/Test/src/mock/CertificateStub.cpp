/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */


#include "SgxEcdsaAttestation/AttestationParsers.h"


namespace intel { namespace sgx { namespace dcap { namespace parser { namespace x509 {

    Certificate::Certificate(): _version{},
                                _subject{},
                                _issuer{},
                                _validity{},
                                _extensions{},
                                _signature{},
                                _serialNumber{},
                                _pubKey{},
                                _info{}
    {}

    bool Certificate::operator==(const Certificate& other) const
    {
        return _version == other._version &&
               _subject == other._subject &&
               _issuer == other._issuer &&
               _validity == other._validity &&
               _extensions == other._extensions &&
               _signature == other._signature &&
               _serialNumber == other._serialNumber &&
               _pubKey == other._pubKey &&
               _info == other._info &&
               _crlDistributionPoint == other._crlDistributionPoint;
    }

    uint32_t Certificate::getVersion() const
    {
        return _version;
    }

    const std::vector<uint8_t>& Certificate::getSerialNumber() const
    {
        return _serialNumber;
    }

    const DistinguishedName& Certificate::getSubject() const
    {
        return _subject;
    }

    const DistinguishedName& Certificate::getIssuer() const
    {
        return _issuer;
    }

    const Validity& Certificate::getValidity() const
    {
        return _validity;
    }

    const std::vector<Extension>& Certificate::getExtensions() const
    {
        return _extensions;
    }

    const std::vector<uint8_t>& Certificate::getInfo() const
    {
        return _info;
    }

    const Signature& Certificate::getSignature() const
    {
        return _signature;
    }

    const std::vector<uint8_t>& Certificate::getPubKey() const
    {
        return _pubKey;
    }

    const std::string& Certificate::getPem() const
    {
        return _pem;
    }

    const std::string &Certificate::getCrlDistributionPoint() const {
        return _crlDistributionPoint;
    }

    Certificate Certificate::parse(const std::string& pem)
    {
        return Certificate(pem);
    }

// Protected

    Certificate::Certificate(const std::string &pem)
    {
        _pem = pem;
    }

}}}}} // namespace intel { namespace sgx { namespace dcap { namespace parser { namespace x509 {
