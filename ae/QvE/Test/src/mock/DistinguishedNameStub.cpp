/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "SgxEcdsaAttestation/AttestationParsers.h"

namespace intel { namespace sgx { namespace dcap { namespace parser { namespace x509 {
  
    DistinguishedName::DistinguishedName(const std::string& raw,
                                         const std::string& commonName,
                                         const std::string& countryName,
                                         const std::string& organizationName,
                                         const std::string& locationName,
                                         const std::string& stateName):
            _raw(raw),
            _commonName(commonName),
            _countryName(countryName),
            _organizationName(organizationName),
            _locationName(locationName),
            _stateName(stateName)
    {}

    const std::string& DistinguishedName::getRaw() const
    {
        return _raw;
    }

    const std::string& DistinguishedName::getCommonName() const
    {
        return _commonName;
    }

    const std::string& DistinguishedName::getCountryName() const
    {
        return _countryName;
    }

    const std::string& DistinguishedName::getOrganizationName() const
    {
        return _organizationName;
    }

    const std::string& DistinguishedName::getLocationName() const
    {
        return _locationName;
    }

    const std::string& DistinguishedName::getStateName() const
    {
        return _stateName;
    }

    bool DistinguishedName::operator==(const DistinguishedName &other) const {
        return _commonName == other._commonName && // do not compare RAW as order may differ
               _countryName == other._countryName &&
               _organizationName == other._organizationName &&
               _locationName == other._locationName &&
               _stateName == other._stateName;
    }

    bool DistinguishedName::operator!=(const DistinguishedName &other) const {
        return !operator==(other);
    }

}}}}} // namespace intel { namespace sgx { namespace dcap { namespace parser { namespace x509 {

