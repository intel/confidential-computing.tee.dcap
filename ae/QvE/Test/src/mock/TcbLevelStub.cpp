/*
 * Copyright(c) 2026 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "SgxEcdsaAttestation/AttestationParsers.h"

namespace intel { namespace sgx { namespace dcap { namespace parser { namespace json {

    TcbLevel::TcbLevel(const std::vector<uint8_t>& cpuSvnComponents,
                       const uint32_t pceSvn,
                       const std::string& status,
                       const std::time_t tcbDate,
                       std::vector<std::string> advisoryIDs)
        : _id(),
          _version(TcbInfo::Version::V2),
          _cpuSvn(cpuSvnComponents),
          _sgxTcbComponents(),
          _tdxTcbComponents(),
          _pceSvn(pceSvn),
          _status(status),
          _tcbDate(tcbDate),
          _advisoryIDs(std::move(advisoryIDs))
    {
    }

    TcbLevel::TcbLevel(const std::string& id,
                       const std::vector<TcbComponent>& sgxTcbComponents,
                       const std::vector<TcbComponent>& tdxTcbComponents,
                       const uint32_t pceSvn,
                       const std::string& status,
                       const std::time_t tcbDate,
                       std::vector<std::string> advisoryIDs)
        : _id(id),
          _version(TcbInfo::Version::V3),
          _cpuSvnComponents(),
          _sgxTcbComponents(sgxTcbComponents),
          _tdxTcbComponents(tdxTcbComponents),
          _pceSvn(pceSvn),
          _status(status),
          _tcbDate(tcbDate),
          _advisoryIDs(std::move(advisoryIDs))
    {
    }

    bool TcbLevel::operator>(const TcbLevel& other) const
    {
        if (_pceSvn != other._pceSvn)
        {
            return _pceSvn > other._pceSvn;
        }
        return _tcbDate > other._tcbDate;
    }

    uint32_t TcbLevel::getSgxTcbComponentSvn(uint32_t componentNumber) const
    {
        if (componentNumber >= _sgxTcbComponents.size())
        {
            throw intel::sgx::dcap::parser::FormatException("Component number out of range");
        }
        return _sgxTcbComponents[componentNumber].getSvn();
    }

    const std::vector<uint8_t>& TcbLevel::getCpuSvn() const
    {
        return _cpuSvn;
    }

    const std::vector<TcbComponent>& TcbLevel::getSgxTcbComponents() const
    {
        return _sgxTcbComponents;
    }

    const TcbComponent& TcbLevel::getSgxTcbComponent(uint32_t componentNumber) const
    {
        if (componentNumber >= _sgxTcbComponents.size())
        {
            throw intel::sgx::dcap::parser::FormatException("Component number out of range");
        }
        return _sgxTcbComponents[componentNumber];
    }

    const std::vector<TcbComponent>& TcbLevel::getTdxTcbComponents() const
    {
        return _tdxTcbComponents;
    }

    const TcbComponent& TcbLevel::getTdxTcbComponent(uint32_t componentNumber) const
    {
        if (componentNumber >= _tdxTcbComponents.size())
        {
            throw intel::sgx::dcap::parser::FormatException("Component number out of range");
        }
        return _tdxTcbComponents[componentNumber];
    }

    uint32_t TcbLevel::getPceSvn() const
    {
        return _pceSvn;
    }

    const std::string& TcbLevel::getStatus() const
    {
        return _status;
    }

    const std::time_t& TcbLevel::getTcbDate() const
    {
        return _tcbDate;
    }

    const std::vector<std::string>& TcbLevel::getAdvisoryIDs() const
    {
        return _advisoryIDs;
    }

}}}}} // namespace intel::sgx::dcap::parser::json
