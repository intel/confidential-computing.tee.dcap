/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <CertVerification/CertificateChain.h>

namespace intel { namespace sgx { namespace dcap {

    Status CertificateChain::parse(const std::string& pemCertChain) {
        return Status::STATUS_OK; // Provide a dummy implementation
    }

    size_t CertificateChain::length() const {
        return 0; // Return a default value
    }

    std::shared_ptr<const dcap::parser::x509::Certificate> CertificateChain::get(const dcap::parser::x509::DistinguishedName &subject) const {
        return nullptr; // Return a default value
    }

    std::shared_ptr<const dcap::parser::x509::Certificate> CertificateChain::getIntermediateCert() const {
        return nullptr; // Return a default value
    }

    std::shared_ptr<const dcap::parser::x509::Certificate> CertificateChain::getRootCert() const {
        return nullptr; // Return a default value
    }

    std::shared_ptr<const dcap::parser::x509::Certificate> CertificateChain::getTopmostCert() const {
        return nullptr; // Return a default value
    }

    std::shared_ptr<const dcap::parser::x509::PckCertificate> CertificateChain::getPckCert() const {
        return nullptr; // Return a default value
    }

    std::vector<std::shared_ptr<const dcap::parser::x509::Certificate>> CertificateChain::getCerts() const {
        return {}; // Return an empty vector
    }

}}} // namespace intel::sgx::dcap
