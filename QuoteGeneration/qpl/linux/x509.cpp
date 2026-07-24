/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
/**
 * File: x509.cpp
 *  
 * Description: X.509 parser
 *
 */
#include "x509.h"
#include <iostream>
#include <map>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sstream>
#include <string.h>
#include <string>
#include <vector>

using std::cout;
using std::endl;
using std::map;
using std::string;
using std::stringstream;
using std::vector;

//----------------------------------------------------------------------
// Extracts CRL Distribution Point URLs from an X.509 certificate.
// When include_relative is false (default), only fullName/URI entries are
// returned — the form used by Intel PCK certificates. Set include_relative=true
// to also collect nameRelativeToCRLIssuer entries (raw ASN.1 string bytes, not
// a valid URL; callers must reconstruct the full URL from the issuer name).
static vector<string> crl_urls(X509 *x509, bool include_relative = false) {
    vector<string> list;
    if (x509 == NULL)
        return list;
    int nid = NID_crl_distribution_points;
    STACK_OF(DIST_POINT) *dist_points = (STACK_OF(DIST_POINT) *)X509_get_ext_d2i(x509, nid, NULL, NULL);
    if (dist_points == NULL)
        return list;
    for (int j = 0; j < sk_DIST_POINT_num(dist_points); j++) {
        DIST_POINT *dp = sk_DIST_POINT_value(dist_points, j);
        if (dp == NULL || dp->distpoint == NULL)
            continue;
        DIST_POINT_NAME *distpoint = dp->distpoint;
        if (distpoint->type == 0 && distpoint->name.fullname != NULL) {
            for (int k = 0; k < sk_GENERAL_NAME_num(distpoint->name.fullname); k++) {
                GENERAL_NAME *gen = sk_GENERAL_NAME_value(distpoint->name.fullname, k);
                if (gen == NULL || gen->type != GEN_URI)
                    continue;
                ASN1_IA5STRING *asn1_str = gen->d.uniformResourceIdentifier;
                if (asn1_str == NULL)
                    continue;
                list.push_back(string(reinterpret_cast<const char *>(ASN1_STRING_get0_data(asn1_str)), ASN1_STRING_length(asn1_str)));
            }
        } else if (include_relative && distpoint->type == 1 && distpoint->name.relativename != NULL) {
            STACK_OF(X509_NAME_ENTRY) *sk_relname = distpoint->name.relativename;
            for (int k = 0; k < sk_X509_NAME_ENTRY_num(sk_relname); k++) {
                X509_NAME_ENTRY *e = sk_X509_NAME_ENTRY_value(sk_relname, k);
                if (e == NULL)
                    continue;
                ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
                if (d == NULL)
                    continue;
                list.push_back(string(reinterpret_cast<const char *>(ASN1_STRING_get0_data(d)), ASN1_STRING_length(d)));
            }
        }
    }
    CRL_DIST_POINTS_free(dist_points);
    return list;
}

std::string get_cdp_url_from_pem_cert(const char *p_cert) {
    std::string cdp_url = "";

    // To use X509 function group
    OpenSSL_add_all_algorithms();

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, p_cert);

    X509 *x509 = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
    vector<string> crls = crl_urls(x509);
    if (crls.size() > 0)
        cdp_url = crls[0];

    BIO_free(bio_mem);

    X509_free(x509);

    return cdp_url;
}
