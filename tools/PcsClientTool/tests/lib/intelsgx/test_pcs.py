#!/usr/bin/env python3
# encoding: utf-8

#
# Copyright(c) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import unittest
from unittest.mock import patch
from dataclasses import dataclass
from lib.intelsgx.pcs import PCS

PCS_SERVICE_URL = 'https://api.trustedservices.intel.com/sgx/certification/v4/'
ISSUER_CHAIN = '''-----BEGIN CERTIFICATE-----
MIICejCCAiCgAwIBAgIVAOzQGYAsOadzMrM8fOARyiAL0W8kMAoGCCqGSM49BAMC
MGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD
b3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw
CQYDVQQGEwJVUzAeFw0xODExMjAwODUyMjRaFw0zMzExMjAwODUyMjRaMGwxHjAc
BgNVBAMMFUludGVsIFNHWCBUQ0IgU2lnbmluZzEaMBgGA1UECgwRSW50ZWwgQ29y
cG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTELMAkG
A1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQg0DszqD50mJwXnOjQ
osPHLreEyMA1BA/6ERklvoQ+YRD8umcLbzUKqHD1XhFD9T8suSZJkQ8La5qZLoZu
81hmo4GiMIGfMB8GA1UdIwQYMBaAFFbN/FB70XcCtlKBwtOy3ILwOft6MD8GA1Ud
HwQ4MDYwNKAyoDCGLmh0dHBzOi8vY2VydHByZS5hZHNkY3NwLmNvbS9JbnRlbFNH
WFJvb3RDQS5jcmwwHQYDVR0OBBYEFOzQGYAsOadzMrM8fOARyiAL0W8kMA4GA1Ud
DwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCY3VHR
2CcxgBL7VRkX5QyH1YUAOCyBbSbxCyd9dGU0dwIgF8FXUnhvHe/C73r6/yVRcjkK
B4Kq6wmyiq9FQSr6XGs=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICezCCAiGgAwIBAgIUVs38UHvRdwK2UoHC07LcgvA5+3owCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE5MTAzMTA5NDkyMVoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5OrBrf+Fu4b8cZB0kCHhTBAH
eo/NX9IWlGVfIRLlNEa+k8v5ahmfFlkBbHPN/EKcX5BW5HDidc9dYG8fRWoStaOB
qDCBpTAfBgNVHSMEGDAWgBRWzfxQe9F3ArZSgcLTstyC8Dn7ejA/BgNVHR8EODA2
MDSgMqAwhi5odHRwczovL2NlcnRwcmUuYWRzZGNzcC5jb20vSW50ZWxTR1hSb290
Q0EuZGVyMB0GA1UdDgQWBBRWzfxQe9F3ArZSgcLTstyC8Dn7ejAOBgNVHQ8BAf8E
BAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAKBggqhkjOPQQDAgNIADBFAiEAg1B3
jCFC87CU3/563+J7+hUkxVYyuJcigx0Y/gEyhjECICl/jwfsNAOT0IUTNRXfiRrX
CoVH3RMMGdhCJOEacAIZ
-----END CERTIFICATE-----
'''
JSON_WITH_FIELDS_IN_NON_ALPHABETICAL_ORDER= b'{"c":"a","a":"b","b":"c"}'
SIGNATURE_OF_JSON_WITH_FIELDS_IN_NON_ALPHABETICAL_ORDER = b'b021e1061c2b34ca5fe1b71ccb0327ecea1b9fa083fc6b4fe17d6c9ba53d4cf96b6e3901f04ba485284fdb220adbbfb9bca24275989f0744f549b8cd5f21f1e2'

@dataclass
class HttpResponse:
    status_code: float
    content: bytes
    headers: dict

class TestGetTcbInfo(unittest.TestCase):

    def get_proper_get_tcb_info_response(self):
        return HttpResponse(200,
            b''.join([
                b'{"tcbInfo":',
                JSON_WITH_FIELDS_IN_NON_ALPHABETICAL_ORDER,
                b',"signature":"',
                SIGNATURE_OF_JSON_WITH_FIELDS_IN_NON_ALPHABETICAL_ORDER,
                b'"}'
            ]), {
            'Request-ID': 'request-id',
            'TCB-Info-Issuer-Chain': ISSUER_CHAIN,
            'Content-Type': 'application/json'
            })

    fmspc = '30806F040000'
    update = 'standard'
    type = 'sgx'

    def test_get_tcb_info_unsuccessful_status_code(self):
        response = self.get_proper_get_tcb_info_response()
        response.status_code = 500

        with patch.object(PCS, '_get_request', return_value=response):
            pcs = PCS(PCS_SERVICE_URL, 4, 'apiKey')
            none = pcs.get_tcb_info(self.fmspc, self.type, self.update)

            self.assertEqual(none, None)

    def test_get_tcb_info_no_request_id_header(self):
        response = self.get_proper_get_tcb_info_response()
        del response.headers['Request-ID']

        with patch.object(PCS, '_get_request', return_value=response):
            pcs = PCS(PCS_SERVICE_URL, 4, 'apiKey')
            none = pcs.get_tcb_info(self.fmspc, self.type, self.update)

            self.assertEqual(none, None)
            self.assertListEqual(pcs.Errors, ['Response missing Request-ID header'])

    def test_get_tcb_info_no_issuer_chain_header(self):
        response = self.get_proper_get_tcb_info_response()
        del response.headers['TCB-Info-Issuer-Chain']

        with patch.object(PCS, '_get_request', return_value=response):
            pcs = PCS(PCS_SERVICE_URL, 4, 'apiKey')
            none = pcs.get_tcb_info(self.fmspc, self.type, self.update)

            self.assertEqual(none, None)
            self.assertListEqual(pcs.Errors, ['Response missing TCB_INFO_ISSUER_CHAIN header'])

    def test_get_tcb_info_no_content_type_header(self):
        response = self.get_proper_get_tcb_info_response()
        del response.headers['Content-Type']

        with patch.object(PCS, '_get_request', return_value=response):
            pcs = PCS(PCS_SERVICE_URL, 4, 'apiKey')
            none = pcs.get_tcb_info(self.fmspc, self.type, self.update)

            self.assertEqual(none, None)
            self.assertListEqual(pcs.Errors, ['Content-Type should be application/json'])

    def test_get_tcb_info_wrong_content_type_header(self):
        response = self.get_proper_get_tcb_info_response()
        response.headers['Content-Type'] = 'application/octet-stream'

        with patch.object(PCS, '_get_request', return_value=response):
            pcs = PCS(PCS_SERVICE_URL, 4, 'apiKey')
            none = pcs.get_tcb_info(self.fmspc, self.type, self.update)

            self.assertEqual(none, None)
            self.assertListEqual(pcs.Errors, ['Content-Type should be application/json'])

    def test_get_tcb_info_not_trusted_chain(self):
        response = self.get_proper_get_tcb_info_response()
        response.headers['TCB-Info-Issuer-Chain'] = response.headers['TCB-Info-Issuer-Chain'].replace('wm', 'dd')

        with patch.object(PCS, '_get_request', return_value=response):
            pcs = PCS(PCS_SERVICE_URL, 4, 'apiKey')
            none = pcs.get_tcb_info(self.fmspc, self.type, self.update)

            self.assertEqual(none, None)
            self.assertListEqual(pcs.Errors, ['Could not validate certificate using trust chain'])


    def test_get_tcb_info_no_tcb_info_in_body(self):
        response = self.get_proper_get_tcb_info_response()
        response.content = b'{}'

        with patch.object(PCS, '_get_request', return_value=response):
            pcs = PCS(PCS_SERVICE_URL, 4, 'apiKey')
            none = pcs.get_tcb_info(self.fmspc, self.type, self.update)

            self.assertEqual(none, None)
            self.assertListEqual(pcs.Errors, ['Could not extract tcbInfo from JSON'])


    def test_get_tcb_info_positive_signature_after_object(self):
        response = self.get_proper_get_tcb_info_response()

        with patch.object(PCS, '_get_request', return_value=response):
            pcs = PCS(PCS_SERVICE_URL, 4, 'apiKey')
            [data, issuer_chain] = pcs.get_tcb_info(self.fmspc, self.type, self.update)

            self.assertEqual(data, response.content)
            self.assertEqual(issuer_chain, response.headers['TCB-Info-Issuer-Chain'])
            self.assertListEqual(pcs.Errors, [])

    def test_get_tcb_info_positive_signature_before_object(self):
        response = self.get_proper_get_tcb_info_response()
        response.content = b''.join([
            b'{"signature":"',
            SIGNATURE_OF_JSON_WITH_FIELDS_IN_NON_ALPHABETICAL_ORDER,
            b'","tcbInfo":',
            JSON_WITH_FIELDS_IN_NON_ALPHABETICAL_ORDER,
            b'}'
        ])

        with patch.object(PCS, '_get_request', return_value=response):
            pcs = PCS(PCS_SERVICE_URL, 4, 'apiKey')
            [data, issuer_chain] = pcs.get_tcb_info(self.fmspc, self.type, self.update)

            self.assertEqual(data, response.content)
            self.assertEqual(issuer_chain, response.headers['TCB-Info-Issuer-Chain'])
            self.assertListEqual(pcs.Errors, [])


class TestGetEnclaveIdentity(unittest.TestCase):

    def get_proper_get_enclave_identity_response(self):
        return HttpResponse(200,
            b''.join([
                b'{"enclaveIdentity":',
                JSON_WITH_FIELDS_IN_NON_ALPHABETICAL_ORDER,
                b',"signature":"',
                SIGNATURE_OF_JSON_WITH_FIELDS_IN_NON_ALPHABETICAL_ORDER,
                b'"}'
            ]), {
            'Request-ID': 'request-id',
            'SGX-Enclave-Identity-Issuer-Chain': ISSUER_CHAIN,
            'Content-Type': 'application/json'
        })

    name = 'QE'
    update = 'standard'

    def test_get_enclave_identity_unsuccessful_status_code(self):
        response = self.get_proper_get_enclave_identity_response()
        response.status_code = 500

        with patch.object(PCS, '_get_request', return_value=response):
            pcs = PCS(PCS_SERVICE_URL, 4, 'apiKey')
            none = pcs.get_enclave_identity(self.name, self.update)

            self.assertEqual(none, None)

    def test_get_enclave_identity_no_request_id_header(self):
        response = self.get_proper_get_enclave_identity_response()
        del response.headers['Request-ID']

        with patch.object(PCS, '_get_request', return_value=response):
            pcs = PCS(PCS_SERVICE_URL, 4, 'apiKey')
            none = pcs.get_enclave_identity(self.name, self.update)

            self.assertEqual(none, None)
            self.assertListEqual(pcs.Errors, ['Response missing Request-ID header'])

    def test_get_enclave_identity_no_issuer_chain_header(self):
        response = self.get_proper_get_enclave_identity_response()
        del response.headers['SGX-Enclave-Identity-Issuer-Chain']

        with patch.object(PCS, '_get_request', return_value=response):
            pcs = PCS(PCS_SERVICE_URL, 4, 'apiKey')
            none = pcs.get_enclave_identity(self.name, self.update)

            self.assertEqual(none, None)
            self.assertListEqual(pcs.Errors, ['Response missing SGX-Enclave-Identity-Issuer-Chain header'])

    def test_get_enclave_identity_no_content_type_header(self):
        response = self.get_proper_get_enclave_identity_response()
        del response.headers['Content-Type']

        with patch.object(PCS, '_get_request', return_value=response):
            pcs = PCS(PCS_SERVICE_URL, 4, 'apiKey')
            none = pcs.get_enclave_identity(self.name, self.update)

            self.assertEqual(none, None)
            self.assertListEqual(pcs.Errors, ['Content-Type should be application/json'])

    def test_get_enclave_identity_wrong_content_type_header(self):
        response = self.get_proper_get_enclave_identity_response()
        response.headers['Content-Type'] = 'application/octet-stream'

        with patch.object(PCS, '_get_request', return_value=response):
            pcs = PCS(PCS_SERVICE_URL, 4, 'apiKey')
            none = pcs.get_enclave_identity(self.name, self.update)

            self.assertEqual(none, None)
            self.assertListEqual(pcs.Errors, ['Content-Type should be application/json'])

    def test_get_enclave_identity_not_trusted_chain(self):
        response = self.get_proper_get_enclave_identity_response()
        response.headers['SGX-Enclave-Identity-Issuer-Chain'] = response.headers['SGX-Enclave-Identity-Issuer-Chain'].replace('wm', 'dd')

        with patch.object(PCS, '_get_request', return_value=response):
            pcs = PCS(PCS_SERVICE_URL, 4, 'apiKey')
            none = pcs.get_enclave_identity(self.name, self.update)

            self.assertEqual(none, None)
            self.assertListEqual(pcs.Errors, ['Could not validate certificate using trust chain'])


    def test_get_enclave_identity_no_enclave_identity_in_body(self):
        response = self.get_proper_get_enclave_identity_response()
        response.content = b'{}'

        with patch.object(PCS, '_get_request', return_value=response):
            pcs = PCS(PCS_SERVICE_URL, 4, 'apiKey')
            none = pcs.get_enclave_identity(self.name, self.update)

            self.assertEqual(none, None)
            self.assertListEqual(pcs.Errors, ['Could not extract enclaveIdentity from JSON'])

    def test_get_enclave_identity_positive_signature_after_object(self):
        response = self.get_proper_get_enclave_identity_response()

        with patch.object(PCS, '_get_request', return_value=response):
            pcs = PCS(PCS_SERVICE_URL, 4, 'apiKey')
            [data, issuer_chain] = pcs.get_enclave_identity(self.name, self.update)

            self.assertEqual(data, response.content)
            self.assertEqual(issuer_chain, response.headers['SGX-Enclave-Identity-Issuer-Chain'])
            self.assertListEqual(pcs.Errors, [])

    def test_get_enclave_identity_positive_signature_before_object(self):
        response = self.get_proper_get_enclave_identity_response()
        response.content = b''.join([
            b'{"signature":"',
            SIGNATURE_OF_JSON_WITH_FIELDS_IN_NON_ALPHABETICAL_ORDER,
            b'","enclaveIdentity":',
            JSON_WITH_FIELDS_IN_NON_ALPHABETICAL_ORDER,
            b'}'
        ])

        with patch.object(PCS, '_get_request', return_value=response):
            pcs = PCS(PCS_SERVICE_URL, 4, 'apiKey')
            [data, issuer_chain] = pcs.get_enclave_identity(self.name, self.update)

            self.assertEqual(data, response.content)
            self.assertEqual(issuer_chain, response.headers['SGX-Enclave-Identity-Issuer-Chain'])
            self.assertListEqual(pcs.Errors, [])

if __name__ == '__main__':
    unittest.main()