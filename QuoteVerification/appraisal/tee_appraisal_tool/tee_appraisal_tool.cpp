/**
 * Copyright (c) 2011-2025, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Intel Corporation nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "jwt-cpp/jwt.h"
#include "se_version.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "se_trace.h"
#include "file_util.h"
#include "format_util.h"
#include "gen_payload.h"
#include "tee_appraisal_tool.h"
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#include <string>
#include <iostream>
#include <elf.h>

template <typename T>
std::string json_stringify(const T &obj)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    obj.Accept(writer);
    return sb.GetString();
}

#define CHECK_NULL_BREAK(p) \
    if (!p)                 \
    {                       \
        break;              \
    }
    
static std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> get_ec_pub_key_from_xy(const std::string &x, const std::string &y)
{
    const auto dx = jwt::base::decode<jwt::alphabet::base64url>(jwt::base::pad<jwt::alphabet::base64url>(x));
    const auto dy = jwt::base::decode<jwt::alphabet::base64url>(jwt::base::pad<jwt::alphabet::base64url>(y));
    BIGNUM *bx = NULL;
    BIGNUM *by = NULL;
    EC_POINT *point = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EC_GROUP *ec_group = NULL;
    size_t len = 0;
    uint8_t *octet_str = NULL;
    OSSL_PARAM_BLD *params_build = NULL;
    OSSL_PARAM *params = NULL;
    bool flag = false;
    do
    {

        bx = BN_bin2bn(reinterpret_cast<const unsigned char *>(dx.c_str()), (int)dx.length(), 0);
        CHECK_NULL_BREAK(bx);
        by = BN_bin2bn(reinterpret_cast<const unsigned char *>(dy.c_str()), (int)dy.length(), 0);
        CHECK_NULL_BREAK(by);

        ec_group = EC_GROUP_new_by_curve_name(NID_secp384r1);
        CHECK_NULL_BREAK(ec_group);
        point = EC_POINT_new(ec_group);
        CHECK_NULL_BREAK(point);
        if (EC_POINT_set_affine_coordinates(ec_group, point, bx, by, NULL) != 1)
        {
            break;
        }
        if (EC_POINT_is_on_curve(ec_group, point, NULL) != 1)
        {
            break;
        }
        len = EC_POINT_point2oct(ec_group, point, POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
        if (len == 0)
        {
            break;
        }
        octet_str = (uint8_t *)malloc(len);
        CHECK_NULL_BREAK(octet_str);
        if (EC_POINT_point2oct(ec_group, point, POINT_CONVERSION_COMPRESSED, octet_str, len, NULL) == 0)
        {
            break;
        }

        params_build = OSSL_PARAM_BLD_new();
        CHECK_NULL_BREAK(params_build);

        if (1 != OSSL_PARAM_BLD_push_utf8_string(params_build, "group", SN_secp384r1, 0))
        {
            break;
        }
        if (1 != OSSL_PARAM_BLD_push_octet_string(params_build, OSSL_PKEY_PARAM_PUB_KEY, octet_str, len))
        {
            break;
        }
        params = OSSL_PARAM_BLD_to_param(params_build);
        CHECK_NULL_BREAK(params);

        // get pkey from params
        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        CHECK_NULL_BREAK(pkey_ctx);

        if (1 != EVP_PKEY_fromdata_init(pkey_ctx))
        {
            break;
        }
        if (1 != EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params))
        {
            break;
        }

        flag = true;
    } while (0);

    BN_free(bx);
    BN_free(by);
    EC_GROUP_free(ec_group);
    EC_POINT_clear_free(point);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(params_build);
    EVP_PKEY_CTX_free(pkey_ctx);
    free(octet_str);

    if (flag == false)
    {
        EVP_PKEY_free(pkey);
        return std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(nullptr, nullptr);
    }
    else
    {
        return std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(pkey, EVP_PKEY_free);
    }
}

static bool convert_jwk_to_pem_str(std::string jwk_json, std::string &pem_str)
{
    if (jwk_json.empty() == true)
    {
        return false;
    }
    rapidjson::Document jwk_doc;
    jwk_doc.Parse<rapidjson::kParseCommentsFlag>(jwk_json.c_str());
    if (jwk_doc.HasParseError() || jwk_doc.HasMember("x") == false || jwk_doc.HasMember("y") == false)
    {
        return false;
    }
    rapidjson::Value &vx = jwk_doc["x"];
    rapidjson::Value &vy = jwk_doc["y"];
    if (vx.IsString() == false || vy.IsString() == false)
    {
        return false;
    }
    auto ec_pubkey = get_ec_pub_key_from_xy(vx.GetString(), vy.GetString());
    if (!ec_pubkey)
    {
        return false;
    }

    BIO *bio = NULL;
    if (!(bio = BIO_new(BIO_s_mem())))
    {
        return false;
    }

    if (0 == PEM_write_bio_PUBKEY(bio, ec_pubkey.get()))
    {
        BIO_free(bio);
        return false;
    }
    size_t st = BIO_number_written(bio) + 1;
    char *pem = (char *)malloc(st);
    if (pem == NULL)
    {
        BIO_free(bio);
        return false;
    }
    memset(pem, 0, st);
    if (BIO_read(bio, pem, (int)st - 1) <= 0)
    {
        BIO_free(bio);
        free(pem);
        return false;
    }
    pem_str = pem;
    BIO_free(bio);
    free(pem);
    return true;
}

CAppraisalUtil::CAppraisalUtil()
    : m_infile(NULL),m_outfile(NULL), m_keyfile(NULL), m_verbose(false)
{
}

CAppraisalUtil::~CAppraisalUtil()
{
}

bool CAppraisalUtil::run(int argc, char **argv)
{
    cmd_t cmd = parse_cmd(argc, argv);
    int ret = false;
    switch (cmd)
    {
    case PRINT_USAGE:
        printf(USAGE);
        break;
    case PRINT_VERSION:
        printf(VERSION_STRING, STRFILEVER, COPYRIGHT);
        break;
    case GENERATE_PAYLOAD:
        ret = generate_payload();
        break;
    case SIGN_POLICY:
        ret = sign_policy();
        break;
    case VERIFY_POLICY:
        ret = verify_policy();
        break;
    default:
        se_trace(SE_TRACE_ERROR, "Command line is not correct.\n%s\n", USAGE);
        break;
    }
    return ret;
}

cmd_t CAppraisalUtil::parse_cmd(int argc, char **argv)
{
    cmd_t cmd = UNKNOWN_CMD;
    argc--;
    argv++;
    if (argc <= 0 || argv == NULL)
    {
        return cmd;
    }
    if (strcmp(*argv, "gen_payload") == 0)
    {
        cmd = GENERATE_PAYLOAD;
    }
    else if (strcmp(*argv, "sign_policy") == 0)
    {
        cmd = SIGN_POLICY;
    }
    else if (strcmp(*argv, "verify_policy") == 0)
    {
        cmd = VERIFY_POLICY;
    }
    else if (argc == 1 && (strcmp(*argv, "-help") == 0 || strcmp(*argv, "-h") == 0))
    {
        cmd = PRINT_USAGE;
    }
    else if (argc == 1 && strcmp(*argv, "-version") == 0)
    {
        cmd = PRINT_VERSION;
    }

    argc--;
    argv++;
    while (argc >= 1)
    {
        if (strcmp(*argv, "-in") == 0)
        {
            if (--argc < 1)
            {
                return UNKNOWN_CMD;
            }
            m_infile = *(++argv);
        }
        else if (strcmp(*argv, "-key") == 0)
        {
            if (--argc < 1)
            {
                return UNKNOWN_CMD;
            }
            m_keyfile = *(++argv);
        }
        else if (strcmp(*argv, "-out") == 0)
        {
            if (--argc < 1)
            {
                return UNKNOWN_CMD;
            }
            m_outfile = *(++argv);
        }
        else if (strcmp(*argv, "-v") == 0)
        {
            m_verbose = true;
        }
        else
        {
            return UNKNOWN_CMD;
        }
        argc--;
        argv++;
    }

    return cmd;
}

bool CAppraisalUtil::generate_payload()
{
    if (!m_infile || !m_outfile)
    {
        se_trace(SE_TRACE_ERROR, "Command line is not correct.\n%s\n", USAGE);
        return false;
    }

    CPayloadGen pg(m_infile);
    std::string output_json = pg.generate_payload();
    if (output_json == "")
    {
        se_trace(SE_TRACE_ERROR, "Failed to generate the payload file.\n");
        return false;
    }
    if (m_verbose)
    {
        se_trace(SE_TRACE_ERROR, "The generated payload:\n%s\n", output_json.c_str());
    }
    if (!write_buffer_to_file(m_outfile, "w", reinterpret_cast<const uint8_t *>(output_json.c_str()), output_json.length(), 0))
    {
        se_trace(SE_TRACE_ERROR, "Failed to write the output file %s\n", m_outfile);
        return false;
    }
    return true;
}

bool CAppraisalUtil::sign_policy()
{
    if (!m_infile || !m_outfile || !m_keyfile)
    {
        se_trace(SE_TRACE_ERROR, "Command line is not correct.\n%s\n", USAGE);
        return false;
    }
    size_t insize = 0;
    uint8_t *inbuf = read_file_to_buffer(m_infile, &insize);
    if (!inbuf)
    {
        se_trace(SE_TRACE_ERROR, "Failed to read the input file %s\n", m_infile);
        return false;
    }
    // check the policy payload
    std::string payload((char *)inbuf, insize);
    free(inbuf);
    rapidjson::Document json;
    json.Parse<rapidjson::kParseCommentsFlag>(payload.c_str());
    if (json.HasParseError() || json.HasMember("policy_array") == false)
    {
        se_trace(SE_TRACE_ERROR, "Failed to parse the input file %s\n", m_infile);
        return false;
    }

    std::string pri_key;
    std::string jwk;
    std::tie(pri_key, jwk) = parse_ec_key();
    if (pri_key == "" || jwk == "")
    {
        se_trace(SE_TRACE_ERROR, "Failed to parse the input key file %s\n", m_keyfile);
        return false;
    }

    auto token = jwt::create()
                     .set_type("JWT")
                     .set_header_claim("jwk", jwt::claim(jwk))
                     .set_payload_claim(CLAIM_NAME, jwt::claim(payload))
                     .sign(jwt::algorithm::es384("", pri_key, "", ""));

    if (m_verbose)
    {
        se_trace(SE_TRACE_ERROR, "The Public jwk is: \n%s\nThe Payload is:\n%s\n", jwk.c_str(), payload.c_str());
    }

    se_trace(SE_TRACE_ERROR, "The signed token: \n%s\n", token.c_str());
    if (!write_buffer_to_file(m_outfile, "w", (const uint8_t *)token.c_str(), token.length(), 0))
    {
        se_trace(SE_TRACE_ERROR, "Failed to write the signed token to the output file %s\n", m_outfile);
        return false;
    }
    return true;
}

bool CAppraisalUtil::verify_policy()
{
    if (!m_infile)
    {
        se_trace(SE_TRACE_ERROR, "Command line is not correct.\n%s\n", USAGE);
        return false;
    }
    size_t insize = 0;
    uint8_t *inbuf = read_file_to_buffer(m_infile, &insize);
    if (!inbuf)
    {
        se_trace(SE_TRACE_ERROR, "Failed to read the input file %s\n", m_infile);
        return false;
    }
    std::string jwt_str((const char *)inbuf, insize);
    free(inbuf);

    try
    {
        auto decoded = jwt::decode(jwt_str);
        auto alg = decoded.get_algorithm();
        auto typ = decoded.get_type();
        if (alg == "ES384" && (typ == "JWS" || typ == "JWT"))
        {
            if (decoded.has_header_claim("jwk") == false)
            {
                se_trace(SE_TRACE_ERROR, "Failed to verify the policy in the input file %s\n", m_infile);
                return false;
            }
            auto jwk_json = decoded.get_header_claim("jwk").to_json();

            std::string pub_key;
            if (convert_jwk_to_pem_str(jwk_json.to_str(), pub_key) == false)
            {
                se_trace(SE_TRACE_ERROR, "Failed to verify the policy in the input file %s\n", m_infile);
                return false;
            }
            auto verifier =
                jwt::verify()
                    .allow_algorithm(jwt::algorithm::es384(pub_key));
            try
            {
                verifier.verify(decoded);
            }
            catch (...)
            {
                se_trace(SE_TRACE_ERROR, "Failed to verify the policy in the input file %s\n", m_infile);
                return false;
            }
            if (decoded.has_payload_claim(CLAIM_NAME) == true)
            {
                if (m_verbose)
                {
                    std::string payload = decoded.get_payload();
                    se_trace(SE_TRACE_ERROR, "The Public jwk is:\n%s\nThe payload is:\n%s\n", jwk_json.to_str().c_str(), decoded.get_payload().c_str());
                }
                se_trace(SE_TRACE_ERROR, "The policy format is correct and could be used for Appraisal.\n");
                return true;
            }

            se_trace(SE_TRACE_ERROR, "The policy format is not correct.\n");
            return false;
        }
    }
    catch (...)
    {
        se_trace(SE_TRACE_ERROR, "Failed to verify the policy in the input file %s\n", m_infile);
    }

    return false;
}

std::tuple<std::string, std::string> CAppraisalUtil::parse_ec_key()
{
    if (!m_keyfile)
        return std::make_tuple("", "");

    bool flag = false;
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = NULL;
    BIGNUM *bn_x = NULL, *bn_y = NULL;
    BIGNUM *bn_r = NULL;
    EC_GROUP *ec_group = NULL;
    EC_POINT *pub_ec_point = NULL;
    BN_CTX *tmp = NULL;
    uint8_t x[ECP384_KEY_SIZE] = {0};
    uint8_t y[ECP384_KEY_SIZE] = {0};
    int id=0;

    do
    {
        // Read the private key and calculate the public key
        bio = BIO_new_file(m_keyfile, "r");
        if(bio == NULL)
        {
            se_trace(SE_TRACE_ERROR, "The input key file %s is not correct. It must be a PEM-formatted, 384-byte EC private key.\n", m_keyfile);
            break;
        }
        pkey = NULL;
        if (!PEM_read_bio_PrivateKey(bio, &pkey, 0, 0))
        {
            se_trace(SE_TRACE_ERROR, "The input key file %s is not correct. It must be a PEM-formatted, 384-byte EC private key.\n", m_keyfile);
            break;
        }
        if (EVP_PKEY_bits(pkey) != 384)
        {
            se_trace(SE_TRACE_ERROR, "The input key file %s is not correct. It must be a PEM-formatted, 384-byte EC private key.\n", m_keyfile);
            break;
        }
        id = EVP_PKEY_get_id(pkey);
        if(id != NID_X9_62_id_ecPublicKey)
        {
            se_trace(SE_TRACE_ERROR, "The input key file %s is not correct. It must be a PEM-formatted, 384-byte EC private key.\n", m_keyfile);
            break;
        }
        if(!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn_r))
        {
            se_trace(SE_TRACE_ERROR, "The input key file %s is not correct. It must be a PEM-formatted, 384-byte EC private key.\n", m_keyfile);
            break;
        }
        ec_group = EC_GROUP_new_by_curve_name(NID_secp384r1);
        if (!ec_group)
        {
            break;
        }
        pub_ec_point = EC_POINT_new(ec_group);
        if (!pub_ec_point)
        {
            break;
        }
        tmp = BN_CTX_new();
        if (!tmp)
        {
            break;
        }
        bn_x = BN_new();
        if (!bn_x)
        {
            break;
        }
        bn_y = BN_new();
        if (!bn_y)
        {
            break;
        }
        if (!EC_POINT_mul(ec_group, pub_ec_point, bn_r, NULL, NULL, tmp))
        {
            break;
        }
        if (!EC_POINT_get_affine_coordinates(ec_group, pub_ec_point, bn_x, bn_y, tmp))
        {
            break;
        }
        if (BN_num_bytes(bn_x) > ECP384_KEY_SIZE || BN_num_bytes(bn_y) > ECP384_KEY_SIZE)
        {
            break;
        }
        if (!BN_bn2bin(bn_x, x))
        {
            break;
        }
        if (!BN_bn2bin(bn_y, y))
        {
            break;
        }
        flag = true;
    } while (0);

    BN_clear_free(bn_x);
    BN_clear_free(bn_y);
    BN_clear_free(bn_r);
    BN_CTX_free(tmp);
    EC_GROUP_free(ec_group);
    EC_POINT_clear_free(pub_ec_point);
    EVP_PKEY_free(pkey);
    BIO_free(bio);

    if (flag == true)
    {
        std::string xin((char *)x, ECP384_KEY_SIZE);
        std::string sx = jwt::base::encode<jwt::alphabet::base64url>(jwt::base::pad<jwt::alphabet::base64url>(xin));
        std::string yin((char *)y, ECP384_KEY_SIZE);
        std::string sy = jwt::base::encode<jwt::alphabet::base64url>(jwt::base::pad<jwt::alphabet::base64url>(yin));

        // Generate jwk
        rapidjson::Document doc;
        doc.SetObject();
        rapidjson::Value v;
        v.SetObject();

        v.AddMember("alg", "ES384", doc.GetAllocator());
        v.AddMember("kty", "EC", doc.GetAllocator());
        {
            rapidjson::Value str(rapidjson::kStringType);
            str.SetString(sx.c_str(), (unsigned int)sx.length());
            v.AddMember("x", str, doc.GetAllocator());
        }
        {
            rapidjson::Value str(rapidjson::kStringType);
            str.SetString(sy.c_str(), (unsigned int)sy.length());
            v.AddMember("y", str, doc.GetAllocator());
        }
        v.AddMember("crv", "P-384", doc.GetAllocator());

        std::string jwk = json_stringify(v);

        size_t size = 0;
        uint8_t *buf = read_file_to_buffer(m_keyfile, &size);
        if (!buf || size == 0)
            return std::make_tuple("", "");
        std::string pri_key((const char *)buf, size);
        free(buf);
        return std::make_tuple(pri_key, jwk);
    }
    return std::make_tuple("", "");
}