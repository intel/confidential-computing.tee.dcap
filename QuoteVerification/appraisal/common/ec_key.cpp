/*
* Copyright(c) 2011-2026 Intel Corporation
*
* SPDX-License-Identifier: BSD-3-Clause
*/

#include "jwt-cpp/jwt.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/bio.h>
#include <string>

#define ECP384_KEY_SIZE 48

#define CHECK_NULL_BREAK(p) \
    if (!p)                 \
    {                       \
        break;              \
    }
static std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> get_ec_pub_key_from_xy(const std::string &x, const std::string &y)
{
    if(x.empty() == true || y.empty() == true)
    {
        return std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(nullptr, nullptr);
    }
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

bool convert_jwk_to_pem_str(std::string &jwk_json, std::string &pem_str)
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

static int generate_ec384_pkey(EVP_PKEY **ppkey)
{
    if (ppkey == NULL)
        return -1;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = -1;
    do
    {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (ctx == NULL)
            break;
        if (EVP_PKEY_keygen_init(ctx) <= 0)
            break;
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1) <= 0)
            break;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
            break;

        *ppkey = pkey;
        ret = 0;
    } while (0);

    EVP_PKEY_CTX_free(ctx);
    if (ret != 0)
        EVP_PKEY_free(pkey);
    return ret;
}

static std::string generate_pub_jwk_from_ec_pkey(EVP_PKEY *pkey)
{
    if (pkey == NULL || EVP_PKEY_bits(pkey) != ECP384_KEY_SIZE * 8)
    {
        return "";
    }

    bool flag = false;
    BIGNUM *bn_x = NULL, *bn_y = NULL;
    uint8_t x[ECP384_KEY_SIZE] = {0};
    uint8_t y[ECP384_KEY_SIZE] = {0};

    do
    {
        if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &bn_x))
        {
            break;
        }
        if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &bn_y))
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

    if (flag == true)
    {
        std::string xin((char *)x, ECP384_KEY_SIZE);
        std::string sx = jwt::base::encode<jwt::alphabet::base64url>(jwt::base::pad<jwt::alphabet::base64url>(xin));
        std::string yin((char *)y, ECP384_KEY_SIZE);
        std::string sy = jwt::base::encode<jwt::alphabet::base64url>(jwt::base::pad<jwt::alphabet::base64url>(yin));

        // Generate jwk
        rapidjson::Document doc;
        doc.SetObject();

        doc.AddMember("alg", "ES384", doc.GetAllocator());
        doc.AddMember("kty", "EC", doc.GetAllocator());
        {
            rapidjson::Value str(rapidjson::kStringType);
            str.SetString(sx.c_str(), (unsigned int)sx.length());
            doc.AddMember("x", str, doc.GetAllocator());
        }
        {
            rapidjson::Value str(rapidjson::kStringType);
            str.SetString(sy.c_str(), (unsigned int)sy.length());
            doc.AddMember("y", str, doc.GetAllocator());
        }
        doc.AddMember("crv", "P-384", doc.GetAllocator());

        rapidjson::StringBuffer buf;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buf);
        doc.Accept(writer);
        std::string jwk = buf.GetString();

        {
            // Check jwk
            std::string pub_key;
            if (convert_jwk_to_pem_str(jwk, pub_key) == false)
            {
                return "";
            }
        }
        return jwk;
    }
    return "";
}

// Generate EC384 key pair:
//     EC private key (PEM format)
//     EC public key ( JWK format)
int generate_ec384_keys(std::string &pub_jwk, std::string &priv_key)
{
    EVP_PKEY *pkey = NULL;

    if (generate_ec384_pkey(&pkey) != 0)
    {
        return -1;
    }
    std::string jwk = generate_pub_jwk_from_ec_pkey(pkey);
    if (jwk == "")
    {
        EVP_PKEY_free(pkey);
        return -1;
    }

    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        EVP_PKEY_free(pkey);
        return -1;
    }
    if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL))
    {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return -1;
    }
    if (BIO_flush(bio) != 1)
    {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return -1;
    }
    size_t size = BIO_number_written(bio) + 1;
    void *buf = malloc(size);
    if (buf == NULL)
    {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return -1;
    }
    memset(buf, 0, size);
    if (BIO_read(bio, buf, (int)size - 1) < 1)
    {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        free(buf);
        return -1;
    }
    std::string key((char *)buf);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    free(buf);

    priv_key = key;
    pub_jwk = jwk;
    return 0;
}