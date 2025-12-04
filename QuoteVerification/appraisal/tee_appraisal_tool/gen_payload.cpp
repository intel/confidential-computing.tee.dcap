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

#include "gen_payload.h"
#include "sgx_quote_5.h"
#include "file_util.h"
#include "format_util.h"
#include "se_trace.h"
#include "metadata.h"
#include "arch.h"
#include "sgx_error.h"
#include "util.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include <string.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <array>
#include <elf.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <fcntl.h>

template <typename T>
std::string json_stringify(const T &obj)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    obj.Accept(writer);
    return sb.GetString();
}

CInputEnclave::CInputEnclave(const char *file)
    : m_file(file), m_class_id("bef7cb8c-31aa-42c1-854c-10db005d5c41")
{
}

CInputEnclave::~CInputEnclave()
{}

bool CInputEnclave::get_meta_offset(const uint8_t *start_addr, uint64_t &meta_offset)
{
    const Elf64_Ehdr *elf_hdr = (Elf64_Ehdr *)start_addr;

    const Elf64_Shdr *shdr = GET_PTR(Elf64_Shdr, elf_hdr, elf_hdr->e_shoff);
    assert(sizeof(Elf64_Shdr) == elf_hdr->e_shentsize);

    const char *shstrtab = GET_PTR(char, elf_hdr, shdr[elf_hdr->e_shstrndx].sh_offset);

    unsigned idx = 0;
    for (; idx < elf_hdr->e_shnum; ++idx, ++shdr)
    {
        if (!strcmp(shstrtab + shdr->sh_name, ".note.sgxmeta"))
            break;
    }
    if (idx == elf_hdr->e_shnum)
    {
        // Cannot find the metadata section
        printf("ERROR: The enclave image should have '.note.sgxmeta' section\n");
        return false;
    }

    // We require that enclaves should have .note.sgxmeta section to store the metadata information
    // We limit this section is used for metadata only and ISV should not extend this section.
    //
    /* .note.sgxmeta layout:
     *
     * |  namesz         |
     * |  metadata size  |
     * |  type           |
     * |  name           |
     * |  metadata       |
     */

    Elf64_Nhdr *note = GET_PTR(Elf64_Nhdr, start_addr, shdr->sh_offset);
    if (note == NULL)
        return false;
    if (shdr->sh_size != ROUND_TO(sizeof(Elf64_Nhdr) + note->n_namesz + note->n_descsz, shdr->sh_addralign))
    {
        printf("ERROR: The '.note.sgxmeta' section size is not correct.\n");
        return false;
    }
    const char *meta_name = "sgx_metadata";
    if (note->n_namesz != (strlen(meta_name) + 1) || memcmp(GET_PTR(void, start_addr, shdr->sh_offset + sizeof(Elf64_Nhdr)), meta_name, note->n_namesz))
    {
        printf("ERROR: The note in the '.note.sgxmeta' section must be named as \"sgx_metadata\"\n");
        return false;
    }
    meta_offset = static_cast<uint64_t>(shdr->sh_offset + sizeof(Elf64_Nhdr) + note->n_namesz);
    return true;
}

bool CInputEnclave::get_metadata_from_file(metadata_t &metadata)
{
    off_t file_size = 0;
    se_file_handle_t fh = open(m_file, O_RDONLY);
    if (fh == -1)
    {
        printf("Failed to open the input file '%s'.\n", m_file);
        return false;
    }

    std::unique_ptr<map_handle_t, void (*)(map_handle_t *)> mh(map_file(fh, &file_size), unmap_file);
    if (!mh)
    {
        close(fh);
        return false;
    }
    uint64_t meta_offset = 0;
    bool ret = get_meta_offset(mh->base_addr, meta_offset);
    close(fh);

    if (ret == true)
    {
        std::ifstream ifs(m_file, std::ios::binary | std::ios::in);
        if (!ifs.good())
        {
            printf("Failed to open the verify file '%s'.\n", m_file);
            return false;
        }
        ifs.seekg(meta_offset, ifs.beg);
        ifs.read(reinterpret_cast<char *>(&metadata), sizeof(metadata));
        ifs.close();
    }
    return ret;
}

std::string CInputEnclave::generate_payload()
{
    metadata_t metadata;

    if (get_metadata_from_file(metadata) == false)
    {
        return "";
    }
    uint8_t mrsigner[SHA256_DIGEST_LENGTH];
    unsigned int hash_len = 0;
    EVP_MD_CTX *evp_ctx = EVP_MD_CTX_new();
    if(evp_ctx )
    if (EVP_DigestInit_ex(evp_ctx, EVP_sha256(), NULL) != 1)
    {
        EVP_MD_CTX_free(evp_ctx);
        return "";
    }
    if (EVP_DigestUpdate(evp_ctx, metadata.enclave_css.key.modulus, SE_KEY_SIZE) != 1)
    {
        EVP_MD_CTX_free(evp_ctx);
        return "";
    }
    if (EVP_DigestFinal(evp_ctx, mrsigner, &hash_len) != 1)
    {
        EVP_MD_CTX_free(evp_ctx);
        return "";
    }
    EVP_MD_CTX_free(evp_ctx);
    if (hash_len != SHA256_DIGEST_LENGTH)
    {
        return "";
    }

    rapidjson::Document doc;
    doc.SetObject();
    std::string description = "";
    rapidjson::Value env(rapidjson::kObjectType);
    {
        rapidjson::Value str_v(rapidjson::kStringType);
        str_v.SetString(m_class_id.c_str(), (unsigned int)m_class_id.length());
        env.AddMember("class_id", str_v, doc.GetAllocator());
        description = "Application SGX Enclave Policy";
        str_v.SetString(description.c_str(), (unsigned int)description.length());
        env.AddMember("description", str_v, doc.GetAllocator());
    }
    rapidjson::Value ref(rapidjson::kObjectType);
    {
        rapidjson::Value str_v(rapidjson::kStringType);
        str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&metadata.enclave_css.body.misc_select), sizeof(metadata.enclave_css.body.misc_select)).c_str(), doc.GetAllocator());
        ref.AddMember("sgx_miscselect", str_v, doc.GetAllocator());
        str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&metadata.enclave_css.body.misc_mask), sizeof(metadata.enclave_css.body.misc_mask)).c_str(), doc.GetAllocator());
        ref.AddMember("sgx_miscselect_mask", str_v, doc.GetAllocator());

        sgx_attributes_t attr;
        attr.flags = metadata.enclave_css.body.attributes.flags | SGX_FLAGS_INITTED;
        attr.xfrm = metadata.enclave_css.body.attributes.xfrm;
        str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&attr), sizeof(attr)).c_str(), doc.GetAllocator());
        ref.AddMember("sgx_attributes", str_v, doc.GetAllocator());
        str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&metadata.enclave_css.body.attribute_mask), sizeof(metadata.enclave_css.body.attribute_mask)).c_str(), doc.GetAllocator());
        ref.AddMember("sgx_attributes_mask", str_v, doc.GetAllocator());
        str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&metadata.enclave_css.body.enclave_hash), sizeof(metadata.enclave_css.body.enclave_hash)).c_str(), doc.GetAllocator());
        ref.AddMember("sgx_mrenclave", str_v, doc.GetAllocator());
        str_v.SetString(bytes_to_string(mrsigner, SHA256_DIGEST_LENGTH).c_str(), doc.GetAllocator());
        ref.AddMember("sgx_mrsigner", str_v, doc.GetAllocator());
        ref.AddMember("sgx_isvprodid", metadata.enclave_css.body.isv_prod_id, doc.GetAllocator());
        ref.AddMember("sgx_isvsvn_min", metadata.enclave_css.body.isv_svn, doc.GetAllocator());
        str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&metadata.enclave_css.body.isv_family_id), sizeof(metadata.enclave_css.body.isv_family_id)).c_str(), doc.GetAllocator());
        ref.AddMember("sgx_isvfamilyid", str_v, doc.GetAllocator());
        str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&metadata.enclave_css.body.isvext_prod_id), sizeof(metadata.enclave_css.body.isvext_prod_id)).c_str(), doc.GetAllocator());
        ref.AddMember("sgx_isvextprodid", str_v, doc.GetAllocator());

        if((metadata.enclave_css.body.attributes.flags & SGX_FLAGS_KSS))
        {
            // KSS feature is set. Add configid/configsvn in the policy payload. User needs to change the configid/configsvn manually
            sgx_config_id_t id;
            memset(&id, 0xFF, sizeof(sgx_config_id_t));
            sgx_config_svn_t svn = 0xFFFF;
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&id), sizeof(sgx_config_id_t)).c_str(), doc.GetAllocator());
            ref.AddMember("sgx_configid", str_v, doc.GetAllocator());
            ref.AddMember("sgx_configsvn_min", svn, doc.GetAllocator());
        }

    }
    rapidjson::Value policy_payload(rapidjson::kObjectType);
    {
        policy_payload.AddMember("environment", env, doc.GetAllocator());
        policy_payload.AddMember("reference", ref, doc.GetAllocator());
    }
    rapidjson::Value policy_array(rapidjson::kArrayType);
    policy_array.PushBack(policy_payload, doc.GetAllocator());
    doc.AddMember("policy_array", policy_array, doc.GetAllocator());

    std::string output_json = json_stringify(doc);
    size_t pos = output_json.find("\"sgx_configid");
    if(pos != std::string::npos)
    {
        output_json.insert(pos, "\n/* Below settings about sgx_configid/sgx_configsvn_min are only for placeholder. PLEASE edit these two fields manually */\n");
        se_trace(SE_TRACE_ERROR, "\033[0;32mNOTE: The generated payload includes two placeholders for KSS related fields \"sgx_configid\" and \"sgx_configsvn_min\". \
Please edit them with your own values.\n\033[0m");
    }
    return output_json;
}

CInputTDReport::CInputTDReport(const uint8_t *inbuf, size_t bsize, ftype_t ft)
    : m_report(inbuf), m_size(bsize), m_ftype(ft), m_class_id_v4("a1e4ee9c-a12e-48ac-bed0-e3f89297f687"), m_class_id_v5("45b734fc-aa4e-4c3d-ad28-e43d08880e68")
{
}

CInputTDReport::~CInputTDReport()
{

}
std::string CInputTDReport::generate_payload()
{
    const sgx_report2_t *report = reinterpret_cast<const sgx_report2_t *>(m_report);
    rapidjson::Document doc;
    doc.SetObject();
    std::string description = "";
    rapidjson::Value env(rapidjson::kObjectType);
    {
        rapidjson::Value str_v(rapidjson::kStringType);
        description = "Application TD TCB";
        if (m_ftype == TDX_REPORT_V15 || m_ftype == TDX_REPORT_V20)
        {
            str_v.SetString(m_class_id_v5.c_str(), (unsigned int)m_class_id_v5.length());
            description += " 1.5";
        }
        else
        {
            str_v.SetString(m_class_id_v4.c_str(), (unsigned int)m_class_id_v4.length());
            description += " 1.0";
        }
        env.AddMember("class_id", str_v, doc.GetAllocator());
        str_v.SetString(description.c_str(), (unsigned int)description.length());
        env.AddMember("description", str_v, doc.GetAllocator());
    }
    rapidjson::Value ref(rapidjson::kObjectType);
    {
        rapidjson::Value str_v(rapidjson::kStringType);
        if(m_ftype == TDX_REPORT_V15 || m_ftype == TDX_REPORT_V20)
        {
            const tee_info_v1_5_t *tee_info = reinterpret_cast<const tee_info_v1_5_t *>(report->tee_info);
            tee_attributes_t att = tee_info->attributes;
            if(ATTRIBUTES_HAS_DEBUG_BIT(att.a[0]))
            {
                se_trace(SE_TRACE_ERROR, "\033[0;33m Warning: TD runs in off-TD debug mode. Its VCPU state and private memory are accessible by the host VMM...\n\033[0m");
            }
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->attributes)), sizeof(tee_info->attributes)).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_attributes", str_v, doc.GetAllocator());
            uint64_t tmp_mask = TDX_DEFAULT_ATTRIBUTES_MASK;
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&tmp_mask), sizeof(tee_info->attributes)).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_attributes_mask", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->xfam)), sizeof(tee_info->xfam)).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_xfam", str_v, doc.GetAllocator());
            tmp_mask = TDX_DEFAULT_XFAM_MASK;
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&tmp_mask), sizeof(tee_info->attributes)).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_xfam_mask", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->mr_td)), sizeof(tee_info->mr_td)).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_mrtd", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->mr_config_id)), sizeof(tee_info->mr_config_id)).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_mrconfigid", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->mr_owner)), sizeof(tee_info->mr_owner)).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_mrowner", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->mr_owner_config)), sizeof(tee_info->mr_owner_config)).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_mrownerconfig", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->rt_mr[0])), sizeof(tee_info->rt_mr[0])).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_rtmr0", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->rt_mr[1])), sizeof(tee_info->rt_mr[1])).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_rtmr1", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->rt_mr[2])), sizeof(tee_info->rt_mr[2])).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_rtmr2", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->rt_mr[3])), sizeof(tee_info->rt_mr[3])).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_rtmr3", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->mr_servicetd)), sizeof(tee_info->mr_servicetd)).c_str(), doc.GetAllocator());
            if (report->report_mac_struct.report_type.version == 1)
            {
                ref.AddMember("tdx _mrservicetd", str_v, doc.GetAllocator());
            }
        }
        else
        {
            const tee_info_t *tee_info = reinterpret_cast<const tee_info_t *>(report->tee_info);
            tee_attributes_t att = tee_info->attributes;
            if(ATTRIBUTES_HAS_DEBUG_BIT(att.a[0]))
            {
                se_trace(SE_TRACE_ERROR, "\033[0;33m Warning: TD runs in off-TD debug mode. Its VCPU state and private memory are accessible by the host VMM...\n\033[0m");
            }
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->attributes)), sizeof(tee_info->attributes)).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_attributes", str_v, doc.GetAllocator());
            uint64_t tmp_mask = TDX_DEFAULT_ATTRIBUTES_MASK;
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&tmp_mask), sizeof(tee_info->attributes)).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_attributes_mask", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->xfam)), sizeof(tee_info->xfam)).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_xfam", str_v, doc.GetAllocator());
            tmp_mask = TDX_DEFAULT_XFAM_MASK;
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&tmp_mask), sizeof(tee_info->attributes)).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_xfam_mask", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->mr_td)), sizeof(tee_info->mr_td)).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_mrtd", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->mr_config_id)), sizeof(tee_info->mr_config_id)).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_mrconfigid", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->mr_owner)), sizeof(tee_info->mr_owner)).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_mrowner", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->mr_owner_config)), sizeof(tee_info->mr_owner_config)).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_mrownerconfig", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->rt_mr[0])), sizeof(tee_info->rt_mr[0])).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_rtmr0", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->rt_mr[1])), sizeof(tee_info->rt_mr[1])).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_rtmr1", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->rt_mr[2])), sizeof(tee_info->rt_mr[2])).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_rtmr2", str_v, doc.GetAllocator());
            str_v.SetString(bytes_to_string(reinterpret_cast<const uint8_t *>(&(tee_info->rt_mr[3])), sizeof(tee_info->rt_mr[3])).c_str(), doc.GetAllocator());
            ref.AddMember("tdx_rtmr3", str_v, doc.GetAllocator());
        }
    }
    rapidjson::Value policy_payload(rapidjson::kObjectType);
    {
        policy_payload.AddMember("environment", env, doc.GetAllocator());
        policy_payload.AddMember("reference", ref, doc.GetAllocator());
    }
    rapidjson::Value policy_array(rapidjson::kArrayType);
    policy_array.PushBack(policy_payload, doc.GetAllocator());
    doc.AddMember("policy_array", policy_array, doc.GetAllocator());

    std::string output_json = json_stringify(doc);
    return output_json;
}

CPayloadGen::CPayloadGen(const char *file)
    : m_file(file)
{
}

CPayloadGen::~CPayloadGen()
{
}

std::string CPayloadGen::generate_payload()
{
    size_t fsize = 0;
    uint8_t *inbuf = read_file_to_buffer(m_file, &fsize);
    if (inbuf == NULL)
    {
        se_trace(SE_TRACE_ERROR, "Failed to read file %s.\n", m_file);
        return "";
    }
    ftype_t ft = check_file_type(inbuf, fsize);
    CInput *inst = NULL;
    std::string res = "";
    switch (ft)
    {
    case SGX_ENCLAVE:
    {
        inst = new CInputEnclave(m_file);
    }
    break;
    case TDX_REPORT_V10:
    case TDX_REPORT_V15:
    case TDX_REPORT_V20:
        inst = new CInputTDReport(inbuf, fsize, ft);
        break;
    default:
        se_trace(SE_TRACE_ERROR, "The format of the input file %s is not correct. Should be one of {signed enclave, TDX report}.\n", m_file);
        break;
    }
    if (inst != NULL)
    {
        res = inst->generate_payload();
        delete inst;
    }
    free(inbuf);
    return res;
}

ftype_t CPayloadGen::check_file_type(const uint8_t *inbuf, size_t bsize)
{
    if (!inbuf || !bsize)
        return UNKNOWN_FILE;

    if (is_sgx_enclave(inbuf, bsize))
    {
        return SGX_ENCLAVE;
    }
    else
    {
        return is_tdx_report(inbuf, bsize);
    }
}

ftype_t CPayloadGen::is_tdx_report(const uint8_t *inbuf, size_t bsize)
{
    (void)bsize;
    const sgx_report2_t *report = reinterpret_cast<const sgx_report2_t *>(inbuf);

    if (report->report_mac_struct.report_type.type == 0x81 &&
        report->report_mac_struct.report_type.subtype == 0 &&
        report->report_mac_struct.report_type.reserved == 0 &&
        report->report_mac_struct.reserved1[0] == 0 &&
        !memcmp(report->report_mac_struct.reserved1, report->report_mac_struct.reserved1 + 1, SGX_REPORT2_MAC_STRUCT_RESERVED1_BYTES - 1) &&
        report->report_mac_struct.reserved2[0] == 0 &&
        !memcmp(report->report_mac_struct.reserved2, report->report_mac_struct.reserved2 + 1, SGX_REPORT2_MAC_STRUCT_RESERVED2_BYTES - 1) &&
        report->reserved[0] == 0 &&
        !memcmp(report->reserved, report->reserved + 1, SGX_REPORT2_RESERVED_BYTES - 1))
    {
        const tee_tcb_info_t *tee_tcb_info = reinterpret_cast<const tee_tcb_info_t *>(report->tee_tcb_info);
        uint8_t tdx_module_major_svn = tee_tcb_info->tee_tcb_svn.tcb_svn[1];

        if (report->report_mac_struct.report_type.version == 0)
        {
            if(tdx_module_major_svn == 0)
            {
                return TDX_REPORT_V10;
            }
            else if(tdx_module_major_svn == 1)
            {
                return TDX_REPORT_V15;
            }
            else if(tdx_module_major_svn == 3)
            {
                return TDX_REPORT_V20;
            }
            else
            {
                return UNKNOWN_FILE;
            }
        }
        else if (report->report_mac_struct.report_type.version == 1)
        {
            if (tdx_module_major_svn == 3)
            {
                return TDX_REPORT_V20;
            }
            else
            {
                return TDX_REPORT_V15;
            }
        }
    }
    return UNKNOWN_FILE;
}

bool CPayloadGen::is_sgx_enclave(const uint8_t *inbuf, size_t bsize)
{
    (void)bsize;
    // check if it is an ELF file
    const Elf64_Ehdr *header = reinterpret_cast<const Elf64_Ehdr *>(inbuf);
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) == 0)
    {
        return true;
    }
    return false;
}
