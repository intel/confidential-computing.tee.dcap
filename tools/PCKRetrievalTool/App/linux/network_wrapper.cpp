/*
 * Copyright(c) 2011-2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
/**
 * File: network_wrapper.cpp
 *  
 * Description: Network access logic
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <curl/curl.h>
#include <fstream>
#include <algorithm>
#include <sgx_ql_lib_common.h>
#include "network_wrapper.h"
#include "utility.h"

using namespace std;

typedef struct _network_malloc_info_t{
    char *base;
    size_t size;
}network_malloc_info_t;

#define MAX_URL_LENGTH  2083
#define LOCAL_NETWORK_SETTING "network_setting.conf"

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

extern string server_url_string;
extern string proxy_type_string;
extern string proxy_url_string;
extern string user_token_string;
extern string use_secure_cert_string;
extern string tcb_update_type_string;

typedef enum _network_proxy_type {
    DIRECT = 0,
    DEFAULT,
    MANUAL
} network_proxy_type;

// Use secure HTTPS certificate or not
extern bool g_use_secure_cert;



static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *stream)
{
    network_malloc_info_t* s=reinterpret_cast<network_malloc_info_t *>(stream);
    size_t start=0;
    size_t data_size = 0;
    if(__builtin_mul_overflow(size, nmemb, &data_size)) return 0;
    if(s->base==NULL){
        s->base = reinterpret_cast<char *>(malloc(data_size));
        s->size = data_size;
        if(s->base==NULL)return 0;
    }else{
        if(data_size > SIZE_MAX - s->size) return 0;
        size_t newsize = s->size + data_size;
        char *p=reinterpret_cast<char *>(realloc(s->base, newsize));
        if(p == NULL){
            return 0;
        }
        start = s->size;
        s->base = p;
        s->size = newsize;
    }
    memcpy(s->base + start, ptr, data_size);
    return data_size;
}

/**
* This method converts CURL error codes to quote3 error codes
*
* @param curl_error Curl library error codes
*
* @return network post Error Codes
*/
static network_post_error_t curl_error_to_network_post_error(CURLcode curl_error)
{
    switch(curl_error){
        case CURLE_OK:
            return POST_SUCCESS;
        default:
            return POST_NETWORK_ERROR;
    }
}

static bool process_configuration_setting(const char *config_file_name, string& url, string &proxy_type, string &proxy_url, string &user_token)
{
    bool ret = true;
    bool config_file_exist = true;
    bool config_file_provide_pccs_url=false;

    ifstream ifs(config_file_name);
    string line;
    if (ifs.is_open()) {
        auto f = [](unsigned char const c) { return std::isspace(c); };
        while (getline(ifs, line)) {
            line.erase(std::remove_if(line.begin(), line.end(), f), line.end());
            if (line[0] == '#' || line.empty())
                continue;
            size_t pos = line.find("=");
            string name = line.substr(0, pos);
            std::transform(name.begin(), name.end(), name.begin(), ::toupper);
            string value = line.substr(pos + 1);
            if (name.compare("PCCS_URL") == 0) {
                if (server_url_string.empty() == true) {
                    url = value;
                    fprintf(stdout,"the pccs_url setting coming from network_setting.conf, and the value is: %s.\n", value.c_str());
                }
                else {
                    url = server_url_string + "/sgx/certification/v4/platforms";
                }
                config_file_provide_pccs_url = true;
            }
            else if (name.compare("USE_SECURE_CERT") == 0) {
                if (use_secure_cert_string.empty() == true) {
                    std::transform(value.begin(), value.end(), value.begin(), ::toupper);
                    if (value.compare("FALSE") == 0) {
                        g_use_secure_cert = false;
                    }
                    fprintf(stdout,"the use_secure_cert setting coming from network_setting.conf, and the value is: %s.\n", value.c_str());
                }
            }
            else if (name.compare("PROXY_TYPE") == 0) {
                if(proxy_type_string.empty() == true) {
                    std::transform(value.begin(), value.end(), value.begin(), ::toupper);
                    proxy_type = value;                    
                    fprintf(stdout,"the proxy_type setting coming from network_setting.conf, and the value is: %s.\n", value.c_str());
                } 
            }
            else if (name.compare("PROXY_URL") == 0) {
                if(proxy_url_string.empty() == true) {
                    proxy_url = value;
                    fprintf(stdout,"the proxy_url setting coming from network_setting.conf, and the value is: %s.\n", value.c_str());
                }
            }
            else if (name.compare("USER_TOKEN") == 0) {
                if(user_token_string.empty() == true) {
                    user_token = value;
                    fprintf(stdout,"the user_token setting coming from network_setting.conf, and the value is: *** (actual value hidden).\n");
                }
            }
            else if (name.compare("TCB_UPDATE_TYPE") == 0){
                if(tcb_update_type_string.empty() == true) {
                    std::transform(value.begin(), value.end(), value.begin(), ::toupper);
                    tcb_update_type_string = value;
                    fprintf(stdout,"the tcb_update_type setting coming from network_setting.conf, and the value is: %s.\n", value.c_str());
                }
            }
            else {
                continue;
            }
        }
    }
    else {
        config_file_exist = false;

        if(server_url_string.empty() == false) {
            url = server_url_string + "/sgx/certification/v4/platforms";
        }
        ret = false;
    }

    //configruaton file exist, however it doesn't provide pccs url
    if(config_file_exist && config_file_provide_pccs_url == false) {
        if(server_url_string.empty() == false) {
            url = server_url_string + "/sgx/certification/v4/platforms";
        }
    }


    if(tcb_update_type_string.compare("EARLY") == 0) {
        url = url + "?update=early";
    }
    else if(tcb_update_type_string.compare("ALL") == 0) {
        url = url + "?update=all";
    }

    return ret;
}

/**
*  Read configuration data
*/
static void network_configuration(string &url, string &proxy_type, string &proxy_url, string& user_token)
{
    //firstly read local configuration File
    char local_configuration_file_path[MAX_PATH] = "";
    bool ret = get_program_path(local_configuration_file_path, MAX_PATH -1);
    if (ret) {
        if(strnlen(local_configuration_file_path ,MAX_PATH)+strnlen(LOCAL_NETWORK_SETTING,MAX_PATH)+sizeof(char) > MAX_PATH) {
            ret = false;
        }
        else {
            (void)strncat(local_configuration_file_path,LOCAL_NETWORK_SETTING, strnlen(LOCAL_NETWORK_SETTING,MAX_PATH));
        }
    }
    if (ret){
        process_configuration_setting(local_configuration_file_path,url, proxy_type, proxy_url, user_token);
    }
    else {
        if(server_url_string.empty() == false) {
            url = server_url_string + "/sgx/certification/v4/platforms";
        }
    }
}



/**
* This method calls curl library to perform https post requet:
* it will combine the buffer, and post to server.
*
* @param buffer: input buffer, that include qeid, cpusvn, pcesvn, pceid, encrypted ppid, platform_manifest(if platform is multi-package)
* @param buffer_size: size of the buffer 
*
* @return SGX_QCNL_SUCCESS Call https get successfully. Other return codes indicate an error occured.
*/


network_post_error_t network_https_post(const uint8_t* raw_data, const uint64_t raw_data_size, const uint16_t platform_id_length, const bool non_enclave_mode)
{
    if (raw_data_size < platform_id_length + static_cast<uint32_t>(PCE_ID_LENGTH)) {
        return POST_INVALID_PARAMETER_ERROR;
    }

    network_post_error_t ret = POST_UNEXPECTED_ERROR;  
    string strJson("");
    ret = generate_json_message_body(raw_data, raw_data_size, platform_id_length, non_enclave_mode, strJson);
    if (ret != POST_SUCCESS) {
        printf("Error: unexpected error occurred while generating json message body.\n");
        return ret;
    }
    CURL *curl = NULL;
    CURLcode curl_ret = CURLE_OK;
    network_malloc_info_t res_body = {0,0};

    // initialize https request url
    string url(server_url_string);
    string proxy_type(proxy_type_string);
    string proxy_url(proxy_url_string);
    string user_token(user_token_string);
    // initialize network configuration
    network_configuration(url, proxy_type, proxy_url, user_token);                   

    ret = POST_UNEXPECTED_ERROR;
    do {
        curl = curl_easy_init();
        if (!curl)
            break;

        if (curl_easy_setopt(curl, CURLOPT_URL, url.c_str()) != CURLE_OK)
            break;

        struct curl_slist *slist = NULL;
        slist = curl_slist_append(slist, "Content-Type: application/json");

        if (user_token.empty()) {
            printf("\n Please input the pccs password, and use \"Enter key\" to end\n");
            int usless_ret = system("stty -echo");
            user_token = "user-token: ";
            char ch;
            while ((ch = static_cast<char>(getchar())) != '\n') {
                user_token = user_token + ch;
            }
            usless_ret = system("stty echo");
            (void)(usless_ret);
        } else {
            user_token = "user-token: " + user_token;
        }

        slist = curl_slist_append(slist, user_token.c_str());
        if (curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist) != CURLE_OK)
            break;
        if (!g_use_secure_cert) {
            // if not set this option, the below error code will be returned for self signed cert
            // CURLE_SSL_CACERT (60) Peer certificate cannot be authenticated with known CA certificates.
            if (curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L) != CURLE_OK)
                break;
            // if not set this option, the below error code will be returned for self signed cert
            // // CURLE_PEER_FAILED_VERIFICATION (51) The remote server's SSL certificate or SSH md5 fingerprint was deemed not OK.
            if (curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L) != CURLE_OK)
                break;
        }

        // Set write callback functions
        if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback) != CURLE_OK)
            break;
        if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, reinterpret_cast<void *>(&res_body)) != CURLE_OK)
            break;
        //	curl_easy_setopt(curl, CURLOPT_VERBOSE,1L);
        if (curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST") != CURLE_OK)
            break;

        // size of the POST data 
        if( curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strJson.size()) != CURLE_OK)
            break;
        // pass in a pointer to the data - libcurl will not copy 
        if(curl_easy_setopt(curl, CURLOPT_POSTFIELDS, strJson.c_str()) != CURLE_OK)
            break;

        // proxy setting	
        if (proxy_type.compare("DIRECT") == 0 || proxy_type.compare("direct") == 0) {
            if (curl_easy_setopt(curl, CURLOPT_NOPROXY, "*") != CURLE_OK){
                printf("Warining: unexpected error occurred while setting network proxy.\n");
            }
        }
        else if (proxy_type.compare("MANUAL") == 0 || proxy_type.compare("manual") == 0) {
            if (curl_easy_setopt(curl, CURLOPT_PROXY, proxy_url.c_str()) != CURLE_OK) {
                printf("Warining: unexpected error occurred while setting network proxy.\n");
            }
        }


        // Perform request
        if ((curl_ret = curl_easy_perform(curl)) != CURLE_OK) {
            ret = curl_error_to_network_post_error(curl_ret);
            break;
        }
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code == 200) {
            ret = POST_SUCCESS;
            break;
        }
        else if (http_code == 401) {
            ret = POST_AUTHENTICATION_ERROR;
            break;
        }
        else {
            ret = POST_UNEXPECTED_ERROR;
            break;
        }

    } while (0);

    if (curl) {
        curl_easy_cleanup(curl);
    }
    free(res_body.base);
    return ret;
}

bool is_server_url_available() {
    char local_configuration_file_path[MAX_PATH] = "";
    bool ret = get_program_path(local_configuration_file_path, MAX_PATH -1);
    if (ret) {
        if(strnlen(local_configuration_file_path ,MAX_PATH)+strnlen(LOCAL_NETWORK_SETTING,MAX_PATH)+sizeof(char) > MAX_PATH) {
            return false;
        }
        else {
            (void)strncat(local_configuration_file_path,LOCAL_NETWORK_SETTING, strnlen(LOCAL_NETWORK_SETTING,MAX_PATH));
        }
    }
    ifstream ifs_local(local_configuration_file_path);
    string line;
    if (ifs_local.is_open()) {
        auto f = [](unsigned char const c) { return std::isspace(c); };
        while (getline(ifs_local, line)) {
            line.erase(std::remove_if(line.begin(), line.end(), f), line.end());
            if (line[0] == '#' || line.empty())
                continue;
            size_t pos = line.find("=");
            string name = line.substr(0, pos);
            std::transform(name.begin(), name.end(), name.begin(), ::toupper);
            string value = line.substr(pos + 1);
            if (name.compare("PCCS_URL") == 0) {
                if (value.empty() == false) {
                    return true;
                }
            }
        }
    }

   return false;
}
