/*
 * Copyright (C) 2011-2026 Intel Corporation. All rights reserved.
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
 * File: main.cpp
 *  
 * Description: Implements the tool functionality.
 */
#include <stdio.h>
#ifndef _WIN32
#include <unistd.h>
#include "regex.h"
#else
#include <regex>
#endif
#include <sstream>
#include <iomanip>
#include <string.h>
#include <inttypes.h>
#include <map>
#include <algorithm>
#include "MPManagement.h"
#include "MPConfigurations.h"
#include "AgentConfiguration.h"
#include "management_logger.h"
#include "common.h"

#define MANAGMENT_TOOL_GET_PLATFORM_MANIFEST       "-get_platform_manifest"
#define MANAGMENT_TOOL_GET_ADD_PACKAGE_REQUEST     "-get_add_package"
#define MANAGMENT_TOOL_SET_MEMBERSHIP_CERTIFICATES "-set_membership_certificates"
#define MANAGMENT_TOOL_GET_KEY_BLOBS               "-get_key_blobs"
#define MANAGMENT_TOOL_GET_SERVER_INFO             "-get_server_info"
#define MANAGMENT_TOOL_SET_SERVER_INFO             "-set_server_info"

#define MANAGMENT_TOOL_USAGE_INFO                  "-h"
#define MANAGMENT_TOOL_VERBOSE_LOG                 "-v"
#define MANAGMENT_TOOL_GET_REG_STATUS              "-get_registration_status"
#define MANAGMENT_TOOL_GET_REG_ERROR_CODE          "-get_last_registration_error_code"
#define MANAGMENT_TOOL_GET_SGX_STATUS              "-get_sgx_status"

#define COVERT_TO_NEG(num)      num * (-1)

#ifndef _WIN32
#define fopen_s(pf,filename,mode) (((*(pf))=fopen((filename),(mode)))==NULL?1:0)
#define sscanf_s sscanf
#endif

typedef int (*handle_func_with_args)(const char *);
typedef int (*handle_func)();

std::map<const string, handle_func_with_args> optionsWithArgs;
std::map<const string, handle_func> optionsNoArgs;
MPManagement *manage = NULL;

LogLevel glog_level = MP_REG_LOG_LEVEL_INFO;
int gargc = 0;

char* getCmdOption(char** begin, char** end, const std::string & option)
{
    char ** itr = std::find(begin, end, option);
    if (itr != end && ++itr != end)
    {
        return *itr;
    }
    return 0;
}

bool cmdOptionExists(char** begin, char** end, const std::string& option)
{
    return std::find(begin, end, option) != end;
}

int numOfCommandLineCommands(char** begin, char** end, char c) {
    int count = 0;
    string str;
    do {
        str = string(*begin);
        count += (int)std::count(str.begin(), str.end(), c);
        begin++;
    } while (begin != end);
    return count;
}

int usage() {
    management_log_message(MP_REG_LOG_LEVEL_INFO, "Tools options:\n");
    management_log_message(MP_REG_LOG_LEVEL_INFO, "-h\t\t\t\t\t\t\t Shows usage instructions.\n");
    management_log_message(MP_REG_LOG_LEVEL_INFO, "-v\t\t\t\t\t\t\t Verbose logs.\n");
    management_log_message(MP_REG_LOG_LEVEL_INFO, "-get_platform_manifest <file_name>\t\t\t Copies Platform Manifest into a file. Sets registration status to completed.\n");
    management_log_message(MP_REG_LOG_LEVEL_INFO, "  \t\t\t\t\t\t\t The user's responsibility is to pass Platform Manifest to registration server.\n");
    management_log_message(MP_REG_LOG_LEVEL_INFO, "-get_add_package <file_name>\t\t\t\t Copies pending Add Package request into a file.\n");
    management_log_message(MP_REG_LOG_LEVEL_INFO, "  \t\t\t\t\t\t\t The user's responsibility is to pass Add Package to registration server\n");
    management_log_message(MP_REG_LOG_LEVEL_INFO, "  \t\t\t\t\t\t\t and set the resulting Platform Certificate using -set_membership_certificates.\n");
    management_log_message(MP_REG_LOG_LEVEL_INFO, "-set_membership_certificates <file_name>\t\t\t Sets the Membership Certificates from file into BIOS, completing Add Package.\n");
    management_log_message(MP_REG_LOG_LEVEL_INFO, "-get_key_blobs <key_blobs_file_name>\t\t\t Copies Package Info Key Blobs into a file. Sets package info status to completed.\n");
    management_log_message(MP_REG_LOG_LEVEL_INFO, "-set_server_info <server_id_file_name> <hex_flags> <URL>\t Sets registration server configurations.\n");
    management_log_message(MP_REG_LOG_LEVEL_INFO, "-get_server_info\t\t\t\t\t\t Prints SGX server information.\n");
    management_log_message(MP_REG_LOG_LEVEL_INFO, "-get_registration_status\t\t\t\t\t Prints and returns registration status.\n");
    management_log_message(MP_REG_LOG_LEVEL_INFO, "-get_last_registration_error_code\t\t\t\t Prints and returns last registration error code.\n");
    management_log_message(MP_REG_LOG_LEVEL_INFO, "-get_sgx_status\t\t\t\t\t\t Prints SGX status.\n");
    management_log_message(MP_REG_LOG_LEVEL_INFO, "\n");
    management_log_message(MP_REG_LOG_LEVEL_INFO, "In case of a tool error a negative number will be returned.\n");
    management_log_message(MP_REG_LOG_LEVEL_INFO, "A positive return value is defined as MpResult.\n");
    management_log_message(MP_REG_LOG_LEVEL_INFO, "\n");
    return 0;
}

int setVerboseLog() {
    glog_level = MP_REG_LOG_LEVEL_DEBUG;
    management_log_message(MP_REG_LOG_LEVEL_INFO, "Using verbose log level.\n");
    return 0;
}

enum class UEFI_REQUEST_TYPE {
    PLATFORM_MANIFEST,
    ADD_PACKAGE    
};

int getUefiRequest(const char *fileName, UEFI_REQUEST_TYPE type) {
    int ret = 0;
    uint8_t buffer[MAX_REQUEST_SIZE];
    uint32_t buffSize = sizeof(buffer);
    MpResult res = MP_UNEXPECTED_ERROR;

    if (gargc - 2 != 1) {
        management_log_message(MP_REG_LOG_LEVEL_ERROR, "Invalid number of parameters, please use the following syntax:\n");
        management_log_message(MP_REG_LOG_LEVEL_INFO, "mpa_manage %s <file_name>\n", ((type == UEFI_REQUEST_TYPE::ADD_PACKAGE)? MANAGMENT_TOOL_GET_ADD_PACKAGE_REQUEST : MANAGMENT_TOOL_GET_PLATFORM_MANIFEST));
        goto out;
    }
    
    if (type == UEFI_REQUEST_TYPE::ADD_PACKAGE) {
        res = manage->getAddPackageRequest(buffer, buffSize);
    } else {
        res = manage->getPlatformManifest(buffer, buffSize);
    }
    if (MP_SUCCESS != res) {
        if(MP_INSUFFICIENT_PRIVILEGES == res)  {
            management_log_message(MP_REG_LOG_LEVEL_WARN, "The registration complete flag could NOT be set, maybe the UEFI variable is in read-only mode.\n");
        }
        ret = (int)res;
        goto out;
    }
    
    ret = writeBufferToFile(fileName, buffer, buffSize);
    if (ret != 0) {
        management_log_message(MP_REG_LOG_LEVEL_ERROR, "Unable to write to file:  \"%s\"\n", fileName);
        goto out;
    }

    management_log_message(MP_REG_LOG_LEVEL_INFO, "%s successfully written to: %s\n",
                           ((type == UEFI_REQUEST_TYPE::ADD_PACKAGE)? "AddPackage request" : "PlatformManifest"),
                           fileName);
out:
    return COVERT_TO_NEG(ret);
}

int performGetPlatformManifest(const char *fileName) {
    return getUefiRequest(fileName, UEFI_REQUEST_TYPE::PLATFORM_MANIFEST);
}

int performGetAddPackage(const char *fileName) {
    return getUefiRequest(fileName, UEFI_REQUEST_TYPE::ADD_PACKAGE);    
}

int performGetKeyBlob(const char *fileName) {
    int ret = 0;
    uint8_t buffer[MAX_DATA_SIZE];
    uint16_t buffSize = sizeof(buffer);
    MpResult res = MP_UNEXPECTED_ERROR;
    
    if (gargc - 2 != 1) {
        management_log_message(MP_REG_LOG_LEVEL_ERROR, "Invalid number of parameters, please use the following syntax:\n");
        management_log_message(MP_REG_LOG_LEVEL_INFO, "mpa_manage -get_key_blobs <key_blobs_file_name>\n");
        goto out;
    }
    
    res = manage->getPackageInfoKeyBlobs(buffer, buffSize);
    if (MP_SUCCESS != res ) {
        if(MP_INSUFFICIENT_PRIVILEGES == res) {
            management_log_message(MP_REG_LOG_LEVEL_WARN, "The package info complete flag could NOT be set, maybe the UEFI variable is in read-only mode.\n");
        }
        ret = (int)res;
        goto out;
    }
    
    ret = writeBufferToFile(fileName, buffer, buffSize);
    if (ret != 0) {
        management_log_message(MP_REG_LOG_LEVEL_ERROR, "Unable to write to file:  \"%s\"\n", fileName);
        goto out;
    }
    
    management_log_message(MP_REG_LOG_LEVEL_INFO, "PackageInfoKeyBlobs successfully written to: %s\n", fileName);
out:
    return COVERT_TO_NEG(ret);
}

#define FLAGS_PARAM_SIZE 6
#define FALGS_REGEX "0[xX][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]$"
int performSetServerInfo(const char *fileName) {
    int ret = 0;
    uint8_t serverId[MAX_DATA_SIZE];
    size_t buffSize = sizeof(serverId);
    char *param1 = NULL;
    char *param2 = NULL;
#ifndef _WIN32
    regex_t regex;
#else
    std::cmatch match;
    std::regex regex(FALGS_REGEX);
    std::regex_constants::match_flag_type flag =
        std::regex_constants::match_default;
#endif
    uint16_t flags = 0;
    MpResult res = MP_UNEXPECTED_ERROR;
    memset(&serverId, 0, sizeof(serverId));
    
    param1 = (char*)fileName+strnlen(fileName, MAX_PATH_SIZE)+1;
    param2 = (char*)fileName+strnlen(fileName, MAX_PATH_SIZE)+1+(FLAGS_PARAM_SIZE+1);
    
    if (gargc - 2 != 3) {
        management_log_message(MP_REG_LOG_LEVEL_ERROR, "Invalid number of parameters, please use the following syntax:\n");
        management_log_message(MP_REG_LOG_LEVEL_INFO, "mpa_manage -set_server_info <server_id_file_name> <hex_flags> <URL>\n\n");
        management_log_message(MP_REG_LOG_LEVEL_INFO, "Pay attention: use ServerId blob and not ServerInfo blob.\n");
        goto out;
    }
#ifndef _WIN32
    ret = regcomp(&regex, FALGS_REGEX, REG_EXTENDED);
    if (0 != ret) {
        management_log_message(MP_REG_LOG_LEVEL_ERROR, "Unexpected failure during regcomp.\n");
        ret = MP_UNEXPECTED_ERROR;
        goto out;
    }

    ret = regexec(&regex, param1, 0, NULL, 0);
    if (0 != ret) {
        management_log_message(MP_REG_LOG_LEVEL_ERROR, "Invalid command: '-set_server_info' should include hex flags value in a length of 2 bytes.\n");
        management_log_message(MP_REG_LOG_LEVEL_INFO, "e.g: mpa_manage -set_server_info file.txt 0x0f01 https://www.web.com\n");
        ret = MP_INVALID_PARAMETER;
        goto out;
    }
#else
    /* use regular expression */
    if (!regex_match(param1, regex, flag)) {
        management_log_message(MP_REG_LOG_LEVEL_ERROR, "Invalid command: '-set_server_info' should include hex flags value in a length of 2 bytes.\n");
        management_log_message(MP_REG_LOG_LEVEL_INFO, "e.g: mpa_manage -set_server_info file.txt 0x0f01 https://www.web.com\n");
        res = MP_INVALID_PARAMETER;
        goto out;
    }
#endif

    ret = sscanf_s(param1 + 2, "%04hX", &flags);
    if (1 != ret) {
        management_log_message(MP_REG_LOG_LEVEL_ERROR, "Unexpected failure during hex flag parsing. error code: %d\n", ret);
        ret = MP_UNEXPECTED_ERROR;
        goto out;
    }

    ret = readFileToBuffer(fileName, (uint8_t*)&serverId, buffSize);
    if (ret != 0) {
        management_log_message(MP_REG_LOG_LEVEL_ERROR, "Unable to read the server id file: \"%s\"\n", fileName);
        goto out;
    }

    res = manage->setRegistrationServerInfo(flags, string(param2, strnlen(param2, MAX_PATH_SIZE)), (uint8_t*)&serverId, (uint16_t)buffSize);
    if (MP_SUCCESS != res) {
        if(MP_INSUFFICIENT_PRIVILEGES == res) {
            management_log_message(MP_REG_LOG_LEVEL_WARN, "The registration server information could NOT be set, maybe the UEFI variable is in read-only mode.\n");
        }
        ret = (int)res;
        goto out;
    }

    management_log_message(MP_REG_LOG_LEVEL_INFO, "ServerInformation changed successfully, please reboot the system.\n");
out:
#ifndef _WIN32
    regfree(&regex);
#endif
    return COVERT_TO_NEG(ret);
}

int performSetMembershipCertificates(const char *fileName) {
    int ret = 0;
    uint8_t mcBuffer[MAX_DATA_SIZE];
    size_t buffSize = sizeof(mcBuffer);
    MpResult res = MP_UNEXPECTED_ERROR;

    if (gargc - 2 != 1) {
        management_log_message(MP_REG_LOG_LEVEL_ERROR, "Invalid number of parameters, please use the following syntax:\n");
        management_log_message(MP_REG_LOG_LEVEL_INFO, "mpa_manage %s <file_name>\n", MANAGMENT_TOOL_SET_MEMBERSHIP_CERTIFICATES );
        goto out;
    }

    ret = readFileToBuffer(fileName, (uint8_t*)&mcBuffer, buffSize);
    if (ret != 0) {
        management_log_message(MP_REG_LOG_LEVEL_ERROR, "Unable to read the Membership Certificate file: \"%s\"\n", fileName);
        goto out;
    }

    res = manage->setMembershipCertificates((uint8_t*)&mcBuffer, (uint16_t)buffSize);
    if (MP_SUCCESS != res) {
        ret = (int)res;
        management_log_message(MP_REG_LOG_LEVEL_INFO, "MembershipCertificate installation failed with code %d\n", ret);
        goto out;
    }

    management_log_message(MP_REG_LOG_LEVEL_INFO, "MembershipCertificate installed successfully, please reboot the system.\n");
out:
    return COVERT_TO_NEG(ret);
}

int performGetRegErrorCode() {
    int ret = 0;
    MpResult res = MP_UNEXPECTED_ERROR;
    RegistrationErrorCode err = MPA_AG_UNEXPECTED_ERROR;

    res = manage->getRegistrationErrorCode(err);
    if (MP_SUCCESS != res) {
        ret = COVERT_TO_NEG((int)res);
        goto out;
    }
    
    management_log_message(MP_REG_LOG_LEVEL_INFO, "Last reported registration error code: %x\n", (int)err);
    management_log_message(MP_REG_LOG_LEVEL_WARN, "Maybe the whole SGX UEFI variables are in read-only mode, so this error code is not accurate.\n");
    ret = (int)err;
out:
    return ret;
}

int performGetRegStatus() {
    int ret = 0;
    MpResult res = MP_UNEXPECTED_ERROR;
    MpTaskStatus status;

    memset(&status, 0, sizeof(status));

    res = manage->getRegistrationStatus(status);
    if (MP_SUCCESS != res) {
        ret = COVERT_TO_NEG((int)res);
        goto out;
    }

    if (MP_TASK_COMPLETED == status) {
        management_log_message(MP_REG_LOG_LEVEL_INFO, "Registration process completed successfully.\n");
    } else {
        management_log_message(MP_REG_LOG_LEVEL_INFO, "Registration is in progress.\n");
        management_log_message(MP_REG_LOG_LEVEL_WARN, "Maybe the whole SGX UEFI variables are in read-only mode, so the registration status is not accurate.\n");
    }
    
    ret = (int)status;
out:
    return ret;
}

int performGetSgxStatus() {
    static const char *MpSgxStatusValues[] =
    {
        "MP_SGX_ENABLED",
        "MP_SGX_DISABLED_REBOOT_REQUIRED",
        "MP_SGX_DISABLED_LEGACY_OS",
        "MP_SGX_DISABLED",
        "MP_SGX_DISABLED_SCI_AVAILABLE",   
        "MP_SGX_DISABLED_MANUAL_ENABLE",  
        "MP_SGX_DISABLED_HYPERV_ENABLED",     
        "MP_SGX_DISABLED_UNSUPPORTED_CPU"    
    };

    static const char *MpSgxStatusStr[] =
    {
        "SGX is enabled",
        "A reboot is required to finish enabling SGX",
        "SGX is disabled and a Software Control Interface is not available to enable it",
        "SGX is not enabled on this platform. More details are unavailable",
        "SGX is disabled, but a Software Control Interface is available to enable it",   
        "SGX is disabled, but can be enabled manually in the BIOS setup",  
        "Detected an unsupported version of Windows* 10 with Hyper-V enabled",     
        "SGX is not supported by this CPU"    
    };

    int ret = 0;
    MpResult res = MP_UNEXPECTED_ERROR;
    MpSgxStatus status;

    memset(&status, 0, sizeof(status));
    
    res = manage->getSgxStatus(status);
    if (MP_SUCCESS != res) {
        ret = COVERT_TO_NEG((int)res);
        goto out;
    }
    
    management_log_message(MP_REG_LOG_LEVEL_INFO, "SGX status: %s, which means: %s.\n", MpSgxStatusValues[(unsigned int)status], MpSgxStatusStr[(unsigned int)status]);
    ret = (int)res;
out:
    return ret;
}


std::string byteArrayToHexString(uint8_t* buffer, uint16_t size) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < size; i++) {
        ss << std::setw(2) << static_cast<int>(buffer[i]);
    }
    return ss.str();
}


int performGetServerInfo() {
    uint16_t flags = 0;
    std::string url = "";
    uint8_t serverId[MAX_DATA_SIZE]; // unused 
    uint16_t serverIdSize = sizeof(serverId);

    MpResult res = manage->getRegistrationServerInfo(flags, url, serverId, serverIdSize);

    if (MP_SUCCESS != res) {
        return COVERT_TO_NEG((int)res);
    }

    management_log_message(MP_REG_LOG_LEVEL_INFO, "SGX server: %s\nFlags: 0x%04X\nServer Id: %s\n",
        url.c_str(), flags, byteArrayToHexString(serverId, serverIdSize).c_str());

    return MP_SUCCESS;
}


int main(int argc, char * argv[]) {
    int ret = 0;
    int foundCommands = 0;
    int numOfCommands = 0;
    char *filename = NULL;
    MPConfigurations conf;

    gargc = argc;
    if(gargc ==1 ) {
        management_log_message(MP_REG_LOG_LEVEL_ERROR, "No input commands found.\n");
        usage();
        ret = COVERT_TO_NEG(MP_INVALID_PARAMETER);
        return ret;
    }

    do {
#ifndef _WIN32
        // Check privileges
        if (getuid()) {
            management_log_message(MP_REG_LOG_LEVEL_INFO, "Please run as root or sudo.\n");
            ret = COVERT_TO_NEG(MP_INSUFFICIENT_PRIVILEGES);
            break;
        }
#endif
        // Read UEFI path
        AgentConfiguration agentConfigurations;
        if (!agentConfigurations.read(conf)) {
            //indented msg to gel with the "ERROR:"
            management_log_message(MP_REG_LOG_LEVEL_INFO, "       Default UEFI path variable [%s] will be used \n", EFIVARS_FILE_SYSTEM);
        }

        // Initiate management
        manage = new MPManagement(string(conf.uefi_path));

        // Count given commands
        numOfCommands = numOfCommandLineCommands(argv + 1, argv + argc, '-');
        if (!numOfCommands) {
            management_log_message(MP_REG_LOG_LEVEL_ERROR, "No input commands found.\n");
            usage();
            ret = COVERT_TO_NEG(MP_INVALID_PARAMETER);
            break;
        }

        // Organize options map
        optionsWithArgs[MANAGMENT_TOOL_GET_PLATFORM_MANIFEST] = performGetPlatformManifest;
        optionsWithArgs[MANAGMENT_TOOL_GET_KEY_BLOBS] = performGetKeyBlob;
        optionsWithArgs[MANAGMENT_TOOL_SET_SERVER_INFO] = performSetServerInfo;
        optionsWithArgs[MANAGMENT_TOOL_GET_ADD_PACKAGE_REQUEST] = performGetAddPackage;
        optionsWithArgs[MANAGMENT_TOOL_SET_MEMBERSHIP_CERTIFICATES] = performSetMembershipCertificates;
        
        optionsNoArgs[MANAGMENT_TOOL_USAGE_INFO] = usage;
        optionsNoArgs[MANAGMENT_TOOL_GET_REG_ERROR_CODE] = performGetRegErrorCode;
        optionsNoArgs[MANAGMENT_TOOL_GET_REG_STATUS] = performGetRegStatus;
        optionsNoArgs[MANAGMENT_TOOL_GET_SGX_STATUS] = performGetSgxStatus;
        optionsNoArgs[MANAGMENT_TOOL_GET_SERVER_INFO] = performGetServerInfo;

        std::map<const string, handle_func_with_args>::iterator itWithArgs = optionsWithArgs.begin();
        std::map<const string, handle_func>::iterator itNoArgs = optionsNoArgs.begin();

        // Set verbose log level if needed
        if (cmdOptionExists(argv + 1, argv + argc, MANAGMENT_TOOL_VERBOSE_LOG)) {
            foundCommands++;
            setVerboseLog();
            gargc--; // "-v" has been processed, so remove it.
        }

        // Iterate over all options without arguments
        while (itNoArgs != optionsNoArgs.end()) {
            if (cmdOptionExists(argv + 1, argv + argc, itNoArgs->first)) {
                foundCommands++;
                ret = itNoArgs->second();
                if (MP_SUCCESS != ret) {
                    break;
                }
            }
            itNoArgs++;
        }

        // Iterate over all options with arguments
        while (itWithArgs != optionsWithArgs.end()) {
            filename = getCmdOption(argv + 1, argv + argc, itWithArgs->first);
            if (filename)
            {
                foundCommands++;
                ret = itWithArgs->second(filename);
                if (MP_SUCCESS != ret) {
                    break;
                }
            }
            itWithArgs++;
        }

        if (foundCommands < numOfCommands) {
            management_log_message(MP_REG_LOG_LEVEL_ERROR, "Invalid input.\n");
            usage();
            ret = COVERT_TO_NEG(MP_INVALID_PARAMETER);
        }
    } while(0);

    if (manage) {
        delete manage;
    }
    return ret;
}

