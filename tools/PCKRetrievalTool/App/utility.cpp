/*
 * Copyright(c) 2011-2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
/**
 * File: utility.cpp
 *
 * Description: utility functions
 *
 */
#include <stdio.h>
#include <string>
#ifdef _MSC_VER
#include <Windows.h>
#include <tchar.h>
#else
#include <dlfcn.h>
#include <unistd.h>
#endif
#include "id_enclave_u.h"
#include "pce_u.h"
#include "sgx_urts.h"     
#include "utility.h"

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

static constexpr size_t ProgPathBufferSize = MAX_PATH + 1;

// Use secure HTTPS certificate or not
extern bool g_use_secure_cert ;


#ifdef DEBUG
#define PRINT_MESSAGE(message) printf(message);
#define PRINT_MESSAGE2(message1,message2) printf(message1, message2);
#else
#define PRINT_MESSAGE(message) ;
#define PRINT_MESSAGE2(message1,message2) ;
#endif

#ifdef  _MSC_VER                
#define PCE_ENCLAVE_NAME  _T("pce.signed.dll")
#define ID_ENCLAVE_NAME   _T("id_enclave.signed.dll")
#define SGX_URTS_LIBRARY _T("sgx_urts.dll")
#define SGX_MULTI_PACKAGE_AGENT_UEFI_LIBRARY _T("mp_uefi.dll")
#define FINDFUNCTIONSYM   GetProcAddress
#define CLOSELIBRARYHANDLE  FreeLibrary
#define EFIVARS_FILE_SYSTEM_IN_OS ""//for Windows OS, don't need this path

HINSTANCE sgx_urts_handle = NULL;
#ifdef UNICODE
typedef sgx_status_t (SGXAPI *sgx_create_enclave_func_t)(const LPCWSTR file_name, const int debug, sgx_launch_token_t* launch_token, int* launch_token_updated, sgx_enclave_id_t* enclave_id, sgx_misc_attribute_t* misc_attr);
#else 
typedef sgx_status_t (SGXAPI *sgx_create_enclave_func_t)(const LPCSTR file_name, const int debug, sgx_launch_token_t* launch_token, int* launch_token_updated, sgx_enclave_id_t* enclave_id, sgx_misc_attribute_t* misc_attr);
#endif

#else
#define PCE_ENCLAVE_NAME  "libsgx_pce.signed.so.1"
#define ID_ENCLAVE_NAME   "libsgx_id_enclave.signed.so.1"
#define SGX_URTS_LIBRARY "libsgx_urts.so"             
#define SGX_MULTI_PACKAGE_AGENT_UEFI_LIBRARY "libmpa_uefi.so.1"
#define FINDFUNCTIONSYM   dlsym
#define CLOSELIBRARYHANDLE  dlclose
#define EFIVARS_FILE_SYSTEM_IN_OS "/sys/firmware/efi/efivars/"
typedef sgx_status_t (SGXAPI *sgx_create_enclave_func_t)(const char* file_name,
    const int debug,
    sgx_launch_token_t* launch_token,
    int* launch_token_updated,
    sgx_enclave_id_t* enclave_id,
    sgx_misc_attribute_t* misc_attr);


void* sgx_urts_handle = NULL;
#endif 


typedef sgx_status_t(SGXAPI* sgx_ecall_func_t)(const sgx_enclave_id_t eid,
    const int index,
    const void* ocall_table,
    void* ms);

typedef sgx_status_t (SGXAPI* sgx_destroy_enclave_func_t)(const sgx_enclave_id_t enclave_id);
typedef sgx_status_t (SGXAPI* sgx_get_target_info_func_t)(const sgx_enclave_id_t enclave_id, sgx_target_info_t* target_info);

#ifdef _MSC_VER
#pragma warning(disable: 4201)    // used to eliminate `unused variable' warning
#define UNUSED(val) (void)(val)

#endif 
#include "MPUefi.h"
typedef MpResult(*mp_uefi_init_func_t)(const char* path, const LogLevel logLevel);
typedef MpResult(*mp_uefi_get_request_type_func_t)(MpRequestType* type);
typedef MpResult(*mp_uefi_get_request_func_t)(uint8_t *request, uint32_t *request_size);
typedef MpResult(*mp_uefi_get_registration_status_func_t)(MpRegistrationStatus* status);
typedef MpResult(*mp_uefi_set_registration_status_func_t)(const MpRegistrationStatus* status);
typedef MpResult(*mp_uefi_terminate_func_t)();



//redefine this function to avoid sgx_urts library compile dependency
sgx_status_t  SGXAPI sgx_ecall(const sgx_enclave_id_t eid,
                              const int index,
                              const void* ocall_table,
                              void* ms)
{
    // sgx_urts library has been tried to loaded before this function call, and this function is be called during sgx_create_enclave call
#if defined(_MSC_VER)
    if (sgx_urts_handle == NULL) {
        printf("ERROR: didn't find the sgx_urts.dll library, please make sure you have installed PSW installer package. \n");
        return SGX_ERROR_UNEXPECTED;
    }
    sgx_ecall_func_t p_sgx_ecall = (sgx_ecall_func_t)FINDFUNCTIONSYM(sgx_urts_handle, "sgx_ecall");
    if(p_sgx_ecall != NULL) {
        return p_sgx_ecall(eid, index, ocall_table, ms);
    }
    else {
        printf("ERROR: didn't find function sgx_ecall in the sgx_urts.dll library. \n");
        return SGX_ERROR_UNEXPECTED;
    }
#else
    if (sgx_urts_handle == NULL) {
        printf("ERROR: didn't find the sgx_urts.so library, please make sure you have installed sgx_urts installer package. \n");
        return SGX_ERROR_UNEXPECTED;
    }
    sgx_ecall_func_t p_sgx_ecall = (sgx_ecall_func_t)FINDFUNCTIONSYM(sgx_urts_handle, "sgx_ecall");
    if(p_sgx_ecall != NULL ) {
        return p_sgx_ecall(eid, index, ocall_table, ms);
    }
    else {
        printf("ERROR: didn't find function sgx_ecall in the sgx_urts.dll library. \n");
        return SGX_ERROR_UNEXPECTED;
    }
#endif

}


#ifdef _MSC_VER
bool get_program_path(TCHAR *p_file_path, size_t buf_size)
{
    UNUSED(p_file_path);
    UNUSED(buf_size);
    return true;
}
#else
bool get_program_path(char *p_file_path, size_t buf_size)
{
    if(NULL == p_file_path || 0 == buf_size){
        return false;
    }

    ssize_t i = readlink( "/proc/self/exe", p_file_path, buf_size - 1);
    if (i == -1)
        return false;
    p_file_path[i] = '\0';

    char* p_last_slash = strrchr(p_file_path, '/' );
    if ( p_last_slash != NULL ) {
        p_last_slash++;   //increment beyond the last slash
        *p_last_slash = '\0';  //null terminate the string
    }
    else {
        p_file_path[0] = '\0';
    }
    return true;
}
#endif


bool get_urts_library_handle()
{
    // try to sgx_urts library to create enclave.
#if defined(_MSC_VER)
    sgx_urts_handle = LoadLibrary(SGX_URTS_LIBRARY);
    if (sgx_urts_handle == NULL) {
        printf("ERROR: didn't find the sgx_urts.dll library, please make sure you have installed PSW installer package. \n");
        return false;
    }
#else
    sgx_urts_handle = dlopen(SGX_URTS_LIBRARY, RTLD_LAZY);
    if (sgx_urts_handle == NULL) {
        printf("ERROR: didn't find the sgx_urts.so library, please make sure you have installed sgx_urts installer package. \n");
        return false;
    }
#endif
    return true;
}

void close_urts_library_handle()
{
    if (sgx_urts_handle != NULL) {
        CLOSELIBRARYHANDLE(sgx_urts_handle);
    }
}

extern "C"
#if defined(_MSC_VER)
bool load_enclave(const TCHAR* enclave_name, sgx_enclave_id_t* p_eid)
#else
bool load_enclave(const char* enclave_name, sgx_enclave_id_t* p_eid)
#endif
{
    bool ret = true;
    sgx_status_t sgx_status = SGX_SUCCESS;
    int launch_token_updated = 0;
    sgx_launch_token_t launch_token = { 0 };
    memset(&launch_token, 0, sizeof(sgx_launch_token_t));

#if defined(_MSC_VER)
    TCHAR enclave_path[ProgPathBufferSize] = _T("");
#else
    char enclave_path[ProgPathBufferSize] = "";
#endif

    if (!get_program_path(enclave_path, ProgPathBufferSize))
        return false;
#if defined(_MSC_VER)    
    if (_tcsnlen(enclave_path, ProgPathBufferSize) + _tcsnlen(enclave_name, ProgPathBufferSize) + sizeof(char) > ProgPathBufferSize)
        return false;
    (void)_tcscat_s(enclave_path, ProgPathBufferSize, enclave_name);

#ifdef UNICODE
    sgx_create_enclave_func_t p_sgx_create_enclave = (sgx_create_enclave_func_t)FINDFUNCTIONSYM(sgx_urts_handle, "sgx_create_enclavew");
#else
    sgx_create_enclave_func_t p_sgx_create_enclave = (sgx_create_enclave_func_t)FINDFUNCTIONSYM(sgx_urts_handle, "sgx_create_enclavea");
#endif
#else
    if (strnlen(enclave_path, ProgPathBufferSize) + strnlen(enclave_name, ProgPathBufferSize) + sizeof(char) > ProgPathBufferSize)
        return false;
    (void)strncat(enclave_path, enclave_name, strnlen(enclave_name, ProgPathBufferSize));

    sgx_create_enclave_func_t p_sgx_create_enclave = (sgx_create_enclave_func_t)FINDFUNCTIONSYM(sgx_urts_handle, "sgx_create_enclave");
#endif


    if (p_sgx_create_enclave == NULL ) {
        printf("ERROR: Can't find the function sgx_create_enclave in sgx_urts library.\n");
        return false;
    }
    
    sgx_status = p_sgx_create_enclave(enclave_path,
        0,
        &launch_token,
        &launch_token_updated,
        p_eid,
        NULL);
    if (SGX_SUCCESS != sgx_status) {
        printf("Error, call sgx_create_enclave: fail [%s], SGXError:%04x.\n",__FUNCTION__, sgx_status);
        ret = false;
    }

    return ret;
}

void unload_enclave(sgx_enclave_id_t* p_eid)
{
    sgx_destroy_enclave_func_t p_sgx_destroy_enclave = (sgx_destroy_enclave_func_t)FINDFUNCTIONSYM(sgx_urts_handle, "sgx_destroy_enclave");
    if (p_sgx_destroy_enclave == NULL) {
        printf("ERROR: Can't find the function sgx_destory_enclave in sgx_urts library.\n");
        return;
    }
    p_sgx_destroy_enclave(*p_eid);
}


// for multi-package platform, get the platform manifet
// return value:
//  UEFI_OPERATION_SUCCESS: successfully get the platform manifest.
//  UEFI_OPERATION_VARIABLE_NOT_AVAILABLE: it means platform manifest is not avaible: it is not multi-package platform or platform manifest has been consumed.
//  UEFI_OPERATION_LIB_NOT_AVAILABLE: it means that the uefi shared library doesn't exist
//  UEFI_OPERATION_FAIL:  it is one add package request, now we don't support it. 
//  UEFI_OPERATION_UNEXPECTED_ERROR: error happens.
uefi_status_t get_platform_manifest(uint8_t ** buffer, uint32_t &out_buffer_size)
{
    uefi_status_t ret = UEFI_OPERATION_UNEXPECTED_ERROR;
#ifdef _MSC_VER
    HINSTANCE uefi_lib_handle = LoadLibrary(SGX_MULTI_PACKAGE_AGENT_UEFI_LIBRARY);
    if (uefi_lib_handle != NULL) {
        PRINT_MESSAGE("Found the UEFI library. \n");
    }
    else {
        out_buffer_size = 0;
        buffer = NULL;
        printf("Warning: If this is a multi-package platform, please install registration agent package.\n");
        printf("         otherwise, the platform manifest information will NOT be retrieved.\n");
        return UEFI_OPERATION_LIB_NOT_AVAILABLE;
    }
#else
    void *uefi_lib_handle = dlopen(SGX_MULTI_PACKAGE_AGENT_UEFI_LIBRARY, RTLD_LAZY);
    if (uefi_lib_handle != NULL) {
        PRINT_MESSAGE("Found the UEFI library. \n");
    }
    else {
        out_buffer_size = 0;
        buffer = NULL;
        printf("Warning: If this is a multi-package platform, please install registration agent package.\n");
        printf("         otherwise, the platform manifest information will NOT be retrieved.\n");
        return UEFI_OPERATION_LIB_NOT_AVAILABLE;
    }
#endif
    mp_uefi_init_func_t p_mp_uefi_init = (mp_uefi_init_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_init");
    mp_uefi_get_request_type_func_t p_mp_uefi_get_request_type = (mp_uefi_get_request_type_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_get_request_type");
    mp_uefi_get_request_func_t p_mp_uefi_get_request = (mp_uefi_get_request_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_get_request_ex");
    mp_uefi_get_registration_status_func_t p_mp_uefi_get_registration_status = (mp_uefi_get_registration_status_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_get_registration_status");
    mp_uefi_terminate_func_t p_mp_uefi_terminate = (mp_uefi_terminate_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_terminate");
    if (p_mp_uefi_init == NULL ||
        p_mp_uefi_get_request_type == NULL ||
        p_mp_uefi_get_request == NULL ||
        p_mp_uefi_get_registration_status == NULL ||
        p_mp_uefi_terminate == NULL) {
        printf("Error: couldn't find uefi function interface(s) in the UEFI shared library.\n");
        CLOSELIBRARYHANDLE(uefi_lib_handle);
        return ret;
    }

    MpResult mpResult = MP_SUCCESS;
    MpRequestType type = MP_REQ_NONE;
    mpResult = p_mp_uefi_init(EFIVARS_FILE_SYSTEM_IN_OS, MP_REG_LOG_LEVEL_NONE);
    if (mpResult != MP_SUCCESS) {
        printf("Error: couldn't init UEFI shared library.\n");
        CLOSELIBRARYHANDLE(uefi_lib_handle);
        return ret;
    }
    do {
        mpResult = p_mp_uefi_get_request_type(&type);
        if (mpResult == MP_SUCCESS) {
            if (type == MP_REQ_REGISTRATION) {
                *buffer = new (std::nothrow) unsigned char[PLATFORM_MANIFEST_LENGTH];
                mpResult = p_mp_uefi_get_request(*buffer, &out_buffer_size);
                if (mpResult != MP_SUCCESS) {
                    printf("Error: Couldn't get the platform manifest information.\n");
                    break;
                }
            }
            else if (type == MP_REQ_ADD_PACKAGE) {
                printf("Error: Add Package type is not supported.\n");
                ret = UEFI_OPERATION_FAIL;
                break;
            }
            else {
                printf("Warning: platform manifest is not available or current platform is not multi-package platform.\n");
                ret = UEFI_OPERATION_VARIABLE_NOT_AVAILABLE;
                break;
            }
        }
        else {
            MpRegistrationStatus status;
            MpResult mpResult_registration_status = p_mp_uefi_get_registration_status(&status);
            if (mpResult_registration_status != MP_SUCCESS) {
                printf("Warning: error occurred while getting registration status, the error code is: %d \n", mpResult_registration_status);
                break;
            }
            if(status.registrationStatus == MP_TASK_COMPLETED){
                printf("Warning: registration has completed, so platform manifest has been removed. \n");
                ret = UEFI_OPERATION_VARIABLE_NOT_AVAILABLE;
                break;
            }
            else {
                printf("Error: get UEFI request type error, and the error code is: %d.\n", mpResult);
                break;
            }
        }
        ret = UEFI_OPERATION_SUCCESS;
    } while (0);
    p_mp_uefi_terminate();

    if (uefi_lib_handle != NULL) {
        CLOSELIBRARYHANDLE(uefi_lib_handle);
    }
    return ret;
}


// for multi-package platform, set registration status 
// return value:
//  UEFI_OPERATION_SUCCESS: successfully set the platform's registration status.
//  UEFI_OPERATION_LIB_NOT_AVAILABLE: it means that the uefi shared library doesn't exist, maybe the registration agent package is not installed
//  UEFI_OPERATION_UNEXPECTED_ERROR: error happens.
uefi_status_t set_registration_status()
{
    uefi_status_t ret = UEFI_OPERATION_UNEXPECTED_ERROR;
#ifdef _MSC_VER
    HINSTANCE uefi_lib_handle = LoadLibrary(SGX_MULTI_PACKAGE_AGENT_UEFI_LIBRARY);
    if (uefi_lib_handle != NULL) {
        PRINT_MESSAGE("Found the UEFI library. \n");
    }
    else {
        printf("Warning: If this is a multi-package platform, please install registration agent package.\n");
        printf("         otherwise, the platform manifest information will NOT be retrieved.\n");
        return UEFI_OPERATION_LIB_NOT_AVAILABLE;
    }
#else
    void *uefi_lib_handle = dlopen(SGX_MULTI_PACKAGE_AGENT_UEFI_LIBRARY, RTLD_LAZY);
    if (uefi_lib_handle != NULL) {
        PRINT_MESSAGE("Found the UEFI library. \n");
    }
    else {
        printf("Warning: If this is a multi-package platform, please install registration agent package.\n");
        printf("         otherwise, the platform manifest information will NOT be retrieved.\n");
        return UEFI_OPERATION_LIB_NOT_AVAILABLE;
    }
#endif
    mp_uefi_init_func_t p_mp_uefi_init = (mp_uefi_init_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_init");
    mp_uefi_set_registration_status_func_t p_mp_uefi_set_registration_status = (mp_uefi_set_registration_status_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_set_registration_status");
    mp_uefi_terminate_func_t p_mp_uefi_terminate = (mp_uefi_terminate_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_terminate");
    if (p_mp_uefi_init == NULL ||
        p_mp_uefi_set_registration_status == NULL ||
        p_mp_uefi_terminate == NULL) {
        printf("Error: couldn't find uefi function interface(s) in the multi-package agent shared library.\n");
        CLOSELIBRARYHANDLE(uefi_lib_handle);
        return ret;
    }

    MpResult mpResult = MP_SUCCESS;
    MpRegistrationStatus status;
    mpResult = p_mp_uefi_init(EFIVARS_FILE_SYSTEM_IN_OS, MP_REG_LOG_LEVEL_NONE);
    if (mpResult != MP_SUCCESS) {
        printf("Error: couldn't init uefi shared library.\n");
        CLOSELIBRARYHANDLE(uefi_lib_handle);
        return ret;
    }

    status.registrationStatus = MP_TASK_COMPLETED;
    status.errorCode = MPA_SUCCESS;
    mpResult = p_mp_uefi_set_registration_status(&status);
    if (mpResult == MP_INSUFFICIENT_PRIVILEGES) {
        printf("Warning: the UEFI variable was in read-only mode, could NOT write it. \n");
    }
    else if (mpResult != MP_SUCCESS) {
        printf("Warning: error occurred while setting registration status, the error code is: %d \n", mpResult);
    }
    else {
        ret = UEFI_OPERATION_SUCCESS;
    }
    
    p_mp_uefi_terminate();

    if (uefi_lib_handle != NULL) {
        CLOSELIBRARYHANDLE(uefi_lib_handle);
    }
    return ret;
}



int collect_data(uint8_t **pp_data_buffer)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_status_t ecall_ret = SGX_SUCCESS;
    sgx_key_128bit_t platform_id = { 0 };
    int ret = 0;
    uint32_t buffer_size = 0;
    uint8_t * p_temp = NULL;

    sgx_enclave_id_t pce_enclave_eid = 0;
    sgx_enclave_id_t id_enclave_eid = 0;
    
    sgx_report_t id_enclave_report;
    uint32_t enc_key_size = REF_RSA_OAEP_3072_MOD_SIZE + REF_RSA_OAEP_3072_EXP_SIZE;
    uint8_t enc_public_key[REF_RSA_OAEP_3072_MOD_SIZE + REF_RSA_OAEP_3072_EXP_SIZE];
    uint8_t encrypted_ppid[REF_RSA_OAEP_3072_MOD_SIZE];
    uint32_t encrypted_ppid_ret_size;
    pce_info_t pce_info;
    uint8_t signature_scheme;
    sgx_target_info_t pce_target_info;

    sgx_get_target_info_func_t p_sgx_get_target_info = NULL;

    bool load_flag = get_urts_library_handle();
    if(false == load_flag) {// can't find urts shared library to load enclave
        ret = -1;
        goto CLEANUP;
    }

    load_flag = load_enclave(ID_ENCLAVE_NAME, &id_enclave_eid);
    if(false == load_flag) { // can't load id_enclave.
        ret = -1;
        goto CLEANUP;
    }

    sgx_status = ide_get_id(id_enclave_eid, &ecall_ret, &platform_id);
    if (SGX_SUCCESS != sgx_status) {
        fprintf(stderr, "Failed to call into the ID_ENCLAVE:get_qe_id. 0x%04x.\n", sgx_status);
        ret = -1;
        goto CLEANUP;
    }

    if (SGX_SUCCESS != ecall_ret) {
        fprintf(stderr, "Failed to get QE_ID. 0x%04x.\n", ecall_ret);
        ret = -1;
        goto CLEANUP;
    }


    load_flag = load_enclave(PCE_ENCLAVE_NAME, &pce_enclave_eid);
    if(false == load_flag) { // can't load pce enclave.
        ret = -1;
        goto CLEANUP;
    }

    p_sgx_get_target_info = (sgx_get_target_info_func_t)FINDFUNCTIONSYM(sgx_urts_handle, "sgx_get_target_info");
    if (p_sgx_get_target_info == NULL) {
        printf("ERROR: Can't find the function sgx_get_target_info in sgx_urts library.\n");
        ret = -1;
        goto CLEANUP;
    }

    sgx_status = p_sgx_get_target_info(pce_enclave_eid, &pce_target_info);
    if (SGX_SUCCESS != sgx_status) {
        fprintf(stderr, "Failed to get pce target info. The error code is:  0x%04x.\n", sgx_status);
        ret = -1;
        goto CLEANUP;
    }

    sgx_status = ide_get_pce_encrypt_key(id_enclave_eid,
                                         &ecall_ret,
                                         &pce_target_info,
                                         &id_enclave_report,
                                         PCE_ALG_RSA_OAEP_3072,
                                         PPID_RSA3072_ENCRYPTED,
                                         enc_key_size,
                                         enc_public_key);
    if (SGX_SUCCESS != sgx_status) {
        fprintf(stderr, "Failed to call into the ID_ENCLAVE: get_report_and_pce_encrypt_key. The error code is: 0x%04x.\n", sgx_status);
        ret = -1;
        goto CLEANUP;
    }

    if (SGX_SUCCESS != ecall_ret) {
        fprintf(stderr, "Failed to generate PCE encryption key. The error code is: 0x%04x.\n", ecall_ret);
        ret = -1;
        goto CLEANUP;
    }

    sgx_status = get_pc_info(pce_enclave_eid,
                              (uint32_t*) &ecall_ret,
                              &id_enclave_report,
                              enc_public_key,
                              enc_key_size,
                              PCE_ALG_RSA_OAEP_3072,
                              encrypted_ppid,
                              REF_RSA_OAEP_3072_MOD_SIZE,
                              &encrypted_ppid_ret_size,
                              &pce_info,
                              &signature_scheme);
    if (SGX_SUCCESS != sgx_status) {
        fprintf(stderr, "Failed to call into PCE enclave: get_pc_info. The error code is: 0x%04x.\n", sgx_status);
        ret = -1;
        goto CLEANUP;
    }
    if (SGX_SUCCESS != ecall_ret) {
        fprintf(stderr, "Failed to get PCE info. The error code is: 0x%04x.\n", ecall_ret);
        ret = -1;
        goto CLEANUP;
    }

    if (signature_scheme != PCE_NIST_P256_ECDSA_SHA256) {
        fprintf(stderr, "PCE returned incorrect signature scheme.\n");
        ret = -1;
        goto CLEANUP;
    }

    if (encrypted_ppid_ret_size != ENCRYPTED_PPID_LENGTH) {
        fprintf(stderr, "PCE returned incorrect encrypted PPID size.\n");
        ret = -1;
        goto CLEANUP;
    }

    buffer_size = ENCRYPTED_PPID_LENGTH + CPU_SVN_LENGTH + ISV_SVN_LENGTH + PCE_ID_LENGTH + DEFAULT_PLATFORM_ID_LENGTH;
    *pp_data_buffer = (uint8_t *) malloc(buffer_size);

    if (NULL == *pp_data_buffer) {
        fprintf(stderr,"Couldn't allocate data buffer\n");
        ret = -1;
        goto CLEANUP;
    }
    memset(*pp_data_buffer, 0, buffer_size);
    p_temp = *pp_data_buffer;
    //encrypted ppid
    memcpy(p_temp, encrypted_ppid, ENCRYPTED_PPID_LENGTH);
    
    //pce id
    p_temp = p_temp + ENCRYPTED_PPID_LENGTH;
    memcpy(p_temp , &(pce_info.pce_id), PCE_ID_LENGTH);

    //cpu svn
    p_temp = p_temp + PCE_ID_LENGTH;
    memcpy(p_temp , id_enclave_report.body.cpu_svn.svn, CPU_SVN_LENGTH);
    
    //pce isv svn
    p_temp = p_temp + CPU_SVN_LENGTH;
    memcpy(p_temp , &(pce_info.pce_isvn), ISV_SVN_LENGTH);
    
    //platform id
    p_temp = p_temp + ISV_SVN_LENGTH;
    memcpy(p_temp , platform_id, DEFAULT_PLATFORM_ID_LENGTH);

    
CLEANUP:
    if(pce_enclave_eid != 0) {
        unload_enclave(&pce_enclave_eid);
    }
    if(id_enclave_eid != 0) {
        unload_enclave(&id_enclave_eid);
    }
    close_urts_library_handle();
    return ret;

}

bool is_valid_proxy_type(std::string& proxy_type) {
    if (proxy_type.compare("DEFAULT") == 0 ||
        proxy_type.compare("MANUAL")  == 0 ||
        proxy_type.compare("AUTO")    == 0 ||
        proxy_type.compare("DIRECT")  == 0 ) { 
        return true;
    }
    else {
        return false;
    }                
}

bool is_valid_use_secure_cert(std::string& use_secure_cert) {
    if (use_secure_cert.compare("TRUE") == 0 ) {
        return true;
    }
    else if(use_secure_cert.compare("FALSE") == 0) {
        g_use_secure_cert = false;
	return true;
    }
    else {
        return false;
    }  
}

bool is_valid_tcb_update_type(std::string& tcb_update_type) {
    if (tcb_update_type.compare("STANDARD") == 0 ||
        tcb_update_type.compare("EARLY")  == 0 ||
        tcb_update_type.compare("ALL")  == 0 ) { 
        return true;
    }
    else {
        return false;
    }                
}


/**
* Method converts byte containing value from 0x00-0x0F into its corresponding ASCII code,
* e.g. converts 0x00 to '0', 0x0A to 'A'.
* Note: This is mainly a helper method for internal use in byte_array_to_hex_string().
*
* @param in byte to be converted (allowed values: 0x00-0x0F)
*
* @return ASCII code representation of the byte or 0 if method failed (e.g input value was not in provided range).
*/
uint8_t convert_value_to_ascii(uint8_t in)
{
	if (in <= 0x09)
	{
		return (uint8_t)(in + '0');
	}
	else if (in <= 0x0F)
	{
		return (uint8_t)(in - 10 + 'A');
	}

	return 0;
}

//Function to do HEX encoding of array of bytes
//@param in_buf, bytes array whose length is in_size
//       out_buf, output the HEX encoding of in_buf on success.
//@return true on success and false on error
//The out_size must always be 2*in_size since each byte into encoded by 2 characters
bool byte_array_to_hex_string(const uint8_t *in_buf, uint64_t in_size, uint8_t *out_buf, uint64_t out_size)
{
	if (in_size>UINT64_MAX / 2)return false;
	if (in_buf == NULL || out_buf == NULL || out_size != in_size * 2)return false;

	for (uint32_t i = 0; i< in_size; i++)
	{
		*out_buf++ = convert_value_to_ascii(static_cast<uint8_t>(*in_buf >> 4));
		*out_buf++ = convert_value_to_ascii(static_cast<uint8_t>(*in_buf & 0xf));
		in_buf++;
	}
	return true;
}
                     

/**
* This function appends request parameters of byte array type to the UR in HEX string format
*
* @param url Request UR
* @param request  Request parameter in byte array
* @param request_size Size of byte array
*
* @return true If the byte array was appended to the UR successfully
*/
network_post_error_t append_body_context(std::string& url, const uint8_t* request, const uint64_t request_size)
{
	if (request_size >= UINT32_MAX / 2)
		return POST_INVALID_PARAMETER_ERROR;

	uint8_t* hex = (uint8_t*)malloc(request_size * 2);
	if (!hex)
		return POST_OUT_OF_MEMORY_ERROR;
	if (!byte_array_to_hex_string(request, request_size, hex, request_size * 2)) {
		free(hex);
		return POST_UNEXPECTED_ERROR;
	}
	url.append(reinterpret_cast<const char*>(hex), request_size * 2);
	free(hex);
	return POST_SUCCESS;
}

network_post_error_t generate_json_message_body(const uint8_t *raw_data, 
                                                const uint64_t raw_data_size,
                                                const uint16_t platform_id_length,
                                                const bool non_enclave_mode, 
                                                std::string &jsonString)
{
    network_post_error_t ret = POST_SUCCESS;
    const uint8_t *position = raw_data;

    jsonString = "{";
    if (true == non_enclave_mode) {
        jsonString += "\"pce_id\": \"";
        if ((ret = append_body_context(jsonString, position, PCE_ID_LENGTH)) != POST_SUCCESS) {
            return ret;
        }
        jsonString += "\" ,\"qe_id\": \"";
        position = position + PCE_ID_LENGTH;
        if ((ret = append_body_context(jsonString, position, platform_id_length)) != POST_SUCCESS) {
            return ret;
        }

        jsonString += "\" ,\"platform_manifest\": \"";
        position = position + platform_id_length;
        if ((ret = append_body_context(jsonString, position, raw_data_size - PCE_ID_LENGTH - platform_id_length)) != POST_SUCCESS) {
            return ret;
        }
    }
    else {
        uint64_t left_size = raw_data_size - platform_id_length - CPU_SVN_LENGTH - ISV_SVN_LENGTH - PCE_ID_LENGTH - ENCRYPTED_PPID_LENGTH;
        jsonString += "\"enc_ppid\": \"";
        if ((ret = append_body_context(jsonString, position, ENCRYPTED_PPID_LENGTH)) != POST_SUCCESS) {
            return ret;
        }

        jsonString += "\" ,\"pce_id\": \"";
        position = position + ENCRYPTED_PPID_LENGTH;
        if ((ret = append_body_context(jsonString, position, PCE_ID_LENGTH)) != POST_SUCCESS) {
            return ret;
        }
        jsonString += "\" ,\"cpu_svn\": \"";
        position = position + PCE_ID_LENGTH;
        if ((ret = append_body_context(jsonString, position, CPU_SVN_LENGTH)) != POST_SUCCESS) {
            return ret;
        }

        jsonString += "\" ,\"pce_svn\": \"";
        position = position + CPU_SVN_LENGTH;
        if ((ret = append_body_context(jsonString, position, ISV_SVN_LENGTH)) != POST_SUCCESS) {
            return ret;
        }

        jsonString += "\" ,\"qe_id\": \"";
        position = position + ISV_SVN_LENGTH;
        if ((ret = append_body_context(jsonString, position, platform_id_length)) != POST_SUCCESS) {
            return ret;
        }

        jsonString += "\" ,\"platform_manifest\": \"";
        if (left_size != 0) {
            position = position + platform_id_length;
            if ((ret = append_body_context(jsonString, position, left_size)) != POST_SUCCESS) {
                return ret;
            }
        }

    }
    jsonString += "\" }";
    return ret;
}
