/*
 * Copyright(c) 2011-2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
/**
 * File: qve_parser.cpp
 *
 * Description: Wrapper functions for the
 * reference implementing the QvE
 * function defined in sgx_qve.h. This
 * would be replaced or used to wrap the
 * PSW defined interfaces to the QvE.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "se_trace.h"
#include "sgx_urts.h"
#include "sgx_dcap_pcs_com.h"

#define QvE_ENCLAVE_NAME "libsgx_qve.signed.so.1"
#define QvE_ENCLAVE_NAME_LEGACY "libsgx_qve.signed.so"

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

static constexpr size_t kQvePathBufferSize = MAX_PATH + 1;

static char g_qve_path[kQvePathBufferSize];

extern "C" bool sgx_qv_set_qve_path(const char* p_path)
{
    // p_path isn't NULL, caller has checked it.
    // len <= sizeof(g_qve_path)
    size_t len = strnlen(p_path, sizeof(g_qve_path));
    // Make sure there is enough space for the '\0'
    // after this line len <= sizeof(g_qve_path) - 1
    if(len > sizeof(g_qve_path) - 1)
        return false;
    strncpy(g_qve_path, p_path, sizeof(g_qve_path) - 1);
    // Make sure the full path is ended with "\0"
    g_qve_path[len] = '\0';
    return true;
}


bool get_qve_path(
    char *p_file_path,
    size_t buf_size)
{
    if(!p_file_path)
        return false;

    Dl_info dl_info;
    if(g_qve_path[0])
    {
        strncpy(p_file_path, g_qve_path, buf_size -1);
        p_file_path[buf_size - 1] = '\0';  //null terminate the string
        return true;
    }
    else if (*SGX_ENCLAVE_PATH)
    {
        if ((strlen(SGX_ENCLAVE_PATH) + 1 + 1) > buf_size) {
            return false;
        }
        (void)strcpy(p_file_path, SGX_ENCLAVE_PATH);
        (void)strcat(p_file_path, "/");
    }
    else if(0 != dladdr(__builtin_return_address(0), &dl_info) &&
        NULL != dl_info.dli_fname)
    {
        if(strnlen(dl_info.dli_fname,buf_size)>=buf_size)
            return false;
        (void)strncpy(p_file_path,dl_info.dli_fname,buf_size);
    }
    else //not a dynamic executable
    {
        ssize_t i = readlink( "/proc/self/exe", p_file_path, buf_size - 1);
        if (i == -1)
            return false;
        p_file_path[i] = '\0';
    }

    char* p_last_slash = strrchr(p_file_path, '/' );
    if ( p_last_slash != NULL )
    {
        p_last_slash++;   //increment beyond the last slash
        *p_last_slash = '\0';  //null terminate the string
    }
    else p_file_path[0] = '\0';
    if(strnlen(p_file_path,buf_size)+strnlen(QvE_ENCLAVE_NAME,buf_size)+sizeof(char)>buf_size)
        return false;
    (void)strncat(p_file_path,QvE_ENCLAVE_NAME, strnlen(QvE_ENCLAVE_NAME,buf_size));
    struct stat info;
    if(stat(p_file_path, &info) != 0 ||
        ((info.st_mode & S_IFREG) == 0 && (info.st_mode & S_IFLNK) == 0)) {
        if ( p_last_slash != NULL )
        {
            *p_last_slash = '\0';  //null terminate the string
        }
        else p_file_path[0] = '\0';
        (void)strncat(p_file_path, QvE_ENCLAVE_NAME_LEGACY, strnlen(QvE_ENCLAVE_NAME_LEGACY, buf_size));
    }
    return true;
}
