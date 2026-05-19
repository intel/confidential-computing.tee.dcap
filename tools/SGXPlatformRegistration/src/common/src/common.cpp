/*
 * Copyright(c) 2011-2026 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
/**
 * File: comomon.cpp
 *  
 * Description: Shared utility functions for file I/O
 */
#ifdef _WIN32
#include "atlstr.h"
#elif defined(STANDALONE)
#include <unistd.h>
#include <limits.h>
#endif

#include "MPConfigurations.h"
#include "common.h"

#ifndef _WIN32
#include "dcap_safe_file_ops.h"
#define fopen_s(pFile,filename,mode) ((*(pFile))=dcap_safe_fopen((filename),(mode)))==NULL
#endif

string getExeDirectory() {
#ifdef _WIN32
    TCHAR szPath[MAX_PATH];
    if (!GetModuleFileName(NULL, szPath, MAX_PATH))
    {
        return "";
    }
    string path = szPath;
    string::size_type pos = path.find_last_of("\\");
    if(pos == string::npos) {
        return "";
    }
    return path.substr(0, pos + 1);
#else
    #ifdef STANDALONE
        char szPath[PATH_MAX];
        ssize_t i = readlink("/proc/self/exe", szPath, sizeof(szPath));
        if (i == -1 || i == PATH_MAX)
        {
            return string(LINUX_INSTALL_PATH);
        }
        szPath[i] ='\0';
        string path = szPath;
        string::size_type pos = path.find_last_of("/");
        if(pos == string::npos) {
            return string(LINUX_INSTALL_PATH);
        }
        return path.substr(0, pos + 1);
    #else // non-standalone non-Windows
        return string(LINUX_INSTALL_PATH);
    #endif
#endif
}

string getConfDirectory() {
#if defined(_WIN32) || defined(STANDALONE)
	return getExeDirectory();
#else
	return string(MP_REG_CONFIG_FILE);
#endif
}

int writeBufferToFile(const char *filename, uint8_t *buffer, size_t buffSize) {
    int ret = 0;
    size_t writtenSize = 0;
    FILE *file = NULL;

    if (fopen_s(&file, filename, "wb") || file == NULL) {
        //agent_log_message(MP_REG_LOG_LEVEL_ERROR, "Failed to open file: %s\n", filename);
        ret = MP_INVALID_PARAMETER;
        goto out;
    }

    writtenSize = fwrite(buffer, sizeof(uint8_t), buffSize, file);
    if (writtenSize != buffSize) {
        //agent_log_message(MP_REG_LOG_LEVEL_ERROR, "Failed to write data to file: %s\n", filename);
        ret = MP_UNEXPECTED_ERROR;
        goto out;
    }

out:
    if (file) {
        fclose(file);
    }
    return ret;
}

int readFileToBuffer(const char *filename, uint8_t *buffer, size_t &buffSize) {
    int ret = 0;
    size_t writtenSize = 0;
    FILE *file = NULL;
    long fileSize;

    if (fopen_s(&file, filename, "rb") || file == NULL) {
        //agent_log_message(MP_REG_LOG_LEVEL_ERROR, "Failed to open file: %s\n", filename);
        ret = MP_INVALID_PARAMETER;
        goto out;
    }

    ret = fseek(file, 0, SEEK_END); // seek to end of file
    if (0 != ret) {
        //agent_log_message(MP_REG_LOG_LEVEL_ERROR, "Failed to seek in file: %s\n", filename);
        ret = MP_UNEXPECTED_ERROR;
        goto out;
    }
    fileSize = ftell(file); // get current file pointer
    ret = fseek(file, 0, SEEK_SET); // seek back to beginning of file
    if (0 != ret) {
        //agent_log_message(MP_REG_LOG_LEVEL_ERROR, "Failed to seek in file: %s\n", filename);
        ret = MP_UNEXPECTED_ERROR;
        goto out;
    }

    if ((unsigned long)fileSize > buffSize) {
        //agent_log_message(MP_REG_LOG_LEVEL_ERROR, "Received file: %s is too big for expected file size: %d.\n", filename, buffSize);
        ret = MP_INVALID_PARAMETER;
        goto out;
    }

    writtenSize = fread(buffer, sizeof(uint8_t), (unsigned long)fileSize, file);
    if (writtenSize != (unsigned long)fileSize) {
        //agent_log_message(MP_REG_LOG_LEVEL_ERROR, "Failed to read data from file: %s\n", filename);
        ret = MP_UNEXPECTED_ERROR;
        goto out;
    }

    buffSize = fileSize;
out:
    if (file) {
        fclose(file);
    }
    return ret;
}
