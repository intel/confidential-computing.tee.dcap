/*
 * Copyright(c) 2026 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _DCAP_SECURE_LOAD_LIBRARY_H_
#define _DCAP_SECURE_LOAD_LIBRARY_H_

#ifdef _WIN32

#include <Windows.h>

static inline HMODULE dcap_secure_load_library(LPCTSTR lpLibFileName)
{
    return LoadLibraryEx(lpLibFileName, NULL, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
}

static inline BOOL dcap_harden_dll_search_path(void)
{
    return SetDllDirectory(TEXT(""));
}

#endif /* _WIN32 */

#endif /* _DCAP_SECURE_LOAD_LIBRARY_H_ */
