/*
 * Copyright(c) 2026 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _DCAP_SAFE_FILE_OPS_H_
#define _DCAP_SAFE_FILE_OPS_H_

#include <stdio.h>
#include <string.h>

#ifndef _MSC_VER
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <dlfcn.h>

/* O_TMPFILE is a Linux-specific extension exposed by <fcntl.h> only when
 * _GNU_SOURCE is defined. Consumers of this header may not enable it, so
 * provide the canonical x86 value as a fallback. We only test it against
 * the caller's `flags`; we never pass it to open(2) ourselves. */
#ifndef O_TMPFILE
#  define O_TMPFILE 020200000
#endif

#if defined(__has_include)
#  if __has_include(<linux/openat2.h>)
#    include <linux/openat2.h>
#    define DCAP_HAVE_OPENAT2_HEADER 1
#  endif
#endif

/* Open rejecting symlinks anywhere in the path.
 * Uses openat2(RESOLVE_NO_SYMLINKS) on Linux >= 5.6 (whole-path),
 * falls back to open(O_NOFOLLOW) (final component only). */
static inline int dcap_safe_open_internal(const char *path, int flags, mode_t mode)
{
#if defined(SYS_openat2)
    /* struct open_how is part of the stable kernel ABI; declare it locally
     * if the kernel header is unavailable (e.g. glibc < 5.6 headers). */
#if !defined(DCAP_HAVE_OPENAT2_HEADER)
    struct open_how {
        uint64_t flags;
        uint64_t mode;
        uint64_t resolve;
    };
#  ifndef RESOLVE_NO_SYMLINKS
#    define RESOLVE_NO_SYMLINKS 0x04
#  endif
#endif
    struct open_how how;
    memset(&how, 0, sizeof(how));
    /* Cast through __typeof__ so this compiles cleanly under -Wsign-conversion
     * regardless of whether how.flags is __u64 (kernel header) or uint64_t
     * (our local fallback). On x86_64 Linux those are different types
     * (unsigned long long vs unsigned long) and a plain (uint64_t) cast
     * triggers -Werror=sign-conversion when the kernel header is present. */
    how.flags = (__typeof__(how.flags))(unsigned int)flags;
    how.mode = (flags & (O_CREAT | O_TMPFILE))
                   ? (__typeof__(how.mode))mode
                   : (__typeof__(how.mode))0;
    how.resolve = (__typeof__(how.resolve))RESOLVE_NO_SYMLINKS;

    int fd = (int)syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof(how));
    if (fd >= 0)
        return fd;
    /* Only fall back when openat2 is unavailable (kernel/seccomp). */
    if (errno != ENOSYS && errno != EPERM)
        return -1;
#endif
    return open(path, flags | O_NOFOLLOW, mode);
}

/* Symlink-safe fopen. See dcap_safe_open_internal for resolution semantics. */
static inline FILE *dcap_safe_fopen(const char *filename, const char *mode)
{
    int flags = 0;
    int has_plus;
    int fd;
    int mi;
    char safe_mode[4];
    FILE *fp;

    if (filename == NULL || mode == NULL) {
        errno = EINVAL;
        return NULL;
    }

#ifdef O_LARGEFILE
    flags |= O_LARGEFILE;
#endif
    has_plus = (strchr(mode, '+') != NULL);
    if (strchr(mode, 'e'))
        flags |= O_CLOEXEC;
    if (strchr(mode, 'x'))
        flags |= O_EXCL;
    switch (mode[0]) {
        case 'r':
            flags |= has_plus ? O_RDWR : O_RDONLY;
            break;
        case 'w':
            flags |= (has_plus ? O_RDWR : O_WRONLY) | O_CREAT | O_TRUNC;
            break;
        case 'a':
            flags |= (has_plus ? O_RDWR : O_WRONLY) | O_CREAT | O_APPEND;
            break;
        default:
            errno = EINVAL;
            return NULL;
    }

    fd = dcap_safe_open_internal(filename, flags, 0666);
    if (fd < 0)
        return NULL;

    /* O_APPEND ensures writes append, but doesn't set initial offset. */
    if (mode[0] == 'a') {
        if (lseek(fd, 0, SEEK_END) == (off_t)-1) {
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return NULL;
        }
    }

    /* Portable fdopen mode: r/w/a, optional 'b', optional '+'. */
    mi = 0;
    safe_mode[mi++] = mode[0];
    if (strchr(mode, 'b'))
        safe_mode[mi++] = 'b';
    if (has_plus)
        safe_mode[mi++] = '+';
    safe_mode[mi] = '\0';

    fp = fdopen(fd, safe_mode);
    if (fp == NULL) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
    }
    return fp;
}

/* Symlink-safe open. See dcap_safe_open_internal for resolution semantics. */
static inline int dcap_safe_open(const char *path, int flags, mode_t mode)
{
    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }
    return dcap_safe_open_internal(path, flags, mode);
}

/* Symlink-safe dlopen: opens the file with symlink protection, then hands
 * the verified fd to dlopen() via /proc/self/fd/N. Clears dlerror() on
 * entry so callers can distinguish open() vs dlopen() failure. */
static inline void *dcap_safe_dlopen(const char *path, int flags)
{
    int fd;
    char fd_path[64];
    void *handle;

    if (path == NULL) {
        errno = EINVAL;
        return NULL;
    }

    (void)dlerror();

    fd = dcap_safe_open_internal(path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0)
        return NULL;

    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    handle = dlopen(fd_path, flags);
    close(fd);
    return handle;
}

#else /* _MSC_VER */
#include <Windows.h>
#include <io.h>
#include <fcntl.h>

/* TODO: callers currently pass ASCII paths; add a wide-char variant if
 * UTF-8/Unicode paths are ever needed (CreateFileA uses the ANSI code page). */

/* Symlink-safe fopen on Windows. Opens with FILE_FLAG_OPEN_REPARSE_POINT
 * (so reparse points are not followed), then rejects the handle if it
 * actually refers to one. Atomic w.r.t. path resolution -> no TOCTOU. */
static inline FILE *dcap_safe_fopen(const char *filename, const char *mode)
{
    DWORD access = 0;
    DWORD creation = 0;
    HANDLE h;
    int has_plus;
    int has_binary;
    int oflags = 0;
    int fd;
    BY_HANDLE_FILE_INFORMATION info;
    FILE *fp;

    if (filename == NULL || mode == NULL)
        return NULL;

    has_plus = (strchr(mode, '+') != NULL);
    has_binary = (strchr(mode, 'b') != NULL);
    switch (mode[0]) {
        case 'r':
            access = has_plus ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ;
            creation = OPEN_EXISTING;
            oflags = has_plus ? _O_RDWR : _O_RDONLY;
            break;
        case 'w':
            access = has_plus ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_WRITE;
            creation = CREATE_ALWAYS;
            oflags = has_plus ? (_O_RDWR | _O_CREAT | _O_TRUNC) : (_O_WRONLY | _O_CREAT | _O_TRUNC);
            break;
        case 'a':
            access = has_plus ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_WRITE;
            creation = OPEN_ALWAYS;
            oflags = has_plus ? (_O_RDWR | _O_CREAT | _O_APPEND) : (_O_WRONLY | _O_CREAT | _O_APPEND);
            break;
        default:
            return NULL;
    }

    /* Preserve fopen()'s "b" => binary, default => text translation. */
    oflags |= has_binary ? _O_BINARY : _O_TEXT;

    h = CreateFileA(filename, access, FILE_SHARE_READ, NULL,
                    creation, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return NULL;

    /* Fail closed: treat attribute query failure as untrusted. */
    if (!GetFileInformationByHandle(h, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        CloseHandle(h);
        return NULL;
    }

    fd = _open_osfhandle((intptr_t)h, oflags);
    if (fd < 0) {
        CloseHandle(h);
        return NULL;
    }

    fp = _fdopen(fd, mode);
    if (fp == NULL)
        _close(fd);  /* also closes underlying handle */
    return fp;
}

#endif /* _MSC_VER */

#endif /* _DCAP_SAFE_FILE_OPS_H_ */
