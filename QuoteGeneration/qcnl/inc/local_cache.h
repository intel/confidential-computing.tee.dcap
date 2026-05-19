/*
 * Copyright(c) 2011-2026 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
/** File: local_cache.h
 *
 * Description: Implementation of local cache for PCK certificate chain & collaterals
 *
 */
#ifndef LOCALCACHE_H_
#define LOCALCACHE_H_
#pragma once

#include "qcnl_config.h"
#include "qcnl_util.h"
#include "se_memcpy.h"
#include <fstream>
#include <list>
#include <mutex>
#include <time.h>
#include <unordered_map>
#include <vector>
#include <algorithm>

#ifdef _MSC_VER
#include <io.h>
#include <windows.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#endif

using namespace std;
static std::mutex mutex_cache_lock;

template <typename Key, typename Value>
class MemoryCache {
private:
    list<Key> keys_;
    unordered_map<Key, pair<Value, typename list<Key>::iterator>> map_;
    size_t size_;

public:
    // Set default cache size to 20
    MemoryCache() : size_(20) {}

    void set(const Key key, const Value value) {
        auto pos = map_.find(key);
        if (pos == map_.end()) {
            keys_.push_front(key);
            map_[key] = {value, keys_.begin()};
            if (map_.size() > size_) {
                map_.erase(keys_.back());
                keys_.pop_back();
            }
        } else {
            keys_.erase(pos->second.second);
            keys_.push_front(key);
            map_[key] = {value, keys_.begin()};
        }
    }

    bool get(const Key key, Value &value) {
        auto pos = map_.find(key);
        if (pos == map_.end())
            return false;
        keys_.erase(pos->second.second);
        keys_.push_front(key);
        map_[key] = {pos->second.first, keys_.begin()};
        value = pos->second.first;
        return true;
    }

    void remove(const Key key) {
        auto pos = map_.find(key);
        if (pos != map_.end()) {
            keys_.erase(pos->second.second);
            map_.erase(key);
        }
    }
};

#pragma pack(push, 1)

struct CacheItemHeader {
    uint16_t version;
    sgx_qpl_cache_type_t cache_type;
    time_t expiry;
};

#pragma pack(pop)
// (key, value) pair, where
//    Cache Key = sha256(URL)
//    Cache value = CacheItemHeader || HTTP RESPONSE(HEADER SIZE || HEADER || BODY SIZE || BODY)
class LocalCache {
private:
    //
    MemoryCache<string, vector<uint8_t>> mem_cache_;
#ifdef _MSC_VER
    wstring cache_dir_;
#else
    string cache_dir_;
#endif

public:
    static LocalCache &Instance() {
        static LocalCache myInstance;
        return myInstance;
    }

    LocalCache(LocalCache const &) = delete;
    LocalCache(LocalCache &&) = delete;
    LocalCache &operator=(LocalCache const &) = delete;
    LocalCache &operator=(LocalCache &&) = delete;

    bool get_data(const string &key, vector<uint8_t> &value) {
        // Lock the cache mutex
        std::lock_guard<std::mutex> lock(mutex_cache_lock);

        bool cache_hit = false;
        if (!mem_cache_.get(key, value)) {
            // If memory cache missed, turn to file cache
            if (!cache_dir_.empty()) {
#ifdef _MSC_VER
                wstring wskey(key.begin(), key.end());
                const auto file_name = cache_dir_ + L"\\" + wskey;
                ifstream ifs(file_name, std::ios::in | std::ios::binary);
                if (ifs.is_open()) {
                    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Cache hit in folder '%s'. \n", cache_dir_.c_str());
                    value.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
                    // Need to update memory cache if file cache is hit
                    mem_cache_.set(key, value);
                    cache_hit = true;
                }
                ifs.close();
#else
                string lowercase = key;
                std::transform(lowercase.begin(), lowercase.end(), lowercase.begin(),
                               [](unsigned char c) { return std::tolower(c); });
                const auto file_name = cache_dir_ + "/" + lowercase;
                /* O_NOFOLLOW rejects a symlink at the final component. */
                int fd = ::open(file_name.c_str(),
                                O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
                if (fd >= 0) {
                    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Cache hit in folder '%s'. \n", cache_dir_.c_str());
                    value.clear();
                    uint8_t buf[4096];
                    for (;;) {
                        ssize_t n = ::read(fd, buf, sizeof(buf));
                        if (n > 0) {
                            value.insert(value.end(), buf, buf + n);
                        } else if (n == 0) {
                            break;
                        } else {
                            if (errno == EINTR) continue;
                            value.clear();
                            break;
                        }
                    }
                    ::close(fd);
                    if (!value.empty()) {
                        // Need to update memory cache if file cache is hit
                        mem_cache_.set(key, value);
                        cache_hit = true;
                    }
                }
#endif
            }
        } else {
            qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Cache hit in memory. \n");
            cache_hit = true;
        }

        return cache_hit;
    }

    void set_data(const string &key, vector<uint8_t> &value) {
        // Lock the cache mutex
        std::lock_guard<std::mutex> lock(mutex_cache_lock);

        // Update memory cache
        mem_cache_.set(key, value);

        if (!cache_dir_.empty()) {
            // Update file cache
#ifdef _MSC_VER
            wstring wskey(key.begin(), key.end());
            const auto file_name = cache_dir_ + L"\\" + wskey;
            ofstream ofs(file_name, ios::out | ios::binary);
            if (!ofs.is_open()) {
                qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Failed to write cache file '%s'. \n", file_name.c_str());
            }
            ofs.write(reinterpret_cast<const char *>(&value[0]), value.size());
            ofs.close();
#else
            string lowercase = key;
            std::transform(lowercase.begin(), lowercase.end(), lowercase.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            const auto file_name = cache_dir_ + "/" + lowercase;
            /* O_NOFOLLOW rejects a symlink at the final component;
             * 0600 restricts the new file to the owning uid. */
            int fd = ::open(file_name.c_str(),
                            O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                            0600);
            if (fd < 0) {
                qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Failed to write cache file '%s' (%s). \n",
                         file_name.c_str(), strerror(errno));
            } else {
                const uint8_t *p = value.data();
                size_t remaining = value.size();
                while (remaining > 0) {
                    ssize_t n = ::write(fd, p, remaining);
                    if (n < 0) {
                        if (errno == EINTR) continue;
                        qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Failed to write cache file '%s' (%s). \n",
                                 file_name.c_str(), strerror(errno));
                        break;
                    }
                    p += n;
                    remaining -= (size_t)n;
                }
                ::close(fd);
            }
#endif

            qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Updated file cache successfully. \n");
        }
    }

    void remove_data(const string &key) {
        // Lock the cache mutex
        std::lock_guard<std::mutex> lock(mutex_cache_lock);

        // Remove memory cache entry
        mem_cache_.remove(key);

        if (!cache_dir_.empty()) {
            // Remove file cache
#ifdef _MSC_VER
            wstring wskey(key.begin(), key.end());
            const auto file_name = cache_dir_ + L"\\" + wskey;
            if (!::DeleteFile(file_name.c_str())) {
                qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Error deleting cache item '%s'. \n", key.c_str());
            }
#else
            string lowercase = key;
            std::transform(lowercase.begin(), lowercase.end(), lowercase.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            const auto file_name = cache_dir_ + "/" + lowercase;
            if (std::remove(file_name.c_str()) != 0) {
                qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Error deleting cache item '%s'. \n", key.c_str());
            }
#endif
        }
    }

#ifdef _WIN32
    bool process_file(const std::wstring &entry_path, int cache_type) {
        std::ifstream ifs(entry_path, std::ios::in | std::ios::binary);
        if (ifs.is_open()) {
            CacheItemHeader cache_header;
            ifs.read(reinterpret_cast<char *>(&cache_header), sizeof(cache_header));
            if (ifs && cache_header.cache_type & cache_type) {
                ifs.close();
                if(!::DeleteFile(entry_path.c_str()))
                    return false;
            } else {
                ifs.close();
            }
            return true;
        }
        else {
            return false;
        }
    }
#else
    bool process_file(const std::string & entry_path, int cache_type) {
        int fd = ::open(entry_path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
            return false;
        CacheItemHeader cache_header;
        ssize_t total = 0;
        while (total < (ssize_t)sizeof(cache_header)) {
            ssize_t n = ::read(fd, reinterpret_cast<char *>(&cache_header) + total,
                               sizeof(cache_header) - total);
            if (n > 0) {
                total += n;
            } else if (n == 0) {
                break;
            } else {
                if (errno == EINTR) continue;
                ::close(fd);
                return false;
            }
        }
        ::close(fd);
        if (total == (ssize_t)sizeof(cache_header) && (cache_header.cache_type & cache_type)) {
            if (std::remove(entry_path.c_str()) != 0)
                return false;
        }
        return true;
    }
#endif

    sgx_qcnl_error_t clear_cache(uint32_t cache_type) {
        sgx_qcnl_error_t ret = SGX_QCNL_SUCCESS;
        // Lock the cache mutex
        std::lock_guard<std::mutex> lock(mutex_cache_lock);

        if (cache_dir_.empty()) {
            return ret;
        }

#ifdef _WIN32
        std::wstring search_path = cache_dir_ + L"\\*.*";
        WIN32_FIND_DATA fd;
        HANDLE hFind = FindFirstFile(search_path.c_str(), &fd);

        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    std::wstring entry_path = cache_dir_ + L"\\" + fd.cFileName;
                    if (!process_file(entry_path, cache_type)) {
                        ret = SGX_QCNL_UNEXPECTED_ERROR;
                        break;
                    }
                }
            } while (FindNextFile(hFind, &fd));
            FindClose(hFind);
        } else {
            qcnl_log(SGX_QL_LOG_ERROR, "Could not open directory: %s \n", cache_dir_.c_str());
            ret = SGX_QCNL_UNEXPECTED_ERROR;
        }
#else
        DIR *dir;
        struct dirent *ent;
        struct stat file_stat;

        if ((dir = opendir(cache_dir_.c_str())) != nullptr) {
            while ((ent = readdir(dir)) != nullptr) {
                std::string entry_path = cache_dir_ + "/" + ent->d_name;
                if (stat(entry_path.c_str(), &file_stat) == 0 && S_ISREG(file_stat.st_mode)) {
                    if (!process_file(entry_path, cache_type)) {
                        ret = SGX_QCNL_UNEXPECTED_ERROR;
                        break;
                    }
                }
            }
            closedir(dir);
        } else {
            qcnl_log(SGX_QL_LOG_ERROR, "Could not open directory: %s \n", cache_dir_.c_str());
            ret = SGX_QCNL_UNEXPECTED_ERROR;
        }
#endif
        return ret;
    }

protected:
    LocalCache() {
        init_cache_directory();
    }
    ~LocalCache() {}

#ifdef _MSC_VER
    void init_cache_directory() {
        const DWORD buffSize = MAX_PATH;

        auto env_home = std::make_unique<wchar_t[]>(buffSize);
        memset(env_home.get(), 0, buffSize);
        GetEnvironmentVariable(L"LOCALAPPDATA", env_home.get(), buffSize);
        std::wstring wenv_home(env_home.get());

        auto env_azdcap_cache = std::make_unique<wchar_t[]>(buffSize);
        memset(env_azdcap_cache.get(), 0, buffSize);
        GetEnvironmentVariable(L"AZDCAP_CACHE", env_azdcap_cache.get(), buffSize);
        std::wstring wenv_azdcap_cache(env_azdcap_cache.get());

        const std::wstring application_name(L"\\.dcap-qcnl");
        std::wstring dirname;

        if (wenv_azdcap_cache != L"" && wenv_azdcap_cache[0] != 0) {
            dirname = wenv_azdcap_cache;
        } else if (wenv_home != L"" && wenv_home[0] != 0) {
            dirname = wenv_home.append(L"\\..\\LocalLow");
        }

        dirname += application_name;
        make_dir(dirname);
        cache_dir_ = dirname;
    }

    bool make_dir(const std::wstring &dirname) {
        CreateDirectory(dirname.c_str(), NULL);
        if (GetLastError() == ERROR_PATH_NOT_FOUND && GetLastError() != ERROR_ALREADY_EXISTS)
            return false;
        return true;
    }
#else
    /*
     * Adopt an existing cache directory only when it is safe:
     *   - it is a real directory (not a symlink)
     *   - it is owned by the effective uid of the current process
     *   - it has no group- or world-write bits set
     */
    bool is_dir_trusted(const std::string &dirname) {
        struct stat buf {};
        if (lstat(dirname.c_str(), &buf) != 0)
            return false;
        if (!S_ISDIR(buf.st_mode))
            return false;
        if (buf.st_uid != geteuid())
            return false;
        if ((buf.st_mode & (S_IWGRP | S_IWOTH)) != 0)
            return false;
        return true;
    }

    void init_cache_directory() {
        const char *cache_locations[5];
        cache_locations[0] = ::getenv("AZDCAP_CACHE");
        cache_locations[1] = ::getenv("XDG_CACHE_HOME");
        cache_locations[2] = ::getenv("HOME");
        cache_locations[3] = ::getenv("TMPDIR");
        cache_locations[4] = "/tmp/";

        string application_name("/.dcap-qcnl/");

        for (auto &cache_location : cache_locations) {
            if (cache_location != 0 && strcmp(cache_location, "") != 0) {
                string dirname = cache_location + application_name;
                if (is_dir_trusted(dirname)) {
                    cache_dir_ = dirname;
                    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Found existing cache directory: %s\n", dirname.c_str());
                    return;
                }
            }
        }

        for (auto &cache_location : cache_locations) {
            if (cache_location != 0 && strcmp(cache_location, "") != 0) {
                string dirname = cache_location + application_name;
                if (make_dir(dirname)) {
                    cache_dir_ = dirname;
                    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Created new cache directory: %s\n", dirname.c_str());
                    return;
                }
            }
        }
    }

    bool make_dir(const std::string &dirname) {
        struct stat buf {};
        int rc = lstat(dirname.c_str(), &buf);
        if (rc == 0) {
            /* Existing entry: only accept if it passes the trust check. */
            return is_dir_trusted(dirname);
        }

        /* 0700 restricts new cache contents to the owning uid. */
        rc = mkdir(dirname.c_str(), 0700);
        if (rc != 0) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Error creating directory '%s'. \n", dirname.c_str());
            return false;
        }

        return true;
    }
#endif
};

#endif // LOCALCACHE_H_
