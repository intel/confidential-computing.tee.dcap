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
 * File: ByteSerialization.h
 *
 * Description: Endian-explicit (little-endian) serialization helpers for
 * integral values. Reading/writing raw byte buffers field-by-field avoids
 * type-punning through reinterpret_cast'ed struct overlays, which is undefined
 * behavior under the C++ strict-aliasing rule.
 */
#ifndef MP_BYTE_SERIALIZATION_H
#define MP_BYTE_SERIALIZATION_H

#include <cassert>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

namespace mp {

/**
 * Deserialize an integral value of type T from `raw` interpreting the bytes
 * as little-endian, starting at `offset`. The caller must ensure `raw` holds
 * at least `offset + sizeof(T)` bytes.
 */
template
<
    typename T,
    typename std::enable_if<std::is_integral<T>::value
                            && !std::is_same<typename std::remove_cv<T>::type, bool>::value, int>::type = 0
>
T parseBytesLE(const uint8_t *raw, size_t offset = 0)
{
    assert(raw != nullptr && "Requires raw pointer to be non nullptr");

    static_assert(CHAR_BIT == 8, "Requires 8 bit byte");

    constexpr size_t SIZE = sizeof(T);

    typename std::make_unsigned<T>::type ret{0};
    for (size_t i = 0; i < SIZE; ++i)
    {
        ret |= static_cast<typename std::make_unsigned<T>::type>(raw[offset + i]) << (i * 8);
    }

    // Reinterpret the accumulated unsigned bits as T via memcpy rather than
    // static_cast<T>(ret): for signed T an out-of-range unsigned->signed
    // conversion is implementation-defined before C++20, which would break the
    // bit-for-bit round-trip with writeBytesLE for negative (two's-complement)
    // patterns. memcpy preserves the object representation deterministically.
    T result;
    std::memcpy(&result, &ret, SIZE);
    return result;
}

/**
 * Inverse of parseBytesLE: serialize an integral value into `raw` as
 * little-endian bytes, starting at `offset`. The caller must ensure `raw`
 * has at least `offset + sizeof(T)` bytes.
 */
template
<
    typename T,
    typename std::enable_if<std::is_integral<T>::value
                            && !std::is_same<typename std::remove_cv<T>::type, bool>::value, int>::type = 0
>
void writeBytesLE(uint8_t *raw, T value, size_t offset = 0)
{
    assert(raw != nullptr && "Requires raw pointer to be non nullptr");

    static_assert(CHAR_BIT == 8, "Requires 8 bit byte");

    constexpr size_t SIZE = sizeof(T);

    for (size_t i = 0; i < SIZE; ++i)
    {
        raw[offset + i] = static_cast<uint8_t>(
            (static_cast<typename std::make_unsigned<T>::type>(value) >> (i * 8)) & 0xFF);
    }
}

} // namespace mp

#endif // #ifndef MP_BYTE_SERIALIZATION_H
