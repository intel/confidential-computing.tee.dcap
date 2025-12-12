/*
 * Copyright(c) 2011-2025 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef QCNLUTIL_H_
#define QCNLUTIL_H_
#pragma once

#include <string>
#include <unordered_map>
#include <cstdint>

using namespace std;

bool convert_ascii_to_value(uint8_t in, uint8_t &val);
uint8_t convert_value_to_ascii(uint8_t in);
bool hex_string_to_byte_array(const uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size);
bool byte_array_to_hex_string(const uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size);
string unescape(const string &src);
bool concat_string_with_hex_buf(string &url, const uint8_t *ba, const uint32_t ba_size);
bool req_body_append_para(string &req_body, const string &para_name, const uint8_t *para, const uint32_t para_size);
void http_header_to_map(const char *resp_header, uint32_t header_size, unordered_map<string, string> &header_map);
bool is_collateral_service_pcs();
string sha256(const void *data, size_t data_size);

#endif
