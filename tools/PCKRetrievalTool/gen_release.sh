#!/usr/bin/env bash
#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

SCRIPT_DIR=$(dirname "$0")
ROOT_DIR="${SCRIPT_DIR}/../../"

SGX_VERSION=$(awk '/STRFILEVER/ {print $3}' ${ROOT_DIR}/QuoteGeneration/common/inc/internal/se_version.h|sed 's/^\"\(.*\)\"$/\1/')


rel_dir_base=PCKIDRetrievalTool_v$SGX_VERSION
rel_dir_name=$rel_dir_base${1:-}

rm -rf "${rel_dir_base}"*
make clean
make STANDALONE=1

mkdir "${rel_dir_name}"
cp PCKIDRetrievalTool "${rel_dir_name}"
cp network_setting.conf "${rel_dir_name}"
cp "../../QuoteGeneration/psw/ae/data/prebuilt/libsgx_pce.signed.so" "${rel_dir_name}/libsgx_pce.signed.so.1"
cp "../../QuoteGeneration/psw/ae/data/prebuilt/libsgx_id_enclave.signed.so" "${rel_dir_name}/libsgx_id_enclave.signed.so.1"
cp "../SGXPlatformRegistration/build/release/lib64/libmpa_uefi.so" "${rel_dir_name}/libmpa_uefi.so.1"
cp "../../../../sdk/build/linux/libsgx_enclave_common.so" "${rel_dir_name}/libsgx_enclave_common.so.1"
cp "../../../../sdk/build/linux/libsgx_urts.so" "${rel_dir_name}/libsgx_urts.so"
cp README_standalone.txt "${rel_dir_name}/README.txt"
cp License.txt "${rel_dir_name}"

tar cvpzf "${rel_dir_name}.tar.gz" "${rel_dir_name}"

exit 0

