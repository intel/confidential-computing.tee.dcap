#!/usr/bin/env bash
#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

top_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
sgxssl_dir=$top_dir/sgxssl
openssl_out_dir=$sgxssl_dir/openssl_source
openssl_ver_name=openssl-3.0.21
sgxssl_github_archive=https://github.com/intel/intel-sgx-ssl/archive
sgxssl_file_name=3.0_Rev5.4
build_script=$sgxssl_dir/Linux/build_openssl.sh
server_url_path=https://www.openssl.org/source
full_openssl_url=$server_url_path/$openssl_ver_name.tar.gz

sgxssl_chksum=e6891fa0e527de24d241343e593b7ccfb516bd44564415bfbee0228a82387e3e
openssl_chksum=617e29af8e421f46649484a4937e48c685e47f46488167c982f88bc4ec1d522f
rm -f "$sgxssl_dir/check_sum_sgxssl.txt" "$sgxssl_dir/check_sum_openssl.txt"
if [ ! -f "$build_script" ]; then
  wget "$sgxssl_github_archive/$sgxssl_file_name.zip" -P "$sgxssl_dir/" || exit 1
  sha256sum "$sgxssl_dir/$sgxssl_file_name.zip" > "$sgxssl_dir/check_sum_sgxssl.txt"
  if ! grep -qF "$sgxssl_chksum" "$sgxssl_dir/check_sum_sgxssl.txt"; then
    echo "File $sgxssl_dir/$sgxssl_file_name.zip checksum failure"
    rm -f "$sgxssl_dir/$sgxssl_file_name.zip"
    exit 1
  fi
  unzip -qq "$sgxssl_dir/$sgxssl_file_name.zip" -d "$sgxssl_dir/" || exit 1
  mv "$sgxssl_dir/intel-sgx-ssl-$sgxssl_file_name/"* "$sgxssl_dir/" || exit 1
  rm "$sgxssl_dir/$sgxssl_file_name.zip" || exit 1
  rm -rf "$sgxssl_dir/intel-sgx-ssl-$sgxssl_file_name" || exit 1
fi
if [[ "$*" == *SERVTD_ATTEST* ]];then
  if [ -f "$build_script" ]; then
    sed -i 's/no-idea/no-idea\ no-threads/' "$build_script"
  fi
  # shellcheck disable=SC2154 # bypass_fun_header, tls_time_source_file, test_makefile are expected from the environment
  if [ -f "$bypass_fun_header" ]; then
    sed -i '/sgxssl_gmtime_r$/a #define\ gmtime\ sgxssl_gmtime' "$bypass_fun_header"
    sed -i 's/D),\ 0/D),\ 3/' Makefile    #for test project fail single thread
    sed -i 's/__thread//' "$tls_time_source_file"
  fi

  # shellcheck disable=SC2154
  if [ -f "$test_makefile" ]; then
    sed -i 's/D),\ 0/D),\ 3/' "$test_makefile"
  fi
fi

if [ ! -f "$openssl_out_dir/$openssl_ver_name.tar.gz" ]; then
  wget "$full_openssl_url" -P "$openssl_out_dir" || exit 1
  sha256sum "$openssl_out_dir/$openssl_ver_name.tar.gz" > "$sgxssl_dir/check_sum_openssl.txt"
  if ! grep -qF "$openssl_chksum" "$sgxssl_dir/check_sum_openssl.txt"; then
    echo "File $openssl_out_dir/$openssl_ver_name.tar.gz checksum failure"
    rm -f "$openssl_out_dir/$openssl_ver_name.tar.gz"
    exit 1
  fi
fi


pushd "$sgxssl_dir/Linux/" || exit
read -ra make_jobs <<< "${MAKE_PARALLEL_JOBS:-}"
case $1 in
    "nobuild")
        ;;
    "clean")
        make "${make_jobs[@]}" clean
        ;;
    "cleanbuild")
        make "${make_jobs[@]}" clean
        ;&
    *)
        if [[ "$*" == *SERVTD_ATTEST* ]];then
            make "${make_jobs[@]}" sgxssl_no_mitigation NO_THREADS=1 LINUX_SGX_BUILD=2 SERVTD_ATTEST=1;
        else
            if [[ "$*" == *FIPS* ]];then
                make "${make_jobs[@]}" sgxssl_no_mitigation FIPS=1;
            else
                make "${make_jobs[@]}" sgxssl_no_mitigation;
            fi
        fi
        ;;
esac
popd || exit
