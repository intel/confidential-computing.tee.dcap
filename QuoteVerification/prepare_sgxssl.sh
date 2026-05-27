#!/usr/bin/env bash
#
# Copyright(c) 2011-2025 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

ARG1=${1:-build}
top_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
sgxssl_dir=$top_dir/sgxssl
openssl_out_dir=$sgxssl_dir/openssl_source
openssl_ver_name=openssl-3.0.20
sgxssl_github_archive=https://github.com/intel/intel-sgx-ssl/archive
sgxssl_file_name=3.0_Rev5.3
build_script=$sgxssl_dir/Linux/build_openssl.sh
server_url_path=https://www.openssl.org/source/
full_openssl_url=$server_url_path/$openssl_ver_name.tar.gz
full_openssl_url_old=$server_url_path/old/3.0/$openssl_ver_name.tar.gz

sgxssl_chksum=0ac906a0ce5cc7f6ddb9f9d8acb9d2ab1aeff98a0d105f3b06bf4b446068d18b
openssl_chksum=c80a01dfc70ece4dc21168932c37739042d404d46ccc81a5986dd75314ecda6f
rm -f check_sum_sgxssl.txt check_sum_openssl.txt
if [ ! -f $build_script ]; then
  wget $sgxssl_github_archive/$sgxssl_file_name.zip -P $sgxssl_dir/ || exit 1
  sha256sum $sgxssl_dir/$sgxssl_file_name.zip > $sgxssl_dir/check_sum_sgxssl.txt
  grep -i $sgxssl_chksum $sgxssl_dir/check_sum_sgxssl.txt
  if [ $? -ne 0 ]; then
    echo "File $sgxssl_dir/$sgxssl_file_name.zip checksum failure"
    rm -f $sgxssl_dir/$sgxssl_file_name.zip
    exit -1
  fi
  unzip -qq $sgxssl_dir/$sgxssl_file_name.zip -d $sgxssl_dir/ || exit 1
  mv $sgxssl_dir/intel-sgx-ssl-$sgxssl_file_name/* $sgxssl_dir/ || exit 1
  rm $sgxssl_dir/$sgxssl_file_name.zip || exit 1
  rm -rf $sgxssl_dir/intel-sgx-ssl-$sgxssl_file_name || exit 1
fi
if [[ "$*" == *SERVTD_ATTEST* ]];then
  if [ -f $build_script ]; then
    sed -i 's/no-idea/no-idea\ no-threads/' $build_script
  fi
  if [ -f $bypass_fun_header ]; then
    sed -i '/sgxssl_gmtime_r$/a #define\ gmtime\ sgxssl_gmtime' $bypass_fun_header
    sed -i 's/D),\ 0/D),\ 3/' Makefile    #for test project fail sigle thread
    sed -i 's/__thread//' $tls_time_source_file
  fi

  if [ -f $test_makefile ]; then
    sed -i 's/D),\ 0/D),\ 3/' $test_makefile
  fi
fi

if [ ! -f $openssl_out_dir/$openssl_ver_name.tar.gz ]; then
  wget $full_openssl_url -P $openssl_out_dir || exit 1
  sha256sum $openssl_out_dir/$openssl_ver_name.tar.gz > $sgxssl_dir/check_sum_openssl.txt
  grep -i $openssl_chksum $sgxssl_dir/check_sum_openssl.txt
  if [ $? -ne 0 ]; then
    echo "File $openssl_out_dir/$openssl_ver_name.tar.gz checksum failure"
    rm -f $openssl_out_dir/$openssl_ver_name.tar.gz
    exit -1
  fi
fi


pushd $sgxssl_dir/Linux/
case $1 in
    "nobuild")
        ;;
    "clean")
        make $MAKE_PARALLEL_JOBS clean
        ;;
    "cleanbuild")
        make $MAKE_PARALLEL_JOBS clean
        ;&
    *)
        if [[ "$*" == *SERVTD_ATTEST* ]];then
            make $MAKE_PARALLEL_JOBS sgxssl_no_mitigation NO_THREADS=1 LINUX_SGX_BUILD=2 SERVTD_ATTEST=1;
        else
            if [[ "$*" == *FIPS* ]];then
                make $MAKE_PARALLEL_JOBS sgxssl_no_mitigation FIPS=1;
            else
                make $MAKE_PARALLEL_JOBS sgxssl_no_mitigation;
            fi
        fi
        ;;
esac
popd


