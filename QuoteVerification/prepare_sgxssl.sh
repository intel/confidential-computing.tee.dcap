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
openssl_ver_name=openssl-3.0.17
sgxssl_github_archive=https://github.com/intel/intel-sgx-ssl/archive
sgxssl_file_name=a0840d311dbf69a3ae888034ca2e607e4129a658
build_script=$sgxssl_dir/Linux/build_openssl.sh
server_url_path=https://www.openssl.org/source/
full_openssl_url=$server_url_path/$openssl_ver_name.tar.gz
full_openssl_url_old=$server_url_path/old/3.0/$openssl_ver_name.tar.gz

sgxssl_chksum=e7c4cb6c68d0262f9c5b888551952678fb27245311b755388790506b7dc785d8
openssl_chksum=dfdd77e4ea1b57ff3a6dbde6b0bdc3f31db5ac99e7fdd4eaf9e1fbb6ec2db8ce
rm -f check_sum_sgxssl.txt check_sum_openssl.txt
if [ ! -f $build_script ]; then
  wget $sgxssl_github_archive/$sgxssl_file_name.zip -P $sgxssl_dir/ || exit 1
  sha256sum $sgxssl_dir/$sgxssl_file_name.zip > $sgxssl_dir/check_sum_sgxssl.txt
  grep $sgxssl_chksum $sgxssl_dir/check_sum_sgxssl.txt
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
  grep $openssl_chksum $sgxssl_dir/check_sum_openssl.txt
  if [ $? -ne 0 ]; then
    echo "File $openssl_out_dir/$openssl_ver_name.tar.gz checksum failure"
    rm -f $openssl_out_dir/$openssl_ver_name.tar.gz
    exit -1
  fi
fi


if [ "$1" = "nobuild" ]; then
  exit 0
fi

pushd $sgxssl_dir/Linux/
if [[ "$*" == *SERVTD_ATTEST* ]];then
  make clean sgxssl_no_mitigation NO_THREADS=1 LINUX_SGX_BUILD=2 SERVTD_ATTEST=1
else
  if [[ "$*" == *FIPS* ]];then
    make clean sgxssl_no_mitigation FIPS=1
  else
    make clean sgxssl_no_mitigation
  fi
fi
popd


