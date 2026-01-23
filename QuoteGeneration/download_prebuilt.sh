#!/usr/bin/env bash
#
# Copyright(c) 2011-2025 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

top_dir=`dirname $0`
out_dir=$top_dir
ae_file_name=prebuilt_dcap_1.25.tar.gz
checksum_file=SHA256SUM_prebuilt_dcap_1.25.cfg
server_url_path=https://download.01.org/intel-sgx/sgx-dcap/1.25/linux/
server_ae_url=$server_url_path/$ae_file_name
server_checksum_url=$server_url_path/$checksum_file

rm -rf $out_dir/$ae_file_name
wget $server_ae_url -P $out_dir
if [ $? -ne 0 ]; then
    echo "Fail to download file $server_ae_url"
    exit -1
fi

rm -f $out_dir/$checksum_file
wget $server_checksum_url -P $out_dir
if [ $? -ne 0 ]; then
    echo "Fail to download file $server_checksum_url"
    exit -1
fi

pushd $out_dir

sha256sum -c $checksum_file
if [ $? -ne 0 ]; then
    echo "Checksum verification failure"
    exit -1
fi

tar -zxf $ae_file_name
cp -f -r prebuilt ..
rm -f -r prebuilt
rm -f $ae_file_name
rm -f $checksum_file

popd
