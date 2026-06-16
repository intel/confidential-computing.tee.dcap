# This file is provided under a dual BSD/GPLv2 license.  When using or
# redistributing this file, you may do so under either license.
#
# GPL LICENSE SUMMARY
#
# Copyright(c) 2016-2018 Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# Contact Information:
# Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
# Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
#
# BSD LICENSE
#
# Copyright(c) 2016-2018 Intel Corporation.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

.DEFAULT_GOAL := sign


TARGET_DIR = build

ifeq ($(INTEL_SIGNED),1)
	SIGN_EXTRA := intel_signed
	TARGET_DIR = build-intel_signed
endif

TARGET := $(shell realpath $(TARGET_DIR))

CC = gcc
LD = ld
CFLAGS = -Wall -Werror -static -nostdlib -nostartfiles -fPIE -fno-stack-protector -mrdrnd
LDFLAGS = -m elf_x86_64 -z max-page-size=0x200000
INCLUDES = -I./include

ifneq ($(SIG_FILE),)
	CSS_SIG_FILE = $(shell realpath $(SIG_FILE))
endif

ifneq ($(PUBKEY_FILE),)
	CSS_PUBKEY_FILE = $(shell realpath $(PUBKEY_FILE))
endif

VERBOSE := @
ifeq ($(V),1)
	VERBOSE :=
endif

SGX_LE_SIGNING_KEY_PATH := sgx_signing_key.pem
SGX_LE_PUBLIC_KEY_PATH := sgx_public_key.pem
SGX_LE_SIGNING_MATERIAL := signing_material.bin

SIGNING_KEY_PATH := $(shell realpath $(SGX_LE_SIGNING_KEY_PATH))
PUBLIC_KEY_PATH := $(shell realpath $(SGX_LE_PUBLIC_KEY_PATH))
SIGNING_MATERIAL := $(shell realpath $(SGX_LE_SIGNING_MATERIAL))

$(SIGNING_KEY_PATH):
	$(VERBOSE) openssl genrsa -3 -out $(SIGNING_KEY_PATH) 3072

$(PUBLIC_KEY_PATH): $(SIGNING_KEY_PATH)
	$(VERBOSE) openssl rsa -in $(SIGNING_KEY_PATH) -outform PEM -pubout -out $(PUBLIC_KEY_PATH)

SGX_LE_C_OBJS := $(addprefix $(TARGET)/,main.o string.o cmac.o)
SGX_LE_S_OBJS := $(addprefix $(TARGET)/,encl_bootstrap.o)

$(TARGET):
	$(VERBOSE) mkdir $@

$(SGX_LE_C_OBJS): $(TARGET)/%.o: %.c | $(TARGET)
	$(VERBOSE) $(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

$(SGX_LE_S_OBJS): $(TARGET)/%.o: %.S | $(TARGET)
	$(VERBOSE) $(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

$(TARGET)/sgx_le.elf: sgx_le.lds $(SGX_LE_C_OBJS) $(SGX_LE_S_OBJS)
	$(VERBOSE) $(LD) $(LDFLAGS) -T $^ -o $@

$(TARGET)/sgx_le.bin: $(TARGET)/sgx_le.elf
	$(VERBOSE) objcopy --remove-section=.got.plt -O binary $< $@

$(TARGET)/sgxsign: sgxsign.c | $(TARGET)
	$(VERBOSE) $(CC) -Wall $(INCLUDES) -o $@ $< -lcrypto

$(TARGET)/bin2c: bin2c.c | $(TARGET)
	$(VERBOSE) $(CC) -Wall $(INCLUDES) -o $@ $<

sign: $(SIGNING_KEY_PATH) $(TARGET)/sgx_le.bin $(TARGET)/sgxsign $(TARGET)/bin2c
	$(VERBOSE) $(TARGET)/sgxsign sign $(SIGNING_KEY_PATH) $(TARGET)/sgx_le.bin $(TARGET)/sgx_le.ss $(SIGN_EXTRA)
	$(VERBOSE) $(TARGET)/bin2c $(TARGET)/sgx_le.bin $(TARGET)/sgx_le_blob.h sgx_le_blob
	$(VERBOSE) $(TARGET)/bin2c $(TARGET)/sgx_le.ss $(TARGET)/sgx_le_ss.h sgx_le_ss

gendata: $(TARGET)/sgx_le.bin $(TARGET)/sgxsign
	$(VERBOSE) $(TARGET)/sgxsign gendata $(TARGET)/sgx_le.bin $(SIGNING_MATERIAL) $(SIGN_EXTRA)

usesig: $(TARGET)/sgx_le.bin $(TARGET)/sgxsign $(TARGET)/bin2c
	$(VERBOSE) $(TARGET)/sgxsign usesig $(CSS_PUBKEY_FILE) $(TARGET)/sgx_le.bin $(CSS_SIG_FILE) $(TARGET)/sgx_le.ss $(SIGN_EXTRA)
	$(VERBOSE) $(TARGET)/bin2c $(TARGET)/sgx_le.bin $(TARGET)/sgx_le_blob.h sgx_le_blob
	$(VERBOSE) $(TARGET)/bin2c $(TARGET)/sgx_le.ss $(TARGET)/sgx_le_ss.h sgx_le_ss

clean:
	$(VERBOSE) rm -vrf $(TARGET) $(SIGNING_MATERIAL)
