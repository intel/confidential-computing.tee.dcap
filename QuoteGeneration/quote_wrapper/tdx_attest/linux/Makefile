#
# Copyright (C) 2011-2022 Intel Corporation. All rights reserved.
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
#

######## Basic Settings ########
TOP_DIR  = ../../..
SDK_NOT_REQUIRED = 1
ifeq ($(wildcard $(TOP_DIR)/buildenv.mk),)
	CFLAGS ?= -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants -fstack-protector-strong -O2 \
		-D_FORTIFY_SOURCE=2 -UDEBUG -DNDEBUG -ffunction-sections -fdata-sections -Wall -Wextra -Winit-self \
		-Wpointer-arith -Wreturn-type -Waddress -Wsequence-point -Wformat-security -Wmissing-include-dirs \
		-Wfloat-equal -Wundef -Wshadow -Wcast-align -Wconversion -Wredundant-decls -DITT_ARCH_IA64 -fcf-protection
	CXXFLAGS ?= -Wnon-virtual-dtor -std=c++14 -fstack-protector-strong -O2 -D_FORTIFY_SOURCE=2 -UDEBUG -DNDEBUG \
		-ffunction-sections -fdata-sections -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type -Waddress \
		-Wsequence-point -Wformat-security -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow -Wcast-align \
		-Wconversion -Wredundant-decls -DITT_ARCH_IA64 -fcf-protection
	COMMON_LDFLAGS ?= -Wl,-z,relro,-z,now,-z,noexecstack
	BUILD_DIR ?= ../out
	SGX_MAJOR_VER ?= 1
	CP ?= cp
	MKDIR ?= mkdir
else
	include $(TOP_DIR)/buildenv.mk
endif



######## Tdx_Attest Settings ########
QGS_MSG_LFLAGS = -L../../qgs_msg_lib/linux -lqgs_msg

Tdx_Attest_C_Files := ../tdx_attest.c

Tdx_Attest_Include_Paths := -I./ -I../../qgs_msg_lib/inc

ifeq ($(V3_DRIVER), 1)
    CFLAGS += -DV3_DRIVER
endif

Tdx_Attest_C_Flags := $(CFLAGS) -g -MMD -fPIC -Wno-attributes $(Tdx_Attest_Include_Paths)

LDUFLAGS := $(COMMON_LDFLAGS)
LDUFLAGS += -Wl,--version-script=tdx_attest.lds -Wl,--gc-sections -g


Tdx_Attest_C_Objects := $(Tdx_Attest_C_Files:.c=.o)
Tdx_Attest_C_Depends := $(Tdx_Attest_C_Files:.c=.d)

Tdx_Attest_Name := libtdx_attest.so
Tdx_Attest_Name_Full := $(Tdx_Attest_Name).$(SGX_VER)
Tdx_Attest_Name_Major := $(Tdx_Attest_Name).$(SGX_MAJOR_VER)
-include $(Tdx_Attest_C_Depends)

.PHONY: all test_app
all:  install_lib

install_lib: $(Tdx_Attest_Name) | $(BUILD_DIR)
	@$(CP) $(Tdx_Attest_Name) $|/$(Tdx_Attest_Name_Full)
	@$(LN) $(Tdx_Attest_Name_Full) $|/$(Tdx_Attest_Name_Major)
	@$(LN) $(Tdx_Attest_Name_Major) $|/$(Tdx_Attest_Name)

######## Tdx_Attest Objects ########
$(Tdx_Attest_Name): $(Tdx_Attest_C_Objects)
	make -C ../../qgs_msg_lib/linux CXXFLAGS="$(CXXFLAGS)"
	$(CC) $^ -shared -shared -Wl,-soname=$@.$(SGX_MAJOR_VER) $(QGS_MSG_LFLAGS) $(LDUFLAGS) -o $@
	@echo "LINK =>  $@"

$(Tdx_Attest_C_Objects): %.o: %.c
	$(CC) $(Tdx_Attest_C_Flags) -c $(Tdx_Attest_C_Files) -o $@

test_app: $(Tdx_Attest_Name) ../test_tdx_attest.c ../tdx_attest.h
	$(CC) -I. -L./linux ../test_tdx_attest.c -L. -ltdx_attest -g -o $@

$(BUILD_DIR):
	$(MKDIR) $@

.PHONY: clean

clean:
	make -C ../../qgs_msg_lib/linux clean
	@$(RM) $(Tdx_Attest_Name) $(Tdx_Attest_C_Objects) $(Tdx_Attest_C_Depends) ./qgs test_app
	@$(RM) $(addprefix $(BUILD_DIR)/,$(Tdx_Attest_Name) $(Tdx_Attest_Name_Full) $(Tdx_Attest_Name_Major))
