#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

######## Basic Settings ########
TOP_DIR  = ../../..
SDK_NOT_REQUIRED = 1
ifeq ($(wildcard $(TOP_DIR)/buildenv.mk),)
	COMMON_FLAGS = -ffunction-sections -fdata-sections \
	-fstack-protector-strong -D_GLIBCXX_ASSERTIONS -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
    -Waddress -Wsequence-point -Wformat-security -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
    -Wcast-align -Wconversion -Wredundant-decls -Wimplicit-fallthrough -DITT_ARCH_IA64 -fcf-protection \
	-fstack-clash-protection

	CC_VERSION := $(shell $(CC) -dumpversion)
	CC_VERSION_MAJOR := $(shell echo $(CC_VERSION) | cut -f1 -d.)
	CC_VERSION_MINOR := $(shell echo $(CC_VERSION) | cut -f2 -d.)
	CC_NO_LESS_THAN_12 := $(shell [ $(CC_VERSION_MAJOR) -ge 12 ] && echo 1 || echo 0)

	ifeq ($(CC_NO_LESS_THAN_12), 1)
		FORTIFY_SOURCE_VAL:= 3
	else
		FORTIFY_SOURCE_VAL:= 2
	endif

	ifdef DEBUG
		COMMON_FLAGS += -O0 -ggdb -DDEBUG -UNDEBUG -DSE_DEBUG_LEVEL=SE_TRACE_DEBUG -DDEBUG_MODE=1
	else
		COMMON_FLAGS += -O2 -g -UDEBUG -DNDEBUG -D_FORTIFY_SOURCE=$(FORTIFY_SOURCE_VAL)
	endif

	CFLAGS = $(COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
	CXXFLAGS = $(COMMON_FLAGS) -Wnon-virtual-dtor -std=c++14

	COMMON_LDFLAGS ?= -Wl,-z,relro,-z,now,-z,noexecstack
	BUILD_DIR ?= ../out
	SGX_VER ?= 1.0
	SGX_MAJOR_VER ?= 1
	CP ?= cp
	MKDIR ?= mkdir
	LN ?= ln -sf
else
	include $(TOP_DIR)/buildenv.mk
endif

CFLAGS += -fPIC -Werror
CXXFLAGS += -fPIC -Werror

######## Tdx_Attest Settings ########
QGS_MSG_LFLAGS = -L../../qgs_msg_lib/linux -lqgs_msg

Tdx_Attest_C_Files := ../tdx_attest.c

Tdx_Attest_Include_Paths := -I./ -I../../qgs_msg_lib/inc

ifeq ($(V3_DRIVER), 1)
    CFLAGS += -DV3_DRIVER
endif

Tdx_Attest_C_Flags := $(CFLAGS) -MMD -Wno-attributes $(Tdx_Attest_Include_Paths)

LDUFLAGS := $(COMMON_LDFLAGS)
LDUFLAGS += -Wl,--version-script=tdx_attest.lds -Wl,--gc-sections


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
	$(CC) $^ -shared -Wl,-soname=$@.$(SGX_MAJOR_VER) $(QGS_MSG_LFLAGS) $(LDUFLAGS) -o $@
	@echo "LINK =>  $@"

$(Tdx_Attest_C_Objects): %.o: %.c
	$(CC) $(Tdx_Attest_C_Flags) -c $(Tdx_Attest_C_Files) -o $@

test_app: $(Tdx_Attest_Name) ../test_tdx_attest.c ../tdx_attest.h
	$(CC) -I. -L./linux ../test_tdx_attest.c -L. -ltdx_attest -o $@

$(BUILD_DIR):
	$(MKDIR) $@

.PHONY: clean

clean:
	make -C ../../qgs_msg_lib/linux clean
	@$(RM) $(Tdx_Attest_Name) $(Tdx_Attest_C_Objects) $(Tdx_Attest_C_Depends) ./qgs test_app
	@$(RM) $(addprefix $(BUILD_DIR)/,$(Tdx_Attest_Name) $(Tdx_Attest_Name_Full) $(Tdx_Attest_Name_Major))
