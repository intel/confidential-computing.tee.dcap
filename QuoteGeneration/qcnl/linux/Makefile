#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

######## SGX SDK Settings ########
TOP_DIR = ../..
include $(TOP_DIR)/buildenv.mk
PREBUILD_OPENSSL_PATH = ../../../prebuilt/openssl

######## SGX CNL Library Settings ########

CNL_Lib_Cpp_Files := $(wildcard *.cpp ../*.cpp)
CNL_Lib_C_Files := $(wildcard *.c ../*.c) ../../common/src/se_thread.c

######## Include path -- Don't forget to update AESM CMakefile ########
CNL_Lib_Include_Paths := -I../../quote_wrapper/common/inc       \
                         -I../inc -I$(SGX_SDK)/include          \
                         -I../../common/inc/internal            \
                         -I../../pce_wrapper/inc                \
                         -I../../../QuoteVerification/QVL/Src/ThirdParty/rapidjson/include/rapidjson	\
                         -I../../../tools/PCKCertSelection/include \
                         -I$(PREBUILD_OPENSSL_PATH)/inc

CNL_Lib_C_Flags := $(COMMON_FLAGS) -g -fPIC -Werror -Wno-attributes $(CNL_Lib_Include_Paths)

LDUFLAGS:= -pthread $(COMMON_LDFLAGS)
LDUFLAGS += -Wl,--version-script=sgx_default_qcnl.lds -Wl,--gc-sections

CNL_Lib_Cpp_Flags := $(CNL_Lib_C_Flags)

ifdef SELF_SIGNED_CERT
CNL_Lib_Cpp_Flags+= -DSELF_SIGNED_CERT
endif

CNL_Lib_Link_Flags := $(SGX_COMMON_FLAGS) -g -L$(TOP_DIR)/build/linux -L$(SGX_SDK)/lib64 \
		-lpthread -ldl ../../../tools/PCKCertSelection/static_out/libPCKCertSelection.a
 
ifndef DEBUG
CNL_Lib_Cpp_Flags += -DDISABLE_TRACE
endif

CNL_Lib_Cpp_Objects := $(CNL_Lib_Cpp_Files:.cpp=.o)
CNL_Lib_C_Objects := $(CNL_Lib_C_Files:.c=.o)
CNL_Lib_Cpp_Deps := $(CNL_Lib_Cpp_Objects:%.o=%.d)
PCK_Selection_Cpp_Objects := $(wildcard ../../../tools/PCKCertSelection/static_out/*.o)

CNL_Lib_Name := libsgx_default_qcnl_wrapper
CNL_Lib_Name_Dynamic := $(CNL_Lib_Name).so
CNL_Lib_Name_Dynamic_Full := $(CNL_Lib_Name_Dynamic).$(SGX_VER)
CNL_Lib_Name_Dynamic_Major := $(CNL_Lib_Name_Dynamic).$(SGX_MAJOR_VER)
CNL_Lib_Name_Static := $(CNL_Lib_Name).a
PCK_Selection_Lib_Static := PCKCertSelection


.PHONY: all run

all: install_lib

install_lib: $(CNL_Lib_Name_Dynamic) | $(BUILD_DIR)
	@$(CP) $(CNL_Lib_Name_Dynamic) $|/$(CNL_Lib_Name_Dynamic_Full)
	@$(LN) $(CNL_Lib_Name_Dynamic_Full) $|/$(CNL_Lib_Name_Dynamic_Major)
	@$(LN) $(CNL_Lib_Name_Dynamic_Major) $|/$(CNL_Lib_Name_Dynamic)

ifeq ($(GEN_STATIC),1)
	@$(MAKE) $(CNL_Lib_Name_Static)
	@$(CP) $(CNL_Lib_Name_Static) $|
endif

run: all

######## CNL Library Objects ########

-include $(CNL_Lib_Cpp_Deps)

$(CNL_Lib_Cpp_Objects): %.o: %.cpp
	@$(CXX) $(CNL_Lib_Cpp_Flags) -MMD -c $< -o $@
	@echo "CXX  <=  $<"

$(CNL_Lib_C_Objects): %.o: %.c
	@$(CC) $(CNL_Lib_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(CNL_Lib_Name_Dynamic): $(CNL_Lib_Cpp_Objects) $(CNL_Lib_C_Objects) $(PCK_Selection_Lib_Static)
	$(CXX) $(CXXFLAGS) $(CNL_Lib_Cpp_Objects) $(CNL_Lib_C_Objects) -shared -Wl,-soname=$(CNL_Lib_Name_Dynamic_Major) $(LDUFLAGS) $(CNL_Lib_Link_Flags) -o $@

$(CNL_Lib_Name_Static): $(CNL_Lib_Cpp_Objects) $(CNL_Lib_C_Objects) $(PCK_Selection_Lib_Static)
	$(AR) rsD $(CNL_Lib_Name_Static) $(CNL_Lib_Cpp_Objects) $(CNL_Lib_C_Objects) $(PCK_Selection_Cpp_Objects)

$(PCK_Selection_Lib_Static):
	make -C ../../../tools/PCKCertSelection/PCKCertSelectionLib -f Makefile.static_lib
force_look:
	true

$(BUILD_DIR):
	@$(MKDIR) $@

.PHONY: clean

clean:
	@$(RM) .config_* $(CNL_Lib_Name) $(CNL_Lib_Cpp_Objects) $(CNL_Lib_Cpp_Deps) $(CNL_Lib_Name_Dynamic) $(CNL_Lib_Name_Static)
	@$(RM) $(addprefix $(BUILD_DIR)/,$(CNL_Lib_Name_Dynamic) $(CNL_Lib_Name_Dynamic_Full) $(CNL_Lib_Name_Dynamic_Major))
	make -C ../../../tools/PCKCertSelection/PCKCertSelectionLib -f Makefile.static_lib clean


