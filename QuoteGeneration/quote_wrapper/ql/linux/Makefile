#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

######## SGX SDK Settings ########
TOP_DIR = ../../..
include $(TOP_DIR)/buildenv.mk

Quote_Library_Dir := ../../quote/linux
Quote_Library := $(Quote_Library_Dir)/libsgx_qe3_logic.so

PCE_Library_Dir := ../../../pce_wrapper/linux/
PCE_Library := $(PCE_Library_Dir)/libsgx_pce_logic.so

######## SGX QL Library Settings ########
vpath %.c $(COMMON_DIR)/src

QL_Lib_Cpp_Files := $(wildcard ../*.cpp)
QL_Lib_C_Files := se_trace.c se_thread.c

QL_Lib_Include_Paths := -I../../common/inc -I./ -I$(SGX_SDK)/include -I../../../common/inc/internal
QL_Lib_Include_Paths += -I../../quote/inc -I../../../pce_wrapper/inc -I../inc

QL_Lib_C_Flags := $(COMMON_FLAGS) -g -fPIC -Werror -Wno-attributes $(QL_Lib_Include_Paths)

LDUFLAGS:= -pthread $(COMMON_LDFLAGS)
LDUFLAGS += -Wl,--version-script=dcap_ql_wrapper.lds -Wl,--gc-sections

QL_Lib_Cpp_Flags := $(QL_Lib_C_Flags)
QL_Lib_Link_Flags := $(SGX_COMMON_FLAGS) -g -L$(Quote_Library_Dir) -lsgx_qe3_logic -L$(PCE_Library_Dir) -lsgx_pce_logic -L$(TOP_DIR)/build/linux -L$(SGX_SDK)/lib64 -lpthread -ldl

QL_Lib_Cpp_Flags += -DDISABLE_TRACE
QL_Lib_Link_Flags += -DDISABLE_TRACE

QL_Lib_Cpp_Objects := $(QL_Lib_Cpp_Files:.cpp=.o)
QL_Lib_C_Objects := $(QL_Lib_C_Files:.c=.o)

QL_Lib_Name_Dynamic := libsgx_dcap_ql.so
QL_Lib_Name_Dynamic_Full := $(QL_Lib_Name_Dynamic).$(call get_full_version,QUOTE_LOADER_VERSION)
QL_Lib_Name_Dynamic_Major := $(QL_Lib_Name_Dynamic).$(call get_major_version,QUOTE_LOADER_VERSION)

.PHONY: all run

all: install_lib

install_lib: $(QL_Lib_Name_Dynamic) | $(BUILD_DIR)
	@$(CP) $(QL_Lib_Name_Dynamic) $|/$(QL_Lib_Name_Dynamic_Full)
	@$(LN) $(QL_Lib_Name_Dynamic_Full) $|/$(QL_Lib_Name_Dynamic_Major)
	@$(LN) $(QL_Lib_Name_Dynamic_Major) $|/$(QL_Lib_Name_Dynamic)

run: all

######## QL Library Objects ########

$(QL_Lib_C_Objects): %.o: %.c
	@$(CC) $(QL_Lib_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(QL_Lib_Cpp_Objects): %.o: %.cpp
	@$(CXX) $(QL_Lib_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(QL_Lib_Name_Dynamic): $(QL_Lib_Cpp_Objects) $(QL_Lib_C_Objects) $(PCE_Library) $(Quote_Library)
	$(CXX) $(CXXFLAGS) $(QL_Lib_Cpp_Objects) $(QL_Lib_C_Objects) -shared -Wl,-soname=$(QL_Lib_Name_Dynamic_Major) $(LDUFLAGS) $(QL_Lib_Link_Flags) -o $@

$(Quote_Library): force_look
	@make -C $(Quote_Library_Dir)

$(PCE_Library): force_look
	@make -C $(PCE_Library_Dir)

force_look:
	true

.PHONY: clean

clean:
	@$(RM) .config_* $(QL_Lib_Name) $(QL_Lib_Cpp_Objects) $(QL_Lib_Cpp_Deps) $(QL_Lib_Name_Dynamic) \
		$(addprefix $(BUILD_DIR)/,$(QL_Lib_Name_Dynamic) $(QL_Lib_Name_Dynamic_Full) $(QL_Lib_Name_Dynamic_Major))
	@make -C $(Quote_Library_Dir) clean
	@make -C $(PCE_Library_Dir)   clean
