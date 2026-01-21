#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

include ../../buildenv.mk

INCLUDE += -I. -I../inc
INCLUDE += -I$(SGX_SDK)/include         \
           -I$(COMMON_DIR)/inc/internal \
           -I$(COMMON_DIR)/inc/internal/linux

INCLUDE += -I$(ROOT_DIR)/../ae/dep/common \
           -I$(ROOT_DIR)/../ae/dep/inc    \
           -I$(ROOT_DIR)/../ae/dep/inc/internal

CXXFLAGS += -fPIC -Werror -g
CFLAGS += -fPIC -Werror -g
Link_Flags := $(SGX_COMMON_CFLAGS) -L$(ROOT_DIR)/build/linux -L$(SGX_SDK)/lib64 -lsgx_urts -lpthread -ldl

vpath %.cpp ..
vpath %.c $(COMMON_DIR)/src

pce_wrapper.o: pce_u.c

pce_u.c: ${ROOT_DIR}/../ae/dep/pce/pce.edl
	@$(SGX_EDGER8R) --untrusted --untrusted-dir . $<

C_SRC := pce_u.c se_trace.c se_thread.c

SRC := pce_wrapper.cpp

OBJ := $(C_SRC:.c=.o) $(SRC:.cpp=.o)

LDUFLAGS:= -pthread $(COMMON_LDFLAGS)
LDUFLAGS += -Wl,--version-script=pce_wrapper.lds -Wl,--gc-sections

PCE_WRAPPER := libsgx_pce_logic.so
PCE_WRAPPER_STATIC := libsgx_pce_logic.a
PCE_WRAPPER_FULL := $(PCE_WRAPPER).$(call get_full_version,PCE_WRAPPER_VERSION)
PCE_WRAPPER_MAJOR := $(PCE_WRAPPER).$(call get_major_version,PCE_WRAPPER_VERSION)

.PHONY: all
all: install_lib
 
.PHONY: install_lib
install_lib: $(PCE_WRAPPER) $(PCE_WRAPPER_STATIC) | $(BUILD_DIR)
	@$(CP) $(PCE_WRAPPER) $|/$(PCE_WRAPPER_FULL)
	@$(LN) $(PCE_WRAPPER_FULL) $|/$(PCE_WRAPPER_MAJOR)
	@$(LN) $(PCE_WRAPPER_MAJOR) $|/$(PCE_WRAPPER)

$(PCE_WRAPPER): $(OBJ)
	$(CXX) $(CXXFLAGS) $(OBJ) -shared $(LDUFLAGS) $(Link_Flags) \
	-Wl,-soname=$(PCE_WRAPPER_MAJOR) -o $@

$(PCE_WRAPPER_STATIC): $(OBJ)
	$(AR) rcsD $@ $^

%.o :%.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDE) -c $< -o $@
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

$(BUILD_DIR):
	@$(MKDIR) $@

.PHONY: clean
clean:
	@$(RM) $(OBJ) *_u.h *_u.c
	@$(RM) $(PCE_WRAPPER) $(PCE_WRAPPER_STATIC) \
		$(addprefix $(BUILD_DIR)/,$(PCE_WRAPPER) $(PCE_WRAPPER_FULL) $(PCE_WRAPPER_MAJOR))

.PHONY: rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all
