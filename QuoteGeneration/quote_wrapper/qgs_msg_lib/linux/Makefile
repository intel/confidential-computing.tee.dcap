#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

######## SGX SDK Settings ########
TOP_DIR  = ../../..
SDK_NOT_REQUIRED = 1
ifeq ($(wildcard $(TOP_DIR)/buildenv.mk),)
	COMMON_FLAGS = -ffunction-sections -fdata-sections \
		-fstack-protector-strong -D_GLIBCXX_ASSERTIONS -Wall -Wextra -Werror -Winit-self -Wpointer-arith \
		-Wreturn-type -Waddress -Wsequence-point -Wformat-security -Wmissing-include-dirs -Wfloat-equal \
		-Wundef -Wshadow -Wcast-align -Wconversion -Wredundant-decls -Wimplicit-fallthrough -DITT_ARCH_IA64 \
		-fcf-protection -fstack-clash-protection

	ifdef DEBUG
		COMMON_FLAGS += -O0 -ggdb -DDEBUG -UNDEBUG -DSE_DEBUG_LEVEL=SE_TRACE_DEBUG -DDEBUG_MODE=1
	else
		COMMON_FLAGS += -O2 -UDEBUG -DNDEBUG -D_FORTIFY_SOURCE=2
	endif

	CXXFLAGS = $(COMMON_FLAGS) -Wnon-virtual-dtor -std=c++14
else
	include $(TOP_DIR)/buildenv.mk
endif

######## LIBQGS_MSG ########
SRC  := $(wildcard ../*.cpp)
OBJS := $(sort $(SRC:.cpp=.o))
LIBQGS_MSG_DEP := $(sort $(SRC:.cpp=.d))
INCLUDES := -I../inc/

LIBQGS_MSG := libqgs_msg.a
-include $(LIBQGS_MSG_DEP)

.PHONY: all
all: $(LIBQGS_MSG)

$(LIBQGS_MSG): $(OBJS)
	$(AR) rcsD $@ $^

$(OBJS): %.o:%.cpp
	$(CXX) -c $(CXXFLAGS) -g -MMD -Werror -fPIC -Wno-attributes $(INCLUDES) $< -o $@

.PHONY: clean
clean:
	@$(RM) $(OBJS) $(LIBQGS_MSG) $(LIBQGS_MSG_DEP)

.PHONY: rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all
