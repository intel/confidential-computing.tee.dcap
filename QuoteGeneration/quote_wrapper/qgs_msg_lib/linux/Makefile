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

######## SGX SDK Settings ########
TOP_DIR  = ../../..
SDK_NOT_REQUIRED = 1
ifeq ($(wildcard $(TOP_DIR)/buildenv.mk),)
	CXXFLAGS ?= -Wnon-virtual-dtor -std=c++14 -fstack-protector-strong -O2 -D_FORTIFY_SOURCE=2 -UDEBUG -DNDEBUG \
		-ffunction-sections -fdata-sections -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type -Waddress \
		-Wsequence-point -Wformat-security -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow -Wcast-align \
		-Wconversion -Wredundant-decls -DITT_ARCH_IA64 -fcf-protection
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
	$(CXX) -c $(CXXFLAGS) -g -MMD -fPIC -Wno-attributes $(INCLUDES) $< -o $@

.PHONY: clean
clean:
	@$(RM) $(OBJS) $(LIBQGS_MSG) $(LIBQGS_MSG_DEP)

.PHONY: rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all
