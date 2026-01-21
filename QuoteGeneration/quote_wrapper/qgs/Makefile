#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

######## SGX SDK Settings ########
TOP_DIR  = ../..
include $(TOP_DIR)/buildenv.mk

QGS_SRCS = se_trace.c server_main.cpp qgs_server.cpp qgs_log.cpp qgs_ql_logic.cpp
QGS_OBJS = $(patsubst %.c,%.o,$(patsubst %.cc,%.o,$(patsubst %.cpp,%.o,$(QGS_SRCS))))

QGS_INC = -I$(SGX_SDK)/include \
		  -I$(COMMON_DIR)/inc/internal \
		  -I$(TOP_DIR)/qpl/inc \
		  -I$(TOP_DIR)/quote_wrapper/tdx_quote/inc \
		  -I$(TOP_DIR)/quote_wrapper/qgs_msg_lib/inc
QGS_CFLAGS = -g -MMD -Werror $(CFLAGS) $(QGS_INC)
QGS_CXXFLAGS = -g -MMD -Werror $(CXXFLAGS) $(QGS_INC)
ifeq ($(CC_NO_LESS_THAN_8), 1)
    QGS_CFLAGS += -fcf-protection=none
    QGS_CXXFLAGS += -fcf-protection=none
endif

DEPENDS = ${QGS_OBJS test_client.o:.o=.d}

# SGX related libraries
QGS_LFLAGS = -L$(TOP_DIR)/build/linux -lsgx_tdx_logic -lsgx_pce_logic -ldl \
             -L$(SGX_SDK)/lib64 -lsgx_urts -g
# add boost_system for link
QGS_LFLAGS += -lboost_system -lboost_thread -lpthread
# add qgs_msg_lib for link
QGS_LFLAGS += -L../qgs_msg_lib/linux -lqgs_msg

vpath %.c $(COMMON_DIR)/src

-include ${DEPENDS}

all: qgs test_client

qgs: $(QGS_OBJS)
	make -C ../qgs_msg_lib/linux
	make -C ../tdx_quote/linux
	$(CXX) -o $@ $^ $(COMMON_LDFLAGS) $(QGS_LFLAGS)

test_client: test_client.o
	$(CC) -o $@ $^ -L../qgs_msg_lib/linux -lqgs_msg

%.o: %.cpp
	$(CXX) -c $(QGS_CXXFLAGS) $<

%.o: %.c
	$(CC) -c $(QGS_CFLAGS) $<

clean:
	make -C ../qgs_msg_lib/linux clean
	make -C ../tdx_quote/linux clean
	rm -f *.d
	rm -f *.o
	rm -f qgs
