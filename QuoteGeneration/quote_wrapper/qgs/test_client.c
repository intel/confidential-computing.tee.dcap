/*
 * Copyright(c) 2011-2026 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <sys/un.h>
#include "qgs_msg_lib.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>


static const unsigned HEADER_SIZE = 4;
#define QGS_UNIX_SOCKET_FILE "/var/run/tdx-qgs/qgs.socket"
#define VSOCK_PORT 4050

#define HEX_DUMP_SIZE 16
static void print_hex_dump(const char *title, const char *prefix_str,
                           const uint8_t *buf, uint32_t len) {
    const uint8_t *ptr = buf;
    uint32_t i, rowsize = HEX_DUMP_SIZE;

    if (!len || !buf)
        return;

    fprintf(stdout, "\t\t%s", title);

    for (i = 0; i < len; i++) {
        if (!(i % rowsize))
            fprintf(stdout, "\n%s%.8x:", prefix_str, i);
        if (ptr[i] <= 0x0f)
            fprintf(stdout, " 0%x", ptr[i]);
        else
            fprintf(stdout, " %x", ptr[i]);
    }

    fprintf(stdout, "\n");
}

static int connect_qgs_socket(void)
{
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    if (strlen(QGS_UNIX_SOCKET_FILE) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "\nUNIX socket path too long: %s\n", QGS_UNIX_SOCKET_FILE);
        return -1;
    }

    strncpy(addr.sun_path, QGS_UNIX_SOCKET_FILE, sizeof(addr.sun_path) - 1);

    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket(AF_UNIX)");
        return -1;
    }

    socklen_t addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                     strlen(addr.sun_path) + 1);
    if (connect(s, (struct sockaddr *)&addr, addr_len) < 0) {
        perror("connect(AF_UNIX)");
        close(s);
        return -1;
    }
    return s;
}

static int connect_qgs_vsock(void)
{

    int s = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (-1 == s)
    {
        fprintf(stderr, "\nsocket return 0x%x\n", s);
        return -1;
    }
    struct sockaddr_vm vm_addr;
    memset(&vm_addr, 0, sizeof(vm_addr));
    vm_addr.svm_family = AF_VSOCK;
    vm_addr.svm_reserved1 = 0;
    vm_addr.svm_port = VSOCK_PORT;
    vm_addr.svm_cid = VMADDR_CID_HOST;
    if (connect(s, (struct sockaddr *)&vm_addr, sizeof(vm_addr)))
    {
        fprintf(stderr, "\nconnect error\n");
        close(s);
        return -1;
    }
    return s;
}

static int test_raw_request(void)
{
    fprintf(stderr, "\nConnecting to unix domain socket at %s ... \n", QGS_UNIX_SOCKET_FILE);
    int s = connect_qgs_socket();
    if (s < 0) {
        fprintf(stderr, "failed\n");
        fprintf(stderr, "\nConnecting to vsock at port %d ... \n", VSOCK_PORT);
        s = connect_qgs_vsock();
        if (s < 0) {
            fprintf(stderr, "failed\n");
            return 1;
        }
    }
    fprintf(stderr, "success\n");

    uint8_t report[1024] = {0};
    report[0] = 0x81;
    ssize_t ret;
    // Write to socket
    ret = send(s, &report, sizeof(report), 0);
    if (ret != sizeof(report))
    {
        perror(NULL);
        fprintf(stderr, "\nraw request send error %ld\n", ret);
        close(s);
        return 1;
    }

    uint8_t buf[8 * 1024] = {0};
    // Read the response
    ret = recv(s, buf, 8 * 1024, 0);
    // No data excepted
    if (ret != 0) {
        perror(NULL);
        fprintf(stderr, "\nraw request recv error %ld\n", ret);
        close(s);
        return 1;
    }
    close(s);
    return 0;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    int s = -1;
    int ret = 0;

    ret = test_raw_request();
    if (0 == ret) {
        fprintf(stderr, "\nraw request success\n");
    }

    uint8_t buf[4 * 1024] = {0};
    uint32_t msg_size = 0;
    uint32_t in_msg_size = 0;
    uint32_t recieved_bytes = 0;

    uint16_t tdqe_isvsvn;
    uint16_t pce_isvsvn;
    const uint8_t *p_platform_id = NULL;
    uint32_t platform_id_size = 0;
    const uint8_t *p_cpusvn = NULL;
    uint32_t cpusvn_size = 0;

    qgs_msg_error_t qgs_msg_ret = QGS_MSG_SUCCESS;
    qgs_msg_header_t *p_header = NULL;
    uint8_t *p_req = NULL;

    qgs_msg_ret = qgs_msg_gen_get_platform_info_req(&p_req, &msg_size);
    if (QGS_MSG_SUCCESS != qgs_msg_ret) {
        fprintf(stderr, "\nqgs_msg_gen_get_platform_info_req return 0x%x\n", qgs_msg_ret);
        ret = 1;
        goto ret_point;
    }

    buf[0] = (uint8_t)((msg_size >> 24) & 0xFF);
    buf[1] = (uint8_t)((msg_size >> 16) & 0xFF);
    buf[2] = (uint8_t)((msg_size >> 8) & 0xFF);
    buf[3] = (uint8_t)(msg_size & 0xFF);

    memcpy(buf + HEADER_SIZE, p_req, msg_size);
    qgs_msg_free(p_req);

    s = connect_qgs_socket();
    if (s < 0) {
        s = connect_qgs_vsock();
        if (s < 0) {
            ret = 1;
            goto ret_point;
        }
    }

    // Write to socket
    if (HEADER_SIZE + msg_size != send(s, buf, HEADER_SIZE + msg_size, 0)) {
        fprintf(stderr, "\nsend error\n");
        ret = 1;
        goto ret_point;
    }

    // Read the response size header
    if (HEADER_SIZE != recv(s, buf, HEADER_SIZE, 0)) {
        perror(NULL);
        fprintf(stderr, "\nrecv error\n");
        ret = 1;
        goto ret_point;
    }

    // decode the size
    for (unsigned i = 0; i < HEADER_SIZE; ++i) {
        in_msg_size = in_msg_size * 256 + ((buf[i]) & 0xFF);
    }

    if (sizeof(buf) - HEADER_SIZE < in_msg_size) {
        fprintf(stderr, "\nReply message body is too big");
        ret = 1;
        goto ret_point;
    }
    while( recieved_bytes < in_msg_size) {
        int recv_ret = (int)recv(s, buf + HEADER_SIZE + recieved_bytes,
                                    in_msg_size - recieved_bytes, 0);
        if (recv_ret <= 0) {
            fprintf(stderr, "\nrecv return value <= 0");
            ret = 1;
            goto ret_point;
        }
        recieved_bytes += (uint32_t)recv_ret;
    }

    qgs_msg_ret = qgs_msg_inflate_get_platform_info_resp(buf + HEADER_SIZE, in_msg_size,
        &tdqe_isvsvn, &pce_isvsvn, &p_platform_id, &platform_id_size, &p_cpusvn, &cpusvn_size);

    if (QGS_MSG_SUCCESS != qgs_msg_ret) {
        fprintf(stderr, "\nqgs_msg_inflate_get_platform_info_resp return 0x%x\n", qgs_msg_ret);
        ret = 1;
        goto ret_point;
    }

    // We've called qgs_msg_inflate_get_platform_info_resp, the message type should be GET_PLATFORM_INFO_RESP
    p_header = (qgs_msg_header_t *)(buf + HEADER_SIZE);
    if (p_header->type != GET_PLATFORM_INFO_RESP) {
        fprintf(stderr, "\ntype in resp msg is 0x%d", p_header->type);
        ret = 1;
        goto ret_point;
    }
    if (p_header->error_code != 0) {
        fprintf(stderr, "\nerror code in resp msg is 0x%x", p_header->error_code);
        ret = 1;
        goto ret_point;
    }
    fprintf(stdout, "\nPCE_ISVSVN: %d\tTDQE_ISVSVN: %d\n", pce_isvsvn, tdqe_isvsvn);
    print_hex_dump("\n\t\tQEID\n", " ", p_platform_id, platform_id_size);
    print_hex_dump("\n\t\tCPUSVN\n", " ", p_cpusvn, cpusvn_size);
    ret = 0;

ret_point:
    if (s >= 0) {
        close(s);
    }

    return ret;
}

