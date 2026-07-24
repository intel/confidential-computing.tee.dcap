/*
 * Copyright(c) 2011-2026 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <sgx_quote_5.h>
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

static int read_exact_file(const char *path, uint8_t *buf, size_t size)
{
    FILE *file = fopen(path, "rb");
    size_t bytes_read = 0;
    int ret = 0;

    if (!file) {
        fprintf(stderr, "\nfailed to open %s\n", path);
        return 1;
    }

    bytes_read = fread(buf, 1, size, file);
    if (bytes_read != size) {
        fprintf(stderr, "\n%s size mismatch: expected %zu bytes, read %zu bytes\n",
                path, size, bytes_read);
        ret = 1;
        goto ret_point;
    }

    if (fgetc(file) != EOF) {
        fprintf(stderr, "\n%s size mismatch: file is larger than %zu bytes\n", path, size);
        ret = 1;
    }

ret_point:
    fclose(file);
    return ret;
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

int test_get_quote_mig_request(void)
{
    int s = -1;
    int ret = 0;
    uint8_t buf[16 * 1024] = {0};
    uint8_t report[sizeof(sgx_report2_t)] = {0};
    uint32_t msg_size = 0;
    uint32_t in_msg_size = 0;
    uint32_t received_bytes = 0;
    uint8_t *p_req = NULL;
    qgs_msg_header_t *p_header = NULL;
    qgs_msg_error_t qgs_msg_ret = QGS_MSG_SUCCESS;
    const uint8_t *p_selected_id = NULL;
    uint32_t selected_id_size = 0;
    const uint8_t *p_quote = NULL;
    uint32_t quote_size = 0;
    tdx_servtd_ext_t servtd_ext_data = {0};
    FILE *fptr = NULL;

    if (read_exact_file("migReport.dat", report, sizeof(report))) {
        ret = 1;
        goto ret_point;
    }

    if (read_exact_file("migStruct.dat", (uint8_t *)&servtd_ext_data, sizeof(servtd_ext_data))) {
        ret = 1;
        goto ret_point;
    }

    qgs_msg_ret = qgs_msg_gen_get_quote_mig_req(report,
                                                 sizeof(report),
                                                 (const uint8_t *)&servtd_ext_data,
                                                 sizeof(servtd_ext_data),
                                                 NULL,
                                                 0,
                                                 &p_req,
                                                 &msg_size);
    if (QGS_MSG_SUCCESS != qgs_msg_ret) {
        fprintf(stderr, "\nqgs_msg_gen_get_quote_mig_req return 0x%x\n", qgs_msg_ret);
        ret = 1;
        goto ret_point;
    }

    if (msg_size + HEADER_SIZE > sizeof(buf)) {
        fprintf(stderr, "\nrequest size too big: %u\n", msg_size);
        ret = 1;
        goto ret_point;
    }

    buf[0] = (uint8_t)((msg_size >> 24) & 0xFF);
    buf[1] = (uint8_t)((msg_size >> 16) & 0xFF);
    buf[2] = (uint8_t)((msg_size >> 8) & 0xFF);
    buf[3] = (uint8_t)(msg_size & 0xFF);

    memcpy(buf + HEADER_SIZE, p_req, msg_size);
    qgs_msg_free(p_req);
    p_req = NULL;

    s = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (-1 == s) {
        fprintf(stderr, "\nsocket return 0x%x\n", s);
        ret = 1;
        goto ret_point;
    }

    struct sockaddr_vm vm_addr;
    memset(&vm_addr, 0, sizeof(vm_addr));
    vm_addr.svm_family = AF_VSOCK;
    vm_addr.svm_reserved1 = 0;
    vm_addr.svm_port = 4050;
    vm_addr.svm_cid = VMADDR_CID_HOST;
    if (connect(s, (struct sockaddr *)&vm_addr, sizeof(vm_addr))) {
        fprintf(stderr, "\nconnect error\n");
        ret = 1;
        goto ret_point;
    }

    if (HEADER_SIZE + msg_size != send(s, buf, HEADER_SIZE + msg_size, 0)) {
        fprintf(stderr, "\nsend error\n");
        ret = 1;
        goto ret_point;
    }

    if (HEADER_SIZE != recv(s, buf, HEADER_SIZE, 0)) {
        perror(NULL);
        fprintf(stderr, "\nrecv error\n");
        ret = 1;
        goto ret_point;
    }

    for (unsigned i = 0; i < HEADER_SIZE; ++i) {
        in_msg_size = in_msg_size * 256 + (buf[i] & 0xFFu);
    }

    if (sizeof(buf) - HEADER_SIZE < in_msg_size) {
        fprintf(stderr, "\nReply message body is too big");
        ret = 1;
        goto ret_point;
    }

    while (received_bytes < in_msg_size) {
        int recv_ret = (int)recv(s, buf + HEADER_SIZE + received_bytes,
                                 in_msg_size - received_bytes, 0);
        if (recv_ret <= 0) {
            if (recv_ret == 0) {
                fprintf(stderr, "\npeer closed connection\n");
            } else {
                perror(NULL);
                fprintf(stderr, "\nrecv return value < 0");
            }
            ret = 1;
            goto ret_point;
        }
        received_bytes += (uint32_t)recv_ret;
    }

    qgs_msg_ret = qgs_msg_inflate_get_quote_resp(buf + HEADER_SIZE,
                                                 in_msg_size,
                                                 &p_selected_id,
                                                 &selected_id_size,
                                                 &p_quote,
                                                 &quote_size);
    if (QGS_MSG_SUCCESS != qgs_msg_ret) {
        fprintf(stderr, "\nqgs_msg_inflate_get_quote_resp return 0x%x\n", qgs_msg_ret);
        ret = 1;
        goto ret_point;
    }

    p_header = (qgs_msg_header_t *)(buf + HEADER_SIZE);
    if (p_header->type != GET_QUOTE_RESP) {
        fprintf(stderr, "\ntype in resp msg is 0x%d", p_header->type);
        ret = 1;
        goto ret_point;
    }

    fprintf(stdout, "\nGET_QUOTE_MIG_REQ response error code: 0x%x\n", p_header->error_code);
    if (selected_id_size != 0) {
        print_hex_dump("\n\t\tSelected ID\n", " ", p_selected_id, selected_id_size);
    }
    if (quote_size != 0) {
        print_hex_dump("\n\t\tQuote\n", " ", p_quote, quote_size);
    }
    fptr = fopen("quote.dat", "wb");
    if (fptr) {
        fwrite(p_quote, quote_size, 1, fptr);
        fclose(fptr);
    }
    fprintf(stdout, "\nWrote TD Quote to quote.dat\n");

ret_point:
    qgs_msg_free(p_req);
    if (s >= 0) {
        close(s);
    }
    return ret;
}


int main(int argc, char *argv[])
{
    if (argc > 1 && strcmp(argv[1], "mig") == 0) {
        return test_get_quote_mig_request();
    }

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
    uint32_t received_bytes = 0;

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
    while( received_bytes < in_msg_size) {
        int recv_ret = (int)recv(s, buf + HEADER_SIZE + received_bytes,
                                    in_msg_size - received_bytes, 0);
        if (recv_ret <= 0) {
            if (recv_ret == 0) {
                fprintf(stderr, "\npeer closed connection\n");
            } else {
                perror(NULL);
                fprintf(stderr, "\nrecv return value < 0");
            }
            ret = 1;
            goto ret_point;
        }
        received_bytes += (uint32_t)recv_ret;
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

