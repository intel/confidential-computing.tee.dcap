/*
 * Copyright (C) 2011-2022 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "tdx_attest.h"

#define devname		"/dev/tdx-attest"

// Directly use the offset here to avoid adding a dependency on the SDK.
#define HEX_DUMP_SIZE	16
#define REPORT_DATA_OFFSET_IN_REPORT 0x80
#define QUOTE_VERSION_OFFSET 0
#define QUOTE_V4_REPORT_DATA_OFFSET 568
#define QUOTE_V5_REPORT_DATA_OFFSET 574

static void print_hex_dump(const char *title, const char *prefix_str,
		const uint8_t *buf, int len)
{
	const uint8_t *ptr = buf;
	int i, rowsize = HEX_DUMP_SIZE;

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

void gen_report_data(uint8_t *reportdata)
{
	int i;

	srand(time(NULL));

	for (i = 0; i < TDX_REPORT_DATA_SIZE; i++)
		reportdata[i] = rand();
}

int main(int argc, char *argv[])
{
    int ret = 1;
    uint32_t quote_size = 0;
    tdx_report_data_t report_data = {{0}};
    tdx_report_data_t report_data_from_report = {{0}};
    tdx_report_t tdx_report = {{0}};
    tdx_uuid_t selected_att_key_id = {0};
    uint8_t *p_quote_buf = NULL;
    tdx_rtmr_event_t rtmr_event = {0};
    FILE *fptr = NULL;
    uint16_t quote_version = 0;
    uint32_t quote_report_data_offset = 0;

    gen_report_data(report_data.d);
    print_hex_dump("\n\t\tTDX report data\n", " ", report_data.d, sizeof(report_data.d));

    if (TDX_ATTEST_SUCCESS != tdx_att_get_report(&report_data, &tdx_report)) {
        fprintf(stderr, "\nFailed to get the report\n");
        goto cleanup;
    }
    fptr = fopen("report.dat","wb");
    if( fptr )
    {
        fwrite(&tdx_report, sizeof(tdx_report), 1, fptr);
        fclose(fptr);
        fptr = NULL;
        fprintf(stdout, "\nWrote TD Report to report.dat\n");
    } else {
        fprintf(stderr, "\nFailed to write report to file\n");

    }


    memcpy(report_data_from_report.d, tdx_report.d + REPORT_DATA_OFFSET_IN_REPORT,
        sizeof(report_data_from_report.d));

    if (TDX_ATTEST_SUCCESS != tdx_att_get_quote(&report_data, NULL, 0, &selected_att_key_id,
        &p_quote_buf, &quote_size, 0)) {
        fprintf(stderr, "\nFailed to get the quote\n");
        goto cleanup;
    }
    print_hex_dump("\n\t\tTDX quote data\n", " ", p_quote_buf, quote_size);

    if (quote_size < 2) {
        fprintf(stderr, "\nQuote buffer is too small\n");
        goto cleanup;
    }

    quote_version = (uint16_t)((uint16_t)p_quote_buf[QUOTE_VERSION_OFFSET]
        | ((uint16_t)p_quote_buf[QUOTE_VERSION_OFFSET + 1] << 8));

    if (quote_version == 4) {
        quote_report_data_offset = QUOTE_V4_REPORT_DATA_OFFSET;
    } else if (quote_version == 5) {
        quote_report_data_offset = QUOTE_V5_REPORT_DATA_OFFSET;
    } else {
        fprintf(stderr, "\nUnsupported quote version: %u\n", (unsigned)quote_version);
        goto cleanup;
    }

    if (quote_size < quote_report_data_offset + sizeof(report_data_from_report.d)) {
        fprintf(stderr, "\nQuote size is too small for report_data in quote version %u\n", (unsigned)quote_version);
        goto cleanup;
    }

    // Verify report_data returned from tdx_att_get_report against quote report_data.
    if (memcmp(p_quote_buf + quote_report_data_offset, report_data_from_report.d,
        sizeof(report_data_from_report.d)) != 0) {
        fprintf(stderr, "\nreport data mismatch\n");
        goto cleanup;
    } else {
        fprintf(stdout, "\nreport data in quote matches the report data in report\n");
    }

    fprintf(stdout, "\nSuccessfully get the TD Quote\n");
    fptr = fopen("quote.dat","wb");
    if( fptr )
    {
        fwrite(p_quote_buf, quote_size, 1, fptr);
        fclose(fptr);
        fptr = NULL;
        fprintf(stdout, "\nWrote TD Quote to quote.dat\n");
    } else {
        fprintf(stderr, "\nFailed to write quote to file\n");
    }

    rtmr_event.version = 1;
    rtmr_event.rtmr_index = 2;
    for (int i = 0; i < sizeof(rtmr_event.extend_data); i++) {
        rtmr_event.extend_data[i] = 1;
    }
    rtmr_event.event_data_size = 0;

    if (TDX_ATTEST_SUCCESS != tdx_att_extend(&rtmr_event)) {
        fprintf(stderr, "\nFailed to extend rtmr[2]\n");
    } else {
        fprintf(stderr, "\nSuccessfully extended rtmr[2]\n");
    }

    rtmr_event.rtmr_index = 3;

    if (TDX_ATTEST_SUCCESS != tdx_att_extend(&rtmr_event)) {
        fprintf(stderr, "\nFailed to extend rtmr[3]\n");
    } else {
        fprintf(stderr, "\nSuccessfully extended rtmr[3]\n");
    }

    ret = 0;

cleanup:
    if (fptr) {
        fclose(fptr);
    }
    tdx_att_free_quote(p_quote_buf);
    return ret;
}
