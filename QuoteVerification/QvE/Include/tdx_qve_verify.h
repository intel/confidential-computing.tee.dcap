#ifndef _TDX_QVE_VERIFY_H_
#define _TDX_QVE_VERIFY_H_

#include "sgx_ql_quote.h"

#if defined(__cplusplus)
extern "C"  {
#endif

__attribute__ ((visibility("default"))) uint8_t do_verify_quote_integrity(
		const uint8_t *p_quote,
		uint32_t quote_size,
		const uint8_t * root_pub_key,
		uint32_t root_pub_key_size,
		const tdx_ql_qv_collateral_t *p_quote_collateral,
		uint8_t *p_td_report,
		uint32_t * p_td_report_size);


#if defined(__cplusplus)
}
#endif

#endif /* !_TDX_QVE_VERIFY_H_*/
