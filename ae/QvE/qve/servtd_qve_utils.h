#ifndef _MIGTH_QVE_UTILS_H_
#define _MIGTH_QVE_UTILS_H_

#include "sgx_error.h"  // for sgx_status_t
#include "sgx_trts_exception.h"


extern "C"{
	void __x86_return_thunk();
	void __x86_indirect_thunk_rax();
	int sgx_is_within_enclave(const void *addr, size_t sz);
	int __cxa_atexit( void (*f)(void *), void *p, void *d);
	sgx_status_t sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
	void *sgx_register_exception_handler(int is_first_handler, sgx_exception_handler_t exception_handler);
	int get_stack_guard(void);
	bool is_valid_sp(uintptr_t sp);

}

#endif //_MIGTH_QVE_UTILS_H_
