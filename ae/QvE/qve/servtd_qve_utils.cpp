#include "sgx_trts_exception.h"
#include "internal/linux/cpuid_gnu.h"
#include "internal/thread_data.h"
#include "sgx_error.h"  // for sgx_status_t
#include <string.h>
#include <pthread.h>

extern "C" 
{
#pragma GCC push_options
#pragma GCC optimize ("-fomit-frame-pointer")

	void __x86_return_thunk()     ///opt/intel/sgxsdk/lib64/libsgx_tcxx.a(Linit_local.o)
	{
		__asm__("ret\n\t");
	}

#pragma GCC pop_options
	void *__dso_handle __attribute__((weak)) = &(__dso_handle);  //libsgx_tsgxssl.a(tmem_mgmt.o): in function `_GLOBAL__sub_I_tmem_mgmt.cpp

#ifndef UNUSED_PARAM
#define UNUSED_PARAM(x) (void)(x)
#endif

	// In SERVTD_ATTEST context there are no real enclaves. The servtd runtime
	// reuses enclave-targeted libraries that rely on these boundary checks.
	// sgx_is_within_enclave() returns 1 to satisfy existing callers, and
	// sgx_is_outside_enclave() must return 0 to remain logically consistent
	// (memory cannot be both within and outside the enclave simultaneously).
	int sgx_is_within_enclave(const void *addr, size_t sz)   //qve.cpp
	{
		UNUSED_PARAM(addr);
		UNUSED_PARAM(sz);
		return 1;
	}
	int sgx_is_outside_enclave(const void *addr, size_t sz)   //libservtd_attest.a(memcpy.o)
	{
		UNUSED_PARAM(addr);
		UNUSED_PARAM(sz);
		return 0;
	}
	uint64_t g_cpu_feature_indicator = 0;



	thread_data_t  *get_thread_data()   //sethread_mutex.cpp: sgx_thread_mutex_unlock_lazy(), sgx_thread_mutex_lock(),sgx_thread_cond_wait()
	{
		static thread_data_t singleThreadData;
		return &singleThreadData;
	}
	int __cxa_atexit( void (*f)(void *), void *p, void *d) {
		UNUSED_PARAM(f);
		UNUSED_PARAM(p);
		UNUSED_PARAM(d);
		return 0;
	}; //libsgx_tsgxssl.a(tmem_mgmt.o): in function `_GLOBAL__sub_I_tmem_mgmt.cpp'; libsgx_tsgxssl.a(tpthread.o): in function `_GLOBAL__sub_I_tpthread.cpp'; TcbInfo.o: in function `__static_initialization_and_destruction_0(int, int)'

	sgx_status_t sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)  //libsgx_tstdc.a(se_cpuid.o): in function `sgx_cpuid'
	{
		__cpuidex(cpuinfo, leaf, subleaf);
		return SGX_SUCCESS;
	}

	void *sgx_register_exception_handler(int is_first_handler, sgx_exception_handler_t exception_handler){
		UNUSED_PARAM(is_first_handler);
		UNUSED_PARAM(exception_handler);
		return NULL;
	} //libsgx_tsgxssl.a(texceptions.o): in function `const_init_exception_handler'

	typedef struct
	{
		unsigned long int ti_module;
		unsigned long int ti_offset;
	} tls_index;

	void *__tls_get_addr(tls_index *ti) //libsgx_tsgxssl.a(bionic_localtime.o): in function `sgxssl_gmtime_r'
	{
		thread_data_t *thread_data = get_thread_data();
		return (unsigned char *)thread_data->tls_addr + ti->ti_offset;
	}

	int atexit(void (*fun)(void))
	{
		return __cxa_atexit((void (*)(void *))fun, NULL, __dso_handle);
	}

	int heap_init(void *_heap_base, size_t _heap_size, size_t _heap_min_size, int _is_edmm_supported);

}
