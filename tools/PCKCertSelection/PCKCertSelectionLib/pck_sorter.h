/*
 * Copyright(c) 2011-2025 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __PCK_SORTER_H__
#define __PCK_SORTER_H__

#include <vector>
#include <memory>

#include "tcb_manager.h"
#include "pck_cert_selection.h"
#include "SgxEcdsaAttestation/AttestationParsers.h"

/**
 * @class PCKSorter
 * @description Sort and select PCK Cert based on its TCB.
 */
class PCKSorter
{
public:
	/**
	 * Initialize platformSvn, pceIsvSvn, pceID, pemCerts members with input data.
	 * pcks, tcbInfo, buckets members are empty at construct.
	 */
	PCKSorter ( cpu_svn_t platform_svn,
				uint16_t pce_isvsvn,
				uint16_t pce_id,
				const char* tcb_info,
				const char* pem_certs[],
				uint32_t ncerts );

	/**
	 * Initialize platformSvn, pceIsvSvn, pceID, pemCerts members with input data.
	 * pcks, tcbInfo, buckets members are empty at construct.
	 */
	PCKSorter ( cpu_svn_t platform_svn,
				uint16_t pce_isvsvn,
				uint16_t pce_id,
				const char* tcb_info,
				const std::vector<const char*> pem_certs);

	/**
	 * Destructor
	 */
	virtual ~PCKSorter ();

	/**
	 * Public class API.
	 *
	 * Input parsing and verification.
	 * Sort PCKs into buckets.
	 * Buckets are based on TCBInfo Levels and are ordered from high TCB Level (index 0) to low TCB Level (last bucket is below lowest TCB Level).
	 * PCKs in buckets are also sorted during insertion based on its TCB.
	 * Selection of best PCK - the first PCK that the raw TCB is high or equal PCK TCB.
	 *
	 * @param [out] best_cert_index - uint32_t* , the index of selected PCK in the input (construct time) certificates array.
	 * @return @ref pck_cert_selection_res_t
	 */
	pck_cert_selection_res_t select_best_pck ( uint32_t* best_cert_index );

	// private types
private:
	/**
	 * TCB Components vector compare result
	 */
	enum class comp_res_t
	{
		COMP_ERROR = 0,				/**< Error. One of the vectors has invalid size.															*/
		COMP_EQUAL_OR_GREATER = 1,	/**< All bytes of left SVN are equal or greater than right SVN.												*/
		COMP_LOWER = 2,				/**< At least one byte of left SVN is smaller than right SVN, no byte of left SVN is greater than right SVN.*/
		COMP_UNDEFINED = 3,			/**< Some bytes of left SVN are greater than right SVN, some are smaller (relatively undermined).			*/
	};

	// private methods
private:
	// private methods are documented in source file
	pck_cert_selection_res_t parse_input_tcb_and_pcks ( void );
	pck_cert_selection_res_t clean_pcks_return ( pck_cert_selection_res_t res );
	bool equal_bytes ( const std::vector<uint8_t>& left, const std::vector<uint8_t>& right );
	comp_res_t compare_tcb_components ( const std::vector<uint8_t>& left, int64_t left_pcesvn, const std::vector<uint8_t>& right, int64_t right_pcesvn );
	void sort_to_buckets ( void );
	pck_cert_selection_res_t find_best_pck ( uint32_t* best_cert_index );
	pck_cert_selection_res_t parse_input_tcb(void);
	// private members
private:
	/** 
	 * Platform raw CPUSVN.
	 */
	cpu_svn_t platformSvn;

	/**
	 * Platform raw PCESVN.
	 */
	uint16_t pceIsvSvn;

	/**
	 * Platform raw PCEID.
	 */
	uint16_t pceID;

	/**
	* Parsed TCBInfo class.
	*/
	TCBManager tcbmgr;
	/**
	 * Array of PCK Certs strings input, PEM format.
	 */
	std::vector < const char* > pemCerts;

	/**
	 * Array of parsed and validated PCK Certs.
	 */
	std::vector < std::shared_ptr < const intel::sgx::dcap::parser::x509::PckCertificate>> pcks;

	/**
	 * Parsed TCBInfo class.
	 */
	intel::sgx::dcap::parser::json::TcbInfo tcbInfo;

	/**
	 * Buckets to store PCK indexes per TCB level.
	 * Each bucket is also sorted internally.
	 */
	std::vector < std::vector < uint32_t > > buckets;
};


#endif	// __PCK_SORTER_H__
