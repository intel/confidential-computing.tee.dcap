package dcap.quote.appraisal

import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

#
# Constant value of each class id
#
sgx_id := "3123ec35-8d38-4ea5-87a5-d6c48b567570"

enclave_id := "bef7cb8c-31aa-42c1-854c-10db005d5c41"

tdx10_id := "9eec018b-7481-4b1c-8e1a-9f7c0c8c777f"

tdx15_id := "f708b97f-0fb2-4e6b-8b03-8a5bcd1221d3"

tdqe_id := "3769258c-75e6-4bc7-8d72-d2b0e224cad2"

guest_td10_id := "a1e4ee9c-a12e-48ac-bed0-e3f89297f687"

guest_td15_id := "45b734fc-aa4e-4c3d-ad28-e43d08880e68"

#
# UINT64_MAX for checking time.parse_rfc3339_ns return value
#
uint64_max := 18446744073709551615

#
# Utility rule to get matched report and policy based on class_id
#
collect_bundle[id] := bundle if {
	some report in input.qvl_result
	some policy in input.policies.policy_array
	is_string(report.environment.class_id)
	is_string(policy.environment.class_id)
	lower(report.environment.class_id) == lower(policy.environment.class_id)
	id := report.environment.class_id
	bundle := {"report": report, "policy": policy}
}

report_in_policy contains id if {
	some report in input.qvl_result
	some policy in input.policies.policy_array
	is_string(report.environment.class_id)
	is_string(policy.environment.class_id)
	lower(report.environment.class_id) == lower(policy.environment.class_id)
	id := report.environment.class_id
}

#
# Utility rule to get report which doesn't has corresponding policy
#
report_not_in_policy contains report if {
	some report in input.qvl_result
	is_string(report.environment.class_id)
	id := lower(report.environment.class_id)
	not report_in_policy[id]
}

#
# Utility rule to get quote hash
#
quote_hash contains hash if {
	some qh in input.qvl_result
	is_string(qh.quote_hash)
	is_string(qh.algo)
	hash := qh
}

#
# Utility rule to get optional user data
#
optional_ud contains user_data if {
	some ud in input.qvl_result
	is_string(ud.user_data)
	user_data := ud.user_data
}

#
# Section 1: Format the final appraisal output
#
final_appraisal_result contains output if {
	count(quote_hash) != 0
	count(optional_ud) != 0
	some user_data
	user_data_str := optional_ud[user_data]
	output := {
		"overall_appraisal_result": final_ret,
		"appraisal_check_date": time.now_ns(),
		"nonce": rand.intn("appraisal", 1000000000000000),
		"quote_hash": quote_hash,
		"user_data": user_data_str,
		"appraised_reports": appraisal_result,
		"certification_data": certification_data,
	}
}

final_appraisal_result contains output if {
	count(quote_hash) == 0
	count(optional_ud) == 0
	output := {
		"overall_appraisal_result": final_ret,
		"appraisal_check_date": time.now_ns(),
		"nonce": rand.intn("appraisal", 1000000000000000),
		"appraised_reports": appraisal_result,
		"certification_data": certification_data,
	}
}

final_appraisal_result contains output if {
	count(quote_hash) != 0
	count(optional_ud) == 0
	output := {
		"overall_appraisal_result": final_ret,
		"appraisal_check_date": time.now_ns(),
		"nonce": rand.intn("appraisal", 1000000000000000),
		"quote_hash": quote_hash,
		"appraised_reports": appraisal_result,
		"certification_data": certification_data,
	}
}

final_appraisal_result contains output if {
	count(quote_hash) == 0
	count(optional_ud) != 0
	some user_data
	user_data_str := optional_ud[user_data]
	output := {
		"overall_appraisal_result": final_ret,
		"appraisal_check_date": time.now_ns(),
		"nonce": rand.intn("appraisal", 1000000000000000),
		"user_data": user_data_str,
		"appraised_reports": appraisal_result,
		"certification_data": certification_data,
	}
}

# Get final appraisal return value
default final_ret := 0

final_ret := 1 if {
	count(appraisal_result) > 0
	every output in appraisal_result {
		output.appraisal_result == 1
	}
} else := 0 if {
	count(appraisal_result) > 0
	some output in appraisal_result
	output.appraisal_result == 0
} else := -1 if {
	count(appraisal_result) > 0
	every output in appraisal_result {
		output.appraisal_result != 0
	}
	some ret in appraisal_result
	ret.appraisal_result == -1
}

#
# Section 2: Try to get appraisal result for each report and corresponding policy
#
# appraise report for TDX 1.5 platform
appraisal_result contains appraisal_output if {
	some item in collect_bundle
	item.report.environment.class_id == tdx15_id
	appraise_ret := platform_appraisal_ret(item)

	appraisal_output := {
		"appraisal_result": appraise_ret,
		"report": {"environment": item.report.environment, "measurement": item.report.measurement},
		"policy": item.policy,
		"detailed_result": platform_sub_ret(item),
	}
}

#
# appraise report for TDX 1.0 platform
#
appraisal_result contains appraisal_output if {
	some item in collect_bundle
	item.report.environment.class_id == tdx10_id
	appraise_ret := platform_appraisal_ret(item)

	appraisal_output := {
		"appraisal_result": appraise_ret,
		"report": {"environment": item.report.environment, "measurement": item.report.measurement},
		"policy": item.policy,
		"detailed_result": platform_sub_ret(item),
	}
}

#
# appraise report for TD QE
#
appraisal_result contains appraisal_output if {
	some item in collect_bundle
	item.report.environment.class_id == tdqe_id
	appraise_ret := td_qe_appraisal_ret(item)

	appraisal_output := {
		"appraisal_result": appraise_ret,
		"report": {"environment": item.report.environment, "measurement": item.report.measurement},
		"policy": item.policy,
		"detailed_result": td_qe_sub_ret(item),
	}
}

#
# appraise report for guest TD 1.5
#
appraisal_result contains appraisal_output if {
	some item in collect_bundle
	item.report.environment.class_id == guest_td15_id
	appraise_ret := td_appraisal_ret(item)

	appraisal_output := {
		"appraisal_result": appraise_ret,
		"report": {"environment": item.report.environment, "measurement": item.report.measurement},
		"policy": item.policy,
		"detailed_result": td_sub_ret(item),
	}
}

#
# appraise report for guest TD 1.0
#
appraisal_result contains appraisal_output if {
	some item in collect_bundle
	item.report.environment.class_id == guest_td10_id
	appraise_ret := td_appraisal_ret(item)

	appraisal_output := {
		"appraisal_result": appraise_ret,
		"report": {"environment": item.report.environment, "measurement": item.report.measurement},
		"policy": item.policy,
		"detailed_result": td_sub_ret(item),
	}
}

#
# appraise report for SGX platform
#
appraisal_result contains appraisal_output if {
	some item in collect_bundle
	item.report.environment.class_id == sgx_id
	appraise_ret := platform_appraisal_ret(item)

	appraisal_output := {
		"appraisal_result": appraise_ret,
		"report": {"environment": item.report.environment, "measurement": item.report.measurement},
		"policy": item.policy,
		"detailed_result": platform_sub_ret(item),
	}
}

#
# appraise report for SGX enclave
#
appraisal_result contains appraisal_output if {
	some item in collect_bundle
	item.report.environment.class_id == enclave_id
	appraise_ret := enclave_appraisal_ret(item)

	appraisal_output := {
		"appraisal_result": appraise_ret,
		"report": {"environment": item.report.environment, "measurement": item.report.measurement},
		"policy": item.policy,
		"detailed_result": enclave_sub_ret(item),
	}
}

#
# appraise report for those report which doesn't have policy
#
appraisal_result contains appraisal_output if {
	some item in report_not_in_policy
	appraise_ret := -1

	appraisal_output := {
		"appraisal_result": appraise_ret,
		"report": {"environment": item.report.environment, "measurement": item.report.measurement},
	}
}

#
# Extract certification data from QVL report
# Suppose QVL report should always has one certification data
#
certification_data contains cert_data if {
	some item in collect_bundle

	cert_data := item.report.certification_data
}

#
# Section 3: Platform TCB appraisal
#
# Check to see if any in a set of status are not in the policy
default unaccepted_tcb_status_present(_) := false

# tcb status check fail in below cases
# a. accepted_tcb_status is a single string, and tcb_status is not same between policy and report
# b. accepted_tcb_status is an array of string, and one of tcb_status in report is not in accpeted_tcb_status
unaccepted_tcb_status_present(bundle) if {
	some status in bundle.report.measurement.tcb_status
	is_string(status)
	is_string(bundle.policy.reference.accepted_tcb_status)
	upper(status) != upper(bundle.policy.reference.accepted_tcb_status)
}

unaccepted_tcb_status_present(bundle) if {
	# support user to input string or 'array of string'
	is_array(bundle.policy.reference.accepted_tcb_status)
	upper_accepted_tcb := [val |
		some status in bundle.policy.reference.accepted_tcb_status
		val := upper(status)
	]
	some status in bundle.report.measurement.tcb_status
	not upper(status) in upper_accepted_tcb
}

default tcb_status_present(_) := false

tcb_status_present(bundle) if {
	# only accept array of string in QVL output
	is_array(bundle.report.measurement.tcb_status)
}

default tcb_uptodate_check(_) := false

tcb_uptodate_check(bundle) if {
	is_array(bundle.policy.reference.accepted_tcb_status)

	# tcb status must have UpToDate
	basic_status := "UPTODATE"
	upper_accepted_tcb := [val |
		some status in bundle.policy.reference.accepted_tcb_status
		val := upper(status)
	]
	basic_status in upper_accepted_tcb
}

tcb_uptodate_check(bundle) if {
	is_string(bundle.policy.reference.accepted_tcb_status)

	# tcb status must have UpToDate
	basic_status := "UPTODATE"
	basic_status == upper(bundle.policy.reference.accepted_tcb_status)
}

# Appraise required tcb_status - this must not contain any strings that are not in the policy
default tcb_status_ok(_) := false

# tcb status is OK if none of the individual status are rejected and the input contains a tcb_status
tcb_status_ok(bundle) if {
	tcb_status_present(bundle)
	tcb_uptodate_check(bundle)
	not unaccepted_tcb_status_present(bundle)
}

# Appraise required platform_tcb expiration_date_check
#  if policy.reference.collateral_grace_period is provided,
#  then the platform TCB earliest_expiration_date must be within the grace period
default expiration_date_check_ok(_) := false

expiration_date_check_ok(bundle) if {
	not bundle.policy.reference.collateral_grace_period
}

# If user defines collateral_grace_period
# min_eval_num must not be present
expiration_date_check_ok(bundle) if {
	is_number(bundle.policy.reference.collateral_grace_period)
	not bundle.policy.reference.min_eval_num

	# Convert grace period from seconds to ns
	grace_period := bundle.policy.reference.collateral_grace_period * 1000000000
	expiration_date := time.parse_rfc3339_ns(bundle.report.measurement.earliest_expiration_date)
	expiration_date != uint64_max
	expiration_date + grace_period >= time.now_ns()
}

# Appraise platform_tcb.tcb_level_date_tag
#  if policies.reference.platform_grace_period is provided, then
#  the platform_tcb.tcb_level_date_tag must be within the grace period
default earliest_accepted_tcb_level_date_tag_ok(_) := false

tcb_level_date_tag_basic_check(bundle) if {
	is_number(bundle.policy.reference.platform_grace_period)
	is_number(bundle.policy.reference.collateral_grace_period)
	bundle.policy.reference.collateral_grace_period == 0
	not bundle.policy.reference.min_eval_num
	basic_status := ["UPTODATE", "OUTOFDATE"]
	is_array(bundle.policy.reference.accepted_tcb_status)
	upper_accepted_tcb := [val |
		some status in bundle.policy.reference.accepted_tcb_status
		val := upper(status)
	]
	every status in basic_status {
		status in upper_accepted_tcb
	}
}

earliest_accepted_tcb_level_date_tag_ok(bundle) if {
	not bundle.policy.reference.platform_grace_period
}

# If current TCB status in report is one of "UpToDate", "ConfigurationNeeded", "SWHardeningNeeded" or "TDRelaunchAdvised"
# and collateral has no expiry, then ignore the check
earliest_accepted_tcb_level_date_tag_ok(bundle) if {
	tcb_level_date_tag_basic_check(bundle)
	expiration_date_check_ok(bundle)
	ignored_status := ["UPTODATE", "CONFIGURATIONNEEDED", "SWHARDENINGNEEDED", "TDRELAUNCHADVISED"]
	every status in bundle.report.measurement.tcb_status {
		upper(status) in ignored_status
	}
}

# If user defines platform_grace_period, then collateral_grace_period must be 0
# accepted_tcb_status must include UpToDate and OutOfDate
# min_eval_num must not be present
earliest_accepted_tcb_level_date_tag_ok(bundle) if {
	tcb_level_date_tag_basic_check(bundle)
	grace_period := bundle.policy.reference.platform_grace_period * 1000000000
	expiration_date := time.parse_rfc3339_ns(bundle.report.measurement.tcb_level_date_tag)
	expiration_date != uint64_max
	expiration_date + grace_period >= time.now_ns()
}

# Appriasal platform_tcb tcb_level_date_tag
# if policies.reference.min_tcb_level_date is provided, then
# the platform_tcb.tcb_level_date_tag must not be before the policy
# min_tcb_level_date
default accepted_tcb_level_date_tag_ok(_) := false

accepted_tcb_level_date_tag_ok(bundle) if {
	not bundle.policy.sgx_platform.reference.min_tcb_level_date
}

accepted_tcb_level_date_tag_ok(bundle) if {
	is_string(bundle.policy.reference.min_tcb_level_date)
	min_tcb_date := time.parse_rfc3339_ns(bundle.policy.reference.min_tcb_level_date)
	min_tcb_date != uint64_max
	tcb_level_date := time.parse_rfc3339_ns(bundle.report.measurement.tcb_level_date_tag)
	tcb_level_date != uint64_max
	tcb_level_date >= min_tcb_date
}

# Appraise optional platform_tcb tcb_eval_num
default tcb_eval_num_ok(_) := false

tcb_eval_num_ok(bundle) if {
	not bundle.policy.reference.min_eval_num
}

# If user defines min_eval_num, then platform_grace_period must not be present
# collateral_grace_period also must not be present
# accepted_tcb_status must include UpToDate
tcb_eval_num_ok(bundle) if {
	is_number(bundle.report.measurement.tcb_eval_num)
	is_number(bundle.policy.reference.min_eval_num)
	not bundle.policy.reference.platform_grace_period
	not bundle.policy.reference.collateral_grace_period
	bundle.report.measurement.tcb_eval_num >= bundle.policy.reference.min_eval_num
}

# Appraise optional platform_tcb platform_provider_id
default platform_provider_id_ok(_) := false

platform_provider_id_ok(bundle) if {
	not bundle.policy.reference.accepted_platform_provider_ids
}

platform_provider_id_ok(bundle) if {
	some provider_id in bundle.policy.reference.accepted_platform_provider_ids
	is_string(provider_id)
	is_string(bundle.report.measurement.platform_provider_id)
	lower(provider_id) == lower(bundle.report.measurement.platform_provider_id)
}

# Appraise sgx_type - all required_sgx_type in policy should not be missing
# sgx_type has swtiched from string to integer (0, 1, 2)
# Suppose sgx_type in QVL output should be one of 0, 1, 2
default sgx_types_ok(_) := false

sgx_types_ok(bundle) if {
	not bundle.policy.reference.accepted_sgx_types
}

sgx_types_ok(bundle) if {
	is_array(bundle.policy.reference.accepted_sgx_types)
	is_number(bundle.report.measurement.sgx_type)
	bundle.report.measurement.sgx_type in bundle.policy.reference.accepted_sgx_types
}

sgx_types_ok(bundle) if {
	is_number(bundle.policy.reference.accepted_sgx_types)
	is_number(bundle.report.measurement.sgx_type)
	bundle.report.measurement.sgx_type == bundle.policy.reference.accepted_sgx_types
}

# Appraise dynamic_platform, only fail in below situation
# policy 'allow_dynamic_platform = false' AND report 'dynamic_platform = true'
default dynamic_platform_ok(_) := false

dynamic_platform_ok(bundle) if {
	not dynamic_platform_fail(bundle)
}

default dynamic_platform_fail(_) := false

dynamic_platform_fail(bundle) if {
	bundle.report.measurement.is_dynamic_platform
	bundle.policy.reference.allow_dynamic_platform == false
}

# Appraise cached_keys, only fail in below situation
# policy 'allow_cached_keys = false' AND report 'cached_keys = true'
default cached_keys_ok(_) := false

cached_keys_ok(bundle) if {
	not cached_keys_fail(bundle)
}

default cached_keys_fail(_) := false

cached_keys_fail(bundle) if {
	bundle.report.measurement.cached_keys
	bundle.policy.reference.allow_cached_keys == false
}

# Appraise smt_enabled, only fail in below situation
# policy 'allow_smt_enabled = false' AND report 'smt_enabled = true'
default smt_enabled_ok(_) := false

smt_enabled_ok(bundle) if {
	not smt_enabled_fail(bundle)
}

default smt_enabled_fail(_) := false

smt_enabled_fail(bundle) if {
	bundle.report.measurement.smt_enabled
	bundle.policy.reference.allow_smt_enabled == false
}

# Appraise optional platform_tcb advisory_ids
default advisory_ids_ok(_) := false

advisory_ids_ok(bundle) if {
	not advisory_ids_rejected(bundle)
}

advisory_ids_rejected(bundle) if {
	some report_id in bundle.report.measurement.advisory_ids
	some policy_id in bundle.policy.reference.rejected_advisory_ids
	upper(report_id) == upper(policy_id)
}

default platform_tcb_policy_present(_) := false

platform_tcb_policy_present(bundle) if {
	bundle.policy
	lower(bundle.policy.environment.class_id) == lower(bundle.report.environment.class_id)
}

# Sum up platform TCB appraisal
default platform_appraisal_ret(_) := 0

platform_appraisal_ret(bundle) := -1 if {
	not platform_tcb_policy_present(bundle)
} else := 1 if {
	tcb_status_ok(bundle)
	expiration_date_check_ok(bundle)
	earliest_accepted_tcb_level_date_tag_ok(bundle)
	accepted_tcb_level_date_tag_ok(bundle)
	tcb_eval_num_ok(bundle)
	platform_provider_id_ok(bundle)
	dynamic_platform_ok(bundle)
	cached_keys_ok(bundle)
	smt_enabled_ok(bundle)
	advisory_ids_ok(bundle)
	sgx_types_ok(bundle)
} else := 0

# Try to output return value for each platform sub function
platform_sub_ret(bundle) := {{
	"tcb_status_check": tcb_status_ok(bundle),
	"expiration_date_check": expiration_date_check_ok(bundle),
	"earliest_accepted_tcb_level_date_tag_check": earliest_accepted_tcb_level_date_tag_ok(bundle),
	"accepted_tcb_level_date_tag_check": accepted_tcb_level_date_tag_ok(bundle),
	"tcb_eval_num_check": tcb_eval_num_ok(bundle),
	"platform_provider_id_check": platform_provider_id_ok(bundle),
	"dynamic_platform_check": dynamic_platform_ok(bundle),
	"cached_keys_check": cached_keys_ok(bundle),
	"smt_enabled_check": smt_enabled_ok(bundle),
	"advisory_ids_check": advisory_ids_ok(bundle),
	"sgx_types_check": sgx_types_ok(bundle),
}}

#
# Section 4: TD QE appraisal, reuse part of functions in platform appraisal
#
default td_qe_policy_present(_) := false

td_qe_policy_present(bundle) if {
	bundle.policy
	lower(bundle.policy.environment.class_id) == lower(bundle.report.environment.class_id)
}

# Sum up platform TCB appraisal
default td_qe_appraisal_ret(_) := 0

td_qe_appraisal_ret(bundle) := -1 if {
	not td_qe_policy_present(bundle)
} else := 1 if {
	tcb_status_ok(bundle)
	expiration_date_check_ok(bundle)
	earliest_accepted_tcb_level_date_tag_ok(bundle)
	accepted_tcb_level_date_tag_ok(bundle)
	tcb_eval_num_ok(bundle)
} else := 0

# Try to output return value for each platform sub function
td_qe_sub_ret(bundle) := {{
	"td_qe_tcb_status_check": tcb_status_ok(bundle),
	"td_qe_expiration_date_check": expiration_date_check_ok(bundle),
	"td_qe_earliest_accepted_tcb_level_date_tag_check": earliest_accepted_tcb_level_date_tag_ok(bundle),
	"td_qe_accepted_tcb_level_date_tag_check": accepted_tcb_level_date_tag_ok(bundle),
	"td_qe_tcb_eval_num_check": tcb_eval_num_ok(bundle),
}}

#
# Section 5: application enclave appraisal
#
default application_enclave_tcb_policy_present(_) := false

application_enclave_tcb_policy_present(bundle) if {
	bundle.policy
	lower(bundle.policy.environment.class_id) == lower(bundle.report.environment.class_id)
}

# Appraise optional enclave_identity miscselect
default miscselect_ok(_) := false

miscselect_ok(bundle) if {
	not bundle.policy.reference.sgx_miscselect
}

miscselect_ok(bundle) if {
	hex2int := {
		"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7,
		"8": 8, "9": 9, "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15,
	}
	value := split(upper(bundle.report.measurement.sgx_miscselect), "")
	policy := split(upper(bundle.policy.reference.sgx_miscselect), "")
	mask := split(upper(bundle.policy.reference.sgx_miscselect_mask), "")
	equal_num := count({i |
		mask[i]
		bits.and(hex2int[value[i]], hex2int[mask[i]]) == bits.and(hex2int[policy[i]], hex2int[mask[i]])
	})
	orig_num := count(mask)
	equal_num == orig_num
}

# Appraise required enclave_identity attributes
default attributes_ok(_) := false

attributes_ok(bundle) if {
	hex2int := {
		"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7,
		"8": 8, "9": 9, "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15,
	}
	value := split(upper(bundle.report.measurement.sgx_attributes), "")
	policy := split(upper(bundle.policy.reference.sgx_attributes), "")
	mask := split(upper(bundle.policy.reference.sgx_attributes_mask), "")
	equal_num := count({i |
		mask[i]
		bits.and(hex2int[value[i]], hex2int[mask[i]]) == bits.and(hex2int[policy[i]], hex2int[mask[i]])
	})
	orig_num := count(mask)
	equal_num == orig_num
}

# Appraise optional enclave_identity ce_attributes
default ce_attributes_ok(_) := false

ce_attributes_ok(bundle) if {
	not bundle.policy.reference.sgx_ce_attributes
}

ce_attributes_ok(bundle) if {
	hex2int := {
		"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7,
		"8": 8, "9": 9, "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15,
	}
	value := split(upper(bundle.report.measurement.sgx_ce_attributes), "")
	policy := split(upper(bundle.policy.reference.sgx_ce_attributes), "")
	mask := split(upper(bundle.policy.reference.sgx_ce_attributes_mask), "")
	equal_num := count({i |
		mask[i]
		bits.and(hex2int[value[i]], hex2int[mask[i]]) == bits.and(hex2int[policy[i]], hex2int[mask[i]])
	})
	orig_num := count(mask)
	equal_num == orig_num
}

default mrenclave_ok(_) := false

mrenclave_ok(bundle) if {
	not bundle.policy.reference.sgx_mrenclave
}

mrenclave_ok(bundle) if {
	lower(bundle.report.measurement.sgx_mrenclave) == lower(bundle.policy.reference.sgx_mrenclave)
}

default mrsigner_ok(_) := false

mrsigner_ok(bundle) if {
	not bundle.policy.reference.sgx_mrsigner
}

mrsigner_ok(bundle) if {
	lower(bundle.report.measurement.sgx_mrsigner) == lower(bundle.policy.reference.sgx_mrsigner)
}

default isvprod_id_ok(_) := false

isvprod_id_ok(bundle) if {
	not bundle.policy.reference.sgx_isvprodid
}

isvprod_id_ok(bundle) if {
	is_number(bundle.report.measurement.sgx_isvprodid)
	is_number(bundle.policy.reference.sgx_isvprodid)
	bundle.report.measurement.sgx_isvprodid == bundle.policy.reference.sgx_isvprodid
}

default isvsvn_ok(_) := false

isvsvn_ok(bundle) if {
	not bundle.policy.reference.sgx_isvsvn_min
}

isvsvn_ok(bundle) if {
	is_number(bundle.report.measurement.sgx_isvsvn)
	is_number(bundle.policy.reference.sgx_isvsvn_min)
	bundle.report.measurement.sgx_isvsvn >= bundle.policy.reference.sgx_isvsvn_min
}

# Appraise optional kss fields: configid, configsvn_min, isvextprodid, isvfamilyid
default configid_ok(_) := false

configid_ok(bundle) if {
	not bundle.policy.reference.sgx_configid
}

configid_ok(bundle) if {
	is_string(bundle.report.measurement.sgx_configid)
	is_string(bundle.policy.reference.sgx_configid)
	lower(bundle.report.measurement.sgx_configid) == lower(bundle.policy.reference.sgx_configid)
}

default configsvn_ok(_) := false

configsvn_ok(bundle) if {
	not bundle.policy.reference.sgx_configsvn_min
}

configsvn_ok(bundle) if {
	is_number(bundle.report.measurement.sgx_configsvn)
	is_number(bundle.policy.reference.sgx_configsvn_min)
	bundle.report.measurement.sgx_configsvn >= bundle.policy.reference.sgx_configsvn_min
}

default isvextprodid_ok(_) := false

isvextprodid_ok(bundle) if {
	not bundle.policy.reference.sgx_isvextprodid
}

isvextprodid_ok(bundle) if {
	is_string(bundle.report.measurement.sgx_isvextprodid)
	is_string(bundle.policy.reference.sgx_isvextprodid)
	lower(bundle.report.measurement.sgx_isvextprodid) == lower(bundle.policy.reference.sgx_isvextprodid)
}

default isvfamilyid_ok(_) := false

isvfamilyid_ok(bundle) if {
	not bundle.policy.reference.sgx_isvfamilyid
}

isvfamilyid_ok(bundle) if {
	is_string(bundle.report.measurement.sgx_isvfamilyid)
	is_string(bundle.policy.reference.sgx_isvfamilyid)
	lower(bundle.report.measurement.sgx_isvfamilyid) == bundle.policy.reference.sgx_isvfamilyid
}

# Sum up enclave appraisal
default enclave_appraisal_ret(_) := 0

enclave_appraisal_ret(bundle) := -1 if {
	not application_enclave_tcb_policy_present(bundle)
} else := 1 if {
	miscselect_ok(bundle)
	attributes_ok(bundle)
	ce_attributes_ok(bundle)
	mrenclave_ok(bundle)
	mrsigner_ok(bundle)
	isvprod_id_ok(bundle)
	isvsvn_ok(bundle)
	configid_ok(bundle)
	configsvn_ok(bundle)
	isvextprodid_ok(bundle)
	isvfamilyid_ok(bundle)
} else := 0

# Try to output return value for each enclave sub function
enclave_sub_ret(bundle) := {{
	"sgx_miscselcect_check": miscselect_ok(bundle),
	"sgx_attributes_check": attributes_ok(bundle),
	"sgx_ce_attributes_check": ce_attributes_ok(bundle),
	"sgx_mrenclave_check": mrenclave_ok(bundle),
	"sgx_mrsigner_check": mrsigner_ok(bundle),
	"sgx_isvprod_id_check": isvprod_id_ok(bundle),
	"sgx_isvsvn_check": isvsvn_ok(bundle),
	"sgx_configid_check": configid_ok(bundle),
	"sgx_configsvn_check": configsvn_ok(bundle),
	"sgx_isvextprodid_check": isvextprodid_ok(bundle),
	"sgx_isvfamilyid_check": isvfamilyid_ok(bundle),
}}

#
# Section 6: TD appraisal
#
default td_tcb_policy_present(_) := false

td_tcb_policy_present(bundle) if {
	bundle.policy
	lower(bundle.policy.environment.class_id) == lower(bundle.report.environment.class_id)
}

# Appraise required guest td attributes
default td_attributes_ok(_) := false

td_attributes_ok(bundle) if {
	not bundle.policy.reference.tdx_attributes
	not bundle.policy.reference.tdx_attributes_mask
}

td_attributes_ok(bundle) if {
	bundle.policy.reference.tdx_attributes

	provided_mask := object.get(bundle.policy.reference, "tdx_attributes_mask", "00000000FFFFFFFF")

	hex2int := {
		"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7,
		"8": 8, "9": 9, "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15,
	}
	value := split(upper(bundle.report.measurement.tdx_attributes), "")
	policy := split(upper(bundle.policy.reference.tdx_attributes), "")
	mask := split(upper(provided_mask), "")
	equal_num := count({i |
		mask[i]
		bits.and(hex2int[value[i]], hex2int[mask[i]]) == bits.and(hex2int[policy[i]], hex2int[mask[i]])
	})

	equal_num == count(mask)
}

# Appraise optional guest td xfam
default td_xfam_ok(_) := false

td_xfam_ok(bundle) if {
	not bundle.policy.reference.tdx_xfam
	not bundle.policy.reference.tdx_xfam_mask
}

td_xfam_ok(bundle) if {
	bundle.policy.reference.tdx_xfam

	provided_mask := object.get(bundle.policy.reference, "tdx_xfam_mask", "FFFFFFFFFFFFFFFF")

	hex2int := {
		"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7,
		"8": 8, "9": 9, "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15,
	}
	value := split(upper(bundle.report.measurement.tdx_xfam), "")
	policy := split(upper(bundle.policy.reference.tdx_xfam), "")
	mask := split(upper(provided_mask), "")
	equal_num := count({i |
		mask[i]
		bits.and(hex2int[value[i]], hex2int[mask[i]]) == bits.and(hex2int[policy[i]], hex2int[mask[i]])
	})

	equal_num == count(mask)
}

# Appraise guest td tdx_mrconfigid, tdx_mrowner, tdx_mrownerconfig and tdx_mrtd
default td_mrconfigid_ok(_) := false

td_mrconfigid_ok(bundle) if {
	not bundle.policy.reference.tdx_mrconfigid
}

td_mrconfigid_ok(bundle) if {
	is_string(bundle.report.measurement.tdx_mrconfigid)
	is_string(bundle.policy.reference.tdx_mrconfigid)
	lower(bundle.report.measurement.tdx_mrconfigid) == lower(bundle.policy.reference.tdx_mrconfigid)
}

default td_mrowner_ok(_) := false

td_mrowner_ok(bundle) if {
	not bundle.policy.reference.tdx_mrowner
}

td_mrowner_ok(bundle) if {
	is_string(bundle.report.measurement.tdx_mrowner)
	is_string(bundle.policy.reference.tdx_mrowner)
	lower(bundle.report.measurement.tdx_mrowner) == lower(bundle.policy.reference.tdx_mrowner)
}

default td_mrownerconfig_ok(_) := false

td_mrownerconfig_ok(bundle) if {
	not bundle.policy.reference.tdx_mrownerconfig
}

td_mrownerconfig_ok(bundle) if {
	is_string(bundle.report.measurement.tdx_mrownerconfig)
	is_string(bundle.policy.reference.tdx_mrownerconfig)
	lower(bundle.report.measurement.tdx_mrownerconfig) == lower(bundle.policy.reference.tdx_mrownerconfig)
}

default td_mrtd_ok(_) := false

td_mrtd_ok(bundle) if {
	not bundle.policy.reference.tdx_mrtd
}

td_mrtd_ok(bundle) if {
	is_string(bundle.report.measurement.tdx_mrtd)
	is_string(bundle.policy.reference.tdx_mrtd)
	lower(bundle.report.measurement.tdx_mrtd) == lower(bundle.policy.reference.tdx_mrtd)
}

# Appraise optional rtmr 0~4
default td_rtmr0_ok(_) := false

td_rtmr0_ok(bundle) if {
	not bundle.policy.reference.tdx_rtmr0
}

td_rtmr0_ok(bundle) if {
	is_string(bundle.report.measurement.tdx_rtmr0)
	is_string(bundle.policy.reference.tdx_rtmr0)
	lower(bundle.report.measurement.tdx_rtmr0) == lower(bundle.policy.reference.tdx_rtmr0)
}

default td_rtmr1_ok(_) := false

td_rtmr1_ok(bundle) if {
	not bundle.policy.reference.tdx_rtmr1
}

td_rtmr1_ok(bundle) if {
	is_string(bundle.report.measurement.tdx_rtmr1)
	is_string(bundle.policy.reference.tdx_rtmr1)
	lower(bundle.report.measurement.tdx_rtmr1) == lower(bundle.policy.reference.tdx_rtmr1)
}

default td_rtmr2_ok(_) := false

td_rtmr2_ok(bundle) if {
	not bundle.policy.reference.tdx_rtmr2
}

td_rtmr2_ok(bundle) if {
	is_string(bundle.report.measurement.tdx_rtmr2)
	is_string(bundle.policy.reference.tdx_rtmr2)
	lower(bundle.report.measurement.tdx_rtmr2) == lower(bundle.policy.reference.tdx_rtmr2)
}

default td_rtmr3_ok(_) := false

td_rtmr3_ok(bundle) if {
	not bundle.policy.reference.tdx_rtmr3
}

td_rtmr3_ok(bundle) if {
	is_string(bundle.report.measurement.tdx_rtmr3)
	is_string(bundle.policy.reference.tdx_rtmr3)
	lower(bundle.report.measurement.tdx_rtmr3) == lower(bundle.policy.reference.tdx_rtmr3)
}

# Appraise optional tdx mrservicetd, only available for TDX 1.5
default td_mrservicetd_ok(_) := false

td_mrservicetd_ok(bundle) if {
	not bundle.policy.reference.tdx_mrservicetd
}

td_mrservicetd_ok(bundle) if {
	is_string(bundle.report.measurement.tdx_mrservicetd)
	is_string(bundle.policy.reference.tdx_mrservicetd)
	lower(bundle.report.measurement.tdx_mrservicetd) == lower(bundle.policy.reference.tdx_mrservicetd)
}

# Sum up TD appraisal
default td_appraisal_ret(_) := 0

td_appraisal_ret(bundle) := -1 if {
	not td_tcb_policy_present(bundle)
} else := 1 if {
	td_attributes_ok(bundle)
	td_xfam_ok(bundle)
	td_mrconfigid_ok(bundle)
	td_mrowner_ok(bundle)
	td_mrownerconfig_ok(bundle)
	td_mrtd_ok(bundle)
	td_rtmr0_ok(bundle)
	td_rtmr1_ok(bundle)
	td_rtmr2_ok(bundle)
	td_rtmr3_ok(bundle)
	td_mrservicetd_ok(bundle)
} else := 0

# Try to output return value for each platform sub function
td_sub_ret(bundle) := {{
	"td_attributes_check": td_attributes_ok(bundle),
	"td_xfam_check": td_xfam_ok(bundle),
	"td_mrconfigid_check": td_mrconfigid_ok(bundle),
	"td_mrowner_check": td_mrowner_ok(bundle),
	"td_mrownerconfig_check": td_mrownerconfig_ok(bundle),
	"td_mrtd_check": td_mrtd_ok(bundle),
	"td_rtmr0_check": td_rtmr0_ok(bundle),
	"td_rtmr1_check": td_rtmr1_ok(bundle),
	"td_rtmr2_check": td_rtmr2_ok(bundle),
	"td_rtmr3_check": td_rtmr3_ok(bundle),
	"td_mrservicetd_check": td_mrservicetd_ok(bundle),
}}
