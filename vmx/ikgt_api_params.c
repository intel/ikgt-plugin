/*******************************************************************************
* Copyright (c) 2015 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

#include "mon_defs.h"
#include "mon_dbg.h"

#include "ikgt_file_codes.h"
#include "ikgt_handler_api.h"
#include "ikgt_internal.h"


#define CHECK_SIZE(params) { \
	if (params->size != sizeof(*params)) { \
	return IKGT_STATUS_ERROR; } \
}

#define CHECK_MONITORING_FLAG(params) { \
	if (params == NULL) { \
	return IKGT_STATUS_ERROR; } \
	if ((params->enable != 0) && (params->enable != 1)) { \
	return IKGT_STATUS_ERROR; } \
}


static ikgt_status_t check_cpu_bitmap(uint64_t *cpu_bitmap)
{
	int32_t bit_index = -1;
	uint32_t ret;

	if (NULL == cpu_bitmap) {
		return IKGT_STATUS_ERROR;
	}

	BITMAP_ARRAY64_CHECKBITS_ALLONE(cpu_bitmap, CPU_BITMAP_MAX, ret);

	if (ret == 0) {
		BITMAP_ARRAY64_HIGHESTINDEX(cpu_bitmap, CPU_BITMAP_MAX, bit_index);
		if (bit_index != -1 && (uint32_t)bit_index >= get_num_of_cpus()) {
			return IKGT_STATUS_ERROR;
		}
	}
	return IKGT_STATUS_SUCCESS;
}

ikgt_status_t check_monitor_cpu_events_params(ikgt_cpu_event_params_t *params)
{
	if (params == NULL) {
		return IKGT_STATUS_ERROR;
	}
	if ((params->enable != 0) && (params->enable != 1)) {
		return IKGT_STATUS_ERROR;
	}

	CHECK_SIZE(params);

	if (IKGT_STATUS_SUCCESS != check_cpu_bitmap(params->cpu_bitmap)) {
		return IKGT_STATUS_ERROR;
	}

	return IKGT_STATUS_SUCCESS;
}

ikgt_status_t check_monitor_cr0_load_params(ikgt_monitor_cr0_load_params_t *params)
{
	CHECK_MONITORING_FLAG(params);

	if (params->cr0_mask.uint64 & IKGT_CR0_RESERVED_BITS) {
		return IKGT_STATUS_ERROR;
	}

	return IKGT_STATUS_SUCCESS;
}

ikgt_status_t check_monitor_cr4_load_params(ikgt_monitor_cr4_load_params_t *params)
{
	CHECK_MONITORING_FLAG(params);

	if (params->cr4_mask.uint64 & IKGT_CR4_RESERVED_BITS) {
		return IKGT_STATUS_ERROR;
	}

	return IKGT_STATUS_SUCCESS;
}

ikgt_status_t check_read_guest_registers_params(ikgt_vmcs_guest_guest_register_t *reg)
{
	if (NULL == reg) {
		return IKGT_STATUS_ERROR;
	}
	/* size should match one existed implementation */
	if (reg->size != sizeof(ikgt_vmcs_guest_guest_register_t)) {
		return IKGT_STATUS_ERROR;
	}
	if ((reg->num == 0) || (reg->num > ((uint32_t)GUEST_REGISTER_MAX_NUM))) {
		return IKGT_STATUS_ERROR;
	}

	return IKGT_STATUS_SUCCESS;
}

#define WRITE_SUPPORTED_REGISTER_COUNT    5
ikgt_status_t check_write_guest_registers_params(ikgt_vmcs_guest_guest_register_t *reg)
{
	uint32_t i = 0;

	if (NULL == reg) {
		return IKGT_STATUS_ERROR;
	}
	/* size should match one exsited implementation */
	if (reg->size != sizeof(ikgt_vmcs_guest_guest_register_t)) {
		return IKGT_STATUS_ERROR;
	}

	if (reg->num == 0 || reg->num > WRITE_SUPPORTED_REGISTER_COUNT) {
		return IKGT_STATUS_ERROR;
	}

	for (i = 0; i < reg->num; i++) {
		if (reg->reg_ids[i] <= IA32_GP_R15)
			return IKGT_STATUS_SUCCESS;

		if ((reg->reg_ids[i] != IA32_GP_RSP)
			&& (reg->reg_ids[i] != VMCS_GUEST_STATE_CR0)
			&& (reg->reg_ids[i] != VMCS_GUEST_STATE_CR4)
			&& (reg->reg_ids[i] != VMCS_GUEST_STATE_RIP)
			&& (reg->reg_ids[i] != VMCS_GUEST_STATE_IDTR_BASE)
			&& (reg->reg_ids[i] != VMCS_GUEST_STATE_IDTR_LIMIT)
			&& (reg->reg_ids[i] != VMCS_GUEST_STATE_RFLAGS)) {
				return IKGT_STATUS_ERROR;
		}
	}

	return IKGT_STATUS_SUCCESS;
}

ikgt_status_t check_get_gva_to_gpa_params(INOUT ikgt_gva_to_gpa_params_t *gva_to_gpa)
{
	if (gva_to_gpa == NULL) {
		return IKGT_STATUS_ERROR;
	}

	if (gva_to_gpa->guest_virtual_address == 0) {
		return IKGT_STATUS_ERROR;
	}
	if (gva_to_gpa->size != sizeof(ikgt_gva_to_gpa_params_t)) {
		return IKGT_STATUS_ERROR;
	}

	return IKGT_STATUS_SUCCESS;
}

ikgt_status_t check_monitor_idtr_load_params(ikgt_monitor_idtr_load_params_t *params)
{
	CHECK_MONITORING_FLAG(params);
	return IKGT_STATUS_SUCCESS;
}

ikgt_status_t check_monitor_gdtr_load_params(ikgt_monitor_gdtr_load_params_t *params)
{
	CHECK_MONITORING_FLAG(params);
	return IKGT_STATUS_SUCCESS;
}

ikgt_status_t check_monitor_msr_params(ikgt_monitor_msr_params_t *params)
{
	uint32_t i = 0;

	CHECK_MONITORING_FLAG(params);

	if (params->num_ids > IKGT_MAX_MSR_IDS) {
		return IKGT_STATUS_ERROR;
	}

	for (i = 0; i < params->num_ids; i++) {
		if ((params->msr_ids[i] > MSR_LOW_LAST && params->msr_ids[i] < MSR_HIGH_FIRST)
			|| ((params->msr_ids[i] > MSR_HIGH_LAST))) {
				return IKGT_STATUS_ERROR;
		}
		/* IA32_MSR_FEATURE_CONTROL is treated as reserved when SMX and VMX are disabled. */
		if (params->msr_ids[i] == IA32_MSR_FEATURE_CONTROL) {
			return IKGT_STATUS_ERROR;
		}
	}

	return IKGT_STATUS_SUCCESS;
}

ikgt_status_t check_update_page_permission_params(ikgt_update_page_permission_params_t *params)
{
	uint32_t i = 0;

	if ((params == NULL) ||
		(params->handle >= MAX_NUM_VIEWS) ||
		(params->addr_list.count <= 0) ||
		(params->addr_list.count > IKGT_ADDRINFO_MAX_COUNT)) {
			return IKGT_STATUS_ERROR;
	}

	for (i = 0; i < params->addr_list.count; i++) {
		if ((params->addr_list.item[i].perms.bit.readable == 0) &&
			(params->addr_list.item[i].perms.bit.writable == 0) &&
			(params->addr_list.item[i].perms.bit.executable == 0)) {
				return IKGT_STATUS_ERROR;
		}
	}

	return IKGT_STATUS_SUCCESS;
}
