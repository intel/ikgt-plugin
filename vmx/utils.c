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
#include "ikgt_file_codes.h"
#include "ikgt_handler_api.h"
#include "ikgt_handler_export.h"
#include "ikgt_internal.h"
#include "ikgt_api_params.h"

#define MON_DEADLOOP()          MON_DEADLOOP_LOG(IKGT_UTILS_C)
#define MON_ASSERT(__condition) MON_ASSERT_LOG(IKGT_UTILS_C, __condition)


typedef union {
	ikgt_monitor_cr0_load_params_t	cr0;
	ikgt_monitor_cr4_load_params_t	cr4;
	ikgt_monitor_idtr_load_params_t	idtr;
	ikgt_monitor_gdtr_load_params_t	gdtr;
} ikgt_monitor_cpu_params_t;

/* ** Important ** */
/* This array is ordered to match the order for registers in the */
/* VMEXIT instruction info field as defined in the IA32 manual. */
static ikgt_cpu_reg_t lookup_ikgt_register_ordered[] = {
	IKGT_CPU_REG_RAX,
	IKGT_CPU_REG_RCX,
	IKGT_CPU_REG_RDX,
	IKGT_CPU_REG_RBX,
	IKGT_CPU_REG_RSP,
	IKGT_CPU_REG_RBP,
	IKGT_CPU_REG_RSI,
	IKGT_CPU_REG_RDI,
	IKGT_CPU_REG_R8,
	IKGT_CPU_REG_R9,
	IKGT_CPU_REG_R10,
	IKGT_CPU_REG_R11,
	IKGT_CPU_REG_R12,
	IKGT_CPU_REG_R13,
	IKGT_CPU_REG_R14,
	IKGT_CPU_REG_R15
};

/* ** Important ** */
/* This array is ordered to match the order for registers in the */
/* VMEXIT instruction info field as defined in the IA32 manual. */
static mon_ia32_gp_registers_t lookup_ia32_register_ordered[] = {
	IA32_REG_RAX,
	IA32_REG_RCX,
	IA32_REG_RDX,
	IA32_REG_RBX,
	IA32_REG_RSP,
	IA32_REG_RBP,
	IA32_REG_RSI,
	IA32_REG_RDI,
	IA32_REG_R8,
	IA32_REG_R9,
	IA32_REG_R10,
	IA32_REG_R11,
	IA32_REG_R12,
	IA32_REG_R13,
	IA32_REG_R14,
	IA32_REG_R15
};

/* Global IKGT STATE */
ikgt_state_t ikgt_state;


ikgt_cpu_reg_t lookup_register_from_list(uint32_t register_index)
{
	MON_ASSERT(register_index < NELEMENTS(lookup_ikgt_register_ordered));
	return lookup_ikgt_register_ordered[register_index];
}

static ikgt_cpu_reg_t get_operand_reg(ia32_vmx_vmcs_vmexit_info_instruction_info_t *instruction_info)
{
	return lookup_register_from_list(instruction_info->bits.register1);
}

static uint64_t get_operand_gva(const guest_vcpu_t *vcpu_id, ia32_vmx_vmcs_vmexit_info_instruction_info_t *instruction_info,
								ia32_vmx_exit_qualification_t *qualification)
{
	/* uint64_t value = 0; */
	mon_ia32_gp_registers_t reg;
	uint64_t base_reg_value = 0;
	uint64_t index_reg_value = 0;
	/* uint64_t hva = 0; */
	uint64_t effective_addr = 0;
	uint64_t displacement = qualification->uint64;
	uint64_t scaling = 1;
	mon_guest_state_value_t value;
	mon_guest_state_t state_id;

	switch (instruction_info->bits.scaling) {
	case 3:
		scaling = 2;
	case 2:
		scaling *= 2;
	case 1:
		scaling *= 2;
	default:
		break;
	}

	/* MON_LOG(mask_anonymous, level_trace,"Operand is in memory\n"); */
	if (instruction_info->bits.index_register_invalid == 0) {
		/* MON_LOG(mask_anonymous, level_trace,"Index Register is valid\n"); */
		reg = lookup_ia32_register_ordered[instruction_info->bits.index_register];
		if (reg < IA32_REG_RIP) {
			state_id = (mon_guest_state_t)reg;
		} else {
			state_id = (mon_guest_state_t)(MON_GUEST_RIP + reg - IA32_REG_RIP);
		}
		if (TRUE == xmon_get_vmcs_guest_state(vcpu_id, state_id, &value)) {
			index_reg_value = value.value;
		} else {
			return 0;
		}
	}

	if (instruction_info->bits.base_register_invalid == 0) {
		/* MON_LOG(mask_anonymous, level_trace,"Base Register is valid\n"); */
		reg = lookup_ia32_register_ordered[instruction_info->bits.base_register];
		if (reg < IA32_REG_RIP) {
			state_id = (mon_guest_state_t)reg;
		} else {
			state_id = (mon_guest_state_t)(MON_GUEST_RIP + reg - IA32_REG_RIP);
		}
		if (TRUE == xmon_get_vmcs_guest_state(vcpu_id, state_id, &value)) {
			base_reg_value = value.value;
		} else {
			return 0;
		}
		/* MON_LOG(mask_anonymous, level_trace,"base_reg_value = %08X\n", base_reg_value); */
	}

	effective_addr = base_reg_value + (index_reg_value * scaling) + displacement;
	/* MON_LOG(mask_anonymous, level_trace,"effective_addr = %08X\n", effective_addr); */
	/* gcpu_gva_to_hva(gcpu, (GVA)effective_addr, &hva); */
	/* value = *((uint64_t *)hva); */
	/* MON_LOG(mask_anonymous, level_trace,"value at effective_addr = %08X\n", value); */

	return effective_addr;
}

void init_dte_lock(void)
{
	lock_initialize(&ikgt_state.dte_lock);
}

void acquire_dte_lock(void)
{
	interruptible_lock_acquire(&ikgt_state.dte_lock);
}

void release_dte_lock(void)
{
	lock_release(&ikgt_state.dte_lock);
}

uint32_t get_num_of_cpus(void)
{
	return ikgt_state.num_of_cpus;
}

/**************************************************************************
* Return TRUE is the CPL of the guest issuing the VMCALL is in ring 0,
* otherwise return FALSE.
**************************************************************************/
boolean_t check_guest_cpl_is_ring0(const guest_vcpu_t *vcpu_id)
{
	mon_guest_state_value_t guest_cs_selector;

	if (FALSE == xmon_get_vmcs_guest_state(vcpu_id, MON_GUEST_CS_SELECTOR,
		&guest_cs_selector)) {
			return MON_ERROR;
	}

	if (BITMAP_GET(guest_cs_selector.value, DESCRIPTOR_CPL_BIT) == 0) {
		return TRUE;
	}

	MON_LOG(mask_plugin, level_error,
		"CPU%d: %s: Error: VMCALL is initialized from ring >0. CPL=%d.\n",
		vcpu_id->guest_cpu_id, __FUNCTION__,
		BITMAP_GET(guest_cs_selector.value, DESCRIPTOR_CPL_BIT));

	return FALSE;
}

boolean_t __gpa_to_hva(const guest_vcpu_t *vcpu_id, view_handle_t view,
						  gpa_t gpa, hva_t *hva)
{
	hpa_t hpa;
	mam_attributes_t hpa_attrs;

	if (FALSE == xmon_gpa_to_hpa(vcpu_id, view, gpa, &hpa, &hpa_attrs)) {
		return FALSE;
	}

	return xmon_hpa_to_hva(hpa, hva);
}

boolean_t __gva_to_hva(const guest_vcpu_t *vcpu_id, view_handle_t view,
						  gva_t gva, hva_t *hva)
{
	gpa_t gpa;

	if (FALSE == xmon_gva_to_gpa(vcpu_id, gva, &gpa)) {
		return FALSE;
	}

	return __gpa_to_hva(vcpu_id, view, gpa, hva);
}

ikgt_guest_state_t *find_guest_state(guest_id_t guest_id)
{
	ikgt_guest_state_t *ikgt_guest_state = NULL;
	list_element_t *iter = NULL;
	boolean_t found = FALSE;

	LIST_FOR_EACH(ikgt_state.guest_state, iter) {
		ikgt_guest_state = LIST_ENTRY(iter, ikgt_guest_state_t, list);
		if (ikgt_guest_state->guest_id == guest_id) {
			found = TRUE;
			break;
		}
	}
	if (found) {
		return ikgt_guest_state;
	}
	return NULL;
}

boolean_t copy_gva_to_hva(const guest_vcpu_t *vcpu_id, gva_t gva,
						  uint32_t size, hva_t hva)
{
	uint64_t dst_hva = 0;
	uint64_t src_gva = (uint64_t)gva;
	uint8_t *local_ptr = (uint8_t *)hva;
	uint32_t size_remaining = size;
	uint32_t size_copied = 0;
	ikgt_guest_state_t *ikgt_guest = NULL;

	if (gva + size <= gva) {
		return FALSE;
	}

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);

	while (size_remaining) {
		if (!__gva_to_hva(vcpu_id,
			ikgt_guest->view[get_active_view(vcpu_id)],
			(gva_t)src_gva, (hva_t *)&dst_hva)) {
				MON_LOG(mask_plugin, level_error,
					"%s: Invalid Parameter Struct address %P\n",
					__FUNCTION__, src_gva);
				return FALSE;
		}
		/* Copy until end */
		if (src_gva > (UINT64_ALL_ONES - size_remaining)) {
			MON_LOG(mask_mon, level_error, "Error: size bounds exceeded\n");
			return FALSE;
		}
		if ((src_gva + size_remaining) <= (src_gva | PAGE_4KB_MASK)) {
			mon_memcpy((void *)local_ptr, (void *)dst_hva, size_remaining);
			return TRUE;
		} else {
			/* Copy until end of page */
			size_copied = (uint32_t)(((src_gva + PAGE_4KB_SIZE)
				& ~PAGE_4KB_MASK) - src_gva);

			mon_memcpy((void *)local_ptr, (void *)dst_hva, size_copied);

			/* Adjust size and pointers for next copy */
			size_remaining -= size_copied;
			local_ptr += size_copied;
			src_gva += size_copied;
		}
	}
	return TRUE;
}

boolean_t copy_hva_to_gva(const guest_vcpu_t *vcpu_id, hva_t hva,
						  uint32_t size, gva_t gva)
{
	uint64_t dst_gva = (uint64_t)gva;
	uint64_t src_hva = 0;
	uint8_t *local_ptr = (uint8_t *)hva;
	uint32_t size_remaining = size;
	uint32_t size_copied = 0;
	ikgt_guest_state_t *ikgt_guest = NULL;

	if (gva + size <= gva) {
		return FALSE;
	}
	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);

	while (size_remaining) {
		if (!__gva_to_hva(vcpu_id,
			ikgt_guest->view[get_active_view(vcpu_id)],
			(gva_t)dst_gva, (hva_t *)&src_hva)) {
				MON_LOG(mask_plugin, level_error,
					"%s: Invalid guest pointer address %P\n",
					__FUNCTION__, gva);
				return FALSE;
		}
		/* Copy until end */
		if (dst_gva > (UINT64_ALL_ONES - size_remaining)) {
			MON_LOG(mask_mon, level_error, "Error: size bounds exceeded\n");
			return FALSE;
		}
		if ((dst_gva + size_remaining) <= (dst_gva | PAGE_4KB_MASK)) {
			mon_memcpy((void *)src_hva, (void *)local_ptr, size_remaining);
			return TRUE;
		} else {
			/* Copy until end of page */
			size_copied = (uint32_t)(((dst_gva + PAGE_4KB_SIZE)
				& ~PAGE_4KB_MASK) - dst_gva);

			mon_memcpy((void *)src_hva, (void *)local_ptr, size_copied);

			/* Adjust size and pointers for next copy */
			size_remaining -= size_copied;
			local_ptr += size_copied;
			dst_gva += size_copied;
		}
	}
	return TRUE;
}

void get_vmcs_guest_state(const guest_vcpu_t *vcpu_id,
						  ikgt_event_vmcs_guest_state_t *ikgt_event_vmcs_guest_state)
{
	mon_guest_state_value_t value1;
	mon_controls_t value2;

	MON_ASSERT(ikgt_event_vmcs_guest_state);

	if (TRUE == xmon_get_vmcs_guest_state(vcpu_id, MON_GUEST_RIP, &value1)) {
		ikgt_event_vmcs_guest_state->ia32_reg_rip = value1.value;
	}
	if (TRUE == xmon_get_vmcs_guest_state(vcpu_id, MON_GUEST_RFLAGS, &value1)) {
		ikgt_event_vmcs_guest_state->ia32_reg_rflags = value1.value;
	}
	if (TRUE == xmon_get_vmcs_control_state(vcpu_id,
		MON_EXIT_INFO_INSTRUCTION_LENGTH,
		&value2)) {
			ikgt_event_vmcs_guest_state->vmcs_exit_info_instruction_length = value2.value;
	}
}

static ikgt_status_t internal_x_monitor_cr0_load(const guest_vcpu_t *vcpu_id,
												 ikgt_monitor_cr0_load_params_t *params,
												 uint64_t *cpu_bitmap)
{

	ikgt_guest_state_t *ikgt_guest = NULL;

	if (check_monitor_cr0_load_params(params) != IKGT_STATUS_SUCCESS) {
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: Invalid input arguments.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		return IKGT_STATUS_ERROR;
	}

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);

	return __monitor_cr0_load(vcpu_id, params, cpu_bitmap);
}

/* Method to check support for CR4 bits on this processor.
* Refer to IA Manual 3A - section 2.5 for CR4 bits.
* For capability information refer to IA Manual 2A - CPUID instruction
* with EAX = 1. Feature information is returned in ECX and EDX.
* These need to be checked for capability.
*/
static ikgt_status_t cr4_bit_support_check(uint64_t mask)
{
	cpuid_params_t cpu_info = { 0 };
	uint32_t i;
	ikgt_cr4_mask_t model_specific_bits;
	ikgt_cr4_mask_t test_bit;
	uint32_t feature_info_cx = 0, feature_info_dx = 0, temp_cx = 0, temp_dx = 0;
	uint32_t feature_info_07_bx = 0, error_07_bx;
	ikgt_status_t status = IKGT_STATUS_SUCCESS;

	mon_memset(&cpu_info, 0, sizeof(cpu_info));
	model_specific_bits.uint64 = 0;

	/* These are the model specific bits with CPUID qualification */
	model_specific_bits.bits.vme = CR4_SUPPORT_BIT_1;
	model_specific_bits.bits.pvi = CR4_SUPPORT_BIT_1;
	model_specific_bits.bits.tsd = CR4_SUPPORT_BIT_1;
	model_specific_bits.bits.de = CR4_SUPPORT_BIT_1;
	model_specific_bits.bits.pse = CR4_SUPPORT_BIT_1;
	model_specific_bits.bits.pae = CR4_SUPPORT_BIT_1;
	model_specific_bits.bits.mce = CR4_SUPPORT_BIT_1;
	model_specific_bits.bits.pge = CR4_SUPPORT_BIT_1;
	model_specific_bits.bits.osfxsr = CR4_SUPPORT_BIT_1;
	/* No rule to check OSXMMEXCPT
	* model_specific_bits.bits.OSXMMEXCPT = 1; */
	model_specific_bits.bits.vmxe = CR4_SUPPORT_BIT_1;
	model_specific_bits.bits.smxe = CR4_SUPPORT_BIT_1;
	model_specific_bits.bits.pcide = CR4_SUPPORT_BIT_1;
	model_specific_bits.bits.osxsave = CR4_SUPPORT_BIT_1;
	model_specific_bits.bits.smep = CR4_SUPPORT_BIT_1;

	/* If any of the mask bits are set for model specific bits. */
	if (!(mask & model_specific_bits.uint64)) {
		return status;
	}

	/* CPUID to check whether the requested bits are supported. We have to
	* run CPUID with EAX = 0x1 and EAX = 0x7 with ECX = 0x0 for sub-leaf 0
	* for all the bits to be checked. */
	/* 1. Execute cpu_id_t with EAX = 0x1 */
	cpu_info.m_rax = 0x1;
	hw_cpuid(&cpu_info);

	/* These are bits in feature information that we are interested in */
	feature_info_cx = (CR4_SUPPORT_BIT_1 << FEAT_CX_VMX) |
		(CR4_SUPPORT_BIT_1 << FEAT_CX_SMX) |
		(CR4_SUPPORT_BIT_1 << FEAT_CX_PCID) |
		(CR4_SUPPORT_BIT_1 << FEAT_CX_OSXSAVE);
	feature_info_dx = (CR4_SUPPORT_BIT_1 << FEAT_DX_VME) |
		(CR4_SUPPORT_BIT_1 << FEAT_DX_DE) |
		(CR4_SUPPORT_BIT_1 << FEAT_DX_PSE) |
		(CR4_SUPPORT_BIT_1 << FEAT_DX_TSC) |
		(CR4_SUPPORT_BIT_1 << FEAT_DX_PAE) |
		(CR4_SUPPORT_BIT_1 << FEAT_DX_MCE) |
		(CR4_SUPPORT_BIT_1 << FEAT_DX_PGE) |
		(CR4_SUPPORT_BIT_1 << FEAT_DX_FXSR);

	/* Check if all bits are supported. */
	if (((feature_info_cx & cpu_info.m_rcx) != feature_info_cx) ||
		((feature_info_dx & cpu_info.m_rdx) != feature_info_dx)) {
			/* ERROR bits */
			temp_cx = feature_info_cx &
				~(feature_info_cx & cpu_info.m_rcx);
			temp_dx = feature_info_dx &
				~(feature_info_dx & cpu_info.m_rdx);

			/* Check which bits are not supported in ECX. Map it to mask bits.
			* Check if any unsupported bits are set in mask. */
			for (i = 0; i < NUM_OF_VALID_CR4_BITS; i++) {
				test_bit.uint64 = 0;
				if (temp_cx & (CR4_SUPPORT_BIT_1 << i)) {
					switch (i) {
						/* VMXE */
					case FEAT_CX_VMX:
						test_bit.bits.vmxe = CR4_SUPPORT_BIT_1;
						break;
						/* SMXE */
					case FEAT_CX_SMX:
						test_bit.bits.smxe = CR4_SUPPORT_BIT_1;
						break;
						/* PCID */
					case FEAT_CX_PCID:
						test_bit.bits.pcide = CR4_SUPPORT_BIT_1;
						break;
						/* OSXSAVE */
					case FEAT_CX_OSXSAVE:
						test_bit.bits.osxsave = CR4_SUPPORT_BIT_1;
						break;
					}
					/* If any bits not supported is set in mask, return error */
					if (mask & test_bit.uint64) {
						status = IKGT_STATUS_ERROR;
						return status;
					}
				}
			}

			/* Check which bits are not supported in EDX. Map it to mask bits.
			* Check if any unsupported bits are set in mask. */
			for (i = 0; i < NUM_OF_VALID_CR4_BITS; i++) {
				test_bit.uint64 = 0;
				if (temp_dx & (CR4_SUPPORT_BIT_1 << i)) {
					switch (i) {
						/* VME or PVI */
					case FEAT_DX_VME:
						test_bit.bits.vme = CR4_SUPPORT_BIT_1;
						test_bit.bits.pvi = CR4_SUPPORT_BIT_1;
						break;
						/* DE */
					case FEAT_DX_DE:
						test_bit.bits.de = CR4_SUPPORT_BIT_1;
						break;
						/* PSE */
					case FEAT_DX_PSE:
						test_bit.bits.pse = CR4_SUPPORT_BIT_1;
						break;
						/* TSC */
					case FEAT_DX_TSC:
						test_bit.bits.tsd = CR4_SUPPORT_BIT_1;
						break;
						/* PAE */
					case FEAT_DX_PAE:
						test_bit.bits.pae = CR4_SUPPORT_BIT_1;
						break;
						/* MCE */
					case FEAT_DX_MCE:
						test_bit.bits.mce = CR4_SUPPORT_BIT_1;
						break;
						/* PGE */
					case FEAT_DX_PGE:
						test_bit.bits.pge = CR4_SUPPORT_BIT_1;
						break;
						/* FXSR */
					case FEAT_DX_FXSR:
						test_bit.bits.osfxsr = CR4_SUPPORT_BIT_1;
						break;
					}
					/* If any bits not supported is set in mask, return error */
					if (mask & test_bit.uint64) {
						status = IKGT_STATUS_ERROR;
						return status;
					}
				}
			}
	}

	/* 2. Execute cpu_id_t with EAX = 0x7 with ECX = 0x0 for sub-leaf 0 */
	mon_memset(&cpu_info, 0, sizeof(cpu_info));
	cpu_info.m_rax = 0x7;
	hw_cpuid(&cpu_info);

	/* These are bits in feature information that we are interested in */
	feature_info_07_bx = CR4_SUPPORT_BIT_1 << FEAT_07_EBX_SMEP;

	/* Check if all bits are supported. */
	if ((feature_info_07_bx & cpu_info.m_rbx) != feature_info_07_bx) {
		/* ERROR bits */
		error_07_bx = feature_info_07_bx &
			~(feature_info_07_bx & cpu_info.m_rbx);

		/* Check which bits are not supported in EBX. Map it to mask bits.
		* Check if any unsupported bits are set in mask. */
		for (i = 0; i < NUM_OF_VALID_CR4_BITS; i++) {
			test_bit.uint64 = 0;
			if (error_07_bx & (CR4_SUPPORT_BIT_1 << i)) {
				switch (i) {
					/* SMEP */
				case FEAT_07_EBX_SMEP:
					test_bit.bits.smep = CR4_SUPPORT_BIT_1;
					break;
				}
				/* If any bits not supported is set in mask, return error */
				if (mask & test_bit.uint64) {
					status = IKGT_STATUS_ERROR;
				}
			}
		}
	}

	return status;
}

static ikgt_status_t internal_x_monitor_cr4_load(const guest_vcpu_t *vcpu_id,
												 ikgt_monitor_cr4_load_params_t
												 *params,
												 uint64_t *cpu_bitmap)
{
	ikgt_guest_state_t *ikgt_guest = NULL;

	if (check_monitor_cr4_load_params(params) != IKGT_STATUS_SUCCESS) {
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: Invalid input arguments.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		return IKGT_STATUS_ERROR;
	}

	if (cr4_bit_support_check(params->cr4_mask.uint64) == IKGT_STATUS_ERROR) {
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: One or more bits are not supported on this CPU.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		return IKGT_STATUS_ERROR;
	}

	if (params->cr4_mask.bits.osxsave) {
		/* OSXSAVE bit is always monitored by IKGT and cannot
		* be monitored by IB/handler */
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: osxsave bit cannot be monitored.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		return IKGT_STATUS_ERROR;
	}
	if (params->cr4_mask.bits.smxe || params->cr4_mask.bits.vmxe) {
		/* In exit handler for cpuid, make sure these bits as cleared
		* when a CPUID call is made */
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: smxe or vmxe bit is not" \
			" supported on this CPU.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		return IKGT_STATUS_ERROR;
	}

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);

	return __monitor_cr4_load(vcpu_id, params, cpu_bitmap);
}

static ikgt_status_t internal_x_monitor_idtr_access(const guest_vcpu_t *vcpu_id,
													ikgt_monitor_idtr_load_params_t
													*params,
													uint64_t *cpu_bitmap)
{
	ikgt_guest_state_t *ikgt_guest = NULL;
	uint32_t i;

	if (check_monitor_idtr_load_params(params) != IKGT_STATUS_SUCCESS) {
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: Invalid input arguments.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		return IKGT_STATUS_ERROR;
	}

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);

	for (i = 0; i < ikgt_state.num_of_cpus; i++) {
		if (BITMAP_ARRAY64_GET(cpu_bitmap, i)) {
			ikgt_guest->gcpu_state[i]->monitor_regs.idtr_load =
				(boolean_t)(params->enable);
		}
	}

	return IKGT_STATUS_SUCCESS;
}

static ikgt_status_t internal_x_monitor_gdtr_load(const guest_vcpu_t *vcpu_id,
												  ikgt_monitor_gdtr_load_params_t
												  *params,
												  uint64_t *cpu_bitmap)
{
	ikgt_guest_state_t *ikgt_guest = NULL;
	uint32_t i;

	if (check_monitor_gdtr_load_params(params) != IKGT_STATUS_SUCCESS) {
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: Invalid input arguments.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		return IKGT_STATUS_ERROR;
	}

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);

	for (i = 0; i < ikgt_state.num_of_cpus; i++) {
		if (BITMAP_ARRAY64_GET(cpu_bitmap, i)) {
			ikgt_guest->gcpu_state[i]->monitor_regs.gdtr_load =
				(boolean_t)(params->enable);
		}
	}

	return IKGT_STATUS_SUCCESS;
}

/* Enable descriptor-table exiting before any write monitoring
* to IDTR, GDTR */
static void enable_dte(const guest_vcpu_t *vcpu_id, uint64_t *cpu_bitmap)
{
	ikgt_descriptor_table_exiting_params_t exiting_params;
	ikgt_guest_state_t *ikgt_guest;
	uint64_t exiting_bitmap[CPU_BITMAP_MAX], i;
	uint32_t ret;

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);

	/* Mask out the requested CPUs with DTE already enabled */
	BITMAP_ARRAY_ASSIGN(exiting_bitmap, CPU_BITMAP_MAX, 0);
	for (i = 0; i < ikgt_state.num_of_cpus; i++) {
		if ((ikgt_guest->gcpu_state[i]->monitor_regs.dte == FALSE) &&
			(BITMAP_ARRAY64_GET(cpu_bitmap, i))) {
				BITMAP_ARRAY64_SET(exiting_bitmap, i);
		}
	}

	BITMAP_ARRAY64_CHECKBITS_ALLZERO(exiting_bitmap, CPU_BITMAP_MAX, ret);

	if (ret == 0) {
		exiting_params.enable = 1;
		descriptor_table_exiting(vcpu_id, &exiting_params,
			exiting_bitmap);
	}
}

/* Disable descriptor-table exiting when IDTR, GDTR monitoring
* in CPU have been disabled */
static void disable_dte(const guest_vcpu_t *vcpu_id, uint64_t *cpu_bitmap)
{
	ikgt_descriptor_table_exiting_params_t exiting_params;
	ikgt_guest_state_t *ikgt_guest;
	uint64_t exiting_bitmap[CPU_BITMAP_MAX], i;
	ikgt_monitor_registers_t *monitor_regs;
	uint32_t ret;

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);

	/* Build CPU bitmap for disabling DTE */
	BITMAP_ARRAY_ASSIGN(exiting_bitmap, CPU_BITMAP_MAX, 0);
	for (i = 0; i < ikgt_state.num_of_cpus; i++) {
		monitor_regs = &ikgt_guest->gcpu_state[i]->monitor_regs;

		/* The DTE must be currently enabled on the requested CPU */
		if ((monitor_regs->dte == TRUE) && (BITMAP_ARRAY64_GET(cpu_bitmap, i))) {
			/* All 4 bits must be currently disabled */
			if ((monitor_regs->gdtr_load == FALSE) &&
				(monitor_regs->idtr_load == FALSE) &&
				(monitor_regs->ldtr_load == FALSE) &&
				(monitor_regs->tr_load == FALSE)) {
					BITMAP_ARRAY64_SET(exiting_bitmap, i);
			}
		}
	}

	BITMAP_ARRAY64_CHECKBITS_ALLZERO(exiting_bitmap, CPU_BITMAP_MAX, ret);

	if (ret == 0) {
		exiting_params.enable = 0;
		descriptor_table_exiting(vcpu_id, &exiting_params,
			exiting_bitmap);
	}
}

boolean_t skip_guest_instruction(const guest_vcpu_t *vcpu_id)
{
	mon_guest_state_value_t value;

	/* not used */
	value.value = 0;
	value.skip_rip = TRUE;

	return xmon_set_vmcs_guest_state(vcpu_id, MON_GUEST_RIP, value);
}

uint64_t get_guest_visible_CR_value(const guest_vcpu_t *vcpu_id,
									mon_ia32_control_registers_t	reg)
{
	mon_controls_t cr_read_shadow, cr_mask;
	mon_guest_state_value_t real_value;

	cr_read_shadow.value = 0;
	cr_mask.value = 0;
	real_value.value = 0;

	switch (reg) {
	case IA32_CTRL_CR0:
		if (FALSE == xmon_get_vmcs_control_state(vcpu_id, MON_CR0_READ_SHADOW,
			&cr_read_shadow)) {
				return 0;
		}
		if (FALSE == xmon_get_vmcs_control_state(vcpu_id, MON_CR0_MASK, &cr_mask)) {
			return 0;
		}
		if (FALSE == xmon_get_vmcs_guest_state(vcpu_id, MON_GUEST_CR0,
			&real_value)) {
				return 0;
		}
		break;
	case IA32_CTRL_CR4:
		if (FALSE == xmon_get_vmcs_control_state(vcpu_id, MON_CR4_READ_SHADOW,
			&cr_read_shadow)) {
				return 0;
		}
		if (FALSE == xmon_get_vmcs_control_state(vcpu_id, MON_CR4_MASK, &cr_mask)) {
			return 0;
		}
		if (FALSE == xmon_get_vmcs_guest_state(vcpu_id, MON_GUEST_CR4,
			&real_value)) {
				return 0;
		}
		break;
	default:
		return 0;
	}
	return (real_value.value & ~cr_mask.value) |
		(cr_read_shadow.value & cr_mask.value);
}

boolean_t save_old_guest_rip(const guest_vcpu_t *vcpu_id)
{
	ikgt_guest_state_t *ikgt_guest = NULL;
	ikgt_guest_cpu_state_t *ikgt_guest_cpu = NULL;
	mon_guest_state_value_t value;

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);
	ikgt_guest_cpu = ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id];
	MON_ASSERT(ikgt_guest_cpu);
	value.value = 0;

	/* Save original RIP before handler processing */
	if (FALSE == xmon_get_vmcs_guest_state(vcpu_id, MON_GUEST_RIP, &value)) {
		return FALSE;
	}
	ikgt_guest_cpu->guest_rip_old = value.value;

	return TRUE;
}

ikgt_status_t get_vmexit_reason(const guest_vcpu_t *vcpu_id,
								ikgt_vmexit_reason_t *reason)
{
	vmexit_reason_t r;

	if (TRUE == xmon_get_vmexit_reason(vcpu_id, &r)) {
		reason->reason = r.reason;
		reason->qualification = r.qualification;
		reason->gva = r.gva;
		return IKGT_STATUS_SUCCESS;
	} else {
		return IKGT_STATUS_ERROR;
	}
}

ikgt_status_t read_vmcs_guest_state(const guest_vcpu_t *vcpu_id,
									uint32_t		id_num,
									ikgt_vmcs_guest_state_reg_id_t
									reg_ids[],
									uint32_t *value_num,
									uint64_t		reg_values[])
{
	uint32_t i;
	ikgt_vmcs_guest_state_reg_id_t reg_id;
	mon_guest_state_t id;
	mon_guest_state_value_t value;

	for (i = 0; i < id_num; i++) {
		reg_id = reg_ids[i];
		if (((uint32_t)reg_id) > ((uint32_t)(NUM_OF_VMCS_GUEST_STATE_REGS - 1))) {
			break;
		}

		if (reg_id == VMCS_STATE_GUEST_UG_SUPPORT) {
			reg_values[i] = xmon_is_unrestricted_guest_supported();
			continue;
		}
		/* Read the visible CR0 to notify handler of correct guest mode */
		else if (reg_id == VMCS_GUEST_STATE_CR0) {
			reg_values[i] = get_guest_visible_CR_value(vcpu_id,
				IA32_CTRL_CR0);
			continue;
		}
		/* Read the visible CR0 to notify handler of correct guest mode */
		else if (reg_id == VMCS_GUEST_STATE_CR4) {
			reg_values[i] = get_guest_visible_CR_value(vcpu_id,
				IA32_CTRL_CR4);
			continue;
		}
		/* Both RIP and RFLAGS are in the end in ikgt_api.h while in middle
		* in mon_api.h
		* Need to move to middle in ikgt_api.h when refactoring the code */
		else if (reg_id == VMCS_GUEST_STATE_RIP) {
			id = MON_GUEST_RIP;
		} else if (reg_id == VMCS_GUEST_STATE_RFLAGS) {
			id = MON_GUEST_RFLAGS;
		} else if (reg_id == VMCS_GUEST_STATE_CR8) {
			id = MON_GUEST_CR8;
		} else if (reg_id < VMCS_GUEST_STATE_PEND_DBE) {
			id = (mon_guest_state_t)reg_id;
		} else if (reg_id >= VMCS_GUEST_STATE_PEND_DBE &&
			reg_id <= VMCS_GUEST_STATE_EFER) {
				id = (mon_guest_state_t)(reg_id - VMCS_GUEST_STATE_PEND_DBE +
					MON_GUEST_PEND_DBE);
		} else if (reg_id >= VMCS_GUEST_STATE_PDPTR0 && reg_id <=
			VMCS_STATE_PREEMPTION_TIMER) {
				id = (mon_guest_state_t)(reg_id - VMCS_GUEST_STATE_PDPTR0 +
					MON_GUEST_PDPTR0);
		} else {
			break;
		}

		if (TRUE == xmon_get_vmcs_guest_state(vcpu_id, id, &value)) {
			reg_values[i] = value.value;
		} else {
			break;
		}
	}

	if (i == id_num) {
		*value_num = i;
		return IKGT_STATUS_SUCCESS;
	} else {
		*value_num = 0;
		return IKGT_STATUS_ERROR;
	}
}

ikgt_status_t write_vmcs_guest_state(const guest_vcpu_t *vcpu_id,
									 uint32_t		num,
									 ikgt_vmcs_guest_state_reg_id_t
									 reg_ids[],
									 uint64_t		reg_values[])
{
	uint32_t i;
	boolean_t success = TRUE;
	mon_guest_state_value_t value;
	mon_guest_state_t id = (mon_guest_state_t)0;

	/* Only RIP, RSP, RFLAGS, IDTR BASE and LIMIT are supported */
	for (i = 0; i < num; i++) {
		/* the value to be written to register */
		value.value = reg_values[i];

		switch (reg_ids[i]) {
		case VMCS_GUEST_STATE_RIP:
			id = MON_GUEST_RIP;
			value.skip_rip = FALSE;
			break;
		case VMCS_GUEST_STATE_RFLAGS:
			id = MON_GUEST_RFLAGS;
			break;
		case VMCS_GUEST_STATE_IDTR_BASE:
			id = MON_GUEST_IDTR_BASE;
			break;
		case VMCS_GUEST_STATE_IDTR_LIMIT:
			id = MON_GUEST_IDTR_LIMIT;
			break;
		case VMCS_GUEST_STATE_CR0:
			id = MON_GUEST_CR0;
			break;
		case VMCS_GUEST_STATE_CR4:
			id = MON_GUEST_CR4;
			break;
		case IA32_GP_RAX ... IA32_GP_R15:
			id = (mon_guest_state_t)reg_ids[i];
			break;
		default:
			/* Cannot reach here */
			MON_DEADLOOP();
		}

		success = xmon_set_vmcs_guest_state(vcpu_id, id, value);
		if (TRUE != success) {
			MON_LOG(mask_plugin, level_error,
				"CPU%d: %s: current_view=%d, current_index=%d:" \
				" Error: set vmcs guest state failed.\n",
				vcpu_id->guest_cpu_id, __FUNCTION__,
				get_active_view(vcpu_id), i);
			return IKGT_STATUS_ERROR;
		}
	}
	return IKGT_STATUS_SUCCESS;
}

ikgt_status_t __monitor_cpu_events(const guest_vcpu_t *vcpu_id,
											   ikgt_cpu_event_params_t *params)
{
	ikgt_status_t status;
	ikgt_monitor_cpu_params_t cpu_params;
	uint64_t cpu_bitmap[CPU_BITMAP_MAX];
	ikgt_guest_state_t *ikgt_guest = NULL;
	uint32_t ret;

	if (check_monitor_cpu_events_params(params) != IKGT_STATUS_SUCCESS) {
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: Invalid input arguments.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		return IKGT_STATUS_ERROR;
	}

	mon_memcpy(cpu_bitmap, params->cpu_bitmap, sizeof(cpu_bitmap));
	BITMAP_ARRAY64_CHECKBITS_ALLZERO(cpu_bitmap, CPU_BITMAP_MAX, ret);

	/* Build bitmap to only monitor current cpu */
	if (ret == 1) {
		BITMAP_ARRAY64_SET(cpu_bitmap, vcpu_id->guest_cpu_id);
	}

	switch (params->cpu_reg) {
	case IKGT_CPU_REG_CR0:
		cpu_params.cr0.enable = params->enable;
		cpu_params.cr0.cr0_mask = params->crx_mask.cr0;
		status = internal_x_monitor_cr0_load(vcpu_id, &cpu_params.cr0,
			cpu_bitmap);
		break;

	case IKGT_CPU_REG_CR4:
		cpu_params.cr4.enable = params->enable;
		cpu_params.cr4.cr4_mask = params->crx_mask.cr4;
		status = internal_x_monitor_cr4_load(vcpu_id, &cpu_params.cr4,
			cpu_bitmap);
		break;

	default:
		status = IKGT_STATUS_ERROR;
		break;
	}

	return status;
}

void build_event_info(const guest_vcpu_t *vcpu_id,
					  ikgt_event_info_t *event_info,
					  ikgt_cpu_event_info_t *cpu_event_info,
					  ikgt_cpu_event_op_t		optype,
					  ikgt_cpu_event_dirn_t	opdirn,
					  ikgt_cpu_reg_t		event_reg,
					  ikgt_cpu_reg_t		operand_reg,
					  uint64_t			operand_gva,
					  ikgt_event_type_t	type)
{
	gpa_t operand_gpa;

	mon_memset(event_info, 0, sizeof(ikgt_event_info_t));
	mon_memset(cpu_event_info, 0, sizeof(ikgt_cpu_event_info_t));

	cpu_event_info->optype = optype;
	cpu_event_info->opdirn = opdirn;
	cpu_event_info->event_reg = event_reg;

	if (IKGT_CPU_EVENT_OP_REG == optype) {
		cpu_event_info->operand_reg = operand_reg;
	} else {
		cpu_event_info->operand_reg = IKGT_CPU_REG_UNKNOWN;
	}

	if (IKGT_CPU_EVENT_OP_MEM == optype) {
		cpu_event_info->operand_gva = operand_gva;

		/* If xmon_gva_to_gpa succeeds operand_gpa will have the correct
		* value of gpa. Else we set it to invalid physical address. Pass
		* this event to handler even though gva_to_gpa failed to ensure
		* handler gets a chance to analyze this event. Handler can choose to
		* ALLOW this event.
		* xmon_gva_to_gpa can fail in cases such as this:
		* it could be an instruction like SIDT with memory not paged in.
		* We get SIDT VMEXIT first, we need to return to guest to handle the
		* page fault. */
		if (xmon_gva_to_gpa(vcpu_id, (gva_t)operand_gva, &operand_gpa)) {
			cpu_event_info->operand_gpa = (uint64_t)operand_gpa;
		} else {
			/* Set invalid address */
			cpu_event_info->operand_gpa = HIGHEST_ACCEPTABLE_PHYSICAL_ADDRESS;
		}
	}

	event_info->type = type;
	event_info->thread_id = (uint32_t)vcpu_id->guest_cpu_id;

	event_info->event_specific_data = (uint64_t)cpu_event_info;
	event_info->view_handle = (uint32_t)get_active_view(vcpu_id);
	/* Initializes event info response to
	* IKGT_EVENT_RESPONSE_UNSPECIFIED first */
	event_info->response = IKGT_EVENT_RESPONSE_UNSPECIFIED;
	get_vmcs_guest_state(vcpu_id, &(event_info->vmcs_guest_state));
}

/*-------------------------------------------------------*
*  FUNCTION : handle_response()
*  PURPOSE  : It's called after handler_report_event().
*             It is served as the universal handling
*             function, based on event type or MTF type.
*  ARGUMENTS: IN vcpu_id    - virtual Guest CPU
*             IN event_info - Include event type, response
*                             event specific response,
*                             thread_id which are needed
*                             during handling response
*             IN param      - Include MTF type, msr ID,
*                             cr related params which are
*                             needed for mtf_enable()
*  RETURNS  : TRUE  - handled in this function
*             FALSE - not handled, leave it to caller
*-------------------------------------------------------*/
boolean_t handle_response(const guest_vcpu_t *vcpu_id,
						  ikgt_event_info_t *event_info,
						  ikgt_enable_mtf_param_t *param)
{
	ia32_vmx_exit_qualification_t cr_qualification;
	mon_guest_state_value_t value;
	ikgt_cpu_event_info_t *cpu_event_info = NULL;

	if (IKGT_EVENT_RESPONSE_ALLOW == event_info->response) {
		/* mtf_type of IKGT_MTF_TYPE_NONE means do nothing */
		cr_qualification.uint64 = param->qualification;

		switch (param->mtf_type) {
		case IKGT_MTF_TYPE_CR0_LOAD:
			if (cr_qualification.cr_access.access_type == 3) {
				/* LMSW - affects only 4 bits PE, MP, EM, TS */
				if (mtf_check_for_cr_guest_update(vcpu_id, param->qualification)) {
					mtf_enable(vcpu_id, param->mtf_type, FALSE);
					return TRUE;
				}
				return FALSE;
			}

			/* no break, keep going down */
		case IKGT_MTF_TYPE_CR4_LOAD:
			if (cr_qualification.cr_access.access_type == 0) {
				/* mov to CR0/CR4 */
				if (mtf_check_for_cr_mov(vcpu_id, param->qualification,
					param->cr_id, param->operand)) {
						mtf_enable(vcpu_id, param->mtf_type, FALSE);
						return TRUE;
				}
			}
			return FALSE;

		case IKGT_MTF_TYPE_MSR_ACCESS:
			if (IA32_MSR_EFER == param->msr_id || IA32_MSR_PAT == param->msr_id) {
				if (mtf_check_for_msr(vcpu_id, param->msr_id)) {
					mtf_enable(vcpu_id, param->mtf_type, FALSE);
					return TRUE;
				}
			}
			return FALSE;

		case IKGT_MTF_TYPE_NONE:
		default:
			break;
		}

		switch (event_info->type) {
		case IKGT_EVENT_TYPE_MEM:
			/* EPT violation */
			ept_mtf_enable(vcpu_id, FALSE);
			return TRUE;

		default:
			/* Response NOT HANDLED */
			return FALSE;
		}
	} else if (IKGT_EVENT_RESPONSE_REDIRECT == event_info->response) {
		switch (event_info->type) {
		case IKGT_EVENT_TYPE_MEM:
			/* EPT violation */
			skip_guest_instruction(vcpu_id);
			return TRUE;

		case IKGT_EVENT_TYPE_CPU:
			cpu_event_info = (ikgt_cpu_event_info_t *)
				event_info->event_specific_data;

			if (cpu_event_info->optype == IKGT_CPU_EVENT_OP_CPUID) {
				return TRUE;
			}

			if ((IKGT_CPU_EVENT_OP_MSR == cpu_event_info->optype)
				|| (IKGT_CPU_REG_CR0 == cpu_event_info->event_reg)
				|| (IKGT_CPU_REG_CR4 == cpu_event_info->event_reg)
				|| (IKGT_CPU_REG_GDTR == cpu_event_info->event_reg)
				|| (IKGT_CPU_REG_IDTR == cpu_event_info->event_reg)) {
					skip_guest_instruction(vcpu_id);
					return TRUE;
			} else {
				xmon_inject_exception(vcpu_id, EXCEPTION_TYPE_UD);
			}
			return TRUE;

		default:
			/* Response NOT HANDLED */
			return FALSE;
		}
	} else if (IKGT_EVENT_RESPONSE_EXCEPTION == event_info->response) {
		/* Inject exception */
		xmon_inject_exception(
			vcpu_id, (exception_type_t)event_info->event_specific_response);
		return TRUE;
	}

	/* Leave switchview to caller function to handle */
	return FALSE;
}

