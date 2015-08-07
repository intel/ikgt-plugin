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

#define MON_DEADLOOP()          MON_DEADLOOP_LOG(IKGT_CR_C)
#define MON_ASSERT(__condition) MON_ASSERT_LOG(IKGT_CR_C, __condition)

#include "vmx_ctrl_msrs.h"

static mon_ia32_gp_registers_t lkup_operand[] = {
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

static mon_ia32_control_registers_t lkup_cr[] = {
	IA32_CTRL_CR0,
	UNSUPPORTED_CR,
	UNSUPPORTED_CR,
	IA32_CTRL_CR3,
	IA32_CTRL_CR4,
	UNSUPPORTED_CR,
	UNSUPPORTED_CR,
	UNSUPPORTED_CR,
	IA32_CTRL_CR8
};


static mon_ia32_control_registers_t get_cr_from_qualification(uint64_t qualification)
{
	ia32_vmx_exit_qualification_t qualification_tmp;
	mon_ia32_control_registers_t cr_id;

	qualification_tmp.uint64 = qualification;
	MON_ASSERT(qualification_tmp.cr_access.number < NELEMENTS(lkup_cr));

	cr_id = lkup_cr[qualification_tmp.cr_access.number];
	MON_ASSERT(UNSUPPORTED_CR != cr_id);

	return cr_id;
}

static mon_ia32_gp_registers_t get_operand_from_qualification(uint64_t qualification)
{
	ia32_vmx_exit_qualification_t qualification_tmp;

	qualification_tmp.uint64 = qualification;
	MON_ASSERT(qualification_tmp.cr_access.move_gpr < NELEMENTS(lkup_operand));
	return lkup_operand[qualification_tmp.cr_access.move_gpr];
}

boolean_t mtf_check_for_cr_mov(
	const guest_vcpu_t *vcpu_id,
	uint64_t			qualification,
	mon_ia32_control_registers_t	cr_id,
	mon_ia32_gp_registers_t		operand
	)
{
	address_t cr_value;
	mon_guest_state_value_t value;
	mon_guest_state_t state_id;
	mon_controls_t cr_read_shadow;
	uint64_t visible_cr0;
	ia32_vmx_exit_qualification_t cr_qualification;

	value.value = 0;
	cr_read_shadow.value = 0;
	cr_qualification.uint64 = qualification;

	switch (cr_qualification.cr_access.access_type) {
	case 0: /* move to CR */
		if (operand < IA32_REG_RIP) {
			state_id = (mon_guest_state_t)operand;
		} else {
			return FALSE;
		}

		if (FALSE == xmon_get_vmcs_guest_state(vcpu_id, state_id, &value)) {
			return FALSE;
		}
		cr_value = value.value;

		visible_cr0 = get_guest_visible_CR_value(vcpu_id, IA32_CTRL_CR0);

		switch (cr_id) {
		case IA32_CTRL_CR0:
			if (FALSE == xmon_get_vmcs_control_state(vcpu_id,
				MON_CR0_READ_SHADOW, &cr_read_shadow)) {
					return FALSE;
			}
			if ((xmon_is_unrestricted_guest_supported() ||
				((visible_cr0 & CR0_PG) == CR0_PG)) &&
				((cr_read_shadow.value & xmon_get_cr0_minimal_settings(vcpu_id))
				== (cr_value & xmon_get_cr0_minimal_settings(vcpu_id)))) {
					return TRUE;
			}
			break;
		case IA32_CTRL_CR3:
			if (xmon_is_unrestricted_guest_supported() ||
				((visible_cr0 & CR0_PG) == CR0_PG)) {
					return TRUE;
			}
			break;
		case IA32_CTRL_CR4:
			if (FALSE == xmon_get_vmcs_control_state(vcpu_id, MON_CR4_READ_SHADOW,
				&cr_read_shadow)) {
					return FALSE;
			}
			if ((xmon_is_unrestricted_guest_supported() ||
				((visible_cr0 & CR0_PG) == CR0_PG)) &&
				((cr_read_shadow.value & xmon_get_cr4_minimal_settings(vcpu_id))
				== (cr_value & xmon_get_cr4_minimal_settings(vcpu_id)))) {
					return TRUE;
			}
			break;
		default:
			return FALSE;
			break;
		}
		;
		break;

	case 1: /* move from CR */
		return FALSE;
		break;

	default:
		MON_DEADLOOP();
		break;
	}

	return FALSE;
}

boolean_t mtf_check_for_cr_guest_update(const guest_vcpu_t *vcpu_id, uint64_t qualification)
{
	address_t value;
	ia32_vmx_exit_qualification_t cr_qualification;
	mon_controls_t cr_read_shadow;

	cr_read_shadow.value = 0;
	cr_qualification.uint64 = qualification;

	if (cr_qualification.cr_access.access_type == 3) {
		value = cr_qualification.cr_access.lmsw_data;
	} else {
		value = 0;
	}

	if (xmon_is_unrestricted_guest_supported()) {
		if (FALSE == xmon_get_vmcs_control_state(vcpu_id, MON_CR0_READ_SHADOW, &cr_read_shadow)) {
			return FALSE;
		}
		if ((cr_read_shadow.value & xmon_get_cr0_minimal_settings(vcpu_id) & 0xf)
			== (value & xmon_get_cr0_minimal_settings(vcpu_id) & 0xf)) {
				return TRUE;
		}
	}

	return FALSE;
}

void enable_cr0load_vmexit(cpu_id_t from UNUSED, void *arg)
{
	ikgt_guest_state_t *ikgt_guest = (ikgt_guest_state_t *)arg;
	const guest_vcpu_t *vcpu_id = NULL;
	uint64_t old_mask = 0, new_mask = 0, mask = 0;
	mon_controls_t value;

	vcpu_id = xmon_get_guest_vcpu();
	MON_ASSERT(vcpu_id);

	value.value = 0;
	value.mask_value.value = UINT64_ALL_ONES;

	mask = ikgt_guest->cr0_mask;
	old_mask = ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id]->ikgt_monitor_cr0_mask;

	/* old | new gives all bits needed to be enabled. */
	/* Then & with those bits previously not enabled to get new ones only. */
	new_mask = old_mask | mask;
	new_mask = new_mask & (~old_mask);

	if ((old_mask != mask) && new_mask) {
		/* Enable VMExit for new bits */
		value.mask_value.mask = new_mask;
		if (TRUE == xmon_set_vmcs_control_state(vcpu_id, MON_CR0_MASK, &value)) {
			ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id]->ikgt_monitor_cr0_mask = old_mask | mask;
		}
	}
}

void disable_cr0load_vmexit(cpu_id_t from UNUSED, void *arg)
{
	ikgt_guest_state_t *ikgt_guest = (ikgt_guest_state_t *)arg;
	const guest_vcpu_t *vcpu_id = NULL;
	uint64_t old_mask = 0, new_mask = 0, mask = 0;
	mon_controls_t value;

	vcpu_id = xmon_get_guest_vcpu();
	MON_ASSERT(vcpu_id);

	value.value = 0;
	value.mask_value.value = 0;
	mask = ikgt_guest->cr0_mask;

	old_mask = ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id]->ikgt_monitor_cr0_mask;

	/* Only bits that were previously enabled are disabled */
	new_mask = old_mask & mask;

	if (new_mask) {
		/* Disable VMExit for new bits */
		value.mask_value.mask = new_mask;
		if (TRUE == xmon_set_vmcs_control_state(vcpu_id, MON_CR0_MASK, &value)) {
			ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id]->ikgt_monitor_cr0_mask = old_mask & (~mask);
		}
	}
}

ikgt_status_t __monitor_cr0_load(const guest_vcpu_t *vcpu_id,
									ikgt_monitor_cr0_load_params_t *params,
									uint64_t *cpu_bitmap)
{
	ipc_destination_t ipc_dest;
	ikgt_guest_state_t *ikgt_guest = NULL;

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	if (!ikgt_guest) {
		return IKGT_STATUS_ERROR;
	}

	ikgt_guest->cr0_mask = params->cr0_mask.uint64;

	BUILD_IPC_BITMAP(cpu_bitmap, ipc_dest);

	if (params->enable) {
		/* Enable on current CPU */
		if (BITMAP_ARRAY64_GET(cpu_bitmap, vcpu_id->guest_cpu_id)) {
			enable_cr0load_vmexit(vcpu_id->guest_cpu_id, (void *)ikgt_guest);
		}

		/* Send IPC to other CPUs */
		ipc_execute_handler_sync(ipc_dest, enable_cr0load_vmexit, (void *)ikgt_guest);
	} else {
		/* Disable on current CPU */
		if (BITMAP_ARRAY64_GET(cpu_bitmap, vcpu_id->guest_cpu_id)) {
			disable_cr0load_vmexit(vcpu_id->guest_cpu_id, (void *)ikgt_guest);
		}

		/* Send IPC to other CPUs */
		ipc_execute_handler_sync(ipc_dest, disable_cr0load_vmexit, (void *)ikgt_guest);
	}

	return IKGT_STATUS_SUCCESS;
}

boolean_t modify_cr3_vmexit_vmcs_control_bit(boolean_t onoff)
{
	const guest_vcpu_t *vcpu_id = NULL;
	processor_based_vm_execution_controls_t proc_exec_controls_mask;
	mon_controls_t value;

	vcpu_id = xmon_get_guest_vcpu();
	MON_ASSERT(vcpu_id);
	value.value = 0;

	/* enable vmexit on cr3_load. */
	proc_exec_controls_mask.uint32 = 0;
	proc_exec_controls_mask.bits.cr3_load = 1;
	value.mask_value.mask = (uint64_t)(proc_exec_controls_mask.uint32);

	if (onoff) {
		value.mask_value.value = UINT64_ALL_ONES;
	} else {
		value.mask_value.value = 0;
	}

	return xmon_set_vmcs_control_state(vcpu_id, MON_CONTROL_VECTOR_PROCESSOR_EVENTS, &value);
}

void enable_cr3load_vmexit(cpu_id_t from UNUSED, void *arg)
{
	ikgt_guest_state_t *ikgt_guest = (ikgt_guest_state_t *)arg;
	const guest_vcpu_t *vcpu_id = NULL;

	vcpu_id = xmon_get_guest_vcpu();
	MON_ASSERT(vcpu_id);

	if (ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id]->monitor_regs.cr3_load == FALSE) {
		if (is_cpu_event_mtf_in_progress(vcpu_id, IKGT_MTF_TYPE_CR3_LOAD)) {
			ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id]->monitor_regs.cr3_load = TRUE;
		} else
			if (TRUE == modify_cr3_vmexit_vmcs_control_bit(TRUE)) {
				ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id]->monitor_regs.cr3_load = TRUE;
			}
	}
}

void enable_cr4load_vmexit(cpu_id_t from UNUSED, void *arg)
{
	ikgt_guest_state_t *ikgt_guest = (ikgt_guest_state_t *)arg;
	const guest_vcpu_t *vcpu_id = NULL;
	uint64_t old_mask = 0, new_mask = 0, mask = 0;
	mon_controls_t value;

	vcpu_id = xmon_get_guest_vcpu();
	MON_ASSERT(vcpu_id);

	value.value = 0;
	value.mask_value.value = UINT64_ALL_ONES;

	mask = ikgt_guest->cr4_mask;
	old_mask = ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id]->ikgt_monitor_cr4_mask;

	/* old | new gives all bits needed to be enabled. */
	/* Then & with those bits previously not enabled to get new ones only. */
	new_mask = old_mask | mask;
	new_mask = new_mask & (~old_mask);

	if ((old_mask != mask) && new_mask) {
		/* Enable VMExit for new bits */
		value.mask_value.mask = new_mask;
		if (TRUE == xmon_set_vmcs_control_state(vcpu_id, MON_CR4_MASK, &value)) {
			ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id]->ikgt_monitor_cr4_mask = old_mask | mask;
		}
	}
}

void disable_cr4load_vmexit(cpu_id_t from UNUSED, void *arg)
{
	ikgt_guest_state_t *ikgt_guest = (ikgt_guest_state_t *)arg;
	const guest_vcpu_t *vcpu_id = NULL;
	uint64_t old_mask = 0, new_mask = 0, mask = 0;
	mon_controls_t value;

	vcpu_id = xmon_get_guest_vcpu();
	MON_ASSERT(vcpu_id);

	value.value = 0;
	value.mask_value.value = 0;

	mask = ikgt_guest->cr4_mask;
	old_mask = ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id]->ikgt_monitor_cr4_mask;

	/* Only bits that were previously enabled are disabled */
	new_mask = old_mask & mask;

	if (new_mask) {
		/* Disable VMExit for new bits */
		value.mask_value.mask = new_mask;
		if (TRUE == xmon_set_vmcs_control_state(vcpu_id, MON_CR4_MASK, &value)) {
			ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id]->ikgt_monitor_cr4_mask = old_mask & (~mask);
		}
	}
}

ikgt_status_t __monitor_cr4_load(const guest_vcpu_t *vcpu_id, ikgt_monitor_cr4_load_params_t *params, uint64_t *cpu_bitmap)
{
	ipc_destination_t ipc_dest;
	ikgt_guest_state_t *ikgt_guest = NULL;

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	if (!ikgt_guest) {
		return IKGT_STATUS_ERROR;
	}

	ikgt_guest->cr4_mask = params->cr4_mask.uint64;

	BUILD_IPC_BITMAP(cpu_bitmap, ipc_dest);

	if (params->enable) {
		/* Enable on current CPU */
		if (BITMAP_ARRAY64_GET(cpu_bitmap, vcpu_id->guest_cpu_id)) {
			enable_cr4load_vmexit(vcpu_id->guest_cpu_id, (void *)ikgt_guest);
		}

		/* Send IPC to other CPUs */
		ipc_execute_handler_sync(ipc_dest, enable_cr4load_vmexit, (void *)ikgt_guest);
	} else {
		/* Disable on current CPU */
		if (BITMAP_ARRAY64_GET(cpu_bitmap, vcpu_id->guest_cpu_id)) {
			disable_cr4load_vmexit(vcpu_id->guest_cpu_id, (void *)ikgt_guest);
		}

		/* Send IPC to other CPUs */
		ipc_execute_handler_sync(ipc_dest, disable_cr4load_vmexit, (void *)ikgt_guest);
	}

	return IKGT_STATUS_SUCCESS;
}

/*  */
/*IKGT access functions. Called when registers are accessed by intercepts in the execution flow. */
/*  */
CALLBACK boolean_t ikgt_report_event_cr_access(const guest_vcpu_t *vcpu_id,
											   uint64_t qualification)
{
	ikgt_cpu_event_info_t *cpu_event_info = NULL;
	ikgt_event_info_t *event_info = NULL;
	ikgt_guest_state_t *ikgt_guest = NULL;
	ikgt_guest_cpu_state_t *ikgt_guest_cpu = NULL;
	ia32_vmx_exit_qualification_t cr_qualification;
	mon_ia32_control_registers_t cr_id;
	mon_ia32_gp_registers_t operand;
	ikgt_cpu_reg_t operand_reg;
	ikgt_enable_mtf_param_t handle_allow; /* pass necessary params to handle_response() */

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);
	ikgt_guest_cpu = ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id];
	MON_ASSERT(ikgt_guest_cpu);

	cr_qualification.uint64 = qualification;
	cr_id = get_cr_from_qualification(qualification);
	operand = get_operand_from_qualification(qualification);

	operand_reg = lookup_register_from_list(cr_qualification.cr_access.move_gpr);

	/* Save original RIP before handler processing */
	save_old_guest_rip(vcpu_id);

	/* setup event info to call handler */
	event_info = &(ikgt_guest_cpu->p_event_info_handler);
	cpu_event_info = &(ikgt_guest_cpu->ikgt_event_specific_info.cpu_event_handler);
	event_info->response = IKGT_EVENT_RESPONSE_UNSPECIFIED;

	switch (cr_id) {
	case IA32_CTRL_CR0:
		handle_allow.mtf_type = IKGT_MTF_TYPE_CR0_LOAD;
		switch (cr_qualification.cr_access.access_type) {
		case 0: /* move to CR0 */
			if (ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id]->ikgt_monitor_cr0_mask) {
				build_event_info(vcpu_id,
					event_info,
					cpu_event_info,
					IKGT_CPU_EVENT_OP_REG,
					IKGT_CPU_EVENT_DIRN_DST,
					IKGT_CPU_REG_CR0,
					operand_reg,
					0,
					IKGT_EVENT_TYPE_CPU);
				if (g_ikgt_event_handlers.cpu_event_handler)
					g_ikgt_event_handlers.cpu_event_handler(event_info);
			} else { /* event not reported to handler, by default do ALLOW */
				if (mtf_check_for_cr_mov(vcpu_id, qualification, cr_id, operand)) {
					mtf_enable(vcpu_id, IKGT_MTF_TYPE_CR0_LOAD, FALSE);
					return TRUE;
				} else {
					return FALSE;
				}
			}
			break;

		case 3: /* LMSW - affects only 4 bits PE, MP, EM, TS */
			if ((ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id]->ikgt_monitor_cr0_mask & 0x0F)) {
				build_event_info(vcpu_id,
					event_info,
					cpu_event_info,
					IKGT_CPU_EVENT_OP_REG,
					IKGT_CPU_EVENT_DIRN_DST,
					IKGT_CPU_REG_CR0,
					operand_reg,
					0,
					IKGT_EVENT_TYPE_CPU);
				if (g_ikgt_event_handlers.cpu_event_handler)
					g_ikgt_event_handlers.cpu_event_handler(event_info);
			} else { /* event not reported to handler, by default do ALLOW */
				if (mtf_check_for_cr_guest_update(vcpu_id, qualification)) {
					mtf_enable(vcpu_id, IKGT_MTF_TYPE_CR0_LOAD, FALSE);
					return TRUE;
				} else {
					return FALSE;
				}
			}
			break;

		default:
			MON_DEADLOOP();
			break;
		}
		break;

	case IA32_CTRL_CR3:
		handle_allow.mtf_type = IKGT_MTF_TYPE_CR3_LOAD;
		switch (cr_qualification.cr_access.access_type) {
		case 0: /* move to CR3 */
			if (ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id]->monitor_regs.cr3_load == TRUE) {
				build_event_info(vcpu_id,
					event_info,
					cpu_event_info,
					IKGT_CPU_EVENT_OP_REG,
					IKGT_CPU_EVENT_DIRN_DST,
					IKGT_CPU_REG_CR3,
					operand_reg,
					0,
					IKGT_EVENT_TYPE_CPU);
				if (g_ikgt_event_handlers.cpu_event_handler)
					g_ikgt_event_handlers.cpu_event_handler(event_info);
			} else { /* event not reported to handler, by default do ALLOW */
				if (mtf_check_for_cr_mov(vcpu_id, qualification, cr_id, operand)) {
					mtf_enable(vcpu_id, IKGT_MTF_TYPE_CR3_LOAD, FALSE);
					return TRUE;
				} else {
					return FALSE;
				}
			}
			break;

		case 1: /* move from CR3 */
			if (!ikgt_guest->monitor_ctrl_regs.cr3_store) {
				return FALSE;
			}

			build_event_info(vcpu_id,
				event_info,
				cpu_event_info,
				IKGT_CPU_EVENT_OP_REG,
				IKGT_CPU_EVENT_DIRN_SRC,
				IKGT_CPU_REG_CR3,
				operand_reg,
				0,
				IKGT_EVENT_TYPE_CPU);
			if (g_ikgt_event_handlers.cpu_event_handler)
				g_ikgt_event_handlers.cpu_event_handler(event_info);
			break;

		default:
			MON_DEADLOOP();
			break;
		}
		break;

	case IA32_CTRL_CR4:
		handle_allow.mtf_type = IKGT_MTF_TYPE_CR4_LOAD;
		switch (cr_qualification.cr_access.access_type) {
		case 0: /* move to CR4 */
			if (ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id]->ikgt_monitor_cr4_mask) {
				build_event_info(vcpu_id,
					event_info,
					cpu_event_info,
					IKGT_CPU_EVENT_OP_REG,
					IKGT_CPU_EVENT_DIRN_DST,
					IKGT_CPU_REG_CR4,
					operand_reg,
					0,
					IKGT_EVENT_TYPE_CPU);
				if (g_ikgt_event_handlers.cpu_event_handler)
					g_ikgt_event_handlers.cpu_event_handler(event_info);
			} else { /* event not reported to handler, by default do ALLOW */
				if (mtf_check_for_cr_mov(vcpu_id, qualification, cr_id, operand)) {
					mtf_enable(vcpu_id, IKGT_MTF_TYPE_CR4_LOAD, FALSE);
					return TRUE;
				} else {
					return FALSE;
				}
			}
			break;

		default:
			MON_DEADLOOP();
			break;
		}
		break;

	default:
		MON_DEADLOOP();
		break;
	}

	/* Expected valid responses */
	MON_ASSERT(IKGT_EVENT_RESPONSE_ALLOW == event_info->response ||
		IKGT_EVENT_RESPONSE_DISPATCHIB == event_info->response ||
		IKGT_EVENT_RESPONSE_REDIRECT == event_info->response ||
		IKGT_EVENT_RESPONSE_EXCEPTION == event_info->response);

	handle_allow.cr_id = cr_id;
	handle_allow.operand = operand;
	handle_allow.qualification = qualification;

	return handle_response(vcpu_id, event_info, &handle_allow);
}



