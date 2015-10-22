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
#include "ikgt_internal.h"

#define MON_DEADLOOP()          MON_DEADLOOP_LOG(IKGT_MTF_C)
#define MON_ASSERT(__condition) MON_ASSERT_LOG(IKGT_MTF_C, __condition)

#include "em64t_defs.h"

#define MTF_COUNT_LIMIT 6

#define VMEXIT_REASON_MTF 37


typedef struct {
	/* Used in Nested MTF */
	uint32_t	mtf_count;                      /* Maintains the count of violations */
	ikgt_mtf_type_t mtf_mode[MTF_COUNT_LIMIT];      /* Maintains the mode of violations */
	uint32_t	padding;

	/* Used in MTF enabled for MSR Violation */
	uint64_t	msr_bitmap;            /* Stores the original MSR Bitmap */

	/* Used in MTF enabled for EPT Violation */
	uint32_t	mtf_view_handle;        /* Stores the original View Handle */
	uint16_t	dummy_ept_in_use;       /* Indicates whether Dummy View in use */
	uint16_t	single_step;            /* Indicates whether Handler requested response on completion */

	uint64_t	fault_rip;              /* Stores the RIP on which Violation occurred */
	uint64_t	next_rip;               /* Stores the next RIP after the violating instruction. Used in SingleStep */
} mtf_guest_cpu_state_t;

typedef struct {
	mtf_guest_cpu_state_t **gcpu_state;     /* Indicates the CPU states for this guest */
	guest_id_t		guest_id;       /* Indicates the Guest ID of this guest */
	uint8_t			padding[6];
	list_element_t		list[1];
} mtf_guest_state_t;

typedef struct {
	list_element_t	guest_state[1];
	uint32_t	num_of_cpus;           /* Indicates the number of cpus on the system */
	uint32_t	padding;
} mtf_state_t;

static uint64_t *zero_filled_msr_bitmap;
static mtf_state_t mtf_state;


static void mtf_guest_initialize(guest_id_t guest_id)
{
	uint32_t i;
	mtf_guest_state_t *mtf_guest = NULL;

	mtf_guest = (mtf_guest_state_t *)mon_malloc(sizeof(mtf_guest_state_t));

	MON_ASSERT(mtf_guest);

	mtf_guest->guest_id = guest_id;
	list_add(mtf_state.guest_state, mtf_guest->list);

	mtf_guest->gcpu_state = (mtf_guest_cpu_state_t **)mon_malloc(mtf_state.num_of_cpus * sizeof(mtf_guest_cpu_state_t *));
	MON_ASSERT(mtf_guest->gcpu_state);
	for (i = 0; i < mtf_state.num_of_cpus; i++) {
		(mtf_guest->gcpu_state)[i] = (mtf_guest_cpu_state_t *)mon_malloc(sizeof(mtf_guest_cpu_state_t));
		MON_ASSERT((mtf_guest->gcpu_state)[i]);
		mon_zeromem((mtf_guest->gcpu_state)[i], sizeof(mtf_guest_cpu_state_t));
	}
}

void init_mtf(uint32_t num_of_cpus, guest_data_t *guest_data)
{
	uint32_t i = 0;

	mon_zeromem(&mtf_state, sizeof(mtf_state));
	mtf_state.num_of_cpus = num_of_cpus;

	list_init(mtf_state.guest_state);

	for (i = 0; (i < MAX_GUESTS_SUPPORTED_BY_XMON) && (guest_data[i].guest_id != INVALID_GUEST_ID); i++)
		/* Register MTF for all guests (primary and secondary) */
			mtf_guest_initialize(guest_data[i].guest_id);

	zero_filled_msr_bitmap = mon_memory_alloc(PAGE_4KB_SIZE);
	/* BEFORE_VMLAUNCH. MALLOC should not fail. */
	MON_ASSERT(zero_filled_msr_bitmap);
}

static mtf_guest_state_t *mtf_find_guest_state(guest_id_t guest_id)
{
	mtf_guest_state_t *mtf_guest_state = NULL;
	list_element_t *iter = NULL;
	boolean_t found = FALSE;

	LIST_FOR_EACH(mtf_state.guest_state, iter) {
		mtf_guest_state = LIST_ENTRY(iter, mtf_guest_state_t, list);
		if (mtf_guest_state->guest_id == guest_id) {
			found = TRUE;
			break;
		}
	}
	if (found) {
		return mtf_guest_state;
	}
	return NULL;
}

boolean_t is_cpu_event_mtf_in_progress(const guest_vcpu_t *vcpu_id, ikgt_mtf_type_t type)
{
	mtf_guest_cpu_state_t *mtf_guest_cpu;
	mtf_guest_state_t *mtf_guest = NULL;
	uint32_t i;
	mon_controls_t value;

	value.value = 0;
	MON_ASSERT(xmon_get_vmcs_control_state(vcpu_id, MON_EXIT_INFO_REASON, &value));

	if (value.value == IA32_VMX_EXIT_BASIC_REASON_MONITOR_TRAP_FLAG) {
		return FALSE;
	}

	mtf_guest = mtf_find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(mtf_guest);
	mtf_guest_cpu = mtf_guest->gcpu_state[vcpu_id->guest_cpu_id];

	for (i = 0; i < mtf_guest_cpu->mtf_count; i++)
		if (mtf_guest_cpu->mtf_mode[i] == type) {
			return TRUE;
		}

		return FALSE;
}

static boolean_t mtf_hw_enable(const guest_vcpu_t *vcpu_id)
{
	mtf_guest_cpu_state_t *mtf_guest_cpu;
	mtf_guest_state_t *mtf_guest = NULL;
	mon_controls_t value;
	mon_guest_state_value_t guest_value;
	uint64_t value1;

	value.value = 0;

	if (FALSE == xmon_get_vmcs_control_state(vcpu_id, MON_CONTROL_VECTOR_PROCESSOR_EVENTS, &value)) {
		return FALSE;
	}

	value1 = value.value;
	value.value = 0;
	value.mask_value.mask = 0;
	value.mask_value.value = value1 | 0x8000000;

	if (FALSE == xmon_set_vmcs_control_state(vcpu_id, MON_CONTROL_VECTOR_PROCESSOR_EVENTS, &value)) {
		return FALSE;
	}

	mtf_guest = mtf_find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(mtf_guest);
	mtf_guest_cpu = mtf_guest->gcpu_state[vcpu_id->guest_cpu_id];
	if (0 == mtf_guest_cpu->mtf_count) {
		/* Save Current/Faulting RIP */
		if (FALSE == xmon_get_vmcs_guest_state(vcpu_id, MON_GUEST_RIP, &guest_value)) {
			return FALSE;
		}
		mtf_guest_cpu->fault_rip = guest_value.value;
		/* Calculate Next RIP */
		if (FALSE == xmon_get_vmcs_control_state(vcpu_id, MON_EXIT_INFO_INSTRUCTION_LENGTH, &value)) {
			return FALSE;
		}
		mtf_guest_cpu->next_rip = mtf_guest_cpu->fault_rip + value.value;
	}


	return TRUE;
}

static boolean_t mtf_hw_disable(const guest_vcpu_t *vcpu_id)
{
	mon_controls_t value;
	uint64_t value1;

	value.value = 0;
	if (FALSE == xmon_get_vmcs_control_state(vcpu_id, MON_CONTROL_VECTOR_PROCESSOR_EVENTS, &value)) {
		return FALSE;
	}

	value1 = value.value;
	value.value = 0;
	value.mask_value.mask = 0;
	value.mask_value.value = value1 & ~0x8000000;

	return xmon_set_vmcs_control_state(vcpu_id, MON_CONTROL_VECTOR_PROCESSOR_EVENTS, &value);
}

boolean_t mtf_enable(const guest_vcpu_t *vcpu_id, ikgt_mtf_type_t type,
					 boolean_t single_step)
{
	boolean_t status = FALSE;
	mtf_guest_cpu_state_t *mtf_guest_cpu;
	mtf_guest_state_t *mtf_guest = NULL;
	uint64_t msr_bitmap;
	mon_controls_t value;
	ikgt_guest_state_t *ikgt_guest = NULL;

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);
	value.value = 0;


	mtf_guest = mtf_find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(mtf_guest);
	mtf_guest_cpu = mtf_guest->gcpu_state[vcpu_id->guest_cpu_id];

	if (0 == mtf_guest_cpu->mtf_count) {
		status = mtf_hw_enable(vcpu_id);
	} else {
		status = TRUE;
	}

	/* Set whether MTF completion event is to be reported to handler */
	mtf_guest_cpu->single_step = (uint16_t)single_step;

	if (status) {
		switch (type) {
		case IKGT_MTF_TYPE_CR3_LOAD:
			/* Disable on current CPU */
			if (ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id]->monitor_regs.cr3_load == FALSE) {
				enable_cr3load_vmexit(vcpu_id->guest_cpu_id, (void *)ikgt_guest);
			}

			mtf_guest_cpu->mtf_mode[mtf_guest_cpu->mtf_count] = IKGT_MTF_TYPE_CR3_LOAD;
			mtf_guest_cpu->mtf_count++;
			MON_ASSERT(mtf_guest_cpu->mtf_count <= MTF_COUNT_LIMIT);
			modify_cr3_vmexit_vmcs_control_bit(FALSE);
			break;
		case IKGT_MTF_TYPE_CR0_LOAD:
			value.mask_value.mask = 0;
			value.mask_value.value = xmon_get_cr0_minimal_settings(vcpu_id);
			xmon_set_vmcs_control_state(vcpu_id, MON_CR0_MASK, &value);

			mtf_guest_cpu->mtf_mode[mtf_guest_cpu->mtf_count] = IKGT_MTF_TYPE_CR0_LOAD;
			mtf_guest_cpu->mtf_count++;
			MON_ASSERT(mtf_guest_cpu->mtf_count <= MTF_COUNT_LIMIT);
			break;
		case IKGT_MTF_TYPE_CR4_LOAD:
			value.mask_value.mask = 0;
			value.mask_value.value = xmon_get_cr4_minimal_settings(vcpu_id);
			xmon_set_vmcs_control_state(vcpu_id, MON_CR4_MASK, &value);

			mtf_guest_cpu->mtf_mode[mtf_guest_cpu->mtf_count] = IKGT_MTF_TYPE_CR4_LOAD;
			mtf_guest_cpu->mtf_count++;
			MON_ASSERT(mtf_guest_cpu->mtf_count <= MTF_COUNT_LIMIT);
			break;
		case IKGT_MTF_TYPE_MSR_ACCESS:
			/* Save the original value */
			if (FALSE == xmon_get_vmcs_control_state(vcpu_id, MON_MSR_BITMAP_ADDRESS, &value)) {
				return FALSE;
			}
			mtf_guest_cpu->msr_bitmap = value.value;
			msr_bitmap = (uint64_t)zero_filled_msr_bitmap;
			xmon_hva_to_hpa(msr_bitmap, &msr_bitmap);
			value.value = msr_bitmap;
			if (FALSE == xmon_set_vmcs_control_state(vcpu_id, MON_MSR_BITMAP_ADDRESS, &value)) {
				return FALSE;
			}

			mtf_guest_cpu->mtf_mode[mtf_guest_cpu->mtf_count] = IKGT_MTF_TYPE_MSR_ACCESS;
			mtf_guest_cpu->mtf_count++;
			MON_ASSERT(mtf_guest_cpu->mtf_count <= MTF_COUNT_LIMIT);
			break;
		default:
			break;
		}
	} else {
		MON_LOG(mask_plugin, level_error, "CPU%d: %s: Enabling MTF failed\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
	}
	if (mtf_guest_cpu->mtf_count == 0) {
		if (!mtf_hw_disable(vcpu_id)) {
			MON_LOG(mask_plugin, level_error, "CPU%d: %s: Disabling MTF failed\n",
				vcpu_id->guest_cpu_id, __FUNCTION__);
		}
	}
	return status;

	return 0;
}

static boolean_t cpu_mtf_vmexit(const guest_vcpu_t *vcpu_id, ikgt_mtf_type_t type)
{
	ikgt_guest_state_t *ikgt_guest = NULL;

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);

	return TRUE;
}

static boolean_t cr_mtf_vmexit(const guest_vcpu_t *vcpu_id, ikgt_mtf_type_t type, uint32_t i)
{
	mtf_guest_cpu_state_t *mtf_guest_cpu = NULL;
	mtf_guest_state_t *mtf_guest = NULL;
	uint64_t msr_bitmap;
	mon_controls_t value;
	ikgt_guest_state_t *ikgt_guest = NULL;

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);
	value.value = 0;
	i = 0;
	mtf_guest = mtf_find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(mtf_guest);
	mtf_guest_cpu = mtf_guest->gcpu_state[vcpu_id->guest_cpu_id];

	switch (type) {
	case IKGT_MTF_TYPE_CR3_LOAD:
		if (ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id]->monitor_regs.cr3_load == TRUE) {
			modify_cr3_vmexit_vmcs_control_bit(TRUE);
		}
		break;
	case IKGT_MTF_TYPE_CR0_LOAD:
		value.mask_value.mask = 0;
		value.mask_value.value = 0;
		xmon_set_vmcs_control_state(vcpu_id, MON_CR0_MASK, &value);
		break;
	case IKGT_MTF_TYPE_CR4_LOAD:
		value.mask_value.mask = 0;
		value.mask_value.value = 0;
		xmon_set_vmcs_control_state(vcpu_id, MON_CR4_MASK, &value);
		break;
	case IKGT_MTF_TYPE_MSR_ACCESS:
		msr_bitmap = mtf_guest_cpu->msr_bitmap;
		xmon_hva_to_hpa(msr_bitmap, &msr_bitmap);
		value.value = msr_bitmap;
		if (FALSE == xmon_set_vmcs_control_state(vcpu_id, MON_MSR_BITMAP_ADDRESS, &value)) {
			return FALSE;
		}
		break;
	default:
		MON_ASSERT(0);
	}

	return TRUE;
}

boolean_t mtf_check_for_msr(const guest_vcpu_t *vcpu_id, msr_id_t msr_id)
{
	switch (msr_id) {
	case IA32_MSR_EFER:
		if (xmon_is_unrestricted_guest_supported() ||
			((get_guest_visible_CR_value(vcpu_id, IA32_CTRL_CR0) & CR0_PG) == CR0_PG)) {
				return TRUE;
		}
		break;
	case IA32_MSR_PAT:
		return TRUE;
	default:
		break;
	}

	return FALSE;
}

CALLBACK boolean_t ikgt_report_event_mtf_vmexit(const guest_vcpu_t *vcpu_id)
{
	boolean_t status = TRUE;
	mtf_guest_cpu_state_t *mtf_guest_cpu;
	mtf_guest_state_t *mtf_guest = NULL;
	mon_guest_state_value_t value;
	uint32_t i;
	boolean_t mtf_for_single_step = FALSE;

	mtf_guest = mtf_find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(mtf_guest);
	mtf_guest_cpu = mtf_guest->gcpu_state[vcpu_id->guest_cpu_id];

	for (i = 0; i < mtf_guest_cpu->mtf_count; i++) {
		if (mtf_guest_cpu->single_step) {
			mtf_for_single_step = TRUE;
		}
		switch (mtf_guest_cpu->mtf_mode[i]) {
		case IKGT_MTF_TYPE_DATA_ALLOW:
			break;
		case IKGT_MTF_TYPE_EXEC_FAULT:
			/* Currently Execution Fault and Data Allow follow the same path and */
			/* IKGT_MTF_TYPE_DATA_ALLOW is used for both the cases */
			MON_DEADLOOP();
			break;
		case IKGT_MTF_TYPE_CPU_DTE:
			status = status && cpu_mtf_vmexit(vcpu_id, IKGT_MTF_TYPE_CPU_DTE);
			break;
		case IKGT_MTF_TYPE_CR3_LOAD:
			status = status && cr_mtf_vmexit(vcpu_id, IKGT_MTF_TYPE_CR3_LOAD, i);
			break;
		case IKGT_MTF_TYPE_CR0_LOAD:
			status = status && cr_mtf_vmexit(vcpu_id, IKGT_MTF_TYPE_CR0_LOAD, i);
			break;
		case IKGT_MTF_TYPE_CR4_LOAD:
			status = status && cr_mtf_vmexit(vcpu_id, IKGT_MTF_TYPE_CR4_LOAD, i);
			break;
		case IKGT_MTF_TYPE_MSR_ACCESS:
			status = status && cr_mtf_vmexit(vcpu_id, IKGT_MTF_TYPE_MSR_ACCESS, i);
			break;
		case IKGT_MTF_TYPE_CPU_HALT:
			status = status && cr_mtf_vmexit(vcpu_id, IKGT_MTF_TYPE_CPU_HALT, i);
			break;
		default:
			MON_ASSERT(0);
		}
	}

	/* Disable MTF */
	if (mtf_guest_cpu->mtf_count > 0) { /* Redundant Check */
		if (!mtf_hw_disable(vcpu_id)) {
			MON_LOG(mask_plugin, level_error, "CPU%d: %s: Disabling MTF failed\n",
				vcpu_id->guest_cpu_id, __FUNCTION__);
			MON_ASSERT(0);
		}
	}
	mtf_guest_cpu->mtf_count = 0;

	return status;
}

void ept_mtf_enable(const guest_vcpu_t *vcpu_id, boolean_t single_step)
{
	mtf_guest_cpu_state_t *mtf_guest_cpu;
	mtf_guest_state_t *mtf_guest = NULL;

	mtf_guest = mtf_find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(mtf_guest);
	mtf_guest_cpu = mtf_guest->gcpu_state[vcpu_id->guest_cpu_id];

	mtf_guest_cpu->mtf_view_handle = (uint32_t)get_active_view(vcpu_id);
	if (!set_active_view(vcpu_id, mtf_guest_cpu->mtf_view_handle, TRUE, TRUE)) {
		MON_LOG(mask_plugin, level_error, "Cannot set Dummy EPT for View %d.\n", mtf_guest_cpu->mtf_view_handle);
	}

	mtf_guest_cpu->dummy_ept_in_use = 1;

	if (mtf_guest_cpu->mtf_count == 0) {
		mtf_hw_enable(vcpu_id);
	}

	mtf_guest_cpu->mtf_mode[mtf_guest_cpu->mtf_count] = IKGT_MTF_TYPE_DATA_ALLOW;
	mtf_guest_cpu->single_step = (uint16_t)single_step;
	mtf_guest_cpu->mtf_count++;
	MON_ASSERT(mtf_guest_cpu->mtf_count <= MTF_COUNT_LIMIT);
}

boolean_t is_dummy_view_in_use(const guest_vcpu_t *vcpu_id)
{
	mtf_guest_cpu_state_t *mtf_guest_cpu;
	mtf_guest_state_t *mtf_guest = NULL;

	mtf_guest = mtf_find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(mtf_guest);
	mtf_guest_cpu = mtf_guest->gcpu_state[vcpu_id->guest_cpu_id];

	return mtf_guest_cpu->dummy_ept_in_use;
}


static
boolean_t ept_mtf_vmexit(const guest_vcpu_t *vcpu_id, uint64_t current_cpu_rip)
{
	mtf_guest_cpu_state_t *mtf_guest_cpu;
	mtf_guest_state_t *mtf_guest = NULL;
	ikgt_guest_state_t *ikgt_guest = NULL;
	uint32_t i;

	mtf_guest = mtf_find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(mtf_guest);
	mtf_guest_cpu = mtf_guest->gcpu_state[vcpu_id->guest_cpu_id];

	MON_ASSERT(mtf_guest_cpu->mtf_count);

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);

	if (ikgt_guest->view_assigned[mtf_guest_cpu->mtf_view_handle]) {
		MON_ASSERT(set_active_view(vcpu_id, mtf_guest_cpu->mtf_view_handle, TRUE, FALSE));
	} else {
		MON_ASSERT(set_active_view(vcpu_id, DEFAULT_VIEW_HANDLE, TRUE, FALSE));
	}

	mtf_guest_cpu->dummy_ept_in_use = 0;

	for (i = 0; i < (uint32_t)mtf_guest_cpu->mtf_count; i++) {
		if (mtf_guest_cpu->mtf_mode[i] != IKGT_MTF_TYPE_DATA_ALLOW) {
			/* This means MTF was enabled for something other than EPT violation as well */
			return FALSE;
		}
	}

	/* Disable MTF */
	mtf_guest_cpu->mtf_count = 0;
	mtf_hw_disable(vcpu_id);


	return TRUE;
}

boolean_t ikgt_report_event_initial_vmexit_check(const guest_vcpu_t *vcpu_id,
						 uint64_t		current_cpu_rip,
						 uint32_t		vmexit_reason)
{
	mtf_guest_cpu_state_t *mtf_guest_cpu;
	mtf_guest_state_t *mtf_guest = NULL;

	mtf_guest = mtf_find_guest_state(vcpu_id->guest_id);
	if (!mtf_guest) {
		return FALSE;
	}
	mtf_guest_cpu = mtf_guest->gcpu_state[vcpu_id->guest_cpu_id];

	if (mtf_guest_cpu->dummy_ept_in_use == 1) {
		if (vmexit_reason == VMEXIT_REASON_MTF) {
			/* Check if MTF VMExit occurred on the faulting RIP (RIP for which MTF was enabled) */
			/* Example: REP-prefixed string instruction */
			if (current_cpu_rip == mtf_guest_cpu->fault_rip) {
				return TRUE;
			} else { /* MTF VMExit occurred NOT on the faulting RIP */
				if (ept_mtf_vmexit(vcpu_id, current_cpu_rip)) {
					mtf_guest_cpu->fault_rip = 0;   /* Reset the state */
					mtf_guest_cpu->next_rip = 0;    /* Reset the state */
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}
