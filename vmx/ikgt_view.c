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

#define MON_DEADLOOP()          MON_DEADLOOP_LOG(IKGT_VIEW_C)
#define MON_ASSERT(__condition) MON_ASSERT_LOG(IKGT_VIEW_C, __condition)


boolean_t is_invalid_perm(uint32_t perm)
{
	return (perm == EPT_NO_PERM) ||
		(perm == EPT_WO_PERM) ||
		(perm == EPT_WX_PERM) ||
		(!xmon_is_execute_only_supported() && (perm == EPT_XO_PERM));
}

uint64_t get_active_view(const guest_vcpu_t *vcpu_id)
{
	ikgt_guest_state_t *ikgt_guest = NULL;
	ikgt_guest_cpu_state_t *ikgt_guest_cpu = NULL;

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);
	ikgt_guest_cpu = ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id];
	MON_ASSERT(ikgt_guest_cpu);

	MON_ASSERT(ikgt_guest_cpu->active_view < MAX_NUM_VIEWS);
	return ikgt_guest_cpu->active_view;
}

boolean_t set_active_view(const guest_vcpu_t *vcpu_id,
						  ikgt_mem_view_handle_t handle,
						  boolean_t update_hw, boolean_t use_dummy_view)
{
	ikgt_guest_state_t *ikgt_guest = NULL;
	ikgt_guest_cpu_state_t *ikgt_guest_cpu = NULL;
	boolean_t status = FALSE;

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	/* BEFORE_VMLAUNCH. CRITICAL check that should not fail. */
	MON_ASSERT(ikgt_guest);

	ikgt_guest_cpu = ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id];
	/* BEFORE_VMLAUNCH. CRITICAL check that should not fail. */
	MON_ASSERT(ikgt_guest_cpu);

	MON_ASSERT(ikgt_guest->view_assigned[handle]);

	if (use_dummy_view) {
		status = xmon_set_active_view(vcpu_id, ikgt_guest->dummy_view[handle],
			update_hw, handle + DUMMY_VIEW_BASE);
	} else {
		status = xmon_set_active_view(vcpu_id, ikgt_guest->view[handle],
			update_hw, handle);
	}

	if (status) {
		ikgt_guest_cpu->dummy_view_active = use_dummy_view;
		ikgt_guest_cpu->active_view = handle;
	}

	return status;
}

static void set_remote_view(cpu_id_t from, void *arg)
{
	view_set_view_cmd_t *set_view_cmd = arg;
	const guest_vcpu_t *vcpu_id = xmon_get_guest_vcpu();
	view_invalidation_data_t view_invalidation_data;

	MON_ASSERT(vcpu_id);
	MON_ASSERT(arg);

	if (set_view_cmd->handle == get_active_view(vcpu_id)) {
		/* Current view is the same as the view that is being updated */
		if (is_dummy_view_in_use(vcpu_id)) {
			if (set_view_cmd->set_dummy_view) {
				/* Dummy View in use and trying to update Dummy View */
				MON_ASSERT(set_active_view(vcpu_id, set_view_cmd->handle,
					TRUE, TRUE));
			}
		} else {
			if (!set_view_cmd->set_dummy_view) {
				/* Dummy View is not in use and trying to update the view */
				MON_ASSERT(set_active_view(vcpu_id, set_view_cmd->handle,
					TRUE, FALSE));
			}
		}
	}

	view_invalidation_data.guest_id = set_view_cmd->guest_id;
	view_invalidation_data.view = set_view_cmd->view;
	xmon_invalidate_view(vcpu_id->guest_cpu_id,
		(void *)&view_invalidation_data);
}

static
	boolean_t end_view_modification_before_cpus_resume(const guest_vcpu_t *vcpu_id,
	view_modification_data_t
	*view_modification_data)
{
	view_set_view_cmd_t set_view_cmd;
	view_invalidation_data_t view_invalidation_data;
	ipc_destination_t ipc_dest;

	MON_ASSERT(view_modification_data);
	MON_ASSERT(view_modification_data->view);

	if (view_modification_data->operation == VIEW_MEM_OP_UPDATE) {
		view_invalidation_data.guest_id = vcpu_id->guest_id;
		view_invalidation_data.view = view_modification_data->view;
		xmon_invalidate_view(vcpu_id->guest_cpu_id,
			(void *)&view_invalidation_data);

		ipc_dest.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;
		ipc_execute_handler_sync(ipc_dest, xmon_invalidate_view,
			(void *)&view_invalidation_data);
	} else if (view_modification_data->operation == VIEW_MEM_OP_RECREATE) {
		xmon_recreate_view(vcpu_id->guest_id, view_modification_data->view,
			view_modification_data->eptp_list_index);

		if (get_active_view(vcpu_id) ==
			view_modification_data->eptp_list_index) {
				MON_ASSERT(set_active_view(vcpu_id,
					view_modification_data->eptp_list_index, TRUE, FALSE));
		}

		view_invalidation_data.guest_id = vcpu_id->guest_id;
		view_invalidation_data.view = view_modification_data->view;
		xmon_invalidate_view(vcpu_id->guest_cpu_id,
			(void *)&view_invalidation_data);

		set_view_cmd.handle = view_modification_data->eptp_list_index;
		set_view_cmd.set_dummy_view = FALSE;
		set_view_cmd.guest_id = vcpu_id->guest_id;
		set_view_cmd.view = view_modification_data->view;

		ipc_dest.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;
		ipc_execute_handler_sync(ipc_dest, set_remote_view,
			(void *)&set_view_cmd);
	} else {
		/* switch */
		MON_ASSERT(view_modification_data->operation == VIEW_MEM_OP_SWITCH);
		/* only switch ept if the active view is not the same as switchto handle */
		if (get_active_view(vcpu_id) !=
			view_modification_data->eptp_list_index) {
				MON_ASSERT(set_active_view(vcpu_id,
					view_modification_data->eptp_list_index, TRUE, FALSE));
		}
	}

	return TRUE;
}

/* assumption - all CPUs stopped */
void invalidate_view(const guest_vcpu_t *vcpu_id, view_handle_t view,
					 uint64_t eptp_list_index)
{
	view_modification_data_t view_modification_data;

	MON_ASSERT(vcpu_id);
	MON_ASSERT(view);

	view_modification_data.eptp_list_index = eptp_list_index;
	view_modification_data.view = view;
	view_modification_data.operation = VIEW_MEM_OP_UPDATE;

	end_view_modification_before_cpus_resume(vcpu_id,
		&view_modification_data);
}

ikgt_status_t apply_page_permission(const guest_vcpu_t *vcpu_id,
									ikgt_update_page_permission_params_t *
									param)
{
	boolean_t status = TRUE;
	uint32_t i = 0;
	ikgt_guest_state_t *ikgt_guest = NULL;

	MON_ASSERT(param);

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);

	if (!ikgt_guest->view_assigned[param->handle]) {
		MON_LOG(mask_anonymous, level_trace, "ERROR: Invalid view handle!\n");
		return IKGT_BAD_PARAMS;
	}

	/* All guests must be in paging mode. */
	if (xmon_is_cpu_in_non_paged_mode(vcpu_id)) {
		/* cannot change perms - another gcpu not paged
		* and uses flat page tables */
		return IKGT_STATUS_ERROR;
	}


	for (i = 0; i < param->addr_list.count; i++) {
		mam_attributes_t attr;
		uint32_t quot, rem;
		int gva_ok;
		hpa_t hpa;
		gva_t gva;
		gpa_t gpa;

		/* (1) Get gva & gpa from input. */
		gva = param->addr_list.item[i].gva;
		gva_ok = xmon_gva_to_gpa(vcpu_id, gva, &gpa) ? 1 : 0;

		if (gpa != param->addr_list.item[i].gpa) {
			gpa = param->addr_list.item[i].gpa;
			gva_ok = 0;
		}

		/* (2) Verify gpa --> hpa. */
		if (xmon_gpa_to_hpa(vcpu_id, ikgt_guest->view[param->handle], gpa,
			&hpa, &attr) == FALSE) {
				status = status && FALSE;
				continue;
		}

		gpa = ALIGN_BACKWARD(gpa, PAGE_4KB_SIZE);
		hpa = ALIGN_BACKWARD(hpa, PAGE_4KB_SIZE);

		/* (3) Get perms from input. */
		attr.uint32 = 0;
		attr.ept_attr.readable = param->addr_list.item[i].perms.bit.readable;
		attr.ept_attr.writable = param->addr_list.item[i].perms.bit.writable;
		attr.ept_attr.executable = param->addr_list.item[i].perms.bit.executable;

		if (is_invalid_perm(attr.uint32)) {
			MON_LOG(mask_anonymous, level_trace,
				"ERROR: invalid perms: [%d] gpa = 0x%016x (0x%x)\n",
				i, gpa, attr.uint32);

			status = status && FALSE;
			continue;
		}

		/* skip invalid permission check on suppress_ve */
		attr.ept_attr.suppress_ve = param->
			addr_list.item[i].perms.bit.suppress_ve;

		/* (4) Update ept entry. */
		if (!xmon_update_view(vcpu_id, ikgt_guest->view[param->handle],
			VIEW_UPDATE_PERMISSIONS_ONLY, gpa, 0, attr,
			param->handle)) {
				MON_LOG(mask_anonymous, level_trace,
					"ERROR: update EPT failed: [%d] gpa = 0x%016x\n", i, gpa);

				status = status && FALSE;
				continue;
		}

		/* The array-index of ret_val bitmap arrays. */
		quot = i / 64;
		/* The bit vector index of each ret_val bitmap array. */
		rem = i % 64;

		/* when reaching here, it indicates the setting of this section is
		* OK, so clear the return_value bitmap value to indicate success */
		BIT_CLR64(param->addr_list.return_value[quot], rem);
	}

	return (status) ? IKGT_STATUS_SUCCESS : IKGT_BAD_PARAMS;
}

boolean_t switch_view(const guest_vcpu_t *vcpu_id, ikgt_mem_view_handle_t next_view,
					  boolean_t use_dummy_view)
{
	MON_ASSERT(next_view < MAX_NUM_VIEWS);
	MON_ASSERT(set_active_view(vcpu_id, next_view, TRUE, use_dummy_view));

	return TRUE;
}

static
	boolean_t check_straddle(const guest_vcpu_t *vcpu_id, view_handle_t view,
	ikgt_event_info_t *p_event_info, hpa_t *host_phys_addr,
	mam_attributes_t *attrs, gva_t *guest_gva,
	gpa_t *guest_phys_addr)
{
	ikgt_mem_event_info_t *p_mem_event;
	uint64_t fault_gva;
	uint64_t fault_rip;
	gpa_t gpa;
	hpa_t hpa;
	mam_attributes_t tmp_attrs;

	p_mem_event = (ikgt_mem_event_info_t *)p_event_info->event_specific_data;

	if (!p_mem_event->destination_gva) {
		return FALSE;
	}
	fault_gva = p_mem_event->destination_gva;
	fault_rip = p_event_info->vmcs_guest_state.ia32_reg_rip;

	if (fault_gva != fault_rip) {
		if (!xmon_gva_to_gpa(vcpu_id, fault_rip, &gpa)) {
			MON_LOG(mask_anonymous, level_trace, "gva to gpa failed\n");
			MON_ASSERT(0);
		}

		if (!xmon_gpa_to_hpa(vcpu_id, view, gpa, &hpa, &tmp_attrs)) {
			MON_LOG(mask_anonymous, level_trace, "gpa to hpa failed\n");
			MON_ASSERT(0);
		}
		if (!tmp_attrs.ept_attr.executable) {
			*guest_gva = fault_rip;
			*guest_phys_addr = gpa;
			*host_phys_addr = hpa;
			attrs->uint32 = tmp_attrs.uint32;
			return TRUE;
		}
	}

	return FALSE;
}

static boolean_t fvs_add_to_dummy_ept_addr_list(hva_t		dummy_ept_addrs_list,
												view_handle_t	view,
												uint64_t	dummy_view_index)
{
	uint64_t *hva = NULL;
	uint64_t dummy_ept_addr;

	if (!dummy_ept_addrs_list || dummy_view_index >= MAX_EPTP_ENTRIES) {
		return FALSE;
	}

	if (xmon_get_ept_addr(view, &dummy_ept_addr) == FALSE) {
		return FALSE;
	}

	hva = (uint64_t *)dummy_ept_addrs_list;
	*(hva + dummy_view_index) = dummy_ept_addr;

	return TRUE;
}

/* assumption - all CPUs stopped */
static void recreate_view(const guest_vcpu_t *vcpu_id, view_handle_t view,
						  uint64_t eptp_list_index)
{
	view_modification_data_t view_modification_data;
	ipc_destination_t ipc_dest;

	MON_ASSERT(vcpu_id);
	MON_ASSERT(view);

	/* Notify MON of the change in View on current CPU */
	xmon_notify_mon_about_view_recreation(vcpu_id->guest_cpu_id,
		(void *)(size_t)vcpu_id->guest_id);

	/* Notify MON of the change in View on other CPUs */
	ipc_dest.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;
	ipc_dest.addr = 0;
	ipc_execute_handler(ipc_dest, xmon_notify_mon_about_view_recreation,
		(void *)(size_t)vcpu_id->guest_id);

	view_modification_data.eptp_list_index = eptp_list_index;
	view_modification_data.view = view;
	view_modification_data.operation = VIEW_MEM_OP_RECREATE;

	end_view_modification_before_cpus_resume(vcpu_id,
		&view_modification_data);
}

extern ikgt_state_t ikgt_state;
ikgt_status_t add_gpa_to_hpa_mapping(const guest_vcpu_t *vcpu_id,
									 uint32_t handle, gpa_t gpa, hpa_t hpa)
{
	boolean_t status = TRUE;
	mam_attributes_t attr;
	ikgt_guest_state_t *ikgt_guest = NULL;

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);

	/* Check if Handle is a valid view */
	if (!ikgt_guest->view_assigned[handle]) {
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: Invalid View handle passed.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		return IKGT_STATUS_ERROR;
	}

	/* Must be MON heap */
	if (!(gpa >= ikgt_state.mem_config.heap_start_gpa &&
		gpa <= ikgt_state.mem_config.heap_end_gpa)) {
			MON_LOG(mask_plugin, level_error,
				"CPU%d: %s: Error: Invalid memory address passed.\n",
				vcpu_id->guest_cpu_id, __FUNCTION__);
			return IKGT_STATUS_ERROR;
	}

	/* Add mapping with RO perms */
	attr.uint32 = 0;
	attr.ept_attr.readable = 1;

	stop_all_cpus();

	status = xmon_update_view(vcpu_id,
		ikgt_guest->view[handle],
		VIEW_UPDATE_MAPPING, gpa,
		hpa, attr, UNSPECIFIED_VIEW_HANDLE);

	if (status == TRUE) {
		/* Recreate View */
		recreate_view(vcpu_id, ikgt_guest->view[handle], handle);
	}

	start_all_cpus(NULL, NULL);

	if (!status) {
		return IKGT_STATUS_ERROR;
	}

	return IKGT_STATUS_SUCCESS;
}

boolean_t ikgt_report_event_ept_violation(const guest_vcpu_t *vcpu_id,
										  uint64_t		qualification,
										  uint64_t		guest_linear_address,
										  uint64_t		guest_physical_address)
{
	mam_attributes_t hpa_attrs;
	hpa_t host_physical_addr = 0;
	gpa_t guest_physical_addr = 0;
	gva_t guest_linear_addr;
	ia32_vmx_exit_qualification_t ept_qualification;
	ikgt_event_info_t *p_event_info;
	ikgt_mem_event_info_t *p_mem_event;
	boolean_t exec_fault;
	boolean_t data_read;
	boolean_t dummy_view_active = FALSE;
	mam_attributes_t view_attr;
	ikgt_guest_state_t *ikgt_guest = NULL;
	ikgt_guest_cpu_state_t *ikgt_guest_cpu = NULL;
	/* pass necessary params to ikgt_handle_response() */
	ikgt_enable_mtf_param_t handle_allow;


	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);
	ikgt_guest_cpu = ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id];
	MON_ASSERT(ikgt_guest_cpu);

	hpa_attrs.uint32 = 0;
	ept_qualification.uint64 = qualification;

	if (ept_qualification.ept_violation.ept_r == 0 &&
		ept_qualification.ept_violation.ept_w == 0 &&
		ept_qualification.ept_violation.ept_x == 0) {
			/* check if it is monitored memory */
			if (!xmon_gpa_to_hpa(vcpu_id,
				ikgt_guest->view[get_active_view(vcpu_id)],
				guest_physical_address, &host_physical_addr,
				&hpa_attrs)) {
					if (xmon_is_mmio_address(ikgt_guest->
						view[get_active_view(vcpu_id)],
						guest_physical_address)) {
							/* MMIO - single step */
							MON_ASSERT(0);
					} else {
						/* if exec fault, cannot skip */
						MON_ASSERT(!((1 == ept_qualification.ept_violation.x) &&
							(0 == ept_qualification.ept_violation.ept_x)));

						/* Invalid memory - redirect */
						skip_guest_instruction(vcpu_id);
					}

					return TRUE;
			} else {
				MON_LOG(mask_plugin, level_error,
					"IKGT internal data structure error\n");
				MON_ASSERT(0);
			}
	}

	if (xmon_handle_sw_ve(vcpu_id, qualification, guest_linear_address,
		guest_physical_address, get_active_view(vcpu_id))) {
			return TRUE;
	}


	/* setup event info to call handler */
	p_event_info = &(ikgt_guest_cpu->p_event_info_handler);
	p_mem_event = &(ikgt_guest_cpu->
		ikgt_event_specific_info.mem_event_handler);

	/*set non-event-specific info */
	p_event_info->event_specific_response = 0;
	p_event_info->type = IKGT_EVENT_TYPE_MEM;
	p_event_info->thread_id = (uint32_t)vcpu_id->guest_cpu_id;
	get_vmcs_guest_state(vcpu_id, &(p_event_info->vmcs_guest_state));
	p_event_info->response = IKGT_EVENT_RESPONSE_UNSPECIFIED;
	/* set event specific info */
	p_mem_event->handle = ikgt_guest_cpu->active_view;
	p_mem_event->destination_gpa = guest_physical_address;
	if (ept_qualification.ept_violation.gla_validity) {
		p_mem_event->destination_gva = guest_linear_address;
	} else {
		p_mem_event->destination_gva = 0;
	}
	p_mem_event->attempt.all_bits = 0;
	p_mem_event->attempt.bit.readable = ept_qualification.ept_violation.r;
	p_mem_event->attempt.bit.writable = ept_qualification.ept_violation.w;
	p_mem_event->attempt.bit.executable = ept_qualification.ept_violation.x;

	p_mem_event->perms.all_bits = 0;
	p_mem_event->perms.bit.readable = ept_qualification.ept_violation.ept_r;
	p_mem_event->perms.bit.writable = ept_qualification.ept_violation.ept_w;
	p_mem_event->perms.bit.executable = ept_qualification.ept_violation.ept_x;
	p_event_info->event_specific_data = (uint64_t)p_mem_event;

	/* Set view number */
	p_event_info->view_handle = (uint32_t)get_active_view(vcpu_id);

	/* Save original RIP before handler processing */
	save_old_guest_rip(vcpu_id);

	/* CALL handler */
	if (g_ikgt_event_handlers.memory_event_handler)
		g_ikgt_event_handlers.memory_event_handler(p_event_info);

	/* Expected responses */
	MON_ASSERT(IKGT_EVENT_RESPONSE_REDIRECT == p_event_info->response ||
		IKGT_EVENT_RESPONSE_ALLOW == p_event_info->response ||
		IKGT_EVENT_RESPONSE_EXCEPTION == p_event_info->response);

	exec_fault = ((1 == p_mem_event->attempt.bit.executable) &&
		(0 == p_mem_event->perms.bit.executable));

	data_read = ((1 == p_mem_event->attempt.bit.readable) &&
		(0 == p_mem_event->perms.bit.readable));

	/* REDIRECT response not allowed for exec
	* only allowed for data r/w event */
	if (p_event_info->response == IKGT_EVENT_RESPONSE_REDIRECT) {
		MON_ASSERT(!exec_fault);
	}

	handle_allow.mtf_type = IKGT_MTF_TYPE_NONE;

	if (handle_response(vcpu_id, p_event_info, &handle_allow)) {
		/* FALSE for unhandled response: switchview */
		return TRUE;
	}

	/* Begin to handle switchview response */
	guest_linear_addr = guest_linear_address;
	guest_physical_addr = guest_physical_address;

	view_attr.uint32 = (uint32_t)(p_event_info->event_specific_response);

	/* If VE is enabled allow switch to dummy view */
	if (xmon_is_ve_enabled(vcpu_id)) {
		if (view_attr.uint32 >= DUMMY_VIEW_BASE) {
			dummy_view_active = TRUE;
			view_attr.uint32 -= DUMMY_VIEW_BASE;
		}
	}

	if ((view_attr.uint32 >= MAX_NUM_VIEWS) ||
		(!ikgt_guest->view_assigned[view_attr.uint32])) {
			MON_LOG(mask_anonymous, level_trace, "Invalid view handle (%d) ",
				view_attr.uint32);

			/*switch to default base view */
			view_attr.uint32 = DEFAULT_VIEW_HANDLE;
			dummy_view_active = FALSE;
	}

	if ((view_attr.uint32 != ikgt_guest_cpu->active_view) || dummy_view_active) {
		if (dummy_view_active) {
			/*put dummy view back in eptp list */
			xmon_add_eptp_entry_single_core(vcpu_id,
				ikgt_guest->dummy_view[view_attr.uint32],
				view_attr.uint32 + DUMMY_VIEW_BASE);
		}
		/* Switch view only if not active already. This check already
		* exists in following function */
		if (!switch_view(vcpu_id, view_attr.uint32, dummy_view_active)) {
			/* Will never come here. Above function never return FALSE. */
			MON_LOG(mask_anonymous, level_trace,
				"EPT switch view setting failed \n");
			xmon_delete_eptp_entry_single_core(vcpu_id,
				view_attr.uint32 + DUMMY_VIEW_BASE);
		}
	}

	if (exec_fault && !dummy_view_active) {
		if (check_straddle(vcpu_id, ikgt_guest->view[view_attr.uint32],
			p_event_info, &host_physical_addr, &hpa_attrs,
			&guest_linear_addr, &guest_physical_addr)) {
				/* Unused Variables: host_physical_addr, hpa_attrs,
				* guest_linear_addr, guest_physical_addr
				* They are required in case Default EPT is
				* not used to do MTF */
				ept_mtf_enable(vcpu_id, FALSE);
		}
	}

	return TRUE;
}

