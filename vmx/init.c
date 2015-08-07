
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
*****************************************************************************/
#include "xmon_api.h"
#include "ikgt_file_codes.h"
#include "plugin_event_handlers.h"
#include "ikgt_handler_export.h"
#include "ikgt_internal.h"

#define MON_DEADLOOP()          MON_DEADLOOP_LOG(IKGT_INIT_C)
#define MON_ASSERT(__condition) MON_ASSERT_LOG(IKGT_INIT_C, __condition)

extern ikgt_state_t ikgt_state;


INLINE void ikgt_guest_cpu_initialize(ikgt_guest_state_t *ikgt_guest)
{
	uint32_t i = 0;

	ikgt_guest->gcpu_state = (ikgt_guest_cpu_state_t **)
		mon_malloc(ikgt_state.num_of_cpus *
		sizeof(ikgt_guest_cpu_state_t *));
	MON_ASSERT(ikgt_guest->gcpu_state);
	for (i = 0; i < ikgt_state.num_of_cpus; i++) {
		ikgt_guest->gcpu_state[i] = (ikgt_guest_cpu_state_t *)
			mon_malloc(sizeof(ikgt_guest_cpu_state_t));
		MON_ASSERT(ikgt_guest->gcpu_state[i]);
		ikgt_guest->gcpu_state[i]->active_view = 0;
		mon_memset(&(ikgt_guest->gcpu_state[i]->monitor_regs), FALSE,
			sizeof(ikgt_monitor_registers_t));
	}
}

INLINE void ikgt_view_initialize(guest_id_t guest_id, ikgt_guest_state_t *ikgt_guest)
{
	uint32_t i = 0;

	/* Base View */
	ikgt_guest->view[DEFAULT_VIEW_HANDLE] = xmon_initialize_view();
	xmon_create_view(guest_id, ikgt_guest->view[DEFAULT_VIEW_HANDLE], FALSE,
		mam_rwx_attrs, DEFAULT_VIEW_HANDLE);

	ikgt_guest->dummy_view[DEFAULT_VIEW_HANDLE] = xmon_initialize_view();
	xmon_copy_view(guest_id, &(ikgt_guest->dummy_view[DEFAULT_VIEW_HANDLE]),
		ikgt_guest->view[DEFAULT_VIEW_HANDLE],
		FALSE, DEFAULT_VIEW_HANDLE + DUMMY_VIEW_BASE);

	ikgt_guest->view_assigned[DEFAULT_VIEW_HANDLE] = TRUE;

	/* Set MON state to launch guest with base view */
	xmon_set_mon_state_before_guest_launch(guest_id, ikgt_guest->
		view[DEFAULT_VIEW_HANDLE]);
}

static
	boolean_t ikgt_guest_initialize(guest_id_t guest_id, boolean_t primary_guest)
{
	ikgt_guest_state_t *ikgt_guest = NULL;

	ikgt_guest = (ikgt_guest_state_t *)mon_malloc(sizeof(ikgt_guest_state_t));
	/* BEFORE_VMLAUNCH. MALLOC should not fail. */
	MON_ASSERT(ikgt_guest);

	/* Initialize ikgt_guest_state_t */
	ikgt_guest->guest_id = guest_id;
	list_add(ikgt_state.guest_state, ikgt_guest->list);

	if (primary_guest) {
		/* Initialize guest_view_t for primary guest */
		ikgt_view_initialize(guest_id, ikgt_guest);
	} else {
		/* Initialize guest_view_t for secondary guests */
		/* ikgt_view_initialize_secondary(guest_id, ikgt_guest); */
	}

	/* Initialize ikgt_guest_cpu_state_t */
	ikgt_guest_cpu_initialize(ikgt_guest);

	/* Initialize state flags */
	mon_memset(&(ikgt_guest->monitor_ctrl_regs), FALSE,
		sizeof(ikgt_monitor_control_registers_t));
	mon_memset(&(ikgt_guest->monitor_dtr_seg_regs), FALSE,
		sizeof(ikgt_monitor_dtr_seg_registers_t));
	mon_memset(&(ikgt_guest->monitor_debug_regs), FALSE,
		sizeof(ikgt_monitor_debug_registers_t));
	ikgt_guest->hlt_exiting = FALSE;

	/* Initialize HVA of dummy eptp list which would be re-mapped to the page
	* allocated by guest when enabling fvs with #VE support.
	* IKGT would maintain this dummy eptp list whenever dummy eptp entries
	* are created/updated/deleted.
	*/
	ikgt_guest->dummy_eptp_list = 0;

	return TRUE;
}

INLINE void ikgt_add_static_guest(guest_id_t guest_id, boolean_t primary_guest)
{
	ikgt_guest_initialize(guest_id, primary_guest);
}

void init_addon(uint32_t num_of_cpus,
				guest_data_t *guest_data,
				memory_config_t *mem_config)
{
	uint32_t i = 0;

	MON_LOG(mask_plugin, level_trace,
		"%s: Initialize IKGT num_cpus %d\n",
		__FUNCTION__, num_of_cpus);

	mon_zeromem(&ikgt_state, sizeof(ikgt_state));
	ikgt_state.num_of_cpus = num_of_cpus;

	list_init(ikgt_state.guest_state);

	for (i = 0; (i < MAX_GUESTS_SUPPORTED_BY_XMON) &&
		(guest_data[i].guest_id != INVALID_GUEST_ID); i++)
		ikgt_add_static_guest(guest_data[i].guest_id,
		guest_data[i].primary_guest);

	/* Initialize memory configuration */
	ikgt_state.mem_config = *mem_config;
}

CALLBACK boolean_t ikgt_report_event_initialize(uint16_t		num_of_cpus,
												guest_data_t *guest_data,
												memory_config_t *mem_config)
{
	MON_LOG(mask_plugin, level_trace,
		"%s: Initializing IKGT. Num of CPUs = %d\n",
		__FUNCTION__, num_of_cpus);

	init_addon(num_of_cpus, guest_data, mem_config);

	/* Initialize MTF */
	init_mtf(num_of_cpus, guest_data);

	init_dte_lock();

	return TRUE;
}

CALLBACK boolean_t ikgt_report_event_initialize_after_aps_launch_guest(uint16_t	num_of_cpus,
																	   guest_data_t
																	   *guest_data)
{
	MON_LOG(mask_plugin, level_trace,
		"%s: Initializing IKGT modules after APs"
		" launched the guest. Num of CPUs = %d\n",
		__FUNCTION__, num_of_cpus);

	/* Initialize handler */
	handler_initialize(num_of_cpus);

	return TRUE;
}

static void populate_ikgt_plugin_handlers(xmon_event_handlers_t *plugin_handlers)
{
	plugin_handlers->initialize_event_handler = ikgt_report_event_initialize;

	plugin_handlers->initialize_after_aps_started_event_handler =
		ikgt_report_event_initialize_after_aps_launch_guest;

	plugin_handlers->ept_violation_event_handler =
		ikgt_report_event_ept_violation;

	plugin_handlers->vmcall_event_handler = ikgt_vmcall_event_handler;

	plugin_handlers->cr_access_event_handler = ikgt_report_event_cr_access;

	plugin_handlers->mtf_vmexit_event_handler = ikgt_report_event_mtf_vmexit;

	plugin_handlers->msr_write_event_handler = ikgt_report_event_msr_write;
}

void plugin_init(void)
{
	xmon_event_handlers_t ikgt_plugin_handlers;

	mon_zeromem(&ikgt_plugin_handlers, sizeof(xmon_event_handlers_t));

	populate_ikgt_plugin_handlers(&ikgt_plugin_handlers);

	xmon_register_handlers(&ikgt_plugin_handlers);
}

