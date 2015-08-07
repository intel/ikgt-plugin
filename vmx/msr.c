
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

#define MON_DEADLOOP()          MON_DEADLOOP_LOG(IKGT_MSR_C)
#define MON_ASSERT(__condition) MON_ASSERT_LOG(IKGT_MSR_C, __condition)


static ikgt_status_t ikgt_start_monitoring_write_msrs(const guest_vcpu_t *vcpu_id, ikgt_monitor_msr_params_t *params)
{
	uint32_t i;
	msr_reg_status_t status;

	for (i = 0; i < params->num_ids; i++) {
		status = xmon_register_msr_write(vcpu_id, params->msr_ids[i]);
		if (MSR_REG_OK == status) {
			params->ret_val[i] = 1;
		} else if (MSR_REG_FAIL == status) {
			params->ret_val[i] = 0;
		} else {
			return IKGT_STATUS_ERROR;
		}
	}

	return IKGT_STATUS_SUCCESS;
}

static ikgt_status_t ikgt_stop_monitoring_write_msrs(const guest_vcpu_t *vcpu_id, ikgt_monitor_msr_params_t *params)
{
	uint32_t i;

	for (i = 0; i < params->num_ids; i++) {
		if (xmon_unregister_msr_write(vcpu_id, params->msr_ids[i])) {
			params->ret_val[i] = 1;
		} else {
			params->ret_val[i] = 0;
		}
	}

	return IKGT_STATUS_SUCCESS;
}

ikgt_status_t __monitor_msr_writes(const guest_vcpu_t *vcpu_id, ikgt_monitor_msr_params_t *params)
{
	ikgt_guest_state_t *ikgt_guest = NULL;

	if (check_monitor_msr_params(params) != IKGT_STATUS_SUCCESS) {
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: Invalid input arguments.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		return IKGT_STATUS_ERROR;
	}

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);

	ikgt_guest->monitor_dtr_seg_regs.msr_writes = (boolean_t)params->enable;

	if (params->enable) {
		ikgt_start_monitoring_write_msrs(vcpu_id, params);
	} else {
		ikgt_stop_monitoring_write_msrs(vcpu_id, params);
	}

	return IKGT_STATUS_SUCCESS;
}

CALLBACK boolean_t ikgt_report_event_msr_write(const guest_vcpu_t *vcpu_id, uint32_t msr_id, boolean_t mon_handled)
{
	ikgt_cpu_event_info_t *cpu_event_info = NULL;
	ikgt_event_info_t *event_info = NULL;
	ikgt_guest_state_t *ikgt_guest = NULL;
	ikgt_enable_mtf_param_t handle_allow; /* pass necessary params to handle_response() */
	boolean_t status = FALSE;
	ikgt_guest_cpu_state_t *ikgt_guest_cpu = NULL;

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);
	ikgt_guest_cpu = ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id];
	MON_ASSERT(ikgt_guest_cpu);

	/* setup event info to call handler */
	event_info = &(ikgt_guest_cpu->p_event_info_handler);
	cpu_event_info = &(ikgt_guest_cpu->ikgt_event_specific_info.cpu_event_handler);

	build_event_info(vcpu_id,
		event_info,
		cpu_event_info,
		IKGT_CPU_EVENT_OP_MSR,
		IKGT_CPU_EVENT_DIRN_DST,
		IKGT_CPU_REG_MSR,
		(ikgt_cpu_reg_t)0,
		0,
		IKGT_EVENT_TYPE_CPU);
	/* Save original RIP before handler processing */
	save_old_guest_rip(vcpu_id);

	if (g_ikgt_event_handlers.cpu_event_handler)
		g_ikgt_event_handlers.cpu_event_handler(event_info);

	/* Expected valid responses */
	MON_ASSERT(IKGT_EVENT_RESPONSE_ALLOW == event_info->response ||
		IKGT_EVENT_RESPONSE_REDIRECT == event_info->response ||
		IKGT_EVENT_RESPONSE_EXCEPTION == event_info->response);


	handle_allow.mtf_type = IKGT_MTF_TYPE_MSR_ACCESS;
	handle_allow.msr_id = msr_id;

	status = handle_response(vcpu_id, event_info, &handle_allow);

	return !status;
}


