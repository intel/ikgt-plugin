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
#include "ikgt_vmx_if.h"
#include "ikgt_internal.h"

#define MON_DEADLOOP()          MON_DEADLOOP_LOG(IKGT_VMCALL_C)
#define MON_ASSERT(__condition) MON_ASSERT_LOG(IKGT_VMCALL_C, __condition)

#include "vmx_ctrl_msrs.h"


static uint64_t ikgt_send_message_to_handler(const guest_vcpu_t *vcpu_id,
									  ikgt_lib_msg_t *ikgt_lib_msg)
{
	ikgt_event_info_t *event_info = NULL;
	ikgt_guest_state_t *ikgt_guest = NULL;
	ikgt_guest_cpu_state_t *ikgt_guest_cpu = NULL;
	uint64_t api_result = 1;

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	MON_ASSERT(ikgt_guest);
	ikgt_guest_cpu = ikgt_guest->gcpu_state[vcpu_id->guest_cpu_id];
	MON_ASSERT(ikgt_guest_cpu);

	/* set up event info to call handler */
	event_info = &(ikgt_guest_cpu->p_event_info_handler);

	mon_zeromem(event_info, sizeof(ikgt_event_info_t));
	event_info->type = IKGT_EVENT_TYPE_MSG;
	event_info->thread_id = (uint32_t)vcpu_id->guest_cpu_id;
	get_vmcs_guest_state(vcpu_id, &(event_info->vmcs_guest_state));

	/* Set view number */
	event_info->view_handle = (uint32_t)get_active_view(vcpu_id);

	if (g_ikgt_event_handlers.message_event_handler) {
		api_result = g_ikgt_event_handlers.message_event_handler(event_info,
			ikgt_lib_msg->arg1,
			ikgt_lib_msg->arg2,
			ikgt_lib_msg->arg3);
	}

	return api_result;
}

/****************************************************************************
* Function name: ikgt_vmcall_event_handler
* Parameters: address_t *arg argument is assumed to be correct.
* Function does not validate input.
****************************************************************************/
CALLBACK mon_status_t ikgt_vmcall_event_handler(const guest_vcpu_t *vcpu_id, address_t *arg)
{
	void **ikgt_msg_guest_ptr = (void **)arg;
	ikgt_lib_msg_t ikgt_lib_msg;
	em64t_cr0_t cr0;
	mon_guest_state_value_t value;
	uint64_t api_result = 1;

	if (!check_guest_cpl_is_ring0(vcpu_id)) {
		xmon_inject_exception(vcpu_id, EXCEPTION_TYPE_UD);
		return MON_ERROR;
	}

	value.value = 0;
	if (FALSE == xmon_get_vmcs_guest_state(vcpu_id, MON_GUEST_CR0, &value)) {
		goto bailout;
	}

	cr0.uint64 = value.value;
	if (cr0.bits.pg == 0) {
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: vmcall_id does not match.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		xmon_inject_exception(vcpu_id, EXCEPTION_TYPE_UD);
		return MON_ERROR;
	}

	/* copy lib message: */
	if (!copy_gva_to_hva(vcpu_id,
		(gva_t)*ikgt_msg_guest_ptr,
		sizeof(ikgt_lib_msg_t),
		(hva_t)&ikgt_lib_msg)) {
			MON_LOG(mask_plugin, level_error,
				"CPU%d: %s: Error: Could not retrieve pointer to parameters.\n",
				vcpu_id->guest_cpu_id, __FUNCTION__);
			xmon_inject_exception(vcpu_id, EXCEPTION_TYPE_UD);
			return MON_ERROR;
	}

	api_result = ikgt_send_message_to_handler(vcpu_id, &ikgt_lib_msg);

bailout:
	value.value = api_result;

	xmon_set_vmcs_guest_state(vcpu_id, MON_GUEST_IA32_GP_RAX, value);

	return MON_OK;
}

