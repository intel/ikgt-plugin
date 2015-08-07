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
#include "ikgt_api_params.h"

#define MON_DEADLOOP()          MON_DEADLOOP_LOG(IKGT_HANDLER_API_C)
#define MON_ASSERT(__condition) MON_ASSERT_LOG(IKGT_HANDLER_API_C , __condition)

#include "vmcall_api.h"

ikgt_event_handlers_t g_ikgt_event_handlers = { NULL };

API int ikgt_printf(const char *format, ...)
{
	va_list args;

	va_start(args, format);

	return mon_vprintf(format, args);
}

/* Following functions- ikgt_malloc() and ikgt_free() have been extended to
* use mon_page_alloc() and mon_page_free() as a temporary solution for
* allocation of more than 2040 bytes using page alignment of buffer for
* differentiating between mon_malloc allocation() and mon_page_alloc() */
API uint64_t *ikgt_malloc(IN uint32_t size)
{
	uint64_t *buf = NULL;
	uint32_t num_pages = 0;

	if (0 == size) {
		MON_LOG(mask_plugin, level_trace, "%s: size must be greater than 0.\n",
			__FUNCTION__);
		return NULL;
	}

	/* Internal function requirement. Max block is 2048 bytes,
	* including 8 byte mem_allocation_info_t structure. */
	if (size <= IKGT_MALLOC_MAX_SIZE) {
		buf = mon_malloc(size);
	} else {
		/* If size is more than 2040 bytes, then find number of pages
		* needed and use mon_page_alloc */
		MON_LOG(mask_plugin, level_info, "%s: Using mon_page_alloc\n",
			__FUNCTION__);
		num_pages = PAGE_ROUNDUP(size);
		buf = mon_page_alloc(num_pages);
	}

	return buf;
}

API void ikgt_free(IN uint64_t *buff)
{
	if (NULL == buff) {
		return;
	}

	/* If buffer is page aligned then use mon_page_free
	* otherwise use mon_mfree.
	* This is a temporary solution. In the long term,
	* a more robust solution will be implemented */
	if (IS_ALIGN((uint64_t)buff, PAGE_4KB_SIZE)) {
		MON_LOG(mask_plugin, level_info, "%s: Using mon_page_free\n", __FUNCTION__);
		mon_page_free(buff);
	} else {
		mon_mfree(buff);
	}
}

/* cpu eventing api for Handler */
API ikgt_status_t ikgt_monitor_cpu_events(INOUT ikgt_cpu_event_params_t
										  *monitor_cpu_events)
{
	const guest_vcpu_t *vcpu_id = xmon_get_guest_vcpu();
	ikgt_status_t status;

	IKGT_API_CHECK_RETURN_STATUS_ON_ERROR(vcpu_id);

	if (NULL == monitor_cpu_events) {
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: Invalid input arguments.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		return IKGT_STATUS_ERROR;
	}

	status = __monitor_cpu_events(vcpu_id, monitor_cpu_events);

	return status;
}

API ikgt_status_t ikgt_monitor_msr_writes(INOUT ikgt_monitor_msr_params_t
										  *monitor_msr_writes)
{
	const guest_vcpu_t *vcpu_id = xmon_get_guest_vcpu();
	ikgt_status_t status;

	IKGT_API_CHECK_RETURN_STATUS_ON_ERROR(vcpu_id);

	if (NULL == monitor_msr_writes) {
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: Invalid input arguments.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		return IKGT_STATUS_ERROR;
	}

	status = __monitor_msr_writes(vcpu_id, monitor_msr_writes);

	return status;
}

API ikgt_status_t ikgt_get_vmexit_reason(ikgt_vmexit_reason_t *reason)
{
	const guest_vcpu_t *vcpu_id = NULL;
	ikgt_status_t status;

	vcpu_id = xmon_get_guest_vcpu();

	status = get_vmexit_reason(vcpu_id, reason);

	return status;
}

API ikgt_status_t ikgt_read_guest_registers(ikgt_vmcs_guest_guest_register_t *reg)
{
	const guest_vcpu_t *vcpu_id = NULL;
	ikgt_status_t status;

	vcpu_id = xmon_get_guest_vcpu();
	IKGT_API_CHECK_RETURN_STATUS_ON_ERROR(vcpu_id);

	if (check_read_guest_registers_params(reg) != IKGT_STATUS_SUCCESS) {
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: Invalid input arguments.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		return IKGT_STATUS_ERROR;
	}

	status = read_vmcs_guest_state(vcpu_id,
		reg->num, reg->reg_ids, &reg->num, reg->reg_values);

	return status;
}

API ikgt_status_t ikgt_write_guest_registers(ikgt_vmcs_guest_guest_register_t *reg)
{
	const guest_vcpu_t *vcpu_id = NULL;
	ikgt_status_t status;

	vcpu_id = xmon_get_guest_vcpu();
	IKGT_API_CHECK_RETURN_STATUS_ON_ERROR(vcpu_id);

	/* IDs except for RIP and RSP would return IKGT_STATUS_ERROR */
	if (check_write_guest_registers_params(reg) != IKGT_STATUS_SUCCESS) {
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: Invalid input arguments.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		return IKGT_STATUS_ERROR;
	}

	status =
		write_vmcs_guest_state(vcpu_id, reg->num, reg->reg_ids,
		reg->reg_values);

	return status;
}

API ikgt_status_t ikgt_gva_to_gpa(INOUT ikgt_gva_to_gpa_params_t *gva_to_gpa)
{
	gva_t gva;
	gpa_t gpa;

	const guest_vcpu_t *vcpu_id = xmon_get_guest_vcpu();

	IKGT_API_CHECK_RETURN_STATUS_ON_ERROR(vcpu_id);

	if (check_get_gva_to_gpa_params(gva_to_gpa) != IKGT_STATUS_SUCCESS) {
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: Invalid input arguments.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		goto fail;
	}

	gva = gva_to_gpa->guest_virtual_address;
	if (!xmon_gva_to_gpa_from_cr3(vcpu_id, gva, gva_to_gpa->cr3, &gpa)) {
		goto fail;
	}

	gva_to_gpa->guest_physical_address = gpa;

	return IKGT_STATUS_SUCCESS;
fail:
	gva_to_gpa->guest_physical_address = 0;
	return IKGT_STATUS_ERROR;
}

API ikgt_status_t ikgt_gpa_to_hva(INOUT ikgt_gpa_to_hva_params_t *gpa_to_hva)
{
	gpa_t gpa;
	hva_t hva;
	ikgt_guest_state_t *ikgt_guest = NULL;
	const guest_vcpu_t *vcpu_id = NULL;

	vcpu_id = xmon_get_guest_vcpu();
	IKGT_API_CHECK_RETURN_STATUS_ON_ERROR(vcpu_id);

	if (NULL == gpa_to_hva) {
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: Invalid input arguments.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		return IKGT_STATUS_ERROR;
	}

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	IKGT_API_CHECK_RETURN_STATUS_ON_ERROR(ikgt_guest);

	/* Check if view_handle is a valid view */
	IKGT_API_CHECK_RETURN_STATUS_ON_ERROR(gpa_to_hva->view_handle < MAX_NUM_VIEWS);
	if (!ikgt_guest->view_assigned[gpa_to_hva->view_handle]) {
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: Invalid input arguments.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		return IKGT_STATUS_ERROR;
	}

	gpa = gpa_to_hva->guest_physical_address;
	gpa_to_hva->host_virtual_address = 0;

	if (!__gpa_to_hva(vcpu_id, ikgt_guest->view[gpa_to_hva->view_handle],
		gpa, &hva)) {
			MON_LOG(mask_plugin, level_error,
				"CPU%d: %s: Error: gpa_t -> hva_t translation failed.\n",
				vcpu_id->guest_cpu_id, __FUNCTION__);
			return IKGT_STATUS_ERROR;
	}

	gpa_to_hva->host_virtual_address = hva;

	return IKGT_STATUS_SUCCESS;
}

API ikgt_status_t ikgt_update_page_permission(INOUT ikgt_update_page_permission_params_t *
											  params)
{
	ikgt_status_t status;
	ikgt_guest_state_t *ikgt_guest = NULL;
	const guest_vcpu_t *vcpu_id = xmon_get_guest_vcpu();

	MON_ASSERT(vcpu_id);

	if (params == NULL) {
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: Input argument pointer is NULL\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		return IKGT_BAD_PARAMS;
	}

	/* By default, initialize each available bit of ret_val bitmaps as 1
	* to indicate failure, for other unused higher bits, clear to 0. */
	BITMAP_ARRAY_ASSIGN(params->addr_list.return_value,
		IKGT_ADDRINFO_MAX_RET,
		MIN(IKGT_ADDRINFO_MAX_COUNT,
		params->addr_list.count));

	ikgt_guest = find_guest_state(vcpu_id->guest_id);
	IKGT_API_CHECK_RETURN_STATUS_ON_ERROR(ikgt_guest);

	if (check_update_page_permission_params(params) != IKGT_STATUS_SUCCESS) {
		MON_LOG(mask_plugin, level_error,
			"CPU%d: %s: Error: Invalid input arguments.\n",
			vcpu_id->guest_cpu_id, __FUNCTION__);
		return IKGT_BAD_PARAMS;
	}

	/* begin gpm mods */
	stop_all_cpus();

	status = apply_page_permission(vcpu_id, params);

	/* end gpm mods */
	if (status == IKGT_STATUS_SUCCESS) {
		invalidate_view(vcpu_id, ikgt_guest->view[params->handle],
			params->handle);
	}

	start_all_cpus(NULL, NULL);

	return status;
}

API ikgt_status_t ikgt_copy_gva_to_hva(gva_t gva, uint32_t size, hva_t hva)
{
	const guest_vcpu_t *vcpu_id = xmon_get_guest_vcpu();

	IKGT_API_CHECK_RETURN_STATUS_ON_ERROR(vcpu_id);

	if (!copy_gva_to_hva(vcpu_id, gva, size, hva)) {
		return IKGT_STATUS_ERROR;
	}

	return IKGT_STATUS_SUCCESS;
}

API void ikgt_register_handlers(ikgt_event_handlers_t *ikgt_event_handlers)
{
	g_ikgt_event_handlers = *ikgt_event_handlers;
}

API ikgt_status_t ikgt_hva_to_hpa(INOUT ikgt_hva_to_hpa_params_t *hva_to_hpa)
{
	hpa_t hpa = 0;

	IKGT_API_CHECK_RETURN_STATUS_ON_ERROR(hva_to_hpa);

	if (hva_to_hpa->size != sizeof(ikgt_hva_to_hpa_params_t)) {
		return IKGT_STATUS_ERROR;
	}

	if (!xmon_hva_to_hpa((hva_t)hva_to_hpa->host_virtual_address, &hpa)) {
		hva_to_hpa->host_physical_address = 0;
		return IKGT_STATUS_ERROR;
	}

	hva_to_hpa->host_physical_address = hpa;

	return IKGT_STATUS_SUCCESS;
}

API ikgt_status_t ikgt_add_gpa_to_hpa_mapping(uint32_t view, gpa_t gpa, hpa_t hpa)
{
	const guest_vcpu_t *vcpu_id = NULL;
	ikgt_status_t status;

	vcpu_id = xmon_get_guest_vcpu();
	IKGT_API_CHECK_RETURN_STATUS_ON_ERROR(vcpu_id);

	status = add_gpa_to_hpa_mapping(vcpu_id, view, gpa, hpa);

	return status;
}

API void ikgt_lock_initialize(ikgt_lock_t *lock)
{
	lock_initialize((mon_lock_t *)lock);
}

API void ikgt_lock_acquire(ikgt_lock_t *lock)
{
	interruptible_lock_acquire((mon_lock_t *)lock);
}

API void ikgt_lock_release(ikgt_lock_t *lock)
{
	lock_release((mon_lock_t *)lock);
}

