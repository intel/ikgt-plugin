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

#ifndef _IKGT_HANDLER_API_H_
#define _IKGT_HANDLER_API_H_

#include "common_types.h"
#include "ikgt_handler_types.h"


#define memset mon_memset

#define memcpy mon_memcpy

/*-------------------------------------------------------*
*  API      : ikgt_get_vmexit_reason()
*  USER     : Handler
*  PURPOSE  : API to get VMEXIT basic reason, qualification and GVA.
*  ARGUMENTS: struct ikgt_vmexit_reason_t contains VMEXIT reason
*  RETURNS  : ikgt_status_t (i.e IKGT_STATUS_SUCCESS(0) or  IKGT_STATUS_ERROR(1))
*--------------------------------------------------------*/
API ikgt_status_t ikgt_get_vmexit_reason(INOUT ikgt_vmexit_reason_t *reason);

/*
* Handler utility API
*/
API int ikgt_printf(IN const char *format, ...);

/*-------------------------------------------------------*
*  FUNCTION : ikgt_malloc()
*  USER     : Handler
*  PURPOSE  : Allocates contiguous buffer of given size,
*             filled with zeroes
*  ARGUMENTS: IN uint32_t size - size of the buffer in bytes.
*                              size <= 2 KILOBYTE required.
*  RETURNS  : uint64_t*  address of allocted buffer if OK,
*             NULL if failed
*-------------------------------------------------------*/
API uint64_t *ikgt_malloc(IN uint32_t size);

/*-------------------------------------------------------*
*  FUNCTION : ikgt_free()
*  USER     : Handler
*  PURPOSE  : Release previously allocated buffer allocated
*             with ikgt_malloc()
*  ARGUMENTS: IN uint64_t *buff - buffer to be released
*  RETURNS  : void
*-------------------------------------------------------*/
API void ikgt_free(IN uint64_t *buff);

/*-------------------------------------------------------*
*  API      : ikgt_read_guest_registers()
*  USER     : Handler
*  PURPOSE  : Read guest VMCS registers values.
*  ARGUMENTS: reg - The pointer to struct that contains
*                       size of the parameter struct,
*                       number of the register IDs/register values
*                       array of register IDs and,
*                       array of register values corresponding to IDs.
*  RETURNS  : ikgt_status_t (i.e IKGT_STATUS_SUCCESS(0) or
*                              IKGT_STATUS_ERROR(1))
*             reg_values - array of guest state register values.
*--------------------------------------------------------*/
API ikgt_status_t ikgt_read_guest_registers(ikgt_vmcs_guest_guest_register_t *reg);

/*-------------------------------------------------------*
*  API      : ikgt_write_guest_registers()
*  USER     : Handler
*  PURPOSE  : Write to guest VMCS registers.
*  ARGUMENTS: reg - The pointer to struct that contains
*                   size of the parameter struct, number of the
*                   register IDs/register values array of register
*                   IDs and, array of register values corresponding
*                   to IDs.
*  RETURNS  : ikgt_status_t (i.e IKGT_STATUS_SUCCESS(0) or
*                              IKGT_STATUS_ERROR(1))
*--------------------------------------------------------*/
API ikgt_status_t ikgt_write_guest_registers(ikgt_vmcs_guest_guest_register_t *reg);

/*-------------------------------------------------------*
*  API      : ikgt_gva_to_gpa()
*  USER     : Handler
*  PURPOSE  : Translate GPA to GPA from given CR3 value
*             If CR3 = 0, use current
*  ARGUMENTS: IN  Size - size of this struct
*             IN  GVA - The guest virtual address
*            IN  cr3 - The CR3 value
*            OUT GPA - The guest physical address
*  RETURNS  : ikgt_status_t (i.e IKGT_STATUS_SUCCESS(0) or
*                              IKGT_STATUS_ERROR(1))
*--------------------------------------------------------*/
API ikgt_status_t ikgt_gva_to_gpa(INOUT ikgt_gva_to_gpa_params_t *gva_to_gpa);

/*-------------------------------------------------------*
*  API      : ikgt_gpa_to_hva()
*  PURPOSE  : API to return Host Virtual Address mapping of a
*             Guest Physical memory address.
*  ARGUMENTS: gpa_to_hva
*             guest_physical_address - The guest physical address of
*             the memory location which needs to be accessed
*             view_handle - Handle of the view in which the translation
*                          should be done
*  RETURNS  : ikgt_status_t (i.e IKGT_STATUS_SUCCESS(0) or
*                              IKGT_STATUS_ERROR(1))
*             host_virtual_address - Translated host virtual
*                                  address pointer
*--------------------------------------------------------*/
API ikgt_status_t ikgt_gpa_to_hva(INOUT ikgt_gpa_to_hva_params_t *gpa_to_hva);

/*-------------------------------------------------------*
*  FUNCTION : ikgt_monitor_cpu_events()
*  PURPOSE  : API to monitor CPU Register events.
*  ARGUMENTS: Size - size of struct ikgt_cpu_event_params_t
*             cpu_bitmap - cpu bitmap to be monitored
*             cpu_reg - cpu register to be monitored
*             Enable - 1=enable, 0=disable
*             MoinitorCR0 specified arguments
*                cr0_mask - CR0 bits that need to be set up
*             MonitorCR4 specified arguments
*                cr4_mask - CR4 bits that need to be set up
*  RETURNS  : ikgt_status_t (i.e IKGT_STATUS_SUCCESS(0) or
*                              IKGT_STATUS_ERROR(1))
*-------------------------------------------------------*/
API ikgt_status_t ikgt_monitor_cpu_events(INOUT ikgt_cpu_event_params_t *monitor_cpu_events);

/*-------------------------------------------------------*
*  API      : ikgt_monitor_msr_writes()
*  PURPOSE  : API to monitor MSR writes.
*  ARGUMENTS: monitor_msr_writes
*             Enable - 1=enable, 0=disable
*             num_ids - Number of MSRs
*             msr_ids[IKGT_MAX_MSR_IDS] - List of MSR Ids.
*  RETURNS  : ikgt_status_t (i.e IKGT_STATUS_SUCCESS(0) or
*                              IKGT_STATUS_ERROR(1))
*             OUT uint32_t ret_val[IKGT_MAX_MSR_IDS] - Success/Failure
*--------------------------------------------------------*/
API ikgt_status_t ikgt_monitor_msr_writes(INOUT ikgt_monitor_msr_params_t *monitor_msr_writes);

/*-------------------------------------------------------*
*  API      : ikgt_update_page_permission()
*  PURPOSE  : Sets the page monitoring permissions (R/W/X)
*            in the specified memory monitor view.
*  ARGUMENTS: params
*               Handle - The handle of the memory
*                       monitoring view for which the
*                       permission is set.
*               addr_list - Page-Aligned list of
*                       gpa_addr_info struct with count
*                       and a status bitmap array.
*  RETURNS  : ikgt_status_t
*              IKGT_STATUS_SUCCESS(0)
*              IKGT_STATUS_ERROR(1)
*--------------------------------------------------------*/
API ikgt_status_t ikgt_update_page_permission(INOUT ikgt_update_page_permission_params_t *
											  params);

/*-------------------------------------------------------*
*  API      : ikgt_copy_gva_to_hva()
*  PURPOSE  : Copies the values of size bytes from the location pointed by
*             gva from guest to the memory block pointed by hva.
*  ARGUMENTS: params
*               gva - Pointer to the source of data to be copied.
*               size -Number of bytes to copy.
*               hva - Pointer to the destination array where the content is to be copied.
*  RETURNS  : ikgt_status_t
*              IKGT_STATUS_SUCCESS(0)
*              IKGT_STATUS_ERROR(1)
*--------------------------------------------------------*/
API ikgt_status_t ikgt_copy_gva_to_hva(gva_t gva, uint32_t size, hva_t hva);


/*-------------------------------------------------------*
*  API      : ikgt_register_handlers()
*  PURPOSE  :  Responsible for exporting the handler's entry points to ikgt plugin.
*  ARGUMENTS: params
*               ikgt_event_handlers - Pointer to an array of entry points.
*--------------------------------------------------------*/
API void ikgt_register_handlers(ikgt_event_handlers_t *ikgt_event_handlers);


/*-------------------------------------------------------*
*  API      : ikgt_hva_to_hpa()
*  PURPOSE  : Get the HPA corresponding to input HVA
*  ARGUMENTS: hva_to_hpa - Pointer to struct ikgt_hva_to_hpa_params_t
*  RETURNS  : ikgt_status_t
*              IKGT_STATUS_SUCCESS(0)
*              IKGT_STATUS_ERROR(1)
*--------------------------------------------------------*/
API ikgt_status_t ikgt_hva_to_hpa(INOUT ikgt_hva_to_hpa_params_t *hva_to_hpa);

/*-------------------------------------------------------*
*  API      : ikgt_add_gpa_to_hpa_mapping
*  PURPOSE  : Add GPA to HPA mapping.
*  ARGUMENTS: view - view id.
*             gpa - GPA.
*             hpa - HPA.
*  RETURNS  : ikgt_status_t (i.e IKGT_STATUS_SUCCESS(0) or
*                              IKGT_STATUS_ERROR(1))
*--------------------------------------------------------*/
API ikgt_status_t ikgt_add_gpa_to_hpa_mapping(uint32_t view, gpa_t gpa, hpa_t hpa);

/*-------------------------------------------------------*
*  FUNCTION : ikgt_lock_initialize()
*  PURPOSE  : initialize lock to unlock state
*  ARGUMENTS: IN lock - lock to be initialized.
*             Must be allocated by Handler.
*  RETURNS  : void
*-------------------------------------------------------*/
API void ikgt_lock_initialize(ikgt_lock_t *lock);

/*-------------------------------------------------------*
*  FUNCTION : ikgt_lock_acquire()
*  PURPOSE  : acquire lock
*  ARGUMENTS: IN lock - ptr to initialized lock
*  RETURNS  : void
*-------------------------------------------------------*/
API void ikgt_lock_acquire(ikgt_lock_t *lock);

/*-------------------------------------------------------*
*  FUNCTION : ikgt_lock_release()
*  PURPOSE  : release lock acquired in ikgt_lock_acquire()
*  ARGUMENTS: IN lock - ptr to initialized lock
*  RETURNS  : void
*-------------------------------------------------------*/
API void ikgt_lock_release(ikgt_lock_t *lock);


#endif  /* _IKGT_HANDLER_API_H_ */
