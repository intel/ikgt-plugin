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

#ifndef _PLUGIN_EVENT_HANDLERS_H_
#define _PLUGIN_EVENT_HANDLERS_H_

#include "ikgt_handler_types.h"


/*-------------------------------------------------------*
*  PURPOSE  : Implementation of VMCALL with id VMCALL_IKGT
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*             arg     (IN) -- VMCALL argument, assumed valid
*  RETURNS  : MON_ERROR
*           MON_OK
*-------------------------------------------------------*/
CALLBACK mon_status_t ikgt_vmcall_event_handler(const guest_vcpu_t *vcpu_id, address_t *arg);

/*-------------------------------------------------------*
*  PURPOSE  : If CR0/CR3/CR4 access happen, this function
*             is called to report to the Handler and deal
*             with the access according to Handler's
*             response
*  ARGUMENTS: vcpu_id       (IN) -- Pointer of Guest
*                                   Virtual CPU
*             qualification (IN) -- IA32_VMX_EXIT_
*                                   QUALIFICATION
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
CALLBACK boolean_t ikgt_report_event_cr_access(const guest_vcpu_t *vcpu_id, uint64_t qualification);

/*-------------------------------------------------------*
*  PURPOSE  : Enable the monitoring for what ikgt_mtf_type_t
*             indicates, according to the given CPU's MTF
*             mode
*  ARGUMENTS: vcpu_id (IN) -- Pointer of Guest Virtual CPU
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
CALLBACK boolean_t ikgt_report_event_mtf_vmexit(const guest_vcpu_t *vcpu_id);

/*-------------------------------------------------------*
*  PURPOSE  : Report the Write Access to the given MSR to
*             Handler. According to Handler's response,
*             setup dispatchib or allow the access. For
*             MSR EFER and PAT, enable MTF.
*  ARGUMENTS: vcpu_id     (IN) -- Pointer of Guest Virtual
*                                 CPU
*             msr_id      (IN) -- MSR ID
*             mon_handled (IN) -- TRUE: default handled by
*                                 MON;
*                                 FALSE: not handled by
*                                 MON
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
CALLBACK boolean_t ikgt_report_event_msr_write(const guest_vcpu_t *vcpu_id, uint32_t msr_id,
											   boolean_t mon_handled);

/*-------------------------------------------------------*
*  PURPOSE  : Report the EPT Violation Event to Handler
*             and handle the event accordingly
*  ARGUMENTS: vcpu_id                (IN) -- Pointer of
*                                           Guest Virtual
*                                           CPU
*             qualification         (IN) -- IA32_VMX_EXIT_
*                                           QUALIFICATION
*             guest_linear_address  (IN) -- Destination
*                                           GVA
*             guest_physical_address(IN) -- Destination
*                                           GPA
*  RETURNS  : TRUE
*             FALSE
*-------------------------------------------------------*/
CALLBACK boolean_t ikgt_report_event_ept_violation(const guest_vcpu_t *vcpu_id,
										  uint64_t qualification, uint64_t guest_linear_address,
										  uint64_t guest_physical_address);



boolean_t ikgt_report_event_initial_vmexit_check(const guest_vcpu_t *vcpu_id,
						 uint64_t		current_cpu_rip,
						 uint32_t		vmexit_reason);
#endif /* _PLUGIN_EVENT_HANDLERS_H_ */
