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
#ifndef _IKGT_API_PARAMS_H_
#define _IKGT_API_PARAMS_H_

ikgt_status_t check_monitor_cpu_events_params(ikgt_cpu_event_params_t *params);

ikgt_status_t check_read_guest_registers_params(ikgt_vmcs_guest_guest_register_t *reg);

ikgt_status_t check_write_guest_registers_params(ikgt_vmcs_guest_guest_register_t *reg);

ikgt_status_t check_get_gva_to_gpa_params(ikgt_gva_to_gpa_params_t *gva_to_gpa);

ikgt_status_t check_monitor_cr0_load_params(ikgt_monitor_cr0_load_params_t *params);

ikgt_status_t check_monitor_cr4_load_params(ikgt_monitor_cr4_load_params_t *params);

ikgt_status_t check_monitor_idtr_load_params(ikgt_monitor_idtr_load_params_t *params);

ikgt_status_t check_monitor_gdtr_load_params(ikgt_monitor_gdtr_load_params_t *params);

ikgt_status_t check_monitor_msr_params(ikgt_monitor_msr_params_t *params);

ikgt_status_t check_update_page_permission_params(ikgt_update_page_permission_params_t *params);

#endif  /* _IKGT_API_PARAMS_H */
