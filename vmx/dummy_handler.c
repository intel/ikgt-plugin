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
#ifndef HANDLER_EXISTS

#include "ikgt_handler_api.h"

#define HANDLER_REV_NUM       0x1


/* dummy handler_report_event() when handler is not provided */
static void handler_report_event(ikgt_event_info_t *event_info)
{
	event_info->response = IKGT_EVENT_RESPONSE_ALLOW;
	if ((event_info->type == IKGT_EVENT_TYPE_CPU)
		&& (((ikgt_cpu_event_info_t *)(event_info->event_specific_data))
		->optype == IKGT_CPU_EVENT_OP_CPUID)) {
		event_info->response = IKGT_EVENT_RESPONSE_UNSPECIFIED;
	}
}

static void populate_ikgt_event_handlers(ikgt_event_handlers_t *ikgt_event_handlers)
{
	ikgt_event_handlers->memory_event_handler = NULL;
	ikgt_event_handlers->cpu_event_handler = &handler_report_event;
	ikgt_event_handlers->message_event_handler = &handler_report_event;
}

/* dummy handler_inialize() when handler is not provided */
void handler_initialize(uint16_t num_of_cpus)
{
	ikgt_printf("HANDLER: Initializing Handler. Num of CPUs = %d\n",
			num_of_cpus);

	mon_zeromem(&ikgt_event_handlers, sizeof(ikgt_event_handlers_t));

	populate_ikgt_event_handlers(&ikgt_event_handlers);

	ikgt_register_handlers(&ikgt_event_handlers);
}

#endif
