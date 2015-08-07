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

#ifndef _IKGT_HANDLER_EXPORT_H_
#define _IKGT_HANDLER_EXPORT_H_

#include "ikgt_handler_types.h"

/* API expected to be implemented by the Handler */

boolean_t handler_initialize(uint16_t num_of_cpus);

#endif  /* _IKGT_HANDLER_EXPORT_H_ */
