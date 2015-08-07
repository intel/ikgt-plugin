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

#ifndef _IKGT_API_H_
#define _IKGT_API_H_

#include "common_types.h"


/*-------------------------------------------------------*
*  API      : ikgt_hypercall()
*  PURPOSE  : Send message to handler
*  ARGUMENTS: arg1 - message id (see message_id_t)
*             arg2 - offset into the input buffer
*             arg3 - offset into the output buffer
*  RETURN   : uint64_t
*              SUCCESS (0)
*              ERROR (1)
*              IKGT_NOT_RUNNING (2)
*              GPA of config_info_t structure (others)
*--------------------------------------------------------*/
uint64_t ikgt_hypercall(uint64_t arg1,
						uint64_t arg2,
						uint64_t arg3);


#endif  /* _IKGT_API_H_ */
