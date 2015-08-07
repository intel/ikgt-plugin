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

#ifndef _IKGT_VMX_IF_H_
#define _IKGT_VMX_IF_H_

#define VMCALL_IKGT 12

#define MON_NATIVE_VMCALL_SIGNATURE                                            \
	(((uint32_t)'$' << 24)                                                     \
	| ((uint32_t)'i' << 16)                                                     \
	| ((uint32_t)'M' << 8)                                                      \
	| ((uint32_t)'@' << 0)                                                      \
	)

typedef struct {
	uint64_t arg1;
	uint64_t arg2;
	uint64_t arg3;
} ikgt_lib_msg_t;

#endif  /* _IKGT_VMX_IF_H_ */
