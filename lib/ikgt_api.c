/*******************************************************************************
* This is an example usage of iKGT.
* Copyright (c) 2015, Intel Corporation.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms and conditions of the GNU General Public License,
* version 2, as published by the Free Software Foundation.
*
* This program is distributed in the hope it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
* more details.
*******************************************************************************/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>

#include "ikgt_vmx_if.h"
#include "ikgt_api.h"
#include "policy_common.h"


extern uint64_t asm_make_vmcall(uint64_t P_RSI, uint64_t P_RDI, uint64_t P_RDX);
extern uint64_t asm_is_cpuid_supported(void);

static bool ikgt_first = true;
static bool ikgt_running;


/*
* Method to check if CPUID instruction is supported on this platform
* Returns - SUCCESS if supported, else ERROR
*/
static uint64_t is_cpuid_supported(void)
{
	if (asm_is_cpuid_supported() != 0) {
		return SUCCESS;
	} else {
		return ERROR;
	}
}

/*
* ikgt_running_check API checks whether Guest OS is running on IKGT
* Returns - SUCCESS if IKGT is running, else ERROR
*/
static uint64_t ikgt_running_check(void)
{
	uint64_t cpu_info[4], i, a;

	for (i = 0; i < 4; i++)
		cpu_info[i] = 0;

	/* Check whether CPUID instruction is supported or not */
	if (is_cpuid_supported() == ERROR) {
		printk(KERN_WARNING "CPUID instruction is not supported\n");
		return ERROR;
	}

	/* CPUID instruction with 3 as parameter */
	a = 3;
	asm ("movq %4, %%rax;" "cpuid;"
		: "=a" (cpu_info[0]),
		"=b" (cpu_info[1]),
		"=c" (cpu_info[2]),
		"=d" (cpu_info[3])
		: "r" (a) /* input */
		:
	);


	/* If signature is matched, IKGT is running */
	if (XMON_RUNNING_SIGNATURE_CORP == cpu_info[3] &&
		XMON_RUNNING_SIGNATURE_MON == cpu_info[2]) {
			return SUCCESS;
	}

	return ERROR;
}

static bool ikgt_check_and_set_running_flag(void)
{
	uint64_t  status;

	if (!ikgt_first)
		return ikgt_running;

	ikgt_first = false;

	status = ikgt_running_check();

	if (SUCCESS == status) {
		ikgt_running = true;
	} else {
		ikgt_running = false;
	}

	return ikgt_running;
}

static uint64_t make_ikgt_call(uint64_t msg)
{
	uint32_t sig = 0;

	/* Check the IKGT running global variable */
	if (!ikgt_check_and_set_running_flag()) {
		printk(KERN_ERR "Error: IKGT is not running\n");

		return IKGT_NOT_RUNNING;
	}

	sig = MON_NATIVE_VMCALL_SIGNATURE;

	return asm_make_vmcall((uint64_t)sig, (uint64_t)VMCALL_IKGT, msg);
}

uint64_t ikgt_hypercall(uint64_t arg1,
						uint64_t arg2,
						uint64_t arg3)
{
	ikgt_lib_msg_t msg;

	msg.arg1 = arg1;
	msg.arg2 = arg2;
	msg.arg3 = arg3;

	return make_ikgt_call((uint64_t)&msg);
}

