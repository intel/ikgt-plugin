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

#ifndef _IKGT_HANDLER_TYPES_H_
#define _IKGT_HANDLER_TYPES_H_

#include "common_types.h"

#define IN
#define OUT
#define INOUT
#define CALLBACK
#define API

#define DEFAULT_VIEW_HANDLE  0                  /* Base View */
#define MAX_NUM_VIEWS        1   /* Maximum supported number of normal views */
#define UNSPECIFIED_VIEW_HANDLE MAX_NUM_VIEWS   /* Used when view creation failed */
#define DUMMY_VIEW_BASE     (MAX_NUM_VIEWS + DEFAULT_VIEW_HANDLE)

#define IKGT_MALLOC_MAX_SIZE 2040               /* In bytes */
#define IKGT_MAX_MSR_IDS     50

#define HIGHEST_ACCEPTABLE_PHYSICAL_ADDRESS 0xFFFFFFFFFFFFFFFF

typedef uint64_t ikgt_mem_view_handle_t;

typedef enum {
	IKGT_STATUS_SUCCESS = 0,
	IKGT_STATUS_ERROR,
	IKGT_ALLOCATE_FAILED,
	IKGT_BAD_PARAMS,
} ikgt_status_t;

typedef struct {
	uint64_t	ia32_reg_rip;
	uint64_t	ia32_reg_rflags;
	uint64_t	vmcs_exit_info_instruction_length;
} ikgt_event_vmcs_guest_state_t;

typedef enum {
	IA32_GP_RAX = 0,
	IA32_GP_RBX,
	IA32_GP_RCX,
	IA32_GP_RDX,
	IA32_GP_RDI,
	IA32_GP_RSI,
	IA32_GP_RBP,
	IA32_GP_RSP,
	IA32_GP_R8,
	IA32_GP_R9,
	IA32_GP_R10,
	IA32_GP_R11,
	IA32_GP_R12,
	IA32_GP_R13,
	IA32_GP_R14,
	IA32_GP_R15,
	VMCS_GUEST_STATE_CR0,
	VMCS_GUEST_STATE_CR3,
	VMCS_GUEST_STATE_CR4,
	VMCS_GUEST_STATE_DR7,
	VMCS_GUEST_STATE_ES_SELECTOR,
	VMCS_GUEST_STATE_ES_BASE,
	VMCS_GUEST_STATE_ES_LIMIT,
	VMCS_GUEST_STATE_ES_AR,
	VMCS_GUEST_STATE_CS_SELECTOR,
	VMCS_GUEST_STATE_CS_BASE,
	VMCS_GUEST_STATE_CS_LIMIT,
	VMCS_GUEST_STATE_CS_AR,
	VMCS_GUEST_STATE_SS_SELECTOR,
	VMCS_GUEST_STATE_SS_BASE,
	VMCS_GUEST_STATE_SS_LIMIT,
	VMCS_GUEST_STATE_SS_AR,
	VMCS_GUEST_STATE_DS_SELECTOR,
	VMCS_GUEST_STATE_DS_BASE,
	VMCS_GUEST_STATE_DS_LIMIT,
	VMCS_GUEST_STATE_DS_AR,
	VMCS_GUEST_STATE_FS_SELECTOR,
	VMCS_GUEST_STATE_FS_BASE,
	VMCS_GUEST_STATE_FS_LIMIT,
	VMCS_GUEST_STATE_FS_AR,
	VMCS_GUEST_STATE_GS_SELECTOR,
	VMCS_GUEST_STATE_GS_BASE,
	VMCS_GUEST_STATE_GS_LIMIT,
	VMCS_GUEST_STATE_GS_AR,
	VMCS_GUEST_STATE_LDTR_SELECTOR,
	VMCS_GUEST_STATE_LDTR_BASE,
	VMCS_GUEST_STATE_LDTR_LIMIT,
	VMCS_GUEST_STATE_LDTR_AR,
	VMCS_GUEST_STATE_TR_SELECTOR,
	VMCS_GUEST_STATE_TR_BASE,
	VMCS_GUEST_STATE_TR_LIMIT,
	VMCS_GUEST_STATE_TR_AR,
	VMCS_GUEST_STATE_GDTR_BASE,
	VMCS_GUEST_STATE_GDTR_LIMIT,
	VMCS_GUEST_STATE_IDTR_BASE,
	VMCS_GUEST_STATE_IDTR_LIMIT,
	VMCS_GUEST_STATE_PEND_DBE,
	VMCS_GUEST_STATE_WORKING_VMCS_PTR,
	VMCS_GUEST_STATE_DEBUG_CONTROL,
	VMCS_GUEST_STATE_INTERRUPTIBILITY,
	VMCS_GUEST_STATE_SLEEP_STATE,
	VMCS_GUEST_STATE_SMBASE,
	VMCS_GUEST_STATE_SYSENTER_CS,
	VMCS_GUEST_STATE_SYSENTER_ESP,
	VMCS_GUEST_STATE_SYSENTER_EIP,
	VMCS_GUEST_STATE_PAT,
	VMCS_GUEST_STATE_EFER,
	VMCS_GUEST_STATE_PDPTR0,
	VMCS_GUEST_STATE_PDPTR1,
	VMCS_GUEST_STATE_PDPTR2,
	VMCS_GUEST_STATE_PDPTR3,
	VMCS_STATE_PREEMPTION_TIMER,
	VMCS_STATE_GUEST_UG_SUPPORT,
	/* Only valid for 64-bit, will return undefined value in 32-bit */
	VMCS_GUEST_STATE_CR8,
	VMCS_GUEST_STATE_RFLAGS,
	VMCS_GUEST_STATE_RIP,
	NUM_OF_VMCS_GUEST_STATE_REGS
} ikgt_vmcs_guest_state_reg_id_t;

typedef enum {
	IKGT_CPU_REG_RAX = 0,
	IKGT_CPU_REG_RBX,
	IKGT_CPU_REG_RCX,
	IKGT_CPU_REG_RDX,
	IKGT_CPU_REG_RDI,
	IKGT_CPU_REG_RSI,
	IKGT_CPU_REG_RBP,
	IKGT_CPU_REG_RSP,
	IKGT_CPU_REG_R8,
	IKGT_CPU_REG_R9,
	IKGT_CPU_REG_R10,
	IKGT_CPU_REG_R11,
	IKGT_CPU_REG_R12,
	IKGT_CPU_REG_R13,
	IKGT_CPU_REG_R14,
	IKGT_CPU_REG_R15,
	IKGT_CPU_REG_CR0,
	IKGT_CPU_REG_CR3,
	IKGT_CPU_REG_CR4,
	IKGT_CPU_REG_IDTR,
	IKGT_CPU_REG_GDTR,
	IKGT_CPU_REG_LDTR,
	IKGT_CPU_REG_TR,
	IKGT_CPU_REG_DR,        /* any dbg reg */
	IKGT_CPU_REG_SR,        /* any seg reg */
	IKGT_CPU_REG_MSR,       /* Any MSR. Look in ECX for MSR Id. */
	IKGT_CPU_REG_UNKNOWN
} ikgt_cpu_reg_t;

typedef enum {
	IKGT_CPU_EVENT_OP_REG,
	IKGT_CPU_EVENT_OP_MEM,
	IKGT_CPU_EVENT_OP_MSR,
	IKGT_CPU_EVENT_OP_FAST_VIEW_SWITCH,
	IKGT_CPU_EVENT_OP_CPUID
} ikgt_cpu_event_op_t;

typedef enum {
	IKGT_CPU_EVENT_DIRN_SRC,
	IKGT_CPU_EVENT_DIRN_DST
} ikgt_cpu_event_dirn_t;

typedef struct {
	IN ikgt_cpu_event_op_t		optype;
	IN ikgt_cpu_event_dirn_t	opdirn;
	IN ikgt_cpu_reg_t		event_reg;      /* The register to which this event pertains */
	IN ikgt_cpu_reg_t		operand_reg;    /* ifoptype==CPU_EVENT_OP_REG */
	IN uint64_t			operand_gva;    /* if optype==CPU_EVENT_OP_MEM */
	IN uint64_t			operand_gpa;    /* if optype==CPU_EVENT_OP_MEM */
	INOUT uint64_t		cpuid_params;   /* if optype==CPU_EVENT_OP_CPUID */
} ikgt_cpu_event_info_t;

typedef union {
	struct {
		uint32_t readable:1, writable:1, executable:1, suppress_ve:1, reserved:28;
	} bit;
	/* Refer IA developer manual 3B for valid bit combinations */
	/* Invalid value results in EPT misconfiguration error */
	uint32_t all_bits;
} ikgt_page_perms_t;

typedef struct {
	IN uint64_t	size;
	IN uint64_t	guest_virtual_address;
	IN uint64_t	cr3;
	OUT uint64_t	guest_physical_address;
} ikgt_gva_to_gpa_params_t;

typedef struct {
	IN ikgt_mem_view_handle_t	view_handle;
	IN uint64_t			guest_physical_address;
	OUT uint64_t		host_virtual_address;
} ikgt_gpa_to_hva_params_t;

typedef struct {
	IN uint64_t	size;
	IN uint64_t	host_virtual_address;
	OUT uint64_t	host_physical_address;
} ikgt_hva_to_hpa_params_t;

typedef struct {
	IN ikgt_mem_view_handle_t	handle;
	/* source of access is in VMCS_GUEST_RIP in ikgt_event_vmcs_guest_state_t */
	IN uint64_t			destination_gva;
	IN uint64_t			destination_gpa;
	IN ikgt_page_perms_t		attempt;
	IN ikgt_page_perms_t		perms;
} ikgt_mem_event_info_t;

typedef struct {
	/* 64bit aligned */
	struct {
		/* IO port address (from 0 to 65535) */
		IN uint32_t	port_id:16;
		/* 1= 1-byte; 2= 2-byte; 4= 4-byte; others not used */
		IN uint32_t	port_size:3;
		/* 0= OUT or OUTS (write); 1= IN or INS (read) */
		IN uint32_t	port_access:1;
		/* String instruction (0 = not string; 1 = string)  */
		IN uint32_t	str_instr:1;
		/* REP prefixed (0 = not REP; 1 = REP)  */
		IN uint32_t	rep_prefix:1;
		/* 0 = monitored only by Handler/IB;
		* 1 = also monitored by MON internally
		* Further extension to solve this owner conflict.
		* Currently, it is always ZERO */
		IN uint32_t	io_owner:1;
		IN uint32_t	reserved0:9; /* not used */
		/* valid only if rep_prefix = 1, rep count (in guest ecx)*/
		IN uint32_t	rep_count:32;
	} instr_info;

	/* This field str_data_gva below is valid for IO string instructions */
	/* (INS/OUTS), points to the memory location of data buffer, which */
	/* contains the value that guest OS attempted to read/write. */

	/* For IN/OUT instruction, set as NULL since the data is in */
	/* guest register AL, AX, or EAX, depending on port_size */

	/* Notes: */
	/* 1).The length of this pointer is calculated as: */
	/*    if rep_prefix=1, then rep_count*port_size */
	/*    if rep_prefix=0, then port_size */
	/* 2).If rep_prefix=1 (means REP OUTS/INS),then the direction of */
	/*    this field depends on guest RFLAGS.DF value: */
	/*    if DF=1, decremented by port_size of bytes for each iteration; */
	/*    if DF=0, incremented by port_size of bytes. */
	/* 3).It is a GVA address, may cross the page boundary, and */
	/*    even non-contiguous guest physical page. */
	/*  */
	IN uint64_t str_data_gva; /* gva pointer to write/read data */
} ikgt_io_event_info_t;

typedef enum {
	IKGT_EVENT_TYPE_CPU,
	IKGT_EVENT_TYPE_MEM,
	IKGT_EVENT_TYPE_MSG,
} ikgt_event_type_t;

typedef enum {
	IKGT_EVENT_RESPONSE_ALLOW = 0,
	IKGT_EVENT_RESPONSE_REDIRECT,

	IKGT_EVENT_RESPONSE_DISPATCHIB,
	IKGT_EVENT_RESPONSE_RETRY,

	IKGT_EVENT_RESPONSE_SINGLESTEP,

	IKGT_EVENT_RESPONSE_EXCEPTION,

	IKGT_EVENT_RESPONSE_UNSPECIFIED = 1023
} ikgt_event_response_t;

typedef struct {
	uint32_t	reason; /* basic reason of VMEXIT */
	uint32_t	padding;
	uint64_t	qualification;
	uint64_t	gva; /* GVA valid only in memory events */
} ikgt_vmexit_reason_t;

typedef struct {
	IN ikgt_event_type_t	type;
	IN uint64_t				thread_id;
	IN ikgt_event_vmcs_guest_state_t	vmcs_guest_state;
	IN uint64_t				event_specific_data; /* Pointer to event specific structure */
	OUT ikgt_event_response_t		response;
	IN uint32_t				view_handle;
	OUT uint64_t			event_specific_response;
	/* Pointer to event specific structure or data */
} ikgt_event_info_t;

/*  */
/* Union used to specify IA-32 Control Register #0 Mask */
/*  */
typedef union {
	struct {
		uint32_t	pe:1;         /* Bit 0: Protection Enable */
		uint32_t	mp:1;         /* Bit 1: Monitor Coprocessor */
		uint32_t	em:1;         /* Bit 2: Emulation */
		uint32_t	ts:1;         /* Bit 3: Task Switched */
		uint32_t	et:1;         /* Bit 4: Extension Type */
		uint32_t	ne:1;         /* Bit 5: Numeric Error */
		uint32_t	bit06_15:10;  /* Bit06_15: reserved Bits */
		uint32_t	wp:1;         /* Bit 16: Write Protect */
		uint32_t	bit17:1;      /* Bit17: reserved Bit */
		uint32_t	am:1;         /* Bit 18: Alignment Mask */
		uint32_t	bit19_28:10;  /* Bit19_28: reserved Bits */
		uint32_t	nw:1;         /* Bit 29: Not Write-through */
		uint32_t	cd:1;         /* Bit 30: Cache Disable */
		uint32_t	pg:1;         /* Bit 31: Paging */
		uint32_t	bit32_63;       /* Bit32_63: reserved Bits */
	} bits;
	uint64_t uint64;
} ikgt_cr0_mask_t;

/*  */
/* Union used to specify IA-32 Control Register #4 Mask */
/*  */
typedef union {
	struct {
		uint32_t	vme:1;        /* Bit 0: V86 Mode Extensions */
		uint32_t	pvi:1;        /* Bit 1: Protected-Mode Virtual Interrupts */
		uint32_t	tsd:1;        /* Bit 2: Time Stamp Disable */
		uint32_t	de:1;         /* Bit 3: Debugging Extensions */
		uint32_t	pse:1;        /* Bit 4: Page Size Extensions */
		uint32_t	pae:1;        /* Bit 5: Physical Address Extension */
		uint32_t	mce:1;        /* Bit 6: Machine-Check Enable */
		uint32_t	pge:1;        /* Bit 7: Page Global Enable */
		uint32_t	pce:1;        /* Bit 8: Performance-Monitoring Counter Enable */
		uint32_t	osfxsr:1;     /* Bit 9: OS Support for FXSAVE/FXSTOR */
		uint32_t	osxmmexcpt:1; /* Bit 10: OS Support for Unmasked SIMD FP Ex. */
		uint32_t	bit11_12:2;   /* Bit11_12: reserved Bits */
		uint32_t	vmxe:1;       /* Bit 13: VMX-Enable Bit */
		uint32_t	smxe:1;       /* Bit 14: SMX-Enable Bit */
		uint32_t	bit15_16:2;   /* Bit15_16: reserved Bits */
		uint32_t	pcide:1;      /* Bit 17: PCID-Enable Bit */
		uint32_t	osxsave:1;    /* Bit 18: XSAVE and Processor Ext. Stat-Enb Bit */
		uint32_t	bit19:1;      /* Bit 19: reserved Bit */
		uint32_t	smep:1;       /* Bit 20: Supervisor Mode Execution Prevention */
		uint32_t	bit21_31:11;  /* Bit21_31: reserved Bits */
		uint32_t	bit32_63;       /* Bit32_63: reserved Bits */
	} bits;
	uint64_t uint64;
} ikgt_cr4_mask_t;

/* Union for monitoring CRx bits */
typedef union {
	ikgt_cr0_mask_t cr0;            /* CR0 bits that need to be set up */
	ikgt_cr4_mask_t cr4;            /* CR4 bits that need to be set up*/
} ikgt_crx_mask_t;

typedef struct {
	IN uint64_t		size;
	IN uint64_t		cpu_bitmap[CPU_BITMAP_MAX];

	/* valid cpu registers to be monitored are: */
	/* CR0, CR3, CR4, DR, IDTR, GDTR, LDTR, TR */
	IN ikgt_cpu_reg_t	cpu_reg;

	IN uint32_t		enable;         /* 1=enable, 0=disable */
	IN ikgt_crx_mask_t	crx_mask;       /* Mask for CR0 and CR4 monitoring */
} ikgt_cpu_event_params_t;

#define GUEST_REGISTER_MAX_NUM     50

typedef struct {
	IN uint64_t				size;
	IN uint32_t				num;
	uint8_t					padding[4];
	IN ikgt_vmcs_guest_state_reg_id_t	reg_ids[GUEST_REGISTER_MAX_NUM];
	INOUT uint64_t				reg_values[GUEST_REGISTER_MAX_NUM];
} ikgt_vmcs_guest_guest_register_t;

typedef struct {
	IN uint64_t		gpa;
	IN ikgt_page_perms_t	perms;
	IN uint8_t		padding1[4];
	IN uint64_t		gva;
} guest_addr_info_t;

#define IKGT_ADDRINFO_MAX_COUNT   100
#define IKGT_ADDRINFO_MAX_RET     NUM_OF_64BIT_ARRAY(IKGT_ADDRINFO_MAX_COUNT)
typedef struct {
	IN uint32_t		count;
	IN uint8_t		padding[4];
	IN guest_addr_info_t	item[IKGT_ADDRINFO_MAX_COUNT];
	OUT uint64_t		return_value[IKGT_ADDRINFO_MAX_RET];
} guest_addr_list_t;

typedef struct {
	IN ikgt_mem_view_handle_t	handle;
	IN guest_addr_list_t		addr_list;
} ikgt_update_page_permission_params_t;

typedef struct {
	uint32_t	enable;
	uint32_t	num_ids;
	IN uint32_t	msr_ids[IKGT_MAX_MSR_IDS];
	OUT uint32_t	ret_val[IKGT_MAX_MSR_IDS];
} ikgt_monitor_msr_params_t;

typedef void (*memory_event_handler_t)(ikgt_event_info_t *event_info);
typedef void (*cpu_event_handler_t)(ikgt_event_info_t *event_info);
typedef uint64_t (*message_event_handler_t)(ikgt_event_info_t *event_info,
											uint64_t arg1, uint64_t arg2, uint64_t arg3);

typedef struct {
	memory_event_handler_t memory_event_handler;
	cpu_event_handler_t cpu_event_handler;
	message_event_handler_t	message_event_handler;
} ikgt_event_handlers_t;

typedef struct {
	volatile uint32_t	uint32_lock;
	volatile uint16_t	owner_cpu_id;
	char			padding[2];
} ikgt_lock_t;


#endif  /* IKGT_HANDLER_TYPES_H_ */
