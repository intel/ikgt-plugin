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

#ifndef _IKGT_INTERNAL_H
#define _IKGT_INTERNAL_H

#include "xmon_api.h"
#include "common_types.h"


#define DESCRIPTOR_CPL_BIT  0x3

#define BUILD_IPC_BITMAP(cpu_bitmap, ipc_dest) { \
	uint32_t idx = 0;       \
	\
	mon_zeromem(&(ipc_dest), sizeof((ipc_dest))); \
	(ipc_dest).addr_shorthand = IPI_DST_CORE_ID_BITMAP; \
	\
	for (idx = 0; idx < CPU_BITMAP_MAX; idx++)   \
	(ipc_dest).core_bitmap[idx] = (uint64_t)(cpu_bitmap)[idx]; \
}

/* This macro can be used in API calls coming from handler and other internal
* methods of IKGT. It returns IKGT_STATUS_ERROR at the point where the
* condition fails. It can be used in methods with "ikgt_status_t" return type.
*/
#ifdef DEBUG
#define IKGT_API_CHECK_RETURN_STATUS_ON_ERROR(__condition)              \
	{                                                                       \
	if (!(__condition))	{												\
	cli_handle_error(#__condition, __FUNCTION__, __FILE__, __LINE__, API_ERROR); \
	return IKGT_STATUS_ERROR;                                       \
	}                                                                   \
	}
#else
#define IKGT_API_CHECK_RETURN_STATUS_ON_ERROR(__condition)              \
	{                                                                       \
	if (!(__condition))	{												\
	return IKGT_STATUS_ERROR;                                       \
	}                                                                   \
	}
#endif

/* CR0 reserved Bits */
#define IKGT_CR0_RESERVED_BITS 0xFFFFFFFF1FFAFFC0

#define NUM_OF_VALID_CR4_BITS 32

/* CR4 reserved Bits */
#define IKGT_CR4_RESERVED_BITS 0xFFFFFFFFFFE99800

#define CR4_SUPPORT_BIT_1 0x1

/* For capability information refer to IA Manual 2A - CPUID instruction
* with EAX = 1. Feature information is returned in ECX and EDX.
*/
typedef enum {
	FEAT_CX_SSE3,           /* Bit 0 */
	FEAT_CX_PCLMULQDQ,      /* Bit 1 */
	FEAT_CX_DTES64,         /* Bit 2 */
	FEAT_CX_MONITOR,        /* Bit 3 */
	FEAT_CX_DS_CPL,         /* Bit 4 */
	FEAT_CX_VMX,            /* Bit 5 */
	FEAT_CX_SMX,            /* Bit 6 */
	FEAT_CX_EST,            /* Bit 7 */
	FEAT_CX_TM2,            /* Bit 8 */
	FEAT_CX_SSSE2,          /* Bit 9 */
	FEAT_CX_CNXT_ID,        /* Bit 10 */
	FEAT_CX_RESERVED_11,    /* Bit 11 */
	FEAT_CX_FMA,            /* Bit 12 */
	FEAT_CX_CMPXCHG16B,     /* Bit 13 */
	FEAT_CX_XTPR,           /* Bit 14 */
	FEAT_CX_PDCM,           /* Bit 15 */
	FEAT_CX_RESERVED_16,    /* Bit 16 */
	FEAT_CX_PCID,           /* Bit 17 */
	FEAT_CX_DCA,            /* Bit 18 */
	FEAT_CX_SSE4_1,         /* Bit 19 */
	FEAT_CX_SSE4_2,         /* Bit 20 */
	FEAT_CX_X2APIC,         /* Bit 21 */
	FEAT_CX_MOVBE,          /* Bit 22 */
	FEAT_CX_POPCNT,         /* Bit 23 */
	FEAT_CX_TSC_D,          /* Bit 24 */
	FEAT_CX_AES,            /* Bit 25 */
	FEAT_CX_XSAVE,          /* Bit 26 */
	FEAT_CX_OSXSAVE,        /* Bit 27 */
	FEAT_CX_AVX,            /* Bit 28 */
	FEAT_CX_RESERVED29_31   /* Bit 29_31 */
} ikgt_feature_info_ecx_t;

typedef enum {
	FEAT_DX_FPU,            /* Bit 0 */
	FEAT_DX_VME,            /* Bit 1 */
	FEAT_DX_DE,             /* Bit 2 */
	FEAT_DX_PSE,            /* Bit 3 */
	FEAT_DX_TSC,            /* Bit 4 */
	FEAT_DX_MSR,            /* Bit 5 */
	FEAT_DX_PAE,            /* Bit 6 */
	FEAT_DX_MCE,            /* Bit 7 */
	FEAT_DX_CX8,            /* Bit 8 */
	FEAT_DX_APIC,           /* Bit 9 */
	FEAT_DX_RESERVED_10,    /* Bit 10 */
	FEAT_DX_SEP,            /* Bit 11 */
	FEAT_DX_MTRR,           /* Bit 12 */
	FEAT_DX_PGE,            /* Bit 13 */
	FEAT_DX_MCA,            /* Bit 14 */
	FEAT_DX_CMOV,           /* Bit 15 */
	FEAT_DX_PAT,            /* Bit 16 */
	FEAT_DX_PSE_36,         /* Bit 17 */
	FEAT_DX_PSN,            /* Bit 18 */
	FEAT_DX_CFLUSH,         /* Bit 19 */
	FEAT_DX_RESERVED_20,    /* Bit 20 */
	FEAT_DX_DS,             /* Bit 21 */
	FEAT_DX_ACPI,           /* Bit 22 */
	FEAT_DX_MMX,            /* Bit 23 */
	FEAT_DX_FXSR,           /* Bit 24 */
	FEAT_DX_SSE_SSE,        /* Bit 25 */
	FEAT_DX_SSE2_SSE2,      /* Bit 26 */
	FEAT_DX_SS,             /* Bit 27 */
	FEAT_DX_HTT,            /* Bit 28 */
	FEAT_DX_TM,             /* Bit 29 */
	FEAT_DX_RESERVED_30,    /* Bit 30 */
	FEAT_DX_PBE             /* Bit 31 */
} ikgt_feature_info_edx_t;

/* For capability information refer to IA Manual 2A - CPUID instruction
* with EAX = 07h. Feature information is returned in EBX.
*/
typedef enum {
	FEAT_07_EBX_FSGSBASE,           /* Bit 0 */
	FEAT_07_EBX_SMEP = 7,           /* Bit 7 */
	FEAT_07_EBX_REP_MOVSB = 9,      /* Bit 9 */
	FEAT_07_EBX_INVPCID             /* Bit 10 */
} ikgt_feature_info_07_ebx_t;

enum mode_allowed_t {
	MODE_32BIT = 0,
	MODE_64BIT,
	MODE_NOT_SUPPORTED,
	MODE_UNKNOWN
};

/* IKGT STATE */
typedef struct {
	list_element_t	guest_state[1]; /* ikgt_guest_state_t */
	uint32_t	num_of_cpus;
	uint8_t		padding[4];
	memory_config_t mem_config;
	mon_lock_t	dte_lock;       /* used for descriptor_table_exiting, dte_disabling_in_progress */
	mon_lock_t	movdr_lock;     /* used for movdr_exiting, movdr_disabling_in_progress */
	mon_lock_t	hlt_lock;       /* used for hlt_exiting, hlt_disabling_in_progress */
} ikgt_state_t;

typedef struct {
	/* "boolean_t" currently is defined as "int32_t" in IKGT. */
	boolean_t	cr3_load;
	boolean_t	cr3_store;
} ikgt_monitor_control_registers_t;

typedef struct {
	/* "boolean_t" currently is defined as "int32_t" in IKGT. */
	boolean_t	gdtr_load;              /* 0 = Disable monitoring, 1 = Enable monitoring */
	boolean_t	idtr_load;
	boolean_t	ldtr_load;
	boolean_t	tr_load;
	boolean_t	segment_regs;
	boolean_t	msr_writes;
} ikgt_monitor_dtr_seg_registers_t;

typedef struct {
	/* "boolean_t" currently is defined as "int32_t" in IKGT. */
	boolean_t	dr0;            /* 0 = Disable monitoring, 1 = Enable monitoring */

	boolean_t	dr1;

	boolean_t	dr2;

	boolean_t	dr3;

	boolean_t	dr6;

	boolean_t	dr7;
} ikgt_monitor_debug_registers_t;

typedef struct {
	/* "boolean_t" currently is defined as "int32_t" in IKGT. */
	boolean_t	cr3_load; /* 0 = Disable monitoring, 1 = Enable monitoring */
	boolean_t	gdtr_load;
	boolean_t	idtr_load;
	boolean_t	ldtr_load;
	boolean_t	tr_load;
	boolean_t	mov_dr;
	boolean_t	hlt;
	boolean_t	dte;
} ikgt_monitor_registers_t;

/* IKGT STATE PER GUEST PER CPU */
typedef struct {
	uint64_t			active_view;
	uint64_t			ikgt_monitor_cr0_mask;
	uint64_t			ikgt_monitor_cr4_mask;
	ikgt_monitor_registers_t	monitor_regs;
	ikgt_event_info_t		p_event_info_handler;
	union {
		ikgt_mem_event_info_t	mem_event_handler;
		ikgt_cpu_event_info_t	cpu_event_handler;
		ikgt_io_event_info_t	io_event_handler;
	} ikgt_event_specific_info;
	uint64_t			guest_rip_old; /* Used for storing old Guest RIP for setup_disptchib() */
	/* Save the original HPA of the GVA passed from guest */
	/* before remapping it to HPA of eptp list */
	/* Will remap the GVA given by Guest back to this value when FVS is disabled */
	hpa_t				eptp_list_paddress_old;
	boolean_t			dummy_view_active;
	uint8_t				padding1[4];
} ikgt_guest_cpu_state_t;

/* IKGT STATE PER GUEST */
typedef struct {
	view_handle_t			view[MAX_NUM_VIEWS]; /* IB Agent view uses TRUSTED_VIEW_HANDLE */
	boolean_t				view_assigned[MAX_NUM_VIEWS];
	view_handle_t			dummy_view[MAX_NUM_VIEWS];
	hva_t					dummy_eptp_list;        /* HVA of one page allocated in guest */
	/* Used by #VE ISR */
	ikgt_guest_cpu_state_t **gcpu_state;
	ikgt_monitor_dtr_seg_registers_t	monitor_dtr_seg_regs;
	ikgt_monitor_debug_registers_t		monitor_debug_regs;
	ikgt_monitor_control_registers_t	monitor_ctrl_regs;

	guest_id_t				guest_id;
	uint16_t				padding1;

	boolean_t				hlt_exiting;
	uint8_t					padding2[4];

	boolean_t				is_old_idtr_api_used; /* Remove when old IDTR monitoring api is phased out */

	uint64_t				cr0_mask;
	uint64_t				cr4_mask;
	/* Flag for checking/setting NMI monitoring for VNMI */
	uint64_t				nmi_handling_flag_on;
	list_element_t			list[1];
} ikgt_guest_state_t;

typedef enum {
	VIEW_MEM_OP_RECREATE = 1,
	VIEW_MEM_OP_SWITCH,
	VIEW_MEM_OP_UPDATE,
	VIEW_MEM_OP_REMOVE
} view_mem_op_t;

typedef struct {
	uint64_t	eptp_list_index;
	view_handle_t	view;
	view_mem_op_t	operation;
	uint32_t	padding;
} view_modification_data_t;

typedef struct {
	guest_id_t	guest_id;
	uint16_t	padding;
	boolean_t	set_dummy_view;
	uint64_t	handle;
	view_handle_t	view;
} view_set_view_cmd_t;

typedef enum {
	IKGT_MTF_TYPE_DATA_ALLOW = 0,
	IKGT_MTF_TYPE_EXEC_FAULT, /* Not being used */
	IKGT_MTF_TYPE_CPU_DTE,
	IKGT_MTF_TYPE_CPU_MOVDR,
	IKGT_MTF_TYPE_CR0_LOAD,
	IKGT_MTF_TYPE_CR3_LOAD,
	IKGT_MTF_TYPE_CR4_LOAD,
	IKGT_MTF_TYPE_MSR_ACCESS,
	IKGT_MTF_TYPE_CPU_HALT,
	IKGT_MTF_TYPE_IO_ACCESS,
	IKGT_MTF_TYPE_NONE
} ikgt_mtf_type_t;

typedef struct {
	ikgt_mtf_type_t			mtf_type;
	uint32_t			msr_id; /* mtf for msr */
	/* mtf for cr */
	uint64_t			qualification;
	mon_ia32_control_registers_t	cr_id;
	mon_ia32_gp_registers_t		operand;
} ikgt_enable_mtf_param_t;

/* Enabling/Disabling descriptor table exiting */
typedef struct {
	uint32_t enable;
} ikgt_descriptor_table_exiting_params_t;

typedef struct {
	uint32_t enable;
} ikgt_monitor_idtr_load_params_t;

typedef struct {
	uint32_t enable;
} ikgt_monitor_gdtr_load_params_t;

typedef struct {
	IN ikgt_cr0_mask_t	cr0_mask;
	uint32_t		enable;
	IN uint8_t		padding[4];
} ikgt_monitor_cr0_load_params_t;

typedef struct {
	uint32_t enable;
} ikgt_monitor_cr3_load_params_t;

typedef struct {
	IN ikgt_cr4_mask_t	cr4_mask;
	uint32_t		enable;
	IN uint8_t		padding[4];
} ikgt_monitor_cr4_load_params_t;


boolean_t check_guest_cpl_is_ring0(const guest_vcpu_t *vcpu_id);

void init_dte_lock(void);

void acquire_dte_lock(void);

void release_dte_lock(void);

uint64_t get_active_view(const guest_vcpu_t *vcpu_id);

boolean_t set_active_view(const guest_vcpu_t *vcpu_id, ikgt_mem_view_handle_t handle,
						  boolean_t update_hw, boolean_t use_dummy_view);

boolean_t copy_gva_to_hva(const guest_vcpu_t *vcpu_id, gva_t gva,
						  uint32_t size, hva_t hva);

boolean_t copy_hva_to_gva(const guest_vcpu_t *vcpu_id, hva_t hva,
						  uint32_t size, gva_t gva);

ikgt_status_t __monitor_cpu_events(const guest_vcpu_t *vcpu_id, ikgt_cpu_event_params_t *params);

ikgt_status_t __monitor_msr_writes(const guest_vcpu_t *vcpu_id, ikgt_monitor_msr_params_t *params);

ikgt_status_t __monitor_cr0_load(const guest_vcpu_t *vcpu_id,
								 ikgt_monitor_cr0_load_params_t *params, uint64_t *cpu_bitmap);
ikgt_status_t __monitor_cr4_load(const guest_vcpu_t *vcpu_id,
								 ikgt_monitor_cr4_load_params_t *params, uint64_t *cpu_bitmap);
ikgt_status_t descriptor_table_exiting(const guest_vcpu_t *vcpu_id,
									   ikgt_descriptor_table_exiting_params_t *params,
									   uint64_t *cpu_bitmap);

uint32_t get_num_of_cpus(void);

ikgt_guest_state_t *find_guest_state(guest_id_t guest_id);

ikgt_cpu_reg_t lookup_register_from_list(uint32_t register_index);

boolean_t save_old_guest_rip(const guest_vcpu_t *vcpu_id);

void build_event_info(const guest_vcpu_t *vcpu_id, ikgt_event_info_t *event_info,
					  ikgt_cpu_event_info_t *cpu_event_info, ikgt_cpu_event_op_t optype,
					  ikgt_cpu_event_dirn_t opdirn,
					  ikgt_cpu_reg_t event_reg, ikgt_cpu_reg_t operand_reg,
					  uint64_t operand_gva, ikgt_event_type_t type);

ikgt_status_t check_monitor_cpu_events_params(ikgt_cpu_event_params_t *params);

boolean_t skip_guest_instruction(const guest_vcpu_t *vcpu_id);

uint64_t get_guest_visible_CR_value(const guest_vcpu_t *vcpu_id,
									mon_ia32_control_registers_t reg);

void init_mtf(uint32_t num_of_cpus, guest_data_t *guest_data);

boolean_t mtf_enable(const guest_vcpu_t *vcpu_id, ikgt_mtf_type_t type, boolean_t single_step);

boolean_t handle_response(const guest_vcpu_t *vcpu_id, ikgt_event_info_t *event_info,
						  ikgt_enable_mtf_param_t *param);

boolean_t mtf_check_for_cr_guest_update(const guest_vcpu_t *vcpu_id, uint64_t qualification);

boolean_t mtf_check_for_cr_mov(const guest_vcpu_t *vcpu_id, uint64_t qualification,
							   mon_ia32_control_registers_t cr_id, mon_ia32_gp_registers_t operand);

boolean_t mtf_check_for_msr(const guest_vcpu_t *vcpu_id, msr_id_t msr_id);

void ept_mtf_enable(const guest_vcpu_t *vcpu_id, boolean_t single_step);

boolean_t is_dummy_view_in_use(const guest_vcpu_t *vcpu_id);

boolean_t modify_cr3_vmexit_vmcs_control_bit(boolean_t onoff);

boolean_t modify_DTE_vmexit_vmcs_control_bit(boolean_t onoff);

void enable_cr3load_vmexit(cpu_id_t from UNUSED, void *arg);

boolean_t is_cpu_event_mtf_in_progress(const guest_vcpu_t *vcpu_id, ikgt_mtf_type_t type);

ikgt_status_t get_vmexit_reason(const guest_vcpu_t *vcpu_id,
								ikgt_vmexit_reason_t *reason);

ikgt_status_t read_vmcs_guest_state(const guest_vcpu_t *vcpu_id, uint32_t id_num,
									ikgt_vmcs_guest_state_reg_id_t reg_ids[], uint32_t *value_num,
									uint64_t reg_values[]);

ikgt_status_t write_vmcs_guest_state(const guest_vcpu_t *vcpu_id, uint32_t id_num,
									 ikgt_vmcs_guest_state_reg_id_t reg_ids[], uint64_t reg_values[]);

boolean_t __gpa_to_hva(const guest_vcpu_t *vcpu_id, view_handle_t view, gpa_t gpa, hva_t *hva);

boolean_t __gva_to_hva(const guest_vcpu_t *vcpu_id, view_handle_t view, gva_t gva, hva_t *hva);

ikgt_status_t __monitor_cpu_events(const guest_vcpu_t *vcpu_id,
								   ikgt_cpu_event_params_t *params);

ikgt_status_t apply_page_permission(const guest_vcpu_t *vcpu_id,
									ikgt_update_page_permission_params_t *param);

void invalidate_view(const guest_vcpu_t *vcpu_id, view_handle_t view, uint64_t eptp_list_index);

void get_vmcs_guest_state(const guest_vcpu_t *vcpu_id,
						  ikgt_event_vmcs_guest_state_t *ikgt_event_vmcs_guest_state);

boolean_t switch_view(const guest_vcpu_t *vcpu_id, ikgt_mem_view_handle_t next_view,
					  boolean_t use_dummy_view);

ikgt_status_t add_gpa_to_hpa_mapping(const guest_vcpu_t *vcpu_id,
									 uint32_t view, gpa_t gpa, hpa_t hpa);

extern ikgt_event_handlers_t g_ikgt_event_handlers;

#endif /* _IKGT_INTERNAL_H */
