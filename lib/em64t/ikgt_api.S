################################################################################
# This is an example usage of iKGT.
# Copyright (c) 2015, Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
################################################################################

.global asm_make_vmcall
.global asm_is_cpuid_supported

#;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
#;uint64_t asm_make_vmcall(uint64_t P_RDI, uint64_t P_RSI, uint64_t P_RDX)
#;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
asm_make_vmcall:
    pushq %rsi
    pushq %rdi
    pushq %rbx
    
   
    #setup params
    # 1st parameter
    movq %rdi, %rax
    # 2nd parameter
    movq %rsi, %rcx
    # rdx has the third parameter

    movq $0x0, %rsi
    movq $0x0, %rdi

    #vmcall
    vmcall

    popq %rbx
    popq %rdi
    popq %rsi

    ret


#;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
#uint64_t asm_is_cpuid_supported(void)
#;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
asm_is_cpuid_supported:
    # Get EFLAGS
    pushfq
    popq %rax
    movq %rax, %rcx /* store first eflag in rcx */

    xorq $0x200000, %rax
    # Load EFLAGS
    pushq %rax
    popfq

    # Get EFLAGS now
    pushfq
    popq %rax

    # compare first and second flags
    xorq %rcx, %rax
    andq $0x200000, %rax

    # Restore RFLAGS
    pushq %rcx
    popfq

    # rax is not modified, return
    ret

