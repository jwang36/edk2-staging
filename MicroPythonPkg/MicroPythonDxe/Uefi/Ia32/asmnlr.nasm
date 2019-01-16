;------------------------------------------------------------------------------
;*
;*   Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
;*   This program and the accompanying materials
;*   are licensed and made available under the terms and conditions of the BSD License
;*   which accompanies this distribution.  The full text of the license may be found at
;*   http://opensource.org/licenses/bsd-license.php
;*
;*   THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
;*   WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
;*
;*    nlrsetjmp.nasm
;*
;*   Abstract:
;*
;------------------------------------------------------------------------------

    DEFAULT REL
    SECTION .text

extern ASM_PFX(nlr_push_tail)

global ASM_PFX(nlr_push)
ASM_PFX(nlr_push):
    pop     ecx                         ; ecx <- return address
    mov     edx, [esp]                  ; edx <- nlr
    mov     [edx + 0x08], ecx           ; eip value to restore in nlr_jump
    mov     [edx + 0x0C], ebp
    mov     [edx + 0x10], esp
    mov     [edx + 0x14], ebx
    mov     [edx + 0x18], edi
    mov     [edx + 0x1C], esi

    push    ecx                         ; make sure nlr_push_tail return back to nlr_push's caller()
    jmp     _nlr_push_tail              ; do the rest in C

global ASM_PFX(asm_nlr_jump)
ASM_PFX(asm_nlr_jump):
    pop     eax                         ; skip return address
    pop     edx                         ; edx <- nlr (top)
    pop     eax                         ; eax <- val
    mov     esi, [edx + 0x1C]
    mov     edi, [edx + 0x18]
    mov     ebx, [edx + 0x14]
    mov     esp, [edx + 0x10]
    mov     ebp, [edx + 0x0C]
    jmp     dword [edx + 0x08]          ; restore "eip"

