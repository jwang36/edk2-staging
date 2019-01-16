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

    .model flat
    .code

EXTERN      _nlr_push_tail:PROC

_nlr_push   PROC
    pop     ecx                         ; ecx <- return address
    mov     edx, [esp]                  ; edx <- nlr
    mov     [edx + 08h], ecx            ; eip value to restore in nlr_jump
    mov     [edx + 0Ch], ebp
    mov     [edx + 10h], esp
    mov     [edx + 14h], ebx
    mov     [edx + 18h], edi
    mov     [edx + 1Ch], esi

    push    ecx                        ; make sure nlr_push_tail return back to nlr_push's caller()
    jmp     _nlr_push_tail             ; do the rest in C
_nlr_push   ENDP

_asm_nlr_jump PROC
    pop     eax                         ; skip return address
    pop     edx                         ; edx <- nlr (top)
    pop     eax                         ; eax <- val
    mov     esi, [edx + 1Ch]
    mov     edi, [edx + 18h]
    mov     ebx, [edx + 14h]
    mov     esp, [edx + 10h]
    mov     ebp, [edx + 0Ch]
    jmp     dword ptr [edx + 08h]       ; restore "eip"
_asm_nlr_jump ENDP

    END
