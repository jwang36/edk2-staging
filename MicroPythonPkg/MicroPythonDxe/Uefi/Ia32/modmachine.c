/** @file
  Edk2 version machine module for MicroPythhon.

Copyright (c) 2017 - 2018, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <stdio.h>
#include <stdint.h>

#include <py/runtime.h>
#include <py/obj.h>

#include <Library/IoLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Protocol/Cpu.h>
#include <Protocol/Smbios.h>

#include "objuefi.h"

#if MICROPY_PY_MACHINE

STATIC EFI_CPU_ARCH_PROTOCOL          *mCpu = NULL;

typedef struct _mp_obj_port_t {
  mp_obj_base_t   base;
  mp_uint_t       width;
} mp_obj_port_t;

STATIC void port_attr(mp_obj_t self_in, qstr attr_in, mp_obj_t *dest)
{
  mp_obj_port_t *self = MP_OBJ_TO_PTR(self_in);

  switch (attr_in) {
  case MP_QSTR_WIDTH:
    if (dest[0] == MP_OBJ_NULL) {
      // Load
      dest[0] = mp_obj_new_int_from_uint(self->width);
    } else if (dest[0] == MP_OBJ_SENTINEL) {
      if (dest[1] == MP_OBJ_NULL) {
        // Delete
      } else {
        // Store
      }
    }
    break;

  default:
    nlr_raise(mp_obj_new_exception_msg_varg(
                &mp_type_AttributeError,
                "Non-existing attribute: %s",
                qstr_str(attr_in)
                ));
  }
}

STATIC mp_obj_t port_subscr(mp_obj_t self_in, mp_obj_t index, mp_obj_t value)
{
  mp_obj_port_t  *self = MP_OBJ_TO_PTR(self_in);
  mp_uint_t      val;
  mp_int_t       index_val;

  if (MP_OBJ_IS_SMALL_INT(index)) {
    index_val = MP_OBJ_SMALL_INT_VALUE(index);
  } else if (!mp_obj_get_int_maybe(index, &index_val)) {
    nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_TypeError,
                                            "%q number must be integers, not %s",
                                            self->base.type->name, mp_obj_get_type_str(index)));
  }

  if (value == MP_OBJ_NULL) {
    //
    // delete
    //
    return mp_const_none;
  } else if (value == MP_OBJ_SENTINEL) {
    //
    // load
    //
    switch (self->width) {
    case 8:
      val = (mp_uint_t)IoRead8(index_val);
      break;

    case 16:
      val = (mp_uint_t)IoRead16(index_val);
      break;

    case 32:
      val = (mp_uint_t)IoRead32(index_val);
      break;

    default:
      return mp_const_none;
    }
    return mp_obj_new_int_from_uint(val);

  } else {
    //
    // store
    //
    switch (self->width) {
    case 8:
      val = (mp_uint_t)IoWrite8(index_val, (UINT8)mp_obj_get_int(value));
      break;

    case 16:
      val = (mp_uint_t)IoWrite16(index_val, (UINT16)mp_obj_get_int(value));
      break;

    case 32:
      val = (mp_uint_t)IoWrite32(index_val, (UINT32)mp_obj_get_int(value));
      break;

    }
    return mp_const_none;
  }
}

const mp_obj_type_t mp_type_port;

mp_obj_t mp_obj_new_port(mp_uint_t n)
{
  mp_obj_port_t *o = m_new_obj(mp_obj_port_t);

  o->base.type = &mp_type_port;
  if (n <= 8) {
    n = 8;
  } else if (n <= 16) {
    n = 16;
  } else {
    n = 32;
  }
  o->width = n;
  return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t port_make_new(const mp_obj_type_t *type_in, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
  (void)type_in;
  mp_arg_check_num(n_args, n_kw, 0, 1, false);

  switch (n_args) {
  case 0:
    // return a new 8-bit port object
    return mp_obj_new_port(8);
  case 1:
  default:
    {
      return mp_obj_new_port(mp_obj_get_int(args[0]));
    }
  }
}

STATIC void port_print(const mp_print_t *print, mp_obj_t o_in, mp_print_kind_t kind)
{
  mp_obj_port_t *o = MP_OBJ_TO_PTR(o_in);

  if (!(MICROPY_PY_UJSON && kind == PRINT_JSON)) {
    kind = PRINT_REPR;
  }
  mp_printf(print, "%d-bit port", o->width);
}

const mp_obj_type_t mp_type_port = {
  { &mp_type_type },
  .name = MP_QSTR_port,
  .print = port_print,
  .make_new = port_make_new,
  .subscr = port_subscr,
  .attr = port_attr,
};

const mp_obj_port_t mp_const_port8_obj = { { &mp_type_port }, 8 };
const mp_obj_port_t mp_const_port16_obj = { { &mp_type_port }, 16 };
const mp_obj_port_t mp_const_port32_obj = { { &mp_type_port }, 32 };

const mp_obj_mem_t machine_mem8_obj = {
  .base = {&mp_type_mem},
  .addr = 0,
  .fields = NULL,
  .typeattr = 0,
  .typespec = "B",
  .typesize = 1,
  .size = 0,
};

const mp_obj_mem_t machine_mem16_obj = {
  .base = {&mp_type_mem},
  .addr = 0,
  .fields = NULL,
  .typeattr = 0,
  .typespec = "H",
  .typesize = 2,
  .size = 0,
};

const mp_obj_mem_t machine_mem32_obj = {
  .base = {&mp_type_mem},
  .addr = 0,
  .fields = NULL,
  .typeattr = 0,
  .typespec = "I",
  .typesize = 4,
  .size = 0,
};

const mp_obj_mem_t machine_mem64_obj = {
  .base = {&mp_type_mem},
  .addr = 0,
  .fields = NULL,
  .typeattr = 0,
  .typespec = "Q",
  .typesize = 8,
  .size = 0,
};


STATIC mp_obj_t mod_machine_reset(size_t n_args, const mp_obj_t *args) {
  gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_machine_reset_obj, 0, 1, mod_machine_reset);


STATIC mp_obj_t mod_machine_freq(size_t n_args, const mp_obj_t *args) {
  EFI_STATUS                Status;
  EFI_SMBIOS_PROTOCOL       *Smbios;
  EFI_SMBIOS_HANDLE         SmbiosHandle;
  EFI_SMBIOS_TYPE           RecordType;
  SMBIOS_TABLE_TYPE4        *Type4Record;

  //
  // Update Front Page banner strings base on SmBios Table.
  //
  Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL,(VOID **)&Smbios);
  if (EFI_ERROR(Status)) {
    return mp_const_none;
  }

  SmbiosHandle  = SMBIOS_HANDLE_PI_RESERVED;
  RecordType    = EFI_SMBIOS_TYPE_PROCESSOR_INFORMATION;
  Status = Smbios->GetNext(Smbios, &SmbiosHandle, &RecordType,
                           (EFI_SMBIOS_TABLE_HEADER **)&Type4Record, NULL);
  if (EFI_ERROR(Status)) {
    return mp_const_none;
  }

  return MP_OBJ_NEW_SMALL_INT(Type4Record->CurrentSpeed);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_machine_freq_obj, 0, 1, mod_machine_freq);

STATIC
VOID
EFIAPI
MsrErrorHandler (
  IN CONST  EFI_EXCEPTION_TYPE  InterruptType,
  IN CONST  EFI_SYSTEM_CONTEXT  SystemContext
  )
{
  if (mCpu != NULL) {
    mCpu->RegisterInterruptHandler (mCpu, EXCEPT_IA32_GP_FAULT, NULL);
  }

  nlr_raise(mp_obj_new_exception_msg_varg(
              &mp_type_Exception,
              "Reserved or unimplemented MSR: 0x%X",
              (UINT32)SystemContext.SystemContextX64->Rcx
              ));
}

static mp_obj_t mod_ets_rdmsr(mp_obj_t msr)
{
  EFI_STATUS  Status;
  UINT64      Value;

  if (mCpu == NULL) {
    Status = gBS->LocateProtocol (&gEfiCpuArchProtocolGuid, NULL, (VOID **)&mCpu);
    RAISE_UEFI_EXCEPTION_ON_ERROR (Status);
  }

  if (mCpu != NULL) {
    Status = mCpu->RegisterInterruptHandler (mCpu, EXCEPT_IA32_GP_FAULT, MsrErrorHandler);
    RAISE_UEFI_EXCEPTION_ON_ERROR (Status);
  }

  Value = AsmReadMsr64((UINT32)mp_obj_get_int (msr));
  if (mCpu != NULL) {
    Status = mCpu->RegisterInterruptHandler (mCpu, EXCEPT_IA32_GP_FAULT, NULL);
    RAISE_UEFI_EXCEPTION_ON_ERROR (Status);
  }

  return mp_obj_new_int_from_ull(Value);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_ets_rdmsr_obj, mod_ets_rdmsr);

static mp_obj_t mod_ets_wrmsr(mp_obj_t msr, mp_obj_t value)
{
  EFI_STATUS  Status;

  if (mCpu == NULL) {
    Status = gBS->LocateProtocol (&gEfiCpuArchProtocolGuid, NULL, (VOID **)&mCpu);
    RAISE_UEFI_EXCEPTION_ON_ERROR (Status);
  }

  if (mCpu != NULL) {
    Status = mCpu->RegisterInterruptHandler (mCpu, EXCEPT_IA32_GP_FAULT, MsrErrorHandler);
    RAISE_UEFI_EXCEPTION_ON_ERROR (Status);
  }

  AsmWriteMsr64 ((UINT32)mp_obj_get_int (msr), (UINT64)mp_obj_get_int (value));
  if (mCpu != NULL) {
    Status = mCpu->RegisterInterruptHandler (mCpu, EXCEPT_IA32_GP_FAULT, NULL);
    RAISE_UEFI_EXCEPTION_ON_ERROR (Status);
  }

  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_ets_wrmsr_obj, mod_ets_wrmsr);

static mp_obj_t mod_ets_get_reg(qstr reg)
{
  UINT64            Value;
  UINTN             Limit;
  IA32_DESCRIPTOR   Desc;
  mp_obj_tuple_t    *TupleValue;

  Value = 0;
  Limit = 0;
  switch (reg) {
  case MP_QSTR_eflags:
    Value = AsmReadEflags();
    break;

  case MP_QSTR_cr0:
    Value = AsmReadCr0();
    break;

  case MP_QSTR_cr2:
    Value = AsmReadCr2();
    break;

  case MP_QSTR_cr3:
    Value = AsmReadCr3();
    break;

  case MP_QSTR_cr4:
    Value = AsmReadCr4();
    break;

  case MP_QSTR_dr0:
    Value = AsmReadDr0();
    break;

  case MP_QSTR_dr1:
    Value = AsmReadDr1();
    break;

  case MP_QSTR_dr2:
    Value = AsmReadDr2();
    break;

  case MP_QSTR_dr3:
    Value = AsmReadDr3();
    break;

  case MP_QSTR_dr4:
    Value = AsmReadDr4();
    break;

  case MP_QSTR_dr5:
    Value = AsmReadDr5();
    break;

  case MP_QSTR_dr6:
    Value = AsmReadDr6();
    break;

  case MP_QSTR_dr7:
    Value = AsmReadDr7();
    break;

  case MP_QSTR_cs:
    Value = AsmReadCs();
    break;

  case MP_QSTR_ds:
    Value = AsmReadDs();
    break;

  case MP_QSTR_es:
    Value = AsmReadEs();
    break;

  case MP_QSTR_fs:
    Value = AsmReadFs();
    break;

  case MP_QSTR_gs:
    Value = AsmReadGs();
    break;

  case MP_QSTR_ss:
    Value = AsmReadSs();
    break;

  case MP_QSTR_tr:
    Value = AsmReadTr();
    break;

  case MP_QSTR_gdtr:
    AsmReadGdtr(&Desc);
    Value = Desc.Base;
    Limit = Desc.Limit;
    break;

  case MP_QSTR_idtr:
    AsmReadIdtr(&Desc);
    Value = Desc.Base;
    Limit = Desc.Limit;
    break;

  case MP_QSTR_ldtr:
    Value = AsmReadLdtr();
    break;

  case MP_QSTR_mm0:
    Value = AsmReadMm0();
    break;

  case MP_QSTR_mm1:
    Value = AsmReadMm1();
    break;

  case MP_QSTR_mm2:
    Value = AsmReadMm2();
    break;

  case MP_QSTR_mm3:
    Value = AsmReadMm3();
    break;

  case MP_QSTR_mm4:
    Value = AsmReadMm4();
    break;

  case MP_QSTR_mm5:
    Value = AsmReadMm5();
    break;

  case MP_QSTR_mm6:
    Value = AsmReadMm6();
    break;

  case MP_QSTR_mm7:
    Value = AsmReadMm7();
    break;

  case MP_QSTR_tsc:
    Value = AsmReadTsc();
    break;

  case MP_QSTR_pmc:
    Value = AsmReadPmc(0);
    break;

  default:
    nlr_raise(mp_obj_new_exception_msg_varg(
                &mp_type_Exception,
                "Invalid or unimplemented register: %s",
                qstr_str (reg)
                ));
    break;
  }

  if (Limit > 0) {
    TupleValue = MP_OBJ_TO_PTR(mp_obj_new_tuple(2, NULL));
    TupleValue->items[0] = mp_obj_new_int_from_ull(Limit);
    TupleValue->items[1] = mp_obj_new_int_from_uint(Value);
    return TupleValue;
  }

  return mp_obj_new_int_from_ull(Value);
}

static void mod_ets_set_reg(qstr reg, mp_obj_t value)
{
  UINT64            Value;
  IA32_DESCRIPTOR   Desc;
  mp_obj_tuple_t    *TupleValue;
  mp_obj_list_t     *ListValue;

  Value       = (UINT64)-1;
  Desc.Limit  = (UINT16)-1;
  Desc.Base   = (UINTN)-1;

  if (MP_OBJ_IS_INT(value)) {
    Value = mp_obj_get_int(value);
  } else if (MP_OBJ_IS_TYPE(value, &mp_type_tuple)) {
    TupleValue = MP_OBJ_TO_PTR(value);
    ASSERT (TupleValue->len >= 2);
    Desc.Limit = mp_obj_get_int(TupleValue->items[0]);
    Desc.Base = mp_obj_get_int(TupleValue->items[1]);
  } else if (MP_OBJ_IS_TYPE(value, &mp_type_list)) {
    ListValue = MP_OBJ_TO_PTR(value);
    ASSERT (ListValue->len >= 2);
    Desc.Limit = mp_obj_get_int(ListValue->items[0]);
    Desc.Base = mp_obj_get_int(ListValue->items[1]);
  } else {
    nlr_raise(mp_obj_new_exception_msg(
                &mp_type_Exception,
                "Unsupported value type"
                ));
  }

  switch (reg) {
  case MP_QSTR_cr0:
    AsmWriteCr0((UINTN)Value);
    break;

  case MP_QSTR_cr2:
    AsmWriteCr2((UINTN)Value);
    break;

  case MP_QSTR_cr3:
    AsmWriteCr3((UINTN)Value);
    break;

  case MP_QSTR_cr4:
    AsmWriteCr4((UINTN)Value);
    break;

  case MP_QSTR_dr0:
    AsmWriteDr0((UINTN)Value);
    break;

  case MP_QSTR_dr1:
    AsmWriteDr1((UINTN)Value);
    break;

  case MP_QSTR_dr2:
    AsmWriteDr2((UINTN)Value);
    break;

  case MP_QSTR_dr3:
    AsmWriteDr3((UINTN)Value);
    break;

  case MP_QSTR_dr4:
    AsmWriteDr4((UINTN)Value);
    break;

  case MP_QSTR_dr5:
    AsmWriteDr5((UINTN)Value);
    break;

  case MP_QSTR_dr6:
    AsmWriteDr6((UINTN)Value);
    break;

  case MP_QSTR_dr7:
    AsmWriteDr7((UINTN)Value);
    break;

  case MP_QSTR_tr:
    AsmWriteTr((UINT16)Value);
    break;

  case MP_QSTR_gdtr:
    AsmWriteGdtr(&Desc);
    break;

  case MP_QSTR_idtr:
    AsmWriteIdtr(&Desc);
    break;

  case MP_QSTR_ldtr:
    AsmWriteLdtr((UINT16)Value);
    break;

  case MP_QSTR_mm0:
    AsmWriteMm0(Value);
    break;

  case MP_QSTR_mm1:
    AsmWriteMm1(Value);
    break;

  case MP_QSTR_mm2:
    AsmWriteMm2(Value);
    break;

  case MP_QSTR_mm3:
    AsmWriteMm3(Value);
    break;

  case MP_QSTR_mm4:
    AsmWriteMm4(Value);
    break;

  case MP_QSTR_mm5:
    AsmWriteMm5(Value);
    break;

  case MP_QSTR_mm6:
    AsmWriteMm6(Value);
    break;

  case MP_QSTR_mm7:
    AsmWriteMm7(Value);
    break;

  default:
    nlr_raise(mp_obj_new_exception_msg_varg(
                &mp_type_Exception,
                "Invalid or unimplemented register: %s",
                qstr_str (reg)
                ));
    break;
  }
}

static mp_obj_t mod_ets_cpuid(size_t n_args, const mp_obj_t *args)
{
  UINT32          Reg1;
  UINT32          Reg2;
  UINT32          Eax;
  UINT32          Ebx;
  UINT32          Ecx;
  UINT32          Edx;
  mp_obj_tuple_t  *Results;

  Reg1 = 0;
  Reg2 = 0;

  if (n_args > 0) {
    Reg1 = mp_obj_get_int(args[0]);
  }

  if (n_args > 1) {
    Reg2 = mp_obj_get_int(args[1]);
  }

  Eax = Reg1;
  Ebx = 0;
  Ecx = Reg2;
  Edx = 0;
  AsmCpuid(Eax, &Eax, &Ebx, &Ecx, &Edx);

  if ((Eax | Ebx | Ecx | Edx) == 0) {
    nlr_raise(mp_obj_new_exception_msg_varg(
                &mp_type_Exception,
                "Invalid cpuid: EAX=%02XH (ECX=%d)",
                Reg1, Reg2
                ));
  }

  Results = MP_OBJ_TO_PTR (mp_obj_new_tuple (4, NULL));
  Results->items[0] = mp_obj_new_int_from_uint (Eax);
  Results->items[1] = mp_obj_new_int_from_uint (Ebx);
  Results->items[2] = mp_obj_new_int_from_uint (Ecx);
  Results->items[3] = mp_obj_new_int_from_uint (Edx);

  return MP_OBJ_FROM_PTR (Results);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN (mod_ets_cpuid_obj, 0, 2, mod_ets_cpuid);

void mod_ets_register_attr(mp_obj_t self_in, qstr attr, mp_obj_t *dest) {
  if (dest[0] == MP_OBJ_NULL) {
    dest[0] = mod_ets_get_reg(attr);
  } else {
    mod_ets_set_reg(attr, dest[1]);
    dest[0] = MP_OBJ_NULL;  // means sucess to store
  }
}

const mp_obj_type_t mp_type_reg = {
  { &mp_type_type },
  .name = MP_QSTR_REGISTER,
  .attr = mod_ets_register_attr,
};

const mp_obj_type_t mp_const_register_obj = {{ &mp_type_reg }};

STATIC const mp_rom_map_elem_t machine_module_globals_table[] = {
  { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_umachine) },

  { MP_ROM_QSTR(MP_QSTR_mem8), MP_ROM_PTR(&machine_mem8_obj) },
  { MP_ROM_QSTR(MP_QSTR_mem16), MP_ROM_PTR(&machine_mem16_obj) },
  { MP_ROM_QSTR(MP_QSTR_mem32), MP_ROM_PTR(&machine_mem32_obj) },
  { MP_ROM_QSTR(MP_QSTR_mem64), MP_ROM_PTR(&machine_mem64_obj) },

  { MP_ROM_QSTR(MP_QSTR_port), MP_ROM_PTR(&mp_type_port) },
  { MP_ROM_QSTR(MP_QSTR_port8), MP_ROM_PTR(&mp_const_port8_obj) },
  { MP_ROM_QSTR(MP_QSTR_port16), MP_ROM_PTR(&mp_const_port16_obj) },
  { MP_ROM_QSTR(MP_QSTR_port32), MP_ROM_PTR(&mp_const_port32_obj) },

  { MP_ROM_QSTR(MP_QSTR_reset),  MP_ROM_PTR(&mod_machine_reset_obj) },
  { MP_ROM_QSTR(MP_QSTR_freq),  MP_ROM_PTR(&mod_machine_freq_obj) },
  { MP_ROM_QSTR(MP_QSTR_rdmsr), MP_ROM_PTR(&mod_ets_rdmsr_obj) },
  { MP_ROM_QSTR(MP_QSTR_wrmsr), MP_ROM_PTR(&mod_ets_wrmsr_obj) },
  { MP_ROM_QSTR(MP_QSTR_regs), MP_ROM_PTR(&mp_const_register_obj) },
  { MP_ROM_QSTR(MP_QSTR_cpuid), MP_ROM_PTR(&mod_ets_cpuid_obj) },
};

STATIC MP_DEFINE_CONST_DICT(machine_module_globals, machine_module_globals_table);

const mp_obj_module_t mp_module_machine = {
  .base = { &mp_type_module },
  .globals = (mp_obj_dict_t*)&machine_module_globals,
};

#endif // MICROPY_PY_MACHINE
