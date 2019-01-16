/** @file
  Edk2 test intefaces for MicroPythhon.

Copyright (c) 2017 - 2018, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <py/mpconfig.h>
#include <py/nlr.h>
#include <py/runtime.h>
#include <py/objtuple.h>
#include <py/objstr.h>
#include <extmod/misc.h>
#include <py/obj.h>
#include <py/objarray.h>
#include <py/objexcept.h>
#include <py/objint.h>
#include <py/objfun.h>

#include <Uefi/UefiSpec.h>
#include <Pi/PiDxeCis.h>

#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>

#include <Protocol/VirtualConsole.h>

#include "objuefi.h"

STATIC EDKII_VIRTUAL_CONSOLE_PROTOCOL *mVirtualConsole = NULL;

extern mp_obj_t UpySuspend(mp_obj_t ms);
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_ets_suspend_obj, UpySuspend);

typedef struct _mp_obj_register_t {
    mp_obj_base_t     base;
} mp_obj_register_t;

// mp_obj_t ch, mp_obj_t scan, mp_obj_t shift, mp_obj_t toggle
static mp_obj_t mod_ets_press_key(size_t n_args, const mp_obj_t *args)
{
  EFI_KEY_DATA                    KeyData;
  EFI_STATUS                      Status;
  const char                      *Input;
  size_t                          Length;

  if (mVirtualConsole == NULL) {
    Status = gBS->LocateProtocol(&gEdkiiVirtualConsoleProtocolGuid, NULL, (VOID **)&mVirtualConsole);
    RAISE_UEFI_EXCEPTION_ON_ERROR (Status);
  }

  SetMem(&KeyData, sizeof(KeyData), 0);

  if (MP_OBJ_IS_STR_OR_BYTES(args[0])) {
    Input = mp_obj_str_get_data(args[0], &Length);
    if (Length > 1) {
      KeyData.Key.UnicodeChar = ((CHAR16 *)Input)[0];
    } else {
      KeyData.Key.UnicodeChar = Input[0];
    }
  } else if (MP_OBJ_IS_INT(args[0])) {
    KeyData.Key.UnicodeChar = mp_obj_get_int(args[0]);
  } else {
    KeyData.Key.UnicodeChar = CHAR_NULL;
  }


  if (n_args > 1) {
    KeyData.Key.ScanCode = mp_obj_get_int(args[1]);
  }

  if (n_args > 2) {
    KeyData.KeyState.KeyShiftState = mp_obj_get_int(args[2]);
    if (KeyData.KeyState.KeyShiftState) {
      KeyData.KeyState.KeyShiftState |= EFI_SHIFT_STATE_VALID;
    }
  }

  if (n_args > 3) {
    KeyData.KeyState.KeyToggleState = mp_obj_get_int(args[3]);
    if (KeyData.KeyState.KeyToggleState) {
      KeyData.KeyState.KeyToggleState |= EFI_TOGGLE_STATE_VALID;
    }
  }

  mVirtualConsole->InputKey(mVirtualConsole, &KeyData);
  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_ets_press_key_obj, 1, 4, mod_ets_press_key);

//typedef
//EFI_STATUS
//(EFIAPI *EDKII_VIRTUAL_CONSOLE_GET_SCREEN)(
//  IN     EDKII_VIRTUAL_CONSOLE_PROTOCOL        *This,
//  IN OUT VIRTUAL_CONSOLE_CHAR                  *ScreenBuffer,
//  IN OUT UINTN                                 *BufferSize,
//  IN     BOOLEAN                               IncludingHistory
//  );
static mp_obj_t mod_ets_get_screen(size_t n_args, const mp_obj_t *args)
{
  EFI_STATUS                      Status;
  VIRTUAL_CONSOLE_CHAR            *Buffer;
  VIRTUAL_CONSOLE_CHAR            *CharPtr;
  UINTN                           CharNum;
  BOOLEAN                         IncludeHistory;
  UINTN                           Index;
  mp_obj_tuple_t                  *ScreenCharAttr;
  mp_obj_tuple_t                  *ScreenSnapshot;
  CHAR8                           *ScreenChar;

  if (mVirtualConsole == NULL) {
    Status = gBS->LocateProtocol(&gEdkiiVirtualConsoleProtocolGuid, NULL, (VOID **)&mVirtualConsole);
    RAISE_UEFI_EXCEPTION_ON_ERROR (Status);
  }

  ScreenSnapshot = NULL;
  Buffer = NULL;
  CharNum = 0;
  IncludeHistory = (n_args == 1) ? (args[0] == mp_const_true) : FALSE;
  Status = mVirtualConsole->GetScreen(mVirtualConsole, Buffer, &CharNum, IncludeHistory);
  if (Status == EFI_BUFFER_TOO_SMALL && CharNum > 0) {
    Buffer = AllocatePool(CharNum * sizeof(VIRTUAL_CONSOLE_CHAR));
    ASSERT(Buffer != NULL);

    ScreenChar = AllocatePool((CharNum + 1) * sizeof(CHAR8));
    ASSERT(ScreenChar != NULL);

    Status = mVirtualConsole->GetScreen(mVirtualConsole, Buffer, &CharNum, IncludeHistory);
    if (!EFI_ERROR(Status)) {
      ScreenSnapshot = MP_OBJ_TO_PTR(mp_obj_new_tuple(2, NULL));
      ScreenCharAttr = MP_OBJ_TO_PTR(mp_obj_new_tuple(CharNum, NULL));

      CharPtr = Buffer;
      for (Index = 0; Index < CharNum; ++Index, ++CharPtr) {
        ScreenChar[Index] = (CHAR8)CharPtr->Char;
        // use space to replace null-char or non-ascii-char
        if (ScreenChar[Index] == 0 || ScreenChar[Index] < 0) {
          ScreenChar[Index] = ' ';
        }

        ScreenCharAttr->items[Index] = mp_obj_new_int_from_uint(CharPtr->Attribute);
      }

      ScreenChar[Index] = '\0';
      ScreenSnapshot->items[0] = mp_obj_new_str_of_type(&mp_type_str, (const byte *)ScreenChar, CharNum);
      ScreenSnapshot->items[1] = MP_OBJ_FROM_PTR(ScreenCharAttr);
    }

    FreePool(Buffer);
    FreePool(ScreenChar);
  }

  return MP_OBJ_FROM_PTR(ScreenSnapshot);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_ets_snapshot_obj, 0, 1, mod_ets_get_screen);

static mp_obj_t mod_ets_clear_history(void)
{
  EFI_STATUS                      Status;

  if (mVirtualConsole == NULL) {
    Status = gBS->LocateProtocol(&gEdkiiVirtualConsoleProtocolGuid, NULL, (VOID **)&mVirtualConsole);
    RAISE_UEFI_EXCEPTION_ON_ERROR (Status);
  }

  mVirtualConsole->ClearHistory(mVirtualConsole);

  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(mod_ets_clear_history_obj, mod_ets_clear_history);

static mp_obj_t mod_ets_debug(size_t n_args, const mp_obj_t *args)
{
  UINTN       Level;
  size_t      Length;
  CHAR8       *MsgType;

  if (n_args == 1) {
    Level = DEBUG_INFO;
  } else {
    Level = mp_obj_get_int(args[1]);
  }

  switch (Level) {
  case DEBUG_ERROR:
    MsgType = "ERROR";
    break;

  case DEBUG_WARN:
    MsgType = "WARN";
    break;

  case DEBUG_VERBOSE:
    MsgType = "VERBOSE";
    break;

  case DEBUG_INFO:
  default:
    MsgType = "INFO";
    break;
  }

  DEBUG((Level, "[ETS.%a] %a", MsgType, mp_obj_str_get_data(args[0], &Length)));

  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_ets_debug_obj, 1, 2, mod_ets_debug);

////////////////////////////////////////////////////////////////////////////////
///
////////////////////////////////////////////////////////////////////////////////
STATIC const mp_rom_map_elem_t _ets_module_globals_table[] = {
  { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR__ets) },
  { MP_ROM_QSTR(MP_QSTR_suspend), MP_ROM_PTR(&mod_ets_suspend_obj) },
  { MP_ROM_QSTR(MP_QSTR_press), MP_ROM_PTR(&mod_ets_press_key_obj) },
  { MP_ROM_QSTR(MP_QSTR_snapshot), MP_ROM_PTR(&mod_ets_snapshot_obj) },
  { MP_ROM_QSTR(MP_QSTR_clear_history), MP_ROM_PTR(&mod_ets_clear_history_obj) },
  { MP_ROM_QSTR(MP_QSTR_debug), MP_ROM_PTR(&mod_ets_debug_obj) },
};
STATIC MP_DEFINE_CONST_DICT(_ets_module_globals, _ets_module_globals_table);

const mp_obj_module_t mp_module__ets = {
  .base = { &mp_type_module },
  .globals = (mp_obj_dict_t *)&_ets_module_globals,
};

