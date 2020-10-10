/** @file
  Implement ReadOnly Variable Services required by PEIM and install
  PEI ReadOnly Varaiable2 PPI. These services operates the non volatile storage space.

Copyright (c) 2006 - 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/


#include "Variable.h"
#include "VariableStore.h"

/**

  Gets the pointer to the first variable header in given variable store area.

  @param VarStoreHeader  Pointer to the Variable Store Header.

  @return Pointer to the first variable header.

**/
VARIABLE_HEADER *
GetStartPointer (
  IN VARIABLE_STORE_HEADER       *VarStoreHeader
  )
{
  //
  // The start of variable store
  //
  return (VARIABLE_HEADER *) HEADER_ALIGN (VarStoreHeader + 1);
}


/**

  Gets the pointer to the end of the variable storage area.

  This function gets pointer to the end of the variable storage
  area, according to the input variable store header.

  @param VarStoreHeader  Pointer to the Variable Store Header.

  @return Pointer to the end of the variable storage area.

**/
VARIABLE_HEADER *
GetEndPointer (
  IN VARIABLE_STORE_HEADER       *VarStoreHeader
  )
{
  //
  // The end of variable store
  //
  return (VARIABLE_HEADER *) HEADER_ALIGN ((UINTN) VarStoreHeader + VarStoreHeader->Size);
}


/**
  This code checks if variable header is valid or not.

  @param  Variable  Pointer to the Variable Header.

  @retval TRUE      Variable header is valid.
  @retval FALSE     Variable header is not valid.

**/
BOOLEAN
IsValidVariableHeader (
  IN  VARIABLE_HEADER   *Variable
  )
{
  if (Variable == NULL || Variable->StartId != VARIABLE_DATA ) {
    return FALSE;
  }

  return TRUE;
}

/**
  This code gets the size of variable header.

  @param AuthFlag   Authenticated variable flag.

  @return Size of variable header in bytes in type UINTN.

**/
UINTN
GetVariableHeaderSize (
  IN  BOOLEAN       AuthFlag
  )
{
  UINTN Value;

  if (AuthFlag) {
    Value = sizeof (AUTHENTICATED_VARIABLE_HEADER);
  } else {
    Value = sizeof (VARIABLE_HEADER);
  }

  return Value;
}

/**
  This code gets the size of name of variable.

  @param  Variable  Pointer to the Variable Header.
  @param  AuthFlag  Authenticated variable flag.

  @return Size of variable in bytes in type UINTN.

**/
UINTN
NameSizeOfVariable (
  IN  VARIABLE_HEADER   *Variable,
  IN  BOOLEAN           AuthFlag
  )
{
  AUTHENTICATED_VARIABLE_HEADER *AuthVariable;

  AuthVariable = (AUTHENTICATED_VARIABLE_HEADER *) Variable;
  if (AuthFlag) {
    if (AuthVariable->State == (UINT8) (-1) ||
       AuthVariable->DataSize == (UINT32) (-1) ||
       AuthVariable->NameSize == (UINT32) (-1) ||
       AuthVariable->Attributes == (UINT32) (-1)) {
      return 0;
    }
    return (UINTN) AuthVariable->NameSize;
  } else {
    if (Variable->State == (UINT8) (-1) ||
       Variable->DataSize == (UINT32) (-1) ||
       Variable->NameSize == (UINT32) (-1) ||
       Variable->Attributes == (UINT32) (-1)) {
      return 0;
    }
    return (UINTN) Variable->NameSize;
  }
}


/**
  This code gets the size of data of variable.

  @param  Variable  Pointer to the Variable Header.
  @param  AuthFlag  Authenticated variable flag.

  @return Size of variable in bytes in type UINTN.

**/
UINTN
DataSizeOfVariable (
  IN  VARIABLE_HEADER   *Variable,
  IN  BOOLEAN           AuthFlag
  )
{
  AUTHENTICATED_VARIABLE_HEADER *AuthVariable;

  AuthVariable = (AUTHENTICATED_VARIABLE_HEADER *) Variable;
  if (AuthFlag) {
    if (AuthVariable->State == (UINT8) (-1) ||
       AuthVariable->DataSize == (UINT32) (-1) ||
       AuthVariable->NameSize == (UINT32) (-1) ||
       AuthVariable->Attributes == (UINT32) (-1)) {
      return 0;
    }
    return (UINTN) AuthVariable->DataSize;
  } else {
    if (Variable->State == (UINT8) (-1) ||
       Variable->DataSize == (UINT32) (-1) ||
       Variable->NameSize == (UINT32) (-1) ||
       Variable->Attributes == (UINT32) (-1)) {
      return 0;
    }
    return (UINTN) Variable->DataSize;
  }
}

/**
  This code gets the pointer to the variable name.

  @param   Variable  Pointer to the Variable Header.
  @param   AuthFlag  Authenticated variable flag.

  @return  A CHAR16* pointer to Variable Name.

**/
CHAR16 *
GetVariableNamePtr (
  IN VARIABLE_HEADER    *Variable,
  IN BOOLEAN            AuthFlag
  )
{
  return (CHAR16 *) ((UINTN) Variable + GetVariableHeaderSize (AuthFlag));
}

/**
  This code gets the pointer to the variable guid.

  @param Variable   Pointer to the Variable Header.
  @param AuthFlag   Authenticated variable flag.

  @return A EFI_GUID* pointer to Vendor Guid.

**/
EFI_GUID *
GetVendorGuidPtr (
  IN VARIABLE_HEADER    *Variable,
  IN BOOLEAN            AuthFlag
  )
{
  AUTHENTICATED_VARIABLE_HEADER *AuthVariable;

  AuthVariable = (AUTHENTICATED_VARIABLE_HEADER *) Variable;
  if (AuthFlag) {
    return &AuthVariable->VendorGuid;
  } else {
    return &Variable->VendorGuid;
  }
}

/**
  This code gets the pointer to the variable data.

  @param   Variable         Pointer to the Variable Header.
  @param   VariableHeader   Pointer to the Variable Header that has consecutive content.
  @param   AuthFlag         Authenticated variable flag.

  @return  A UINT8* pointer to Variable Data.

**/
UINT8 *
GetVariableDataPtr (
  IN  VARIABLE_HEADER   *Variable,
  IN  VARIABLE_HEADER   *VariableHeader,
  IN  BOOLEAN           AuthFlag
  )
{
  UINTN Value;

  //
  // Be careful about pad size for alignment
  //
  Value =  (UINTN) GetVariableNamePtr (Variable, AuthFlag);
  Value += NameSizeOfVariable (VariableHeader, AuthFlag);
  Value += GET_PAD_SIZE (NameSizeOfVariable (VariableHeader, AuthFlag));

  return (UINT8 *) Value;
}


/**
  This code gets the pointer to the next variable header.

  @param  StoreInfo         Pointer to variable store info structure.
  @param  Variable          Pointer to the Variable Header.
  @param  VariableHeader    Pointer to the Variable Header that has consecutive content.

  @return  A VARIABLE_HEADER* pointer to next variable header.

**/
VARIABLE_HEADER *
GetNextVariablePtr (
  IN  VARIABLE_STORE_INFO   *StoreInfo,
  IN  VARIABLE_HEADER       *Variable,
  IN  VARIABLE_HEADER       *VariableHeader
  )
{
  EFI_PHYSICAL_ADDRESS  TargetAddress;
  EFI_PHYSICAL_ADDRESS  SpareAddress;
  UINTN                 Value;

  Value =  (UINTN) GetVariableDataPtr (Variable, VariableHeader, StoreInfo->AuthFlag);
  Value += DataSizeOfVariable (VariableHeader, StoreInfo->AuthFlag);
  Value += GET_PAD_SIZE (DataSizeOfVariable (VariableHeader, StoreInfo->AuthFlag));
  //
  // Be careful about pad size for alignment
  //
  Value = HEADER_ALIGN (Value);

  if (StoreInfo->FtwLastWriteData != NULL) {
    TargetAddress = StoreInfo->FtwLastWriteData->TargetAddress;
    SpareAddress = StoreInfo->FtwLastWriteData->SpareAddress;
    if (((UINTN) Variable < (UINTN) TargetAddress) && (Value >= (UINTN) TargetAddress)) {
      //
      // Next variable is in spare block.
      //
      Value = (UINTN) SpareAddress + (Value - (UINTN) TargetAddress);
    }
  }

  return (VARIABLE_HEADER *) Value;
}

/**
  Compare two variable names, one of them may be inconsecutive.

  @param StoreInfo      Pointer to variable store info structure.
  @param Name1          Pointer to one variable name.
  @param Name2          Pointer to another variable name.
  @param NameSize       Variable name size.

  @retval TRUE          Name1 and Name2 are identical.
  @retval FALSE         Name1 and Name2 are not identical.

**/
BOOLEAN
CompareVariableName (
  IN VARIABLE_STORE_INFO    *StoreInfo,
  IN CONST CHAR16           *Name1,
  IN CONST CHAR16           *Name2,
  IN UINTN                  NameSize
  )
{
  EFI_PHYSICAL_ADDRESS  TargetAddress;
  EFI_PHYSICAL_ADDRESS  SpareAddress;
  UINTN                 PartialNameSize;

  if (StoreInfo->FtwLastWriteData != NULL) {
    TargetAddress = StoreInfo->FtwLastWriteData->TargetAddress;
    SpareAddress = StoreInfo->FtwLastWriteData->SpareAddress;
    if (((UINTN) Name1 < (UINTN) TargetAddress) && (((UINTN) Name1 + NameSize) > (UINTN) TargetAddress)) {
      //
      // Name1 is inconsecutive.
      //
      PartialNameSize = (UINTN) TargetAddress - (UINTN) Name1;
      //
      // Partial content is in NV storage.
      //
      if (CompareMem ((UINT8 *) Name1, (UINT8 *) Name2, PartialNameSize) == 0) {
        //
        // Another partial content is in spare block.
        //
        if (CompareMem ((UINT8 *) (UINTN) SpareAddress, (UINT8 *) Name2 + PartialNameSize, NameSize - PartialNameSize) == 0) {
          return TRUE;
        }
      }
      return FALSE;
    } else if (((UINTN) Name2 < (UINTN) TargetAddress) && (((UINTN) Name2 + NameSize) > (UINTN) TargetAddress)) {
      //
      // Name2 is inconsecutive.
      //
      PartialNameSize = (UINTN) TargetAddress - (UINTN) Name2;
      //
      // Partial content is in NV storage.
      //
      if (CompareMem ((UINT8 *) Name2, (UINT8 *) Name1, PartialNameSize) == 0) {
        //
        // Another partial content is in spare block.
        //
        if (CompareMem ((UINT8 *) (UINTN) SpareAddress, (UINT8 *) Name1 + PartialNameSize, NameSize - PartialNameSize) == 0) {
          return TRUE;
        }
      }
      return FALSE;
    }
  }

  //
  // Both Name1 and Name2 are consecutive.
  //
  if (CompareMem ((UINT8 *) Name1, (UINT8 *) Name2, NameSize) == 0) {
    return TRUE;
  }
  return FALSE;
}

/**
  This function compares a variable with variable entries in database.

  @param  StoreInfo     Pointer to variable store info structure.
  @param  Variable      Pointer to the variable in our database
  @param  VariableHeader Pointer to the Variable Header that has consecutive content.
  @param  VariableName  Name of the variable to compare to 'Variable'
  @param  VendorGuid    GUID of the variable to compare to 'Variable'
  @param  PtrTrack      Variable Track Pointer structure that contains Variable Information.

  @retval EFI_SUCCESS    Found match variable
  @retval EFI_NOT_FOUND  Variable not found

**/
EFI_STATUS
CompareWithValidVariable (
  IN  VARIABLE_STORE_INFO           *StoreInfo,
  IN  VARIABLE_HEADER               *Variable,
  IN  VARIABLE_HEADER               *VariableHeader,
  IN  CONST CHAR16                  *VariableName,
  IN  CONST EFI_GUID                *VendorGuid,
  OUT VARIABLE_POINTER_TRACK        *PtrTrack
  )
{
  VOID      *Point;
  EFI_GUID  *TempVendorGuid;

  TempVendorGuid = GetVendorGuidPtr (VariableHeader, StoreInfo->AuthFlag);

  if (VariableName[0] == 0) {
    PtrTrack->CurrPtr = Variable;
    return EFI_SUCCESS;
  } else {
    //
    // Don't use CompareGuid function here for performance reasons.
    // Instead we compare the GUID a UINT32 at a time and branch
    // on the first failed comparison.
    //
    if ((((INT32 *) VendorGuid)[0] == ((INT32 *) TempVendorGuid)[0]) &&
        (((INT32 *) VendorGuid)[1] == ((INT32 *) TempVendorGuid)[1]) &&
        (((INT32 *) VendorGuid)[2] == ((INT32 *) TempVendorGuid)[2]) &&
        (((INT32 *) VendorGuid)[3] == ((INT32 *) TempVendorGuid)[3])
        ) {
      ASSERT (NameSizeOfVariable (VariableHeader, StoreInfo->AuthFlag) != 0);
      Point = (VOID *) GetVariableNamePtr (Variable, StoreInfo->AuthFlag);
      if (CompareVariableName (StoreInfo, VariableName, Point, NameSizeOfVariable (VariableHeader, StoreInfo->AuthFlag))) {
        PtrTrack->CurrPtr = Variable;
        return EFI_SUCCESS;
      }
    }
  }

  return EFI_NOT_FOUND;
}

/**
  Get variable header that has consecutive content.

  @param StoreInfo      Pointer to variable store info structure.
  @param Variable       Pointer to the Variable Header.
  @param VariableHeader Pointer to Pointer to the Variable Header that has consecutive content.

  @retval TRUE          Variable header is valid.
  @retval FALSE         Variable header is not valid.

**/
BOOLEAN
GetVariableHeader (
  IN VARIABLE_STORE_INFO    *StoreInfo,
  IN VARIABLE_HEADER        *Variable,
  OUT VARIABLE_HEADER       **VariableHeader
  )
{
  EFI_PHYSICAL_ADDRESS  TargetAddress;
  EFI_PHYSICAL_ADDRESS  SpareAddress;
  EFI_HOB_GUID_TYPE     *GuidHob;
  UINTN                 PartialHeaderSize;

  if (Variable == NULL) {
    return FALSE;
  }

  //
  // First assume variable header pointed by Variable is consecutive.
  //
  *VariableHeader = Variable;

  if (StoreInfo->FtwLastWriteData != NULL) {
    TargetAddress = StoreInfo->FtwLastWriteData->TargetAddress;
    SpareAddress = StoreInfo->FtwLastWriteData->SpareAddress;
    if (((UINTN) Variable > (UINTN) SpareAddress) &&
        (((UINTN) Variable - (UINTN) SpareAddress + (UINTN) TargetAddress) >= (UINTN) GetEndPointer (StoreInfo->VariableStoreHeader))) {
      //
      // Reach the end of variable store.
      //
      return FALSE;
    }
    if (((UINTN) Variable < (UINTN) TargetAddress) && (((UINTN) Variable + GetVariableHeaderSize (StoreInfo->AuthFlag)) > (UINTN) TargetAddress)) {
      //
      // Variable header pointed by Variable is inconsecutive,
      // create a guid hob to combine the two partial variable header content together.
      //
      GuidHob = GetFirstGuidHob (&gEfiCallerIdGuid);
      if (GuidHob != NULL) {
        *VariableHeader = (VARIABLE_HEADER *) GET_GUID_HOB_DATA (GuidHob);
      } else {
        *VariableHeader = (VARIABLE_HEADER *) BuildGuidHob (&gEfiCallerIdGuid, GetVariableHeaderSize (StoreInfo->AuthFlag));
        PartialHeaderSize = (UINTN) TargetAddress - (UINTN) Variable;
        //
        // Partial content is in NV storage.
        //
        CopyMem ((UINT8 *) *VariableHeader, (UINT8 *) Variable, PartialHeaderSize);
        //
        // Another partial content is in spare block.
        //
        CopyMem ((UINT8 *) *VariableHeader + PartialHeaderSize, (UINT8 *) (UINTN) SpareAddress, GetVariableHeaderSize (StoreInfo->AuthFlag) - PartialHeaderSize);
      }
    }
  } else {
    if (Variable >= GetEndPointer (StoreInfo->VariableStoreHeader)) {
      //
      // Reach the end of variable store.
      //
      return FALSE;
    }
  }

  return IsValidVariableHeader (*VariableHeader);
}

/**
  Get variable name or data to output buffer.

  @param  StoreInfo     Pointer to variable store info structure.
  @param  NameOrData    Pointer to the variable name/data that may be inconsecutive.
  @param  Size          Variable name/data size.
  @param  Buffer        Pointer to output buffer to hold the variable name/data.

**/
VOID
GetVariableNameOrData (
  IN VARIABLE_STORE_INFO    *StoreInfo,
  IN UINT8                  *NameOrData,
  IN UINTN                  Size,
  OUT UINT8                 *Buffer
  )
{
  EFI_PHYSICAL_ADDRESS  TargetAddress;
  EFI_PHYSICAL_ADDRESS  SpareAddress;
  UINTN                 PartialSize;

  if (StoreInfo->FtwLastWriteData != NULL) {
    TargetAddress = StoreInfo->FtwLastWriteData->TargetAddress;
    SpareAddress = StoreInfo->FtwLastWriteData->SpareAddress;
    if (((UINTN) NameOrData < (UINTN) TargetAddress) && (((UINTN) NameOrData + Size) > (UINTN) TargetAddress)) {
      //
      // Variable name/data is inconsecutive.
      //
      PartialSize = (UINTN) TargetAddress - (UINTN) NameOrData;
      //
      // Partial content is in NV storage.
      //
      CopyMem (Buffer, NameOrData, PartialSize);
      //
      // Another partial content is in spare block.
      //
      CopyMem (Buffer + PartialSize, (UINT8 *) (UINTN) SpareAddress, Size - PartialSize);
      return;
    }
  }

  //
  // Variable name/data is consecutive.
  //
  CopyMem (Buffer, NameOrData, Size);
}

/**

  Retrieve details about a variable, given by VariableInfo->Buffer or
  VariableInfo->Index, and pass the details back in VariableInfo->Header.

  This function is used to resolve the variable data structure into
  VariableInfo->Header, for easier access later without revisiting the variable
  data in variable store. If pointers in the structure of VariableInfo->Header
  are not NULL, it's supposed that they are buffers passed in to hold a copy of
  data of corresponding data fields in variable data structure. Otherwise, this
  function simply returns pointers pointing to address of those data fields.

  The variable is specified by either VariableInfo->Index or VariableInfo->Buffer.
  If VariableInfo->Index is given, this function finds the corresponding variable
  first from variable storage according to the Index.

  If both VariableInfo->Index and VariableInfo->Buffer are given, it's supposed
  that VariableInfo->Buffer is a buffer passed in to hold a whole copy of
  requested variable data to be returned.

  @param[in,out] VariableInfo             Pointer to variable information.

  @retval EFI_INVALID_PARAMETER  VariableInfo is NULL or both VariableInfo->Buffer
                                 and VariableInfo->Index are NULL (0).
  @retval EFI_NOT_FOUND          If given Buffer or Index is out of range of
                                 any given or internal storage copies.
  @retval EFI_SUCCESS            Variable details are retrieved successfully.

**/
EFI_STATUS
EFIAPI
GetVariableInfo (
  IN  OUT PROTECTED_VARIABLE_INFO   *VariableInfo
  )
{
  VARIABLE_HEADER               *VariablePtr;
  VARIABLE_HEADER               *VariableHeader;
  VARIABLE_HEADER               *VariableBuffer;
  AUTHENTICATED_VARIABLE_HEADER *AuthVariablePtr;
  VARIABLE_STORE_TYPE           StoreType;
  VARIABLE_STORE_INFO           StoreInfo;
  UINTN                         Offset;
  UINTN                         NameSize;
  UINTN                         DataSize;

  if (VariableInfo == NULL ||
      (VariableInfo->Buffer == NULL && VariableInfo->Index == VAR_INDEX_INVALID)) {
    ASSERT (VariableInfo != NULL);
    ASSERT (VariableInfo->Buffer != NULL);
    ASSERT (VariableInfo->Index != VAR_INDEX_INVALID);
    return EFI_INVALID_PARAMETER;
  }

  VariableBuffer  = VariableInfo->Buffer;
  VariableHeader  = NULL;
  VariablePtr     = NULL;
  if (VariableInfo->Index != VAR_INDEX_INVALID) {
    //
    // For variables stored in memory-like media, e.g. SPI flash or HOB,
    // VariableInfo->Index is interpreted simply as the offset to the start of
    // variable store.
    //
    StoreType = VAR_INDEX_STORE_TYPE (VariableInfo->Index);
    GetVariableStore (StoreType, &StoreInfo);

    Offset = (UINTN)(VariableInfo->Index & (~VAR_INDEX_STORE_TYPE_MASK));
    if (StoreInfo.FtwLastWriteData != NULL
        && ((UINTN)StoreInfo.FtwLastWriteData->TargetAddress
            - (UINTN)StoreInfo.VariableStoreHeader) >= Offset)
    {
      Offset -= ((UINTN)StoreInfo.FtwLastWriteData->TargetAddress - (UINTN)StoreInfo.VariableStoreHeader);
      if (Offset >= StoreInfo.FtwLastWriteData->Length
          || (Offset + GetVariableHeaderSize (StoreInfo.AuthFlag))
             >= StoreInfo.FtwLastWriteData->Length)
      {
        return EFI_NOT_FOUND;
      }

      VariablePtr = (VARIABLE_HEADER *)((UINTN)StoreInfo.FtwLastWriteData->SpareAddress + Offset);
    } else {
      VariablePtr = (VARIABLE_HEADER *)((UINTN)StoreInfo.VariableStoreHeader + Offset);
    }

    //
    // Keep a whole copy of the variable, if a buffer is given.
    //
    //  Note: The variable might not be in consecutive space.
    //
    if (VariableBuffer != NULL) {
      //
      // Variable header
      //
      GetVariableHeader (StoreInfo, VariablePtr, &VariableHeader);
      if (!IsValidVariableHeader (VariableHeader)) {
        return EFI_COMPROMISED_DATA;
      }

      CopyMem (
        VariableBuffer,
        VariableHeader,
        GetVariableHeaderSize (StoreInfo.AuthFlag)
        );

      //
      // Variable name
      //
      GetVariableNameOrData (
        StoreInfo,
        GetVariableNamePtr (VariablePtr, VariableHeader, StoreInfo.AuthFlag),
        NameSizeOfVariable (VariableHeader, StoreInfo.Flag),
        GetVariableNamePtr (VariableBuffer, VariableHeader, StoreInfo.AuthFlag)
        );

      //
      // Variable data
      //
      GetVariableNameOrData (
        StoreInfo,
        GetVariableDataPtr (VariablePtr, VariableHeader, StoreInfo.AuthFlag),
        DataSizeOfVariable (VariableHeader, StoreInfo.Flag),
        GetVariableDataPtr (VariableBuffer, VariableHeader, StoreInfo.AuthFlag)
        );
    } else if (StoreType == VariableStoreTypeHob) {
      VariableBuffer = VariablePtr;
      VariableHeader = VariablePtr;
    }

    VariableInfo->Flags.Auth = StoreInfo.AuthFlag;
  } else if (VariableBuffer != NULL) {
    VariableHeader  = VariableBuffer;
    VariablePtr     = VariableBuffer;
  }

  ASSERT (VariablePtr != NULL);
  ASSERT (VariableHeader != NULL);

  NameSize = NameSizeOfVariable (VariableHeader, VariableInfo->Flags.Auth);
  DataSize = DataSizeOfVariable (VariableHeader, VariableInfo->Flags.Auth);

  if (VariableInfo->Header.VendorGuid == NULL) {
    VariableInfo->Header.VendorGuid
      = GetVendorGuidPtr (VariableHeader, VariableInfo->Flags.Auth);
  } else {
    CopyGuid (VariableInfo->Header.VendorGuid,
              GetVendorGuidPtr (VariableHeader, VariableInfo->Flags.Auth));
  }

  if (VariableInfo->Flags.Auth) {
    AuthVariablePtr = (AUTHENTICATED_VARIABLE_HEADER *)VariableHeader;

    VariableInfo->Header.Attributes     = AuthVariablePtr->Attributes;
    VariableInfo->Header.PubKeyIndex    = AuthVariablePtr->PubKeyIndex;
    VariableInfo->Header.MonotonicCount = ReadUnaligned64 (&(AuthVariablePtr->MonotonicCount));
    if (VariableInfo->Header.TimeStamp == NULL) {
      VariableInfo->Header.TimeStamp    = &AuthVariablePtr->TimeStamp;
    } else {
      CopyMem (VariableInfo->Header.TimeStamp, &AuthVariablePtr->TimeStamp,
               sizeof (EFI_TIME));
    }
  } else {
    VariableInfo->Header.Attributes     = VariableHeader->Attributes;
    VariableInfo->Header.PubKeyIndex    = 0;
    VariableInfo->Header.MonotonicCount = 0;
    VariableInfo->Header.TimeStamp      = NULL;
  }

  //
  // If no consecutive space, don't return back variable name and data.
  //
  if (VariableBuffer != NULL) {
    if (VariableInfo->Header.VariableName == NULL) {
      VariableInfo->Header.VariableName
        = GetVariableNamePtr (VariableBuffer, VariableInfo->Flags.Auth);
    } else if (VariableInfo->Header.NameSize >= NameSize) {
      CopyMem (VariableInfo->Header.VariableName,
               GetVariableNamePtr (VariableBuffer, VariableInfo->Flags.Auth),
               NameSize);
    }

    if (VariableInfo->Header.Data == NULL) {
      VariableInfo->Header.Data
        = GetVariableDataPtr (VariableBuffer, VariableBuffer, VariableInfo->Flags.Auth);
    } else if (VariableInfo->Header.DataSize >= DataSize) {
      CopyMem (
        VariableInfo->Header.Data,
        GetVariableDataPtr (VariableBuffer, VariableBuffer, VariableInfo->Flags.Auth),
        DataSize
        );
    }
  } else {
    if (VariableInfo->Header.VariableName != NULL
        && VariableInfo->Header.NameSize >= NameSize) {
      GetVariableNameOrData (
        StoreInfo,
        GetVariableNamePtr (VariablePtr, VariableHeader, StoreInfo.AuthFlag),
        NameSize,
        VariableInfo->Header.VariableName
        );
    }

    if (VariableInfo->Header.Data != NULL
        && VariableInfo->Header.DataSize >= DataSize) {
      GetVariableNameOrData (
        StoreInfo,
        GetVariableDataPtr (VariablePtr, VariableHeader, StoreInfo.AuthFlag),
        DataSize,
        VariableInfo->Header.Data
        );
    }
  }

  VariableInfo->Header.NameSize = NameSize;
  VariableInfo->Header.DataSize = DataSize;

  return EFI_SUCCESS;
}

/**

  Retrieve details of the variable next to given variable within VariableStore.

  If VarInfo->Buffer is NULL, the first one in VariableStore is returned.

  VariableStart and/or VariableEnd can be given optionally for the situation
  in which the valid storage space is smaller than the VariableStore->Size.
  This usually happens when PEI variable services make a compact variable
  cache to save memory, which cannot make use VariableStore->Size to determine
  the correct variable storage range.

  @param VariableStore            Pointer to a variable storage. It's optional.
  @param VariableStart            Start point of valid range in VariableStore.
  @param VariableEnd              End point of valid range in VariableStore.
  @param VariableInfo             Pointer to variable information.

  @retval EFI_INVALID_PARAMETER  VariableInfo or VariableStore is NULL.
  @retval EFI_NOT_FOUND          If the end of VariableStore is reached.
  @retval EFI_SUCCESS            The next variable is retrieved successfully.

**/
EFI_STATUS
EFIAPI
GetNextVariableInfo (
  IN      VARIABLE_STORE_HEADER     *VariableStore,
  IN      VARIABLE_HEADER           *VariableStart,
  IN      VARIABLE_HEADER           *VariableEnd,
  IN  OUT PROTECTED_VARIABLE_INFO   *VariableInfo
  )
{
  VARIABLE_HEADER                   *Variable;
  VARIABLE_STORE_INFO               StoreInfo;

  if (VariableStore == NULL || VariableInfo == NULL) {
    ASSERT (VariableStore != NULL);
    ASSERT (VariableInfo != NULL);
    return EFI_INVALID_PARAMETER;
  }

  StoreInfo.VariableStoreHeader = VariableStore;
  StoreInfo.AuthFlag            = VariableInfo->Flags.Auth;
  StoreInfo.FtwLastWriteData    = NULL;
  StoreInfo.IndexTable          = NULL;

  if (VariableEnd == NULL) {
    VariableEnd = GetEndPointer (VariableStore);
  }

  Variable = VariableInfo->Buffer;
  if (Variable == NULL) {
    Variable = (VariableStart != NULL) ? VariableStart
                                       : GetStartPointer (VariableStore);
  } else {
    Variable = GetNextVariablePtr (&StoreInfo, Variable, Variable);
  }

  VariableInfo->Buffer = Variable;
  VariableInfo->Index  = (UINT32)((UINTN)Variable - (UINTN)VariableStore);

  if (((UINTN)Variable + GetVariableHeaderSize (StoreInfo.AuthFlag)) >= (UINTN)VariableEnd
      || !IsValidVariableHeader (Variable))
  {
    return EFI_NOT_FOUND;
  }

  return GetVariableInfo (VariableStore, VariableInfo);
}

