/** @file
  The common protected variable operation routines.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Base.h>
#include <Uefi.h>
#include <PiPei.h>

#include <Guid/VariableFormat.h>
#include <Guid/VarErrorFlag.h>

#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>

#include "ProtectedVariableInternal.h"

EFI_TIME              mDefaultTimeStamp = {0,0,0,0,0,0,0,0,0,0,0};
VARIABLE_IDENTIFIER   mUnprotectedVariables[] = {
  {
    METADATA_HMAC_VARIABLE_NAME,
    &METADATA_HMAC_VARIABLE_GUID
  },
  {
    METADATA_HMAC_VARIABLE_NAME,
    &METADATA_HMAC_VARIABLE_GUID
  },
  {
    VAR_ERROR_FLAG_NAME,
    &gEdkiiVarErrorFlagGuid
  }
};

/**

  Retrieve the context and global configuration data structure from HOB.

  Once protected NV variable storage is cached and verified in PEI phase,
  all related information are stored in a HOB which can be used by PEI variable
  service itself and passed to SMM along with the boot flow, which can avoid
  many duplicate works, like generating HMAC key, verifying NV variable storage,
  etc.

  The HOB can be identified by gEdkiiProtectedVariableGlobalGuid.

  @param[out]   ContextIn   Pointer to context stored by PEI variable services.
  @param[out]   Global      Pointer to global configuration data from PEI phase.

  @retval EFI_SUCCESS     The HOB was found, and Context and Global are retrieved.
  @retval EFI_NOT_FOUND   The HOB was not found.

**/
EFI_STATUS
EFIAPI
GetProtectedVariableContextFromHob (
  OUT PROTECTED_VARIABLE_CONTEXT_IN   **ContextIn OPTIONAL,
  OUT PROTECTED_VARIABLE_GLOBAL       **Global OPTIONAL
  )
{
  VOID                            *Data;
  UINTN                           DataSize;
  EFI_PEI_HOB_POINTERS            Hob;
  EFI_HOB_MEMORY_ALLOCATION       *MemoryAllocationHob;

  //
  // Search the global from allocated memory blob.
  //
  Data = NULL;
  DataSize = 0;
  MemoryAllocationHob = NULL;
  Hob.Raw = GetFirstHob (EFI_HOB_TYPE_MEMORY_ALLOCATION);
  while (Hob.Raw != NULL) {
    MemoryAllocationHob = (EFI_HOB_MEMORY_ALLOCATION *) Hob.Raw;
    if (CompareGuid(&MemoryAllocationHob->AllocDescriptor.Name,
		                &gEdkiiProtectedVariableGlobalGuid)) {
      Data = (VOID *)(UINTN)
             MemoryAllocationHob->AllocDescriptor.MemoryBaseAddress;
      DataSize = (UINTN)MemoryAllocationHob->AllocDescriptor.MemoryLength;
      break;
	  }

    Hob.Raw = GET_NEXT_HOB (Hob);
    Hob.Raw = GetNextHob (EFI_HOB_TYPE_MEMORY_ALLOCATION, Hob.Raw);
  }

  ASSERT (Data != NULL);

  if (ContextIn != NULL) {
    *ContextIn = Data;
    ASSERT ((*ContextIn)->StructSize < DataSize);
  }

  if (Global != NULL) {
    *Global = (PROTECTED_VARIABLE_GLOBAL *)
              ((UINTN)Data + ((PROTECTED_VARIABLE_CONTEXT_IN *)Data)->StructSize);
    ASSERT ((*Global)->StructSize < DataSize);
    ASSERT ((((PROTECTED_VARIABLE_CONTEXT_IN *)Data)->StructSize
             + (*Global)->StructSize) <= DataSize);

    //
    // Fix pointers in the HOB
    //
    if ((*Global)->Table.Address < (UINTN)Data
        || (*Global)->Table.Address > (UINTN)Data + DataSize)
    {
      (*Global)->Table.Address = (EFI_PHYSICAL_ADDRESS)(*Global) + sizeof (PROTECTED_VARIABLE_GLOBAL);
      (*Global)->ProtectedVariableCache = (*Global)->Table.Address
                                          + (*Global)->TableCount * sizeof (UINT32);
      (*Global)->ProtectedVariableCache = (EFI_PHYSICAL_ADDRESS)
                                          ALIGN_VALUE ((*Global)->ProtectedVariableCache, 16);
    }
  }

  return EFI_SUCCESS;
}

/**

  Derive HMAC key from given variable root key.

  @param[in]  RootKey       Pointer to root key to derive from.
  @param[in]  RootKeySize   Size of root key.
  @param[out] HmacKey       Pointer to generated HMAC key.
  @param[in]  HmacKeySize   Size of HMAC key.

  @retval TRUE      The HMAC key is derived successfully.
  @retval FALSE     Failed to generate HMAC key from given root key.

**/
BOOLEAN
EFIAPI
GenerateMetaDataHmacKey (
  IN   CONST UINT8  *RootKey,
  IN   UINTN        RootKeySize,
  OUT  UINT8        *HmacKey,
  IN   UINTN        HmacKeySize
  )
{
  UINT8       Salt[AES_BLOCK_SIZE];

  return HkdfSha256ExtractAndExpand (
           RootKey,
           RootKeySize,
           Salt,
           0,
           (UINT8 *)METADATA_HMAC_KEY_NAME,
           METADATA_HMAC_KEY_NAME_SIZE,
           HmacKey,
           HmacKeySize
           );
}

/**

  Return the size of variable MetaDataHmacVar.

  @param[in] AuthFlag         Auth-variable indicator.

  @retval size of variable MetaDataHmacVar.

**/
UINTN
GetMetaDataHmacVarSize (
  IN      BOOLEAN     AuthFlag
  )
{
  UINTN           Size;

  if (AuthFlag) {
    Size = sizeof (AUTHENTICATED_VARIABLE_HEADER);
  } else {
    Size = sizeof (VARIABLE_HEADER);
  }

  Size += METADATA_HMAC_VARIABLE_NAME_SIZE;
  Size += GET_PAD_SIZE (Size);
  Size += METADATA_HMAC_SIZE;
  Size += GET_PAD_SIZE (Size);

  return Size;
}

/**

  Digests the given variable data and updates HMAC context.

  @param[in,out]  Context   Pointer to initialized HMAC context.
  @param[in]      VarInfo   Pointer to variable data.

  @retval TRUE    HMAC context was updated successfully.
  @retval FALSE   Failed to update HMAC context.

**/
BOOLEAN
UpdateVariableMetadataHmac (
  IN  VOID                      *Context,
  IN  PROTECTED_VARIABLE_INFO   *VarInfo
  )
{
  VOID            *Buffer[12];
  UINT32          BufferSize[12];
  UINTN           Index;
  BOOLEAN         Status;

  if (VarInfo == NULL ||
      VarInfo->CipherData == NULL ||
      VarInfo->CipherDataSize == 0)
  {
    return TRUE;
  }

  //
  // HMAC (":" || VariableName)
  //
  Buffer[0]       = METADATA_HMAC_SEP;
  BufferSize[0]   = METADATA_HMAC_SEP_SIZE;

  Buffer[1]       = VarInfo->Header.VariableName;
  BufferSize[1]   = (UINT32)VarInfo->Header.NameSize;

  //
  // HMAC (":" || VendorGuid || Attributes || DataSize)
  //
  Buffer[2]       = METADATA_HMAC_SEP;
  BufferSize[2]   = METADATA_HMAC_SEP_SIZE;

  Buffer[3]       = VarInfo->Header.VendorGuid;
  BufferSize[3]   = sizeof (EFI_GUID);

  Buffer[4]       = &VarInfo->Header.Attributes;
  BufferSize[4]   = sizeof (VarInfo->Header.Attributes);

  Buffer[5]       = &VarInfo->CipherDataSize;
  BufferSize[5]   = sizeof (VarInfo->CipherDataSize);

  //
  // HMAC (":" || CipherData)
  //
  Buffer[6]       = METADATA_HMAC_SEP;
  BufferSize[6]   = METADATA_HMAC_SEP_SIZE;

  Buffer[7]       = VarInfo->CipherData;
  BufferSize[7]   = VarInfo->CipherDataSize;

  //
  // HMAC (":" || PubKeyIndex || AuthMonotonicCount || TimeStamp)
  //
  Buffer[8]       = METADATA_HMAC_SEP;
  BufferSize[8]   = METADATA_HMAC_SEP_SIZE;

  Buffer[9]       = &VarInfo->Header.PubKeyIndex;
  BufferSize[9]   = sizeof (VarInfo->Header.PubKeyIndex);

  Buffer[10]      = &VarInfo->Header.MonotonicCount;
  BufferSize[10]  = sizeof (VarInfo->Header.MonotonicCount);

  Buffer[11]      = (VarInfo->Header.TimeStamp != NULL) ?
                    VarInfo->Header.TimeStamp : &mDefaultTimeStamp;
  BufferSize[11]  = sizeof (EFI_TIME);

  for (Index = 0; Index < ARRAY_SIZE (Buffer); ++Index) {
    Status = HmacSha256Update (Context, Buffer[Index], BufferSize[Index]);
    if (!Status) {
      ASSERT (FALSE);
      return FALSE;
    }
  }

  return TRUE;
}

EFI_STATUS
EFIAPI
GetVariableHmacInternal (
  IN      PROTECTED_VARIABLE_CONTEXT_IN   *ContextIn,
  IN      PROTECTED_VARIABLE_GLOBAL       *Global,
  IN      PROTECTED_VARIABLE_INFO         VarInfo,
  IN  OUT VARIABLE_SIGNATURE              *VarSig
  )
{
  VOID                            *Context;

  //
  // Don't calc HMAC for unprotected variables. Keep a copy of its data instead.
  //
  if (CheckKnownUnprotectedVariable (Global, &VarInfo) < UnprotectedVarIndexMax) {
    CopyMem (VAR_SIGNATURE (VarSig), VarInfo->Header.Data, VarInfo->Header.DataSize);
    VarSig->SigSize = VarInfo->Header.DataSize;
    return EFI_SUCCESS;
  }

  ASSERT (VarSig->SigSize >= sizeof (Global->MetaDataHmacKey));

  Context = HmacSha256New ();
  if (Context == NULL) {
    ASSERT (Context != NULL);
    return EFI_OUT_OF_RESOURCES;
  }

  if (!HmacSha256SetKey (Context, Global->MetaDataHmacKey, sizeof (Global->MetaDataHmacKey))
      || !UpdateVariableMetadataHmac (Context, VarInfo)
      || !HmacSha256Final (Context, VAR_SIG_VALUE (VarSig)))
  {
    ASSERT (FALSE);
    Status = EFI_ABORTED;
  } else {
    Status = EFI_SUCCESS;
  }

  HmacSha256Free (Context);

  return Status;;
}

EFI_STATUS
EFIAPI
GetVariableHmac (
  IN      VARIABLE_HEADER     *Variable,
  IN  OUT VARIABLE_SIGNATURE  *VarSig
  )
{
  EFI_STATUS                      Status;
  PROTECTED_VARIABLE_CONTEXT_IN   *ContextIn;
  PROTECTED_VARIABLE_GLOBAL       *Global;
  PROTECTED_VARIABLE_INFO         VarInfo;

  Status = GetProtectedVariableContext (&ContextIn, &Global);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  VarInfo.Address    = Variable;
  VarInfo.Flags.Auth = Global->Flags.Auth;
  VarInfo.CacheIndex = (UINT32)-1;
  VarInfo.StoreIndex = (UINT32)-1;

  Status = ContextIn->GetVariableInfo (NULL, &VarInfo);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  return GetVariableHmacInternal (ContextIn, Global, VarInfo, VarSig);
}

EFI_STATUS
VerifyVariableHmac (
  IN  PROTECTED_VARIABLE_CONTEXT_IN   *ContextIn,
  IN  PROTECTED_VARIABLE_GLOBAL       *Global,
  IN  PROTECTED_VARIABLE_INFO         *VarInfo,
  IN  VARIABLE_SIGNATURE              *VarSig
  )
{
  EFI_STATUS         Status;
  VARIABLE_SIGNATURE *NewVarSig;

  NewVarSig = AllocateZeroPool (sizeof (VARIABLE_SIGNATURE) + VarSig->SigSize);
  if (NewVarSig == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = GetVariableHmacInternal (ContextIn, Global, VarInfo, NewVarSig);
  if (!EFI_ERROR (Status)) {
    if (CompareMem (VAR_SIG_VALUE (VarSig), VAR_SIG_VALUE (NewVarSig)) != 0) {
      Status = EFI_COMPROMISED_DATA;
    }
  }

  FreePool (NewVarSig);
  return Status;
}


/**

  Retrieve the cached copy of NV variable storage.

  @param[in]  Global              Pointer to global configuration data.
  @param[out] VariableFvHeader    Pointer to FV header of NV storage in cache.
  @param[out] VariableStoreHeader Pointer to variable storage header in cache.

  @retval EFI_SUCCESS   The cache of NV variable storage is returned successfully.

**/
EFI_STATUS
EFIAPI
GetVariableStoreCache (
  IN      PROTECTED_VARIABLE_GLOBAL             *Global,
      OUT EFI_FIRMWARE_VOLUME_HEADER            **VariableFvHeader,
      OUT VARIABLE_STORE_HEADER                 **VariableStoreHeader,
      OUT VARIABLE_HEADER                       **VariableStart,
      OUT VARIABLE_HEADER                       **VariableEnd
  )
{
  EFI_FIRMWARE_VOLUME_HEADER      *FvHeader;
  VARIABLE_STORE_HEADER           *VarStoreHeader;
  UINT32                          Size;

  if (Global->VariableCache == 0 || Global->VariableCacheSize == 0) {
    return EFI_NOT_READY;
  }

  FvHeader = (EFI_FIRMWARE_VOLUME_HEADER *)(UINTN)Global->VariableCache;
  VarStoreHeader = (VARIABLE_STORE_HEADER *)(UINTN)
                   (Global->VariableCache + FvHeader->HeaderLength);

  if (VariableFvHeader != NULL) {
    *VariableFvHeader = FvHeader;
  }

  if (VariableStoreHeader != NULL) {
    *VariableStoreHeader = VarStoreHeader;
  }

  if (VariableStart != NULL) {
    *VariableStart = (VARIABLE_HEADER *)HEADER_ALIGN (VarStoreHeader + 1);
  }

  if (VariableEnd != NULL) {
    Size = VarStoreHeader->Size + FvHeader->HeaderLength;
    Size = MIN (Size, (UINT32)FvHeader->FvLength);
    Size = MIN (Size, Global->VariableCacheSize);

    *VariableEnd = (VARIABLE_HEADER *)((UINTN)FvHeader + Size);
  }

  return EFI_SUCCESS;
}

/**
  Initialize variable MetaDataHmacVar.

  @param[in,out]  Variable      Pointer to buffer of MetaDataHmacVar.
  @param[in]      AuthFlag      Variable format flag.

**/
VOID
InitMetadataHmacVariable (
  IN  OUT VARIABLE_HEADER       *Variable,
  IN      BOOLEAN               AuthFlag
  )
{
  UINT8                             *NamePtr;
  AUTHENTICATED_VARIABLE_HEADER     *AuthVariable;

  Variable->StartId     = VARIABLE_DATA;
  Variable->State       = VAR_ADDED;
  Variable->Reserved    = 0;
  Variable->Attributes  = VARIABLE_ATTRIBUTE_NV_BS_RT;

  if (AuthFlag) {
    AuthVariable = (AUTHENTICATED_VARIABLE_HEADER *)Variable;

    AuthVariable->NameSize        = METADATA_HMAC_VARIABLE_NAME_SIZE;
    AuthVariable->DataSize        = METADATA_HMAC_SIZE;
    AuthVariable->PubKeyIndex     = 0;
    AuthVariable->MonotonicCount  = 0;

    ZeroMem (&AuthVariable->TimeStamp, sizeof (EFI_TIME));
    CopyMem (&AuthVariable->VendorGuid, &METADATA_HMAC_VARIABLE_GUID, sizeof (EFI_GUID));

    NamePtr = (UINT8 *)AuthVariable + sizeof (AUTHENTICATED_VARIABLE_HEADER);
  } else {
    Variable->NameSize        = METADATA_HMAC_VARIABLE_NAME_SIZE;
    Variable->DataSize        = METADATA_HMAC_SIZE;

    CopyMem (&Variable->VendorGuid, &METADATA_HMAC_VARIABLE_GUID, sizeof (EFI_GUID));

    NamePtr = (UINT8 *)Variable + sizeof (VARIABLE_HEADER);
  }

  CopyMem (NamePtr, METADATA_HMAC_VARIABLE_NAME, METADATA_HMAC_VARIABLE_NAME_SIZE);
}

/**
  Re-calculate HMAC based on new variable data and re-generate MetaDataHmacVar.

  @param[in]      ContextIn       Pointer to context provided by variable services.
  @param[in]      Global          Pointer to global configuration data.
  @param[in]      NewVarInfo      Pointer to buffer of new variable data.
  @param[in,out]  NewHmacVarInfo  Pointer to buffer of new MetaDataHmacVar.

  @return EFI_SUCCESS           The HMAC value was updated successfully.
  @return EFI_ABORTED           Failed to calculate the HMAC value.
  @return EFI_OUT_OF_RESOURCES  Not enough resource to calculate HMC value.
  @return EFI_NOT_FOUND         The MetaDataHmacVar was not found in storage.

**/
EFI_STATUS
RefreshVariableMetadataHmac (
  IN      PROTECTED_VARIABLE_CONTEXT_IN     *ContextIn,
  IN      PROTECTED_VARIABLE_GLOBAL         *Global,
  IN      PROTECTED_VARIABLE_INFO           *NewVarInfo,
  IN  OUT PROTECTED_VARIABLE_INFO           *NewHmacVarInfo
  )
{
  EFI_STATUS                        Status;
  VOID                              *Context;
  UINT32                            Counter;
  VARIABLE_STORE_HEADER             *VarStore;
  PROTECTED_VARIABLE_INFO           VarInfo;
  PROTECTED_VARIABLE_INFO           CurrHmacVarInfo;
  UINT8                             *HmacValue;
  VARIABLE_HEADER                   *VariableStart;
  VARIABLE_HEADER                   *VariableEnd;

  Status = RequestMonotonicCounter (&Counter);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }
  Counter += 1;

  Status = GetVariableStoreCache (Global, NULL, &VarStore, &VariableStart, &VariableEnd);
  ASSERT_EFI_ERROR (Status);

  //
  // Delete current MetaDataHmacVariable first, if any.
  //
  if (Global->UnprotectedVariables[IndexHmacAdded] != 0) {
    CurrHmacVarInfo.Address     = NULL;
    CurrHmacVarInfo.Offset      = Global->UnprotectedVariables[IndexHmacAdded];
    CurrHmacVarInfo.Flags.Auth  = Global->Flags.Auth;
    Status = ContextIn->GetVariableInfo (VarStore, &CurrHmacVarInfo);
    if (EFI_ERROR (Status) || CurrHmacVarInfo.Address == NULL) {
      ASSERT_EFI_ERROR (Status);
      ASSERT (CurrHmacVarInfo.Address != NULL);
      return EFI_NOT_FOUND;
    }

    //
    // Force marking current MetaDataHmacVariable as VAR_IN_DELETED_TRANSITION.
    //
    CurrHmacVarInfo.Address->State &= VAR_IN_DELETED_TRANSITION;
    Status = ContextIn->UpdateVariableStore (
                          &CurrHmacVarInfo,
                          OFFSET_OF (VARIABLE_HEADER, State),
                          sizeof (CurrHmacVarInfo.Address->State),
                          &CurrHmacVarInfo.Address->State
                          );
    if (EFI_ERROR (Status)) {
      ASSERT_EFI_ERROR (Status);
      return Status;
    }

    Global->UnprotectedVariables[IndexHmacInDel] = CurrHmacVarInfo.Offset;
    Global->UnprotectedVariables[IndexHmacAdded] = 0;
  }

  //
  // Construct new MetaDataHmacVariable.
  //
  InitMetadataHmacVariable (NewHmacVarInfo->Address, Global->Flags.Auth);

  NewHmacVarInfo->Offset      = (UINT32)-1;    // Skip calculating offset
  NewHmacVarInfo->Flags.Auth  = Global->Flags.Auth;
  Status = ContextIn->GetVariableInfo (NULL, NewHmacVarInfo);
  ASSERT_EFI_ERROR (Status);
  HmacValue = NewHmacVarInfo->Header.Data;

  //
  // Re-calculate HMAC for all valid variables
  //
  Context = HmacSha256New ();
  if (Context == NULL) {
    ASSERT (Context != NULL);
    return EFI_OUT_OF_RESOURCES;
  }

  Status = EFI_ABORTED;
  if (!HmacSha256SetKey (Context,
                         Global->MetaDataHmacKey,
                         sizeof (Global->MetaDataHmacKey)))
  {
    ASSERT (FALSE);
    goto Done;
  }

  //
  // HMAC (|| Var1 || Var2 || ... || VarN)
  //
  VarInfo.Address     = NULL;
  VarInfo.Offset      = 0;
  VarInfo.Flags.Auth  = Global->Flags.Auth;
  while (TRUE) {
    Status = ContextIn->GetNextVariableInfo (VarStore, VariableStart, VariableEnd, &VarInfo);
    if (EFI_ERROR (Status) || VarInfo.Address == NULL) {
      break;
    }

    //
    // Old copy of variable should be marked as in-deleting or deleted. It's
    // safe just check valid variable here.
    //
    if (VarInfo.Address->State == VAR_ADDED
        && !IS_KNOWN_UNPROTECTED_VARIABLE (Global, &VarInfo))
    {
      //
      // VarX = HMAC (":" || VariableName)
      //        HMAC (":" || VendorGuid || Attributes || DataSize)
      //        HMAC (":" || CipherData)
      //        HMAC (":" || PubKeyIndex || AuthMonotonicCount || TimeStamp)
      //
      VarInfo.CipherData      = VarInfo.Header.Data;
      VarInfo.CipherDataSize  = (UINT32)VarInfo.Header.DataSize;
      if (!UpdateVariableMetadataHmac (Context, &VarInfo)) {
        goto Done;
      }
    }
  }

  //
  // HMAC (|| NewVariable)
  //
  if (!UpdateVariableMetadataHmac (Context, NewVarInfo)) {
    goto Done;
  }

  //
  // HMAC (RpmcMonotonicCounter)
  //
  if (!HmacSha256Update (Context, &Counter, sizeof (Counter))) {
    ASSERT (FALSE);
    goto Done;
  }

  if (!HmacSha256Final (Context, HmacValue)) {
    ASSERT (FALSE);
    goto Done;
  }

  Status = EFI_SUCCESS;

Done:
  if (Context != NULL) {
    HmacSha256Free (Context);
  }

  return Status;
}

/**

  Check if a given variable is unprotected variable specified in advance
  and return its index ID.

  @param[in] Global     Pointer to global configuration data.
  @param[in] VarInfo    Pointer to variable information data.

  @retval IndexHmacInDel    Variable is MetaDataHmacVar in delete-transition state.
  @retval IndexHmacAdded    Variable is MetaDataHmacVar in valid state.
  @retval IndexErrorFlag    Variable is VarErrorLog.
  @retval Others            Variable is not any known unprotected variables.

**/
UNPROTECTED_VARIABLE_INDEX
CheckKnownUnprotectedVariable (
  IN  PROTECTED_VARIABLE_GLOBAL     *Global,
  IN  PROTECTED_VARIABLE_INFO       *VarInfo
  )
{
  UNPROTECTED_VARIABLE_INDEX     Index;

  if (Global != NULL && VarInfo != NULL && VarInfo->Address != NULL) {
    for (Index = 0; Index < UnprotectedVarIndexMax; ++Index) {
      if (Global->UnprotectedVariables[Index] != 0
          && VarInfo->Offset != 0
          && VarInfo->Offset < Global->ProtectedVariableCacheSize)
      {
        if (VarInfo->Offset == Global->UnprotectedVariables[Index]) {
          break;
        }
      } else if (IS_VARIABLE (&VarInfo->Header,
                              mUnprotectedVariables[Index].VariableName,
                              mUnprotectedVariables[Index].VendorGuid)) {
        break;
      }
    }
  } else {
    Index = UnprotectedVarIndexMax;
  }

  return Index;
}

/**

  Check if a given variable is valid and protected variable.

  @param[in] Global     Pointer to global configuration data.
  @param[in] VarInfo    Pointer to variable information data.

  @retval TRUE    Variable is valid and protected variable.
  @retval FALSE   Variable is not valid and/or not protected variable.

**/
BOOLEAN
IsValidProtectedVariable (
  IN  PROTECTED_VARIABLE_GLOBAL     *Global,
  IN  PROTECTED_VARIABLE_INFO       *VarInfo
  )
{
  EFI_STATUS      Status;
  UINTN           Index;

  if (VarInfo->Address == NULL
      || (VarInfo->Address->State != VAR_ADDED
          && VarInfo->Address->State != (VAR_ADDED & VAR_IN_DELETED_TRANSITION)))
  {
    return FALSE;
  }

  if (IS_KNOWN_UNPROTECTED_VARIABLE (Global, VarInfo)) {
    return FALSE;
  }

  if (VarInfo->Address->State == (VAR_ADDED & VAR_IN_DELETED_TRANSITION)) {
    if (Global->TableCount > 0) {
      for (Index = 0; Index < Global->TableCount; ++Index) {
        if (VarInfo->Offset == Global->Table.OffsetList[Index]) {
          break;
        }
      }

      if (Index >= Global->TableCount) {
        return FALSE;
      }
    }

    if (VarInfo->Header.Data == NULL || VarInfo->Header.DataSize == 0) {
      return FALSE;
    }

    VarInfo->CipherData     = NULL;
    VarInfo->CipherDataSize = 0;
    VarInfo->PlainData      = NULL;
    VarInfo->PlainDataSize  = 0;

    Status = GetCipherDataInfo (VarInfo);
    if (Status == EFI_UNSUPPORTED) {
      VarInfo->PlainData        = VarInfo->Header.Data;
      VarInfo->PlainDataSize    = (UINT32)VarInfo->Header.DataSize;
      VarInfo->CipherDataType   = 0;
      VarInfo->CipherHeaderSize = 0;
    } else if (Status != EFI_SUCCESS) {
      return FALSE;
    }
  }

  return TRUE;
}

/**
  Find the variable managed by ProtectedVariableLib.

  @param  VariableName  Name of the variable to be found
  @param  VendorGuid    Vendor GUID to be found.
  @param  Variable      Pointer to variable with state VAR_ADDED.
  @param  VariableInDel Pointer to variable with state VAR_IN_DELETED_TRANSITION.

  @retval  EFI_SUCCESS            Variable found successfully
  @retval  EFI_NOT_FOUND          Variable not found
  @retval  EFI_INVALID_PARAMETER  Invalid variable name
**/
EFI_STATUS
EFIAPI
ProtectedVariableLibFindVariable (
  IN      CONST  CHAR16           *VariableName,
  IN      CONST  EFI_GUID         *VendorGuid,
      OUT VARIABLE_HEADER         *Variable,
      OUT VARIABLE_HEADER         *VariableInDel OPTIONAL
  )
{
  EFI_STATUS                    Status;
  PROTECTED_VARIABLE_CONTEXT_IN *ContextIn;
  PROTECTED_VARIABLE_GLOBAL     *Global;
  VARIABLE_SIGNATURE            *VarSig;
  PROTECTED_VARIABLE_INFO       VarInfo;

  if (VariableName == NULL || VendorGuid == NULL || Variable == NULL) {
    ASSERT (VariableName != NULL);
    ASSERT (VendorGuid != NULL);
    ASSERT (Variable != NULL);
    return EFI_INVALID_PARAMETER;
  }

  Status = GetProtectedVariableContext (&ContextIn, &Global);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  ZeroMem (&VarInfo, sizeof (VarInfo));
  *Variable = NULL;
  if (VariableInDel != NULL) {
    *VariableInDel = NULL;
  }

  VarSig = VAR_SIG_PTR (Global->VariableSignatures);
  while (VarSig != NULL) {
    VarInfo.Header.VariableName = VAR_SIG_NAME (VarSig);
    VarInfo.Header.VendorGuid   = VAR_SIG_GUID (VarSig);

    if (IS_VARIABLE (&VarInfo.Header, VariableName, VendorGuid)) {
      if (VarSig->CacheIndex != VAR_INDEX_INVALID) {
        VarInfo.Index   = VarSig->CacheIndex;
        VarInfo.Address = VAR_PTR (Global->VariableCache + VarInfo.Index);
      } else {
        VarInfo.Index   = VarSig->StoreIndex;
        VarInfo.Address = NULL;

        Status = ContextIn->GetVariableInfo (NULL, &VarInfo);
        if (EFI_ERROR (Status) || VarInfo.Address == NULL) {
          return EFI_COMPROMISED_DATA;
        }
      }

      if (VarSig->State == VAR_ADDED) {
        *Variable = VarInfo.Address;
      } else if (VariableInDel != NULL) {
        *VariableInDel = VarInfo.Address;
      }

      if (*Variable != NULL && (VariableInDel == NULL || *VariableInDel != NULL)) {
        break;
      }
    } else if (*Variable != NULL || (VariableInDel != NULL && *VariableInDel != NULL)) {
      break;
    }

    VarSig = VAR_SIG_NEXT (VarSig);
  }

  return EFI_SUCCESS;
}

/**

  An alternative version of ProtectedVariableLibGetData to get plain data, if
  encrypted, from given variable, for different use cases.

  @param[in,out]      VarInfo     Pointer to structure containing variable information.

  @retval EFI_SUCCESS               Found the specified variable.
  @retval EFI_INVALID_PARAMETER     VarInfo is NULL or both VarInfo->Address and
                                    VarInfo->Offset are invalid.
  @retval EFI_NOT_FOUND             The specified variable could not be found.

**/
EFI_STATUS
EFIAPI
ProtectedVariableLibGetDataInfoInternal (
  IN      PROTECTED_VARIABLE_CONTEXT_IN     *ContextIn,
  IN      PROTECTED_VARIABLE_GLOBAL         *Global,
  IN  OUT PROTECTED_VARIABLE_INFO           *VarInfo
  )
{
  EFI_STATUS                        Status;
  PROTECTED_VARIABLE_CONTEXT_IN     *ContextIn;
  PROTECTED_VARIABLE_GLOBAL         *Global;
  VARIABLE_STORE_HEADER             *VarStore;
  VOID                              *Buffer;
  UINTN                             BufferSize;
  VOID                              *Data;
  UINT32                            DataSize;

  Status = GetProtectedVariableContext (&ContextIn, &Global);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  Status = GetVariableStoreCache (Global, NULL, &VarStore, NULL, NULL);
  if (EFI_ERROR (Status)) {
    VarStore = NULL;
  }

  if (VarInfo == NULL || (VarInfo->Address == NULL && VarInfo->Offset == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  if (VarInfo->Header.Data == NULL) {
    if (ContextIn->VariableServiceUser == FromPeiModule) {
      //
      // PEI variable storage has only one valid copy. Variable information can
      // only be retrieved from it.
      //
      Status = ContextIn->GetVariableInfo (VarStore, VarInfo);
    } else {
      //
      // Retrieve variable information from local cached variable storage, so that
      // we can decrypt it in-place to avoid repeat decryption.
      //
      Status = ContextIn->GetVariableInfo (NULL, VarInfo);
    }
    ASSERT_EFI_ERROR (Status);
  }

  //
  // Need to re-use PlainData and PlainDataSize.
  //
  Data      = VarInfo->PlainData;
  DataSize  = VarInfo->PlainDataSize;

  VarInfo->PlainData      = NULL;
  VarInfo->PlainDataSize  = 0;

  if (VarInfo->Header.DataSize == 0) {
    return EFI_SUCCESS;
  }

  if (IS_KNOWN_UNPROTECTED_VARIABLE (Global, VarInfo)) {
    //
    // No need to do decryption.
    //
    VarInfo->PlainData      = VarInfo->Header.Data;
    VarInfo->PlainDataSize  = (UINT32)VarInfo->Header.DataSize;
    VarInfo->CipherData     = NULL;
    VarInfo->CipherDataSize = 0;

    VarInfo->Flags.DecryptInPlace = TRUE;
  } else {
    //
    // Check if the data has been decrypted or not.
    //
    VarInfo->CipherData     = NULL;
    VarInfo->CipherDataSize = 0;
    VarInfo->PlainData      = NULL;
    VarInfo->PlainDataSize  = 0;
    Status = GetCipherDataInfo (VarInfo);
    if (Status == EFI_UNSUPPORTED) {
      VarInfo->PlainData        = VarInfo->Header.Data;
      VarInfo->PlainDataSize    = (UINT32)VarInfo->Header.DataSize;
      VarInfo->CipherDataType   = 0;
      VarInfo->CipherHeaderSize = 0;

      Status = EFI_SUCCESS;
    } else if (EFI_ERROR (Status)) {
      ASSERT_EFI_ERROR (Status);
      return Status;
    }
  }

  //
  // Check data buffer size.
  //
  if (Data != NULL && VarInfo->PlainDataSize != 0) {
    if (DataSize < VarInfo->PlainDataSize) {
      VarInfo->PlainDataSize = DataSize;
      return EFI_BUFFER_TOO_SMALL;
    }
  }

  //
  // If the variable data is cipher data, decrypt it inplace if possible.
  //
  if (VarInfo->PlainData == NULL && VarInfo->CipherData != NULL) {
    VarInfo->Key      = Global->RootKey;
    VarInfo->KeySize  = sizeof (Global->RootKey);

    switch (ContextIn->VariableServiceUser) {
    case FromPeiModule:
      //
      // PEI has no separate variable cache. We can't do decryption inplace.
      //
      VarInfo->Flags.DecryptInPlace = FALSE;
      //
      // If no buffer passed in, don't do decryption at all.
      //
      if (Data != NULL) {
        VarInfo->PlainData = Data;
        Data = NULL;
        Status = DecryptVariable (VarInfo);
        if (Status == EFI_UNSUPPORTED) {
          VarInfo->PlainData        = VarInfo->Header.Data;
          VarInfo->PlainDataSize    = (UINT32)VarInfo->Header.DataSize;
          VarInfo->CipherDataType   = 0;
          VarInfo->CipherHeaderSize = 0;

          Status = EFI_SUCCESS;
        }
      }
      break;

    case FromSmmModule:
      VarInfo->Flags.DecryptInPlace = TRUE;
      Status = DecryptVariable (VarInfo);
      if (Status == EFI_UNSUPPORTED) {
        VarInfo->PlainData        = VarInfo->Header.Data;
        VarInfo->PlainDataSize    = (UINT32)VarInfo->Header.DataSize;
        VarInfo->CipherDataType   = 0;
        VarInfo->CipherHeaderSize = 0;

        Status = EFI_SUCCESS;
      }
      break;

    case FromBootServiceModule:
    case FromRuntimeModule:
      //
      // The SMM passes back only decrypted data. We re-use the original cipher
      // data buffer to keep the plain data along with the cipher header.
      //
      VarInfo->Flags.DecryptInPlace = TRUE;
      Buffer = (VOID *)((UINTN)VarInfo->CipherData + VarInfo->CipherHeaderSize);
      BufferSize = VarInfo->PlainDataSize;
      Status = ContextIn->FindVariableSmm (
                            VarInfo->Header.VariableName,
                            VarInfo->Header.VendorGuid,
                            &VarInfo->Header.Attributes,
                            &BufferSize,
                            Buffer
                            );
      if (!EFI_ERROR (Status)) {
        //
        // Flag the payload as plain data to avoid re-decrypting.
        //
        VarInfo->CipherDataType = ENC_TYPE_NULL;
        VarInfo->PlainDataSize  = (UINT32)BufferSize;
        VarInfo->PlainData      = Buffer;

        Status = SetCipherDataInfo (VarInfo);
        if (Status == EFI_UNSUPPORTED) {
          Status = EFI_SUCCESS;
        }
      }
      break;

    default:
      Status = EFI_UNSUPPORTED;
      break;
    }

    VarInfo->CipherData     = NULL;
    VarInfo->CipherDataSize = 0;
  }

  if (!EFI_ERROR (Status)) {
    if (Data != NULL && VarInfo->PlainData != NULL && Data != VarInfo->PlainData) {
      CopyMem (Data, VarInfo->PlainData, VarInfo->PlainDataSize);
      VarInfo->PlainData = Data;
    }
  }

  return Status;
}

/**

  An alternative version of ProtectedVariableLibGetData to get plain data, if
  encrypted, from given variable, for different use cases.

  @param[in,out]      VarInfo     Pointer to structure containing variable information.

  @retval EFI_SUCCESS               Found the specified variable.
  @retval EFI_INVALID_PARAMETER     VarInfo is NULL or both VarInfo->Address and
                                    VarInfo->Offset are invalid.
  @retval EFI_NOT_FOUND             The specified variable could not be found.

**/
EFI_STATUS
EFIAPI
ProtectedVariableLibGetDataInfo (
  IN  OUT PROTECTED_VARIABLE_INFO       *VarInfo
  )
{
  EFI_STATUS                        Status;
  PROTECTED_VARIABLE_CONTEXT_IN     *ContextIn;
  PROTECTED_VARIABLE_GLOBAL         *Global;

  Status = GetProtectedVariableContext (&ContextIn, &Global);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  return ProtectedVariableLibGetDataInfoInternal (ContextIn, Global, VarInfo);
}

/**

  Retrieve plain data, if encrypted, of given variable.

  If variable encryption is employed, this function will initiate a SMM request
  to get the plain data. Due to security consideration, the decryption can only
  be done in SMM environment.

  @param[in]      Variable           Pointer to header of a Variable.
  @param[out]     Data               Pointer to plain data of the given variable.
  @param[in, out] DataSize           Size of data returned or data buffer needed.
  @param[in]      AuthFlag           Auth-variable indicator.

  @retval EFI_SUCCESS                Found the specified variable.
  @retval EFI_INVALID_PARAMETER      Invalid parameter.
  @retval EFI_NOT_FOUND              The specified variable could not be found.
  @retval EFI_BUFFER_TOO_SMALL       If *DataSize is smaller than needed.

**/
EFI_STATUS
EFIAPI
ProtectedVariableLibGetData (
  IN      VARIABLE_HEADER                   *Variable,
  IN  OUT VOID                              *Data,
  IN  OUT UINT32                            *DataSize,
  IN      BOOLEAN                           AuthFlag
  )
{
  EFI_STATUS                        Status;
  PROTECTED_VARIABLE_INFO           VarInfo;

  if (Variable == NULL || DataSize == NULL) {
    ASSERT (Variable != NULL);
    ASSERT (DataSize != NULL);
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (&VarInfo, sizeof (VarInfo));

  VarInfo.Address       = Variable;
  VarInfo.Flags.Auth    = AuthFlag;
  VarInfo.PlainData     = Data;
  VarInfo.PlainDataSize = *DataSize;

  Status = ProtectedVariableLibGetDataInfoInternal (ContextIn, Global, &VarInfo);
  if (!EFI_ERROR (Status) || Status == EFI_BUFFER_TOO_SMALL) {
    if (VarInfo.PlainDataSize > *DataSize) {
      Status = EFI_BUFFER_TOO_SMALL;
    }
    *DataSize = VarInfo.PlainDataSize;
  }

  return Status;
}

/**
  This service retrieves a variable's value using its name and GUID.

  Read the specified variable from the UEFI variable store. If the Data
  buffer is too small to hold the contents of the variable, the error
  EFI_BUFFER_TOO_SMALL is returned and DataSize is set to the required buffer
  size to obtain the data.

  @param  VariableName          A pointer to a null-terminated string that is the variable's name.
  @param  VariableGuid          A pointer to an EFI_GUID that is the variable's GUID. The combination of
                                VariableGuid and VariableName must be unique.
  @param  Attributes            If non-NULL, on return, points to the variable's attributes.
  @param  DataSize              On entry, points to the size in bytes of the Data buffer.
                                On return, points to the size of the data returned in Data.
  @param  Data                  Points to the buffer which will hold the returned variable value.
                                May be NULL with a zero DataSize in order to determine the size of the buffer needed.

  @retval EFI_SUCCESS           The variable was read successfully.
  @retval EFI_NOT_FOUND         The variable was be found.
  @retval EFI_BUFFER_TOO_SMALL  The DataSize is too small for the resulting data.
                                DataSize is updated with the size required for
                                the specified variable.
  @retval EFI_INVALID_PARAMETER VariableName, VariableGuid, DataSize or Data is NULL.
  @retval EFI_DEVICE_ERROR      The variable could not be retrieved because of a device error.

**/
EFI_STATUS
EFIAPI
ProtectedVariableLibGet (
  IN CONST  CHAR16                          *VariableName,
  IN CONST  EFI_GUID                        *VariableGuid,
  OUT       UINT32                          *Attributes,
  IN OUT    UINTN                           *DataSize,
  OUT       VOID                            *Data OPTIONAL
  )
{
  EFI_STATUS                          Status;
  PROTECTED_VARIABLE_CONTEXT_IN       *ContextIn;
  PROTECTED_VARIABLE_GLOBAL           *Global;
  VARIABLE_SIGNATURE                  *VarSig;
  VARIABLE_SIGNATURE                  *CurrVarSig;
  PROTECTED_VARIABLE_INFO             VarInfo;
  EFI_GUID                            VendorGuid;
  EFI_TIME                            TimeStamp;
  VOID                                *DataBuffer;

  if (VariableName == NULL || VendorGuid == NULL || DataSize == NULL) {
    ASSERT (VariableName != NULL);
    ASSERT (VendorGuid != NULL);
    ASSERT (DataSize != NULL);
    return EFI_INVALID_PARAMETER;
  }

  Status = GetProtectedVariableContext (&ContextIn, &Global);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  ZeroMem (&VarInfo, sizeof (VarInfo));
  VarInfo.Index = VAR_INDEX_INVALID;
  DataBuffer    = NULL;

  if (Data != NULL && Global->LastAccessedVariable != 0) {
    VarSig = VAR_SIG_PTR (Global->LastAccessedVariable);

    VarInfo.Header.VariableName = VAR_SIG_NAME (VarSig);
    VarInfo.Header.VendorGuid   = VAR_SIG_GUID (VarSig);

    if (IS_VARIABLE (&VarInfo.Header, VariableName, VendorGuid)) {
      VarInfo.Index = (VarSig->CacheIndex != VAR_INDEX_INVALID)
                      ? VarSig->CacheIndex
                      : VarSig->StoreIndex;
    }
  }

  //
  // Search all variables if it's not the one accessed last time.
  //
  if (VarInfo.Index == VAR_INDEX_INVALID) {
    VarSig = VAR_SIG_PTR (Global->VariableSignatures);
    while (VarSig != NULL) {
      VarInfo.Header.VariableName = VAR_SIG_NAME (VarSig);
      VarInfo.Header.VendorGuid   = VAR_SIG_GUID (VarSig);

      if (IS_VARIABLE (&VarInfo.Header, VariableName, VendorGuid)) {
        VarInfo.Index = (VarSig->CacheIndex != VAR_INDEX_INVALID)
                        ? VarSig->CacheIndex
                        : VarSig->StoreIndex;
        if (VarSig->State == VAR_ADDED) {
          break;
        }
      } else if (VarInfo.Index != VAR_INDEX_INVALID) {
        VarSig = NULL;
        break;
      }

      VarSig = VAR_SIG_NEXT (VarSig);
    }
  }

  if (VarSig == NULL || VarInfo.Index == VAR_INDEX_INVALID) {
    return EFI_NOT_FOUND;
  }

  if (Attributes != NULL) {
    *Attributes = VarSig->Attributes;
  }

  if (Data == NULL || *DataSize < VarSig->PlainDataSize) {
    *DataSize = VarSig->PlainDataSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  //
  // Verify signature before copy the data back, if the variable is not in cache.
  //
  if (VarSig->CacheIndex == VAR_INDEX_INVALID) {
    ASSERT (VarSig->StoreIndex != VAR_INDEX_INVALID);

    //
    // Get detailed information about the variable.
    //
    DataBuffer = AllocatePool (VarSig->DataSize);
    if (DataBuffer == NULL) {
      ASSERT (DataBuffer != NULL);
      return EFI_OUT_OF_RESOURCES;
    }

    //
    // Note the variable might be in inconsecutive space.
    //
    VarInfo.Header.VariableName = VAR_SIG_NAME (VarSig);
    VarInfo.Header.NameSize     = 0;  // Prevent name from being retrieved again.
    VarInfo.Header.TimeStamp    = &TimeStamp;
    VarInfo.Header.VendorGuid   = &VendorGuid;
    VarInfo.Header.Data         = DataBuffer;
    VarInfo.Header.DataSize     = VarSig->DataSize;

    Status = ContextIn->GetVariableInfo (&VarInfo);
    ASSERT_EFI_ERROR (Status);

    //
    // The variable must be validated against its HMAC value to avoid TOCTOU,
    // if it's not been cached yet.
    //
    Status = VerifyVariableHmac (ContextIn, Global, &VarInfo, VarSig);
    if (EFI_ERROR (Status)) {
      goto Done;
    }
  } else {
    //
    // CacheIndex is the address of variable in cache.
    //
    VarInfo.Index   = VAR_INDEX_INVALID;
    VarInfo.Buffer  = (VOID *)(UINTN)VarSig->CacheIndex;

    Status = ContextIn->GetVariableInfo (&VarInfo);
    ASSERT_EFI_ERROR (Status);
  }

  //
  // Decrypt the data, if encrypted.
  //
  VarInfo.PlainData     = Data;
  VarInfo.PlainDataSize = *DataSize;
  Status = ProtectedVariableLibGetDataInfoInternal (ContextIn, Global, VarInfo);
  if (!EFI_ERROR (Status) || Status == EFI_BUFFER_TOO_SMALL) {
    if (VarInfo.PlainDataSize > *DataSize) {
      Status = EFI_BUFFER_TOO_SMALL;
    }
    *DataSize = VarInfo.PlainDataSize;
  }

Done:
  if (DataBuffer != NULL) {
    FreePool (DataBuffer);
  }

  return Status;
}

