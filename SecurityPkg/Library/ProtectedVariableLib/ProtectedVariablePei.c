/** @file

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Base.h>
#include <Uefi.h>
#include <PiPei.h>

#include <Guid/VariableFormat.h>
#include <Ppi/MemoryDiscovered.h>

#include <Library/HobLib.h>
#include <Library/ReportStatusCodeLib.h>

#include "ProtectedVariableInternal.h"

/**
  Callback use to re-verify all variables and cache them in memory.

  @param[in] PeiServices          General purpose services available to every PEIM.
  @param[in] NotifyDescriptor     The notification structure this PEIM registered on install.
  @param[in] Ppi                  The memory discovered PPI.  Not used.

  @retval EFI_SUCCESS             The function completed successfully.
  @retval others                  There's error in MP initialization.
**/
EFI_STATUS
EFIAPI
MemoryDiscoveredPpiNotifyCallback (
  IN EFI_PEI_SERVICES           **PeiServices,
  IN EFI_PEI_NOTIFY_DESCRIPTOR  *NotifyDescriptor,
  IN VOID                       *Ppi
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
  VOID                                *Buffer;
  UINTN                               VarSize;

  Status = GetProtectedVariableContext (&ContextIn, &Global);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  //
  // Traverse all valid variables.
  //
  ZeroMem (&VarInfo, sizeof (VarInfo));
  VarSig = VAR_SIG_PTR (Global->VariableSignatures);
  while (VarSig != NULL) {
    if (VarSig->CacheIndex == VAR_INDEX_INVALID && VarSig->State == VAR_ADDED) {
      ASSERT (VarSig->StoreIndex != VAR_INDEX_INVALID);

      VarSize =  VARIABLE_HEADER_SIZE (Global->Flags.Auth);
      VarSize += VarSig->NameSize + GET_PAD_SIZE (VarSig->NameSize);
      VarSize += VarSig->DataSize + GET_PAD_SIZE (VarSig->DataSize);
      VarSize = HEADER_ALIGN (VarSize);

      //
      // Get detailed information about the variable.
      //
      Buffer = AllocateZeroPool (VarSize);
      if (Buffer == NULL) {
        REPORT_STATUS_CODE (
          EFI_ERROR_CODE | EFI_ERROR_UNRECOVERED,
          (PcdGet32 (PcdStatusCodeVariableIntegrity) | (EFI_OUT_OF_RESOURCES & 0xFF))
          );
        ASSERT (Buffer != NULL);
        return EFI_OUT_OF_RESOURCES;
      }

      //
      // Note the variable might be in inconsecutive space.
      //
      VarInfo.Index   = VarSig->StoreIndex;
      VarInfo.Buffer  = Buffer;
      Status = ContextIn->GetVariableInfo (&VarInfo);
      ASSERT_EFI_ERROR (Status);

      //
      // Make sure that the cached copy is not compromised.
      //
      Status = VerifyVariableHmac (ContextIn, Global, &VarInfo, VarSig);
      if (EFI_ERROR (Status)) {
        REPORT_STATUS_CODE (
          EFI_ERROR_CODE | EFI_ERROR_UNRECOVERED,
          (PcdGet32 (PcdStatusCodeVariableIntegrity) | (Status & 0xFF))
          );
        ASSERT_EFI_ERROR (Status);
        CpuDeadLoop ();
      }

      //
      // Simply use the cache address as CacheIndex of the variable.
      //
      VarSig->CacheIndex = (EFI_PHYSICAL_ADDRESS)(UINTN)Buffer;
    }

    VarSig = VAR_SIG_NEXT (VarSig);
  }

  return EFI_SUCCESS;
}

EFI_PEI_NOTIFY_DESCRIPTOR  mPostMemNotifyList[] = {
  {
    (EFI_PEI_PPI_DESCRIPTOR_NOTIFY_CALLBACK | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
    &gEfiPeiMemoryDiscoveredPpiGuid,
    MemoryDiscoveredPpiNotifyCallback
  }
};

/**

  Get context and/or global data structure used to process protected variable.

  @param[out]   ContextIn   Pointer to context provided by variable runtime services.
  @param[out]   Global      Pointer to global configuration data.

  @retval EFI_SUCCESS         Get requested structure successfully.

**/
EFI_STATUS
EFIAPI
GetProtectedVariableContext (
  OUT PROTECTED_VARIABLE_CONTEXT_IN   **ContextIn OPTIONAL,
  OUT PROTECTED_VARIABLE_GLOBAL       **Global OPTIONAL
  )
{
  return GetProtectedVariableContextFromHob (ContextIn, Global);
}

INTN
EFIAPI
CompareVariable (
  IN  VARIABLE_SIGNATURE      *Variable1,
  IN  VARIABLE_SIGNATURE      *Variable2
  )
{
  CHAR16            *Name1;
  CHAR16            *Name2;
  INTN              Result;

  Name1   = VAR_NAME (Variable1);
  Name2   = VAR_NAME (Variable2);
  Result  = StrnCmp (
              Name1,
              Name2,
              MIN (Variable1->NameSize, Variable2->NameSize) / sizeof (CHAR16)
              );
  if (Result == 0) {
    //
    // The variable name is the same. Compare the GUID as string.
    //
    Result = StrnCmp (
              (CHAR16 *)&Variable1->VendorGuid,
              (CHAR16 *)&Variable2->VendorGuid,
              sizeof (EFI_GUID) / sizeof (CHAR16)
              );
  }

  return Result;
}

VOID
MoveNodeBackward (
  IN  OUT VARIABLE_SIGNATURE  *Node,
  IN      SORT_METHOD         SortMethod
  )
{
  VARIABLE_SIGNATURE  *Curr;
  VARIABLE_SIGNATURE  *Prev;
  INTN                Result;

  Curr = Node;
  while (Curr != NULL) {
    Prev = PREV_SIGNATURE (Curr);
    if (Prev == NULL) {
      Result = -1;
    } else {
      Result = SortMethod (Prev, Node);
    }

    if (Result <= 0) {
      if (Curr != Node) {
        //
        // Remove Node first
        //
        if (Node->Prev != 0) {
          PREV_SIGNATURE (Node)->Next = Node->Next;
        }

        if (Node->Next != NULL) {
          NEXT_SIGNATURE (Node)->Prev = Node->Prev;
        }

        //
        // Insert Node before Curr.
        //
        Node->Prev = Curr->Prev;
        Node->Next = (EFI_PHYSICAL_ADDRESS) (UINTN)Curr;

        if (Curr->Prev != NULL) {
          PREV_SIGNATURE (Curr)->Next = (EFI_PHYSICAL_ADDRESS) (UINTN)Node;
        }
        Curr->Prev = (EFI_PHYSICAL_ADDRESS) (UINTN)Node;
      }

      //
      // If there're two identical variables in storage, one of them must be
      // "in-delete-transition" state. Mark it as "deleted" anyway.
      //
      if (Result == 0) {
        if (Curr->State == (VAR_ADDED & VAR_IN_DELETED_TRANSITION)) {
          Curr->State &= VAR_DELETED;
        }

        if (Prev->State == (VAR_ADDED & VAR_IN_DELETED_TRANSITION)) {
          Prev->State &= VAR_DELETED;
        }
      }

      break;
    }

    Curr = Prev;
  }
}

VOID
SortVariableSignatureList (
  IN      PROTECTED_VARIABLE_CONTEXT_IN *ContextIn,
  IN  OUT PROTECTED_VARIABLE_GLOBAL     *Global,
  IN      SORT_METHOD                   SortMethod
  )
{
  VARIABLE_SIGNATURE          *Curr;
  VARIABLE_SIGNATURE          *Next;
  VARIABLE_IDENTIFIER         VarId;
  UNPROTECTED_VARIABLE_INDEX  VarIndex;
  UINTN                        Index;

  SetMem (Global->UnprotectedVariables, sizeof (Global->UnprotectedVariables), (UINT8)-1);

  Curr = (VARIABLE_SIGNATURE *)(UINTN)Global->VariableSignatures;
  while (Curr != NULL) {
    //
    // Check known unprotected variables first.
    //
    VarId.VariableName  = VAR_NAME (Curr);
    VarId.VendorGuid    = &Curr->VendorGuid;
    for (Index = 0; Index < UnprotectedVarIndexMax; ++Index) {
      if (Global->UnprotectedVariables[Index] == INVALID_VAR_INDEX
          && IS_VARIABLE (&VarId,
                          mUnprotectedVariables[Index].VariableName,
                          mUnprotectedVariables[Index].VendorGuid))
      {
        if (Index <= IndexHmacAdded) {
          if (Curr->State == (VAR_ADDED & VAR_IN_DELETED_TRANSITION)) {
            VarIndex = IndexHmacInDel;
          } else if (Curr->State == VAR_ADDED) {
            VarIndex = IndexHmacAdded;
          }
        } else {
          VarIndex = Index;
        }

        Global->UnprotectedVariables[VarIndex] = (EFI_PHYSICAL_ADDRESS)(UINTN)Curr;
        break;
      }
    }

    //
    // Re-order current variable.
    //
    Next = NEXT_SIG (Curr);
    MoveNodeBackward (Curr, SortMethod);
    Curr = Next;
  }

  //
  // Find the new head of the linked list re-ordered.
  //
  Curr = (VARIABLE_SIGNATURE *)(UINTN)Global->VariableSignatures;
  while (Curr->Prev != 0) {
    Curr = PREV_SIG (Curr);
  }
  Global->VariableSignatures = (EFI_PHYSICAL_ADDRESS)(UINTN)Curr;
}

/**

  Verify the HMAC value stored in MetaDataHmacVar against all valid and
  protected variables in storage.

  @param[in]      ContextIn       Pointer to context provided by variable services.
  @param[in,out]  Global          Pointer to global configuration data.

  @retval   EFI_SUCCESS           The HMAC value matches.
  @retval   EFI_ABORTED           Error in HMAC value calculation.
  @retval   EFI_VOLUME_CORRUPTED  Inconsistency found in NV variable storage.
  @retval   EFI_COMPROMISED_DATA  The HMAC value doesn't match.
**/
EFI_STATUS
VerifyMetaDataHmac (
  IN      PROTECTED_VARIABLE_CONTEXT_IN   *ContextIn,
  IN OUT  PROTECTED_VARIABLE_GLOBAL       *Global
  )
{
  EFI_STATUS                           Status;
  VARIABLE_STORE_HEADER               *VariableStore;
  VARIABLE_HEADER                     *VariableStart;
  VARIABLE_HEADER                     *VariableEnd;
  VARIABLE_SIGNATURE                  *VariableSig;
  PROTECTED_VARIABLE_INFO             VariableInfo;
  UINT32                              Counter;
  VOID                                *Hmac;
  VOID                                *HmacPlus;
  UINT8                               HmacVal[METADATA_HMAC_SIZE];
  UINT8                               HmacValPlus[METADATA_HMAC_SIZE];
  UINT8                               *UnprotectedVarData[UnprotectedVarIndexMax];
  VARIABLE_HEADER                     *UnprotectedVar[UnprotectedVarIndexMax];
  EFI_PHYSICAL_ADDRESS                Index;
  BOOLEAN                             IsProtectedVar;

  HmacPlus  = NULL;
  Hmac      = HmacSha256New ();
  if (Hmac == NULL) {
    ASSERT (Hmac != NULL);
    return EFI_OUT_OF_RESOURCES;
  }

  if (!HmacSha256SetKey (Hmac, Global->MetaDataHmacKey, sizeof (Global->MetaDataHmacKey))) {
    ASSERT (FALSE);
    Status = EFI_ABORTED;
    goto Done;
  }

  //
  // Retrieve the RPMC counter value.
  //
  Status = RequestMonotonicCounter (&Counter);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    goto Done;
  }

  ZeroMem (UnprotectedVar, sizeof (UnprotectedVar));
  ZeroMem (UnprotectedVarData, sizeof (UnprotectedVarData));

  GetVariableStoreCache (Global, NULL, &VariableStore, &VariableStart, &VariableEnd);
  VariableInfo.Address    = NULL;
  VariableInfo.Flags.Auth = Global->Flags.Auth;
  VariableSig             = (VARIABLE_SIGNATURE *)(UINTN)Global->VariableSignatures;
  while (VariableSig != NULL) {
    if (VariableSig->State != VAR_ADDED
        && VariableSig->State != (VAR_ADDED & VAR_IN_DELETED_TRANSITION)) {
      continue;
    }

    //
    // Check known unprotected variables.
    //
    IsProtectedVar = TRUE;
    for (Index = 0; Index < UnprotectedVarIndexMax; ++Index) {
      if (Global->UnprotectedVariables[Index] == VariableSig) {
        IsProtectedVar = FALSE;
        break;
      }
    }

    //
    // Only take protected variables into account.
    //
    if (IsProtectedVar) {
      if (!Status = HmacSha256Update (Hmac, VAR_SIG_DATA (VariableSig), VariableSig->SigSize)) {
        ASSERT (FALSE);
        Status = EFI_ABORTED;
        goto Done;
      }
    }

    VariableSig = NEXT_SIG (VariableSig);
  }

  //
  // If two MetaDataHmacVariable were found, check which one is valid. So we
  // need two HMAC values to check against: one for Counter, one for Counter+1.
  //
  if (Global->UnprotectedVariables[IndexHmacAdded] != INVALID_VAR_INDEX
      && Global->UnprotectedVariables[IndexHmacInDel] != INVALID_VAR_INDEX)
  {
    //
    // Check Counter+1. There must be something wrong in last boot.
    //
    HmacPlus = HmacSha256New ();
    if (HmacPlus == NULL || !HmacSha256Duplicate (Hmac, HmacPlus)) {
      ASSERT (FALSE);
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }

    ++Counter;
    if (!HmacSha256Update (HmacPlus, &Counter, sizeof (Counter))
        || !HmacSha256Final (HmacPlus, HmacValPlus))
    {
      ASSERT (FALSE);
      Status = EFI_ABORTED;
      goto Done;
    }
    --Counter;  // Restore the Counter since we haven't got the HMAC for it.
  }

  //
  // Check current Counter.
  //
  if (!HmacSha256Update (Hmac, &Counter, sizeof (Counter))
      || !HmacSha256Final (Hmac, HmacVal))
  {
    ASSERT (FALSE);
    Status = EFI_ABORTED;
    goto Done;
  }

  //
  // At least one HMAC value must match the data in one of MetaDataHmacVariables.
  //
  //  When writing (update or add) a variable, there will be following steps
  //  performed:
  //
  //    1 - mark old MetaDataHmacVariable as VAR_IN_DELETED_TRANSITION
  //    2 - encrypt variable data, if enabled
  //    3 - calculate new value for MetaDataHmacVariable
  //    4 - force add new MetaDataHmacVariable as VAR_ADDED
  //    5 - write protected variable
  //    6 - increment Counter
  //    7 - mark old MetaDataHmacVariable as VAR_DELETED
  //
  Status = EFI_SUCCESS;
  if (Global->UnprotectedVariables[IndexHmacAdded] != INVALID_VAR_INDEX
      && Global->UnprotectedVariables[IndexHmacInDel] == INVALID_VAR_INDEX)
  {
    //
    // No error in last boot,
    //    Old MetaDataHmacVariable: deleted
    //    New MetaDataHmacVariable: added
    //                    Variable: updated/added
    //                     Counter: advanced
    //
    // Just check HMAC value for current Counter.
    //
    if (CompareMem (
          VAR_SIG_VALUE (Global->UnprotectedVariables[IndexHmacAdded]),
          HmacVal,
          METADATA_HMAC_SIZE
          ) != 0)
    {
      Status = EFI_COMPROMISED_DATA;
    }
    //
    // Everything is OK. Nothing special to do here.
    //
  } else if (Global->UnprotectedVariables[IndexHmacAdded] == INVALID_VAR_INDEX
             && Global->UnprotectedVariables[IndexHmacInDel] != INVALID_VAR_INDEX)
  {
    //
    // Error occurred in-between step-2 and step-4 in last boot,
    //    Old MetaDataHmacVariable: not deleted (transition)
    //    New MetaDataHmacVariable: not added
    //                    Variable: not updated/added
    //                     Counter: not advanced
    //
    // Just check HMAC value for current Counter.
    //
    if (CompareMem (
          VAR_SIG_VALUE (Global->UnprotectedVariables[IndexHmacInDel]),
          HmacVal,
          METADATA_HMAC_SIZE
          ) != 0)
    {
      Status = EFI_COMPROMISED_DATA;
      goto Done;
    }
    //
    // Restore HmacInDel as HmacAdded
    //
    Global->UnprotectedVariables[IndexHmacAdded] = Global->UnprotectedVariables[IndexHmacInDel];
    Global->UnprotectedVariables[IndexHmacInDel] = INVALID_VAR_INDEX;
  } else if (Global->UnprotectedVariables[IndexHmacAdded] != INVALID_VAR_INDEX
             && Global->UnprotectedVariables[IndexHmacInDel] != INVALID_VAR_INDEX)
  {
    //
    // Error occurred in-between step-4 and step-7 in last boot,
    //    Old MetaDataHmacVariable: not deleted (transition)
    //    New MetaDataHmacVariable: added
    //                    Variable: <uncertain>
    //                     Counter: <uncertain>
    //
    // Check HMAC value for current Counter or Counter+1.
    //
    if (CompareMem (
          VAR_SIG_VALUE (Global->UnprotectedVariables[IndexHmacInDel]),
          HmacVal,
          METADATA_HMAC_SIZE
          ) == 0)
    {
      //
      // (Error occurred in-between step-4 and step-5)
      //                 Variable: not updated/added
      //                  Counter: not advanced
      //

      //
      // Restore HmacInDel and delete HmacAdded
      //
      Index = Global->UnprotectedVariables[IndexHmacAdded];
      Global->UnprotectedVariables[IndexHmacAdded] = Global->UnprotectedVariables[IndexHmacInDel];
      Global->UnprotectedVariables[IndexHmacInDel] = Index;
    } else if (CompareMem (
                VAR_SIG_VALUE (Global->UnprotectedVariables[IndexHmacAdded]),
                HmacValPlus,
                METADATA_HMAC_SIZE
                ) == 0)
    {
      //
      // (Error occurred in-between step-5 and step-6)
      //                 Variable: updated/added
      //                  Counter: not advanced
      //

      //
      // Keep HmacAdded, delete HmacInDel, and advance RPMC to match the HMAC.
      //
      Status = IncrementMonotonicCounter ();
      if (EFI_ERROR (Status)) {
        ASSERT_EFI_ERROR (Status);
      }
    } else if (CompareMem (
                VAR_SIG_VALUE (Global->UnprotectedVariables[IndexHmacAdded]),
                HmacVal,
                METADATA_HMAC_SIZE
                ) == 0)
    {
      //
      // (Error occurred in-between step-6 and step-7)
      //                 Variable: updated/added
      //                  Counter: advanced
      //

      //
      // Just keep HmacAdded and delete HmacInDel.
      //
    } else {
      //
      // It's impossible that HmacInDel matches HmacValPlus (Counter+1) when
      // both HmacInDel and HmacAdded exist.
      //
      Status = EFI_COMPROMISED_DATA;
    }
  } else {
    //
    // There must be logic error or variable written to storage skipped
    // the protected variable service, if code reaches here.
    //
    Status = EFI_COMPROMISED_DATA;
    ASSERT (FALSE);
  }

Done:
  if (Hmac != NULL) {
    HmacSha256Free (Hmac);
  }

  if (HmacPlus != NULL) {
    HmacSha256Free (HmacPlus);
  }

  return Status;
}

/**

  Initialization for protected variable services.

  If this initialization failed upon any error, the whole variable services
  should not be used.  A system reset might be needed to re-construct NV
  variable storage to be the default state.

  @param[in]  ContextIn   Pointer to variable service context needed by
                          protected variable.

  @retval EFI_SUCCESS               Protected variable services are ready.
  @retval EFI_INVALID_PARAMETER     If ContextIn == NULL or something missing or
                                    mismatching in the content in ContextIn.
  @retval EFI_COMPROMISED_DATA      If failed to check integrity of protected variables.
  @retval EFI_OUT_OF_RESOURCES      Fail to allocate enough resource.
  @retval EFI_UNSUPPORTED           Unsupported to process protected variable.

**/
EFI_STATUS
EFIAPI
ProtectedVariableLibInitialize (
  IN  PROTECTED_VARIABLE_CONTEXT_IN   *ContextIn
  )
{
  EFI_STATUS                          Status;
  UINT32                              HobDataSize;
  PROTECTED_VARIABLE_CONTEXT_IN       *GlobalHobData;
  UINT8                               *RootKey;
  UINT32                              KeySize;
  UINT32                              NvVarCacheSize;
  UINT32                              VarNumber;
  PROTECTED_VARIABLE_GLOBAL           *Global;
  VARIABLE_SIGNATURE                  *SigBuffer;
  VARIABLE_SIGNATURE                  *Signature;
  UINT32                              SigBufferSize;
  UINTN                               Index;
  BOOLEAN                             AuthFlag;

  if (ContextIn == NULL
      || ContextIn->InitVariableStore == NULL
      || ContextIn->GetNextVariableInfo == NULL)
  {
    ASSERT (ContextIn != NULL);
    ASSERT (ContextIn->InitVariableStore != NULL);
    ASSERT (ContextIn->GetNextVariableInfo != NULL);
    return EFI_INVALID_PARAMETER;
  }

  //
  // Walk all variables to get info for future operations.
  //
  NvVarCacheSize  = 0;
  SigBufferSize   = 0;
  Status          = ContextIn->InitVariableStore (
                                NULL,
                                NULL,
                                NULL,
                                &SigBufferSize,
                                METADATA_HMAC_SIZE,
                                NULL,
                                &VarNumber,
                                &AuthFlag
                                );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    ASSERT_EFI_ERROR (Status);
    return EFI_VOLUME_CORRUPTED;
  }

  //
  // Build a HOB for Global as well as ContextIn. Memory layout:
  //
  //      ContextIn
  //      Global
  //      Variable Signature List
  //
  // To save precious NEM space of processor, variable cache will not be
  // allocated at this point until physical memory is ready for use.
  //
  HobDataSize = ContextIn->StructSize
                + sizeof (PROTECTED_VARIABLE_GLOBAL)
                + SigBufferSize;
  GlobalHobData = BuildGuidHob (
                    &gEdkiiProtectedVariableGlobalGuid,
                    HobDataSize
                    );
  if (GlobalHobData == NULL) {
    ASSERT (HobDataSize < (1 << sizeof (((EFI_HOB_GENERIC_HEADER *)0)->HobLength)));
    ASSERT (GlobalHobData != NULL);
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Keep the ContextIn in HOB for later uses.
  //
  CopyMem (GlobalHobData, ContextIn, sizeof (*ContextIn));

  ContextIn           = GlobalHobData;
  Global              = (PROTECTED_VARIABLE_GLOBAL *)
                        ((UINTN)ContextIn + ContextIn->StructSize);

  Global->StructVersion = PROTECTED_VARIABLE_CONTEXT_OUT_STRUCT_VERSION;
  Global->StructSize    = HobDataSize - ContextIn->StructSize;

  Global->VariableCache       = 0;
  Global->VariableCacheSize   = 0;
  Global->VariableNumber      = VarNumber;
  Global->VariableSignatures  = 0;

  Global->Flags.Auth        = AuthFlag;
  Global->Flags.WriteInit   = FALSE;
  Global->Flags.WriteReady  = FALSE;

  //
  // Get root key and generate HMAC key.
  //
  Status = GetVariableKey (&RootKey, (UINTN *)&KeySize);
  if (EFI_ERROR (Status) || RootKey == NULL || KeySize < sizeof (Global->RootKey)) {
    ASSERT_EFI_ERROR (Status);
    ASSERT (RootKey != NULL);
    ASSERT (KeySize >= sizeof (Global->RootKey));
    return EFI_DEVICE_ERROR;
  }
  CopyMem (Global->RootKey, RootKey, sizeof (Global->RootKey));

  //
  // Derive the MetaDataHmacKey from root key
  //
  if (!GenerateMetaDataHmacKey (
         Global->RootKey,
         sizeof (Global->RootKey),
         Global->MetaDataHmacKey,
         sizeof (Global->MetaDataHmacKey)
         ))
  {
    ASSERT (FALSE);
    return EFI_ABORTED;
  }

  //
  // Re-walk all NV variables and build signature list.
  //
  Status = ContextIn->InitVariableStore (
                        NULL,
                        NULL,
                        SigBuffer,
                        &SigBufferSize,
                        METADATA_HMAC_SIZE,
                        GetVariableHmac,
                        &VarNumber,
                        &AuthFlag
                        );
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }
  ASSERT (Global->VariableNumber == VarNumber);

  //
  // Sort the variables in order to calc final HMAC stored in L"MetaDataHmacVar".
  // This is to avoid the interference from inconsistent information about
  // variables, like location. The only things which should be taken care is
  // the content and state of them.
  //
  SortVariableSignatureList (ContextIn, Global, CompareVariable);

  //
  // Fixup number of valid protected variables (i.e. exclude unprotected ones)
  //
  for (Index = 0; VarNumber != 0 && Index < UnprotectedVarIndexMax; ++Index) {
    if (Global->UnprotectedVariables[Index] != INVALID_VAR_INDEX) {
      --VarNumber;
    }
  }

  //
  // Check the integrity of all NV variables, if any.
  //
  if ((Global->UnprotectedVariables[IndexHmacAdded] != INVALID_VAR_INDEX
       || Global->UnprotectedVariables[IndexHmacInDel] != INVALID_VAR_INDEX))
  {
    Status = VerifyMetaDataHmac (ContextIn, Global);
  } else if (VarNumber != 0) {
    //
    // There's no MetaDataHmacVariable found for protected variables. Suppose
    // the variable storage is compromised.
    //
    Status = EFI_COMPROMISED_DATA;
  }

  if (EFI_ERROR (Status)) {
    REPORT_STATUS_CODE (
      EFI_ERROR_CODE | EFI_ERROR_UNRECOVERED,
      (PcdGet32 (PcdStatusCodeVariableIntegrity) | (Status & 0xFF))
      );
    ASSERT_EFI_ERROR (Status);
    CpuDeadLoop ();
  }

  Status = PeiServicesNotifyPpi(mPostMemNotifyList);
  return Status;
}

/**

  Get a verified copy of NV variable storage.

  @param[out]     VariableFvHeader      Pointer to the header of whole NV firmware volume.
  @param[out]     VariableStoreHeader   Pointer to the header of variable storage.

  @retval EFI_SUCCESS             A copy of NV variable storage is returned
                                  successfully.
  @retval EFI_NOT_FOUND           The NV variable storage is not found or cached.

**/
EFI_STATUS
EFIAPI
ProtectedVariableLibGetStore (
  OUT EFI_FIRMWARE_VOLUME_HEADER            **VariableFvHeader,
  OUT VARIABLE_STORE_HEADER                 **VariableStoreHeader
  )
{
  EFI_STATUS                        Status;
  PROTECTED_VARIABLE_GLOBAL         *Global;

  Status = GetProtectedVariableContext (NULL, &Global);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  return GetVariableStoreCache (Global, VariableFvHeader, VariableStoreHeader, NULL, NULL);
}

/**

  Prepare for variable update.

  (Not suppported in PEI phase.)

  @retval EFI_UNSUPPORTED         Updating variable is not supported.

**/
EFI_STATUS
EFIAPI
ProtectedVariableLibWriteInit (
  VOID
  )
{
  return EFI_UNSUPPORTED;
}

/**

  Update a variable with protection provided by this library.

  Not supported in PEI phase.

  @param[in,out]  CurrVariable        Variable to be updated. It's NULL if
                                      adding a new variable.
  @param[in,out]  CurrVariableInDel   In-delete-transition copy of updating variable.
  @param[in]      NewVariable         Buffer of new variable data.
  @param[out]     NewVariable         Buffer of "MetaDataHmacVar" and new
                                      variable (encrypted).
  @param[in]      NewVariableSize     Size of NewVariable.
  @param[out]     NewVariableSize     Size of (encrypted) NewVariable and
                                      "MetaDataHmacVar".

  @retval EFI_UNSUPPORTED         Not support updating variable in PEI phase.

**/
EFI_STATUS
EFIAPI
ProtectedVariableLibUpdate (
  IN  OUT VARIABLE_HEADER             *CurrVariable,
  IN      VARIABLE_HEADER             *CurrVariableInDel,
  IN  OUT VARIABLE_HEADER             *NewVariable,
  IN  OUT UINTN                       *NewVariableSize
  )
{
  ASSERT (FALSE);
  return EFI_UNSUPPORTED;
}

/**
  Return the next variable name and GUID.

  This function is called multiple times to retrieve the VariableName
  and VariableGuid of all variables currently available in the system.
  On each call, the previous results are passed into the interface,
  and, on return, the interface returns the data for the next
  interface. When the entire variable list has been returned,
  EFI_NOT_FOUND is returned.

  @param  This              A pointer to this instance of the EFI_PEI_READ_ONLY_VARIABLE2_PPI.

  @param  VariableNameSize  On entry, points to the size of the buffer pointed to by VariableName.
                            On return, the size of the variable name buffer.
  @param  VariableName      On entry, a pointer to a null-terminated string that is the variable's name.
                            On return, points to the next variable's null-terminated name string.
  @param  VariableGuid      On entry, a pointer to an EFI_GUID that is the variable's GUID.
                            On return, a pointer to the next variable's GUID.

  @retval EFI_SUCCESS           The variable was read successfully.
  @retval EFI_NOT_FOUND         The variable could not be found.
  @retval EFI_BUFFER_TOO_SMALL  The VariableNameSize is too small for the resulting
                                data. VariableNameSize is updated with the size
                                required for the specified variable.
  @retval EFI_INVALID_PARAMETER VariableName, VariableGuid or
                                VariableNameSize is NULL.
  @retval EFI_DEVICE_ERROR      The variable could not be retrieved because of a device error.

**/
EFI_STATUS
EFIAPI
ProtectedVariableLibWriteFinal (
  IN  VARIABLE_HEADER         *NewVariable,
  IN  UINTN                   VariableSize,
  IN  UINTN                   Offset
  )
{
  return EFI_UNSUPPORTED;
}

