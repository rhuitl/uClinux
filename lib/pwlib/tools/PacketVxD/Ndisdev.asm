.LALL
;*****************************************************************************
;
;       (C) Copyright MICROSOFT Corp, 1995
;
;       Title:      LANCELNK.ASM sourced from:
;       Title:      NDISLNK.ASM - Assembly linkage to NDIS Wrapper for MACs
;                                  and Protocols
;
;	Information in this document is Microsoft Confidential. 
;	Copyright (c) 1996, Microsoft Corporation, all rights reserve
;
;	This document is provided for informational purposes only and Microsoft 
;	Corporation makes no warranties, either expressed or implied, in this document.
;	Information in this document may be substantially changed without notice in
;	subsequent versions of windows and does not represent a commitment on the 
;	part of Microsoft Corporation. This information is for internal use only for 
;	development purposes.
;
;       Version:    3.00
;
;       Date:       05-Nov-1991
;
;=============================================================================
    TITLE $LANCELNK
    .386P



INCLUDE VMM.INC
INCLUDE NETVXD.INC          ; Net VxD initialization oredr

;INCLUDE NDIS.INC  Dont have this so include the bit we need from the NDIS.H file.

Begin_Service_Table Ndis

    Ndis_Service NdisGetVersion,LOCAL
    
    Ndis_Service NdisAllocateSpinLock,LOCAL
    Ndis_Service NdisFreeSpinLock,LOCAL
    Ndis_Service NdisAcquireSpinLock,LOCAL
    Ndis_Service NdisReleaseSpinLock,LOCAL
    
    Ndis_Service NdisOpenConfiguration,LOCAL
    Ndis_Service NdisReadConfiguration,LOCAL
    Ndis_Service NdisCloseConfiguration,LOCAL
    Ndis_Service NdisReadEisaSlotInformation, LOCAL
    Ndis_Service NdisReadMcaPosInformation,LOCAL

    Ndis_Service NdisAllocateMemory,LOCAL
    Ndis_Service NdisFreeMemory,LOCAL
    Ndis_Service NdisSetTimer,LOCAL
    Ndis_Service NdisCancelTimer,LOCAL
    Ndis_Service NdisStallExecution,LOCAL
    Ndis_Service NdisInitializeInterrupt,LOCAL
    Ndis_Service NdisRemoveInterrupt,LOCAL
    Ndis_Service NdisSynchronizeWithInterrupt,LOCAL
    Ndis_Service NdisOpenFile,LOCAL
    Ndis_Service NdisMapFile,LOCAL
    Ndis_Service NdisUnmapFile,LOCAL
    Ndis_Service NdisCloseFile,LOCAL

    Ndis_Service NdisAllocatePacketPool,LOCAL
    Ndis_Service NdisFreePacketPool,LOCAL
    Ndis_Service NdisAllocatePacket,LOCAL
    Ndis_Service NdisReinitializePacket,LOCAL
    Ndis_Service NdisFreePacket,LOCAL
    Ndis_Service NdisQueryPacket,LOCAL

    Ndis_Service NdisAllocateBufferPool,LOCAL
    Ndis_Service NdisFreeBufferPool,LOCAL
    Ndis_Service NdisAllocateBuffer,LOCAL
    Ndis_Service NdisCopyBuffer,LOCAL
    Ndis_Service NdisFreeBuffer,LOCAL
    Ndis_Service NdisQueryBuffer,LOCAL
    Ndis_Service NdisGetBufferPhysicalAddress,LOCAL
    Ndis_Service NdisChainBufferAtFront,LOCAL
    Ndis_Service NdisChainBufferAtBack,LOCAL
    Ndis_Service NdisUnchainBufferAtFront,LOCAL
    Ndis_Service NdisUnchainBufferAtBack,LOCAL
    Ndis_Service NdisGetNextBuffer,LOCAL
    Ndis_Service NdisCopyFromPacketToPacket,LOCAL

    Ndis_Service NdisRegisterProtocol,LOCAL
    Ndis_Service NdisDeregisterProtocol,LOCAL
    Ndis_Service NdisOpenAdapter,LOCAL
    Ndis_Service NdisCloseAdapter,LOCAL
    Ndis_Service NdisSend,LOCAL
    Ndis_Service NdisTransferData,LOCAL
    Ndis_Service NdisReset,LOCAL
    Ndis_Service NdisRequest,LOCAL

    Ndis_Service NdisInitializeWrapper,LOCAL
    Ndis_Service NdisTerminateWrapper,LOCAL
    Ndis_Service NdisRegisterMac,LOCAL
    Ndis_Service NdisDeregisterMac,LOCAL
    Ndis_Service NdisRegisterAdapter,LOCAL
    Ndis_Service NdisDeregisterAdapter,LOCAL
    Ndis_Service NdisCompleteOpenAdapter,LOCAL
    Ndis_Service NdisCompleteCloseAdapter,LOCAL
    Ndis_Service NdisCompleteSend,LOCAL
    Ndis_Service NdisCompleteTransferData,LOCAL
    Ndis_Service NdisCompleteReset,LOCAL
    Ndis_Service NdisCompleteRequest,LOCAL
    Ndis_Service NdisIndicateReceive,LOCAL
    Ndis_Service NdisIndicateReceiveComplete,LOCAL
    Ndis_Service NdisIndicateStatus,LOCAL
    Ndis_Service NdisIndicateStatusComplete,LOCAL
    Ndis_Service NdisCompleteQueryStatistics,LOCAL

    Ndis_Service NdisEqualString,LOCAL
    Ndis_Service NdisRegAdaptShutdown,LOCAL
    Ndis_Service NdisReadNetworkAddress,LOCAL

    Ndis_Service NdisWriteErrorLogEntry,LOCAL

    Ndis_Service NdisMapIoSpace,LOCAL
    Ndis_Service NdisDeregAdaptShutdown,LOCAL

    Ndis_Service NdisAllocateSharedMemory,LOCAL
    Ndis_Service NdisFreeSharedMemory, LOCAL

    Ndis_Service NdisAllocateDmaChannel, LOCAL
    Ndis_Service NdisSetupDmaTransfer, LOCAL
    Ndis_Service NdisCompleteDmaTransfer, LOCAL
    Ndis_Service NdisReadDmaCounter, LOCAL
    Ndis_Service NdisFreeDmaChannel, LOCAL
    Ndis_Service NdisReleaseAdapterResources, LOCAL
    Ndis_Service NdisQueryGlobalStatistics, LOCAL

    Ndis_Service NdisOpenProtocolConfiguration, LOCAL
    Ndis_Service NdisCompleteBindAdapter, LOCAL
    Ndis_Service NdisCompleteUnbindAdapter, LOCAL
    Ndis_Service WrapperStartNet, LOCAL
    Ndis_Service WrapperGetComponentList, LOCAL
    Ndis_Service WrapperQueryAdapterResources, Local
    Ndis_Service WrapperDelayBinding, Local
    Ndis_Service WrapperResumeBinding, Local
    Ndis_Service WrapperRemoveChildren, Local
    Ndis_Service NdisImmediateReadPciSlotInformation, Local
    Ndis_Service NdisImmediateWritePciSlotInformation, Local
    Ndis_Service NdisReadPciSlotInformation, Local
    Ndis_Service NdisWritePciSlotInformation, Local
    Ndis_Service NdisPciAssignResources, Local
    Ndis_Service NdisQueryBufferOffset, Local
End_Service_Table Ndis

NDIS_STATUS_SUCCESS EQU 0



; the following equate makes the VXD dynamically loadable.
DEVICE_DYNAMIC EQU 1


DECLARE_VIRTUAL_DEVICE %DEVICE, 3, 10, <%DEVICE>_Control, Undefined_Device_Id, PROTOCOL_Init_Order

VxD_LOCKED_DATA_SEG

Public bInitAlready	
	bInitAlready	 DB 0
	
VxD_LOCKED_DATA_ENDS

VxD_LOCKED_CODE_SEG


BeginProc C_Device_Init


IFDEF NDIS_STDCALL
	extern _DriverEntry@8:NEAR
ELSE
	extern _DriverEntry:NEAR
ENDIF

	mov  		al, bInitAlready
	cmp  		al, 0					; Make sure we' haven't been called already.
	jnz  		Succeed_Init_Phase
	inc  		bInitAlready			; Set the "Called Already" Flag

; Make sure the wrapper (Ndis.386) is loaded
   VxDcall	NdisGetVersion
   jc   		Fail_Init_Phase

   push 		0
   push 		0

IFDEF NDIS_STDCALL
   call 		_DriverEntry@8
ELSE
   call 		_DriverEntry
   add  		esp,8
ENDIF

   cmp  		eax, NDIS_STATUS_SUCCESS
   jne  		Fail_Init_Phase

Succeed_Init_Phase:
   clc
   ret

Fail_Init_Phase:
   stc
   ret

EndProc C_Device_Init


Begin_Control_Dispatch %DEVICE

    Control_Dispatch Sys_Dynamic_Device_Init, C_Device_Init
    Control_Dispatch W32_DEVICEIOCONTROL,     PacketIOControl, sCall, <ecx, ebx, edx, esi>
;     Control_Dispatch DEBUG_QUERY,           PacketDebugQuery, sCall

End_Control_Dispatch %DEVICE



VxD_LOCKED_CODE_ENDS

;******************************************************************************
;                 R E A L   M O D E   I N I T   C O D E
;******************************************************************************

;******************************************************************************
;
;   MAC_Real_Init
;
;   DESCRIPTION:
;
;   ENTRY:
;
;   EXIT:
;
;   USES:
;
;==============================================================================

VxD_REAL_INIT_SEG

BeginProc MAC_Real_Init

;
;   If another us is loaded then don't load -- Just abort our load
;
     test    bx, Duplicate_From_INT2F OR Duplicate_Device_ID
     jnz     SHORT Ndis_RI_Abort_Load



;   No other  is loaded.

     xor     bx, bx
     xor     si, si
     mov     ax, Device_Load_Ok
     ret

Ndis_RI_Abort_Load:
     xor     bx, bx
     xor     si, si
     mov     ax, Abort_Device_Load
     ret

EndProc MAC_Real_Init

VxD_REAL_INIT_ENDS

END MAC_Real_Init
