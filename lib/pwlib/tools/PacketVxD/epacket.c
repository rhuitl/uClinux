/*
 * epacket.c
 *
 * Ethernet Packet Interface to NDIS drivers.
 *
 * Copyright 1998 Equivalence Pty. Ltd.
 *
 * Original code by William Ingle (address unknown)
 *
 * $Log: epacket.c,v $
 * Revision 1.2  1998/10/06 10:24:42  robertj
 * Fixed hang when using reset command, removed the command!
 *
 * Revision 1.1  1998/09/28 08:08:31  robertj
 * Initial revision
 *
 */

#include <basedef.h>
#include <vmm.h>
#include <ndis.h>
#include <vwin32.h>
#include <string.h>

#include <epacket.h>   // From PWLib

#include "lock.h"


#pragma intrinsic(memset,memcpy,strlen,strcat,strcpy)


///////////////////////////////////////////////////////////////////////////////

#define MAJOR_VERSION 1
#define MINOR_VERSION 2

#define MAX_OPEN 4
#define MAX_REQUESTS 4
#define TRANSMIT_PACKETS 64 //was 16


#define  ETHERNET_HEADER_LENGTH   14
#define  ETHERNET_DATA_LENGTH     1500
#define  ETHERNET_PACKET_LENGTH   (ETHERNET_HEADER_LENGTH+ETHERNET_DATA_LENGTH)


typedef struct _PACKET_RESERVED 
{
  LIST_ENTRY	ListElement;

  char*		lpBuffer;
  DWORD		cbBuffer;
  DWORD*	lpcbBytesReturned;
  OVERLAPPED*	lpoOverlapped;
  DWORD		hDevice;
  DWORD		tagProcess;
} PACKET_RESERVED, *PPACKET_RESERVED;


typedef struct _INTERNAL_REQUEST 
{
  PACKET_RESERVED Reserved;
  NDIS_REQUEST    Request;
} INTERNAL_REQUEST, *PINTERNAL_REQUEST;


typedef struct _OPEN_INSTANCE 
{
  LIST_ENTRY      ListElement;

  DWORD           hDevice;
  NDIS_STATUS     Status; 
  NDIS_HANDLE     AdapterHandle;
  NDIS_HANDLE     BindAdapterContext;
  NDIS_HANDLE     PacketPool;
  NDIS_HANDLE     BufferPool;

  NDIS_SPIN_LOCK  RcvQSpinLock;
  LIST_ENTRY      RcvList;

  NDIS_SPIN_LOCK  RequestSpinLock;
  LIST_ENTRY      RequestList;

  NDIS_SPIN_LOCK  ResetSpinLock;
  LIST_ENTRY      ResetIrpList;

  INTERNAL_REQUEST  Requests[MAX_REQUESTS];
} OPEN_INSTANCE, *POPEN_INSTANCE;


typedef struct _DEVICE_EXTENSION 
{
  PDRIVER_OBJECT  DriverObject;
  NDIS_HANDLE	  NdisProtocolHandle;
  LIST_ENTRY	  OpenList;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;



#define RESERVED(_p) ((PPACKET_RESERVED)((_p)->ProtocolReserved))


//
// define wrapper for VWIN32_DIOCCompletionRoutine 
//

void VXDINLINE VWIN32_DIOCCompletionRoutine( DWORD hEvent )
{
  _asm mov ebx, hEvent
  VxDCall( VWIN32_DIOCCompletionRoutine );
}


#pragma VxD_LOCKED_CODE_SEG
#pragma VxD_LOCKED_DATA_SEG



PDEVICE_EXTENSION GlobalDeviceExtension = NULL;

 
///////////////////////////////////////////////////////////////////////////////
    
VOID NDIS_API PacketTransferDataComplete(IN NDIS_HANDLE  ProtocolBindingContext,
                                         IN PNDIS_PACKET pPacket,
                                         IN NDIS_STATUS  Status,
                                         IN UINT         BytesTransfered)
{
  // upcall when no more data available

  POPEN_INSTANCE Open = (POPEN_INSTANCE)ProtocolBindingContext;
  PPACKET_RESERVED pReserved = (PPACKET_RESERVED)(pPacket->ProtocolReserved);
  OVERLAPPED * pOverlap = (OVERLAPPED *)(pReserved->lpoOverlapped);
  PNDIS_BUFFER pNdisBuffer;


  // free buffer descriptor
  NdisUnchainBufferAtFront(pPacket, &pNdisBuffer);
  if (pNdisBuffer)
    NdisFreeBuffer(pNdisBuffer);

  // set total bytes returned
  BytesTransfered += ETHERNET_HEADER_LENGTH;
  *pReserved->lpcbBytesReturned += BytesTransfered;

  pOverlap->O_InternalHigh = *(pReserved->lpcbBytesReturned);

  // The internal member of overlapped structure contains
  // a pointer to the event structure that will be signalled,
  // resuming the execution of the waitng GetOverlappedResult
  // call.
  VWIN32_DIOCCompletionRoutine(pOverlap->O_Internal);

  // Unlock buffers   
  PacketPageUnlock(pReserved->lpBuffer, pReserved->cbBuffer);
  PacketPageUnlock(pReserved->lpcbBytesReturned, sizeof(DWORD));
  PacketPageUnlock(pReserved->lpoOverlapped, sizeof(OVERLAPPED));

  // recycle the packet
  NdisReinitializePacket(pPacket);

  // Put the packet on the free queue
  NdisFreePacket(pPacket);
}


///////////////////////////////////////////////////////////////////////////////

VOID NDIS_API PacketSendComplete(IN NDIS_HANDLE  ProtocolBindingContext,
                                 IN PNDIS_PACKET pPacket,
                                 IN NDIS_STATUS  Status)
{
  // upcall on completion of send

  PNDIS_BUFFER     pNdisBuffer;
  PPACKET_RESERVED Reserved = (PPACKET_RESERVED)pPacket->ProtocolReserved;

  
  // free buffer descriptor
  NdisUnchainBufferAtFront(pPacket, &pNdisBuffer);
  
  if (pNdisBuffer)
    NdisFreeBuffer(pNdisBuffer);
  
  // return status
  Reserved->lpoOverlapped->O_InternalHigh = Status;
  
  // The internal member of overlapped structure contains
  // a pointer to the event structure that will be signalled,
  // resuming the execution of the waiting GetOverlappedResult
  // call.
  VWIN32_DIOCCompletionRoutine(Reserved->lpoOverlapped->O_Internal);
  
  // Unlock buffers	
  PacketPageUnlock(Reserved->lpBuffer, Reserved->cbBuffer);
  PacketPageUnlock(Reserved->lpcbBytesReturned, sizeof(DWORD));
  PacketPageUnlock(Reserved->lpoOverlapped, sizeof(OVERLAPPED));
  
  // recycle the packet
  NdisReinitializePacket(pPacket);
  
  // Put the packet back on the free list
  NdisFreePacket(pPacket);
}


///////////////////////////////////////////////////////////////////////////////

VOID NDIS_API PacketResetComplete(IN NDIS_HANDLE ProtocolBindingContext,
                                  IN NDIS_STATUS Status)
{
  // upcall on reset completion

  POPEN_INSTANCE Open = (POPEN_INSTANCE)ProtocolBindingContext;
  PLIST_ENTRY    ResetListEntry;


  //  remove the reset request from the list
  NdisAcquireSpinLock(&Open->ResetSpinLock);
  
  if (IsListEmpty(&Open->ResetIrpList)) { 
    NdisReleaseSpinLock(&Open->ResetSpinLock);
    return;
  }

  ResetListEntry = RemoveHeadList(&Open->ResetIrpList);
  NdisReleaseSpinLock(&Open->ResetSpinLock);
  
  // Acquire request element from list
  NdisAcquireSpinLock(&Open->RequestSpinLock);
  
  InsertTailList(&Open->RequestList, ResetListEntry);
  
  NdisReleaseSpinLock(&Open->RequestSpinLock);
}


///////////////////////////////////////////////////////////////////////////////

NDIS_STATUS NDIS_API PacketReset(POPEN_INSTANCE pOpen)
{
  // reset the protocol

  PLIST_ENTRY ResetListEntry;
  NDIS_STATUS Status;

  
  // Acquire request element from list
  NdisAllocateSpinLock(&pOpen->RequestSpinLock);
  
  if (IsListEmpty(&pOpen->RequestList)) { 
    NdisReleaseSpinLock(&pOpen->RequestSpinLock);
    return NDIS_STATUS_RESOURCES;
  }

  ResetListEntry = RemoveHeadList(&pOpen->RequestList);
  NdisReleaseSpinLock(&pOpen->RequestSpinLock);
  
  // Insert Reset IRP into Request Queue
  NdisAcquireSpinLock(&pOpen->ResetSpinLock);
  
  InsertTailList(&pOpen->ResetIrpList, ResetListEntry);
  
  NdisReleaseSpinLock(&pOpen->ResetSpinLock);
  
  // Reset the adapter
  NdisReset(&Status, pOpen->AdapterHandle);
  
  if (Status != NDIS_STATUS_PENDING)
    PacketResetComplete(pOpen, Status);
  return Status;
}


///////////////////////////////////////////////////////////////////////////////

VOID NDIS_API PacketRequestComplete(IN NDIS_HANDLE   ProtocolBindingContext,
                                    IN PNDIS_REQUEST NdisRequest,
                                    IN NDIS_STATUS   Status)
{
  // perform a packet request complete

  POPEN_INSTANCE    Open      = (POPEN_INSTANCE)ProtocolBindingContext;
  PINTERNAL_REQUEST pRequest  = CONTAINING_RECORD(NdisRequest, INTERNAL_REQUEST, Request);
  PPACKET_RESERVED  pReserved = &pRequest->Reserved;
  OVERLAPPED      * pOverlap  = (OVERLAPPED *)pReserved->lpoOverlapped;
  EPACKET_OID     * oidData   = (EPACKET_OID*)pReserved->lpBuffer;


  if (Status == NDIS_STATUS_SUCCESS) {
    // set total bytes returned
    *pReserved->lpcbBytesReturned = oidData->Length + sizeof(EPACKET_OID) - sizeof(oidData->Data);
    pOverlap->O_InternalHigh      = *(pReserved->lpcbBytesReturned);
  }
  else {
    *pReserved->lpcbBytesReturned = 0; // set total bytes returned
    pOverlap->O_InternalHigh      = *pReserved->lpcbBytesReturned;
    oidData->Length = Status;         // return status in oidData if there is an error 
  }
  
  // The internal member of overlapped structure contains
  // a pointer to the event structure that will be signalled,
  // resuming the execution of the waitng GetOverlappedResult
  // call.
  VWIN32_DIOCCompletionRoutine(pOverlap->O_Internal);
  
  // Unlock buffers	
  PacketPageUnlock(pReserved->lpBuffer, pReserved->cbBuffer);
  PacketPageUnlock(pReserved->lpcbBytesReturned, sizeof(DWORD));
  PacketPageUnlock(pReserved->lpoOverlapped, sizeof(OVERLAPPED));
  
  // Return request element to list
  NdisAcquireSpinLock(&Open->RequestSpinLock);
  
  InsertTailList(&Open->RequestList, &pReserved->ListElement);
  
  NdisReleaseSpinLock(&Open->RequestSpinLock);
}


///////////////////////////////////////////////////////////////////////////////

DWORD NDIS_API PacketRequest(POPEN_INSTANCE  Open,
                             DWORD           FunctionCode,
                             DWORD           dwDDB,
                             DWORD           hDevice,
                             PDIOCPARAMETERS pDiocParms)
{
  // perform a packet request

  PLIST_ENTRY       RequestListEntry;
  PINTERNAL_REQUEST pRequest;
  PPACKET_RESERVED  pReserved;
  EPACKET_OID *  OidData;
  NDIS_STATUS       Status;
  

  // Acquire request element from list
  NdisAcquireSpinLock(&Open->RequestSpinLock);
  
  if (IsListEmpty(&Open->RequestList)) { 
    *(DWORD *)(pDiocParms->lpcbBytesReturned) = 0;
    NdisReleaseSpinLock(&Open->RequestSpinLock);
    return NDIS_STATUS_SUCCESS;
  }

  RequestListEntry = RemoveHeadList(&Open->RequestList);
  NdisReleaseSpinLock(&Open->RequestSpinLock);
  
  pReserved = CONTAINING_RECORD(RequestListEntry, PACKET_RESERVED, ListElement);
  pRequest  = CONTAINING_RECORD(pReserved, INTERNAL_REQUEST, Reserved);
  OidData   = (EPACKET_OID*)(pDiocParms->lpvInBuffer);

  if ((pDiocParms->cbInBuffer != pDiocParms->cbOutBuffer) ||
      (pDiocParms->cbInBuffer < sizeof(*OidData) - sizeof(OidData->Data) + OidData->Length)) {
    *(DWORD *)pDiocParms->lpcbBytesReturned = 1;
    return NDIS_STATUS_BUFFER_TOO_SHORT;
  }

  // The buffer is valid
  pReserved->lpBuffer          = (PVOID)PacketPageLock(pDiocParms->lpvInBuffer, pDiocParms->cbInBuffer);
  pReserved->lpcbBytesReturned = (PVOID)PacketPageLock(pDiocParms->lpcbBytesReturned, sizeof(DWORD));
  pReserved->lpoOverlapped     = (PVOID)PacketPageLock(pDiocParms->lpoOverlapped, sizeof(OVERLAPPED));
  pReserved->cbBuffer          = pDiocParms->cbInBuffer;
  pReserved->hDevice           = pDiocParms->hDevice;
  pReserved->tagProcess        = pDiocParms->tagProcess;
  
  if (FunctionCode == IOCTL_EPACKET_SET_OID) {                      
    pRequest->Request.RequestType                                  = NdisRequestSetInformation;
    pRequest->Request.DATA.SET_INFORMATION.Oid                     = OidData->Oid;
    pRequest->Request.DATA.SET_INFORMATION.InformationBufferLength = OidData->Length;
    pRequest->Request.DATA.SET_INFORMATION.InformationBuffer       = OidData->Data;
  } 
  else {
    if (OidData->Oid >= 0x01000000)
      pRequest->Request.RequestType = NdisRequestQueryInformation;
    else
      pRequest->Request.RequestType = NdisRequestGeneric1;
    pRequest->Request.DATA.QUERY_INFORMATION.Oid                     = OidData->Oid;
    pRequest->Request.DATA.QUERY_INFORMATION.InformationBufferLength = OidData->Length;
    pRequest->Request.DATA.QUERY_INFORMATION.InformationBuffer       = OidData->Data;
  }

  // submit the request
  NdisRequest(&Status, Open->AdapterHandle, &pRequest->Request);

  if (Status == NDIS_STATUS_PENDING)
    return(-1);      // This will make DeviceIOControl return ERROR_IO_PENDING

  PacketRequestComplete(Open, &pRequest->Request, Status);
  return Status;
}


///////////////////////////////////////////////////////////////////////////////

NDIS_STATUS NDIS_API PacketReceiveIndicate(IN NDIS_HANDLE ProtocolBindingContext,
                                           IN NDIS_HANDLE MacReceiveContext,
                                           IN PVOID       HeaderBuffer,
                                           IN UINT        HeaderBufferSize,
                                           IN PVOID       LookaheadBuffer,
                                           IN UINT        LookaheadBufferSize,
                                           IN UINT        PacketSize)
{
  // upcall on packet arrival

  POPEN_INSTANCE      Open;
  PLIST_ENTRY         PacketListEntry;
  PNDIS_PACKET        pPacket;
  NDIS_STATUS         Status;
  UINT                BytesTransfered = 0;
  PPACKET_RESERVED    pReserved;


  if (HeaderBufferSize != ETHERNET_HEADER_LENGTH)
    return NDIS_STATUS_NOT_ACCEPTED;
  
  Open = (POPEN_INSTANCE) ProtocolBindingContext;
  
  //  See if there are any pending reads that we can satisfy
  NdisAcquireSpinLock(&Open->RcvQSpinLock); // fixed 5.11.97
  
  if (IsListEmpty(&Open->RcvList)) { 
    NdisReleaseSpinLock(&Open->RcvQSpinLock);
    return NDIS_STATUS_NOT_ACCEPTED;
  }

  PacketListEntry = RemoveHeadList(&Open->RcvList);
  NdisReleaseSpinLock(&Open->RcvQSpinLock);
  
  pReserved = CONTAINING_RECORD(PacketListEntry, PACKET_RESERVED, ListElement);
  pPacket = CONTAINING_RECORD(pReserved, NDIS_PACKET, ProtocolReserved);
  
  // Copy the MAC header
  NdisMoveMemory(RESERVED(pPacket)->lpBuffer, HeaderBuffer, HeaderBufferSize);

  //  Call the Mac to transfer the data portion of the packet
  NdisTransferData(&Status, Open->AdapterHandle, MacReceiveContext, 0, PacketSize, pPacket, &BytesTransfered);
  if (Status == NDIS_STATUS_PENDING)
    return NDIS_STATUS_PENDING;

  if (Status == NDIS_STATUS_SUCCESS) {
    PacketTransferDataComplete(Open, pPacket, Status, BytesTransfered);
    return NDIS_STATUS_SUCCESS;
  }

  PacketTransferDataComplete(Open, pPacket, Status, 0);
  return NDIS_STATUS_SUCCESS;
}


///////////////////////////////////////////////////////////////////////////////

VOID NDIS_API PacketReceiveComplete(IN NDIS_HANDLE ProtocolBindingContext)
{
  // upcall when receive complete
}


///////////////////////////////////////////////////////////////////////////////

VOID NDIS_API PacketStatus(IN NDIS_HANDLE ProtocolBindingContext,
                           IN NDIS_STATUS Status,
                           IN PVOID       StatusBuffer,
                           IN UINT        StatusBufferSize)
{
  // get packet status
}


///////////////////////////////////////////////////////////////////////////////

VOID NDIS_API PacketStatusComplete(IN NDIS_HANDLE ProtocolBindingContext)
{
  // completion handler
}


///////////////////////////////////////////////////////////////////////////////

VOID NDIS_API PacketBindAdapterComplete(IN NDIS_HANDLE  ProtocolBindingContext,
                                        IN NDIS_STATUS  Status,
                                        IN NDIS_STATUS  OpenErrorStatus)
{
  // upcall on Bind completion

  POPEN_INSTANCE Open = (POPEN_INSTANCE)ProtocolBindingContext;

  // If the binding is unsuccessful then we deallocate data structures in 
  // preparation for unloading
  if (Status != NDIS_STATUS_SUCCESS) {
    NdisFreeSpinLock(&Open->RequestSpinLock);
    NdisFreeSpinLock(&Open->RcvQSpinLock);

    NdisFreeBufferPool(Open->BufferPool);
    NdisFreePacketPool(Open->PacketPool);

    NdisFreeMemory(Open, sizeof(OPEN_INSTANCE), 0);
  }
  else {
    // Insert New Adapter into list
    InsertTailList(&GlobalDeviceExtension->OpenList, &Open->ListElement);
  }
}


///////////////////////////////////////////////////////////////////////////////

VOID NDIS_API PacketBindAdapter(OUT PNDIS_STATUS pStatus,
                                IN  NDIS_HANDLE  BindAdapterContext,
                                IN  PNDIS_STRING pAdapterName,
                                IN  PVOID        SystemSpecific1,
                                IN  PVOID        SystemSpecific2)
{
  //   bind this driver to a NIC
  
  POPEN_INSTANCE    oiNew;
  NDIS_STATUS	    ErrorStatus, AllocStatus;
  UINT              Medium;
  NDIS_MEDIUM       MediumArray = NdisMedium802_3;
  UINT              i;


  //  allocate some memory for the open structure
  NdisAllocateMemory((PVOID *)&oiNew, sizeof(OPEN_INSTANCE), 0, -1);
  if (oiNew == NULL) { // not enough memory
    *pStatus = NDIS_STATUS_RESOURCES;
    return;
  }
  
  NdisZeroMemory((PVOID)oiNew, sizeof(OPEN_INSTANCE));
  
  // Save Binding Context
  oiNew->BindAdapterContext = BindAdapterContext;
  
  // Save the device handle
  oiNew->hDevice = (DWORD)SystemSpecific1;
  
  // Allocate a packet pool for our xmit and receive packets
  NdisAllocatePacketPool(&AllocStatus,
                         &(oiNew->PacketPool),
                         TRANSMIT_PACKETS,
                         sizeof(PACKET_RESERVED));
  if (AllocStatus != NDIS_STATUS_SUCCESS) { // not enough memory
    NdisFreeMemory(oiNew, sizeof(OPEN_INSTANCE), 0);
    *pStatus = NDIS_STATUS_RESOURCES;
    return;
  }
  
  // Allocate a buffer pool for our xmit and receive buffers
  NdisAllocateBufferPool(&AllocStatus, &(oiNew->BufferPool), TRANSMIT_PACKETS);
  if (AllocStatus != NDIS_STATUS_SUCCESS) { // not enough memory
    NdisFreeMemory(oiNew, sizeof(OPEN_INSTANCE), 0);
    *pStatus = NDIS_STATUS_RESOURCES;
    return;
  }

  //  list to hold irp's that want to reset the adapter
  NdisAllocateSpinLock(&oiNew->ResetSpinLock);
  InitializeListHead(&oiNew->ResetIrpList);

  //  Initialize list for holding pending read requests
  NdisAllocateSpinLock(&oiNew->RcvQSpinLock);
  InitializeListHead(&oiNew->RcvList);
  
  //  Initialize the request list
  NdisAllocateSpinLock(&oiNew->RequestSpinLock);
  InitializeListHead(&oiNew->RequestList);
  
  //  link up the request stored in our open block
  for (i = 0; i < MAX_REQUESTS; i++) {
    // Braces are required as InsertTailList macro has multiple statements in it
    InsertTailList(&oiNew->RequestList, &oiNew->Requests[i].Reserved.ListElement);
  }
  
  //  Try to open the MAC
  NdisOpenAdapter(pStatus, &ErrorStatus, &oiNew->AdapterHandle, &Medium, &MediumArray, 1,
                  GlobalDeviceExtension->NdisProtocolHandle, oiNew, pAdapterName, 0, NULL);
  
  //  Save the status returned by NdisOpenAdapter for completion routine
  oiNew->Status = *pStatus;
  
  switch (*pStatus) {
    case NDIS_STATUS_PENDING:
      break;
    
    case NDIS_STATUS_SUCCESS:
      ErrorStatus = NDIS_STATUS_SUCCESS;
    
      // fall through to completion routine with oiNew->Status 
      // set to !NDIS_STATUS_PENDING
    
    default:
      PacketBindAdapterComplete(oiNew, *pStatus, ErrorStatus);
      break;
  }
}


///////////////////////////////////////////////////////////////////////////////

VOID NDIS_API PacketUnbindAdapterComplete(IN POPEN_INSTANCE Open,
                                          IN NDIS_STATUS Status)
{
  // upcall on NdisCloseAdapter completion


  // If Open->Status == NDIS_STATUS_PENDING then we must complete the pended unbinding
  if (Open->Status == NDIS_STATUS_PENDING) {
    NdisCompleteUnbindAdapter(Open->BindAdapterContext, Status);
    Open->Status = NDIS_STATUS_SUCCESS;
  }

  if (Status != NDIS_STATUS_SUCCESS)
    return;

  // Remove Adapter from global list
  RemoveEntryList(&Open->ListElement);

  // Free Memory
  NdisFreeSpinLock(&Open->RequestSpinLock);
  NdisFreeSpinLock(&Open->RcvQSpinLock);
  NdisFreeSpinLock(&Open->ResetSpinLock);

  NdisFreeBufferPool(Open->BufferPool);

  NdisFreePacketPool(Open->PacketPool);

  NdisFreeMemory(Open, sizeof(OPEN_INSTANCE), 0);
}


///////////////////////////////////////////////////////////////////////////////

VOID NDIS_API PacketUnbindAdapter(OUT PNDIS_STATUS   Status,
                                  IN  POPEN_INSTANCE Open,
                                  IN  POPEN_INSTANCE junk)
{
  // detach protocol from the NIC clean up any pending I/O requests

  PLIST_ENTRY  PacketListEntry;
  PNDIS_PACKET pPacket;


  //  The open instance of the device is about to close
  //  We need to complete all pending I/O requests
  //  First we complete any pending read requests
  NdisAcquireSpinLock(&Open->RcvQSpinLock);

  while (!IsListEmpty(&Open->RcvList)) {
    PacketListEntry = RemoveHeadList(&Open->RcvList);
    pPacket = CONTAINING_RECORD(PacketListEntry, NDIS_PACKET, ProtocolReserved);

    //  complete normally
    PacketTransferDataComplete(Open, pPacket, NDIS_STATUS_SUCCESS, 0);
  }

  NdisReleaseSpinLock(&Open->RcvQSpinLock);

  // close the adapter
  NdisCloseAdapter(Status, Open->AdapterHandle);

  // Save status returned from NdisCloseAdapter for completion routine
  Open->Status = *Status;

  if (*Status != NDIS_STATUS_PENDING)
    PacketUnbindAdapterComplete(Open, *Status);
}


///////////////////////////////////////////////////////////////////////////////

VOID NDIS_API PacketUnload()
{
  // deregister the protocol, free remaining memory 
  //  - called by NdisCloseAdapter when last adapter closed

  NDIS_STATUS Status;
  
  if (GlobalDeviceExtension != NULL) {
    NdisDeregisterProtocol(&Status, GlobalDeviceExtension->NdisProtocolHandle);
    
    if (Status == NDIS_STATUS_SUCCESS)
      NdisFreeMemory(GlobalDeviceExtension, sizeof(DEVICE_EXTENSION), 0);
    GlobalDeviceExtension = NULL;
  }
}


///////////////////////////////////////////////////////////////////////////////

NTSTATUS NDIS_API DriverEntry(IN PDRIVER_OBJECT  DriverObject,
                              IN PUNICODE_STRING RegistryPath)

{
  // initialiae the driver

  NDIS_PROTOCOL_CHARACTERISTICS ProtocolChar;
  NDIS_STRING ProtoName = NDIS_STRING_CONST("EPACKET");
  NDIS_STATUS Status;


  // Because the driver can be loaded once for each Netcard on the system,
  // and because DriverEntry is called each time, we must ensure that
  // initialization is performed only once.
  if (GlobalDeviceExtension != NULL)
    return NDIS_STATUS_SUCCESS;
        
  NdisAllocateMemory((PVOID *)&GlobalDeviceExtension, sizeof(DEVICE_EXTENSION), 0, -1 );
  if (GlobalDeviceExtension == NULL)
    return NDIS_STATUS_RESOURCES;

  NdisZeroMemory((UCHAR*)GlobalDeviceExtension, sizeof(DEVICE_EXTENSION));
  NdisZeroMemory((UCHAR*)&ProtocolChar, sizeof(NDIS_PROTOCOL_CHARACTERISTICS));
  ProtocolChar.MajorNdisVersion            = 0x03;
  ProtocolChar.MinorNdisVersion            = 0x0a;
  ProtocolChar.Reserved                    = 0;
  ProtocolChar.OpenAdapterCompleteHandler  = PacketBindAdapterComplete;
  ProtocolChar.CloseAdapterCompleteHandler = PacketUnbindAdapterComplete;
  ProtocolChar.SendCompleteHandler         = PacketSendComplete;
  ProtocolChar.TransferDataCompleteHandler = PacketTransferDataComplete;
  ProtocolChar.ResetCompleteHandler        = PacketResetComplete;
  ProtocolChar.RequestCompleteHandler      = PacketRequestComplete;
  ProtocolChar.ReceiveHandler              = PacketReceiveIndicate;
  ProtocolChar.ReceiveCompleteHandler      = PacketReceiveComplete;
  ProtocolChar.StatusHandler               = PacketStatus;
  ProtocolChar.StatusCompleteHandler       = PacketStatusComplete;
  ProtocolChar.BindAdapterHandler          = PacketBindAdapter;
  ProtocolChar.UnbindAdapterHandler        = PacketUnbindAdapter;
  ProtocolChar.UnloadProtocolHandler       = PacketUnload;
  ProtocolChar.Name                        = ProtoName;
  
  NdisRegisterProtocol(&Status,
                       &GlobalDeviceExtension->NdisProtocolHandle,
                       &ProtocolChar,
                       sizeof(NDIS_PROTOCOL_CHARACTERISTICS));
  
  if (Status != NDIS_STATUS_SUCCESS) {
    NdisFreeMemory(GlobalDeviceExtension, sizeof(DEVICE_EXTENSION), 0);
    return Status;
  }
  
  // initialize open list
  InitializeListHead(&GlobalDeviceExtension->OpenList);
  
  // initialize global device extension
  GlobalDeviceExtension->DriverObject = DriverObject;
  
  return Status;
}


///////////////////////////////////////////////////////////////////////////////

POPEN_INSTANCE GetOpen(DWORD handle)
{
  // return a specified Open Instance      

  PLIST_ENTRY     pHead = &GlobalDeviceExtension->OpenList;
  PLIST_ENTRY     pTemp;
  POPEN_INSTANCE  Open;
  

  if (GlobalDeviceExtension == NULL)
    return NULL;
  
  // search the list for the Open Instance containing the specified handle
  
  for (pTemp = pHead->Flink; pTemp != pHead; pTemp = pTemp->Flink) {
    Open = CONTAINING_RECORD(pTemp, OPEN_INSTANCE, ListElement);        
    if (Open && Open->hDevice == handle)
      return Open;
  }
  
  return NULL; // just in case
}


///////////////////////////////////////////////////////////////////////////////

VOID PacketAllocatePacketBuffer(PNDIS_STATUS    pStatus,
                                POPEN_INSTANCE  pOpen,
                                PNDIS_PACKET    *ppPacket,
                                PDIOCPARAMETERS pDiocParms,
                                DWORD           FunctionCode )
{
  // allocate a buffer for reading/writing

  PNDIS_BUFFER pNdisBuffer;
  PNDIS_PACKET pPacket;
  

  //  Try to get a packet from our list of free ones
  NdisAllocatePacket(pStatus, ppPacket, pOpen->PacketPool);
  
  if (*pStatus != NDIS_STATUS_SUCCESS) {
    *(DWORD *)(pDiocParms->lpcbBytesReturned) = 0;
    return;
  }
  
  pPacket = *ppPacket;
  
  // Buffers used asynchronously must be page locked
  switch (FunctionCode) {
    case IOCTL_EPACKET_READ:
      RESERVED(pPacket)->lpBuffer = (PVOID)PacketPageLock(pDiocParms->lpvOutBuffer, pDiocParms->cbOutBuffer);
      RESERVED(pPacket)->cbBuffer = pDiocParms->cbOutBuffer;
      break;
    
    case IOCTL_EPACKET_WRITE:
      RESERVED(pPacket)->lpBuffer = (PVOID)PacketPageLock(pDiocParms->lpvInBuffer, pDiocParms->cbInBuffer);
      RESERVED(pPacket)->cbBuffer = pDiocParms->cbInBuffer;
      break;
    
    default:
      // recycle the packet
      NdisReinitializePacket(pPacket);
    
      // Put the packet on the free queue
      NdisFreePacket(pPacket);
    
      *(DWORD *)(pDiocParms->lpcbBytesReturned) = 0;
      *pStatus = NDIS_STATUS_NOT_ACCEPTED;
      return;
  }
  
  RESERVED(pPacket)->lpcbBytesReturned = (PVOID)PacketPageLock(pDiocParms->lpcbBytesReturned, sizeof(DWORD));
  RESERVED(pPacket)->lpoOverlapped     = (PVOID)PacketPageLock(pDiocParms->lpoOverlapped, sizeof(OVERLAPPED));
  RESERVED(pPacket)->hDevice           = pDiocParms->hDevice;
  RESERVED(pPacket)->tagProcess        = pDiocParms->tagProcess;
  
  switch (FunctionCode) {
    case IOCTL_EPACKET_READ:
      NdisAllocateBuffer(pStatus,
                         &pNdisBuffer,
                         pOpen->BufferPool,
                         (PVOID)(RESERVED(pPacket)->lpBuffer + ETHERNET_HEADER_LENGTH),
                         pDiocParms->cbOutBuffer);
      break;
    
    case IOCTL_EPACKET_WRITE:
      NdisAllocateBuffer(pStatus,
                         &pNdisBuffer,
                         pOpen->BufferPool,
                         (PVOID)RESERVED(pPacket)->lpBuffer,
                         pDiocParms->cbInBuffer);
      break;
  }
  
  if (*pStatus == NDIS_STATUS_SUCCESS)
    NdisChainBufferAtFront(pPacket, pNdisBuffer); // Attach buffer to Packet
  else {
    NdisReinitializePacket(pPacket);  // recycle the packet
    NdisFreePacket(pPacket);          // Put the packet on the free queue
    *(DWORD *)(pDiocParms->lpcbBytesReturned) = 0;
  }
}


///////////////////////////////////////////////////////////////////////////////

DWORD PacketRead(POPEN_INSTANCE     Open,
                 DWORD              dwDDB,
                 DWORD              hDevice,
                 PDIOCPARAMETERS    pDiocParms)
{
  // read a packet

  NDIS_STATUS     Status;
  PNDIS_PACKET    pPacket;
  
  //  Check that the buffer can hold a max length Ethernet packet
  if (pDiocParms->cbOutBuffer < ETHERNET_PACKET_LENGTH) {
    *(DWORD *)(pDiocParms->lpcbBytesReturned) = 0; // Need bigger buffer       
    return NDIS_STATUS_SUCCESS;
  }
  
  PacketAllocatePacketBuffer(&Status, Open, &pPacket, pDiocParms, IOCTL_EPACKET_READ);
  
  if (Status == NDIS_STATUS_SUCCESS) {
    //  Put this packet in a list of pending reads.
    //  The receive indication handler will attempt to remove packets
    //  from this list for use in transfer data calls
    NdisAcquireSpinLock(&Open->RcvQSpinLock); // fixed 6.11.97
    InsertTailList(&Open->RcvList, &RESERVED(pPacket)->ListElement);
    NdisReleaseSpinLock(&Open->RcvQSpinLock);
  }

  return -1;  // This will make DeviceIOControl return ERROR_IO_PENDING
}


///////////////////////////////////////////////////////////////////////////////

DWORD PacketWrite(POPEN_INSTANCE    Open,
                  DWORD             dwDDB,
                  DWORD             hDevice,
                  PDIOCPARAMETERS   pDiocParms)
{
  // write a packet

  PNDIS_PACKET    pPacket;
  NDIS_STATUS     Status;

  
  PacketAllocatePacketBuffer(&Status, Open, &pPacket, pDiocParms, IOCTL_EPACKET_WRITE);
  if (Status != NDIS_STATUS_SUCCESS)
    return 0;   // This will return immediately with no data written
  
  // Call the MAC
  NdisSend(&Status, Open->AdapterHandle, pPacket);
  if (Status != NDIS_STATUS_PENDING) {
    //  The send didn't pend so call the completion handler now
    PacketSendComplete(Open, pPacket, Status);
  }

  return(-1); // This will make DeviceIOControl return ERROR_IO_PENDING
}


///////////////////////////////////////////////////////////////////////////////

DWORD _stdcall PacketIOControl(DWORD           dwService,
                               DWORD           dwDDB,
                               DWORD           hDevice,
                               PDIOCPARAMETERS pDiocParms) 
{
  // called from applications

  POPEN_INSTANCE  Open;
  NDIS_STATUS     Status;
  UCHAR           AdapterBuffer[5];
  NDIS_STRING     AdapterName = NDIS_STRING_CONST(AdapterBuffer);


  switch (dwService) {
    case DIOC_OPEN:
      return NDIS_STATUS_SUCCESS;
    
    case DIOC_CLOSEHANDLE:
      if ((Open = GetOpen(hDevice)) != NULL)
        PacketUnbindAdapter(&Status, Open, NULL);
      return NDIS_STATUS_SUCCESS;

    case IOCTL_EPACKET_VERSION:
      if (pDiocParms->cbOutBuffer < 2)
        *(DWORD *)(pDiocParms->lpcbBytesReturned) = 0;
      else {
        ((BYTE *)pDiocParms->lpvOutBuffer)[0] = MAJOR_VERSION;
        ((BYTE *)pDiocParms->lpvOutBuffer)[1] = MINOR_VERSION;
        *(DWORD *)pDiocParms->lpcbBytesReturned = 2;
      }
      return NDIS_STATUS_SUCCESS;

    case IOCTL_EPACKET_BIND:
      memcpy(AdapterName.Buffer, (BYTE *)pDiocParms->lpvInBuffer,
             min(strlen((char *)pDiocParms->lpvInBuffer), sizeof(AdapterBuffer)-1));
      AdapterName.Buffer[sizeof(AdapterBuffer)-1] = '\0';
      PacketBindAdapter(&Status,
                        GlobalDeviceExtension->NdisProtocolHandle,
                        &AdapterName,
                        (PVOID)hDevice, /* special */
                        NULL);
      // Note: If the above usage of the 4'th arg to PacketBindAdapter
      //       causes problems, use a global variable instead.
      if (Status == NDIS_STATUS_SUCCESS || Status == NDIS_STATUS_PENDING) {
        *(DWORD *)pDiocParms->lpcbBytesReturned = 1;
        return NDIS_STATUS_SUCCESS;
      }
      break;

    case IOCTL_EPACKET_SET_OID:
    case IOCTL_EPACKET_QUERY_OID:
      if ((Open = GetOpen(hDevice)) != NULL)
        return PacketRequest(Open, dwService, dwDDB, hDevice, pDiocParms);
      break;
    
    case IOCTL_EPACKET_READ:
      if ((Open = GetOpen(hDevice)) != NULL)
        return PacketRead(Open, dwDDB, hDevice, pDiocParms);
      break;
    
    case IOCTL_EPACKET_WRITE:
      if ((Open = GetOpen(hDevice)) != NULL)
        return PacketWrite(Open, dwDDB, hDevice, pDiocParms);
      break;
  }

  *(DWORD *)pDiocParms->lpcbBytesReturned = 0;
  return NDIS_STATUS_SUCCESS;
}


// End of File ////////////////////////////////////////////////////////////////
