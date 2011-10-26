/*
 * lock.c
 *
 * Ethernet Packet Interface to NDIS drivers.
 *
 * Copyright 1998 Equivalence Pty. Ltd.
 *
 * Original code by William Ingle (address unknown)
 *
 * $Log: lock.c,v $
 * Revision 1.1  1998/09/28 08:08:38  robertj
 * Initial revision
 *
 */

#define WANTVXDWRAPS

#include <basedef.h>
#include <vmm.h>
#include <vxdwraps.h>               // must come last

#include "lock.h"


#pragma VxD_LOCKED_CODE_SEG
#pragma VxD_LOCKED_DATA_SEG


DWORD _stdcall PacketPageLock(DWORD lpMem, DWORD cbSize)
{
  // lock a page

  DWORD LinOffset = lpMem & 0xfff; // page offset of memory to map
  DWORD LinPageNum = lpMem >> 12;  // generate page number
  DWORD nPages = ((lpMem + cbSize) >> 12) - LinPageNum + 1; // Calculate # of pages to map globally

  // Return global mapping of passed in pointer, as this new pointer
  // is how the memory must be accessed out of context.
  return _LinPageLock(LinPageNum, nPages, PAGEMAPGLOBAL) + LinOffset;
}


void _stdcall PacketPageUnlock(void * lpMem, DWORD cbSize)
{
  // unlock a page

  DWORD LinPageNum = (DWORD)lpMem >> 12;
  DWORD nPages = (((DWORD)lpMem + cbSize) >> 12) - LinPageNum + 1;

  // Free globally mapped memory
  _LinPageUnlock(LinPageNum, nPages, PAGEMAPGLOBAL);
}


// End of File ////////////////////////////////////////////////////////////////
