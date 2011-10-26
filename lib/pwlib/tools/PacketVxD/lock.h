/*
 * lock.h
 *
 * Ethernet Packet Interface to NDIS drivers.
 *
 * Copyright 1998 Equivalence Pty. Ltd.
 *
 * Original code by William Ingle (address unknown)
 *
 * $Log: lock.h,v $
 * Revision 1.1  1998/09/28 08:08:40  robertj
 * Initial revision
 *
 */

DWORD _stdcall PacketPageLock  (DWORD lpMem, DWORD cbSize);
void  _stdcall PacketPageUnlock(void * lpMem, DWORD cbSize);


// End of File ////////////////////////////////////////////////////////////////
