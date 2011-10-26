/*
 * $Id: ntstream.c,v 1.1 2003/01/25 15:10:03 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * A convenient interface to the NT backup stream functions (Backup*)
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

#define W32_SID_HEADER_SIZE       20

#if TARGET==WIN32

/* Open a file for stream operation */

struct nt_sid *open_streams(char *name, int is_write)
{
 struct nt_sid *rc;

 if((rc=(struct nt_sid *)malloc(sizeof(struct nt_sid)))==NULL)
  return(NULL);
 if((rc->hf=CreateFile(name, is_write?GENERIC_WRITE:GENERIC_READ,
                       FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,
                       OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS,
                       0))==INVALID_HANDLE_VALUE)
 {
  free(rc);
  return(NULL);
 }
 rc->is_write=is_write;
 rc->lpcontext=NULL;
 rc->rem.LowPart=rc->rem.HighPart=0;
 return(rc);
}

/* Finalize a backup operation before closing the stream */

static void finalize_backup(struct nt_sid *sid)
{
 DWORD dummy;

 if(sid->lpcontext!=NULL)
 {
  if(sid->is_write)
   BackupWrite(sid->hf, NULL, 0, &dummy, TRUE, FALSE, &sid->lpcontext);
#if SFX_LEVEL>=ARJ
  else
   BackupRead(sid->hf, NULL, 0, &dummy, TRUE, FALSE, &sid->lpcontext);
#endif
  sid->lpcontext=NULL;
 }
}

/* Close a stream operations handle */

void close_streams(struct nt_sid *sid)
{
 finalize_backup(sid);
 CloseHandle(sid->hf);
}

/* Skip to the next stream */

int next_stream(WIN32_STREAM_ID *dest, struct nt_sid *sid)
{
 DWORD lo, hi, b;

 if(sid->is_write)
  return(-1);
 if(sid->rem.LowPart!=0||sid->rem.HighPart!=0)
 {
  if(!BackupSeek(sid->hf, sid->rem.LowPart, sid->rem.HighPart, &lo, &hi, &sid->lpcontext))
   return(-1);
  if(lo!=sid->rem.LowPart||hi!=sid->rem.HighPart)
   return(-1);
  sid->rem.LowPart=sid->rem.HighPart=0;
 }
 if(!BackupRead(sid->hf, (unsigned char *)dest, W32_SID_HEADER_SIZE, &b, FALSE, TRUE, &sid->lpcontext))
  return(-1);
 if(b!=W32_SID_HEADER_SIZE)
  return(-1);
 sid->rem=dest->Size;
 return(0);
}

/* Looks for a specific stream ID. Returns stream size. */

unsigned long seek_stream_id(DWORD id, struct nt_sid *sid)
{
 int tampered;
 WIN32_STREAM_ID winsid;

 /* Perform 1st iteration for "virgin" streams (that haven't yet been operated
    with). Redo the lookup in a second operation if the streams were in use. */
 tampered=(sid->lpcontext!=NULL)?1:0;
 do
 {
  while(!next_stream(&winsid, sid))
  {
   if(winsid.dwStreamId==id)
    return((winsid.Size.HighPart>0)?0xFFFFFFFF:winsid.Size.LowPart);
  }
  finalize_backup(sid);
 } while(tampered--);
 return(0);
}

#if SFX_LEVEL>=ARJ

/* Read from a stream */

unsigned long read_stream(unsigned char *dest, unsigned long bytes, struct nt_sid *sid)
{
 unsigned long br, rc;

 if(sid->is_write)
  return(0);
 br=(sid->rem.HighPart==0&&sid->rem.LowPart<bytes)?sid->rem.LowPart:bytes;
 if(br==0)
  return(0);
 if(!BackupRead(sid->hf, dest, br, &rc, FALSE, TRUE, &sid->lpcontext))
  return(0);
 sid->rem=LargeIntegerSubtract(sid->rem, ConvertUlongToLargeInteger(rc));
 return(rc);
}

#endif

/* Initialize a new stream before writing */

int create_stream(WIN32_STREAM_ID *src, struct nt_sid *sid)
{
 DWORD lo, hi, b;

 if(!sid->is_write)
  return(-1);
 if(sid->rem.LowPart!=0&&sid->rem.HighPart!=0)
 {
  if(!BackupSeek(sid->hf, sid->rem.LowPart, sid->rem.HighPart, &lo, &hi, &sid->lpcontext))
   return(-1);
  if(lo!=sid->rem.LowPart||hi!=sid->rem.HighPart)
   return(-1);
  sid->rem.LowPart=sid->rem.HighPart=0;
 }
 if(!BackupWrite(sid->hf, (unsigned char *)src, W32_SID_HEADER_SIZE, &b, FALSE, TRUE, &sid->lpcontext))
  return(-1);
 if(b!=W32_SID_HEADER_SIZE)
  return(-1);
 sid->rem=src->Size;
 return(0);
}

/* Write to a stream */

unsigned long write_stream(unsigned char *src, unsigned long bytes, struct nt_sid *sid)
{
 unsigned long bw, rc;

 if(!sid->is_write)
  return(0);
 /* This is crucial to prevent overflow */
 bw=(sid->rem.HighPart==0&&sid->rem.LowPart<bytes)?sid->rem.LowPart:bytes;
 if(bw==0)
  return(0);
 if(!BackupWrite(sid->hf, src, bw, &rc, FALSE, TRUE, &sid->lpcontext))
  return(0);
 sid->rem=LargeIntegerSubtract(sid->rem, ConvertUlongToLargeInteger(rc));
 return(rc);
}

#endif
