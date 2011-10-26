/*
 * $Id: arjtypes.h,v 1.1.1.1 2002/03/28 00:01:28 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * OS-independent types are to be declared here.
 *
 */

#ifndef ARJTYPES_INCLUDED
#define ARJTYPES_INCLUDED

/* Message classes */

#ifdef FMSG_ST
typedef char FAR FMSG;
typedef FMSG * FAR FMSGP;
typedef FMSG * FAR NMSGP;
#else
typedef char FMSG;
typedef char *FMSGP;
typedef char *NMSGP;
#endif

/* File access mode record */

struct file_mode
{
 int dos;                               /* For internals of ARJ (-hb, etc.) */
 int native;
};

/* Timestamp record */

struct timestamp
{
 unsigned long dos;                     /* Local */
 unsigned long unixtime;                /* GMT */
};

/* A handy macro for verifying the validity of timestamps */

#define ts_valid(t) (t.dos!=0L)

/* Prototypes */

void fm_store(struct file_mode *dest, int host_os, int mode);
unsigned int fm_native(struct file_mode *fm, int host_os);
void ts_store(struct timestamp *dest, int host_os, unsigned long value);
unsigned long ts_native(struct timestamp *ts, int host_os);
int ts_cmp(struct timestamp *ts1, struct timestamp *ts2);
void make_timestamp(struct timestamp *dest, int y, int m, int d, int hh, int mm, int ss);
void timestamp_to_str(char *str, struct timestamp *ts);

#endif
