/*
 * $Id: ext_hdr.h,v 1.1.1.1 2002/03/28 00:02:52 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This file is an interface to the extended header manager, EXT_HDR.C.
 *
 */

#ifndef EXT_HDR_INCLUDED
#define EXT_HDR_INCLUDED

/* Common definitions */

#define EXT_HDR_OVERHEAD           8    /* Number of bytes that each EH takes
                                           away besides its data */

/* Block processing flags: bits 0...1 = processing status
                           bits 2...N = bit flags

   Processed status: when compressing, transition occurs from EH_UNPROCESSED
                     to EH_FINALIZED via EH_PROCESSING.
                     when extracting, transition occurs from EH_PROCESSING to
                     EH_UNPROCESSED. */

#define EH_UNPROCESSED        0x0000    /* Not yet stored */
#define EH_PROCESSING         0x0001    /* Currently being processed */
#define EH_FINALIZED          0x0002    /* Processing complete */

/* Extended header management structure */

struct ext_hdr
{
 char tag;
 char FAR *raw;
 unsigned int size;
 struct ext_hdr FAR *next;
 /* These are initialized from the outside */
 char flags;
 unsigned int cur_offset;
};

#define EH_STATUS(eh) (eh->flags&3)

/* Prototypes */

struct ext_hdr FAR *eh_alloc();
struct ext_hdr FAR *eh_lookup(struct ext_hdr FAR *eh, char tag);
struct ext_hdr FAR *eh_find_pending(struct ext_hdr FAR *eh);
struct ext_hdr FAR *eh_append(struct ext_hdr FAR *eh, char tag, char FAR *block, unsigned int size);
void eh_release(struct ext_hdr FAR *eh);

#endif
