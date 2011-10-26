/*
 * $Id: arj_xms.h,v 1.1.1.1 2002/03/28 00:02:01 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in ARJ_XMS.ASM are declared here.
 *
 */

#ifndef ARJ_XMS_INCLUDED
#define ARJ_XMS_INCLUDED

/* XMS memory move structure */

struct xms_move
{
 unsigned long length;                  /* Must be even */
 short src_handle;                      /* Source handle */
 unsigned long src_offset;              /* Source offset */
 short dest_handle;                     /* Destination handle */
 unsigned long dest_offset;             /* Destination offset */
};

/* Prototypes */

int detect_xms();
void get_xms_entry();
int allocate_xms(unsigned short kbs, short *handle);
int free_xms(short handle);
int move_xms(struct xms_move *xms_mm);

#endif

