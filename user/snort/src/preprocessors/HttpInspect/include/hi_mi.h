/*
**  @file       hi_mi.h
**
**  @author     Daniel Roelker <droelker@atlas.cs.cuc.edu>
**
**  @brief      Contains the functions in hi_mi.h.  Not much
**
**  NOTES:
**    - 3.2.03:  Initial Development.  DJR
*/
#ifndef __HI_MI_H__
#define __HI_MI_H__

#include <sys/types.h>

#include "hi_include.h"
#include "hi_si.h"

int hi_mi_mode_inspection(HI_SESSION *Session, int iInspectMode, 
        u_char *data, int dsize);

#endif

