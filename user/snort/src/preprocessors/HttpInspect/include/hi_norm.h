/**
**  @file       hi_norm.h
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**  
**  @brief      Contains function prototypes for normalization routines.
**  
**  Contains stuctures and headers for normalization routines.
**  
**  NOTES:
**      - Initial development.  DJR
*/
#ifndef __HI_NORM_H__
#define __HI_NORM_H__

#include <sys/types.h>

#include "hi_include.h"
#include "hi_ui_config.h"
#include "hi_si.h"

int hi_norm_init(HTTPINSPECT_GLOBAL_CONF *GlobalConf);
int hi_normalization(HI_SESSION *Session, int iInspectMode);
int hi_norm_uri(HI_SESSION *Session, u_char *uribuf,int *uribuf_size,
                u_char *uri, int uri_size);

#endif
