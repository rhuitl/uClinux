/**
**  @file       hi_server.h
**  
**  @author     Daniel Roelker <droelker@sourcefire.com>
**  
**  @brief      Header file for HttpInspect Server Module
**  
**  This file defines the server structure and functions to access server
**  inspection.
**  
**  NOTE:
**      - Initial development.  DJR
*/
#ifndef __HI_SERVER_H__
#define __HI_SERVER_H__

#include "hi_include.h"

typedef struct s_HI_SERVER
{
    unsigned char *header;
    int           header_size;

} HI_SERVER;

int hi_server_inspection(void *S, unsigned char *data, int dsize);

#endif
