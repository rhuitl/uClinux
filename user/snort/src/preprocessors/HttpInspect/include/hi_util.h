/**
**  @file       hi_util.h
**  
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      HttpInspect utility functions.
**  
**  Contains function prototype and inline utility functions.
**
**  NOTES:
**      - Initial development.  DJR
*/

#ifndef __HI_UTIL_H__
#define __HI_UTIL_H__

#include "hi_include.h"

/*
**  NAME
**    hi_util_in_bounds::
*/
/**
**  This function checks for in bounds condition on buffers.  
**  
**  This is very important for much of what we do here, since inspecting
**  data buffers is mainly what we do.  So we always make sure that we are
**  within the buffer.
**  
**  This checks a half-open interval with the end pointer being one char
**  after the end of the buffer.
**  
**  @param start the start of the buffer.
**  @param end   the end of the buffer.
**  @param p     the pointer within the buffer
**  
**  @return integer
**  
**  @retval 1 within bounds
**  @retval 0 not within bounds
*/
static INLINE int hi_util_in_bounds(u_char *start, u_char *end, u_char *p)
{
    if(p >= start && p < end)
    {
        return 1;
    }

    return 0;
}

#endif

