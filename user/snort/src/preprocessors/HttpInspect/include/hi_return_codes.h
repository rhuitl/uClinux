/**
**  @file       hi_return_codes.h
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      This file defines the return codes for the HttpInspect
**              functions.
**
**  Common return codes are defined here for all functions and libraries to
**  use.  This should make function error checking easier.
**
**  NOTES:
**
**  - 2.14.03:  Initial Development.  DJR
*/

#ifndef __HI_RETURN_CODES_H__
#define __HI_RETURN_CODES_H__

#include "hi_include.h"

#define HI_BOOL_FALSE 0
#define HI_SUCCESS    0

/*
**  Non-fatal errors are positive
*/
#define HI_BOOL_TRUE          1
#define HI_NONFATAL_ERR       1
#define HI_OUT_OF_BOUNDS      2

/*
**  Fatal errors are negative
*/
#define HI_FATAL_ERR         -1
#define HI_INVALID_ARG       -2
#define HI_MEM_ALLOC_FAIL    -3
#define HI_NOT_FOUND         -4
#define HI_INVALID_FILE      -5

#endif
