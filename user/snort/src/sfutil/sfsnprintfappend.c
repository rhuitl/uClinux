/*
*
*  sfsnprintfappend.h
*
*  snprintf that appends to destination buffer
*
*  Copyright (C) 2004 Sourcefire, Inc.
*
*  Author: Steven Sturges
*
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>

/****************************************************************************
 *
 * Function: sfsnprintfappend
 *
 * Purpose: snprintf that appends to destination buffer
 *
 *          Appends the snprintf format string and arguments to dest
 *          without going beyond dsize bounds.  Assumes dest has
 *          been properly allocated, and is of dsize in length.
 *
 * Arguments: dest      ==> pointer to string buffer to append to
 *            dsize     ==> size of buffer dest
 *            format    ==> snprintf format string
 *            ...       ==> arguments for printf
 *
 * Returns: number of characters added to the buffer
 *
 ****************************************************************************/
int sfsnprintfappend(char *dest, int dsize, const char *format, ...)
{
    int currLen, appendLen;
    va_list ap;

    if (!dest || dsize == 0)
        return -1;

    currLen = strlen(dest);

    va_start(ap, format);
    appendLen = vsnprintf(dest+currLen, dsize-currLen, format, ap);
    va_end(ap);

    return appendLen;
}

