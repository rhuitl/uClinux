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
#ifndef _SFSNPRINTF_APPEND_H_
#define _SFSNPRINTF_APPEND_H_

int sfsnprintfappend(char *dest, int dsize, const char *format, ...);

#endif /* _SFSNPRINTF_APPEND_H_ */
