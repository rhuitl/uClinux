/**
 * @file   util_str.h
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Fri Jun 27 10:34:37 2003
 * 
 * @brief  string utility functions
 * 
 * some string handling wrappers
 */

#ifndef _UTIL_STR_H
#define _UTIL_STR_H

int str2int(char *str, int *ret, int allow_negative);
int toggle_option(char *name, char *value, int *opt_value);

#endif /* _UTIL_STR_H */

