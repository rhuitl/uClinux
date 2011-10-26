/**
 * @file   util_math.h
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Fri Jun 27 10:12:57 2003
 * 
 * @brief  math related util functions
 * 
 * Place simple math functions that are useful all over the place
 * here.
 */

#ifndef _UTIL_MATH_H
#define _UTIL_MATH_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef UINT64
#define UINT64 unsigned long long
#endif

double calc_percent(double amt, double total);
double calc_percent64(UINT64 amt, UINT64 total);

#endif /* _UTIL_MATH_H */


