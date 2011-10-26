/**
 * @file   util_math.c
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Fri Jun 27 10:12:57 2003
 * 
 * @brief  math related util functions
 * 
 * Place simple math functions that are useful all over the place
 * here.
 */

#include "util_math.h"

/** 
 * Calculate the percentage of something.
 *
 * If the total is <= 0, we return 0.
 * 
 * @param amt amount to that you have
 * @param total amount there is
 * 
 * @return a/b * 100
 */
double calc_percent(double amt, double total)
{
    if(total <= 0.0)
        return 0.0;    
    
    return (amt/total) * 100.0;
}

double calc_percent64(UINT64 amt, UINT64 total)
{
    if (total <= 0)
        return 0.0;

    return (amt/total) * 100.0;
}

