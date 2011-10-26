/*
 * check_system.c
 *
 * Check, that the system we are running on has proper bit sizes and
 * does proper handling of right bit shift operations
 *
 * $Id: check_system.c,v 1.4 1998/09/09 21:07:09 gert Exp $
 *
 */

#include "../include/voice.h"
#include <assert.h>

void check_system (void)
     {

     /*
      * Check, that right bit shift works properly
      */

     volatile signed int a = -1024;
     volatile signed int b;
     volatile signed int c = 1024;
     volatile signed int d = 10;

     b = a / c;
     c = a >> d;
     assert(b == c);

     /*
      * Check, that the bitsizes are ok
      */

     assert(sizeof(vgetty_s_int16) == 2);
     assert(sizeof(vgetty_u_int16) == 2);
     assert(sizeof(vgetty_s_int32) == 4);
     assert(sizeof(vgetty_u_int32) == 4);
     assert(sizeof(vgetty_s_int64) == 8);
     assert(sizeof(vgetty_u_int64) == 8);

     /*
      * Check, that int is at least 32 bits wide
      */

     assert(sizeof(int) >= 4);
     }
