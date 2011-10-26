/* test program for mgetty's config routines 
 *  - ptr/int + struct size checks
 *
 * $Id: t_config.c,v 1.1 2004/11/02 08:14:19 gert Exp $
 *
 * $Log: t_config.c,v $
 * Revision 1.1  2004/11/02 08:14:19  gert
 * test ptr/int and struct alignment for mgetty's config routines
 *
 */

#include <stdio.h>

#include "mgetty.h"
#include "config.h"
#include "conf_mg.h"

int main _P2((argc, argv), int argc, char ** argv)
{
int rc = 0;

p_int test1_i;
void * test1_p;

conf_data c_a[2];

    /* test 1: make sure "p_int" and "void *" have same size
     */
    if ( sizeof(test1_i) != sizeof(test1_p) )
    {
	fprintf( stderr, "%s: test1 FAIL: sizeof(p_int)=%d <-> sizeof(void *)=%d\n", argv[0], sizeof(test1_i), sizeof(test1_p) );
	rc++;
    }

    /* test 2: make sure "struct of struct" and "array of struct"
     * have same alignment - otherwise config.c logic will break down
     */
    if ( ( (char *)&c_a[1] - (char *)&c_a[0] )  !=
         ( (char *)&c.switchbd - (char *)&c.speed ) )
    {
	fprintf( stderr, "%s: test2 FAIL: struct-in-struct != array-of-struct.\n", argv[0] );
	rc++;
    }

    return rc;
}
