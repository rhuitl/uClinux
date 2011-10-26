/*
 * $Id: pam_modutil_cleanup.c,v 1.1 2005/09/21 10:00:58 t8m Exp $
 *
 * This function provides a common pam_set_data() friendly version of free().
 */

#include "pam_modutil_private.h"

#include <stdlib.h>

void
pam_modutil_cleanup (pam_handle_t *pamh UNUSED, void *data,
		     int error_status UNUSED)
{
    if (data) {
	/* junk it */
	(void) free(data);
    }
}
