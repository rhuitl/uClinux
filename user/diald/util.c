
#include "diald.h"

/*
 *      On some embedded systems we don't have a full shell, just call
 *      program directly (obviously it can't be a sh script!).
 */

char _argvbuf[256];

int execuc(char *buf)
{
        char	*argv[32], *sp;
        int    	argc = 0, prevspace = 1;

	strcpy(_argvbuf, buf);
        for (sp = (char *) _argvbuf; (*sp != 0); ) {
                if (prevspace && !isspace(*sp)) {
			/* FIX: should check we don't blow 32 argv's */
                        argv[argc++] = sp;
		}
                if ((prevspace = isspace(*sp)))
                        *sp = 0;
                sp++;
        }
        argv[argc] = 0;

	return(execv(argv[0], argv));
}

