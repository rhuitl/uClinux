#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <asm/uCbootstrap.h>

_bsc1(int,reset,int,a)

main(int argc, char *argv[])
{
	reset(PGM_RESET_AFTER);
	/* not reached, PGM_RESET_AFTER drops into the bootloader */
}
