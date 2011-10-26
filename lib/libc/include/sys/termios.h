#ifndef _SYS_TERMIOS_H
#define _SYS_TERMIOS_H
#include <termios.h>

#ifndef N_TTY
/* line disciplines */
#define N_TTY		0
#define N_SLIP		1
#define N_MOUSE		2
#define N_PPP		3
#define N_STRIP		4
#define N_AX25		5
#define N_X25		6	/* X.25 async  */
#define N_6PACK		7
#define N_MASC		8	/* Mobitex module  */
#define N_R3964		9	/* Simatic R3964 module  */
#define N_PROFIBUS_FDL	10	/* Profibus  */
#define N_IRDA		11	/* Linux IR  */
#define N_SMSBLOCK	12	/* SMS block mode  */
#define N_HDLC		13	/* synchronous HDLC  */
#define N_SYNC_PPP	14	/* synchronous PPP  */
#define	N_HCI		15	/* Bluetooth HCI UART  */
#endif

#endif
