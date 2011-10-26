/* serial.c:
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *                     The Silver Hammer Group, Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <dirent.h>
#include <errno.h>
#include <termios.h>
#include <fcntl.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <termios.h>
#include <signal.h>
#include <sys/time.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <serial.h>

#ifdef IPSERVER
#include <asm/shglcore.h>
#endif

#ifdef L_makerawtty
void make_raw_tty(struct termios * tty)
{
	int i;
	for(i=0;i<NCCS;i++)
		tty->c_cc[i] = '\0';
	tty->c_cc[VMIN] = 1;
	tty->c_cc[VTIME] = 0;
	tty->c_iflag = (IGNBRK | IGNPAR);
	tty->c_oflag = 0;
	tty->c_lflag = 0;
	tty->c_cflag |= CS8;
}
#endif

#ifdef L_makecookedtty

#define INIT_C_CC "\003\034\177\025\004\0\1\0\021\023\032\0\022\017\027\026\0"

void make_cooked_tty(struct termios * tty)
{
	int i;
	memcpy(tty->c_cc, INIT_C_CC, NCCS);
	tty->c_cc[VERASE] = '\x08';
	tty->c_iflag = ICRNL | IXON;
	tty->c_oflag = OPOST | ONLCR;
	tty->c_lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN;
}
#endif

#ifdef L_setserial
int setserial(int fd, const char * string)
{
	char buf[10];
	const char * pos = string;
	int rs485=0;
	struct termios tc;
	
	tcgetattr(fd, &tc);
	
	while (pos && *pos) {
		const char * comma = strchr(pos, ',');
		int len;
		
		if (comma == 0)
			len = strlen(pos);
		else
			len = comma-pos;
			
		if ((len<0) || (len>9))
			return -1;
			
		strncpy(buf, pos, len);
		buf[len] = 0;
		
		if (isdigit(*buf)) {
			int i = atoi(buf);
			switch (i) {
			case 1:
				tc.c_cflag &= ~CSTOPB;
				break;
			case 2:
				tc.c_cflag |= CSTOPB;
				break;
			case 5:
				tc.c_cflag = (tc.c_cflag & ~CSIZE) | CS5;
				break;
			case 6:
				tc.c_cflag = (tc.c_cflag & ~CSIZE) | CS6;
				break;
			case 7:
				tc.c_cflag = (tc.c_cflag & ~CSIZE) | CS7;
				break;
			case 8:
				tc.c_cflag = (tc.c_cflag & ~CSIZE) | CS8;
				break;
			case 300:
				cfsetospeed(&tc, B300);
				break;
			case 1200:
				cfsetospeed(&tc, B1200);
				break;
			case 2400:
				cfsetospeed(&tc, B2400);
				break;
			case 4800:
				cfsetospeed(&tc, B4800);
				break;
			case 9600:
				cfsetospeed(&tc, B9600);
				break;
			case 14400:
			case 19200:
				cfsetospeed(&tc, B19200);
				break;
			case 28800:
			case 38400:
				cfsetospeed(&tc, B38400);
				break;
			case 57600:
				cfsetospeed(&tc, B57600);
				break;
			
			case 424:
			case 485:
				rs485=1;
				break;

			case 232:
				rs485=-1;
				break;
			
			default:
				return -1;
			}
		} else 
		switch (tolower(*buf)) {
		case 'n': 
			tc.c_cflag &= ~PARENB;
			break;
		case 'e':
			tc.c_cflag |= PARENB;
			tc.c_cflag &= ~PARODD;
			break;
		case 'o':
			tc.c_cflag |= PARENB;
			tc.c_cflag |= PARODD;
			break;
		case 'm':
			tc.c_cflag &= ~CLOCAL;
#ifdef CBLOCKR
			tc.c_cflag |= CBLOCKR; /* Don't read from port unless CD is high */
#endif
			break;
		case 'l':
			tc.c_cflag |= CLOCAL;
			break;
		case 'h':
			switch (tolower(buf[1])) {
			case 'n':
				tc.c_cflag &= ~CRTSCTS;
				tc.c_iflag &= ~(IXON|IXOFF|IXANY);
				break;
			case 'b':
				tc.c_cflag |= CRTSCTS;
				tc.c_iflag |= IXON|IXOFF|IXANY;
				break;
			case 's':
				tc.c_cflag &= ~CRTSCTS;
				tc.c_iflag |= IXON|IXOFF|IXANY;
				break;
			case 'h':
				tc.c_cflag |= CRTSCTS;
				tc.c_iflag &= ~(IXON|IXOFF|IXANY);
				break;
			default:
				return -1;
			}
			break;
		default:
			return -1;
		}

		if (!comma)
			break;
		else
			pos = comma+1;
	}
	
#ifdef CAUTORTS
	if (rs485 == 1) {
		tc.c_cflag &= ~(CRTSCTS);	/* This flag is contraindicated for 485 */
		tc.c_cflag |= CLOCAL;		/* This flag is mandatory for 485 */
		
		tc.c_cflag |= CAUTORTS; 
	} else if (rs485 == -1) {
		tc.c_cflag &= ~(CAUTORTS);
	}
#endif
	
	tcsetattr(fd, TCSANOW, &tc);

	return 0;
}
#endif

#ifdef L_getserialp
int getserialparams(int fd, int * baud, char * parity, int * dbits, int * sbits, char * modem, char * hs)
{
	struct termios tc;
	
	tcgetattr(fd, &tc);
	
	if (baud)
		*baud = tcspeed_to_number(cfgetospeed(&tc));
	
	if (dbits)  {
		switch (tc.c_cflag & CSIZE) {
		case CS5:	*dbits = 5;
				break;
		case CS6:	*dbits = 6;
				break;
		case CS7:	*dbits = 7;
				break;
		case CS8:	*dbits = 8;
				break;
		}
	}
	
	if (sbits) {
		*sbits = (tc.c_cflag & CSTOPB) ? 2 : 1;
	}
	
	if (parity) {
		*parity = (tc.c_cflag & PARENB) 
			? (tc.c_cflag & PARODD)
				? 	'O'
				:	'E'
			:  'N';
	}
	
	if (modem) {
		*modem = (tc.c_cflag & CLOCAL) ? 'L' : 'M';
	}

	if (hs) {
		int hw,sw;
		
		hw = (tc.c_cflag & CRTSCTS);
		sw = (tc.c_iflag & (IXON|IXOFF|IXANY));
		
		if (hw && sw)
			*hs = 'B';
		else if (sw)
			*hs = 'S';
		else if (hw)
			*hs = 'H';
		else
			*hs = 'N';
	}
	
	return 0;
}
#endif

#ifdef L_setserialp
int setserialparams(int fd, int * baud, char * parity, int * dbits, int * sbits, char * modem, char * hs)
{
	struct termios tc;
	
	tcgetattr(fd, &tc);
	
	if (baud)
		cfsetospeed(&tc, tcspeed_from_number(*baud));
	
	if (dbits)  {
		tc.c_cflag &= ~CSIZE;
		switch (tc.c_cflag & CSIZE) {
		case 5:	tc.c_cflag |= CS5;
			break;
		case 6:	tc.c_cflag |= CS6;
			break;
		case 7:	tc.c_cflag |= CS7;
			break;
		case 8:	tc.c_cflag |= CS8;
			break;
		}
	}
	
	if (sbits) {
		if (*sbits == 2)
			tc.c_cflag |= CSTOPB;
		else
			tc.c_cflag &= ~CSTOPB;
	}
	
	if (parity) {
		tc.c_cflag &= ~(PARENB|PARODD);
		switch (toupper(*parity)) {
		case 'N':	break;
		case 'E':	tc.c_cflag |= PARENB;
				break;
		case 'O':	tc.c_cflag |= PARENB|PARODD;
				break;
		}
	}
	
	if (modem) {
		if (toupper(*modem) == 'L')
			tc.c_cflag |= CLOCAL;
		else
			tc.c_cflag &= ~CLOCAL;
	}

	if (hs) {
	}
	
	return 0;
}
#endif


#ifdef L_tcspeed
static struct {
        int number;
        speed_t code;
} tcspeeds[] = {
#ifdef B50
        {50, B50},
#endif
#ifdef B75
        {75, B75},
#endif
#ifdef B110
        {110, B110},
#endif
#ifdef B134
        {134, B134},
#endif
#ifdef B150
        {150, B150},
#endif
#ifdef B200
        {200, B200},
#endif
#ifdef B300
        {300, B300},
#endif
#ifdef B600
        {600, B600},
#endif
#ifdef B1200
        {1200, B1200},
#endif
#ifdef B1800
        {1800, B1800},
#endif
#ifdef B2400
        {2400, B2400},
#endif
#ifdef B4800
        {4800, B4800},
#endif
#ifdef B9600
        {9600, B9600},
#endif
#ifdef B19200
        {19200, B19200},
#endif
#ifdef B38400
        {38400, B38400},
#endif
#ifdef B57600
        {57600, B57600},
#endif
#ifdef B115200
        {115200, B115200},
#endif
#ifdef B230400
        {230400, B230400},
#endif
#ifdef B460800
        {460800, B460800},
#endif
#ifdef B0
        {0, B0},
#endif
        {0, 0}
};

int tcspeed_to_number(code)
speed_t code;
{
    int i;
    code &= CBAUD;
    for(i=0;tcspeeds[i].code;i++)
        if (tcspeeds[i].code == code)
          return tcspeeds[i].number;
    return 0;
}

speed_t tcspeed_from_number(number)
int number;
{
    int i;
    for(i=0;tcspeeds[i].code;i++)
        if (tcspeeds[i].number == number)
          return tcspeeds[i].code;
    return B0;
}
#endif

#ifdef L_cfgetospeedn
int cfgetospeedn(tp)
struct termios *tp;
{
    return tcspeed_to_number(cfgetospeed(tp));
}
#endif

#ifdef L_cfgetispeedn
int cfgetispeedn(tp)
struct termios *tp;
{
    return tcspeed_to_number(cfgetispeed(tp));
}
#endif

#ifdef L_cfsetospeedn
int cfsetospeedn(tp, speed)
struct termios *tp; int speed;
{
    return cfsetospeed(tp, tcspeed_from_number(speed));
}
#endif

#ifdef L_cfsetispeedn
int cfsetispeedn(tp, speed)
struct termios *tp; int speed;
{
    return cfsetispeedn(tp, tcspeed_from_number(speed));
}
#endif

#ifdef L_readall
size_t readall(int fd, void * buf, size_t count, struct timeval * timeout)
{
	size_t total = 0;
	while (total < count) {
		int partial;
		
		if (timeout) {
			fd_set rfds;
			FD_ZERO(&rfds);
			FD_SET(fd, &rfds);
			partial = select(fd+1, &rfds, 0, 0, timeout);
			
			if (partial < 0)
				return -1;
			else if (partial == 0) {
				errno = ETIME;
				return -1;
			}
		}
		
		partial = read(fd, ((char*)buf) + total, count - total);
		if (partial <= 0)
			return partial;
		total += partial;
	}
	return total;
}
#endif

#ifdef L_readaline
size_t readaline(int fd, char * buf, size_t count, struct timeval * timeout)
{
	size_t total = 0;
	while (total < count) {
		int partial;
		
		if (timeout) {
			fd_set rfds;
			FD_ZERO(&rfds);
			FD_SET(fd, &rfds);
			partial = select(fd+1, &rfds, 0, 0, timeout);
			
			if (partial < 0)
				return -1;
			else if (partial == 0) {
				errno = ETIME;
				return -1;
			}
		}
		
		partial = read(fd, buf + total, 1);
		if (partial <= 0)
			return partial;

		if (buf[total] == '\n')
			break;

		total += partial;
		
	}
	if ((total>0) && (buf[total-1] == '\r'))
		total--;
	buf[total] = '\0';
	return total;
}
#endif

#ifdef L_writeall
size_t writeall(int fd, void * buf, size_t count, struct timeval * timeout)
{
	size_t total = 0;
	while (total < count) {
		int partial;
		
		if (timeout) {
			fd_set wfds;
			FD_ZERO(&wfds);
			FD_SET(fd, &wfds);
			partial = select(fd+1, 0, &wfds, 0, timeout);
			
			if (partial < 0)
				return -1;
			else if (partial == 0) {
				errno = ETIME;
				return -1;
			}
		}
		
		partial = write(fd, ((char*)buf) + total, count - total);
		if (partial <= 0)
			return partial;
		total += partial;
	}
	return total;
}
#endif

#ifdef L_hexdump
void printf_hexdump(unsigned char * buffer, int length, unsigned long pos)
{
	FILE	*fp;
	int	count;
	int	c;
	char	text[17];
	unsigned char	buf[130];

	c = 0;
	
	text[16] = 0;
	
	strcpy(text, "                ");
	
	while (c < (pos & 0xf)) {
	   if (c == 0)
	     printf("%4X:", pos & 0xfffffff0);
	  printf( (c == 8) ? "-  " : "   ");
	  text[c] = ' ';
	  c++;
	}
	
	  {
	    int p = 0;

            while (length > 0) {
              c = (pos & 0xf);
            
              if (c == 0)
                printf("%4X:", pos & 0xfffffff0);
              
              if ((*buffer < 32) || (*buffer>126))
                text[c] = '.';
              else
                text[c] = *buffer;
            
	      printf( (c==15) ? " %02.2X" : (c == 8) ? "-%02.2X" : " %02.2X", *buffer);
	      
	      if (c == 15)
	        printf(" %s\n", text);
	    
              pos++;
              p++;
              
              buffer++;
              length--;
            }
	  }
	  
	  if (c = (pos & 0x0f)) {

	    while (c < 16) {
	      printf( (c == 8) ? "-  " : "   ");
	      text[c] = ' ';
	      c++;
	    }
	  
	    printf(" %s\n", text);
	  }
	    
}
#endif

#ifdef L_id485
int identify_485(int fd)
{
	int orig, i, v, result;
	
	struct { int set, result; } test[] = {
		{ 0, 0 },
		{ TIOCM_RTS, TIOCM_CD },
		{ TIOCM_DTR, 0 },
		{ TIOCM_RTS|TIOCM_DTR, TIOCM_CD }
	};
	
	if (ioctl(fd, TIOCMGET, &orig)==-1)
		return -1;

	result = 1;
	for(i=0;i<(sizeof(test)/sizeof(test[0]));i++) {
		v = test[i].set;
		if (ioctl(fd, TIOCMSET, &v)==-1) {
			result = -1;
			goto done;
		}
		if (ioctl(fd, TIOCMGET, &v)==-1) {
			result = -1;
			goto done;
		}
		if ((v & TIOCM_CD) != test[i].result) {
			result = 0;
			break;
		}
	}

done:
	ioctl(fd, TIOCMSET, &orig);
	
	if (result == 1) {
		struct termios t;
		tcgetattr(fd, &t);
#ifdef IPSERVER
		t.c_cflag |= CAUTORTS;
#endif		
		tcsetattr(fd, TCSANOW, &t);
	}
	
	return result;
}
#endif

#ifdef L_commstatus
void commstatus(int error)
{
#ifdef IPSERVER
	SHGLCORE_LATCH_BIT(SHGLCORE_LATCH_ERROR_LED) = error ? 1 : 0;
#endif
}
#endif

#ifdef L_alarmstatus
void alarmstatus(int alarm)
{
#ifdef IPSERVER
	SHGLCORE_LATCH_BIT(SHGLCORE_LATCH_ALARM_LED) = alarm ? 1 : 0;
	SHGLCORE_LATCH_BIT(SHGLCORE_LATCH_RELAY_1) = alarm ? 1 : 0;
#endif
}
#endif
