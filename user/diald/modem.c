/*
 * modem.c - Modem control functions.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 *
 * Portions of this code were derived from the code for pppd copyright
 * (c) 1989 Carnegie Mellon University. The copyright notice on this code
 * is reproduced below.
 *
 * Copyright (c) 1989 Carnegie Mellon University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Carnegie Mellon University.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "diald.h"

static char *current_dev = 0;
static int rotate_offset = 0;

/* local variables */

static struct termios inittermios;      /* Initial TTY termios */
static int restore_term = 0;
int pgrpid;

#if B9600 == 9600
/*
 * XXX assume speed_t values numerically equal bits per second
 * (so we can ask for any speed).
 */
#define translate_speed(bps)	(bps)

#else
/*
 * List of valid speeds.
 */
struct speed {
    int speed_int, speed_val;
} speeds[] = {
#ifdef B50
    { 50, B50 },
#endif
#ifdef B75
    { 75, B75 },
#endif
#ifdef B110
    { 110, B110 },
#endif
#ifdef B134
    { 134, B134 },
#endif
#ifdef B150
    { 150, B150 },
#endif
#ifdef B200
    { 200, B200 },
#endif
#ifdef B300
    { 300, B300 },
#endif
#ifdef B600
    { 600, B600 },
#endif
#ifdef B1200
    { 1200, B1200 },
#endif
#ifdef B1800
    { 1800, B1800 },
#endif
#ifdef B2000
    { 2000, B2000 },
#endif
#ifdef B2400
    { 2400, B2400 },
#endif
#ifdef B3600
    { 3600, B3600 },
#endif
#ifdef B4800
    { 4800, B4800 },
#endif
#ifdef B7200
    { 7200, B7200 },
#endif
#ifdef B9600
    { 9600, B9600 },
#endif
#ifdef B19200
    { 19200, B19200 },
#endif
#ifdef B38400
    { 38400, B38400 },
#endif
#ifdef EXTA
    { 19200, EXTA },
#endif
#ifdef EXTB
    { 38400, EXTB },
#endif
#ifdef B57600
    { 57600, B57600 },
#endif
#ifdef B115200
    { 115200, B115200 },
#endif
#ifdef B230400
    { 230400, B230400 },
#endif
    { 0, 0 }
};

/*
 * Translate from bits/second to a speed_t.
 */
int translate_speed(int bps)
{
    struct speed *speedp;

    if (bps == 0)
	return 0;
    for (speedp = speeds; speedp->speed_int; speedp++)
	if (bps == speedp->speed_int)
	    return speedp->speed_val;
    syslog(LOG_WARNING, "speed %d not supported", bps);
    return 0;
}
#endif

/*
 * set_up_tty: Set up the serial port on `fd' for 8 bits, no parity,
 * at the requested speed, etc.  If `local' is true, set CLOCAL
 * regardless of whether the modem option was specified.
 */
void set_up_tty(int fd, int local, int spd)
{
    int speed, i;
    struct termios tios;

    if (tcgetattr(fd, &tios) < 0) {
	syslog(LOG_ERR, "could not get initial terminal attributes: %m");
    }

    tios.c_cflag = CS8 | CREAD | HUPCL;
    if (local || !modem) tios.c_cflag |= CLOCAL;
    if (crtscts == 1) tios.c_cflag |= CRTSCTS;
    tios.c_iflag = IGNBRK | IGNPAR;
    tios.c_oflag = 0;
    tios.c_lflag = 0;
    for (i = 0; i < NCCS; i++)
	tios.c_cc[i] = 0;
    tios.c_cc[VMIN] = 1;
    tios.c_cc[VTIME] = 0;

    speed = translate_speed(spd);
    if (speed) {
	cfsetospeed(&tios, speed);
	cfsetispeed(&tios, speed);
    } else {
	speed = cfgetospeed(&tios);
    }

    if (tcsetattr(fd, TCSAFLUSH, &tios) < 0) {
	syslog(LOG_ERR, "failed to set terminal attributes: %m");
    }
}

/*
 * setdtr - control the DTR line on the serial port.
 * This is called from die(), so it shouldn't call die().
 */
void setdtr(int fd, int on)
{
    int modembits = TIOCM_DTR;

    ioctl(fd, (on? TIOCMBIS: TIOCMBIC), &modembits);
}


/*
 * fork_dialer - run a program to connect the serial device.
 */
void fork_dialer(char *program, int fd)
{
    int pid;

    block_signals();
#ifdef __uClinux__
    syslog(LOG_NOTICE, "running dialer \"%s\"", program);
    pid = dial_pid = vfork();
#else
    pid = dial_pid = fork();
#endif

    if (pid != 0)
      unblock_signals();

    if (pid < 0) {
        syslog(LOG_ERR, "failed to fork dialer: %m");
	/* FIXME: Probably this should not be fatal */
        die(1);
    }

    if (pid == 0) {
        /* change the signal actions back to the defaults, then unblock them. */
        default_sigacts();
	unblock_signals();

        /* make sure the child doesn't inherit any extra file descriptors */
	close(proxy_mfd);      /* close the master pty endpoint */
	close(proxy_sfd);      /* close the slave pty endpoint */
	if (fifo_fd != -1) close(fifo_fd);
	if (monitors) {
	    MONITORS *c = monitors;
	    while (c) {
	    	close(c->fd);
		c = c->next;
	    }
	}

	/* make sure the stdin and stdout get directed to the modem */
        if (fd != 0) { dup2(fd, 0); close(fd); }
        dup2(0, 1);
	/* FIXME: direct the stderr to the console? */
        dup2(0, 2);

#ifndef __uClinux__
	setenv("MODEM",current_dev,1);	/* set the current device */
	if (fifoname)		/* set the current command FIFO (if any) */
	    setenv("FIFO",fifoname,1);
#endif
#ifdef EMBED
        execuc(program);
        syslog(LOG_ERR, "could not exec dialer: errno=%d", errno);
#else
        execl("/bin/sh", "sh", "-c", program, (char *)0);
        syslog(LOG_ERR, "could not exec /bin/sh: %m");
#endif
        _exit(127);
        /* NOTREACHED */
    }
    syslog(LOG_INFO,"Running connect (pid = %d).",dial_pid);
}

/*
 * Open up a modem and set up the desired parameters.
 */
int open_modem()
{
    int npgrpid;
    int i;
    /*
     * Open the serial device and set it up.
     */

    modem_hup = 0;
    modem_fd = -1;
    dial_status = 0;

    if (mode == MODE_DEV) return 0;

    if (req_pid) {
	/* The user has specified a device. Use it, no search or lock needed. */
	if ((modem_fd = open(req_dev, O_RDWR | O_NDELAY)) < 0) {
	    syslog(LOG_ERR,"Can't open requested device '%s'",req_dev);
	    killpg(req_pid,SIGKILL);
	    kill(req_pid,SIGKILL);
	    req_pid = 0;
	    dial_status = -1;
	    return 1;
	}
	current_dev = req_dev;
	use_req=1;
    } else {
	for (i = 0; i < device_count; i++) {
	    current_dev = devices[(i+rotate_offset)%device_count];
	    /*
	     * March down the device list till we manage to open one up or
	     * we run out of devices to try.
	     */

	    if (lock_dev && lock(current_dev) < 0)
		continue;

	    /* OK. Locked one, try to open it */
	    if ((modem_fd = open(current_dev, O_RDWR | O_NDELAY)) >= 0)
		break;
	    else {
	       syslog(LOG_ERR,"Error opening device %s: %m",current_dev);
	    }
	    current_dev = 0;

	    /* That didn't work, get rid of the lock */
	    if (lock_dev) unlock();
	}
	if (modem_fd < 0) {
	    syslog(LOG_INFO,"Couldn't find a free device to call out on.");
	    dial_status = -1;
	    return 2;
	}
    }

    if (rotate_devices)
    	rotate_offset = (rotate_offset+1)%device_count;

    /* Make sure we are the session leader */
    if ((npgrpid = setsid()) >= 0)
	pgrpid = npgrpid;

    /* set device to be controlling tty */
    /* This should only happen in SLIP mode */
    if (mode == MODE_SLIP) {
	if (ioctl(modem_fd, TIOCSCTTY, 1) < 0) {
	    syslog(LOG_ERR, "failed to set modem to controlling tty: %m");
	    die(1);
	}

        if (tcsetpgrp(modem_fd, pgrpid) < 0) {
	    syslog(LOG_ERR, "failed to set process group: %m");
	    die(1);
	}
    }

    /* Get rid of any initial line noise */
    tcflush(modem_fd, TCIOFLUSH);

    if (tcgetattr(modem_fd, &inittermios) < 0) {
	syslog(LOG_ERR, "failed to get initial modem terminal attributes: %m");
    }

    /* So we don't try to restore if we die before this */
    restore_term = 1;

    /* Clear the NDELAY flag now */
    if (fcntl(modem_fd,F_SETFL,fcntl(modem_fd,F_GETFL)&~(O_NDELAY)) < 0)
	syslog(LOG_ERR, "failed to clear O_NDELAY flag: %m"), die(1);

    if (!req_pid) {
	/* hang up and then start again */
	set_up_tty(modem_fd, 1, 0);
	sleep(1);
	set_up_tty(modem_fd, 1, inspeed);

	/* Get rid of any initial line noise after the hangup */
	tcflush(modem_fd, TCIOFLUSH);
	fork_dialer(connector, modem_fd);
    } else {
	/* someone else opened the line, we just set the mode */
	set_up_tty(modem_fd, 0, inspeed);
    }
    return 0;
}

/*
 * Reopen up a modem that closed on a sighup and set up the desired parameters.
 */
void reopen_modem()
{
    int npgrpid;

    if(debug&DEBUG_VERBOSE)
	syslog(LOG_INFO,"Reopening modem device");

    close(modem_fd);
    sleep(1);
    if ((modem_fd = open(current_dev, O_RDWR | O_NDELAY)) < 0) {
	syslog(LOG_ERR,"Can't reopen device '%s'",current_dev);
    } else {
	/* Make sure we are the session leader */
	if ((npgrpid = setsid()) >= 0)
	    pgrpid = npgrpid;

	/* set device to be controlling tty */
	/* This should only happen in SLIP mode */
	if (mode == MODE_SLIP) {
	    if (ioctl(modem_fd, TIOCSCTTY, 1) < 0) {
		syslog(LOG_ERR, "failed to set modem to controlling tty: %m");
		die(1);
	    }

	    if (tcsetpgrp(modem_fd, pgrpid) < 0) {
		syslog(LOG_ERR, "failed to set process group: %m");
		die(1);
	    }
	}

	set_up_tty(modem_fd, 1, inspeed);
	/* Clear the NDELAY flag now */
	if (fcntl(modem_fd,F_SETFL,fcntl(modem_fd,F_GETFL)&~(O_NDELAY)) < 0)
	    syslog(LOG_ERR, "failed to clear O_NDELAY flag: %m"), die(1);
    }
}

void finish_dial()
{
    if (!req_pid)
        set_up_tty(modem_fd, 0, inspeed);
}

/*
 * Close the modem, making sure it hangs up properly!
 */
void close_modem()
{
    if (mode == MODE_DEV) {
	req_pid = 0;
	modem_fd = -1 ;
	return ;
    }

    if (debug&DEBUG_VERBOSE)
        syslog(LOG_INFO,"Closing modem line.");

    if (modem_fd < 0) {
 	return;
    }

    /* Get rid of what ever might be waiting to go out still */
    tcflush(modem_fd, TCIOFLUSH);

    /*
     * Restore the initial termio settings.
     */

    if (restore_term) {
	tcsetattr(modem_fd, TCSANOW, &inittermios);
    }

    /*
     * Hang up the modem up by dropping the DTR.
     * We do this because the initial termio settings
     * may not have set HUPCL. This forces the issue.
     * We need the sleep to give the modem a chance to hang
     * up before we get another program asserting the DTR.
     */
    setdtr(modem_fd, 0);
    sleep(1);

    close(modem_fd);
    if (req_pid) {
	if (debug&DEBUG_VERBOSE)
	    syslog(LOG_INFO, "Killing requesting shell pid %d",req_pid);
	killpg(req_pid, SIGKILL);
	kill(req_pid, SIGKILL);
	req_pid = 0;
    } else if (lock_dev) unlock();
    modem_fd = -1;
}
