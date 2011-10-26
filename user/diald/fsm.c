/*
 * fsm.c - Control Finite State Machine for diald main loop.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include "diald.h"

#define STATE(name,timeout,tstate) \
        { timeout, act_ ## name, trans_ ## name, STATE_ ## tstate, #name }

/* Protocol control structure */
struct {
	void (*start)();
	int (*set_addrs)();
	int (*dead)();
	void (*stop)();
	void (*reroute)();
	void (*kill)();
	void (*zombie)();
} pcontrol[3] = {
    {slip_start,slip_set_addrs,slip_dead,slip_stop,slip_reroute,slip_kill,slip_zombie},
    {ppp_start,ppp_set_addrs,ppp_dead,ppp_stop,ppp_reroute,ppp_kill,ppp_zombie},
    {dev_start,dev_set_addrs,dev_dead,dev_stop,dev_reroute,dev_kill,dev_zombie},
};


int blocked = 0;		/* user has blocked the link */
int state = STATE_DOWN;		/* DFA state */
int current_retry_count = 0;	/* current retry count */
int no_redial_delay = 0;

void GOTO(int);

/*
 * Actions and transition rules for the FSM.
 */

void act_DOWN(void)
{
    current_retry_count = retry_count;
}
void trans_DOWN(void)
{
    request_down = 0;
    use_req = 0;
    if (request_up && !blocked) {request_up = 0; GOTO(STATE_CONNECT);}
    else if ((forced || !queue_empty()) && !blocked) GOTO(STATE_CONNECT);
    else if (delayed_quit && queue_empty() && !forced) {
	syslog(LOG_INFO,"Carrying out delayed termination request.");
	terminate = 1;
    }
}

/* Grumble. Attempt to generate a nicely formatted ascii date without
 * a built in newline.
 */
char *cdate(void)
{
    static char dt[128];
    int len;

    time((time_t *)&call_start_time);
#ifdef EMBED
    len = 0;
#else
    len = strftime(dt,128,"%c %Z",localtime((time_t *)&call_start_time));
#endif
    if (len == 128) dt[len] = 0;
    return dt;
}

void act_CONNECT(void)
{
    if (acctlog && (acctfp = fopen(acctlog,"a")) != NULL) {
	    fprintf(acctfp,"%s: Calling site %s.\n",
	    cdate(), remote_ip);
	    fclose(acctfp);
    }
    txtotal = rxtotal = 0;
    dial_status = 0;
    force_dynamic = 0;
    no_redial_delay = 0;
    if (open_modem() == 2)
	no_redial_delay = 2;
}
void trans_CONNECT(void)
{
    if (dial_pid == 0) {
	if (dial_status == 0) {
	    dial_failures = 0;
	    redial_rtimeout = redial_timeout;
	    if (mode != MODE_DEV)
	        finish_dial(); /* go into a CLOCAL connection */
	    GOTO(STATE_START_LINK);
	} else {
	    syslog(LOG_INFO,"Connect script failed.");
	    dial_failures++;
	    if (redial_rtimeout == -1) redial_rtimeout = redial_timeout;
	    if (redial_backoff_start >= 0 && dial_failures > redial_backoff_start) {
		redial_rtimeout *= 2;
		if (redial_rtimeout > redial_backoff_limit)
		    redial_rtimeout = redial_backoff_limit;
	    }
	    if (dial_fail_limit != 0 && dial_failures > dial_fail_limit) {
		/* want to block connection until the user comes back...*/
		blocked = 1;
		dial_failures = 0;
		redial_rtimeout = redial_timeout;
		current_retry_count = 0;
		syslog(LOG_INFO,"Too many dialing failures in a row. Blocking connection.");
	    }
	    GOTO(STATE_CLOSE);
	}
    } else if (state_timeout == 0) {
	syslog(LOG_INFO,"Connect script timed out. Killing script.");
    } else if (req_pid && !use_req) {
        /* we never get here on a connect FIFO request anyway */
        syslog(LOG_INFO,"Cancelling connect script in favour of FIFO request.");
	GOTO(STATE_STOP_DIAL);
    }
}

void act_STOP_DIAL(void)
{
    if (dial_pid) {
        if (debug&DEBUG_VERBOSE)
            syslog(LOG_INFO,"Sending SIGINT to (dis)connect process %d",
		dial_pid);
	if (kill(dial_pid,SIGINT) == -1 && errno == ESRCH) {
	    dial_pid = 0;
	    dial_status = -1;
	}
    }
}
void trans_STOP_DIAL(void)
{
    if (dial_pid == 0) GOTO(STATE_CLOSE);
}


void act_KILL_DIAL(void)
{
    if (dial_pid) {
        if (debug&DEBUG_VERBOSE)
            syslog(LOG_INFO,"Sending SIGKILL to (dis)connect process %d",
		dial_pid);
	if (kill(dial_pid,SIGKILL) == -1 && errno == ESRCH) {
	    dial_pid = 0;
	    dial_status = -1;
	}
    }
}
void trans_KILL_DIAL(void)
{
    if (dial_pid == 0) GOTO(STATE_CLOSE);
}

void act_START_LINK(void)
{
    if (acctlog && (acctfp = fopen(acctlog,"a")) != NULL) {
        fprintf(acctfp,"%s: Connected to site %s.\n",
	    cdate(), remote_ip);
	fclose(acctfp);
    }
    (*pcontrol[mode].start)();
}
void trans_START_LINK(void)
{
    if ((*pcontrol[mode].dead)()) {
	/* link protocol died before we really got going */
	/* We must reroute, just in case we got so far as to change routing */
   	(*pcontrol[mode].reroute)();
	GOTO(STATE_DISCONNECT);
    } else if ((*pcontrol[mode].set_addrs)()) {
	/* Ok, we're up and running. */
	GOTO(STATE_UP);
    }

    /* If we fall through then we haven't finished the setup yet. */
    if (state_timeout == 0) {
	/* If we time out, then we're going to stop. We need to reroute
         *  just in case the routes got changed before we timed out.
	 */
	syslog(LOG_INFO,"pppd startup timed out. Check your pppd options. Killing pppd.");
	(*pcontrol[mode].reroute)();
    }
}

void act_STOP_LINK(void)
{
    (*pcontrol[mode].stop)();
}
void trans_STOP_LINK(void)
{
    if ((*pcontrol[mode].dead)()) GOTO(STATE_DISCONNECT);
}

void act_KILL_LINK(void)
{
    (*pcontrol[mode].kill)();
}
void trans_KILL_LINK(void)
{
    if ((*pcontrol[mode].dead)()) GOTO(STATE_DISCONNECT);
}

void act_UP(void)
{
    idle_filter_init();
    flush_timeout_queue();
    interface_up();
    ppp_half_dead = 0;
    if (buffer_packets)
   	 forward_buffer();
    /* Once we get here, we might as well kill off any outstanding
     * FIFO requests */
    if (!use_req && req_pid) {
        killpg(req_pid, SIGKILL);
        kill(req_pid, SIGKILL);
	req_pid=0;
        syslog(LOG_INFO,"Cancelling link up requested denied in favour of existing link.");
    }
}

void trans_UP(void)
{
    request_up = 0;
    if (blocked || request_down) {
	request_down = 0;
	goto take_link_down;
    }
    if (state_timeout == 0) {
	if (!forced && queue_empty()) {  /* the link may be forced up. */
	    syslog(LOG_INFO,"%s %d %s",
	    	"Failed to received first packet within",
	    	first_packet_timeout,
	    	"seconds. Closing Link down.");
	    goto take_link_down;
	}
	state_timeout = -1;
    }
    if (!forced && queue_empty() && state_timeout == -1) {
	syslog(LOG_INFO,"Closing down idle link.");
take_link_down:
	current_retry_count = 0;
	flush_timeout_queue();
	/* WARNING: You MUST do this before calling idle_filter_proxy(),
           or the snoop socket will not bind properly! */
   	(*pcontrol[mode].reroute)();
	idle_filter_proxy();
	GOTO(STATE_STOP_LINK);
	return;
    }
    if (ppp_half_dead) {
	syslog(LOG_ERR,"PPP network layer died, but link did not. Probable configuration error.");
	GOTO(STATE_HALF_DEAD);
	return;
    }
    if ((*pcontrol[mode].dead)() || modem_hup) {
	syslog(LOG_INFO,"Link died on remote end.");
    	if (two_way) flush_timeout_queue();
	no_redial_delay = 1;
	current_retry_count = died_retry_count;
	/* WARNING: You MUST do this before calling idle_filter_proxy(),
           or the snoop socket will not bind properly! */
   	(*pcontrol[mode].reroute)();
	idle_filter_proxy();
	GOTO(STATE_DISCONNECT);
	return;
    }
}

void act_HALF_DEAD(void)
{
    /* We're half dead, make sure we monitor the correct device... */
    (*pcontrol[mode].reroute)();
    idle_filter_proxy();
}

void trans_HALF_DEAD(void)
{
    if ((*pcontrol[mode].dead)()) {
	/* link protocol died and did not come back */
   	(*pcontrol[mode].reroute)();
	GOTO(STATE_DISCONNECT);
    } else if ((*pcontrol[mode].set_addrs)()) {
	/* Ok, we're up and running. */
	GOTO(STATE_UP);
    }
    /* If we fall through then we haven't finished the setup yet. */
    if (state_timeout == 0) {
	/* If we time out, then we're going to stop. We need to reroute
         *  just in case the routes got changed before we timed out.
	 */
	syslog(LOG_INFO,"pppd restart timed out. Killing pppd.");
	(*pcontrol[mode].reroute)();
    }
}

void act_DISCONNECT(void)
{
    dial_status = 0;
    if (disconnector) {
        if (mode != MODE_DEV) {
	    reopen_modem();
            fork_dialer(disconnector, modem_fd);
	}
    }
}
void trans_DISCONNECT(void)
{
    if (dial_pid == 0) {
	if (dial_status != 0)
	    syslog(LOG_INFO,"Disconnect script failed");
	GOTO(STATE_CLOSE);
    } else if (state_timeout == 0) {
	syslog(LOG_INFO,"Disconnect script timed out. Killing script.");
    }
}

void act_CLOSE(void)
{
    if (acctlog && (acctfp = fopen(acctlog,"a")) != NULL) {
	int duration = -call_start_time;
	char *tm;
	tm = cdate();
	duration += call_start_time;
        fprintf(acctfp,"%s: Disconnected. Call duration %d seconds.\n",
	    tm,duration);
        fprintf(acctfp,"      IP transmitted %d bytes and received %d bytes.\n",
	    txtotal,rxtotal);
	fclose(acctfp);
    }
    close_modem();
    interface_down();
    if (no_redial_delay == 0) {
	if (redial_rtimeout == -1)
	    redial_rtimeout = redial_timeout;
        syslog(LOG_INFO,"Delaying %d seconds before clear to dial.",
	    redial_rtimeout);
	state_timeout = redial_rtimeout;
    } else if (no_redial_delay == 2) {
        syslog(LOG_INFO,"Delaying %d seconds before clear to dial.",
	    nodev_retry_timeout);
	state_timeout = nodev_retry_timeout;
    }
}
void trans_CLOSE(void)
{
    if (request_up) GOTO(STATE_DOWN); /* STATE_DOWN handles the link-up-request */
    if (no_redial_delay == 1) {
	no_redial_delay = 0;
	GOTO(STATE_RETRY);
    }
}

void act_RETRY(void)
{
    current_retry_count--;
}
void trans_RETRY(void)
{
	if (blocked) {
		GOTO(STATE_DOWN);
		return;
	}
    if (request_up) GOTO(STATE_DOWN);
    if (current_retry_count >= 0) GOTO(STATE_CONNECT);
    else GOTO(STATE_DOWN);
}


void act_ERROR(void)
{
    syslog(LOG_ERR,"Subprocess sent SIGKILL still alive after %d seconds. Reaping zombie.",kill_timeout);
    (*pcontrol[mode].zombie)();	/* deal with the zombie */
}
void trans_ERROR(void) {
    if ((*pcontrol[mode].dead)()) GOTO(STATE_DISCONNECT);
}

void act_ZOMBIE(void)
{
    syslog(LOG_ERR,"Subprocess sent SIGKILL still alive after %d seconds. Reaping zombie.",kill_timeout);

    sig_chld(SIGKILL);	/* try to reap the zombie */
    if (dial_pid) {
	/* If the zombie didn't get reaped, forget it exists */
	dial_pid = 0;
    	dial_status = -1;
    }
}
void trans_ZOMBIE(void) {
    if (dial_pid == 0) GOTO(STATE_CLOSE);
}

/*
 * State definitions and actions for the control DFA.
 * The routine change_state handles transitions.
 */

struct {
    int *timeout;
    void (*action)(void);
    void (*trans)(void);
    int timeout_state;
    char *name;
} trans[] = {
    STATE(DOWN ,0, DOWN),
    STATE(CONNECT, &connect_timeout, STOP_DIAL),
    STATE(STOP_DIAL, &stop_dial_timeout, KILL_DIAL),
    STATE(KILL_DIAL, &kill_timeout, ZOMBIE),
    STATE(START_LINK, &start_pppd_timeout, STOP_LINK),
    STATE(STOP_LINK, &stop_pppd_timeout, KILL_LINK),
    STATE(KILL_LINK, &kill_timeout, ERROR),
    STATE(UP, &first_packet_timeout, UP),
    STATE(DISCONNECT, &disconnect_timeout, STOP_DIAL),
    STATE(CLOSE, 0, RETRY),
    STATE(RETRY, 0, RETRY),
    STATE(ERROR, 0, ERROR),
    STATE(ZOMBIE, 0, ZOMBIE),
    STATE(HALF_DEAD, &start_pppd_timeout, STOP_LINK)
};

void output_state()
{
    if (monitors) {
	mon_write(MONITOR_STATE,"STATE\n",6);
	mon_write(MONITOR_STATE,trans[state].name,strlen(trans[state].name));
	mon_write(MONITOR_STATE,"\n",1);
    }
}

void GOTO(int new_state)
{
    state_timeout = (trans[new_state].timeout)
                     ? *trans[new_state].timeout : -1;
    if (debug&DEBUG_STATE_CONTROL)
    	syslog(LOG_DEBUG,"new state %s action %d timeout %d",
	    trans[new_state].name,(int)trans[new_state].action,state_timeout);
    state = new_state;
    output_state();
    (*trans[new_state].action)();
}

/*
 * Change the state according to the current state and events.
 */

void change_state()
{
    /* Change state from the current state if conditions warrent */
    (*trans[state].trans)();
    /* Check if the current state timed out */
    if (state_timeout == 0) GOTO(trans[state].timeout_state);
}
