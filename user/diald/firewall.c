/*
 * firewall.c - Packet filtering for diald.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include "diald.h"

static FW_unit units[FW_NRUNIT];
static int initialized = 0;
int impulse_init_time = 0;
int impulse_time = 0;
int impulse_fuzz = 0;

void del_connection(FW_Connection *);

/*
 * Initialize the units.
 */

static void init_units(void)
{
    int i;

    for (i = 0; i < FW_NRUNIT; i++) {
	units[i].used = 0;
	units[i].filters = NULL;
	units[i].last = NULL;
	units[i].connections = malloc(sizeof(FW_Connection));
	units[i].nrules = 0;
	units[i].nfilters = 0;
	if (!units[i].connections) {
	    syslog(LOG_ERR,"Out of memory! AIIEEE!");
	    die(1);
	}
	units[i].connections->next = units[i].connections->prev
	    = units[i].connections;
    }
    initialized = 1;
}

/* is the time given by "clock" in the given slot? */

static unsigned int in_slot(FW_Timeslot *slot, time_t *clock)
{
    struct tm *ltime = localtime(clock);
    int ctime = ltime->tm_hour*60*60+ltime->tm_min*60+ltime->tm_sec; 

#if 0
    syslog(LOG_INFO,"slot check: %d %d %d %d",
	ltime->tm_sec+ltime->tm_min*60+ltime->tm_hour*60*60, ltime->tm_wday,
	ltime->tm_mday, ltime->tm_mon);
#endif

    while (slot) {
#if 0
    syslog(LOG_INFO,"slot def: %d %d %x %x %x",
	slot->start, slot->end, slot->wday, slot->mday, slot->month);
#endif
	if ((slot->start <= ctime)
	&&  (ctime <= slot->end)
	&&  (slot->wday & (1<<ltime->tm_wday))
	&&  (slot->mday & (1<<(ltime->tm_mday-1)))
	&&  (slot->month & (1<<ltime->tm_mon))) {
	    return 1;
	}
	slot = slot->next;
    }

    return 0;
}


/*
 * return 0 if the given time is in the given slots active time set.
 * Otherwise return the number of seconds until the slot is next active, or
 * the number of seconds until the next occurance of 00:00 hours, whichever
 * comes first.
 */

static unsigned int slot_start_timeout(FW_Timeslot *slot, time_t *clock)
{
    struct tm *ltime = localtime(clock);
    int ctime, mintime;

    if (in_slot(slot,clock)) return 0;

    /* Ok, we are currently NOT in this slot's time range. */

    ctime = ltime->tm_hour*60*60 + ltime->tm_min*60 + ltime->tm_sec;
    mintime =  24*60*60 - ctime;

    while (slot) {
    	if ((slot->wday & (1<<ltime->tm_wday))
    	&& (slot->mday & (1<<(ltime->tm_mday-1)))
    	&& (slot->month & (1<<ltime->tm_mon))
	&& (slot->start >= ctime)) {
	    /* Ok, this slot disjunct occurs today */
	    if (mintime >= (slot->start - ctime))
		mintime = slot->start - ctime;
    	}
	slot = slot->next;
    }

    return mintime;
}

/*
 * return 0 if the given time is not in the given slots active time set.
 * Otherwise return the number of seconds until the slot times out, or
 * the number of seconds until the next occurance of 00:00 hours, whichever
 * comes first.
 */

static unsigned int slot_end_timeout(FW_Timeslot *slot, time_t *clock)
{
    struct tm *ltime = localtime(clock);
    int ctime, maxtime;

    if (!in_slot(slot,clock)) return 0;

    /* Ok, we are currently in this slot's time range. */

    ctime = ltime->tm_hour*60*60 + ltime->tm_min*60 + ltime->tm_sec;
    maxtime = -1;

    while (slot) {
    	if ((slot->wday & (1<<ltime->tm_wday))
    	&& (slot->mday & (1<<(ltime->tm_mday-1)))
    	&& (slot->month & (1<<ltime->tm_mon))
	&& (slot->start <= ctime)
	&& (ctime <= slot->end)) {
	    /* Ok, this slot disjunct is active now */
	    int t = slot->end - ctime;
	    if (maxtime <= t)
		maxtime = t;
    	}
	slot = slot->next;
    }

    if (maxtime == -1)
        return 24*60*60 - ctime;
    else
    	return maxtime;
}

/* Find a connection in the queue */
static FW_Connection *find_connection(FW_unit *unit, FW_ID *id)
{
    FW_Connection *c = unit->connections->next;

    /* look for a connection that matches this one */
    while (c != unit->connections) {
	if (memcmp((unsigned char *)&c->id,
		(unsigned char *)id,sizeof(FW_ID))==0)
	   break;
	c = c->next;
    }
    if (c == unit->connections) {
	return 0;
    } else {
	return c;
    }
}

/*
 * Add/update a connection in the queue.
 */

static void add_connection(
    FW_unit *unit, FW_Connection *c, FW_ID *id, unsigned int timeout, TCP_STATE lflags)
{
    /* look for a connection that matches this one */
    if (c == NULL) {
	if (timeout > 0) {
	    /* no matching connection, add one */
	    c = malloc(sizeof(FW_Connection));
	    if (c == 0) {
	       syslog(LOG_ERR,"Out of memory! AIIEEE!");
	       die(1);
	    }
	    c->id = *id;
	    init_timer(&c->timer);
            c->tcp_state = lflags;
	    c->unit = unit;
	    c->timer.data = (int)c;
	    c->timer.function = (void *)(int)del_connection;
	    c->next = unit->connections->next;
	    c->prev = unit->connections;
	    unit->connections->next->prev = c;
	    unit->connections->next = c;
	    c->timer.expires = timeout;
	    add_timer(&c->timer);
	    if (debug&DEBUG_CONNECTION_QUEUE)
    		syslog(LOG_INFO,"Adding connection %d @ %ld - timeout %d",(int)c,
			time(0),timeout);
	}
    } else {
	/* found a matching connection, toss it's old timer */
	if (timeout > 0) {
	    /* reanimating a ghost? */
	    del_timer(&c->timer);
	    c->timer.expires = timeout;
	    add_timer(&c->timer);
	    if (debug&DEBUG_CONNECTION_QUEUE)
    		syslog(LOG_INFO,"Adding connection %d @ %ld - timeout %d",(int)c,
			time(0),timeout);
	} else {
	    /* timeout = 0, so toss the connection */
	    del_timer(&c->timer);
	    del_connection(c);
	}
    }
}

/*
 * Get a connection out of a queue.
 */

void del_connection(FW_Connection *c)
{
    if (debug&DEBUG_CONNECTION_QUEUE)
	syslog(LOG_INFO,"Deleting connection %d @ %ld",(int)c,time(0));

    c->next->prev = c->prev;
    c->prev->next = c->next;
    free(c);
}

void del_impulse(FW_unit *unit)
{

    if (unit->impulse_mode) {
	unit->impulse_mode = 0;
	if (impulse_time > 0) {
	    unit->impulse.data = (int)unit;
	    unit->impulse.function = (void *)(int)del_impulse;
	    unit->impulse.expires = impulse_time;
	    if (debug&DEBUG_CONNECTION_QUEUE)
		syslog(LOG_INFO,"Refreshing impulse generator: mode %d, time %ld @ %ld",unit->impulse_mode,unit->impulse.expires,time(0));
	    add_timer(&unit->impulse);
	}
    } else {
	unit->impulse_mode = 1;
	impulse_init_time = 0;	/* zero the initial impulse time */
	if (impulse_fuzz > 0) {
	    unit->impulse.data = (int)unit;
	    unit->impulse.function = (void *)(int)del_impulse;
	    unit->impulse.expires = impulse_fuzz;
	    if (debug&DEBUG_CONNECTION_QUEUE)
		syslog(LOG_INFO,"Refreshing impulse generator: mode %d, time %ld @ %ld",unit->impulse_mode,unit->impulse.expires,time(0));
	    add_timer(&unit->impulse);
	}
    }
}

/* Check if a forcing rule currently applies to the connection */

static void fw_force_update(FW_unit *unit)
{
    FW_Filters *fw;
    int timeout, mintime;
    time_t clock = time(0);

    /* check if the current forcing slot has expired */
    if (unit->force_etime > clock) return;

    fw = unit->filters;
    mintime = 24*60*60;
    unit->force = 0;

    while (fw) {
	if (fw->filt.type == FW_TYPE_UP || fw->filt.type == FW_TYPE_DOWN) {
	    /* check when the rule is next applicable */
	    timeout = slot_start_timeout(fw->filt.times,&clock);
	
	    if (timeout > 0) {
		/* first time at which a previous slot starts */
		if (timeout < mintime)
		    mintime = timeout;
		goto next_rule;
	    } else {
		/* time at which the current slot ends */
		timeout = slot_end_timeout(fw->filt.times,&clock);
		if (timeout < mintime)
		    mintime = timeout;
	    }
	} else
	    goto next_rule;

        if (fw->filt.type == FW_TYPE_UP)
	    unit->force = 1;
	else
	    unit->force = 2;

	break;

next_rule: /* try the next filter */
	fw = fw->next;
    }

    unit->force_etime = clock + mintime;
}

/* Check if an impulse rule currently applies to the connection */

static void fw_impulse_update(FW_unit *unit, int force)
{
    FW_Filters *fw;
    int timeout, mintime, itimeout, ifuzz, ftimeout;
    time_t clock = time(0);

    /* check if the current forcing slot has expired */
    if (clock < unit->impulse_etime && !force) return;

    fw = unit->filters;
    mintime = 24*60*60;
    itimeout = 0;
    ftimeout = 0;
    ifuzz = 0;

    while (fw) {
	if (fw->filt.type == FW_TYPE_IMPULSE) {
	    /* check when the rule is next applicable */
	    timeout = slot_start_timeout(fw->filt.times,&clock);
	    if (timeout > 0) {
		/* Will be applicable soon */
		/* first time at which a previous slot starts
	 	 * (i.e. schedule changes) */
		if (timeout < mintime)
		    mintime = timeout;
		goto next_rule;
	    } else {
		/* time at which the current slot ends */
		timeout = slot_end_timeout(fw->filt.times,&clock);
		ifuzz = fw->filt.fuzz;
		itimeout = fw->filt.timeout;
		ftimeout = fw->filt.timeout2;
		if (timeout < mintime)
		    mintime = timeout;
	    }
	} else
	    goto next_rule;

	break;

next_rule: /* try the next filter */
	fw = fw->next;
    }
    unit->impulse_etime = clock + mintime;

    del_timer(&unit->impulse);
    if (unit->up && (itimeout > 0 || (force && ftimeout > 0))) {
    	/* place the current impulse generator into the impulse queue */
    	impulse_time = itimeout;
   	impulse_init_time = ftimeout;
    	impulse_fuzz = ifuzz;
    	unit->impulse_mode = 0;
    	unit->impulse.data = (int)unit;
    	unit->impulse.function = (void *)(int)del_impulse;
    	unit->impulse.expires = (force)?ftimeout:itimeout;
    	add_timer(&unit->impulse);
	if (debug&DEBUG_CONNECTION_QUEUE)
	    syslog(LOG_INFO,"Refreshing impulse generator: mode %d, time %ld @ %ld",unit->impulse_mode,unit->impulse.expires,time(0));
    }
}

static void log_packet(int accept, struct iphdr *pkt, int len,  int rule)
{
    char saddr[20], daddr[20];
    struct in_addr addr;
    int sport = 0, dport = 0;
    struct tcphdr *tcp = (struct tcphdr *)((char *)pkt + 4*pkt->ihl);
    struct udphdr *udp = (struct udphdr *)tcp;

    addr.s_addr = pkt->saddr;
    strcpy(saddr,inet_ntoa(addr));
    addr.s_addr = pkt->daddr;
    strcpy(daddr,inet_ntoa(addr));

    if (pkt->protocol == IPPROTO_TCP || pkt->protocol == IPPROTO_UDP)
	sport = ntohs(udp->source), dport = ntohs(udp->dest);

    if (pkt->protocol == IPPROTO_TCP) {
	syslog(LOG_INFO,
	    "filter %s rule %d proto %d len %d seq %lx ack %lx flags %s%s%s%s%s%s packet %s,%d => %s,%d",
	    (accept)?"accepted":"ignored",rule,
	    pkt->protocol,
	    ntohs(pkt->tot_len),
	    ntohl(tcp->seq), ntohl(tcp->ack_seq),
	    (tcp->fin) ? " FIN" : "",
	    (tcp->syn) ? " SYN" : "",
	    (tcp->rst) ? " RST" : "",
	    (tcp->psh) ? " PUSH" : "",
	    (tcp->ack) ? " ACK" : "",
	    (tcp->urg) ? " URG" : "",
	    saddr, sport, daddr, dport);
    } else {
	syslog(LOG_INFO,
	    "filter %s rule %d proto %d len %d packet %s,%d => %s,%d",
	    (accept)?"accepted":"ignored",rule,
	    pkt->protocol,
	    htons(pkt->tot_len),
	    saddr, sport, daddr, dport);
    }
}

/* Check if we need to reorder IP addresses for cannonical ordering */
static int ip_direction(struct iphdr *pkt)
{
    struct udphdr *udp = (struct udphdr *)((char *)pkt + 4*pkt->ihl);
    if (ntohl(pkt->saddr) > ntohl(pkt->daddr)
    || (ntohl(pkt->saddr) == ntohl(pkt->daddr) &&
       (pkt->protocol == IPPROTO_TCP || pkt->protocol == IPPROTO_UDP)
       && ntohs(udp->source) > ntohs(udp->dest)))
	return 2;
    else
	return 1;
}

static void ip_swap_addrs(struct iphdr *pkt)
{
    struct udphdr *udp = (struct udphdr *)((char *)pkt + 4*pkt->ihl);
    unsigned long taddr;
    unsigned short tport;
    if (pkt->protocol == IPPROTO_TCP || pkt->protocol == IPPROTO_UDP) {
	tport = udp->source;
	udp->source = udp->dest;
	udp->dest = tport;
    } 
    taddr = pkt->saddr;
    pkt->saddr = pkt->daddr;
    pkt->daddr = taddr;
}

void print_filter(FW_Filter *filter)
{
    int i;
    syslog(LOG_INFO,"filter: prl %d log %d type %d cnt %d tm %d",
	filter->prule,filter->log,filter->type,
	filter->count,filter->timeout);
    for (i = 0; i < filter->count; i++) {
	syslog(LOG_INFO,"    term: shift %d op %d off %d%c msk %x tst %x",
	    filter->terms[i].shift, filter->terms[i].op,
	    filter->terms[i].offset&0x7f,
	    (filter->terms[i].offset&0x80)?'d':'h',
	    filter->terms[i].mask, filter->terms[i].test);
    }
}

/* Check if a packet passes the filters */
int check_firewall(int unitnum, unsigned char *pkt, int len)
{
    FW_unit *unit;
    FW_Filters *fw;
    unsigned char *data;
    FW_ProtocolRule *prule, *pprule = 0;
    FW_Term *term;
    int i,v,rule;
    int direction,opdir;
    TCP_STATE lflags;
    clock_t clock = time(0);
    FW_ID id;
    FW_Connection *conn;
    struct iphdr * ip_pkt = (struct iphdr *)pkt;

    if (!initialized) init_units();

    if (unitnum < 0 || unitnum >= FW_NRUNIT) {
	/* FIXME: set an errorno? */
	return -1;
    }

    unit = &units[unitnum];
    fw = unit->filters;

    data = pkt + 4*((struct iphdr *)pkt)->ihl;

    /* Find the correct protocol rule */
    for (i = 0; i < unit->nrules; i++) {
	pprule = &unit->prules[i];
	if (FW_PROTO_ALL(pprule->protocol)
	|| pprule->protocol == ip_pkt->protocol)
	break;
    }

    if (pprule == 0) {
	return -1;	/* No protocol rules? */
    }

    /* Build the connection ID, and set the direction flag */
    direction = ip_direction(ip_pkt);
    if (direction == 2) ip_swap_addrs(ip_pkt);
    for (i = 0; i < FW_ID_LEN; i++)
	id.id[i] = (FW_IN_DATA(pprule->codes[i])?data:pkt)
		    [FW_OFFSET(pprule->codes[i])];
    if (direction == 2) ip_swap_addrs(ip_pkt);
    conn = find_connection(unit,&id);
    opdir = (direction==1)?2:1;

    /* Do the TCP liveness changes */
    if (ip_pkt->protocol == IPPROTO_TCP) {
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip_pkt + 4*ip_pkt->ihl);
	int tcp_data_len = len - (4*ip_pkt->ihl + sizeof(struct tcphdr));

	if (conn) {
	    lflags = conn->tcp_state;
	} else {
	    lflags.fin_seq[0] = lflags.fin_seq[1] = 0;
	    lflags.tcp_flags = 0;
            lflags.saw_fin = 0;
	}
	if (tcp->rst) {
	    lflags.saw_fin = 0;
	    lflags.tcp_flags = 0;
	} else if (tcp->fin) {
	    lflags.saw_fin |= direction;
	    lflags.fin_seq[direction-1] = ntohl(tcp->seq)+tcp_data_len+1;
	} else if (tcp->syn || tcp_data_len > 0) {
	    /* Either we have a SYN packet, or we have a data carrying
   	     * packet. In either case we want to declare this direction live.
	     * FIXME. It is possible that this should set saw_fin to 0 in the
	     * case that we have a SYN packet.
	     */
	    lflags.saw_fin &= ~direction;
	    lflags.tcp_flags |= direction;
	}
	if ((lflags.saw_fin & opdir) && (tcp->ack)) {
	    if (lflags.fin_seq[opdir-1] == ntohl(tcp->ack_seq)) {
		lflags.tcp_flags &= ~direction;
	    }
	}

	if (conn) {
	    conn->tcp_state = lflags;
	}
    }

    rule = 1;
    while (fw) {
#if 0
	print_filter(&fw->filt);
#endif
	/* is this rule currently applicable? */
	if ((unit->up && fw->filt.type == FW_TYPE_BRINGUP)
	   || (!unit->up && fw->filt.type == FW_TYPE_KEEPUP)
	   || !in_slot(fw->filt.times,&clock)
	   || fw->filt.type == FW_TYPE_IMPULSE
	   || fw->filt.type == FW_TYPE_UP
	   || fw->filt.type == FW_TYPE_DOWN)
	    goto next_rule;

	/* Check the protocol rule */
	prule = &unit->prules[fw->filt.prule];
	if (!(FW_PROTO_ALL(prule->protocol)
	|| prule->protocol == ip_pkt->protocol))
	    goto next_rule;

	/* Check the terms */
	for (i = 0;
	(fw->filt.count > FW_MAX_TERMS) || (i < fw->filt.count); i++) {
	    if (i > FW_MAX_TERMS && fw->filt.count == 0) {
		fw = fw->next, i = 0;
		if (fw == NULL) break;
	    }
	    term = &fw->filt.terms[i];
	    if (FW_TCP_STATE(term->offset))
		v = (lflags.tcp_flags >> term->shift) && term->mask;
	    else
	        v = (ntohl(*(int *)(&(FW_IN_DATA(term->offset)?data:pkt)
				  [FW_OFFSET(term->offset)]))
		    >> term->shift) & term->mask;
#if 0
	    syslog(LOG_INFO,"testing ip %x:%x data %x:%x mask %x shift %x test %x v %x",
		ntohl(*(int *)(&pkt[FW_OFFSET(term->offset)])),
		*(int *)(&pkt[FW_OFFSET(term->offset)]),
		ntohl(*(int *)(&data[FW_OFFSET(term->offset)])),
		*(int *)(&data[FW_OFFSET(term->offset)]),
		term->mask,
		term->shift,
		term->test,
		v);
#endif
	    switch (term->op) {
	    case FW_EQ: if (v != term->test) goto next_rule; break;
	    case FW_NE: if (v == term->test) goto next_rule; break;
	    case FW_GE: if (v < term->test) goto next_rule; break;
	    case FW_LE: if (v > term->test) goto next_rule; break;
	    }
	}
	/* Ok, we matched a rule. What are we suppose to do? */
#if 0
	if (fw->filt.log)
#endif
        if (debug&DEBUG_FILTER_MATCH)
	    log_packet(fw->filt.type!=FW_TYPE_IGNORE,ip_pkt,len,rule);

	/* Check if this entry goes into the queue or not */
	if (fw->filt.type != FW_TYPE_IGNORE && fw->filt.type != FW_TYPE_WAIT) {
	    add_connection(unit,conn,&id,fw->filt.timeout,lflags);
	}
	/* check if we are no longer waiting */
	if (fw->filt.type == FW_TYPE_WAIT) {
		unit->waiting = 0;
		/* WAITING rules don't do the final match, but
		 * must occur before other rules
		 */
		goto next_rule;
	}

	/* Return 1 if accepting rule with non zero timeout, 0 otherwise */
	return ((fw->filt.type != FW_TYPE_IGNORE || fw->filt.type != FW_TYPE_WAIT) && fw->filt.timeout > 0);

next_rule: /* try the next filter */
	fw = fw->next;
	rule++;
    }
    /* Failed to match any rule. This means we ignore the packet */
    if (debug&DEBUG_FILTER_MATCH)
        log_packet(0,ip_pkt,len,0);
    return 1;
}

static void pcountdown(int level, long secs)
{
    char buf[10];
    sprintf(buf,"%02ld:%02ld:%02ld\n",secs/3600,(secs/60)%60,secs%60);
    if (monitors) mon_write(level,buf,9);
}

int ctl_firewall(int op, struct firewall_req *req)
{
    FW_unit *unit;
    if (!initialized) init_units();

    /* Need to check that req is OK */

    if (req && req->unit >= FW_NRUNIT) return -1; /* ERRNO */

    if (req) unit = &units[req->unit];
    else unit = units;
    
    switch (op) {
    case IP_FW_QFLUSH:
	if (!req) return -1; /* ERRNO */
	{
	    FW_Connection *c,*cn;
	    for (c = unit->connections->next;
	    c != unit->connections; c = cn) {
		cn = c->next;
		del_timer(&c->timer);
		c->next->prev = c->prev;
		c->prev->next = c->next;
		free((void *)c);
	    }
	    return 0;
	}
    case IP_FW_QCHECK:
	if (!req) return -1; /* ERRNO */
	
	fw_force_update(unit);
	fw_impulse_update(unit,0);

	return (unit->force == 2
		|| (unit->force == 0
		    && !(unit->up && unit->impulse_mode == 0
		   	 && (impulse_init_time > 0 || impulse_time > 0))
		    && unit->connections == unit->connections->next));


    case IP_FW_PFLUSH:
	if (!req) return -1; /* ERRNO */
	unit->nrules = 0;
	return 0;
    /* PFLUSH implies FFLUSH */
    case IP_FW_FFLUSH:
	if (!req) return -1; /* ERRNO */
	{
	    FW_Filters *next, *filt = unit->filters;
	    while (filt)
	    	{ next = filt->next; free(filt); filt = next; }
	    unit->filters = NULL;
	    unit->last = NULL;
	}
	return 0;
    case IP_FW_AFILT:
	if (!req) return -1; /* ERRNO */
	{
	    FW_Filters *filters = malloc(sizeof(FW_Filters));
	    if (filters == 0) {
		syslog(LOG_ERR,"Out of memory! AIIEEE!");
		return -1; /* ERRNO */
	    }
	    filters->next = 0;
	    filters->filt = req->fw_arg.filter;
	    if (unit->last) unit->last->next = filters;
	    if (!unit->filters) unit->filters = filters;
	    unit->last = filters;
	    unit->nfilters++;
	}
	return 0;
    case IP_FW_APRULE:
	if (!req) return -1; /* ERRNO */
	if (unit->nrules >= FW_MAX_PRULES) return -1; /* ERRNO */
	unit->prules[(int)unit->nrules] = req->fw_arg.rule;
	return unit->nrules++;
    /* Printing does nothing right now */
    case IP_FW_PCONN:
	if (!req) return -1; /* ERRNO */
	{
	    unsigned long atime = time(0);
            unsigned long tstamp = timestamp();
	    FW_Connection *c;
	    char saddr[20], daddr[20];
    	    struct in_addr addr;
	    syslog(LOG_INFO,"up = %d, forcing = %d, impulse = %d, iitime = %d, itime = %d, ifuzz = %d, itimeout = %ld, timeout = %ld, next alarm = %d",
		unit->up,unit->force, unit->impulse_mode, impulse_init_time, impulse_time,
		impulse_fuzz,
		unit->impulse.expected-tstamp,unit->force_etime-atime,
		next_alarm());
	    for (c=unit->connections->next; c!=unit->connections; c=c->next) {
		if (c->timer.next == 0) c->timer.expected = tstamp;
                addr.s_addr = c->id.id[1] + (c->id.id[2]<<8)
                        + (c->id.id[3]<<16) + (c->id.id[4]<<24);
                strcpy(saddr,inet_ntoa(addr));
                addr.s_addr = c->id.id[5] + (c->id.id[6]<<8)
                        + (c->id.id[7]<<16) + (c->id.id[8]<<24);
                strcpy(daddr,inet_ntoa(addr));
                syslog(LOG_INFO,
                        "ttl %ld, %d - %s/%d => %s/%d (tcp state ([%lx,%lx] %d,%d))",
                        c->timer.expected-tstamp, c->id.id[0],
                        saddr, c->id.id[10]+(c->id.id[9]<<8),
                        daddr, c->id.id[12]+(c->id.id[11]<<8),
			c->tcp_state.fin_seq[0],
			c->tcp_state.fin_seq[1],
			c->tcp_state.saw_fin,
			c->tcp_state.tcp_flags);
	    }
	    return 0;
	}
	return 0;
    case IP_FW_MCONN:
	if (!req || !monitors) return -1; /* ERRNO */
	{
	    unsigned long atime = time(0);
            unsigned long tstamp = timestamp();
	    FW_Connection *c;
	    char saddr[20], daddr[20];
  	    int sport, dport;
	    char proto[20];
    	    struct protoent *pent;
    	    struct in_addr addr;
            char buf[1024];

	    sprintf(buf,"STATUS\n%d\n%d\n%d\n%d\n%d\n%d\n",
		unit->up, unit->force, unit->impulse_mode,
		impulse_init_time, impulse_time,
		impulse_fuzz);
	    if (monitors) mon_write(MONITOR_STATUS,buf,strlen(buf));

	    pcountdown(MONITOR_STATUS,(unit->impulse_mode)?(unit->impulse.expected-tstamp):0);
	    pcountdown(MONITOR_STATUS,unit->force_etime-atime);
	    pcountdown(MONITOR_STATUS,next_alarm());
	    if (monitors) mon_write(MONITOR_QUEUE,"QUEUE\n",6);
	    for (c=unit->connections->next; c!=unit->connections; c=c->next) {
		if (c->timer.next == 0) continue;
                addr.s_addr = c->id.id[1] + (c->id.id[2]<<8)
                        + (c->id.id[3]<<16) + (c->id.id[4]<<24);
                strcpy(saddr,inet_ntoa(addr));
                addr.s_addr = c->id.id[5] + (c->id.id[6]<<8)
                        + (c->id.id[7]<<16) + (c->id.id[8]<<24);
                strcpy(daddr,inet_ntoa(addr));
#ifdef EMBED
		pent = NULL;
#else
		pent = getprotobynumber(c->id.id[0]);
#endif
		if (pent) strcpy(proto,pent->p_name);
		else sprintf(proto,"%d",c->id.id[0]);
		sport = c->id.id[10]+(c->id.id[9]<<8);
		dport = c->id.id[12]+(c->id.id[11]<<8);
                sprintf(buf,
                        "%-4s  %15s/%-5d  %15s/%-5d  ",
                        proto, saddr, sport,
                        daddr, dport);
                if (monitors) mon_write(MONITOR_QUEUE,buf,strlen(buf));
		pcountdown(MONITOR_QUEUE,c->timer.expected-tstamp);
	    }
	    if (monitors) mon_write(MONITOR_QUEUE,"END QUEUE\n",10);
	    return 0;
	}
	return 0;
    case IP_FW_PPRULE:
	if (!req) return -1; /* ERRNO */
	return 0;
    case IP_FW_PFILT:
	if (!req) return -1; /* ERRNO */
	return 0;
    /* Opening and closing firewalls is cooperative right now.
     * Also, it does nothing to change the behavior of a device
     * associated with the firewall.
     */
    case IP_FW_OPEN:
	{
	    int i;
	    for (i = 0; i < FW_NRUNIT; i++)
		if (units[i].used == 0) {
		    struct firewall_req mreq;
		    mreq.unit = i;
		    ctl_firewall(IP_FW_PFLUSH,&mreq);
		    units[i].used = 1;
		    units[i].force_etime = 0;
		    units[i].impulse_etime = 0;
		    units[i].waiting = 1;
		    return i;
		}
	    return -1;	/* ERRNO */
	}
    case IP_FW_CLOSE:
	{
	    struct firewall_req mreq;
	    if (!req) return -1; /* ERRNO */
	    mreq.unit = req->unit;
	    ctl_firewall(IP_FW_PFLUSH,&mreq);
	    unit->used = 0;
	    return 0;
	}
    case IP_FW_UP:
	unit->up = 1;
	run_ip_up();
	fw_force_update(unit);
	fw_impulse_update(unit,1);
	return 0;

    case IP_FW_DOWN:
	if (unit->up) run_ip_down();
	unit->up = 0;
	/* turn off the impulse generator */
	del_timer(&unit->impulse);
	return 0;
    case IP_FW_WAIT:
	return unit->waiting;
    case IP_FW_RESET_WAITING:
	unit->waiting = 1;
	return 0;
    }
    return -1; /* ERRNO */
}
