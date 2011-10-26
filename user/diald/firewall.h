/*
 * firewall.h - Firewall headers.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#define FW_ID_LEN 16			/* number of bytes in a connection id */
#define FW_OFFSET(x) ((x)&0x7f)		/* offset into a header */
#define FW_IP_OFFSET(x) ((x)&0x7f)	/* construct a ip header offset */
#define FW_DATA_OFFSET(x) (0x80|((x)&0x7f))	/* offset into an ip data */
#define FW_IN_IP(x) (((x)&0x80)==0)	/* in ip hdr segment */
#define FW_IN_DATA(x) ((x)&0x80)	/* in data segment */
#define FW_TCP_STATE(x) ((x)==255)	/* test tcp_state variable */
#define FW_PROTO_ALL(x) ((x)==255)	/* any protocol */

/* Direction indicators */
#define FW_DIR_IN 0
#define FW_DIR_OUT 1
#define FW_DIR_BOTH 2

/* Comparision operators */
#define FW_EQ 0
#define FW_NE 1
#define FW_GE 2
#define FW_LE 3

#define FW_MAX_TERMS 10			/* Max terms per filter struct */
#define FW_MAX_PRULES 32
#define FW_NRUNIT 16			/* max # of unit's FW can monitor */

/*
 * Externally visible structures.
 */

typedef struct firewall_prule {
    unsigned char protocol;		/* Protocol: 255 = match all. */
    unsigned char codes[FW_ID_LEN];	/* coding rule, byte offsets */
} FW_ProtocolRule;

typedef struct firewall_term {
    unsigned char shift:5;	/* 0-31 */
    unsigned char op:2;		/* operation: =, !=, >=, <= */
    unsigned char offset;	/* offset code. Same as in protocol rules */
    unsigned int mask;		/* mask value */
    unsigned int test;		/* test value */
} FW_Term;

/*
 * Times that a rule should be applied.
 */
typedef struct FW_Timeslot {
    unsigned int start;			/* first minute of day in slot */
    unsigned int end;			/* last minute of day in slot */
    unsigned int wday:7;                /* days of the week slot applies */
    unsigned int mday:31;               /* days of the month slot applies */
    unsigned short month:12;            /* month of the year slot applies */
    struct FW_Timeslot *next;		/* next slot in disjunct */
} FW_Timeslot;

#define FW_TYPE_BRINGUP 0		/* bring the link up */
#define FW_TYPE_KEEPUP	1		/* keep the link active */
#define FW_TYPE_ACCEPT	2		/* bring up and active */
#define FW_TYPE_IGNORE	3		/* ignore this packet */
#define FW_TYPE_UP	4
#define FW_TYPE_DOWN	5
#define FW_TYPE_IMPULSE 6
#define FW_TYPE_WAIT	7		/* use packet to mark start of
					 * active transmissions. Generally
					 * a routing packet of some kind.
					 */

/*
 * Firewall filter.
 */
typedef struct firewall_rule {
    FW_Timeslot *times;		/* chain of times the filter can be applied */
    unsigned char prule:5;	/* protocol rule, 0-31. */
    unsigned char type:3;	/* link type */
    unsigned char count:7;	/* number of terms. maximum FW_MAX_TERMS */
    unsigned char log:1;	/* log matches to this rule */
    unsigned int timeout;	/* timeout in seconds. Max approx 136 years */
    unsigned int fuzz;		/* fuzz to apply to impulse rules */
    unsigned int timeout2;	/* impulse timeout after first used */
    FW_Term terms[FW_MAX_TERMS];	/* terms in the rule */
} FW_Filter;

/*
 * Firewall request structure for ioctl's.
 */

struct firewall_req {
    unsigned char unit;			/* firewall unit */
    union {
        char ifname[16];		/* FIXME! */
	FW_Filter filter;
	FW_ProtocolRule rule;
	int value;
    } fw_arg;
};

/*
 * Firewall IOCTL's
 */

#define IP_FW_QFLUSH	1	/* flush the timeout queue */
#define IP_FW_QCHECK	2	/* is the queue empty or not */
#define IP_FW_FFLUSH	3	/* flush the filters */
#define IP_FW_PFLUSH	4	/* flush the protocol rules */
#define IP_FW_AFILT     5	/* add a filter rule */
#define IP_FW_APRULE	6	/* add a protocol rule */
#define IP_FW_PCONN	7	/* print the connections */
#define IP_FW_PPRULE	8	/* print the rules */
#define IP_FW_PFILT	9	/* print the filters */
#define IP_FW_OPEN	10	/* print the filters */
#define IP_FW_CLOSE	11	/* print the filters */
#define IP_FW_UP	12	/* mark the interface as up */
#define IP_FW_DOWN	13	/* mark the interface as down */
#define IP_FW_MCONN	14	/* print the connections to monitor */
#define IP_FW_WAIT	15	/* check if we are done waiting for
				 * routing packet */
#define IP_FW_RESET_WAITING 16

/*
 * Internal data structures.
 */

/*
 * List of filters.
 */
typedef struct fw_filters {
    struct fw_filters *next;	/* next filter in the firewall chain */
    FW_Filter filt;
} FW_Filters;

/*
 * Identifier structure.
 */
typedef struct {
    unsigned char id[FW_ID_LEN];	/* identifier for this connection */
} FW_ID;

/*
 * TCP State structure.
 */
typedef struct tcp_state {
    unsigned char tcp_flags:2;		/* TCP liveness flags */
    unsigned char saw_fin:2;		/* directions we saw a FIN in */
    unsigned long fin_seq[2];		/* sequence numbers for FIN packets */
} TCP_STATE;

/*
 * Connection entry;
 */
typedef struct fw_connection {
    struct timer_lst timer;		/* timer for this connection */
    FW_ID id;				/* identifier for this connection */
    TCP_STATE tcp_state;		/* TCP state information */
    struct fw_unit *unit;		/* Unit this connection is in */
    struct fw_connection *next,*prev;	/* queue chain pointers */
} FW_Connection;

typedef struct fw_unit {
    FW_ProtocolRule prules[FW_MAX_PRULES];	/* prules */
    FW_Filters *filters;		/* list of filters */
    FW_Filters *last;			/* last filter in the list */
    FW_Connection *connections;		/* connection queue */
    int live;				/* number of live connections in queue */
    struct timer_lst impulse;		/* impulse timer */
    unsigned long force_etime;		/* time of next forcing event */
    unsigned long impulse_etime;	/* time of next impulse change event */
    char used;				/* is this unit free */
    unsigned char up:1;			/* Is the line currently up or down? */
    unsigned char force:2;		/* 0 = queue only, 1 = force up,
   					 * 2 = force down */
    unsigned char impulse_mode:1;	/* impulse mode 0 = on, 1 = fuzz */
    unsigned char waiting:1;		/* waiting for routing packet */
    char nrules;			/* how many rules are assigned */
    short nfilters;			/* how many filters are assigned */
} FW_unit;

int ctl_firewall(int, struct firewall_req *);
int check_firewall(int, unsigned char *, int);
