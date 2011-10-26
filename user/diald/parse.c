/*
 * parse.c - Options parsing code.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include <setjmp.h>
#include "diald.h"

#define TOK_LE 256
#define TOK_GE 257
#define TOK_NE 258
#define TOK_INET 259
#define TOK_STR 260
#define TOK_NUM 261
#define TOK_ERR 262
#define TOK_EOF 263
#define ADVANCE token = token->next

struct prule {
    char *name;
} prules[FW_MAX_PRULES];
static int nprules = 0;

static struct var {
   char *name;
   int offset;
   int shift;
   unsigned int mask;
   struct var *next;
} *vars = 0;

static struct strvar {
   char *name;
   char *value;
   struct strvar *next;
} *strvars = 0;

typedef struct token {
    int offset;
    int type;
    char *str;
    struct token *next;
} Token;

static FW_Timeslot *cslot,*tslot;

char *errstr;
Token *tlist;
Token *token;
char *context;

static jmp_buf unwind;

void parse_init()
{
    cslot = (FW_Timeslot *)malloc(sizeof(FW_Timeslot));
    cslot->next = 0;
    cslot->start = 0;
    cslot->end = 24*60*60-1;
    cslot->wday = 0x7f;
    cslot->mday = 0x7fffffff;
    cslot->month = 0xfff;
}

void parse_error(char *s)
{
    syslog(LOG_ERR,"%s parsing error. Got token '%s'. %s",context,token->str,s);
    syslog(LOG_ERR,"parse string: '%s'",errstr);
    longjmp(unwind,1);
}

static const char *find_strvar(const char *name)
{
    struct strvar *v;
    
    /* Replace an existing strvar, or allocate a new one */
    for (v = strvars; v; v = v->next) {
	if (strcmp(v->name, name) == 0) {
	    return v->value;
	}
    }
    return 0;
}

typedef struct {
    char *buf;
    int pos;
    int len;
} growbuf_t;

static void grow_char(growbuf_t *buf, char c)
{
    if (buf->pos + 1 >= buf->len) {
	buf->len += 50;
	buf->buf = realloc(buf->buf, buf->len);
	if (buf->buf == 0) { syslog(LOG_ERR,"Out of memory! AIIEEE!"); die(1); }
    }
    buf->buf[buf->pos++] = c;
}

static void grow_str(growbuf_t *buf, const char *str)
{
    while (*str) {
	grow_char(buf, *str++);
    }
}

void tokenize(char *cntxt, int argc, char **argv)
{
    char *s;
    int i, len;
    Token *prev = 0, *new;
    growbuf_t growbuf = { 0, 0, 0 };

    context = cntxt;

    /* merge the arguments into one string, substituting and string variables
     * as we go
     */
    for (i = 0; i < argc; i++) {
	char *pt;

	if (i != 0) {
	    grow_char(&growbuf, ' ');
	}
	for (pt = argv[i]; *pt; ) {
	    if (pt[0] == '$' && pt[1] == '{') {
		/* We need to substitute this variable */
		char *end = strchr(pt, '}');
		const char *value;

		if (end) {
		    *end++ = 0;
		}
		pt += 2;

		/* Now pt points to the variable name. See if it exists */
		value = find_strvar(pt);
		if (value) {
		    grow_str(&growbuf, value);
		}
		break;
	    }
	    grow_char(&growbuf, *pt);

	    pt++;
	}
    }

    grow_char(&growbuf, 0);

    /* Now 'growbuf.buf' points to an allocated, null-terminated buffer with variables expanded */

    errstr = growbuf.buf;

    tlist = 0;

    for (s = errstr; *s;) {
	new = malloc(sizeof(Token));
	if (new == 0) { syslog(LOG_ERR,"Out of memory! AIIEEE!"); die(1); }
        if (prev == 0) tlist = new; else prev->next = new;
	prev = new;
	new->next = 0;
	new->offset = s-errstr;
	if (*s == '<' && s[1] == '=') {
	    new->type = TOK_LE; s += 2;
	} else if (*s == '>' && s[1] == '=') {
	    new->type = TOK_GE; s += 2;
	} else if (*s == '!' && s[1] == '=') {
	    new->type = TOK_NE; s += 2;
	} else if (isalpha(*s) || *s == '.' || *s == '_') {
	    new->type = TOK_STR;
	    while (isalnum(*s) || *s == '.' || *s == '_' || *s == '-') s++;
	} else if (*s == '0' && s[1] == 'x' && isxdigit(s[2])) {
	    new->type = TOK_NUM;
	    s += 2;
	    while (isxdigit(*s)) s++;
	} else if (*s == '0' && isdigit(s[1])) {
	    new->type = TOK_NUM;
	    s++;
	    while (isdigit(*s)) s++;
	} else if (isdigit(*s)) {
	    while (isdigit(*s)) s++;
	    if (*s == '.') {
	        new->type = TOK_INET;
		s++;
		if (!isdigit(*s)) goto tokerr;
		while (isdigit(*s)) s++;
		if (*s != '.') goto tokerr;
		s++;
		if (!isdigit(*s)) goto tokerr;
		while (isdigit(*s)) s++;
		if (*s != '.') goto tokerr;
		s++;
		if (!isdigit(*s)) goto tokerr;
		while (isdigit(*s)) s++;
	        if (*s == '.') s++;
	        goto done;
tokerr:
		new->type = TOK_ERR;
	    } else {
		new->type = TOK_NUM;
	    }
	} else {
	    new->type = *s++;
	}
done:
	len = (s-errstr)-new->offset;
	new->str = malloc(len+1);
	if (new->str == 0) { syslog(LOG_ERR,"Out of memory! AIIEEE!"); die(1); }
	strncpy(new->str,errstr+new->offset,len);
	new->str[len] = 0;
    }
    new = malloc(sizeof(Token));
    if (new == 0) { syslog(LOG_ERR,"Out of memory! AIIEEE!"); die(1); }
    if (prev == 0) tlist = new; else prev->next = new;
    prev = new;
    new->next = 0;
    new->offset = s-errstr;
    new->type = TOK_EOF;
    new->str = strdup("");
    token = tlist;
}

void free_tokens(void)
{
    Token *next;
    if (token && token->type != TOK_EOF)
	syslog(LOG_ERR,
	    "Parsing error. Got token '%s' when end of parse was expected.",
	    token->str);
    while (tlist) {
	next = tlist->next;
	free(tlist->str);
	free(tlist);
	tlist = next;
    }
    tlist = 0;
    free(errstr);
}


void init_prule(FW_ProtocolRule *rule)
{
    rule->protocol = 0;
}

void init_filter(FW_Filter *filter)
{
    filter->times = cslot;
    filter->prule = 0;
    filter->log = 0;
    filter->count = 0;
    filter->timeout = 0;
}

void eat_whitespace(void)
{
    if (token->type == ' ') { ADVANCE; }
}

void parse_whitespace(void)
{
    if (token->type != ' ') parse_error("Expecting whitespace");
    ADVANCE;
}

static void set_start(int i)
{
    if (i == -1)
   	tslot->start = 0;
    else
    	tslot->start = i;
}

static void set_end(int i)
{
    if (i == -1)
	tslot->end = 24*60*60-1;
    else
        tslot->end = i;
    if (tslot->end < tslot->start) {
	parse_error("End of time slot must be later than start.");
    }
}

static void set_weekdays(int i)
{
    if (i < 0) {
	tslot->wday = 0x7f;
    } else if (i < 7) {
	tslot->wday |= (1<<i);
    } else {
	parse_error("Weekday specification must be in range 0-6.");
    }
}


static void set_days(int i)
{
    if (i < 0) {
	tslot->mday = 0x7fffffff;
    } else if (i > 0 && i < 32) {
	tslot->mday |= (1<<(i-1));
    } else {
	parse_error("Month day specification must be in range 1-31.");
    }
}

static void set_month(int i)
{
    if (i < 0) {
	tslot->month = 0xfff;
    } else if (i > 0 && i < 13) {
	tslot->month |= (1<<(i-1));
    } else {
	parse_error("Month specification must be in range 1-12.");
    }
}

static void parse_time(void (*set_func)(int))
{
    int hour, min, sec;

    if (token->type == '*') {
	(*set_func)(-1);
	ADVANCE;
    } else {
	if (token->type != TOK_NUM)
	    parse_error("Expecting a number for hours.");
	sscanf(token->str,"%d",&hour);
	if (hour < 0 || hour > 23)
	    parse_error("Hours value must be between 0 and 23");
	ADVANCE;
	if (token->type != ':')
	    parse_error("Expecting a ':'.");
	ADVANCE;
	if (token->type != TOK_NUM)
	    parse_error("Expecting a number for minutes.");
	sscanf(token->str,"%d",&min);
	if (min < 0 || min > 59)
	    parse_error("Minutes value must be between 0 and 59");
	ADVANCE;
	if (token->type != ':')
	    parse_error("Expecting a ':'.");
	ADVANCE;
	if (token->type != TOK_NUM)
	    parse_error("Expecting a number for seconds.");
	sscanf(token->str,"%d",&sec);
	if (sec < 0 || sec > 59)
	    parse_error("Seconds value must be between 0 and 59");
	ADVANCE;
	(*set_func)(hour*60*60+min*60+sec);
    }
}

static void parse_times(void (*set_func)(int))
{
    int i,j;

    if (token->type == '*') {
	(*set_func)(-1);
	ADVANCE;
    } else {
	while (1) {
	    if (token->type != TOK_NUM)
		parse_error("Expecting a number.");
	    sscanf(token->str,"%i",&i);
	    (*set_func)(i);
	    ADVANCE;
	    if (token->type == '-') {
		ADVANCE;
		if (token->type != TOK_NUM)
		    parse_error("Expecting a number.");
		sscanf(token->str,"%i",&j);
		for (; i <= j; i++)
		    (*set_func)(i);
		ADVANCE;
	    }
	    if (token->type != ',') break;
	    ADVANCE;
	}
    }
}

void parse_restrict_disjunct()
{
    /* clear the current settings */
    tslot->start = 0;
    tslot->end = 0;
    tslot->wday = 0;
    tslot->mday = 0;
    tslot->month = 0;
    tslot->next = 0;
    eat_whitespace();
    parse_time(set_start);
    parse_whitespace();
    parse_time(set_end);
    parse_whitespace();
    parse_times(set_weekdays);
    parse_whitespace();
    parse_times(set_days);
    parse_whitespace();
    parse_times(set_month);
    eat_whitespace();
}

void parse_restrict(void *var, char **argv)
{
    tslot = cslot = (FW_Timeslot *)malloc(sizeof(FW_Timeslot));
    tokenize("restrict",5,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }
    parse_restrict_disjunct();

    while (token->type == ',') {
	ADVANCE;
    	tslot->next = (FW_Timeslot *)malloc(sizeof(FW_Timeslot));
	tslot = tslot->next;
	parse_restrict_disjunct();
    }
    free_tokens();
}


void parse_or_restrict(void *var, char **argv)
{
    tokenize("restrict",5,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }
    tslot->next = (FW_Timeslot *)malloc(sizeof(FW_Timeslot));
    tslot = tslot->next;
    parse_restrict_disjunct();
    free_tokens();
}

void parse_new_prule_name(void)
{
    int i;
    if (token->type != TOK_STR) parse_error("Expecting a string.");
    for (i = 0; i < nprules; i++)
	if (strcmp(token->str,prules[i].name) == 0)
	    parse_error("Rule name already defined.");
    prules[nprules].name = strdup(token->str);
    ADVANCE;
}

void parse_protocol_name(FW_ProtocolRule *prule)
{
    struct protoent *proto;
    if (token->type == TOK_STR) {
	if (strcmp(token->str,"any") == 0)
	    { prule->protocol = 255; ADVANCE; return; }
        if ((proto = getprotobyname(token->str)))
	    { prule->protocol = proto->p_proto; ADVANCE; return; }
	parse_error("Expecting a protocol name or 'any'.");
    } else if (token->type == TOK_NUM) {
	int p;
	sscanf(token->str,"%i",&p);
	if (p > 254) parse_error("Expecting number from 0-254.");
	prule->protocol = p;
	ADVANCE;
    } else
        parse_error("Expecting a string or a number.");
}

int parse_offset(void)
{
    int v;
    int flag = 0;
    if (token->type == '+') { flag = 1; ADVANCE; }
    if (token->type == TOK_NUM) {
	sscanf(token->str,"%i",&v);
	ADVANCE;
	if (FW_OFFSET(v) != v) parse_error("Offset definition out of range.");
	return ((flag) ? FW_DATA_OFFSET(v) : FW_IP_OFFSET(v));
    }
    parse_error("Expecting an offset definition: <num> or +<num>.");
    return 0; /* NOTREACHED */
}

void parse_prule_spec(FW_ProtocolRule *prule)
{
    int i;
    prule->codes[0] = parse_offset();
    for (i = 1; i < FW_ID_LEN; i++) {
	if (token->type != ':') parse_error("Expecting ':'");
	ADVANCE;
	prule->codes[i] = parse_offset();
    }
}

void parse_prule_name(FW_Filter *filter)
{
    int i;
    if (token->type != TOK_STR) parse_error("Expecting a string.");
    for (i = 0; i < nprules; i++)
	if (strcmp(token->str,prules[i].name) == 0) {
	    filter->prule = i;
	    ADVANCE;
	    return;
	}
    parse_error("Not a known protocol rule.");
}

void parse_timeout(FW_Filter *filter)
{
    int to;
    if (token->type != TOK_NUM) parse_error("Expecting a number.");
    sscanf(token->str,"%i",&to);
    if (to < 0)
	parse_error("Out of acceptable range for a timeout.");
    filter->timeout = to;
    ADVANCE;
}

/* <rvalue> ::= <num> | <name> | <inet> */
int parse_rvalue(void)
{
    int v;
    if (token->type == TOK_NUM) {
	sscanf(token->str,"%i",&v);
	ADVANCE; return v;
    } else if (token->type == TOK_INET) {
	if ((v = ntohl(inet_addr(token->str))) == -1)
	    parse_error("Bad inet address specification.");
	ADVANCE; return v;
    } else if (token->type == TOK_STR) {
	struct protoent *proto;
	struct servent *serv;
	if ((proto = getprotobyname(token->str))) {
	    ADVANCE; return proto->p_proto;
	} else if (strncmp("udp.",token->str,4) == 0) {
	    if ((serv = getservbyname(token->str+4,"udp"))) {
	 	ADVANCE; return htons(serv->s_port);
	    }
#ifdef EMBED
		/* come old NETtel broken config file compatibilty */
		v = 0;
		if (sscanf(token->str+4, "%i", &v) == 1 && v > 0) {
			ADVANCE; return(v);
		}
#endif
	    parse_error("Not a known udp service port.");
	} else if (strncmp("tcp.",token->str,4) == 0) {
	    if ((serv = getservbyname(token->str+4,"tcp"))) {
	 	ADVANCE; return htons(serv->s_port);
	    }
#ifdef EMBED
		/* come old NETtel broken config file compatibilty */
		v = 0;
		if (sscanf(token->str+4, "%i", &v) == 1 && v > 0) {
			ADVANCE; return(v);
		}
#endif
	    parse_error("Not a known tcp service port.");
	}
	parse_error("Not a known value name.");
    } else {
	parse_error("Expecting an <rvalue> specification.");
    }
    return 0; /* NOTREACHED */
}


/* <varspec> ::= <offset> [(<shift>)] [&<mask>] */
void parse_varspec(struct var *variable)
{
    int shift  = 0;
    variable->offset = parse_offset();
    if (token->type == '(') {
	ADVANCE;
	if (token->type != TOK_NUM)
	    parse_error("Expecting a bit shift value.");
	sscanf(token->str,"%i",&shift);
	if (shift > 31) parse_error("Shift value must be in [0,31].");
	ADVANCE;
	if (token->type != ')') parse_error("Expecting a ')'.");
	ADVANCE;
    }
    variable->shift = shift;
    if (token->type == '&') {
	ADVANCE;
	variable->mask = parse_rvalue();
    } else {
	variable->mask = 0xffffffffU;
    }
}

void parse_var_name(struct var *variable)
{
    struct var *cvar;

    if (token->type == TOK_STR) {
	for (cvar = vars; cvar; cvar = cvar->next) {
	    if (strcmp(cvar->name,token->str) == 0)
		parse_error("Expecting a new variable name");
	}
	variable->name = strdup(token->str);
	ADVANCE;
    } else
       parse_error("Expecting a variable name.");
}

/* <varref> ::= <name> */
void parse_varref(FW_Term *term)
{
    struct var *cvar;

    if (token->type == TOK_STR) {
	for (cvar = vars; cvar; cvar = cvar->next) {
	    if (strcmp(cvar->name,token->str) == 0) {
		term->offset = cvar->offset;
		term->shift = cvar->shift;
		term->mask = cvar->mask;
		ADVANCE;
		return;
	    }
	}
	parse_error("Not a known variable name.");
    }
    parse_error("Expecting a variable name.");
}

/* <lvalue> ::= <varref> | <varref>&<rvalue> */
void parse_lvalue(FW_Term *term)
{
    parse_varref(term);
    if (token->type == '&') {
	ADVANCE;
	term->mask &= parse_rvalue();
    }
}

int parse_op(FW_Term *term)
{
    if (token->type == TOK_NE) term->op = FW_NE;
    else if (token->type == '=') term->op = FW_EQ;
    else if (token->type == TOK_GE) term->op = FW_GE;
    else if (token->type == TOK_LE) term->op = FW_LE;
    else return 0;
    ADVANCE;
    return 1;
}

/* <term> ::= <lvalue> | !<lvalue> | <lvalue> <op> <rvalue> */
void parse_term(FW_Filter *filter)
{
    if (token->type == '!') {
	ADVANCE;
	parse_lvalue(&filter->terms[filter->count]);
	filter->terms[filter->count].op = FW_EQ;
	filter->terms[filter->count].test = 0;
    } else {
	parse_lvalue(&filter->terms[filter->count]);
	if (parse_op(&filter->terms[filter->count])) {
	    filter->terms[filter->count].test = parse_rvalue();
	} else {
	    filter->terms[filter->count].op = FW_NE;
	    filter->terms[filter->count].test = 0;
	}
    }
    filter->count++;
}

void parse_terms(FW_Filter *filter)
{
    if (token->type == TOK_STR && strcmp(token->str,"any") == 0)
	{ ADVANCE; return; }
    parse_term(filter);
    while (token->type == ',') { ADVANCE; parse_term(filter); }
}

void parse_prule(void *var, char **argv)
{
    FW_ProtocolRule prule;
    struct firewall_req req;
    tokenize("prule",3,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }
    parse_new_prule_name();
    parse_whitespace();
    parse_protocol_name(&prule);
    parse_whitespace();
    parse_prule_spec(&prule);
    free_tokens();
    nprules++;
    /* Save the prule in the kernel */
    req.unit = fwunit;
    req.fw_arg.rule = prule;
    ctl_firewall(IP_FW_APRULE,&req);
}


void parse_bringup(void *var, char **argv)
{
    FW_Filter filter;
    struct firewall_req req;
    init_filter(&filter);
    filter.type = FW_TYPE_BRINGUP;
    tokenize("bringup",3,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }
    parse_prule_name(&filter);
    parse_whitespace();
    parse_timeout(&filter);
    parse_whitespace();
    parse_terms(&filter);
    free_tokens();
    /* Save the filter in the kernel */
    req.unit = fwunit;
    req.fw_arg.filter = filter;
    ctl_firewall(IP_FW_AFILT,&req);
}

void parse_keepup(void *var, char **argv)
{
    FW_Filter filter;
    struct firewall_req req;
    init_filter(&filter);
    filter.type = FW_TYPE_KEEPUP;
    tokenize("keepup",3,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }
    parse_prule_name(&filter);
    parse_whitespace();
    parse_timeout(&filter);
    parse_whitespace();
    parse_terms(&filter);
    free_tokens();
    /* Save the filter in the kernel */
    req.unit = fwunit;
    req.fw_arg.filter = filter;
    ctl_firewall(IP_FW_AFILT,&req);
}

void parse_accept(void *var, char **argv)
{
    FW_Filter filter;
    struct firewall_req req;
    init_filter(&filter);
    filter.type = FW_TYPE_ACCEPT;
    tokenize("accept",3,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }
    parse_prule_name(&filter);
    parse_whitespace();
    parse_timeout(&filter);
    parse_whitespace();
    parse_terms(&filter);
    free_tokens();
    /* Save the filter in the kernel */
    req.unit = fwunit;
    req.fw_arg.filter = filter;
    ctl_firewall(IP_FW_AFILT,&req);
}

void parse_ignore(void *var, char **argv)
{
    FW_Filter filter;
    struct firewall_req req;
    init_filter(&filter);
    filter.type = FW_TYPE_IGNORE;
    tokenize("ignore",2,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }
    parse_prule_name(&filter);
    parse_whitespace();
    parse_terms(&filter);
    free_tokens();
    /* Save the filter in the kernel */
    req.unit = fwunit;
    req.fw_arg.filter = filter;
    ctl_firewall(IP_FW_AFILT,&req);
}

void parse_up(void *var, char **argv)
{
    FW_Filter filter;
    struct firewall_req req;
    init_filter(&filter);
    filter.type = FW_TYPE_UP;
    /* Save the filter in the kernel */
    req.unit = fwunit;
    req.fw_arg.filter = filter;
    ctl_firewall(IP_FW_AFILT,&req);
}

void parse_down(void *var, char **argv)
{
    FW_Filter filter;
    struct firewall_req req;
    init_filter(&filter);
    filter.type = FW_TYPE_DOWN;
    /* Save the filter in the kernel */
    req.unit = fwunit;
    req.fw_arg.filter = filter;
    ctl_firewall(IP_FW_AFILT,&req);
}

void parse_impulse(void *var, char **argv)
{
    int t1,t2;

    FW_Filter filter;
    struct firewall_req req;
    init_filter(&filter);
    filter.type = FW_TYPE_IMPULSE;
    tokenize("impulse",1,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }

    if (token->type != TOK_NUM)
	parse_error("Expecting a number.");
    sscanf(token->str,"%i",&t1);
    ADVANCE;
    if (token->type != ',')
	parse_error("Expecting a ','");
    ADVANCE;
    if (token->type != TOK_NUM)
	parse_error("Expecting a number.");
    sscanf(token->str,"%i",&t2);
    ADVANCE;
    if (token->type == ',') {
	filter.timeout2 = t1;
	filter.timeout = t2;
	ADVANCE;
	if (token->type != TOK_NUM)
	    parse_error("Expecting a number.");
	sscanf(token->str,"%i",&filter.fuzz);
	ADVANCE;
    } else {
	filter.timeout = t1;
	filter.timeout2 = t1;
	filter.fuzz = t2;
    }

    free_tokens();
    /* Save the filter in the kernel */
    req.unit = fwunit;
    req.fw_arg.filter = filter;
    ctl_firewall(IP_FW_AFILT,&req);
}

void parse_var(void *var, char **argv)
{
    struct var *variable = malloc(sizeof(struct var));
    if (variable == 0) { syslog(LOG_ERR,"Out of memory! AIIEEE!"); die(1); }
    tokenize("var",2,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }
    parse_var_name(variable);
    parse_whitespace();
    parse_varspec(variable);
    free_tokens();
    /* add the new variable to the linked list */
    variable->next = vars;
    vars = variable;
}

void flush_prules(void)
{
    struct firewall_req req;
    req.unit = fwunit;
    ctl_firewall(IP_FW_PFLUSH,&req);
    nprules = 0;
}

void flush_vars(void)
{
    struct var *next;
    for (; vars; vars = next) {
	next = vars->next;
	free(vars->name);
	free(vars);
    }
    vars = 0;
}

void flush_strvars(void)
{
    struct strvar *next;
    for (; strvars; strvars = next) {
	next = strvars->next;
	free(strvars->name);
	free(strvars->value);
	free(strvars);
    }
    strvars = 0;
}

void flush_filters(void)
{
    struct firewall_req req;
    req.unit = fwunit;
    ctl_firewall(IP_FW_FFLUSH,&req);
}

void parse_set(void *var, char **argv)
{
    struct strvar *v;

    tokenize("set",2,argv);
    if (setjmp(unwind)) { token = 0; free_tokens(); return; }

    if (token->type != TOK_STR) {
       parse_error("Expecting a variable name.");
    }

    /* Replace an existing strvar, or allocate a new one */
    for (v = strvars; v; v = v->next) {
	if (strcmp(v->name, token->str) == 0) {
	    free(v->value);
	    v->value = 0;
	    break;
	}
    }
    if (!v) {
	v = malloc(sizeof(struct strvar));
	v->name = strdup(token->str);
    }
    ADVANCE;
    parse_whitespace();
    if (!token->str) {
       parse_error("Expecting a variable value.");
    }
    v->value = strdup(token->str);
    ADVANCE;

    free_tokens();
    /* add the new variable to the linked list */
    v->next = strvars;
    strvars = v;
}

