/*======================================================================

    Dump CardBus socket registers

    dump_cardbus.c 1.3 2001/06/04 23:32:05

    The contents of this file are subject to the Mozilla Public
    License Version 1.1 (the "License"); you may not use this file
    except in compliance with the License. You may obtain a copy of
    the License at http://www.mozilla.org/MPL/

    Software distributed under the License is distributed on an "AS
    IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
    implied. See the License for the specific language governing
    rights and limitations under the License.

    The initial developer of the original code is David A. Hinds
    <dahinds@users.sourceforge.net>.  Portions created by David A. Hinds
    are Copyright (C) 1999 David A. Hinds.  All Rights Reserved.

    Alternatively, the contents of this file may be used under the
    terms of the GNU Public License version 2 (the "GPL"), in which
    case the provisions of the GPL are applicable instead of the
    above.  If you wish to allow the use of your version of this file
    only under the terms of the GPL and not to allow others to use
    your version of this file under the MPL, indicate your decision
    by deleting the provisions above and replace them with the notice
    and other provisions required by the GPL.  If you do not delete
    the provisions above, a recipient may use your version of this
    file under either the MPL or the GPL.
    
======================================================================*/

#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "yenta.h"

/*====================================================================*/

typedef struct proc_cardbus {
    u_int	reg[16];
} proc_cardbus;

typedef struct proc_info {
    char	type[32];
    u_int	flags;
    int		psock;
    u_char	bus;
    u_char	devfn;
    u_char	cardbus;
} proc_info;

static proc_cardbus *load_cardbus(char *fn)
{
    FILE *f = fopen(fn, "r");
    static proc_cardbus cb;
    char s[50];
    int i, j;
    
    if (!f) return NULL;
    memset(&cb, 0, sizeof cb);
    for (i = 0; (i < 16) && !feof(f); i += 4) {
	fgets(s, 49, f);
	if (strlen(s) < 35) break;
	for (j = 0; j < 4; j++)
	    cb.reg[i+j] = strtoul(s + 9*j, NULL, 16);
    }
    fclose(f);
    return &cb;
}

#define NTAG 5
char *tag[] = { "type:", "psock:", "bus:", "devfn:", "cardbus:" };

static proc_info *load_info(char *fn)
{
    FILE *f = fopen(fn, "r");
    static proc_info in;
    char s[50];
    u_int i, a, b;
    
    if (!f) return NULL;
    memset(&in, 0, sizeof in);
    while (!feof(f)) {
	fgets(s, 49, f);
	for (i = 0; i < NTAG; i++)
	    if (strncmp(s, tag[i], strlen(tag[i])) == 0) break;
	switch (i) {
	case 0: strcpy(in.type, s+10); break;
	case 1: in.psock = strtoul(s+10, NULL, 10); break;
	case 2: in.bus = strtoul(s+10, NULL, 16); break;
	case 3:
	    sscanf(s+10, "%02x.%d", &a, &b);
	    in.devfn = (a<<3) | b;
	    break;
	case 4: in.cardbus = strtoul(s+10, NULL, 16);
	}
    }
    fclose(f);
    return &in;
}

/*====================================================================*/

static char *event[] = {
    "cstschg", "ccd1", "ccd2", "pwrcycle",
    "16bit", "32bit", "cint", "badcard",
    "datalost", "badvcc", "5Vcard", "3Vcard",
    "XVcard", "YVcard", "rsvd", "rsvd",
    "rsvd", "rsvd", "rsvd", "rsvd",
    "rsvd", "rsvd", "rsvd", "rsvd",
    "rsvd", "rsvd", "rsvd", "rsvd",
    "5Vsock", "3Vsock", "XVsock", "YVsock"
};

static void print_events(char *tag, u_int val)
{
    int i;
    printf("  %s:%*s 0x%08x", tag, 15-(int)strlen(tag), "", val);
    if (val)
	printf("\n   ");
    for (i = 0; i < 32; i++)
	if (val & (1<<i)) printf(" [%s]", event[i]);
    printf("\n");
}

/*====================================================================*/

static void dump_sock(proc_cardbus *cb, proc_info *in)
{
    u_int val;
    print_events("Socket Event", cb->reg[CB_SOCKET_EVENT>>2]);
    print_events("Socket Mask", cb->reg[CB_SOCKET_MASK>>2]);
    print_events("Socket State", cb->reg[CB_SOCKET_STATE>>2]);
    val = cb->reg[CB_SOCKET_CONTROL>>2];
    printf("  Socket Control:  0x%08x\n    [Vcc", val);
    switch (val & CB_SC_VCC_MASK) {
    case CB_SC_VCC_OFF:	printf(" off]"); break;
    case CB_SC_VCC_5V:	printf("=5v]"); break;
    case CB_SC_VCC_3V:	printf("=3.3v]"); break;
    case CB_SC_VCC_XV:	printf("=Xv]"); break;
    case CB_SC_VCC_YV:	printf("=Yv]"); break;
    }
    printf(" [Vpp");
    switch (val & CB_SC_VPP_MASK) {
    case CB_SC_VPP_OFF:	printf(" off]"); break;
    case CB_SC_VPP_5V:	printf("=5v]"); break;
    case CB_SC_VPP_3V:	printf("=3.3v]"); break;
    case CB_SC_VPP_XV:	printf("=Xv]"); break;
    case CB_SC_VPP_YV:	printf("=Yv]"); break;
    }
    if (val & CB_SC_CCLK_STOP)
	printf(" [stopclk]");
    printf("\n\n");
}

/*====================================================================*/

int main(int argc, char *argv[])
{
    char fn[100];
    int i;
    proc_info *in;
    proc_cardbus *cb;

    if (access("/proc/bus/pccard", R_OK) != 0)
	fprintf(stderr, "/proc/bus/pccard does not exist!\n");
    for (i = 0; ; i++) {
	sprintf(fn, "/proc/bus/pccard/%02d/cardbus", i);
	if (access(fn, R_OK) != 0)
	    break;
	cb = load_cardbus(fn);
	sprintf(fn, "/proc/bus/pccard/%02d/info", i);
	in = load_info(fn);
	printf("Socket %d:\n", i);
	dump_sock(cb, in);
    }
    return 0;
}
