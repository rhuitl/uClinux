/* ulogd_PCAP.c, Version $Revision: 699 $
 *
 * ulogd output target for writing pcap-style files (like tcpdump)
 *
 * FIXME: descr.
 * 
 *
 * (C) 2002 by Harald Welte <laforge@gnumonks.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id: ulogd_PCAP.c 699 2005-02-14 16:12:49Z laforge $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <pcap.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

#ifndef ULOGD_PCAP_DEFAULT
#define ULOGD_PCAP_DEFAULT	"/var/log/ulogd.pcap"
#endif

#ifndef ULOGD_PCAP_SYNC_DEFAULT
#define ULOGD_PCAP_SYNC_DEFAULT	0
#endif

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

static config_entry_t pcapf_ce = { 
	.key = "file", 
	.type = CONFIG_TYPE_STRING, 
	.options = CONFIG_OPT_NONE,
	.u = { .string = ULOGD_PCAP_DEFAULT }
};

static config_entry_t pcapsync_ce = { 
	.next = &pcapf_ce, 
	.key = "sync", 
	.type = CONFIG_TYPE_INT,
	.options = CONFIG_OPT_NONE,
	.u = { .value = ULOGD_PCAP_SYNC_DEFAULT }
};

static FILE *of = NULL;

struct intr_id {
	char* name;
	unsigned int id;		
};

#define INTR_IDS 	5
static struct intr_id intr_ids[INTR_IDS] = {
	{ "raw.pkt", 0 },
	{ "raw.pktlen", 0 },
	{ "ip.totlen", 0 },
	{ "oob.time.sec", 0 },
	{ "oob.time.usec", 0 },
};

#define GET_VALUE(x)	ulogd_keyh[intr_ids[x].id].interp->result[ulogd_keyh[intr_ids[x].id].offset].value
#define GET_FLAGS(x)	ulogd_keyh[intr_ids[x].id].interp->result[ulogd_keyh[intr_ids[x].id].offset].flags

static int pcap_output(ulog_iret_t *res)
{
	struct pcap_pkthdr pchdr;

	pchdr.caplen = GET_VALUE(1).ui32;
	pchdr.len = GET_VALUE(2).ui32;

	if (GET_FLAGS(3) & ULOGD_RETF_VALID
	    && GET_FLAGS(4) & ULOGD_RETF_VALID) {
		pchdr.ts.tv_sec = GET_VALUE(3).ui32;
		pchdr.ts.tv_usec = GET_VALUE(4).ui32;
	} else {
		/* use current system time */
		gettimeofday(&pchdr.ts, NULL);
	}

	if (fwrite(&pchdr, sizeof(pchdr), 1, of) != 1) {
		ulogd_log(ULOGD_ERROR, "Error during write: %s\n",
			  strerror(errno));
		return 1;
	}
	if (fwrite(GET_VALUE(0).ptr, pchdr.caplen, 1, of) != 1) {
		ulogd_log(ULOGD_ERROR, "Error during write: %s\n",
			  strerror(errno));
		return 1;
	}

	if (pcapf_ce.u.value)
		fflush(of);

	return 0;
}

/* stolen from libpcap savefile.c */
#define LINKTYPE_RAW            101
#define TCPDUMP_MAGIC	0xa1b2c3d4

static int write_pcap_header(void)
{
	struct pcap_file_header pcfh;
	int ret;

	pcfh.magic = TCPDUMP_MAGIC;
	pcfh.version_major = PCAP_VERSION_MAJOR;
	pcfh.version_minor = PCAP_VERSION_MINOR;
	pcfh.thiszone = timezone;
	pcfh.sigfigs = 0;
	pcfh.snaplen = 64 * 1024; /* we don't know the length in advance */
	pcfh.linktype = LINKTYPE_RAW;

	ret =  fwrite(&pcfh, sizeof(pcfh), 1, of);
	fflush(of);

	return ret;
}
	
/* get all key id's for the keys we are intrested in */
static int get_ids(void)
{
	int i;
	struct intr_id *cur_id;

	for (i = 0; i < INTR_IDS; i++) {
		cur_id = &intr_ids[i];
		cur_id->id = keyh_getid(cur_id->name);
		if (!cur_id->id) {
			ulogd_log(ULOGD_ERROR, 
				"Cannot resolve keyhash id for %s\n", 
				cur_id->name);
			return 1;
		}
	}	
	return 0;
}

void append_create_outfile(void) {
	struct stat st_dummy;
	int exist = 0;

	if (stat(pcapf_ce.u.string, &st_dummy) == 0 && st_dummy.st_size > 0) {
		exist = 1;
	}

	if (!exist) {
		of = fopen(pcapf_ce.u.string, "w");
		if (!of) {
			ulogd_log(ULOGD_FATAL, "can't open pcap file: %s\n",
				  strerror(errno));
			exit(2);
		}
		if (!write_pcap_header()) {
			ulogd_log(ULOGD_FATAL, "can't write pcap header: %s\n",
				  strerror(errno));
			exit(2);
		}
	} else {
		of = fopen(pcapf_ce.u.string, "a");
		if (!of) {
			ulogd_log(ULOGD_FATAL, "can't open pcap file: %s\n", 
				strerror(errno));
			exit(2);
		}		
	}
}

static void pcap_signal_handler(int signal)
{
	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "pcap: reopening capture file\n");
		fclose(of);
		append_create_outfile();
		break;
	default:
		break;
	}
}

static int pcap_init(void)
{
	/* FIXME: error handling */
	config_parse_file("PCAP", &pcapsync_ce);

#ifdef DEBUG_PCAP
	of = stdout;
#else
	append_create_outfile();
#endif
	return 0;
}

static void pcap_fini(void)
{
	if (of)
		fclose(of);
}

static ulog_output_t pcap_op = {
	.name = "pcap", 
	.init = &pcap_init,
	.fini = &pcap_fini,
	.output = &pcap_output,
	.signal = &pcap_signal_handler,
};

void _init(void)
{
	if (get_ids()) {
		ulogd_log(ULOGD_ERROR, "can't resolve all keyhash id's\n");
	}

	register_output(&pcap_op);
}
