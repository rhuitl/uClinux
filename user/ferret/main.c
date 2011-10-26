/* Copyright (c) 2007 by Errata Security */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "ferret.h"
#include "formats.h"
#include "netframe.h"
#include "protos.h"

#include "pcap.h"

pcap_if_t *alldevs;

/* PCAP file-format

 0  32-bits - "magic number"
 4  16-bits - major version
    16-bits - minor version
 8  32-bits - timezone offset (should be zero)
12  32-bits - time stamp accuracy (should be zero)
16  32-bits - snap/slice length (maximum packet size)
20  32-bits - link layer type

Magic number:
	a1 b2 c3 d4 = big-endian
	d4 c3 b2 a1 = little-endian

Version:
	2.4 = most common version

Timezone offset, Timestamp accuracy:
	these fields are no longer used

Link-layer type:
	0		BSD loopback devices, except for later OpenBSD
	1		Ethernet, and Linux loopback devices
	6		802.5 Token Ring
	7		ARCnet
	8		SLIP
	9		PPP
	10		FDDI
	100		LLC/SNAP-encapsulated ATM
	101		"raw IP", with no link
	102		BSD/OS SLIP
	103		BSD/OS PPP
	104		Cisco HDLC
	105		802.11
	108		later OpenBSD loopback devices (with the AF_
			value in network byte order)
	113		special Linux "cooked" capture
	114		LocalTalk


*/
/*

802.11 
 	11	 *  802.11b - 11-mbps
 	12	 *  802.11d - operation in multiple regulatory domains 
 	13	 *  802.11e - wireless multimedia extensions 
 	14	 *  802.11g - 54-mbps
 	15	 *  802.11h - power management 
 	16	 *  802.11i - MAC security enhancements  

 */

FILE *fpOut = NULL;

struct CapFile
{
	int byte_order;
	int protocol;
	int frame_number;
};
#define CAPFILE_BIGENDIAN		1
#define CAPFILE_LITTLEENDIAN	2
#define CAPFILE_ENDIANUNKNOWN	3

int debug=0;

void FRAMERR(struct NetFrame *frame, const char *msg, ...)
{
	va_list marker;

	if (debug==0)
		return;

	va_start(marker, msg);

	fprintf(stderr, "%s(%d): ", frame->filename, frame->frame_number);

	vfprintf(stderr, msg, marker);

	va_end(marker);
}



void process_frame(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	switch (frame->protocol) {
	case 1:
		process_ethernet_frame(seap, frame, px, length);
		break;
	case 0x7f:
		break;
	case 0x69: /* WiFi */
		process_wifi_frame(seap, frame, px, length);
		break;
	default:
		FRAMERR(frame, "unknown cap file protocol = %d (expected Ethernet or wifi)\n", frame->protocol);
		break;
	}
}

unsigned PCAP16(struct CapFile *capfile, unsigned char *buf)
{
	switch (capfile->byte_order) {
	case CAPFILE_BIGENDIAN: return ex16be(buf);
	case CAPFILE_LITTLEENDIAN: return ex16le(buf);
	default: return 0xa3a3;
	}
}
unsigned PCAP32(struct CapFile *capfile, unsigned char *buf)
{
	switch (capfile->byte_order) {
	case CAPFILE_BIGENDIAN: return ex32be(buf);
	case CAPFILE_LITTLEENDIAN: return ex32le(buf);
	default: return 0xa3a3;
	}
}

void pcapHandlePacket(unsigned char *v_seap, 
    const struct pcap_pkthdr *framehdr, const unsigned char *buf)
{
	static struct NetFrame frame[1] = {0};
	struct Seaper *seap = (struct Seaper*)v_seap;

	seap->something_found = 0;

	frame->filename = "live";
	frame->protocol = seap->linktype;
	frame->frame_number++;
	
	frame->time_secs = framehdr->ts.tv_sec;
	frame->time_usecs = framehdr->ts.tv_usec;
	frame->original_length = framehdr->caplen;
	frame->captured_length = framehdr->caplen;
	frame->protocol = seap->linktype;	

	process_frame(seap, frame, buf, frame->captured_length);

}

void process_live(struct Seaper *seap, const char *devicename)
{
    int traffic_seen = FALSE;
    int total_packets_processed = 0;
    pcap_t *hPcap;
    char errbuf[1024];

    hPcap = pcap_open_live(    (char*)devicename,
                            2000,    /*snap len*/
                            1,        /*promiscuous*/
                            10,        /*10-ms read timeout*/
                            errbuf
                            );
    if (hPcap == NULL) {
        fprintf(stderr, "%s: %s\n", devicename, errbuf);
        return;
    }

	seap->linktype = pcap_datalink(hPcap);

	printf("SNIFFING: %s\n", devicename);
	printf("LINKTYPE: %d\n", seap->linktype);

    /* Pump packets through it */
    for (;;) {
        int packets_read;
        
        packets_read = pcap_dispatch(
                                hPcap, /*handle to PCAP*/
                                10,        /*next 10 packets*/
                                pcapHandlePacket, /*callback*/
                                (unsigned char*)seap
                                );
        total_packets_processed += packets_read;
        if (!traffic_seen && total_packets_processed > 0) {
            fprintf(stderr, "Traffic seen\n");
            traffic_seen = TRUE;
        }
    }

    /* Close the file and go onto the next one */
    pcap_close(hPcap);

}

int process_file(struct Seaper *seap, const char *capfilename)
{
	struct CapFile capfile[1] = {0};
	FILE *fp;
	unsigned char buf[2048];
	int bytes_read;

	/* if no file, open interface */
	if (capfilename[0] == '-') {
		switch (capfilename[1]) {
		case 'd':
			debug++;
			break;
		case 'i':
			if (capfilename[2] == '\0') {
				char *devicename;
				char errbuf[1024];
				devicename = pcap_lookupdev(errbuf);
				if (devicename == NULL)
					fprintf(stderr, "%s\n", errbuf);
				else
					process_live(seap, devicename);
			} else if (isdigit(capfilename[2])) {
				pcap_if_t *d;
				int i=0;
				int inum = strtol(capfilename+2,0,0);

				for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

				process_live(seap, d->name);

			} else {
				process_live(seap, capfilename+2);
			}
			break;
		default:
			break;

		}
		return 0;
	}

	fp = fopen(capfilename, "rb");
	if (fp == NULL) {
		perror(capfilename);
		return -1;
	}

	; //printf("%s: processing...\n", capfilename);

	bytes_read = fread(buf, 1, 24, fp);
	if (bytes_read < 24) {
		if (bytes_read < 0)
			perror(capfilename);
		else if (bytes_read == 0)
			fprintf(stderr, "%s: file empty\n", capfilename);
		else
			fprintf(stderr, "%s: file too short\n", capfilename);
		fclose(fp);
		return -1;
	}

	/* PCAP: Magic Number */
	switch (ex32be(buf)) {
	case 0xa1b2c3d4:	capfile->byte_order = CAPFILE_BIGENDIAN; break;
	case 0xd4c3b2a1:	capfile->byte_order = CAPFILE_LITTLEENDIAN; break;
	default:
		fprintf(stderr, "%s: unknown byte-order in cap file\n");
		capfile->byte_order = CAPFILE_ENDIANUNKNOWN; break;
	}

	/* Version */
	{
		unsigned major = PCAP16(capfile, buf+4);
		unsigned minor = PCAP16(capfile, buf+6);
		
		if (major != 2 || minor != 4)
			fprintf(stderr, "%s: unknown version %d.%d\n", capfilename, major, minor);
	}

	/* Protocol */
	capfile->protocol = ex32le(buf+20);
	switch (capfile->protocol) {
	case 0x7f:
		fclose(fp);
		return -1;
		break;
	case 0x69: /* WiFi */
	case 0x01: /*ethernet*/
		break;
	default:
		fprintf(stderr, "%s: unknown cap file protocol = %d (expected Ethernet or wifi)\n", capfilename, capfile->protocol);
		fclose(fp);
		return -1;
		break;
	}

	for (;;) {
		struct NetFrame frame[1] = {0};
		unsigned char header[16];

		seap->something_found = 0;

		frame->filename = capfilename;
		frame->protocol = capfile->protocol;
		frame->frame_number = ++ capfile->frame_number;

		bytes_read = fread(header, 1, 16, fp);
		if (bytes_read < 16) {
			if (bytes_read < 0)
				perror(capfilename);
			else if (bytes_read == 0)
				; //fprintf(stderr, "%s: end-of-file\n", capfilename);
			else
				fprintf(stderr, "%s: premature end of file\n", capfilename);
			break;
		}

		frame->time_secs = PCAP32(capfile, header);
		frame->time_usecs = PCAP32(capfile, header+4);
		frame->original_length = PCAP32(capfile, header+8);
		frame->captured_length = PCAP32(capfile, header+12);

		if (frame->captured_length > sizeof(buf)) {
			printf("%s: frame too big\n", capfilename);
			bytes_read = fread(buf, 1, sizeof(buf), fp);
			if (bytes_read >= sizeof(buf)) {
				char c;
				int bytes_left;
				
				bytes_left = frame->captured_length - sizeof(buf);
				frame->captured_length = sizeof(buf);
				while (bytes_left) {
					bytes_read = fread(&c, 1, 1, fp);
					if (bytes_read < 1)
						break;
					bytes_left--;
				}
			}
		} else
			bytes_read = fread(buf, 1, frame->captured_length, fp);
		if (bytes_read < frame->captured_length) {
			if (bytes_read < 0)
				perror(capfilename);
			else
				fprintf(stderr, "%s: premature end of file\n", capfilename);
			break;
		}

		process_frame(seap, frame, buf, frame->captured_length);

		if (fpOut && seap->something_found) {
			fwrite(header, 1, 16, fpOut);
			fwrite(buf, 1, frame->captured_length, fpOut);
			fflush(fpOut);
		}
	}


	fclose(fp);
	seaper_dump(seap, capfilename);

	return 0;
}

struct Seaper seap[1] = {0};
int main(int argc, char **argv)
{
	int i;
	char errbuf[PCAP_ERRBUF_SIZE];

	//fpOut = fopen("sample2.pcap", "wb");

	if (fpOut) {
		fwrite(
		"\xd4\xc3\xb2\xa1\x02\x00\x04\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\xff\xff\x00\x00\x69\x00\x00\x00",
		1,
		24,
		fpOut);
	}

	printf("-- FERRET 1.0 - 2007 (c) Errata Security ---\n");

	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) != -1)
	{
		pcap_if_t *d;
		i=0;

		/* Print the list */
		if (argc==1)
		for(d=alldevs; d; d=d->next)
		{
			printf("%d. %s", ++i, d->name);
			if (d->description)
				printf(" (%s)\n", d->description);
			else
				printf(" (No description available)\n");
		}
	}


	if (argc <= 1) {
		printf("\nUsage:\n ferret -i<num>, where <num> is an interface to monitor\n");
		printf(" ferret <packet-capture> <packet-capture> ..., for offline analysis\n");
		return 0;
	}

	for (i=1; i<argc; i++) {
		memset(seap, 0, sizeof(*seap));
		process_file(seap, argv[i]);
	}

	return 0;
}