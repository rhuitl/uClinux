/* Copyright (c) 2007 by Errata Security */
#include "ferret.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "formats.h"
#include "netframe.h"
char scrubbed[4096];

static FILE *fpseap;

#define MAX_DEPTH 12

void dump_names(struct SeapName *names, char *path, int depth);

void dump_values(struct SeapValue *values, char *path, int depth)
{
	int i;
	unsigned path_offset = strlen(path);

	for (i=0; values; i++, values = values->next) {
		unsigned j,k;

		for (j=0, k=0; j<values->length && k<sizeof(scrubbed)-2; j++) {
			if (values->value[j] == '\"')
				;
			else if (values->value[j] == '\'')
				;
			else if (values->value[j] == '\\') {
				scrubbed[k++] = '\\';
				scrubbed[k++] = '\\';
			} else
				scrubbed[k++] = values->value[j];
		}
		scrubbed[k] = '\0';

		sprintf(path+path_offset, "[%d]", i);

		fprintf(fpseap, "%s = new Array;\n", path);
		fprintf(fpseap, "%s[x] = '%s';\n", path, scrubbed);
		if (values->names && depth < MAX_DEPTH) {
			unsigned o = strlen(path);
			strcat(path, "[y]");

			fprintf(fpseap, "%s = new Array;\n", path);
			dump_names(values->names, path, depth+1);
			path[o] = '\0';
		}
	}

	path[path_offset] = '\0';
}

void dump_names(struct SeapName *names, char *path, int depth)
{
	int i;
	unsigned path_offset = strlen(path);

	for (i=0; names; i++, names = names->next) {
		int j,k;

		for (j=0, k=0; names->name[j] && k<sizeof(scrubbed)-2; j++) {
			if (names->name[j] == '\"')
				;
			else if (names->name[j] == '\'')
				;
			else if (names->name[j] == '\\') {
				scrubbed[k++] = '\\';
				scrubbed[k++] = '\\';
			} else
				scrubbed[k++] = names->name[j];
		}
		scrubbed[k] = '\0';

		sprintf(path+path_offset, "[%d]", i);

		fprintf(fpseap, "%s = new Array;\n", path);
		fprintf(fpseap, "%s[x] = '%s';\n", path, scrubbed);
		if (names->values && depth < MAX_DEPTH) {
			unsigned o = strlen(path);
			strcat(path, "[y]");

			fprintf(fpseap, "%s = new Array;\n", path);
			dump_values(names->values, path, depth+1);
			path[o] = '\0';
		}
	}

	path[path_offset] = '\0';
}
void seaper_dump(struct Seaper *seap, const char *capfilename)
{
	char path[50000];
	FILE *fp;
	const char *trailer="</head>\n"
"<body onLoad=\"init();\">\n"
"<h1>FERRET: prototype</h1>\n"
"<div id=\"treeDiv1\"></div>\n"
"</body>\n"
"</html>\n";

	sprintf(path, "%s.html", capfilename);
	fpseap = fopen(path, "w");

	fp = fopen("header.html", "r");
	if (fp == NULL)
		perror("header.html");
	else {
		char buf[100];

		while (fgets(buf, sizeof(buf),fp)) {
			fwrite(buf,1,strlen(buf),fpseap);
		}
		fclose(fp);
	}

	fprintf(fpseap, "<script>\n");
	fprintf(fpseap, "var x = 'caption';\n");
	fprintf(fpseap, "var y = 'children';\n");

	fprintf(fpseap, "var a = new Array;\n");

	sprintf(path, "a");
	dump_names(seap->records, path, 0);
	
	fprintf(fpseap, "</script>\n");
	fwrite(trailer, 1, strlen(trailer), fpseap);
	fclose(fpseap);
}
static unsigned count_digits(unsigned __int64 n)
{
	int i=0;
	for (i=0; n; i++)
		n = n/10;

	return i;
}
static void format_unsigned(char *buf, unsigned length, unsigned *r_offset, unsigned __int64 num)
{
	unsigned digits = count_digits(num);
	unsigned new_offset;

	if (*r_offset >= length)
		return;
	if (*r_offset + 1 >= length) {
		buf[(*r_offset)++] = '\0';
		return;
	}

	if (digits == 0) {
		buf[(*r_offset)++] = '0';
		buf[(*r_offset)] = '\0';
	} else {
		if (*r_offset + digits >= length) {
			memset(buf+*r_offset, '0', length-*r_offset);
			buf[length-1] = '\0';
			*r_offset = length;
			return;
		}

		buf[*r_offset+digits] = '\0';
		new_offset = *r_offset + digits;

		while (num) {
			buf[*r_offset + --digits] = (num%10)["01234567890"];
			num = num / 10;
		}
		
		*r_offset = new_offset;
	}
}

void process_record(struct Seaper *seap, ...)
{
	enum {MAX_RECORDS=100};
	int record_count;
	va_list marker;
	struct SeapName **r_name = &seap->records;
	int is_new_entry = 0;
	struct SeapName *namelist[MAX_RECORDS];
	struct SeapValue *valuelist[MAX_RECORDS];

	va_start(marker, seap);

	for (record_count=0; record_count<MAX_RECORDS; record_count++) {
		const char *name;
		const unsigned char *value;
		enum RECORD_FORMAT fmt;
		unsigned length;
		char valbuf[1024];
		unsigned vallen=0;

		name = va_arg(marker, char *);
		if (name == 0)
			break;

		fmt = va_arg(marker, int);
		
		value = va_arg(marker, unsigned char *);
		length = va_arg(marker, unsigned);


		switch (fmt) {
		case REC_FRAMESRC:
		case REC_FRAMEDST:
			{
				struct NetFrame *frame = (struct NetFrame *)value;

				if (frame->ipver == 6) {
					length = 16;
					if (fmt == REC_FRAMESRC)
						value = &frame->src_ipv6[0];
					else
						value = &frame->dst_ipv6[0];
					fmt = REC_IPv6;
				} else {
					length = 4;
					if (fmt == REC_FRAMESRC)
						value = (const unsigned char*)&frame->src_ipv4;
					else
						value = (const unsigned char*)&frame->dst_ipv4;
					fmt = REC_IPv4;
				}
			}
			break;
		}

		switch (fmt) {
		case REC_SZ:			/* zero-terminated string, length should be -1 */
			if (value == 0)
				value = (const unsigned char*)"";
			vallen = strlen((const char*)value);
			if (vallen> sizeof(valbuf)-3)
				vallen = sizeof(valbuf)-3;
			valbuf[0] = '\"';
			memcpy(valbuf+1, value, vallen);
			valbuf[vallen+1] = '\"';
			valbuf[vallen+2] = '\0';
			vallen += 2;
			break;
		case REC_PRINTABLE:	/* printable string, length should be length of the string */
			{
				unsigned i;

				if (value == 0)
					value = (const unsigned char*)"";
				vallen=0;
				valbuf[vallen++] = '\"';

				for (i=0; vallen<sizeof(valbuf)-6 && i<length; i++) {
					if (isprint(value[i]) && value[i] != '\"' && value[i] != '\\')
						valbuf[vallen++] = value[i];
					else {
						valbuf[vallen++] = '\\';
						valbuf[vallen++] = 'x';
						valbuf[vallen++] = "0123456789ABCDEF"[(value[i]>>4)&0x0F];
						valbuf[vallen++] = "0123456789ABCDEF"[(value[i]>>0)&0x0F];
					}
				}
				valbuf[vallen++] = '\"';
				valbuf[vallen] = '\0';
			}
			break;
		case REC_HEXSTRING:	/* printable string, length should be length of the string */
			{
				unsigned i;

				if (value == 0)
					value = (const unsigned char*)"";
				vallen=0;
				valbuf[vallen++] = '$';

				for (i=0; vallen<sizeof(valbuf)-6 && i<length; i++) {
					valbuf[vallen++] = "0123456789ABCDEF"[(value[i]>>4)&0x0F];
					valbuf[vallen++] = "0123456789ABCDEF"[(value[i]>>0)&0x0F];
				}
				valbuf[vallen] = '\0';
			}
			break;
		case REC_OID: /* asn.1 object identifer */
			{
				unsigned i=0;

				vallen = 0;
				while (vallen < sizeof(valbuf)-2 && i<length) {
					unsigned __int64 id=0;

					/* Grab the next id */
					while (i<length && value[i]&0x80) {
						id |= value[i]&0x7F;
						id <<= 7;
						i++;
					}
					id |= value[i++];

					/* Format the integer */
					if (vallen == 0) {
						format_unsigned(valbuf, sizeof(valbuf), &vallen, id/40);
						valbuf[vallen++] = '.';
						format_unsigned(valbuf, sizeof(valbuf), &vallen, id%40);
					} else {
						valbuf[vallen++] = '.';
						format_unsigned(valbuf, sizeof(valbuf), &vallen, id);
					}
				}
			}
			break;
		case REC_MACADDR:	/* MAC address, length should be 6 */
			_snprintf(valbuf, sizeof(valbuf), "[%02x:%02x:%02x:%02x:%02x:%02x]",
				value[0],
				value[1],
				value[2],
				value[3],
				value[4],
				value[5]
				);
			vallen = strlen(valbuf);
			break;
		case REC_IPv4:
			if (length == sizeof(unsigned)) {
				unsigned ip = *(unsigned*)value;
				_snprintf(valbuf, sizeof(valbuf), "[%d.%d.%d.%d]",
					(ip>>24)&0xFF,
					(ip>>16)&0xFF,
					(ip>> 8)&0xFF,
					(ip>> 0)&0xFF
					);
				vallen = strlen(valbuf);
			} else {
				fprintf(stderr, "unknown integer size");
				break;
			}
			break;
		case REC_IPv6:
			if (length == 16) {
				unsigned i;
				unsigned nulls=0;
				strcpy(valbuf, "[");

				for (i=0; i<8; i++) {
					unsigned n = ex16be(value+i*2);
					if (n == 0) {
						if (nulls == 0) {
							strcat(valbuf, ":");
							nulls = 1;
						} else if (nulls == 1)
							;
						else {
							_snprintf(valbuf+strlen(valbuf), sizeof(valbuf)-strlen(valbuf), ":%x", n);
						}
					} else {
						if (nulls == 1)
							nulls = 2;
						if (i==0)
							_snprintf(valbuf+strlen(valbuf), sizeof(valbuf)-strlen(valbuf), "%x", n);
						else
							_snprintf(valbuf+strlen(valbuf), sizeof(valbuf)-strlen(valbuf), ":%x", n);
					}
				}
				strcat(valbuf, "]");
				vallen = strlen(valbuf);
			} else {
				fprintf(stderr, "unknown integer size");
				break;
			}
			break;
		case REC_UNSIGNED:
			if (length == sizeof(unsigned)) {
				_snprintf(valbuf, sizeof(valbuf), "%u", *(unsigned*)value);
				vallen = strlen(valbuf);
			} else {
				fprintf(stderr, "unknown integer size");
				break;
			}
			break;
		case REC_HEX24:
			if (length == sizeof(unsigned)) {
				_snprintf(valbuf, sizeof(valbuf), "0x%03x", *(unsigned*)value);
				vallen = strlen(valbuf);
			} else {
				fprintf(stderr, "unknown integer size");
				break;
			}
			break;
		default:
			fprintf(stderr, "unknown record type\n");
			break;;
		}
		

		/* Insert record into list */
		while (*r_name != NULL && strcmp((*r_name)->name, name) != 0)
			r_name = &(*r_name)->next;
		if (*r_name == NULL) {
			*r_name = malloc(sizeof(**r_name));
			(*r_name)->name = (char*)name;
			(*r_name)->next = 0;
			(*r_name)->values = 0;
			is_new_entry++;
		}
		namelist[record_count] = *r_name;

		{
			struct SeapValue **r_value = &(*r_name)->values;
			while (*r_value != NULL && memcmp((*r_value)->value, valbuf, vallen) != 0)
				r_value = &(*r_value)->next;
			if (*r_value == NULL) {
				*r_value = malloc(sizeof(**r_value));
				(*r_value)->value = malloc(vallen+1);
				memcpy((*r_value)->value, valbuf, vallen);
				valbuf[vallen] = '\0';
				(*r_value)->length = vallen;
				(*r_value)->next = 0;
				(*r_value)->names = 0;
				is_new_entry++;
			}

			r_name = &(*r_value)->names;
			valuelist[record_count] = *r_value;
		}
	}

	if (is_new_entry) {
		int i;

		seap->something_found = 1;
		for (i=0; i<record_count; i++) {
			if (i>0)
				printf(", ");
			printf("%s=%.*s", namelist[i]->name, valuelist[i]->length, valuelist[i]->value);
			
		}
		printf("\n");
	}


	va_end(marker);
}
