/*
 * crunchfc.c
 *
 * $Id: crunchfc.c,v 1.1 2006/02/13 09:58:08 andrzej Exp $
 *
 * Redboot Flash Configuration parser. 
 * Configuration parsing routines. 
 *
 * Copyright (C) 2006 Ekiert sp z o.o.
 * Author: Andrzej Ekiert <a.ekiert@ekiert.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version. 
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "crunchfc.h"
#include "ftypes.h"
#include "crc.h"
#include "debug.h"

/*
 * RedBoot configuration layout is the following: 
 *  0 to 3         : len
 *  4 to 7         : CONFIG_KEY1
 *  8 to len-9     : data
 *  len-8 to len-5 : CONFIG_KEY2
 *  len-4 to len-1 : checksum
 *
 * Tested with RedBoot v. 2.02
 */
#define CONFIG_KEY1    0x0BADFACE
#define CONFIG_KEY2    0xDEADDEAD

/*
 * Each data item is variable length, with the name, type and dependencies
 * encoded into the object.
 *  offset   contents
 *       0   data type
 *       1   length of name (N)
 *       2   enable sense
 *       3   length of enable key (M)
 *       4   key name
 *     N+4   enable key
 *   M+N+4   data value
 */

/*
 * Fix 32-bit number endianness. 
 */
static inline void fix_endian32(void *vptr, uint8_t swab)
{
	uint8_t *ptr = (uint8_t*)vptr;
	uint8_t tmp;
	if (!swab) {
		return;
	}
	tmp = *ptr;
	*ptr = *(ptr+3);
	*(ptr+3) = tmp;
	tmp = *(ptr+1);
	*(ptr+1) = *(ptr+2);
	*(ptr+2) = tmp;
}

/*
 * Configuration key description. 
 */
struct fconfig_key {
	uint8_t type;
	uint8_t namelen, ensense, enlen;
	uint8_t *keyname;
	uint8_t *enkey;
	uint8_t *dataval;
};

/*
 * Fill-in the key description structure. 
 *
 * 'ptr' should point to the start of key data. There MUST BE at least 4 more 
 * bytes in the buffer (and there should be more, if start address is valid). 
 */
static uint8_t *get_key(uint8_t *ptr, struct fconfig_key *key)
{
	key->type = *ptr++;
	key->namelen = *ptr++;
	key->ensense = *ptr++;
	key->enlen = *ptr++;
	key->keyname = ptr;
	ptr += key->namelen;
	key->enkey = ptr;
	ptr += key->enlen;

	/* Be warned: 'dataval' may be an odd pointer and may contain 
	 * an uint32_t. If the pointer is odd, then uint32_t will be unaligned.
	 * Never try to cast it: *(uint32_t*)key->dataval. On many architectures 
	 * this will not work.
	 */
	key->dataval = ptr;

	if (!verify_ftype(key->type)) {
		MESSAGE(VERB_LOW, "Unsupported type: %d\n", key->type);
		return NULL;
	}

	ptr += TYPE_SIZE(key->type);

	return ptr;
}

/*
 * Print key data to the screen. 
 * It is assumed that key has been filled-in by get_key(). 
 */
static void print_key(struct fconfig_key *key, uint8_t verb, uint8_t swab)
{
	uint8_t buf[MAX_TYPE_SIZE];
	printer_t printer;

	MESSAGE(verb, "\n");
	MESSAGE(verb, "Name length: %d\n", key->namelen);
	MESSAGE(verb, "Enable sense: %d\n", key->ensense);
	if (key->ensense==0) {
		MESSAGE(verb, "Enable key length: %d\n", key->enlen);
		MESSAGE(verb, "Enable key: %s\n", key->enkey);
	}
	MESSAGE(verb, "Key name: %s\n", key->keyname);
	MESSAGE(verb, "Value: ");
	if (verb <= verbosity) {
		memcpy(buf, key->dataval, TYPE_SIZE(key->type));
		switch (key->type) {
		case CONFIG_BOOL : 
		case CONFIG_INT : 
			fix_endian32(buf, swab);
			break;
		default : 
			break;
		}
		printer = TYPE_PRINTER(key->type);
		if (printer) {
			printer(buf);
		}
	}
	MESSAGE(verb, "\n");
}

/*
 * Find the address, where a key with given 'nickname' starts. 
 * 'data' should have been previously validated with verify_fconfig(). 
 */
static uint8_t *locate_key(struct config_data *data, uint8_t *nickname)
{
	struct fconfig_key key;
	uint32_t len = data->reallen;
	uint8_t *keyptr = NULL;
	uint8_t *ptr = data->buf+8;
	uint8_t *ptrend = data->buf+len-9;

	while (ptr < ptrend-4) {
		keyptr = ptr;
		ptr = get_key(ptr, &key);
		if (ptr == NULL) {
			MESSAGE(VERB_LOW, "Error in structure\n");
			return NULL;
		}
		if (ptr > ptrend) {
			MESSAGE(VERB_LOW, "Parser went out of struct!\n");
			return NULL;
		}

		if ((key.type == 0) && (key.namelen==0)) {
			MESSAGE(VERB_NORMAL, "EOF reached - key not found\n");
			return NULL;
		}
		
		if (strncmp(nickname, key.keyname, key.namelen) == 0) {
			break;
		}
	}
	return keyptr;
}

/*
 * Verify the correctness of the configuration structure. 
 */
static int8_t buf_check(struct config_data *data)
{
	struct fconfig_key key;
	uint32_t len = data->reallen;
	uint8_t *ptr = data->buf+8;
	uint8_t *ptrend = data->buf+len-9;

	while (ptr < ptrend-4) {
		ptr = get_key(ptr, &key);
		if (ptr == NULL) {
			MESSAGE(VERB_LOW, "Error in structure\n");
			return -1;
		}
		if (ptr > ptrend) {
			MESSAGE(VERB_LOW, "Parser went out of struct!\n");
			return -1;
		}

		if ((key.type == 0) && (key.namelen==0)) {
			MESSAGE(VERB_HIGH, "EOF reached - structure OK\n");
			return 0;
		}
		print_key(&key, VERB_HIGH, data->swab);
	}
	return 0;
}

/*
 * Check whether given buffer contains something that looks mostly like 
 * a valid configuration. Try to automatically tell what the endianness is. 
 *
 * You must call this function before doing anything else to the 'data' buffer.
 */
int8_t verify_fconfig(struct config_data *data)
{
	uint32_t len;
	uint32_t key;
	uint32_t crc;
	uint32_t maxlen;
	uint8_t *buf;
	uint8_t swab;

	buf = data->buf;
	maxlen = data->maxlen;

	for (swab = 0; swab < 2; swab++) {
		memcpy(&key, buf+4, sizeof(key));
		fix_endian32(&key, swab);
		if (key == CONFIG_KEY1) {
			break;
		}
	}
	if (swab == 0) {
		MESSAGE(VERB_HIGH, "Using native endianness\n");
	} else if (swab == 1) {
		MESSAGE(VERB_HIGH, "Using non-native endianness\n");
	} else {
		MESSAGE(VERB_NORMAL, "Key1 is not valid, terminating\n");
		return -1;
	}

	memcpy(&len, buf, sizeof(len));
	fix_endian32(&len, swab);

	MESSAGE(VERB_NORMAL, "Data length is %d, maxlen is %d\n", 
							len, maxlen);
	if (len > maxlen) {
		MESSAGE(VERB_NORMAL, "This is too long.\n");
		return -1;
	}

	memcpy(&key, buf+len-8, sizeof(key));
	fix_endian32(&key, swab);
	if (key != CONFIG_KEY2) {
		MESSAGE(VERB_NORMAL, "Key2 is not valid, terminating\n");
		return -1;
	}

	/* verify crc... */
	memcpy(&crc, buf+len-4, sizeof(crc));
	fix_endian32(&crc, swab);
	if (crc != crc32(buf, len-4)) {
		MESSAGE(VERB_NORMAL, "CRC verification failed.\n");
		return -1;
	}
	MESSAGE(VERB_NORMAL, "CRC is valid.\n");

	data->swab = swab;
	data->reallen = len;

	if (buf_check(data)) {
		MESSAGE(VERB_NORMAL, "Configuration structure is broken.\n");
		return -1;
	}

	return 0;
}

/*
 * Find a key with given nickname, check its type and print value
 * Assumes that verify_fconfig() has been called on 'data' before. 
 */
int8_t get_key_value(struct config_data *data, uint8_t *nickname)
{
	printer_t printer;
	struct fconfig_key key;
	uint8_t *ptr; 

	ptr = locate_key(data, nickname);
	if (ptr == NULL) {
		MESSAGE(VERB_LOW, "Unknown key.\n");
		return -1;
	}
	if (get_key(ptr, &key) == NULL) {
		MESSAGE(VERB_LOW, "Erroneous key.\n");
		return -1;
	}
	print_key(&key, VERB_HIGH, data->swab);

	printer = TYPE_PRINTER(key.type);
	if (printer == NULL) {
		MESSAGE(VERB_LOW, "Printer missing for type %d\n", key.type);
		return -1;
	}	
	printer(key.dataval);
	return 0;
}

/*
 * Find a key with given nickname, check its type and set value
 * Assumes that verify_fconfig() has been called on 'data' before. 
 */
int8_t set_key_value(struct config_data *data, uint8_t *nickname, void *value)
{
	uint32_t offset;
	uint8_t buf[MAX_TYPE_SIZE];
	parser_t parser;
	struct fconfig_key key;
	uint8_t *ptr; 

	ptr = locate_key(data, nickname);
	if (ptr == NULL) {
		MESSAGE(VERB_LOW, "Unknown key.\n");
		return -1;
	}
	if (get_key(ptr, &key) == NULL) {
		MESSAGE(VERB_LOW, "Erroneous key.\n");
		return -1;
	}

	MESSAGE(VERB_NORMAL, "\nBefore change:");
	print_key(&key, VERB_NORMAL, data->swab);
	
	parser = TYPE_PARSER(key.type);
	if (parser == NULL) {
		MESSAGE(VERB_LOW, "Parser missing for type %d\n", key.type);
		return -1;
	}

	memset(buf, 0, MAX_TYPE_SIZE);
	if (parser(value, buf)) {
		MESSAGE(VERB_LOW, "Bad value.\n");
		return -1;
	}

	offset = (uint32_t)(key.dataval - data->buf);
	MESSAGE(VERB_HIGH, "Writing %d bytes at offset %d\n", 
		TYPE_SIZE(key.type), offset);

	/* do an actual write to the device or file */
	if (lseek(data->fd, offset, SEEK_SET) == -1) {
		MESSAGE(VERB_LOW, "lseek() failed\n");
		return -1;
	}	
	if (write(data->fd, buf, TYPE_SIZE(key.type)) == -1) {
		MESSAGE(VERB_LOW, "write() failed\n");
		return -1;
	}
	/* keep our buffer in sync with the device or file */
	memcpy(key.dataval, buf, TYPE_SIZE(key.type));

	MESSAGE(VERB_NORMAL, "\nAfter change:");
	print_key(&key, VERB_NORMAL, data->swab);

	return 0;
}

/*
 * Recalculate the checksum of a configuration buffer. 
 * Assumes that verify_fconfig() has been called on 'data' before. 
 */
void recalculate_crc(struct config_data *data)
{
	uint32_t len;
	uint32_t crc;
	uint8_t *buf;
	uint8_t swab;

	len = data->reallen;
	buf = data->buf;
	swab = data->swab;

	/* Show old */
	memcpy(&crc, buf+len-4, sizeof(crc));
	fix_endian32(&crc, swab);	
	MESSAGE(VERB_NORMAL, "Old CRC: %04x\n", crc);

	/* Set new */
	crc = crc32(buf, len-4);
	fix_endian32(&crc, swab);

	MESSAGE(VERB_HIGH, "Writing CRC at offset %d\n", len-4);

	/* do an actual write to the device or file */
	if (lseek(data->fd, len-4, SEEK_SET) == -1) {
		MESSAGE(VERB_LOW, "CRC: lseek() failed\n");
		return;
	}
	if (write(data->fd, &crc, sizeof(crc)) == -1) {
		MESSAGE(VERB_LOW, "CRC: write() failed\n");
		return;
	}
	/* keep our buffer in sync with the device or file */
	memcpy(buf+len-4, &crc, sizeof(crc));

	/* Show new */
	memcpy(&crc, buf+len-4, sizeof(crc));
	fix_endian32(&crc, swab);
	MESSAGE(VERB_NORMAL, "New CRC: %04x\n", crc);
}

