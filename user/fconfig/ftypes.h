/*
 * ftypes.h
 *
 * $Id: ftypes.h,v 1.1 2006/02/13 09:58:08 andrzej Exp $
 *
 * Redboot Flash Configuration parser. 
 * Argument parsers - header. 
 *
 * Copyright (C) 2006 Ekiert sp z o.o.
 * Author: Andrzej Ekiert <a.ekiert@ekiert.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version. 
 */

#ifndef FTYPES_H
#define FTYPES_H

typedef int8_t (*parser_t)(uint8_t *text, void *buf);
typedef void (*printer_t)(void *buf);

/*
 * This is very unfortunate that RedBoot authors didn't encode these
 * constants in the configuration structure. 
 */
//CYGNUM_REDBOOT_FLASH_SCRIPT_SIZE
#define MAX_SCRIPT_LENGTH 512

//CYGNUM_REDBOOT_FLASH_STRING_SIZE
#define MAX_STRING_LENGTH 128

//CYGNUM_REDBOOT_FLASH_CONFIG_SIZE
#define MAX_CONFIG_DATA 4096

/*
 * RedBoot flash configuration type description. 
 */
#define MAX_TYPE_NAME 16
#define MAX_TYPE_SIZE MAX_CONFIG_DATA
typedef struct {
	uint8_t type_name[MAX_TYPE_NAME];
	int16_t type_size;
	parser_t parser;
	printer_t printer;
} type_t;

#define NUM_TYPES 8
extern type_t types[NUM_TYPES];

/* 
 * 'data type' field encoding 
 */
#define CONFIG_EMPTY   0
#define CONFIG_BOOL    1
#define CONFIG_INT     2
#define CONFIG_STRING  3
#define CONFIG_SCRIPT  4
#define CONFIG_IP      5
#define CONFIG_ESA     6
#define CONFIG_NETPORT 7

/*
 * Size assumptions (may not be valid for all platforms!): 
 *  - bool: assuming 4 bytes (might be 2)
 *  - int: assuming 4 bytes (might be 2)
 *  MAX_STRING_LENGTH and MAX_SCRIPT_LENGTH depend on RedBoot configuration
 *  and are not encoded anywhere within the structure. 
 */
#define SIZE_EMPTY 0
#define SIZE_BOOL 4
#define SIZE_INT 4
#define SIZE_STRING MAX_STRING_LENGTH 
#define SIZE_SCRIPT MAX_SCRIPT_LENGTH  
#define SIZE_IP 4
#define SIZE_ESA 8
#define SIZE_NETPORT MAX_STRING_LENGTH 

#define TYPE_NAME(index) (types[index].type_name)
#define TYPE_SIZE(index) (types[index].type_size)
#define TYPE_PARSER(index) (types[index].parser)
#define TYPE_PRINTER(index) (types[index].printer)

int8_t verify_ftype(uint8_t type);

int8_t parse_bool(uint8_t *text, void *buf);
int8_t parse_int(uint8_t *text, void *buf);
int8_t parse_script(uint8_t *text, void *buf);
int8_t parse_string(uint8_t *text, void *buf);
int8_t parse_ip(uint8_t *text, void *buf);
int8_t parse_esa(uint8_t *text, void *buf);
int8_t parse_netport(uint8_t *text, void *buf);

void print_bool(void *buf);
void print_int(void *buf);
void print_string(void *buf);
void print_script(void *buf);
void print_ip(void *buf);
void print_esa(void *buf);
void print_netport(void *buf);

#endif //FTYPES_H

