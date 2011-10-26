/*
 * $Id: file_reg.h,v 1.1.1.1 2002/03/28 00:02:55 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in FILE_REG.C are declared here.
 *
 */

#ifndef FILE_REG_INCLUDED
#define FILE_REG_INCLUDED

int reg_validation(char *key1, char *key2, char *name, char *validation);
void hot_reg(char *block);
void parse_reg_key();

#endif
