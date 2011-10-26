/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* $Id$ */
#ifndef __SPO_PLUGBASE_H__
#define __SPO_PLUGBASE_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "event.h"
#include "decode.h"

#define NT_OUTPUT_ALERT   0x1  /* output node type alert */
#define NT_OUTPUT_LOG     0x2  /* output node type log */
#define NT_OUTPUT_SPECIAL 0x4  /* special output node type */

/***************************** Output Plugin API  *****************************/
typedef struct _OutputKeywordNode
{
    char *keyword;
    char node_type;
    void (*func)(char *);

} OutputKeywordNode;

typedef struct _OutputKeywordList
{
    OutputKeywordNode entry;
    struct _OutputKeywordList *next;

} OutputKeywordList;

typedef struct _OutputFuncNode
{
    void (*func)(Packet *, char *, void *, Event *);
    void *arg;
    struct _OutputFuncNode *next;

} OutputFuncNode;

void InitOutputPlugins();
int ActivateOutputPlugin(char *plugin_name, char *plugin_options);
void RegisterOutputPlugin(char *, int, void (*func)(u_char *));
OutputKeywordNode *GetOutputPlugin(char *plugin_name);
void DumpOutputPlugins();
void AddFuncToOutputList(void (*func) (Packet *, char *, void *, Event *),
        char node_type, void *arg);
void SetOutputList(void (*func) (Packet *, char *, void *, Event *),
        char node_type, void *arg);
/*************************** End Output Plugin API  ***************************/

#endif /* __SPO_PLUGBASE_H__ */
