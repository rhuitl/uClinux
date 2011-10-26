/*
 * ftpp_ui_server_lookup.c
 *
 * Copyright (C) 2004 Sourcefire,Inc
 * Steven A. Sturges <ssturges@sourcefire.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Description:
 *
 * This file contains functions to access the SERVER_LOOKUP structure.
 *
 * We wrap the access to SERVER_LOOKUP so changing the lookup algorithms
 * are more modular and independent.  This is the only file that would need
 * to be changed to change the algorithmic lookup.
 *
 * NOTES:
 * - 16.09.04:  Initial Development.  SAS
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ftpp_util_kmap.h"
#include "ftpp_ui_config.h"
#include "ftpp_return_codes.h"

/*
 * Function: ftpp_ui_server_lookup_init(SERVER_LOOKUP **ServerLookup)
 *
 * Purpose: Initialize the server_lookup structure.
 *
 *          We need to initialize the server_lookup structure for
 *          the FTP server configuration.  Don't want a NULL pointer
 *          flying around, when we have to look for server configs.
 *
 * Arguments: ServerLookup      => pointer to the pointer of the server
 *                                 lookup structure.
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftpp_ui_server_lookup_init(SERVER_LOOKUP **ServerLookup)
{
    *ServerLookup = KMapNew(NULL); 
    if(*ServerLookup == NULL)
    {
        return FTPP_MEM_ALLOC_FAIL;
    }

    return FTPP_SUCCESS;
}

/*
 * Function: ftpp_ui_server_lookup_cleanup(SERVER_LOOKUP **ServerLookup)
 *
 * Purpose: Free the server_lookup structure.
 *          We need to free the server_lookup structure.
 *
 * Arguments: ServerLookup  => pointer to the pointer of the server
 *                             lookup structure.
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftpp_ui_server_lookup_cleanup(SERVER_LOOKUP **ServerLookup)
{
    KMAP *km;

    if (ServerLookup == NULL)
        return FTPP_INVALID_ARG;

    km = *ServerLookup;

    if (km)
    {
        free(km);
        *ServerLookup = NULL;
    }

    return FTPP_SUCCESS;
}

/*
 * Function: ftpp_ui_server_lookup_add(SERVER_LOOKUP *ServerLookup,
 *                                 char *ip, int len, 
 *                                 FTP_SERVER_PROTO_CONF *ServerConf)
 * 
 * Purpose: Add a server configuration to the list.
 *          We add these keys like you would normally think to add
 *          them, because on low endian machines the least significant
 *          byte is compared first.  This is what we want to compare
 *          IPs backward, doesn't work on high endian machines, but oh
 *          well.  Our platform is Intel.
 *
 * Arguments: ServerLookup => a pointer to the lookup structure
 *            IP           => the ftp server address
 *            len          => Length of the address 
 *            ServerConf   => a pointer to the server configuration structure
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftpp_ui_server_lookup_add(SERVER_LOOKUP *ServerLookup, unsigned long Ip,
                            FTP_SERVER_PROTO_CONF *ServerConf)
{
    int iRet;

    if(!ServerLookup || !ServerConf)
    {
        return FTPP_INVALID_ARG;
    }

    if((iRet = KMapAdd(ServerLookup, (void *)&Ip, 4, (void *)ServerConf)))
    {
        /*
         *  This means the key has already been added.
         */
        if(iRet == 1)
        {
            return FTPP_NONFATAL_ERR;
        }
        else
        {
            return FTPP_MEM_ALLOC_FAIL;
        }
    }

    return FTPP_SUCCESS;
}

/*
 * Function: ftpp_ui_server_lookup_find(SERVER_LOOKUP *ServerLookup,
 *                                  char *ip, int len,
 *                                  int *iError)
 *
 * Purpose: Find a server configuration given a IP.
 *          We look up a server configuration given an IP and
 *          return a pointer to that server configuration if found.
 *
 * Arguments: ServerLookup => a pointer to the lookup structure
 *            IP           => the ftp server address
 *            len          => Length of the address 
 *            iError       => a pointer to an error code
 *
 * Returns: int => return code indicating error or success
 *
 * Returns: FTP_SERVER_PROTO_CONF* => Pointer to server configuration
 *                            structure matching IP if found, NULL otherwise.
 *
 */
FTP_SERVER_PROTO_CONF *ftpp_ui_server_lookup_find(SERVER_LOOKUP *ServerLookup, 
                                            unsigned long Ip, int *iError)
{
    FTP_SERVER_PROTO_CONF *ServerConf = NULL;

    if(!iError)
    {
        return NULL;
    }

    if(!ServerLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return NULL;
    }

    *iError = FTPP_SUCCESS;

    /* TODO: change this to use a quick find of IP/mask */
    if(!(ServerConf = (FTP_SERVER_PROTO_CONF *)
                        KMapFind(ServerLookup,(void *)&Ip,4)))
    {
        *iError = FTPP_NOT_FOUND;
    }

    return ServerConf;
}

/*
 * Function: ftpp_ui_server_lookup_first(SERVER_LOOKUP *ServerLookup,
 *                                   int *iError)
 *
 * Purpose: This lookups the first server configuration, so we can
 *          iterate through the configurations.
 *
 * Arguments: ServerLookup  => pointer to the server lookup structure
 *            iError        => pointer to the integer to set for errors
 *
 * Returns: FTP_SERVER_PROTO_CONF* => Pointer to first server
 *                                    configuration structure
 *
 */
FTP_SERVER_PROTO_CONF *ftpp_ui_server_lookup_first(SERVER_LOOKUP *ServerLookup,
                                            int *iError)
{
    FTP_SERVER_PROTO_CONF *ServerConf;

    if(!iError)
    {
        return NULL;
    }

    if(!ServerLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return NULL;
    }

    *iError = FTPP_SUCCESS;

    if(!(ServerConf = (FTP_SERVER_PROTO_CONF *)KMapFindFirst(ServerLookup)))
    {
        *iError = FTPP_NOT_FOUND;
    }

    return ServerConf;
}

/*
 * Function: ftpp_ui_server_lookup_next(SERVER_LOOKUP *ServerLookup,
 *                                  int *iError)
 *
 * Iterates to the next configuration, like a list it just returns
 * the next config in the config list.
 *
 * Purpose: This lookups the next server configuration, so we can
 *          iterate through the configurations.
 *
 * Arguments: ServerLookup  => pointer to the server lookup structure
 *            iError        => pointer to the integer to set for errors
 *
 * Returns: FTP_SERVER_PROTO_CONF*  => Pointer to next server configuration
 *                             structure
 *
 */
FTP_SERVER_PROTO_CONF *ftpp_ui_server_lookup_next(SERVER_LOOKUP *ServerLookup,
                                           int *iError)
{
    FTP_SERVER_PROTO_CONF *ServerConf;

    if(!iError)
    {
        return NULL;
    }

    if(!ServerLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return NULL;
    }

    *iError = FTPP_SUCCESS;

    if(!(ServerConf = (FTP_SERVER_PROTO_CONF *)KMapFindNext(ServerLookup)))
    {
        *iError = FTPP_NOT_FOUND;
    }

    return ServerConf;
}
