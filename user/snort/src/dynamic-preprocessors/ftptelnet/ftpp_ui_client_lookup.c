/*
 * ftpp_ui_client_lookup.c
 *
 * Copyright (C) 2004 Sourcefire,Inc
 * Steven A. Sturges <ssturges@sourcefire.com>
 * Daniel J. Roelker <droelker@sourcefire.com>
 * Marc A. Norton <mnorton@sourcefire.com>
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
 * This file contains functions to access the CLIENT_LOOKUP structure.
 *
 * We wrap the access to CLIENT_LOOKUP so changing the lookup algorithms
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
 * Function: ftpp_ui_client_lookup_init(CLIENT_LOOKUP **ClientLookup)
 *
 * Purpose: Initialize the client_lookup structure.
 *
 *          We need to initialize the client_lookup structure for
 *          the FTP client configuration.  Don't want a NULL pointer
 *          flying around, when we have to look for FTP clients.
 *
 * Arguments: ClientLookup      => pointer to the pointer of the client
 *                                 lookup structure.
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftpp_ui_client_lookup_init(CLIENT_LOOKUP **ClientLookup)
{
    *ClientLookup = KMapNew(NULL); 
    if(*ClientLookup == NULL)
    {
        return FTPP_MEM_ALLOC_FAIL;
    }

    return FTPP_SUCCESS;
}

/*
 * Function: ftpp_ui_client_lookup_cleanup(CLIENT_LOOKUP **ClientLookup)
 *
 * Purpose: Free the client_lookup structure.
 *          We need to free the client_lookup structure.
 *
 * Arguments: ClientLookup  => pointer to the pointer of the client
 *                             lookup structure.
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftpp_ui_client_lookup_cleanup(CLIENT_LOOKUP **ClientLookup)
{
    KMAP *km;

    if (ClientLookup == NULL)
        return FTPP_INVALID_ARG;

    km = *ClientLookup;

    if (km)
    {
        free(km);
        *ClientLookup = NULL;
    }

    return FTPP_SUCCESS;
}

/*
 * Function: ftpp_ui_client_lookup_add(CLIENT_LOOKUP *ClientLookup,
 *                                 char *ip, int len, 
 *                                 FTP_CLIENT_PROTO_CONF *ClientConf)
 * 
 * Purpose: Add a client configuration to the list.
 *          We add these keys like you would normally think to add
 *          them, because on low endian machines the least significant
 *          byte is compared first.  This is what we want to compare
 *          IPs backward, doesn't work on high endian machines, but oh
 *          well.  Our platform is Intel.
 *
 * Arguments: ClientLookup => a pointer to the lookup structure
 *            IP           => the ftp client address
 *            len          => Length of the address 
 *            ClientConf   => a pointer to the client configuration structure
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftpp_ui_client_lookup_add(CLIENT_LOOKUP *ClientLookup, unsigned long Ip,
                            FTP_CLIENT_PROTO_CONF *ClientConf)
{
    int iRet;

    if(!ClientLookup || !ClientConf)
    {
        return FTPP_INVALID_ARG;
    }

    if((iRet = KMapAdd(ClientLookup, (void *)&Ip, 4, (void *)ClientConf)))
    {
        /*
         * This means the key has already been added.
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
 * Function: ftpp_ui_client_lookup_find(CLIENT_LOOKUP *ClientLookup,
 *                                  char *ip, int len,
 *                                  int *iError)
 *
 * Purpose: Find a client configuration given a IP.
 *          We look up a client configuration given an IP and
 *          return a pointer to that client configuration if found.
 *
 * Arguments: ClientLookup => a pointer to the lookup structure
 *            IP           => the ftp client address
 *            len          => Length of the address 
 *            iError       => a pointer to an error code
 *
 * Returns: int => return code indicating error or success
 *
 * Returns: FTP_CLIENT_PROTO_CONF* => Pointer to client configuration
 *                           structure matching IP if found, NULL otherwise.
 *
 */
FTP_CLIENT_PROTO_CONF *ftpp_ui_client_lookup_find(CLIENT_LOOKUP *ClientLookup, 
                                            unsigned long Ip, int *iError)
{
    FTP_CLIENT_PROTO_CONF *ClientConf = NULL;

    if(!iError)
    {
        return NULL;
    }

    if(!ClientLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return NULL;
    }

    *iError = FTPP_SUCCESS;

    /* TODO: change this to use a quick find of IP/mask */
    if(!(ClientConf = (FTP_CLIENT_PROTO_CONF *)
                        KMapFind(ClientLookup,(void *)&Ip,4)))
    {
        *iError = FTPP_NOT_FOUND;
    }

    return ClientConf;
}

/*
 * Function: ftpp_ui_client_lookup_first(CLIENT_LOOKUP *ClientLookup,
 *                                   int *iError)
 *
 * Purpose: This lookups the first client configuration, so we can
 *          iterate through the configurations.
 *
 * Arguments: ClientLookup  => pointer to the client lookup structure
 *            iError        => pointer to the integer to set for errors
 *
 * Returns: FTP_CLIENT_PROTO_CONF* => Pointer to first client configuration
 *                             structure
 *
 */
FTP_CLIENT_PROTO_CONF *ftpp_ui_client_lookup_first(CLIENT_LOOKUP *ClientLookup,
                                            int *iError)
{
    FTP_CLIENT_PROTO_CONF *ClientConf;

    if(!iError)
    {
        return NULL;
    }

    if(!ClientLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return NULL;
    }

    *iError = FTPP_SUCCESS;

    if(!(ClientConf = (FTP_CLIENT_PROTO_CONF *)KMapFindFirst(ClientLookup)))
    {
        *iError = FTPP_NOT_FOUND;
    }

    return ClientConf;
}

/*
 * Function: ftpp_ui_client_lookup_next(CLIENT_LOOKUP *ClientLookup,
 *                                  int *iError)
 *
 * Iterates to the next configuration, like a list it just returns
 * the next config in the config list.
 *
 * Purpose: This lookups the next client configuration, so we can
 *          iterate through the configurations.
 *
 * Arguments: ClientLookup  => pointer to the client lookup structure
 *            iError        => pointer to the integer to set for errors
 *
 * Returns: FTP_CLIENT_PROTO_CONF*  => Pointer to next client configuration
 *                             structure
 *
 */
FTP_CLIENT_PROTO_CONF *ftpp_ui_client_lookup_next(CLIENT_LOOKUP *ClientLookup,
                                           int *iError)
{
    FTP_CLIENT_PROTO_CONF *ClientConf;

    if(!iError)
    {
        return NULL;
    }

    if(!ClientLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return NULL;
    }

    *iError = FTPP_SUCCESS;

    if(!(ClientConf = (FTP_CLIENT_PROTO_CONF *)KMapFindNext(ClientLookup)))
    {
        *iError = FTPP_NOT_FOUND;
    }

    return ClientConf;
}
