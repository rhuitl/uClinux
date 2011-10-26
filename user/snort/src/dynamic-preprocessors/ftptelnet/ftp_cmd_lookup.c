/*
 * ftp_cmd_lookup.c
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
 * This file contains functions to access the CMD_LOOKUP structure.
 *
 * We wrap the access to CMD_LOOKUP so changing the lookup algorithms
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
 * Function: ftp_cmd_lookup_init(CMD_LOOKUP **CmdLookup)
 *
 * Purpose: Initialize the cmd_lookup structure.
 *
 *          We need to initialize the cmd_lookup structure for
 *          the FTP command configuration.  Don't want a NULL pointer
 *          flying around, when we have to look for FTP commands.
 *
 * Arguments: CmdLookup         => pointer to the pointer of the cmd
 *                                 lookup structure.
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftp_cmd_lookup_init(CMD_LOOKUP **CmdLookup)
{
    KMAP *km = KMapNew(NULL); 
    *CmdLookup = km;
    if(*CmdLookup == NULL)
    {
        return FTPP_MEM_ALLOC_FAIL;
    }

    km->nocase = 1;

    return FTPP_SUCCESS;
}

/*
 * Function: ftp_cmd_lookup_cleanup(CMD_LOOKUP **CmdLookup)
 *
 * Purpose: Free the cmd_lookup structure.
 *          We need to free the cmd_lookup structure.
 *
 * Arguments: CmdLookup     => pointer to the pointer of the cmd
 *                             lookup structure.
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftp_cmd_lookup_cleanup(CMD_LOOKUP **CmdLookup)
{
    KMAP *km;

    if (CmdLookup == NULL)
        return FTPP_INVALID_ARG;

    km = *CmdLookup;

    if (km)
    {
        free(km);
        *CmdLookup = NULL;
    }

    return FTPP_SUCCESS;
}

/*
 * Function: ftp_cmd_lookup_add(CMD_LOOKUP *CmdLookup,
 *                                 char *ip, int len, 
 *                                 FTP_CMD_CONF *FTPCmd)
 * 
 * Purpose: Add a cmd configuration to the list.
 *          We add these keys like you would normally think to add
 *          them, because on low endian machines the least significant
 *          byte is compared first.  This is what we want to compare
 *          IPs backward, doesn't work on high endian machines, but oh
 *          well.  Our platform is Intel.
 *
 * Arguments: CmdLookup    => a pointer to the lookup structure
 *            cmd          => the ftp cmd
 *            len          => Length of the cmd
 *            FTPCmd       => a pointer to the cmd configuration structure
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftp_cmd_lookup_add(CMD_LOOKUP *CmdLookup, char *cmd, int len, 
                            FTP_CMD_CONF *FTPCmd)
{
    int iRet;

    if(!CmdLookup || !FTPCmd)
    {
        return FTPP_INVALID_ARG;
    }

    if((iRet = KMapAdd(CmdLookup, (void *)cmd, len, (void *)FTPCmd)))
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
 * Function: ftp_cmd_lookup_find(CMD_LOOKUP *CmdLookup,
 *                                  char *ip, int len,
 *                                  int *iError)
 *
 * Purpose: Find a cmd configuration given a IP.
 *          We look up a cmd configuration given an FTP cmd and
 *          return a pointer to that cmd configuration if found.
 *
 * Arguments: CmdLookup    => a pointer to the lookup structure
 *            cmd          => the ftp cmd
 *            len          => Length of the cmd
 *            iError       => a pointer to an error code
 *
 * Returns: int => return code indicating error or success
 *
 * Returns: FTP_CMD_CONF* => Pointer to cmd configuration structure
 *                            matching IP if found, NULL otherwise.
 *
 */
FTP_CMD_CONF  *ftp_cmd_lookup_find(CMD_LOOKUP *CmdLookup, 
                                            char *cmd, int len, int *iError)
{
    FTP_CMD_CONF *FTPCmd = NULL;

    if(!iError)
    {
        return NULL;
    }

    if(!CmdLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return NULL;
    }

    *iError = FTPP_SUCCESS;

    if(!(FTPCmd = (FTP_CMD_CONF *)KMapFind(CmdLookup,(void *)cmd,len)))
    {
        *iError = FTPP_NOT_FOUND;
    }

    return FTPCmd;
}

/*
 * Function: ftp_cmd_lookup_first(CMD_LOOKUP *CmdLookup,
 *                                   int *iError)
 *
 * Purpose: This lookups the first cmd configuration, so we can
 *          iterate through the configurations.
 *
 * Arguments: CmdLookup     => pointer to the cmd lookup structure
 *            iError        => pointer to the integer to set for errors
 *
 * Returns: FTP_CMD_CONF* => Pointer to first cmd configuration structure
 *
 */
FTP_CMD_CONF *ftp_cmd_lookup_first(CMD_LOOKUP *CmdLookup,
                                            int *iError)
{
    FTP_CMD_CONF *FTPCmd;

    if(!iError)
    {
        return NULL;
    }

    if(!CmdLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return NULL;
    }

    *iError = FTPP_SUCCESS;

    if(!(FTPCmd = (FTP_CMD_CONF *)KMapFindFirst(CmdLookup)))
    {
        *iError = FTPP_NOT_FOUND;
    }

    return FTPCmd;
}

/*
 * Function: ftp_cmd_lookup_next(CMD_LOOKUP *CmdLookup,
 *                                  int *iError)
 *
 * Iterates to the next configuration, like a list it just returns
 * the next config in the config list.
 *
 * Purpose: This lookups the next cmd configuration, so we can
 *          iterate through the configurations.
 *
 * Arguments: CmdLookup     => pointer to the cmd lookup structure
 *            iError        => pointer to the integer to set for errors
 *
 * Returns: FTP_CMD_CONF*  => Pointer to next cmd configuration structure
 *
 */
FTP_CMD_CONF *ftp_cmd_lookup_next(CMD_LOOKUP *CmdLookup,
                                           int *iError)
{
    FTP_CMD_CONF *FTPCmd;

    if(!iError)
    {
        return NULL;
    }

    if(!CmdLookup)
    {
        *iError = FTPP_INVALID_ARG;
        return NULL;
    }

    *iError = FTPP_SUCCESS;

    if(!(FTPCmd = (FTP_CMD_CONF *)KMapFindNext(CmdLookup)))
    {
        *iError = FTPP_NOT_FOUND;
    }

    return FTPCmd;
}
