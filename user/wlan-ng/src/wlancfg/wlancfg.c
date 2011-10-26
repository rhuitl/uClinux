/* src/wlancfg/wlancfg.c
*
* User utility for setting, saving, and querying the wlan card configuration.
*
* Copyright (C) 2001 Rebel.com Inc.  All Rights Reserved.
* --------------------------------------------------------------------
*
* linux-wlan
*
*   The contents of this file are subject to the Mozilla Public
*   License Version 1.1 (the "License"); you may not use this file
*   except in compliance with the License. You may obtain a copy of
*   the License at http://www.mozilla.org/MPL/
*
*   Software distributed under the License is distributed on an "AS
*   IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
*   implied. See the License for the specific language governing
*   rights and limitations under the License.
*
*   Alternatively, the contents of this file may be used under the
*   terms of the GNU Public License version 2 (the "GPL"), in which
*   case the provisions of the GPL are applicable instead of the
*   above.  If you wish to allow the use of your version of this file
*   only under the terms of the GPL and not to allow others to use
*   your version of this file under the MPL, indicate your decision
*   by deleting the provisions above and replace them with the notice
*   and other provisions required by the GPL.  If you do not delete
*   the provisions above, a recipient may use your version of this
*   file under either the MPL or the GPL.
*
* --------------------------------------------------------------------
*
* Inquiries regarding the linux-wlan Open Source project can be
* made directly to:
*
* AbsoluteValue Systems Inc.
* info@linux-wlan.com
* http://www.linux-wlan.com
*
* --------------------------------------------------------------------
*
* Originally written 2001 by Robert James.
*
* The author may be reached as bob.james@rebel.com, or
*   Robert James
*   Rebel.com Inc.
*   150 Isabella St., Suite 1000
*   Ottawa, Ontario
*   Canada    K1S 5R3
*
* --------------------------------------------------------------------
*/

/*
**    The "wlancfg" utility program provides an alternative method to
** "wlanctl", for manipulating MIB values.  It was designed to provide
** an easier mechanism for saving and restoring the complete wireless
** configuration (i.e. when re-starting the device driver) and to provide
** a more efficient mechanism for GUI's to query multiple MIB's.
**
** Usage:   wlancfg  query   dev
**          wlancfg  show    dev  [all]
**          wlancfg  set     dev
**          wlancfg  list
**          wlancfg  version
**
**          where:  dev      - Name of device (e.g. wlan0).
**
** The functions are as follows:
**
**     query   - Read MIB names (separated by whitespace) from "stdin"
**               and output their values (separated by carriage returns)
**               to "stdout".  The MIB's may be either read/write or
**               read-only.
**     show    - Query the values of all supported read/write MIB's and
**               output their values (separated by carriage returns) to
**               "stdout".  The syntax of the output will be:
**
**                   name=value
**
**               If the "all" parameter is specified, then all supported
**               MIB's (i.e. read-only MIB's as well) are output.
**     set     - Read MIB name/value pairs (separated by carriage returns)
**               from "stdin" and set the values of the specified MIB's.  The
**               pairs must have the same syntax as above.  The MIB's must
**               be read/write.
**     list    - Display a list of all supported MIB's.
**     version - Display the compiled version of "wlancfg".
*/

/*================================================================*/
/* System Includes */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* Ugly hack for LinuxPPC R4, don't have time to figure it out right now */
#if defined(__WLAN_PPC__)
#undef __GLIBC__
#endif

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

/*================================================================*/
/* Project Includes */

#include <wlan/wlan_compat.h>
#include <wlan/version.h>
#include <wlan/p80211types.h>
#include <wlan/p80211msg.h>
#include <wlan/p80211meta.h>
#include <wlan/p80211metamsg.h>
#include <wlan/p80211metamib.h>
#include <wlan/p80211metastruct.h>
#include <wlan/p80211ioctl.h>

/*================================================================*/
/* Local Types */

/*
** The request specification (req_spec) structure is used to record
** frequently used information about the "dot11req_mibget" and
** "dot11req_mibset" request messages.  It is used to prevent the
** necessity of recalculating this information when executing these
** requests repeatedly.
*/

typedef struct req_spec
{
    UINT32        msgcode;    /* Request message code. */
    UINT32        msglen;     /* Length of message. */

    p80211meta_t  *attptr;    /* "mibattribute" argument. */
    UINT32        attdid;     /* "mibattribute" DID. */
    UINT32        attoff;     /* Request message offset. */
    UINT32        attlen;     /* Request message data length. */

    p80211meta_t  *resptr;    /* "resultcode" argument. */
    UINT32        resdid;     /* "resultcode" DID. */
    UINT32        resoff;     /* Request message offset. */
    UINT32        reslen;     /* Request message data length. */
} req_spec_t;

/*================================================================*/
/* Local Function Declarations */

static void wlancfg_usage(void);
static int  wlancfg_query(char *device);
static int  wlancfg_show(char *device, int all);
static int  wlancfg_set(char *device);
static void wlancfg_list(void);

static int  wlancfg_reqspec(char *request, req_spec_t *mibget);
static int  wlancfg_getvalue(char *device, p80211meta_t *item,
                             req_spec_t *mibget,
                             int skt, p80211ioctl_req_t *req,
                             char *value);
static int  wlancfg_setvalue(char *device, req_spec_t *mibset,
                             int skt, p80211ioctl_req_t *req,
                             char *value);
static int  wlancfg_build(char *device, req_spec_t *spec, char *value,
                          p80211msgd_t *msg);
static void wlancfg_totext(p80211meta_t *item, req_spec_t *mibget,
                           p80211msgd_t *msg, char *value);
static int  wlancfg_getreq(char *cat, char *name, int argcnt,
                           UINT32 *msgcode, p80211meta_t **arglist);

/*****************************************************************
**
** main
**
**    "wlancfg" main entry point.
**
** Arguments:  argc  - Number of command line arguments.
**             argv  - Array of argument strings.
**
** Returns:    0 - Success.
**             1 - Failure.
*/

int main(int argc, char **argv)
{
    int  result, all;

    if (argc < 2) goto usage;

    if (strcmp(argv[1], "query") == 0)
        {
        if (argc != 3) goto usage;
        result = wlancfg_query(argv[2]);
        goto done;
        }

    if (strcmp(argv[1], "show") == 0)
        {
        all = 0;
        if (argc != 3)
            {
            if (argc != 4) goto usage;
            if (strcmp(argv[3], "all") != 0) goto usage;
            all = 1;
            }
        result = wlancfg_show(argv[2], all);
        goto done;
        }

    if (strcmp(argv[1], "set") == 0)
        {
        if (argc != 3) goto usage;
        result = wlancfg_set(argv[2]);
        goto done;
        }

    if (strcmp(argv[1], "list") == 0)
        {
        if (argc != 2) goto usage;
        wlancfg_list();
        result = 0;
        goto done;
        }

    if (strcmp(argv[1], "version") == 0)
        {
        if (argc != 2) goto usage;
        printf("%s\n", WLAN_RELEASE);
        result = 0;
        goto done;
        }

usage:
    wlancfg_usage();
    result = 0;

done:

    return(result);
}

/*****************************************************************
**
** wlancfg_usage
**
**    Output the command syntax.
*/

static void wlancfg_usage(void)
{
    printf("\nQuery, show, or set configuration settings.\n\n");

    printf("Usage:  wlancfg  query   dev\n");
    printf("        wlancfg  show    dev  [all]\n");
    printf("        wlancfg  set     dev\n");
    printf("        wlancfg  list\n");
    printf("        wlancfg  version\n\n");

    printf("        where:  dev  - Name of device (e.g. wlan0).\n");

    return;
}

/*****************************************************************
**
** wlancfg_query
**
**    Query specific MIB's and output their values.
**
** Returns:    0 - Success.
**             1 - Failure.
*/

static int wlancfg_query(
char  *device)             /* I:   Device name. */
{
    int                result;
    req_spec_t         mibget;
    p80211ioctl_req_t  req;
    UINT8              msg[MSG_BUFF_LEN];
    int                skt, cnt;
    char               name[100], value[MSG_BUFF_LEN];
    UINT32             did;
    p80211meta_t       *item;

    /*
    ** All MIB values will be queried using the "dot11req_mibget" request.
    ** Do some initialization for this request.
    */

    result = wlancfg_reqspec("dot11req_mibget", &mibget);
    if (result != 0) return(1);

    /*
    ** Get a socket to be used to talk to the device driver and then
    ** set up the invariant parts of the "ioctl" request.  The variable
    ** parts (i.e. length and result code) will be set later when the
    ** actual requests are created.
    */

    skt = socket(AF_INET, SOCK_STREAM, 0);
    if (skt == -1)
        {
        perror("wlancfg");
        return(1);
        }

    strncpy(req.name, device, sizeof(req.name));
    req.magic = P80211_IOCTL_MAGIC;    /* Set the magic. */
    req.data  = msg;

    /*
    ** Read MIB names from "stdin" until there are no more.  Make sure
    ** that the user hasn't had an "accident" and entered a name which
    ** is too long.
    **
    ** Note:    The "scanf()" documentation is not clear on how strings
    **       which are too long are handled.  Possibilities are:
    **
    **          1. "n" characters read and no null-termination added.
    **          2. "n" characters read and '\0' added at "name[n]".
    **          3. "n-1" characters read and '\0' added at "name[n-1]".
    **
    **       The following code will work in all 3 cases and not overflow
    **       the "name" array.
    */

    name[sizeof(name)-2] = '\0';
    name[sizeof(name)-1] = '\0';

    while (1)
        {
        cnt = scanf("%99s", name);               /* sizeof(name)-1 = 99 */
        if (cnt == 0 || cnt == EOF) break;

        if (name[sizeof(name)-2] != '\0' || name[sizeof(name)-1] != '\0')
            {
            fprintf(stderr, "wlancfg: MIB name is too long.\n");
            return(1);
            }

        /*
        ** Find the MIB.
        */

        did = p80211_text2did(mib_catlist, NULL, NULL, name);
        if (did == P80211DID_INVALID)
            {
            fprintf(stderr, "wlancfg: Unknown MIB: %s\n", name);
            return(1);
            }

        item = p80211_did2item(mib_catlist, did);
        if (item == NULL)      /* Should never happen. */
            {
            fprintf(stderr, "wlancfg: Internal MIB search error: %s\n", name);
            return(1);
            }

        /*
        ** Query the MIB value and output it.  If no value was found
        ** (i.e. the MIB is unsupported), then output an empty line so
        ** that the input names and output values don't get out of sync.
        ** Otherwise, output the actual value...which follows the "=".
        ** The "=" will always exist so we don't need to deal with the
        ** case where it is not found.
        */

        result = wlancfg_getvalue(device, item, &mibget, skt, &req, value);
        if (result != 0) return(1);

        if (value[0] == '\0')
            printf("\n");
        else
            printf("%s\n", strchr(value, '=')+1);
        }

    return(0);
}

/*****************************************************************
**
** wlancfg_show
**
**    Query all the current writeable MIB's and output them.  If the "all"
** flag is set, then all MIB's (including read-only MIB's) are output.
**
** Returns:    0 - Success.
**             1 - Failure.
*/

static int wlancfg_show(
char  *device,             /* I:   Device name. */
int   all)                 /* I:   "all" flag. */
{
    int                result;
    req_spec_t         mibget;
    p80211ioctl_req_t  req;
    UINT8              msg[MSG_BUFF_LEN];
    int                skt, i, j, k, ncats, ngrps, nitems, out;
    UINT32             did;
    grplistitem_t      *grp;
    p80211meta_t       *item;
    char               value[MSG_BUFF_LEN];

    /*
    ** All MIB values will be queried using the "dot11req_mibget" request.
    ** Do some initialization for this request.
    */

    result = wlancfg_reqspec("dot11req_mibget", &mibget);
    if (result != 0) return(1);

    /*
    ** Get a socket to be used to talk to the device driver and then
    ** set up the invariant parts of the "ioctl" request.  The variable
    ** parts (i.e. length and result code) will be set later when the
    ** actual requests are created.
    */

    skt = socket(AF_INET, SOCK_STREAM, 0);
    if (skt == -1)
        {
        perror("wlancfg");
        return(1);
        }

    strncpy(req.name, device, sizeof(req.name));
    req.magic = P80211_IOCTL_MAGIC;    /* Set the magic. */
    req.data  = msg;

    /*
    ** Scan through all the MIB's in all the groups in all the catagories.
    ** Output the MIB if it is writeable or if all MIB's are being output.
    ** However, DON'T output the MIB if it is not readable!
    */

    ncats = GETMETASIZE(mib_catlist);

    for (i = 1; i < ncats; i++)
        {
        ngrps = GETMETASIZE(mib_catlist[i].grplist);

        for (j = 1; j < ngrps; j++)
            {
            did = P80211DID_MKSECTION(i) | P80211DID_MKGROUP(j);
            grp = p80211_did2grp(mib_catlist, did);
            if (grp == NULL)        /* Should never happen. */
                {
                fprintf(stderr, "wlancfg: DID %lx not found.\n", did);
                return(1);
                }

            item = grp->itemlist;
            nitems = GETMETASIZE(item);

            for (item++, k = 1; k < nitems; k++, item++)
                {
                out = all || ((item->did & P80211DID_ACCESS_WRITE) != 0);
                out = out && ((item->did & P80211DID_ACCESS_READ) != 0);
                if (out)
                    {
                    result = wlancfg_getvalue(device, item, &mibget,
                                              skt, &req, value);
                    if (result != 0) return(1);

                    /*
                    ** Output the value only if a value was found (i.e. skip
                    ** unsupported MIB's).
                    */

                    if (value[0] != '\0') printf("%s\n", value);
                    }
                }
            }
        }

    return(0);
}

/*****************************************************************
**
** wlancfg_set
**
**    Set the wlan parameters.
**
** Returns:    0 - Success.
**             1 - Failure.
*/

static int wlancfg_set(
char  *device)             /* I:   Device name. */
{
    int                result;
    req_spec_t         mibset;
    p80211ioctl_req_t  req;
    UINT8              msg[MSG_BUFF_LEN];
    int                skt;
    char               pair[500], *ch;

    /*
    ** All MIB values will be set using the "dot11req_mibset" request.
    ** Do some initialization for this request.
    */

    result = wlancfg_reqspec("dot11req_mibset", &mibset);
    if (result != 0) return(1);

    /*
    ** Get a socket to be used to talk to the device driver and then
    ** set up the invariant parts of the "ioctl" request.  The variable
    ** parts (i.e. length and result code) will be set later when the
    ** actual requests are created.
    */

    skt = socket(AF_INET, SOCK_STREAM, 0);
    if (skt == -1)
        {
        perror("wlancfg");
        return(1);
        }

    strncpy(req.name, device, sizeof(req.name));
    req.magic = P80211_IOCTL_MAGIC;    /* Set the magic. */
    req.data  = msg;

    /*
    ** Read MIB name/value pairs from "stdin" until there are no more.
    ** There should be one pair per line.  The following things can happen
    ** with "fgets()":
    **
    **    1. Nothing is read (i.e. end of file).  We are done.
    **    2. The last character read is a '\n'.  Strip the carriage return
    **       off and process the line.
    **    3. No '\n' was read but the buffer was not filled.  The last
    **       line in the file has been read.  Process it.  The next read
    **       should result in an end-of-file.
    **    4. No '\n' was read and the buffer was filled.  The line is
    **       too long.  Abort things.
    */

    while (1)
        {
        if (fgets(pair, sizeof(pair), stdin) == NULL) break;
        ch = strrchr(pair, '\n');
        if (ch != NULL)
            *ch = '\0';
        else
            if (strlen(pair) >= sizeof(pair)-1)
                {
                fprintf(stderr, "wlancfg: MIB name/value is too long.\n");
                return(1);
                }

        /*
        ** Set the MIB value.
        */

        result = wlancfg_setvalue(device, &mibset, skt, &req, pair);
        if (result != 0) return(1);
        }

    return(0);
}

/*****************************************************************
**
** wlancfg_list
**
**    List all supported MIB's.
*/

static void wlancfg_list(void)
{
    int            i, j, k, l;
    int            ncat, ngrp, nitm;
    int            len, cnt, type;
    catlistitem_t  *cat;
    grplistitem_t  *grp;
    p80211meta_t   *mib;
    p80211enum_t   *enump;

    /*
    ** Go through every MIB in every group in every catagory and find the
    ** maximum MIB name length.
    */

    len = 0;

    ncat = GETMETASIZE(mib_catlist);
    cat  = mib_catlist + 1;

    for (i = 1; i < ncat; i++, cat++)
        {
        ngrp = GETMETASIZE(cat->grplist);
        grp  = (cat->grplist) + 1;

        for (j = 1; j < ngrp; j++, grp++)
            {
            nitm = GETMETASIZE(grp->itemlist);
            mib  = grp->itemlist + 1;

            for (k = 1; k < nitm; k++, mib++)
                {
                l = strlen(mib->name);
                if (len < l) len = l;
                }
            }
        }

    /*
    ** Go through each MIB catagory.
    */

    ncat = GETMETASIZE(mib_catlist);
    cat  = mib_catlist + 1;

    for (i = 1; i < ncat; i++, cat++)
        {
        cnt = printf("\nCatagory: %s\n", cat->name);
        for (j = 2; j < cnt; j++) printf("=");
        printf("\n");

        /*
        ** Go through each MIB in this group.
        */

        ngrp = GETMETASIZE(cat->grplist);
        grp  = (cat->grplist) + 1;

        for (j = 1; j < ngrp; j++, grp++)
            {
            printf("\n%s\n", grp->name);
            nitm = GETMETASIZE(grp->itemlist);
            mib  = grp->itemlist + 1;

            for (k = 1; k < nitm; k++, mib++)
                {
                cnt = printf("    %s", mib->name);
                for (l = cnt-6; l < len; l++) printf(" ");

                printf((mib->did & P80211DID_ACCESS_READ) ?
                       "R" : " ");
                printf((mib->did & P80211DID_ACCESS_WRITE) ?
                       "W  " : "   ");

                type = p80211item_gettype(mib);

                if (type == P80211_TYPE_OCTETSTR)
                    printf("OCTETSTR{minlen=%ld,maxlen=%ld}\n",
                                                   mib->minlen, mib->maxlen);
                else if (type == P80211_TYPE_DISPLAYSTR)
                    printf("DISPLAYSTR{minlen=%ld,maxlen=%ld}\n",
                                                   mib->minlen, mib->maxlen);
                else if (type == P80211_TYPE_INT) {
		  if (mib->min || mib->max) 
                    printf("INT{min=%ld,max=%ld}\n", mib->min, mib->max);
		  else
                    printf("INT\n");
                } else if (type == P80211_TYPE_ENUMINT) {
                    printf("ENUMINT{");
                    enump = mib->enumptr;
                    for (l = 0; l < enump->nitems; l++)
                        {
                        printf("%s", enump->list[l].name);
                        if (l < enump->nitems - 1) printf("|");
                        }
                    printf("}\n");
                    }
                else if (type == P80211_TYPE_UNKDATA)
                    printf("UNKDATA{maxlen=%ld}\n", mib->maxlen);
                else if (type == P80211_TYPE_INTARRAY)
                    printf("INTARRAY{len=%ld}\n", mib->maxlen);
                else if (type == P80211_TYPE_BITARRAY)
                    printf("BITARRAY{range=%ld-%ld}\n", mib->min, mib->max);
                else if (type == P80211_TYPE_MACARRAY)
                    printf("MACARRAY{maxlen=%ld}\n", mib->maxlen);
                else
                    printf("Unknown type!\n");
                }
            }
        }

    return;
}

/*****************************************************************
**
** wlancfg_reqspec
**
**    Build the "request specification" structure for the "dot11req_mibget"
** or "dot11req_mibset" request.  As well, verify that the request is as we
** expect it.  Note that this verification shouldn't be necessary at all
** if we are sure that there is no bug in the request definition!
**
** Returns:    0 - Success.
**             1 - Failure.
*/

static int wlancfg_reqspec(
char        *request,    /* I:   "dot11req_mibget" or "dot11req_mibset". */
req_spec_t  *spec)       /* O:   Request specification. */
{
    int           result;
    p80211meta_t  *arglist;

    /* 
    ** Find the request message code.
    */

    result = wlancfg_getreq("dot11req", request, 2, &spec->msgcode, &arglist);
    if (result != 0) return(1);

    /*
    ** Make sure that the first argument is "mibattribute".  If so, then
    ** fill in the specification for the "mibattribute" argument.  Make
    ** sure that the offset and length values are valid.  Also, make sure
    ** that the "mibattribute" argument is flagged as "request" and that
    ** there are conversion functions defined for it.
    */

    if (strcmp(arglist[1].name, "mibattribute") != 0)
        {
        fprintf(stderr, "wlancfg: First argument is not MIBATTRIBUTE.\n");
        return(1);
        }

    spec->attptr = &arglist[1];
    spec->attdid = spec->msgcode | P80211DID_MKITEM(1) | arglist[1].did;
    spec->attoff = p80211item_getoffset(msg_catlist, spec->attdid);
    spec->attlen = p80211item_maxdatalen(msg_catlist, spec->attdid);

    if (spec->attoff == 0xffffffff || spec->attlen == 0xffffffffUL)
        {
        fprintf(stderr, "wlancfg: Invalid MIBATTRIBUTE offset or length.\n");
        return(1);
        }

    if (!P80211ITEM_ISREQUEST(arglist[1].flags))
        {
        fprintf(stderr, "wlancfg: MIBATTRIBUTE argument is non-request.\n");
        return(1);
        }

    if (arglist[1].fromtextptr == NULL || arglist[1].totextptr == NULL)
        {
        fprintf(stderr, "wlancfg: Missing MIBATTRIBUTE conversion function.\n");
        return(1);
        }

    /*
    ** Make sure that the second argument is "resultcode".  If so, then
    ** fill in the specification for the "resultcode" argument.  Make
    ** sure that the offset and length values are valid.  Also, make sure
    ** that it is not a required argument.
    */

    if (strcmp(arglist[2].name, "resultcode") != 0)
        {
        fprintf(stderr, "wlancfg: Second argument is not RESULTCODE.\n");
        return(1);
        }

    spec->resptr = &arglist[2];
    spec->resdid = spec->msgcode | P80211DID_MKITEM(2) | arglist[2].did;
    spec->resoff = p80211item_getoffset(msg_catlist, spec->resdid);
    spec->reslen = p80211item_maxdatalen(msg_catlist, spec->resdid);

    if (spec->resoff == 0xffffffff || spec->reslen == 0xffffffffUL)
        {
        fprintf(stderr, "wlancfg: Invalid RESULTCODE offset or length.\n");
        return(1);
        }

    if ((P80211ITEM_ISREQUIRED(arglist[2].flags)) &&
        (P80211ITEM_ISREQUEST(arglist[2].flags)))
        {
        fprintf(stderr, "wlancfg: RESULTCODE argument is required.\n");
        return(1);
        }

    /*
    ** Set the message length.  This should correspond to the "resultcode"
    ** argument.  However, make the check general just in case the arguments
    ** were not defined as expected.
    */

    spec->msglen = sizeof(p80211msg_t) + sizeof(p80211item_t);

    if (spec->resoff > spec->attoff)
        spec->msglen += spec->resoff + spec->reslen;
    else
        spec->msglen += spec->attoff + spec->attlen;

    return(0);
}

/*****************************************************************
**
** wlancfg_getvalue
**
**    Get the value of the specified MIB.  The value is returned as
** a name/value pair in the following syntax:
**
**      name=value
**
** If the MIB is unsupported, then a 0-length string is returned.
**
** Returns:    0 - Success.
**             1 - Failure.
*/

static int wlancfg_getvalue(
char               *device,    /* I:   Device name. */
p80211meta_t       *item,      /* I:   Pointer to MIB item. */
req_spec_t         *mibget,    /* I:   "dot11req_mibget" request spec. */
int                skt,        /* I:   ioctl() socket. */
p80211ioctl_req_t  *req,       /* I:   ioctl() request structure. */
char               *value)     /* O:   MIB value. */
{
    int           result;
    p80211msgd_t  *msg;

    /*
    ** Build the "dot11req_mibget" message.
    */

    msg = (p80211msgd_t *) (req->data);

    result = wlancfg_build(device, mibget, item->name, msg);
    if (result != 0) return(1);

    /*
    ** Set up the ioctl request.
    */

    req->len    = msg->msglen;
    req->result = 0;

    result = ioctl(skt, P80211_IFREQ, req);
    if (result == -1)
        {
        perror("wlancfg");
        return(1);
        }

    /*
    ** Convert the MIB value to a string.
    */

    wlancfg_totext(item, mibget, msg, value);

    return(0);
}

/*****************************************************************
**
** wlancfg_setvalue
**
**    Set the value of the specified MIB.  The MIB must be specified as
** a name/value pair in the following syntax:
**
**      name=value
**
** Returns:    0 - Success.
**             1 - Failure.
*/

static int wlancfg_setvalue(
char               *device,    /* I:   Device name. */
req_spec_t         *mibset,    /* I:   "dot11req_mibset" request spec. */
int                skt,        /* I:   ioctl() socket. */
p80211ioctl_req_t  *req,       /* I:   ioctl() request structure. */
char               *value)     /* I:   MIB name/value. */
{
    int            result;
    p80211msgd_t   *msg;
    p80211itemd_t  *itmhdr;
    UINT8          tmpitem[MSG_BUFF_LEN];
    UINT32         resultcode;

    /*
    ** Build the "dot11req_mibset" message.
    */

    msg = (p80211msgd_t *) (req->data);

    result = wlancfg_build(device, mibset, value, msg);
    if (result != 0) return(1);

    /*
    ** Set up the ioctl request.
    */

    req->len    = msg->msglen;
    req->result = 0;

    result = ioctl(skt, P80211_IFREQ, req);
    if (result == -1)
        {
        perror("wlancfg");
        return(1);
        }

    /*
    ** Get the result code and make sure that it has a value.
    */

    itmhdr = (p80211itemd_t *) (msg->args + mibset->resoff);

    if (itmhdr->status != P80211ENUM_msgitem_status_data_ok)
        {
        p80211_error2text(itmhdr->status, tmpitem);
        fprintf(stderr, "wlancfg: %s resultcode=%s\n", value, tmpitem);
        return(1);
        }

    /*
    ** Make sure that the request worked.
    */

    resultcode = *((UINT32 *) (itmhdr->data));

    if (resultcode != P80211ENUM_resultcode_success)
        {
        p80211_error2text(resultcode, tmpitem);
        fprintf(stderr, "wlancfg: %s=%s\n", value, tmpitem);
        return(1);
        }

    return(0);
}

/*****************************************************************
**
** wlancfg_build
**
**    Build the request message buffer for either "dot11req_mibget"
** or "dot11req_mibset".  For "dot11req_mibget", "value" should be the
** name of the MIB.  For "dot11req_mibset", "value" should be the
** MIB name/value pair (i.e. name=value).
**
** Returns:    0 - Success.
**             1 - Failure.
*/

static int wlancfg_build(
char          *device,    /* I:   Device name. */
req_spec_t    *spec,      /* I:   Request specification. */
char          *value,     /* I:   "mibattribute" argument value. */
p80211msgd_t  *msg)       /* O:   Message buffer. */
{
    p80211meta_t   *arg;
    char           tmpstr[MSG_BUFF_LEN];
    p80211itemd_t  *itmhdr;

    /*
    ** Initialize the message buffer.
    */

    msg->msgcode = spec->msgcode;
    msg->msglen  = spec->msglen;
    strncpy(msg->devname, device, WLAN_DEVNAMELEN_MAX - 1);

    /*
    ** Add the "mibattribute" argument to the request buffer.  Note that
    ** the "fromtextptr" conversion function looks for an "=" so we will
    ** need to create a value string that will keep it happy.  Actually,
    ** what is expected is "mibattribute=....." but only the "=" is
    ** necessary.
    */

    arg    = spec->attptr;
    itmhdr = (p80211itemd_t *) (msg->args + spec->attoff);

    tmpstr[0] = '=';
    strcpy(tmpstr+1, value);

    memset(itmhdr, 0, sizeof(p80211item_t) + spec->attlen);
    (*(arg->fromtextptr))(msg_catlist, spec->attdid, (UINT8 *) itmhdr, tmpstr);

    if (itmhdr->status != (UINT16) P80211ENUM_msgitem_status_data_ok)
        {
        p80211_error2text(itmhdr->status, tmpstr);
        fprintf(stderr, "wlancfg: %s=%s\n", value, tmpstr);
        return(1);
        }

    /*
    ** Set the "resultcode" argument to "no value".
    */

    itmhdr = (p80211itemd_t *) (msg->args + spec->resoff);

    itmhdr->did    = spec->resdid;
    itmhdr->status = (UINT16) P80211ENUM_msgitem_status_no_value;
    itmhdr->len    = (UINT16) (spec->reslen);

    memset(itmhdr->data, 0, spec->reslen);

    return(0);
}

/*****************************************************************
**
** wlancfg_totext
**
**    Convert the MIB to a string.  The value is returned as a name/value
** pair in the following syntax:
**
**      name=value
**
** If the MIB cannot be converted for any reason, then a 0-length string is
** returned.
*/

static void wlancfg_totext(
p80211meta_t   *item,      /* I:   Pointer to MIB item. */
req_spec_t     *mibget,    /* I:   "dot11req_mibget" request specification. */
p80211msgd_t   *msg,       /* I:   Message buffer. */
char           *value)     /* O:   Value string. */
{
    p80211itemd_t  *itmhdr;
    UINT8          tmpitem[MSG_BUFF_LEN];
    UINT32         resultcode;
    p80211meta_t   *arg;
    char           *eq;

    /*
    ** Initialize the string to a 0-length string just in case there
    ** is an error.
    */

    value[0] = '\0';

    /*
    ** Get the result code and make sure that it has a value.
    */

    itmhdr = (p80211itemd_t *) (msg->args + mibget->resoff);

    if (itmhdr->status != P80211ENUM_msgitem_status_data_ok)
        {
        p80211_error2text(itmhdr->status, tmpitem);
        fprintf(stderr, "wlancfg: %s resultcode=%s\n", item->name, tmpitem);
        return;
        }

    /*
    ** If the result code is "not supported", then return the empty string
    ** with no error.  Otherwise, there is an error.
    */

    resultcode = *((UINT32 *) (itmhdr->data));

    if (resultcode != P80211ENUM_resultcode_success)
        {
        if (resultcode != P80211ENUM_resultcode_not_supported)
            {
            p80211_error2text(resultcode, tmpitem);
            fprintf(stderr, "wlancfg: %s=%s\n", item->name, tmpitem);
            }
        return;
        }

    /*
    ** Get the MIB value and make sure that it has a value.
    */

    arg = mibget->attptr;

    itmhdr = (p80211itemd_t *) (msg->args + mibget->attoff);

    if (itmhdr->status != P80211ENUM_msgitem_status_data_ok)
        {
        p80211_error2text(itmhdr->status, tmpitem);
        fprintf(stderr, "wlancfg: %s mibattribute=%s\n", item->name, tmpitem);
        return;
        }

    /*
    ** Convert the MIB to a string.  This will have the form:
    **
    **     mibattribute=name=value
    **
    ** Extract everthing after the first '='.  Something went wrong if
    ** there is no "="...just return the empty string.  Also, in some
    ** cases where the value does not exist, "totextptr" appears to
    ** neglect to add the "=" after the MIB name.  If this happens, then
    ** add the "=" ourselves.
    */

    (*(arg->totextptr))(msg_catlist, mibget->attdid, (UINT8 *) itmhdr, tmpitem);

    eq = strchr(tmpitem, '=');
    if (eq != NULL)
        {
        strcpy(value, eq+1);
        if (strchr(value, '=') == NULL) strcat(value, "=");
        }

    return;
}

/*****************************************************************
**
** wlancfg_getreq
**
**    Find a request and verify its arguments.
**
** Returns:    0 - Success.
**             1 - Failure.
*/

static int wlancfg_getreq(
char           *cat,       /* I:   Request catagory. */
char           *name,      /* I:   Request name. */
int            argcnt,     /* I:   Expected number of arguments. */
UINT32         *msgcode,   /* O:   Message code for request. */
p80211meta_t   **arglist)  /* O:   Pointer to argument list. */
{
    grplistitem_t  *grp;

    /*
    ** Find the request message code.
    */

    *msgcode = p80211_text2did(msg_catlist, cat, name, NULL);
    if (*msgcode == P80211DID_INVALID)
        {
        fprintf(stderr, "wlancfg: Could not find \"%s\" request.\n", name);
        return(1);
        }

    /*
    ** Find find the argument metadata list for the request.
    */

    grp = p80211_did2grp(msg_catlist, *msgcode);
    if (grp == NULL)
        {
        fprintf(stderr, "wlancfg: Could not find \"%s\" arguments.\n", name);
        return(1);
        }

    *arglist = grp->itemlist;

    /*
    ** Make sure that the number of arguments is correct.  Note that the list
    ** size is 1 more than the argument count!
    */

    if (GETMETASIZE(*arglist) != argcnt+1)
        {
        fprintf(stderr, "wlancfg: \"%s\" argument count is wrong.\n", name);
        return(1);
        }

    return(0);
}
