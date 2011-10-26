/**
**  @file       hi_client_norm.c
**  
**  @author     Daniel Roelker <droelker@sourcefire.com>
**  
**  @brief      HTTP client normalization routines
**  
**  We deal with the normalization of HTTP client requests headers and 
**  URI.
**  
**  In this file, we handle all the different HTTP request URI evasions.  The
**  list is:
**      - ASCII decoding
**      - UTF-8 decoding
**      - IIS Unicode decoding
**      - Directory traversals (self-referential and traversal)
**      - Multiple Slashes
**      - Double decoding
**      - %U decoding
**      - Bare Byte Unicode decoding
**      - Base36 decoding
**  
**  NOTES:
**      - Initial development.  DJR
*/
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>

#include "hi_norm.h"
#include "hi_return_codes.h"

#define MAX_URI 4096

int hi_client_norm(HI_SESSION *Session)
{
    static u_char UriBuf[MAX_URI];
    static u_char PostBuf[MAX_URI];
    HI_CLIENT_REQ    *ClientReq;
    int iRet;
    int iUriBufSize = MAX_URI;
    int iPostBufSize = MAX_URI;

    if(!Session || !Session->server_conf)
    {
        return HI_INVALID_ARG;
    }

    ClientReq = &Session->client.request;

    /* Handle URI normalization */
    if(ClientReq->uri_norm)
    {
        /* Enable checking for long dirs */
        Session->norm_flags &= ~HI_BODY;

        if( (iRet = hi_norm_uri(Session, UriBuf, &iUriBufSize, 
                           ClientReq->uri, ClientReq->uri_size)) )
        {
            /* There was a non-fatal problem normalizing */
            ClientReq->uri_norm = NULL;
            ClientReq->uri_norm_size = 0;
        }
        else 
        {
            /* Client code is expecting these to be set to non-NULL if 
             * normalization occurred. */
            ClientReq->uri_norm      = UriBuf;
            ClientReq->uri_norm_size = iUriBufSize;
        }
    }

    /* Handle normalization of post methods. 
     * Note: posts go into a different buffer. */
    if(ClientReq->post_norm)
    {
        /* Disable checking for long dirs in body */
        Session->norm_flags |= HI_BODY;

        if( (iRet = hi_norm_uri(Session, PostBuf, &iPostBufSize, 
                           ClientReq->post_raw, ClientReq->post_raw_size)) )
        {
            ClientReq->post_norm = NULL;
            ClientReq->post_norm_size = 0;
        }
        else 
        {
            ClientReq->post_norm      = PostBuf;
            ClientReq->post_norm_size = iPostBufSize;
        }
    }

    /*
    printf("** uri_norm = |");
    for(iCtr = 0; iCtr < ClientReq->uri_norm_size; iCtr++)
    {
        if(!isprint((int)ClientReq->uri_norm[iCtr]))
        {
            printf(".[%.2x]", ClientReq->uri_norm[iCtr]);
            continue;
        }
        printf("%c", ClientReq->uri_norm[iCtr]);
    }
    printf("| size = %u\n", ClientReq->uri_norm_size);
    */

    return HI_SUCCESS;
}
