/*
 * chap.h - Challenge Handshake Authentication Protocol definitions.
 *
 * Copyright (c) 1995 Eric Rosenquist, Strata Software Limited.
 * http://www.strataware.com/
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Eric Rosenquist.  The name of the author may not be used to
 * endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * $Id: chap_ms.h,v 1.2 2002-08-28 06:19:47 philipc Exp $
 */

#ifndef __CHAPMS_INCLUDE__

typedef struct {
    u_char LANManResp[24];
    u_char NTResp[24];
    u_char UseNT;		/* If 1, ignore the LANMan response field */
} MS_ChapResponse;
/* We use MS_CHAP_RESPONSE_LEN, rather than sizeof(MS_ChapResponse),
   in case this struct gets padded. */

typedef struct {
    u_char PeerChallenge[16];
    u_char Reserved[8];
    u_char NTResp[24];
    u_char Flags;
} MS_ChapResponse_v2;

void ChapMS __P((chap_state *, char *, int, char *, int));
int  ChapMS_Resp __P((chap_state *, char *, int, u_char *));
void ChapMS_v2 __P((chap_state *, char *, int, char *, int));
int  ChapMS_v2_Resp __P((chap_state *, char *, int, u_char *, char *));
void ChapMS_v2_Auth __P((chap_state *, char *, int, u_char *, char *));

int reqchapms(char **);
int nochapms(char **);
int reqchapms_v2(char **);
int nochapms_v2(char **);

#define __CHAPMS_INCLUDE__
#endif /* __CHAPMS_INCLUDE__ */
