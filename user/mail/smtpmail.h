/*  ----------------------------------------------------------------<Prolog>-
    Name:       smtpmail.h
    Title:      SMTP mailer function

    Modified:	 10/16/99 Pat Adamo (padamo@worldnet.att.net)
    Original:	 06/18/97, 99/07/06 Scott Beasley (jscottb@infoave.com)

    Synopsis:   Functions to format and send SMTP messages.  Messages
                may be sent with "cc"'s "bcc"'s as well as the normal
                "to" receivers.
            
    Copyright:  Copyright (C) 1999 P. Adamo, ripped off from sfl library.
    License:    this is free software; you can redistribute it and/or modify
                it. This software is distributed in the hope that it will be
                useful, but without any warranty whatsoever.
 ------------------------------------------------------------------</Prolog>-*/

#ifndef _smtpmail_included               /*  allow multiple inclusions        */
#define _smtpmail_included

#define SMTP_MAILER_NAME	"smtpmail function"

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdarg.h>		//for variable argument lists
//#include <netinet/in.h>
#include <arpa/inet.h>
//#include <unistd.h>
//#include <netdb.h>
#include <errno.h>


#define TESTING 0
#define SILENT 1
#define TRUE 1
#define FALSE 0

/*  Macros & defines                                                         */
/* Macro to encoding a char and make it printable. */
#define ENC(c) ((c) ? ((c) & 077) + ' ': '`')
/* Macro to write too the smtp port. */
//#define smtp_send_data(sock,strout) write_TCP((sock),(strout),strlen((strout)))
//#define smtp_send_data(sock,strout)	write ((int) handle, buffer, length)


typedef struct SMTP {
	//these fields may be filled in with the indicated data.  Any string fields
	//that are not used MUST be initialized to "".
   char *strSmtpServer;						//This is the "xxx.xxx.xxx.xxx" string 
   												//IP Addrress of the SMTP mail server or
													//the address of the SMTP Proxy server
   char *strSubject;							//String containing the Subject of the e-mail.
   char *strMessageBody;					//String of the Message Body.  May be
													//multiple lines seperated by crlfs
													//terminated by a NULL
   char *strSenderUserId;					//string containing the e-mail address of
													//the sender ex: "padamo@worldnet.att.net"
   char *strFullSenderUserId;          //alternate sender e-mail address in the
   												//following form: 
   												//""Pat Adamo" <padamo@worldnet.att.net>"
   char *strDestUserIds;					//String formatted as a list of recipient
													//e-mail addresses ex:
													//"padamo@worldnet.att.net;jsmith@comp.com"
   char *strFullDestUserIds;           //alternate list of recipient e-mail address
   												//in the following form: 
   												//""Pat Adamo" <padamo@worldnet.att.net>;
   												//"John Smith" <jsmith@comp.com>"
   char *strCcUserIds;						//String formatted as a list of carbon-copy
   												//recipient e-mail addresses ex:
													//"padamo@worldnet.att.net;jsmith@comp.com"
   char *strFullCcUserIds;					//alternate list of carbon-copy recipient
   												//e-mail address in the following form: 
   												//""Pat Adamo" <padamo@worldnet.att.net>;
   												//"John Smith" <jsmith@comp.com>"
   char *strBccUserIds;						//String formatted as a list of blind 
   												//carbon-copy recipient e-mail addresses ex:
													//"padamo@worldnet.att.net;jsmith@comp.com"
   char *strFullBccUserIds;				//alternate list of blind carbon-copy recipient
   												//e-mail address in the following form: 
   												//""Pat Adamo" <padamo@worldnet.att.net>;
   												//"John Smith" <jsmith@comp.com>"
   char *strRplyPathUserId;				//e-mail address to address replies to
													//ex: "padamo@worldnet.att.net"
   char *strRrcptUserId;					//e-mail address to send return receipt
													//the sender ex: "padamo@worldnet.att.net"
   char *strMsgComment;						//String Message Comment (optional)
   char *strMailerName;						//Name of function or program sending this
													//message.  If not supplied, will be
													//substituted with defn SMTP_MAILER_NAME
  	int  sock_fd;								//internal storage for socket file descriptor
	//not implemented yet...
   int  connect_retry_cnt;					//number of tries to connect to server
   int  retry_wait_time;					//amount of time to wait before retries
	} SMTP;

//Function prototypes
int smtp_send_mail (SMTP *smtp, int show_progress);
void smtp_clear(SMTP * smtp);
char * smtp_fill_in_addresses(char * source_string);
void smtp_print(SMTP * smtp);

//Stactic function prototypes
int smtp_send_mail_func (SMTP *smtp, int recipient_index, int show_progress);
static int getreply (int iSocket, SMTP *smtp);
char * getstrfld (char *strbuf, int fldno, int ofset, char *sep, char *retstr);
char * trim (char *strin);
char * ltrim (char *string);
char * strcrop (char *string);
char * xstrcat (char *dest, const char *src, ...);
char * xstrcpy (char *dest, const char *src, ...);
char * replacechrswith (char *strbuf, char *chrstorm, char chartorlcwith);
int smtp_connect(SMTP * smtp);
void smtp_send_data(int sock,char * strout);
char * encode_mime_time (long date, long time);
void local_to_gmt (long date, long time, long *gmt_date, long *gmt_time);
time_t date_to_timer (long date, long time);
long timer_to_gmdate (time_t time_secs);
long timer_to_gmtime (time_t time_secs);
int day_of_week (long date);
long time_now (void);
long date_now (void);



#endif //_smtpmail_included

