/*  ---------------------------------------------------------------
    Name:       patmail.c
    Title:      SMTP mailer functions

		
    Written:    Pat Adamo, Friar Systems
    			Adopted from sflmail.c 97/06/18  Scott Beasley <jscottb@infoave.com>
				This code has been created from a bunch of sfl files.
				All necessary functions have been brought into this file
				in order to NOT need the linked library.

    Synopsis:   Functions to format and send SMTP messages.  
    
    Copyright:  Copyright (c) 1999 Pat Adamo
    License:    this is free software; you can redistribute it and/or modify it.
                This software is distributed in the hope that it will be useful, 
                but without any warranty.
 ------------------------------------------------------------------*/

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
#include "smtpmail.h"


SMTP smtp;


static char
    *months [] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        };
static char
    *days [] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};



#if 0
main()
	{
	printf("-------------------------------------------------\n\r");
	printf("SMTP Mailing Test\n\r");
	smtp_clear(&smtp);
	
	smtp.strSmtpServer = "192.168.38.22";
	smtp.strMessageBody = "This is the body of the Pat's e-Mail from his uCLinux-Coldfire Board!";
	smtp.strSubject = "This is the subject of Pat's ucLinux e-Mail.<15>";
	
	//this is the e-mail address of the sender
	smtp.strSenderUserId = "";		//smtp.strSenderUserId = "padamo@worldnet.att.net";
	smtp.strFullSenderUserId = """Pat Adamo"" <padamo@worldnet.att.net>";
	
	//NOTE: these must be pointed into VARIABLE SPACE, otherwise you get memory faults!
	//Desitination addresses
	smtp.strDestUserIds = smtp_fill_in_addresses("padamo@worldnet.att.net;padamo@worldnet.att.net");
	if (smtp.strDestUserIds == NULL) exit(-1);
	smtp.strFullDestUserIds = "";
	
	//CC addresses
	smtp.strCcUserIds = "";
	smtp.strCcUserIds = smtp_fill_in_addresses("padamo@worldnet.att.net;Pat_Adamo@ademco.com");
	if (smtp.strCcUserIds == NULL) exit(-1);
	smtp.strFullCcUserIds = "";
	
	//BCC addresses
	smtp.strBccUserIds = "";
	smtp.strBccUserIds = smtp_fill_in_addresses("padamo@worldnet.att.net;Pat_Adamo@ademco.com");
	if (smtp.strBccUserIds == NULL) exit(-1);
	smtp.strFullBccUserIds = "";
	
	smtp.strRplyPathUserId = "padamo@worldnet.att.net";
	//this is who the return receipt goes back to
	smtp.strRrcptUserId = "";
	//override the name of the mailing function with this field
	smtp.strMailerName = "";
	//add a comment here if necessary
	smtp.strMsgComment = "";
	smtp_print(&smtp);
	smtp_send_mail(&smtp,TRUE);	//show progress of sending process
	free(smtp.strDestUserIds);
	free(smtp.strCcUserIds);
	free(smtp.strBccUserIds);
	printf("-------------------------------------------------\n\r");
	
	} //end proc main()
#endif

//	addr_field_string POINTS to the pointer
char * smtp_fill_in_addresses(char * source_string)
	{
	char * retval;
	retval = (char *)malloc(strlen(source_string)+1);
	if (retval != NULL)
	   {
	   //copy source into variable space!
	   strcpy(retval,source_string);
	   }
	return(retval);
	} //end proc smtp_fill_in_address_field()	
	
	
void smtp_clear(SMTP * smtp)
   {
   if (smtp == NULL) return;
	smtp->strSmtpServer = "";
	smtp->strMessageBody = "";
	smtp->strSubject = "";
	//this is the e-mail address of the sender
	smtp->strSenderUserId = "";
	smtp->strFullSenderUserId = "";
	//Desitination addresses
	smtp->strDestUserIds = "";
	smtp->strFullDestUserIds = "";
	//CC addresses
	smtp->strCcUserIds = "";
	smtp->strFullCcUserIds = "";
	//BCC addresses
	smtp->strBccUserIds = "";
	smtp->strFullBccUserIds = "";
	smtp->strRplyPathUserId = "";
	//this is who the return receipt goes back to
	smtp->strRrcptUserId = "";
	//override the name of the mailing function with this field
	smtp->strMailerName = "";
	//add a comment here if necessary
	smtp->strMsgComment = "";	
	} //end proc smtp_clear()
	
	
void smtp_print(SMTP * smtp)
   {
	printf("Server: %s\n\r",smtp->strSmtpServer);
	printf("Message Body: %s \n\r",smtp->strMessageBody);
	printf("Subject: %s \n\r",smtp->strSubject);
	printf("SenderUserId: %s\n\r",smtp->strSenderUserId);
	printf("DestUserIds: %s \n\r",smtp->strDestUserIds);
	printf("RrcptUserId: %s \n\r",smtp->strRrcptUserId);
   }

//----------------------------------------------------------------------
//    Function: smtp_send_mail_ex
//
//    Synopsis: Format and send a SMTP message.  
//		Receivers are ";" or "," terminated.
//    
//		smtp points to a filled in SMTP structure.
//		show_progress 0 = do not show progress, 1 = printf to stdout
//			to show progress.
//---------------------------------------------------------------------

int smtp_send_mail (SMTP *smtp, int show_progress)
   {
   int iCnt,x,retval;
   char strRetBuff[513];
   char *strRcptUserIds;

   /* The following tells the mail server who to send it to. */
	//Loop for each recipient
   iCnt = 0;



	if (show_progress)
   	printf("Mallocing %d\n\r",strlen (smtp->strDestUserIds) +
                                     strlen (smtp->strCcUserIds) +
                                     strlen (smtp->strBccUserIds) + 3);

   strRcptUserIds = (char *) malloc (strlen (smtp->strDestUserIds) +
                                     strlen (smtp->strCcUserIds) +
                                     strlen (smtp->strBccUserIds) + 3);

	
   if (strRcptUserIds == NULL)
   	{
		if (show_progress)
   		printf("Malloc Failed!\n\r");
   	return(-100);
   	} //end if malloc failed

	//concatenate the destuserids, the ccuserids, and the bccuserids
   sprintf (strRcptUserIds, "%s;%s;%s", smtp->strDestUserIds,
            smtp->strCcUserIds, smtp->strBccUserIds);


   while (1)
     	{
      getstrfld (strRcptUserIds, iCnt++, 0, ",;", strRetBuff);

      if (*strRetBuff)
         {
		   if (show_progress)
		   	printf("Recipient %d %s\n\r",iCnt,strRetBuff);
         }
        else
         break;
		} //wend (1)
	
	iCnt--;	//will always at least be 1(if no recipients!)
	
	//iCnt now knows how many resipients...

   free (strRcptUserIds);
	
	for (x = 1;x<=iCnt;x++)
	   {
	   //send a message for each recipient...
	   retval = smtp_send_mail_func(smtp,x,show_progress);
	   if (retval) break;
	   } //next x
	
	return (retval);
	} //end proc smtp_send_mail()
	

int smtp_send_mail_func (SMTP *smtp,int recipient_index, int show_progress)
   {
   int iCnt;
   int iSocket;
   char strOut[514], strRetBuff[513];
   char computer[256];
   char *strRcptUserIds;
   int rply;
	
	if (show_progress)
		printf("Sending Message to Recipient %d of %s.\n\r",recipient_index,smtp->strDestUserIds);


	iSocket = smtp_connect(smtp);

	if (iSocket <0) return (-1);
	
	if (show_progress)
		printf("Waiting for Reply from SMTP Server.\n\r");
	
   if (getreply (iSocket, smtp) > 400 || iSocket < 1)
       return -1;

	/* Format a SMTP meassage header.  */
   /* Just say hello to the mail server. */

	if (show_progress)
   	printf("Saying HELO to Server.\n\r");

   gethostname(&computer[0],255); //get back the name of this computer
   xstrcpy (strOut, "HELO ", computer, "\n", NULL);
   smtp_send_data (iSocket, strOut);

	if (show_progress)
   	printf("Waiting for Reply from SMTP Server for HELO Msg.\n\r");

	if (getreply (iSocket, smtp) > 400)
		return -2;

   /* Tell the mail server who the message is from. */
   xstrcpy (strOut, "MAIL FROM:<", smtp->strSenderUserId, ">\n", NULL);

	if (show_progress)
   	printf("%s",strOut);

   smtp_send_data (iSocket, strOut);

	if (show_progress)
   	printf("Waiting for Reply from SMTP Server for MAIL FROM: msg.\n\r");

   if (getreply (iSocket, smtp) > 400)
       return -3;

	if (show_progress)
   	printf("Mallocing %d\n\r",strlen (smtp->strDestUserIds) +
                                     strlen (smtp->strCcUserIds) +
                                     strlen (smtp->strBccUserIds) + 3);

   strRcptUserIds = (char *) malloc (strlen (smtp->strDestUserIds) +
                                     strlen (smtp->strCcUserIds) +
                                     strlen (smtp->strBccUserIds) + 3);

	
   if (strRcptUserIds == NULL)
   	{
		if (show_progress)
   		printf("Malloc Failed!\n\r");
   	return(-100);
   	} //end if malloc failed

	//concatenate the destuserids, the ccuserids, and the bccuserids
   sprintf (strRcptUserIds, "%s;%s;%s", smtp->strDestUserIds,
            smtp->strCcUserIds, smtp->strBccUserIds);

   /* The following tells the mail server who to send it to. */
	//Loop for each recipient
   iCnt = 0;
	
   while (1)
     	{
      getstrfld (strRcptUserIds, iCnt++, 0, ",;", strRetBuff);

      if (*strRetBuff)
         {
         if (recipient_index == iCnt)
            {
            xstrcpy (strOut, "RCPT TO:<", strRetBuff, ">\r\n", NULL);
			
			   if (show_progress)
				   printf("Recipient %d %s",iCnt,strOut);

            smtp_send_data (iSocket, strOut);

			   if (show_progress)
				   printf("Waiting for Reply from SMTP Server for RCPT TO: msg.\n\r");

            if (getreply (iSocket, smtp) > 400)
               return -4;
            } //end if matching recipient index
         }
        else
         break;
		} //wend (1)

	
   free (strRcptUserIds);

   /* Now give it the Subject and the message to send. */
	if (show_progress)
		printf("DATA\n\r");

   smtp_send_data (iSocket, "DATA\r\n");
	
	if (show_progress)
		printf("Waiting for Reply from SMTP Server for DATA Message.\n\r");

   if (getreply (iSocket, smtp) > 400)
       return -5;

   /* Set the date and time of the message. */
   xstrcpy ( strOut, "Date: ", encode_mime_time (date_now (), time_now ()),
             " \r\n", NULL );

	if (show_progress)
		printf("%s",strOut);

   smtp_send_data (iSocket, strOut);

   /* The following shows all who it was sent to. */
   if ( smtp->strFullDestUserIds && *smtp->strFullDestUserIds )
		{
      replacechrswith (smtp->strFullDestUserIds, ";", ',');
      xstrcpy (strOut, "To: ", smtp->strFullDestUserIds, "\r\n", NULL);
		}
     else
		{
      replacechrswith (smtp->strDestUserIds, ";", ',');
      xstrcpy (strOut, "To: ", smtp->strDestUserIds, "\r\n", NULL);
		} //end if FullDestUserIds not Null

   // Set up the Reply-To path. 
   //If there is no setting for  the reply-to, stick in the e-mail address of
   //the sender.
   if (!smtp->strRplyPathUserId || !*smtp->strRplyPathUserId)
      smtp->strRplyPathUserId = smtp->strSenderUserId;

   //if the reply address is not surrounded by <>, add them.
   if ( (strstr( smtp->strRplyPathUserId, "<" ) != (char *)NULL) &&
        (strstr( smtp->strRplyPathUserId, ">" ) != (char *)NULL) )
   	{
      xstrcat (strOut, "Reply-To:", smtp->strRplyPathUserId, "\r\n", NULL);
     	}
     else
     	{
      xstrcat (strOut, "Reply-To:<", smtp->strRplyPathUserId, ">\r\n", NULL);
     	} //end if RplyPathUserId has <>


   //indicate the sender of the message.
   //If we have a FullSenderUserID, us it, otherwise use the SenderUserId
   if ( smtp->strFullSenderUserId && *smtp->strFullSenderUserId )
   	{
      xstrcat (strOut, "Sender:", smtp->strFullSenderUserId, "\r\n", NULL);
      xstrcat (strOut, "From:", smtp->strFullSenderUserId, "\r\n", NULL);
     	}
     else
     	{
      xstrcat (strOut, "Sender:", smtp->strSenderUserId, "\r\n", NULL);
      xstrcat (strOut, "From:", smtp->strSenderUserId, "\r\n", NULL);
     	} //end if FullSenderUserId not Null

	if (show_progress)
		printf("%s",strOut);

   smtp_send_data (iSocket, strOut);

	//reset strOut
   *strOut = '\0';

   /* Post any CC's. */
   //If there are FullCcUserIds, substitute ;s with ,s and use it,
   //otherwise, if there are CcUserIds, substitute ;s with ,s and use it
   if (smtp->strFullCcUserIds && *smtp->strFullCcUserIds)
     	{
      replacechrswith (smtp->strFullCcUserIds, ";", ',');
      xstrcat (strOut, "Cc:", smtp->strFullCcUserIds, "\r\n", NULL );
     	}
     else
	   {
   	if (smtp->strCcUserIds && *smtp->strCcUserIds)
     		{
       	replacechrswith (smtp->strCcUserIds, ";", ',');
       	xstrcat (strOut, "Cc:", smtp->strCcUserIds, "\r\n", NULL );
     		}
		} //end if FullCcUserIds not Null

   /* Post any BCC's. */
   //If there are FullBccUserIds, substitute ;s with ,s and use it,
   //otherwise, if there are BccUserIds, substitute ;s with ,s and use it
   if (smtp->strFullBccUserIds && *smtp->strFullBccUserIds)
      {
      replacechrswith (smtp->strFullBccUserIds, ";", ',');
      xstrcat (strOut, "Bcc:", smtp->strFullBccUserIds, "\r\n", NULL);
      }
     else
	  	{
      if (smtp->strBccUserIds && *smtp->strBccUserIds)
	     {
	     replacechrswith (smtp->strBccUserIds, ";", ',');
	     xstrcat (strOut, "Bcc:", smtp->strBccUserIds, "\r\n", NULL);
	     }
	  	} //end if FullBccUserIds not Null

   /* Post any Return-Receipt-To. */
   //e-mail address of e-mail address to send return receipt to.
   if (smtp->strRrcptUserId && *smtp->strRrcptUserId)
   	xstrcat (strOut, "Return-Receipt-To:", smtp->strRrcptUserId, ">\r\n",
      		NULL);

   //indicate the mailing function.
   //If the caller is overriding, use the name supplied, otherwise
   //send the name of this function.
   if (smtp->strMailerName && *smtp->strMailerName)
   	xstrcat (strOut, "X-Mailer: ", smtp->strMailerName, "\r\n", NULL);
     else
      xstrcat (strOut, "X-Mailer: ", SMTP_MAILER_NAME, "\r\n", NULL);

   /* Set the mime version. */
   strcat (strOut, "MIME-Version: 1.0\r\n");
   strcat (strOut,
   "Content-Type: Multipart/Mixed; boundary=Message-Boundary-21132\r\n");

	if (show_progress)
   	printf("%s\n\r",strOut);

   smtp_send_data (iSocket, strOut);

   /* Write out any message comment included. */
   xstrcpy (strOut, "Comments: ", smtp->strMsgComment, "\r\n", NULL);

   /* Send the subject and message body. */
   xstrcat (strOut, "Subject:", smtp->strSubject, "\n\r\n", NULL);

   
	if (show_progress)
   	printf("%s\n\r",strOut);

   smtp_send_data (iSocket, strOut);
   	
   //reset strOut
   *strOut = '\0';

   /* Keep rfc822 in mind with all the sections. */
   if (smtp->strMessageBody && *smtp->strMessageBody)
      {
      strcat (strOut, "\r\n--Message-Boundary-21132\r\n");
      strcat (strOut, "Content-Type: text/plain; charset=US-ASCII\r\n");
      strcat (strOut, "Content-Transfer-Encoding: 7BIT\r\n");
      strcat (strOut, "Content-description: Body of message\r\n\r\n");
		if (show_progress)
			printf("%s\n\r",strOut);
      smtp_send_data (iSocket, strOut);
      smtp_send_data (iSocket, smtp->strMessageBody);
      smtp_send_data (iSocket, "\r\n");
		if (show_progress)
  			printf("%s\n\r",smtp->strMessageBody);
      } //end if there is a message body


	if (show_progress)
   	printf("Closing Message.\n\r");

   /* This ends the message. */
   smtp_send_data (iSocket, ".\r\n");
	
	if (show_progress)
		printf("Waiting for Reply from SMTP Server .close .\n\r");

   if (getreply (iSocket, smtp) > 400)
      return -7;

	if (show_progress)
   	printf("Sending QUIT.\n\r");

   /* Now log off the SMTP port. */
   smtp_send_data (iSocket, "QUIT\n");

	if (show_progress)
		printf("Waiting for Reply from SMTP Server Quit msg.\n\r");

   if (getreply (iSocket, smtp) > 400)
   	return -8;

   /*
      Clean-up.
   */
   /* Close the port up. */

   #if (!TESTING)
	if ((smtp->sock_fd = close(smtp->sock_fd)) < 0)
		{
		if (show_progress)
			fprintf(stderr, "ERROR: failed to close SMTP Connection through, errno=%d\n",errno);
		return(-1);
		} //end if close failed
	#endif


   return 0;
	} //end proc smtp_send_mail()


/*
 *  getreply -- internal
 *
 *  Synopsis: Get a reply from the SMTP server and see thats it's not
 *  an error. This function is used by smtp_send_mail.
 * -------------------------------------------------------------------------*/

static int getreply (int iSocket, SMTP *smtp)
	{
  	char strRetBuff[513];

   #if TESTING
   return(1);	//make believe that all was well
   #endif

   *strRetBuff = 0;
   read (iSocket, strRetBuff, 512);

   /* See if we have not gotten a response back from the mail server. */
   if (!*strRetBuff)
     	{
   	return 777;
     	}


   trim (strRetBuff);
   strRetBuff[3] = (char)0;

   return atoi (strRetBuff);
	} //end proc getreply()


/*  ---------------------------------------------------------------------[<]-
    Function: getstrfld

    Synopsis: Gets a sub-string from a formated string. nice strtok
    replacement.

    usage:
      char strarray[] = { "123,456,789,abc" };
      char strretbuff[4];
      getstrfld (strarray, 2, 0, ",", strretbuff);

    This would return the string "789" and place it also in strretbuff.
    Returns a NULL if fldno is out of range, else returns a pointer to
    head of the buffer.  Submitted by Scott Beasley <jscottb@infoave.com>
    ---------------------------------------------------------------------[>]-*/

char * getstrfld (char *strbuf, int fldno, int ofset, char *sep, char *retstr)
	{
   char *offset, *strptr;
   int curfld;

   offset = strptr = (char *)NULL;
   curfld = 0;

   strbuf += ofset;

   while (*strbuf)
     {
       strptr = !offset ? strbuf : offset;
       offset = strpbrk ((!offset ? strbuf : offset), sep);

       if (offset)
          offset++;
       else if (curfld != fldno)
         {
           *retstr = (char)NULL;
           break;
         }

       if (curfld == fldno)
         {
           strncpy (retstr, strptr,
              (int)(!offset ? strlen (strptr)+ 1 :
              (int)(offset - strptr)));
           if (offset)
              retstr[offset - strptr - 1] = 0;

           break;
         }
       curfld++;
     }
   return retstr;
	} //end proc getstrfld()
	
	
	
/*  ---------------------------------------------------------------------[<]-
    Function: trim

    Synopsis: Eats the whitespace's from the left and right side of a
    string.  This function maintains a proper pointer head.  Returns a
    pointer to head of the buffer.
    Submitted by Scott Beasley <jscottb@infoave.com>
    ---------------------------------------------------------------------[>]-*/

char * trim (char *strin)
	{
    ltrim (strin);
    strcrop (strin);
    return strin;
	}

#define deletechar(strbuf,pos) strcpy((strbuf+pos),(strbuf+pos+1))

/*  ---------------------------------------------------------------------[<]-
    Function: ltrim

    Synopsis: Deletes leading white spaces in string, and returns a
    pointer to the first non-blank character.  If this is a null, the
    end of the string was reached.
    ---------------------------------------------------------------------[>]-*/

char * ltrim (char *string)
	{

   	while (isspace(*string))
       deletechar(string,0);

   	return string;
	}

/*  ---------------------------------------------------------------------[<]-
    Function: strcrop

    Synopsis: Drops trailing whitespace from string by truncating string
    to the last non-whitespace character.  Returns string.  If string is
    null, returns null.
    ---------------------------------------------------------------------[>]-*/

char * strcrop (char *string)
	{
    char *last;

    if (string)
      	{
        last = string + strlen (string);
        while (last > string)
          	{
            if (!isspace (*(last - 1)))
                break;
            last--;
          	}
        *last = 0;
      	}
    return (string);
	}



/*  ---------------------------------------------------------------------[<]-
    Function: xstrcat

    Synopsis: Concatenates multiple strings into a single result.  Eg.
    xstrcat (buffer, "A", "B", NULL) stores "AB" in buffer.  Returns dest.
    Append the string to any existing contents of dest.
    From DDJ Nov 1992 p. 155, with adaptions.
    ---------------------------------------------------------------------[>]-*/

char * xstrcat (char *dest, const char *src, ...)
	{
    char *feedback = dest;
    va_list va;

    while (*dest)                       /*  Find end of dest string          */
        dest++;

    va_start (va, src);
    while (src)
      	{
        while (*src)
            *dest++ = *src++;
        src = va_arg (va, char *);
      	} //wend (src)
    *dest = '\0';                       /*  Append a null character          */
    va_end (va);
    return (feedback);
	} //end proc xtrcat()


/*  ---------------------------------------------------------------------[<]-
    Function: xstrcpy

    Synopsis: Concatenates multiple strings into a single result.  Eg.
    xstrcpy (buffer, "A", "B", NULL) stores "AB" in buffer.  Returns dest.
    Any existing contents of dest are cleared.  If the dest buffer is NULL,
    allocates a new buffer with the required length and returns that.  The
    buffer is allocated using mem_alloc(), and should eventually be freed
    using mem_free() or mem_strfree().  Returns NULL if there was too little
    memory to allocate the new string.  
    ---------------------------------------------------------------------[>]-*/

char * xstrcpy (char *dest, const char *src, ...)
	{
    const char *src_ptr;
    va_list va;
    size_t dest_size;                   /*  Size of concatenated strings     */

    /*  Allocate new buffer if necessary                                     */
	if (dest == NULL)
      	{
        va_start (va, src);             /*  Start variable args processing   */
        src_ptr   = src;
        dest_size = 1;                  /*  Allow for trailing null char     */
        while (src_ptr)
          	{
            dest_size += strlen (src_ptr);
            src_ptr = va_arg (va, char *);
          	} //wend (src_ptr)
        va_end (va);                    /*  End variable args processing     */

		  dest = (char *) malloc(dest_size);
        if (dest == NULL)
            return (NULL);              /*  Not enough memory                */
      	} //end if (dest == NULL)

    /*  Now copy strings into destination buffer                             */
    va_start (va, src);                 /*  Start variable args processing   */
    src_ptr  = src;
    dest [0] = '\0';
    while (src_ptr)
      	{
        strcat (dest, src_ptr);
        src_ptr = va_arg (va, char *);
      	} //wend (src_ptr)
    va_end (va);                        /*  End variable args processing     */
    return (dest);
	} //end proc xtrcpy()

/*  ---------------------------------------------------------------------[<]-
    Function: replacechrswith

    Synopsis: Subsitutes known char(s)in a string with another. Returns
    pointer to head of the buffer.
    Submitted by Scott Beasley <jscottb@infoave.com>
    ---------------------------------------------------------------------[>]-*/

char * replacechrswith (char *strbuf, char *chrstorm, char chartorlcwith)
	{
   char *offset;

   offset = (char *)NULL;

   while (*strbuf)
      {
         offset = strpbrk (strbuf, chrstorm);
         if (offset)
           {
             *(offset)= chartorlcwith;
           }

         else
             break;
      }

   return strbuf;
	} //end proc replacechrswith()
	
void smtp_send_data(int sock,char * strout)
	{
	#if (!TESTING)
	write (sock, strout, strlen(strout));
	#endif
	} //end proc smtp_send_data();

int smtp_connect(SMTP * smtp)
	{
	struct sockaddr_in address;
	int len;
	int result;
	
	#if TESTING
	return(1);
	#endif

	printf("Connecting to SMTP Server at %s.\n",smtp->strSmtpServer);
	//create a socket
	if ((smtp->sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		{
		fprintf(stderr, "ERROR: failed to open Socket, errno = %d.\n",errno);
		return(-1);
		} //end if socket failed
	//set up the address
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr(smtp->strSmtpServer);
	address.sin_port = htons(25);      //mail proxy port
	len = sizeof(address);
	result = connect(smtp->sock_fd,(struct sockaddr *)&address,len);
	if (result == -1)
		{
		//connect failed
		fprintf(stderr, "ERROR: failed to open SMTP Connection, errno=%d\n", errno);
		return(-1);
		} //end if (result == -1) - connect failed
	printf("Connection Made to SMTP Server.\n");
	return(smtp->sock_fd);	//return the socket file descriptor
	} //end proc smpt_connect()
	
	
	
#define GET_MONTH(d)        (int) (((d) % 10000L) / 100)
#define GET_DAY(d)          (int) ( (d) % 100)
#define GET_CCYEAR(d)       (int) ( (d) / 10000L)
#define GET_YEAR(d)         (int) (((d) % 1000000L) / 10000L)
#define GET_HOUR(t)         (int) ( (t) / 1000000L)
#define GET_MINUTE(t)       (int) (((t) % 1000000L) / 10000L)
#define GET_SECOND(t)       (int) (((t) % 10000L) / 100)
#define MAKE_DATE(c,y,m,d)  (long) (c) * 1000000L +                          \
                            (long) (y) * 10000L +                            \
                            (long) (m) * 100 + (d)
#define MAKE_TIME(h,m,s,c)  (long) (h) * 1000000L +                          \
                            (long) (m) * 10000L +                            \
                            (long) (s) * 100 + (c)


/*  ---------------------------------------------------------------------[<]-
    Function: encode_mime_time

    Synopsis: Encode date and time (in long format) in Mime RFC1123 date
    format, e.g. Mon, 12 Jan 1995 12:05:01 GMT.  The supplied date and time
    are in local time.  Returns the date/time string if the date was legal,
    else returns "?".  Returned string is in a static buffer.
    ---------------------------------------------------------------------[>]-*/

char * encode_mime_time (long date, long time)
	{
    int
        day_week,                       /*  Day of week number (0 is sunday) */
        month;                          /*  Month number                     */
    static char
        buffer [50];

    local_to_gmt (date, time, &date, &time);
    day_week = day_of_week (date);
    month    = GET_MONTH   (date);
    if (day_week >= 0 && day_week < 7 && month > 0 && month < 13)
      {
        sprintf (buffer, "%s, %02d %s %04d %02d:%02d:%02d GMT",
                         days       [day_week],
                         GET_DAY    (date),
                         months     [month - 1],
                         GET_CCYEAR (date),
                         GET_HOUR   (time),
                         GET_MINUTE (time),
                         GET_SECOND (time)
                 );
        return (buffer);
      }
    else
        return ("?");
	} //end proc encode_mime_time()



/*  ---------------------------------------------------------------------[<]-
    Function: local_to_gmt

    Synopsis: Converts the specified date and time to GMT.  Returns the GMT
    date and time in two arguments.
    ---------------------------------------------------------------------[>]-*/

void local_to_gmt (long date, long time, long *gmt_date, long *gmt_time)
	{
    time_t
        time_value;

    time_value = date_to_timer   (date, time);
    *gmt_date  = timer_to_gmdate (time_value);
    *gmt_time  = timer_to_gmtime (time_value);
	} //end proc local_to_gmt()


/*  ---------------------------------------------------------------------[<]-
    Function: date_to_timer

    Synopsis: Converts the supplied date and time into a time_t timer value.
    This is the number of non-leap seconds since 00:00:00 GMT Jan 1, 1970.
    Function was rewritten by Bruce Walter <walter@fortean.com>.  If the
    input date and time are invalid, returns 0.
    ---------------------------------------------------------------------[>]-*/

time_t date_to_timer (long date, long time)
	{
    struct tm
        time_struct;
    time_t
        timer;

    time_struct.tm_sec   = GET_SECOND (time);
    time_struct.tm_min   = GET_MINUTE (time);
    time_struct.tm_hour  = GET_HOUR   (time);
    time_struct.tm_mday  = GET_DAY    (date);
    time_struct.tm_mon   = GET_MONTH  (date) - 1;
    time_struct.tm_year  = GET_CCYEAR (date) - 1900;
    time_struct.tm_isdst = -1;
    timer = mktime (&time_struct);
    if (timer == -1)
        return (0);
    else
        return (timer);
	} //end proc date_to_timer()

/*  ---------------------------------------------------------------------[<]-
   Function: timer_to_date

    Synopsis: Converts the supplied timer value into a long date value.
    Dates are stored as long values: CCYYMMDD.  If the supplied value is
    zero, returns zero.  If the supplied value is out of range, returns
    1 January, 1970 (19700101). The timer value is assumed to be UTC (GMT).
    ---------------------------------------------------------------------[>]-*/

long timer_to_date (time_t time_secs)
	{								
    struct tm
        *time_struct;

   if (time_secs == 0)
        return (0);
    else
      {
        /*  Convert into a long value CCYYMMDD                               */
        time_struct = localtime (&time_secs);
        if (time_struct)
          {
            time_struct-> tm_year += 1900;
            return (MAKE_DATE (time_struct-> tm_year / 100,
                               time_struct-> tm_year % 100,
                               time_struct-> tm_mon + 1,
                               time_struct-> tm_mday));
          }
        else
            return (19700101);
      }
	} //end proc timer_to_date()

/*  ---------------------------------------------------------------------[<]-
    Function: timer_to_time

    Synopsis: Converts the supplied timer value into a long time value.
    Times are stored as long values: HHMMSS00.  Since the timer value does
    not hold centiseconds, these are set to zero.  If the supplied value
    was zero or invalid, returns zero.  The timer value is assumed to be UTC
    (GMT).
    ---------------------------------------------------------------------[>]-*/

long timer_to_time (time_t time_secs)
	{
    struct tm
        *time_struct;

    if (time_secs == 0)
        return (0);
    else
      {
        /*  Convert into a long value HHMMSS00                               */
        time_struct = localtime (&time_secs);
        if (time_struct)
            return (MAKE_TIME (time_struct-> tm_hour,
                               time_struct-> tm_min,
                               time_struct-> tm_sec,
                               0));
        else
            return (0);
      }
	} //end proc timer_to_time()


/*  ---------------------------------------------------------------------[<]-
    Function: timer_to_gmdate

    Synopsis: Converts the supplied timer value into a long date value in
    Greenwich Mean Time (GMT).  Dates are stored as long values: CCYYMMDD.
    If the supplied value is zero, returns zero.  If the supplied value is
    out of range, returns 1 January, 1970 (19700101).
    ---------------------------------------------------------------------[>]-*/

long timer_to_gmdate (time_t time_secs)
	{
    struct tm
        *time_struct;

    if (time_secs == 0)
        return (0);
    else
      {
        /*  Convert into a long value CCYYMMDD                               */
        time_struct = gmtime (&time_secs);
        if (time_struct == NULL)        /*  If gmtime is not implemented     */
            time_struct = localtime (&time_secs);

        if (time_struct)
          {
            time_struct-> tm_year += 1900;
            return (MAKE_DATE (time_struct-> tm_year / 100,
                               time_struct-> tm_year % 100,
                               time_struct-> tm_mon + 1,
                               time_struct-> tm_mday));
          }
        else
            return (19700101);          /*  We had an invalid date           */
      }
	} //end proc timer_to_gmdate()


/*  ---------------------------------------------------------------------[<]-
    Function: timer_to_gmtime

    Synopsis: Converts the supplied timer value into a long time value in
    Greenwich Mean Time (GMT).  Times are stored as long values: HHMMSS00.
    On most systems the clock does not return centiseconds, so these are
    set to zero.  If the supplied value is zero or invalid, returns zero.
    ---------------------------------------------------------------------[>]-*/

long timer_to_gmtime (time_t time_secs)
	{
    struct tm
        *time_struct;

    if (time_secs == 0)
        return (0);
    else
      {
        /*  Convert into a long value HHMMSS00                               */
        time_struct = gmtime (&time_secs);
        if (time_struct == NULL)        /*  If gmtime is not implemented     */
            time_struct = localtime (&time_secs);

        if (time_struct)
            return (MAKE_TIME (time_struct-> tm_hour,
                               time_struct-> tm_min,
                               time_struct-> tm_sec,
                               0));
        else
            return (0);
      }
	} //end proc timer_to_gmtime()

/*  ---------------------------------------------------------------------[<]-
    Function: day_of_week

    Synopsis: Returns the day of the week where 0 is Sunday, 1 is Monday,
    ... 6 is Saturday.  Uses Zeller's Congurence algorithm.
    ---------------------------------------------------------------------[>]-*/

int day_of_week (long date)
	{
    int
        year  = GET_CCYEAR (date),
        month = GET_MONTH  (date),
        day   = GET_DAY    (date);

    if (month > 2)
        month -= 2;
    else
      {
        month += 10;
        year--;
      }
    day = ((13 * month - 1) / 5) + day + (year % 100) +
          ((year % 100) / 4) + ((year / 100) / 4) - 2 *
           (year / 100) + 77;

    return (day - 7 * (day / 7));
	} //end proc day_of_week()

/*  ---------------------------------------------------------------------[<]-
    Function: time_now

    Synopsis: Returns the current time as a long value (HHMMSSCC).  If the
    system clock does not return centiseconds, these are set to zero.
    ---------------------------------------------------------------------[>]-*/

long time_now (void)
	{

    /*  The BSD gettimeofday function returns seconds and microseconds       */
    struct timeval
        time_struct;

    gettimeofday (&time_struct, 0);
    return (timer_to_time (time_struct.tv_sec)
                         + time_struct.tv_usec / 10000);

	} //end proc time_now()

/*  ---------------------------------------------------------------------[<]-
    Function: date_now

    Synopsis: Returns the current date as a long value (CCYYMMDD).  Since
    most system clocks do not return a century, this function assumes that
    all years 80 and above are in the 20th century, and all years 00 to 79
    are in the 21st century.  For best results, consume before 1 Jan 2080.
    ---------------------------------------------------------------------[>]-*/

long date_now (void)
	{
    return (timer_to_date (time (NULL)));
	} //end proc date_now()

