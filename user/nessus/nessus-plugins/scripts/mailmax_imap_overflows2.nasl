#
# (C) Tenable Network Security
#
# Ref:
#  Date: Sat, 17 May 2003 14:31:14 +0200 
#  From: 0x36 <release@0x36.org>
#  To: bugtraq@securityfocus.com
#  Subject: Buffer overflow vulnerability found in MailMax version 5



if(description)
{
 script_id(11637);
 script_bugtraq_id(7327);
 script_version ("$Revision: 1.5 $");

 
 name["english"] = "MailMax IMAP overflows (2)";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary commands may be executed on the remote host using the
remote IMAP server.

Description :

The remote host is running a version of the MailMax IMAP server which, 
according to its version number, is vulnerable to various overflows which 
may allow an authenticated user to execute arbitrary commands on this 
host or to disable it remotely.

Solution : 

Upgrade to MailMax 5.5 or newer

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of the remote IMAP server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#

include("imap_func.inc");

port = get_kb_item("Services/imap");
if(!port)port = 143;
banner = get_imap_banner ( port: port );
if ( ! banner ) exit(0);
if(egrep(pattern:"MailMax [1-5][^0-9]", string:banner) ) security_warning(port);
