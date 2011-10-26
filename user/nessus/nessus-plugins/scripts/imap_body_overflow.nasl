#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10966);
 script_bugtraq_id(4713);
 script_cve_id("CVE-2002-0379");
 script_version ("$Revision: 1.11 $");
 
 
 name["english"] = "IMAP4buffer overflow in the BODY command";

 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to execute arbitrary code on the remote host, through the 
IMAP server.

Description :

The remote version of UW-IMAP is vulnerable to a buffer overflow condition 
which may allow an authenticated attacker to execute arbitrary code on the 
remote host with the privileges of the IMAP server.


Solution : 

Upgrade to imap-2001a

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:L/Au:R/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "checks for a buffer overflow in imapd";
 summary["francais"] = "vérifie la présence d'un dépassement de buffer dans imapd";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 # can be changed to MIXED when real attack tried.
 
 script_copyright(english:"This script is Copyright (C) Tenable Network Security");
 
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "logins.nasl");
		       		     
 script_require_ports("Services/imap", 143);
 script_exclude_keys("imap/false_imap");
 exit(0);
}

include("imap_func.inc");

port = get_kb_item("Services/imap");
if(!port)port = 143;
if(!get_port_state(port))exit(0);
banner = get_imap_banner(port:port);
if ( ! banner || !ereg(pattern:"OK .* IMAP4rev1 *200[01]\.[0-9][^ ]* at", string:banner))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

r = recv_line(socket:soc, length:4096);

send(socket:soc, data:string("x capability\r\n"));
r = recv_line(socket:soc, length:4096);

# According to the UW guys, if the server replies with IMAP4 and IMAP4REV1
# then it's vulnerable to the overflow.
if("CAPABILITY IMAP4 IMAP4REV1" >< r ) security_warning(port);
