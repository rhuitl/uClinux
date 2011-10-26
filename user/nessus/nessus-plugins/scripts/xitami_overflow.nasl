#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added a source reference link on www.securiteam.com

if(description)
{
 script_id(10322);
 script_bugtraq_id(6599);
 script_version ("$Revision: 1.13 $");
 
 name["english"] = "Xitami Web Server buffer overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "It is possible to make the remote web server execute
arbitrary code by sending a lot of data on the remote
TCP port 81.
	
This problem may allow an attacker to execute arbitrary code on
the remote system or create a denial of service.

Solution : None at this time. Contact Xitami

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Xitami buffer overflow";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports(81);
 exit(0);
}

#
# The script code starts here
#


port = 81;
if(get_port_state(port))
{
 data = crap(8192);
 soc = open_sock_tcp(port);
 if(soc > 0)
 {
  send(socket:soc, data:data);
  close(soc);
  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);
  else close(soc2);
 }
}
