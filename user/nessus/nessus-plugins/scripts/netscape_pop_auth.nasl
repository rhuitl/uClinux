#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10681);
 script_bugtraq_id(1787);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2000-0960");
 name["english"] = "Netscape Messenging Server User List";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote POP server allows an attacker to determine wether
a given username exists or not.

Description :

The remote POP server allows an attacker to obtain a list
of valid logins on the remote host, thanks to a brute force
attack.

If the user connects to this port and issues the commands :
USER 'someusername'
PASS 'whatever'

Then he will get a different response if the account 'someusername'
exists or not.

Solution : 

None at this time

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the error messages issued by the pop3 server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"],
 	       francais:family["francais"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#
include("pop3_func.inc");

port = get_kb_item("Services/pop3");
if (!port) port = 110;
banner =  get_pop3_banner(port:port);
if ( ! banner || "Netscape Messaging Server" >!< banner ) exit(0);

if (get_port_state(port))
{
 soc = open_sock_tcp(port);

 if (soc)
 {
  r = recv_line(socket:soc, length:4096);
  if(r)
  {
   send(socket:soc, data:string("USER nessus", rand(), "\r\n"));
   r = recv_line(socket:soc, length:4096);
   send(socket:soc, data:string("PASS nessus", rand(), "\r\n"));
   r = recv_line(socket:soc, length:4096);
   close(soc);
   if(r && "User unknown" >< r)security_note(port);
  }
 }
}
