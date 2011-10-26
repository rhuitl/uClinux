#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10260);
 script_version ("$Revision: 1.33 $");
 script_cve_id("CVE-1999-0098", "CVE-1999-1015", "CVE-1999-1504");
 script_bugtraq_id(61, 62);
 name["english"] = "HELO overflow";
 name["francais"] = "Dépassement de HELO";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote SMTP server seems to allow remote users to
send mail anonymously by providing arguments that are 
too long to the HELO command (more than 1024 chars).

This problem may allow malicious users to send hate
mail or threatening mail using your server,
and keep their anonymity.

Risk factor : Low

Solution : If you are using sendmail, upgrade to
version 8.9.x or newer. If you do not run sendmail, contact
your vendor.";


 desc["francais"] = "
Le serveur SMTP distant semble permettre à n'importe qui
d'envoyer des mails de maniere anonyme en donnant un
argument trop long à la commande HELO (plus de 1024
caractères).

Ce problème peut permettre à des personnes mal intentionnées
d'envoyer des messages agressifs ou menacant en utilisant
votre serveur de mail, et en gardant leur anonymat.

Facteur de risque : Faible.

Solution : Si vous utilisez sendmail, mettez le à jour
en version 8.9.x. Si vous n'utilisez pas sendmail,
contactez votre vendeur.";


 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Checks if the remote mail server can be used to send anonymous mail"; 
 summary["francais"] = "Vérifie si le serveur de mail distant peut etre utilisé pour envoyer du mail anonyme";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "sendmail_expn.nasl", "smtpserver_detect.nasl", "smtpscan.nasl");
 script_exclude_keys("SMTP/wrapped", 
 		     "SMTP/qmail", 
		     "SMTP/microsoft_esmtp_5",
		     "SMTP/postfix",
		     "SMTP/domino");
		     
 script_require_keys("SMTP/sendmail");
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

sig = get_kb_item(string("smtp/", port, "/real_banner"));
if ( sig && "Sendmail" >!< sig ) exit(0);
banner = get_smtp_banner(port:port);
if("Sendmail" >!< banner) exit(0);


if(safe_checks())
{
  if("Sendmail" >< banner)
  {
   version = ereg_replace(string:banner,
                         pattern:".* Sendmail (.*)/.*",
                         replace:"\1");
  
  if(ereg(string:version, pattern:"((^[0-7]\..*)|(^8\.[0-8]\..*))"))
  {
   alrt = 
"You are running a version of Sendmail which is older
than version 8.9.0.

There's a flaw in this version which allows people to send
mail anonymously through this server (their IP won't be shown
to the recipient), through a buffer overflow in the HELO
command.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : upgrade to sendmail 8.9.0 or newer
Risk factor : Low";

   security_warning(port:port, data:alrt);
   }
 } 
 exit(0);
}


if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 data = smtp_recv_banner(socket:soc);
 if (!data)
 {
  close(soc);
  exit(0);
 }
 crp = string("HELO ", crap(1030), "\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:4);
 if(data == "250 ")security_warning(port);
 close(soc);
 }
}
