#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10248);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-1999-0096");
 
 name["english"] = "Sendmail 'decode' flaw";
 name["francais"] = "Sendmail : problème avec 'decode'";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "

The remote SMTP server seems to pipe mail
sent to the 'decode' alias to a program.

There have been in the past a lot of security 
problems regarding this, as it would allow 
an attacker to overwrite arbitrary files
on the remote server.

We suggest you deactivate this alias.


Solution : remove the 'decode' line in /etc/aliases.

Risk factor : High";


 desc["francais"] = "
Le serveur SMTP distant semble directement
envoyer les mails adressés à l'alias 'decode'
à un programme.

Il y a eut beaucoup de problèmes à ce sujet
dans le passé, puisque il était possible
pour un pirate d'effacer des fichiers
arbitraires sur une machine ayant cette
politique.

Il est recommandé que vous désactiviez 
cet alias.

Solution : retirez la ligne 'decode' dans /etc/aliases.

Facteur de risque : Elevé";

 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Checks if the remote mail server can be used to overwrite files"; 
 summary["francais"] = "Vérifie si le serveur de mail distant peut etre utilisé pour effacer des fichiers";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_require_keys("SMTP/expn", "SMTP/sendmail");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");


# We need the EXPN command to be available

expn = get_kb_item("SMTP/expn");
if(!expn)exit(0);


port = get_kb_item("Services/smtp");
if(!port)port = 25;
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
 crp = string("EXPN decode\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(ereg(pattern:"^250 .*", string:data))
 {
  if("/bin" >< data)security_hole(port);
 }
 close(soc);
 }
}
