#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10258);
 script_bugtraq_id(2308);
 script_version ("$Revision: 1.28 $");
 script_cve_id("CVE-1999-0203");
 
 name["english"] = "Sendmail's from piped program";
 script_name(english:name["english"]);
 
 desc["english"] = "

The remote SMTP server did not complain when issued the
command :
	MAIL FROM: |testing
	
This probably means that it is possible to send mail 
that will be bounced to a program, which is 
a serious threat, since this allows anyone to execute 
arbitrary commands on this host.

*** This security hole might be a false positive, since
*** some MTAs will not complain to this test, but instead
*** just drop the message silently
   
Solution : upgrade your MTA or change it.

Risk factor : High";


 desc["francais"] = "

Le serveur SMTP distant n'a pas refusé la
suite de commandes suivante :
	MAIL FROM: |testing
	
Cela signifie probablement qu'il est possible
d'envoyer du courrier qui sera bouncé 
à un programme, ce qui est un problème de 
sécurité puisque cela permet à n'importe qui 
d'executer des commandes arbitraires sur 
cette machine.


*** Ce problème de sécurité peut etre
*** une fausse alerte, puisque certains MTA 
*** ne refusent pas ces commandes mais ignorent
*** le message envoyé

Solution : mettez à jour votre MTA ou changez-le.

Facteur de risque : Elevé";

 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Checks if the remote mail server can be used to gain a shell"; 
 summary["francais"] = "Vérifie si le serveur de mail distant peut etre utilisé obtenir un shell";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "sendmail_expn.nasl", "smtpserver_detect.nasl");
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
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 data = smtp_recv_banner(socket:soc);
 if(!data)exit(0);
 if("Sendmail" >!< data)exit(0);

 crp = string("HELO example.com\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 crp = string("MAIL FROM: |testing\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:4);
 if(data=="250 ")security_hole(port);
 close(soc);
 }
}
