#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10259);
 script_version ("$Revision: 1.25 $");
 
 name["english"] = "Sendmail mailing to files";
 name["francais"] = "Sendmail envoye des mails aux fochiers";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "

The remote SMTP server did not complain when issued the
command :
	MAIL FROM: root@this_host
	RCPT TO: /tmp/nessus_test
	
This probably means that it is possible to send mail directly
to files, which is a serious threat, since this allows
anyone to overwrite any file on the remote server.

*** This security hole might be a false positive, since
*** some MTAs will not complain to this test, but instead
*** just drop the message silently.
*** Check for the presence of file 'nessus_test' in /tmp !
   
Solution : upgrade your MTA or change it.

Risk factor : High";


 desc["francais"] = "

Le serveur SMTP distant n'a pas refusé la
suite de commandes suivante :
	MAIL FROM: root@this_host
	RCPT TO: /tmp/nessus_test
	
Cela signifie probablement qu'il est possible
d'envoyer du courrier directement aux programmes,
ce qui est un problème de sécurité puisque
cela permet à n'importe qui d'effacer n'importe
quel fichier sur le système distant.

*** Ce problème de sécurité peut etre
*** une fausse alerte, puisque certains MTA 
*** ne refusent pas ces commandes mais ignorent
*** le message envoyé.
*** Vérfiez la présence du fichier nessus_test dans /tmp !

Solution : mettez à jour votre MTA ou changez-le.

Facteur de risque : Elevé";

 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Checks if the remote mail server can be used to gain a shell"; 
 summary["francais"] = "Vérifie si le serveur de mail distant peut etre utilisé pour obtenir un shell";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "sendmail_expn.nasl", "smtpserver_detect.nasl");
 script_exclude_keys("SMTP/wrapped", 
  		     "SMTP/microsoft_esmtp_5", 
 		     "SMTP/qmail",
 	 	     "SMTP/postfix");
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
 data = smtp_recv_banner(socket:soc);	
 if(!data || "Sendmail" >!< data)exit(0); # Only Sendmail vulnerable
 crp = string("HELO example.com\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 crp = string("MAIL FROM: root@",get_host_name(),"\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 crp = string("RCPT TO: /tmp/nessus_test\r\n");
 send(socket:soc, data:crp);
 
 data = recv_line(socket:soc, length:4);
 if(data == "250 "){
 	security_hole(port);
 	data = recv_line(socket:soc, length:1024);
 
	crp = string("DATA\r\nYour MTA is vulnerable to the 'mailto files' attack\r\n.\r\nQUIT\r\n");
 	send(socket:soc, data:crp);
	}
 close(soc);
 }
}
