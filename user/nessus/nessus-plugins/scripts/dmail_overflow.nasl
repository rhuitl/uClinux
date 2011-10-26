#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10438);
 script_bugtraq_id(1297);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2000-0490");
 name["english"] = "Netwin's DMail ETRN overflow";
 name["francais"] = "Dépassement de buffer ETRN dans DMail de Netwin";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote SMTP server is vulnerable to a buffer
overflow when the ETRN command is issued arguments 
which are too long.

This problem may allow an attacker to shut this server
down or to execute arbitrary code on this host.

Solution : Contact your vendor for a fix. If you are using
Netwin's DMail, then upgrade to version 2.7r or newer.

Risk factor : High";


 desc["francais"] = "
Le serveur SMTP distant est vulnérable à un dépassement
de buffer lorsqu'un argument trop long est passé à la commande
ETRN.

Ce problème peut permettre à un pirate de couper ce serveur
ou bien meme d'executer du code arbitraire sur ce système.

Solution : Contactez votre vendeur pour un patch. Si vous utilisez
DMail de Netwin, alors mettez-le à jour en version 2.7r

Facteur de risque : Elevé";


 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Checks if the remote mail server is vulnerable to a ETRN overflow"; 
 summary["francais"] = "Vérifie si le serveur de mail est vulnérable a un overflow ETRN";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
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

if(safe_checks())
{
 banner = get_smtp_banner(port:port);
 
 if(banner)
 {
  if("2.7r" >< banner)exit(0);
  
  if(egrep(string:banner,
  	  pattern:"^220.*DSMTP ESMTP Server v2\.([0-7]q*|8[a-h]).*"))
	  {
	   alrt = "
The remote DMAIL SMTP server may be vulnerable to a buffer
overflow when the ETRN command is issued an argument that
is too long. 

This problem may allow an attacker to shut this server
down or to execute arbitrary code on this host.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : Contact your vendor for a fix. If you are using
Netwin's DMail, then upgrade to version 2.7r or newer.

Risk factor : High";
	 security_hole(port:port, data:alrt);
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
 crp = string("HELO example.com\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 crp = string("ETRN ", crap(500), "\r\n");
 send(socket:soc, data:crp);
 send(socket:soc, data:string("QUIT\r\n"));
 close(soc);

 soc2 = open_sock_tcp(port);
 if(!soc2)security_hole(port);
 else close(soc2);
 }
}
