#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10319);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-1999-0880");
 
 name["english"] = "wu-ftpd SITE NEWER vulnerability";
 name["francais"] = "Vulnérabilité SITE NEWER de wu-ftpd";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
	     
 desc["english"] = "
The remote FTP server accepts the command 'SITE NEWER'.

Some wu-ftpd servers (and probably others) are vulnerable 
to a resource exhaustion where an attacker may invoke 
this command to use all the memory available on the server.

Solution : Make sure that you are running the latest
version of your FTP server. If you are a wu-ftpd
user, then make sure that you are using at least
version 2.6.0.

*** This warning may be irrelevant.

Risk factor : Medium";
		 
		 
desc["francais"] = "
Le serveur FTP distant accepte la commande 'SITE NEWER'.

Certains serveurs wu-ftpd (et sans doute d'autres serveurs
FTP) sont vulnérables à une attaque par consommation
de ressource, au cours de laquelle un pirate utilise cette
commande pour consommer toute la mémoire disponible sur
le serveur FTP distant.

*** Cette mise en garde peut n'avoir aucun interet
	     
Solution : assurez-vous que vous faites tourner la dernière
version de votre serveur FTP. Si vous utilisez wu-ftpd,
alors utilisez au moins la version 2.6.0";
	 	     
 script_description(english:desc["english"],
 		    francais:desc["francais"]);
		    
 
 script_summary(english:"Checks if the remote FTP server accepts the SITE NEWER command",
 		francais:"Détermine si le serveur ftp distant accepte la commande SITE NEWER");
 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
		  
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login", "ftp/wuftpd");
 script_require_ports("Services/ftp", 21);
  
 exit(0);
}

#
# The script code starts here : 
#
include("ftp_func.inc");

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");


port = get_kb_item("Services/ftp");
if(!port)port = 21;
if (! get_port_state(port)) exit(0);

banner = get_ftp_banner(port: port);

if((!login) || safe_checks())
{
 if(egrep(pattern:".*wu-((1\..*)|(2\.[0-5])).*",
 	 string:banner))security_warning(port);
  exit(0);
}




# Connect to the FTP server
soc = open_sock_tcp(port);
if(soc)
{
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
 
  # We are in
 
  port2 = ftp_pasv(socket:soc);
  soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
  if(soc2)
  {
   c = string("SITE NEWER 19900101000000 \r\n");
   send(socket:soc, data:c);
   b = recv(socket:soc, length:3);
   if(b == "150")security_warning(port);
   close(soc2);
  }
  ftp_close(socket: soc);
 }
}
