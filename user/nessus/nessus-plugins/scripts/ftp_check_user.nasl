#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10082);
 script_version ("$Revision: 1.13 $");
 name["english"] = "FTPd tells if a user exists";
 name["francais"] = "FTPd indique si un utilisateur existe";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to determine the existence of a user on the remote 
system by issuing the command CWD ~<username>, like :

	CWD ~root
	
An attacker may use this to determine the existence of known to be 
vulnerable accounts (like guest) or to determine which system you 
are running.

Solution : inform your vendor, and ask for a patch, or change your FTP server
Risk factor : Low";
 

 desc["francais"] = "

Il est possible de déterminer l'existence de certains
comptes sur la machine distante en faisant la commande 
CWD ~<nom d'utilisateur>, comme :

	CWD ~root
	
Un pirate peut utiliser ce problème pour découvrir la présence
de certains comptes vulnérables (tels que guest) ou pour
déterminer le type de système que vous faites tourner.

Solution : informez le vendeur de votre serveur FTP de cette
	    vulnérabilité et demandez une correction, ou changez
	    de serveur FTP
	    
Facteur de risque : Faible.";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "CWD ~root";
 summary["francais"] = "CWD ~root";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_keys("ftp/anonymous");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include('ftp_func.inc');
port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);


anon = get_kb_item("ftp/anonymous");
if(anon)
{
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);
 if(ftp_authenticate(socket:soc, user:"anonymous",pass:"nessus@"))
 {
  data = string("CWD ~root\r\n");
  send(socket:soc, data:data);
  a = recv_line(socket:soc, length:1024);
  if(a)
  {
  if("550 /" >< a)security_warning(port);
  }
  data = string("QUIT\r\n");
  send(socket:soc, data:data);
 }
close(soc);
}
