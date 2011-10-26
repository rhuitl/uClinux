#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10087);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-1999-0201");
 name["english"] = "FTP real path";
 name["francais"] = "Vrai chemin d'accès au répertoire FTP";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It is possible to gather the
real path of the public area of the ftp server
(like /home/ftp) by issuing the following
command :

	CWD
	
This problem may help an attacker to find where
to put a .rhost file using other security
flaws.

Risk factor : Low";
 

 desc["francais"] = "Il est possible d'obtenir
le vrai chemin d'accès du répertoire ftp
public (comme /home/ftp), en entrant
la commande :

	CWD
	
Ce problème peut aider un pirate à trouver
ou mettre un fichier .rhost en utilisant
d'autres problèmes de sécurité.

Facteur de risque : Faible";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Get the real path of the remote ftp home";
 summary["francais"] = "Obtient le vrai chemin d'accès au repertoire ftp distant";
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
  data = string("CWD\r\n");
  send(socket:soc, data:data);
  a = recv_line(socket:soc, length:1024);
  if("550 /" >< a){
  report = "It is possible to gather the
real path of the public area of the ftp server
(like /home/ftp) by issuing the following
command :
	CWD
	
We determined that the root of the remote FTP server is located
under '" + (ereg_replace(pattern:"^550 (/.*):.*", string:a, replace:"\1")) + "'.
	
This problem may help an attacker to find where
to put a .rhost file using other security
flaws.

Risk factor : Low";
  security_warning(port:port, data:report);
  }
  data = string("QUIT\r\n");
  send(socket:soc, data:data);
 }
close(soc);
}
