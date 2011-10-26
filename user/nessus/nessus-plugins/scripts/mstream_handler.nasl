#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10391);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2000-0138");
 
 name["english"] = "mstream handler Detect";
 name["francais"] = "Detection d'un handler mstream";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host appears to be running
a mstream handler, which is a trojan that can be 
used to control your system or make it 
attack another network (this is 
actually called a distributed denial
of service attack tool)

It is very likely that this host
has been compromised

Solution : Restore your system from backups,
	   contact CERT and your local
	   authorities

Risk factor : Critical";



 desc["francais"] = "
Le systeme distant semble faire tourner
un handler mstream, qui peut etre utilisé pour prendre 
le controle de celui-ci ou pour attaquer un 
autre réseau (outil de déni de service 
distribué)

Il est très probable que ce systeme a été
compromis

Solution : reinstallez votre système à partir
	   des sauvegardes, et contactez le CERT
	   et les autorités locales
	   
Facteur de risque : Critique";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Detects the presence of a mstream agent";
 summary["francais"] = "Detecte la présence d'un agent mstream";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);

 script_require_ports(6723, 15104, 12754); 
 script_dependencies("find_service.nes");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

include("misc_func.inc");
include('global_settings.inc');
if ( islocalhost() ) exit(0);
if (!  thorough_tests ) exit(0);


function check(port, pass)
{
 if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  send(socket:soc, data:string(pass, "\r\n"));
  r = recv(socket:soc, length:2, timeout:2);
  close(soc);
  if(r == "> ")
	{
  	security_hole(port);
  	return(1);
	}
  }
 }
  return(0);
}

port = get_unknown_svc();
if(port)
{
 if(check(port:port, pass:"sex"))exit(0);
 if(check(port:port, pass:"N7%diApf!"))exit(0);
}
else
{
 if(check(port:6723, pass:"sex"))exit(0);
 if(check(port:15104, pass:"N7%diApf!"))exit(0);
 if(check(port:12754, pass:"N7%diApf!"))exit(0);
}
