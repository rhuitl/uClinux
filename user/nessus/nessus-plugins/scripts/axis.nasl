#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10023);
 script_bugtraq_id(1025);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0191");

 name["english"] = "Bypass Axis Storpoint CD authentication";
 name["francais"] = "outrepasse l'authentication d'Axis Storpoint CD";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to access the remote host AxisStorpoint
configuration by requesting :

	http://server/cd/../config/html/cnf_gi.htm
	
Solution : upgrade to the latest version available at
	   http://www.se.axis.com/techsup/cdsrv/storpoint_cd/index.html
Risk factor : High";


 desc["francais"] = "
Il est possible d'accéder au fichier de configuration du
serveur Axis StorPoint distant en faisant la requete :

	http://server/cd/../config/html/cnf_gi.htm

Solution : Mettez-le à jour en installant la version disponible à
	http://www.se.axis.com/techsup/cdsrv/storpoint_cd/index.html
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Requests /cd/../config/html/cnf_gi.htm";
 summary["francais"] = "Demande /cd/../config/html/cnf_gi.htm";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


cgi_should_fail = "/config/html/cnf_gi.htm";
cgi_should_succeed = "/cd/../config/html/cnf_gi.htm";

port = get_http_port(default:80);

if ( ! get_port_state(port) ) exit(0);

res = is_cgi_installed_ka(port:port, item:cgi_should_fail);
if ( ! res )
{
 res = is_cgi_installed_ka(port:port, item:cgi_should_succeed);
 if ( res ) security_hole(port);
}
