#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10013);
 script_bugtraq_id(770);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-0885");
 name["english"] = "alibaba.pl";
 name["francais"] = "alibaba.pl";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'alibaba.pl' CGI script is installed on 
 this machine. This CGI script has a well known security flaw that 
 would allow an attacker to execute arbitrary commands on the 
 remote server.

Solution : Remove the 'alibaba.pl' script from your web server's 
CGI directory (typically cgi-bin/).

Risk factor : High";


 desc["francais"] = "Le cgi 'alibaba.pl' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui d'executer
des commandes arbitraires sur le serveur.

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/alibaba.pl";
 summary["francais"] = "Vérifie la présence de /cgi-bin/alibaba.pl";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
foreach dir (cgi_dirs())
{
 if(is_cgi_installed_ka(item:string(dir, "/alibaba.pl"), port:port)) 
 {
 item = string(dir, "/alibaba.pl|dir");
 req = http_get(item:item, port:port);
 b = http_keepalive_send_recv(port:port, data:req);
 if( b == NULL ) exit(0);
 if("alibaba.pl" >< b && "<DIR>" >< b) {
 	security_hole(port);
	exit(0);
	}
 }
}
