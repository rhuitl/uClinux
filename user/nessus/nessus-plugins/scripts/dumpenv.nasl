#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10060);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-1178");
 name["english"] = "Dumpenv";
 name["francais"] = "Dumpenv";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The cgi 'dumpenv.pl'  is installed. This
CGI gives away too much information about the web server
configuration, which will help an attacker.

Solution : remove it from /cgi-bin.

Risk factor : Low";


 desc["francais"] = "Le cgi 'dumpenv' est installé. Celui-ci
donne beaucoup trop d'informations sur la configuration
du serveur web à un pirate, ce qui n'est pas une
bonne chose.

Solution : retirez-le de /cgi-bin.

Facteur de risque : Faible";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/dumpenv";
 summary["francais"] = "Vérifie la présence de /cgi-bin/dumpenv";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
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

port = get_http_port(default:80);

cgi = "dumpenv.pl";
res = is_cgi_installed_ka(item:cgi, port:port);
if( res )security_warning(port);
