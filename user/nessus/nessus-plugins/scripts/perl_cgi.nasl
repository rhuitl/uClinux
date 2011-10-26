#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10173);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-0509");
 name["english"] = "perl interpreter can be launched as a CGI";
 name["francais"] = "l'interpreteur perl peut etre lancé comme un CGI";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'Perl' CGI is installed and can be launched
as a CGI. This is equivalent to giving a free shell to an attacker, with the
http server privileges (usually root or nobody).

Solution : remove it from /cgi-bin

Risk factor : High";


 desc["francais"] = "Le cgi 'perl' est installé et peut etre
lancé comme un CGI. C'est comme donner un shell à n'importe
qui, avec les droits de root ou de nobody.

Solution : retirez-le de /cgi-bin

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "checks for the presence of /cgi-bin/perl";
 summary["francais"] = "vérifie la présence de /cgi-bin/perl";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
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


port = get_http_port(default:80);
if (port && (is_cgi_installed_ka(item:"perl?-v", port:port) || 
             is_cgi_installed_ka(item:"perl.exe?-v", port:port)))
  security_hole(port);
