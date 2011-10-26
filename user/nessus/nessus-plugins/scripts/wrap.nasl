#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10317);
 script_bugtraq_id(373);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-0149");
 
 name["english"] = "wrap";
 name["francais"] = "wrap";
 name["deutsch"] = "wrap";
 script_name(english:name["english"], francais:name["francais"], deutsch:name["deutsch"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a CGI script that is prone to
information disclosure. 

Description :

The 'wrap' CGI is installed.  This CGI allows anyone to get a listing
for any directory with mode +755. 

*** Note that all implementations of 'wrap' are not vulnerable.

See also : 

http://seclists.org/lists/bugtraq/1997/Apr/0076.html
   
Solution : 

Remove this CGI script.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/wrap";
 summary["francais"] = "Vérifie la présence de /cgi-bin/wrap";
 summary["deutsch"] = "Überprüft auf Existenz von /cgi-bin/wrap"; 

 script_summary(english:summary["english"], francais:summary["francais"], deutsch:summary["deutsch"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison",
                deutsch:"Dieses Skript ist urheberrechtlich geschützt (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 family["deutsch"] = "CGI Mißbrauch";
 script_family(english:family["english"], francais:family["francais"], deutsch:family["deutsch"]);
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
res = is_cgi_installed_ka(port:port, item:"wrap");
if(res)security_warning(port);

