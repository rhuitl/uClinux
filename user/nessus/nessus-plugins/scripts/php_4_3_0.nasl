#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11237);
 script_bugtraq_id(6875);

 script_version("$Revision: 1.6 $");
 name["english"] = "php 4.3.0";
 script_cve_id("CVE-2003-0097");

 script_name(english:name["english"]);
 desc["english"] = "
The remote host is running PHP 4.3.0

There is a flaw in this version which may allow
an attacker to execute arbitrary PHP code on this
host.

Solution : Upgrade to PHP 4.3.1
Risk factor : High";




 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of PHP";
 summary["francais"] = "Vérifie la version de PHP";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
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
include("backport.inc");

port = get_http_port(default:80);
if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner)exit(0);
 php = get_php_version(banner:banner);
 if ( ! php ) exit(0);
 if(ereg(pattern:"PHP/4\.3\.0[^0-9]*", string:php))
   security_hole(port);
}
