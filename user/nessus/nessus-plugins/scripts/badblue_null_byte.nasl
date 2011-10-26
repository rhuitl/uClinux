#
# This script was written by Michel Arboi <arboi@alussinan.org>
# GPL
# *untested*
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#

if(description)
{
 script_id(11064);
 script_bugtraq_id(5226);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2002-1021");
 name["english"] = "BadBlue invalid null byte vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "It was possible to read the content of /EXT.INI
(BadBlue configuration file) by sending an invalid GET request.

A cracker may exploit this vulnerability to steal the passwords.


Solution : upgrade your software or protect it with a filtering reverse proxy
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Read BadBlue protected configuration file";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nes", "no404.nasl", "http_version.nasl");
 exit(0);
}

########

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
if ( ! port ) exit(0);
banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ("BadBlue" >!< banner ) exit(0);


r = string("/ext.ini.%00.txt");
res = is_cgi_installed_ka(item:r, port:port);
if( res ) security_hole(port);
