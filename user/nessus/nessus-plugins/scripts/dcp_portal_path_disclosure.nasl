#
# written by Renaud Deraison
#
#
# Ahmet Sabri ALPER <s_alper@hotmail.com>
# To:  BugTraq
# Subject:  [ARL02-A02] DCP-Portal Root Path Disclosure Vulnerability



if (description)
{
 script_id(11477);
 script_bugtraq_id(4113);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2002-0282");
 
 script_name(english:"DCP-Portal Path Disclosure");
 desc["english"] = "
DCP-Portal discloses its physical path when an empty request
to add_user.php is made

Solution : Upgrade to a newer version.
Risk factor : Low";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if DCP-Portal displays its physical path");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

if ( ! can_host_php(port:port) ) exit(0);

		


foreach d (cgi_dirs())
{
 url = string(d, "/add_user.php");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 
 if(egrep(pattern:".*Warning:.*output started at /.*", string:buf))
   {
    security_warning(port);
    exit(0);
   }
}

