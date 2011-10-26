#
#
# This script was written by Charles Thier <cthier@thethiers.net>
# This script was based off of Renaud Deraison's script 
# 11522 Linksys Router default password script.
# GPLv2
#


if(description)
{
    script_id(18413);
    script_version("$Revision: 1.3 $");
    script_cve_id("CVE-1999-0508");
    name["english"] = "Allied Telesyn Router/Switch Web interface found with default password";
    script_name(english:name["english"]);
 
   desc["english"] = "
The Allied Telesyn Router/Switch has the default password set.

The attacker could use this default password to gain remote access
to your switch or router.  This password could also be potentially used to
gain other sensitive information about your network from the device.

Solution : Connect to this Router/Switch and change the default password.

Risk factor : High";

   script_description(english:desc["english"]);
 
   summary["english"] = "Logs into Allied Telesyn routers and switches Web interface with default password";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2005 Charles Thier");
   script_family(english:"Misc.");
   script_dependencies("http_version.nasl");
   script_require_ports("Services/www", 80);

   exit(0);
}


#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner (port:port);
if (!banner || ("Server: ATR-HTTP-Server" >!< banner))
  exit(0);

res = http_get_cache(item:"/", port:port);
if ( res == NULL ) exit(0);
if ( egrep ( pattern:"^HTTP/.* 401 .*", string:res ) )
{
 req -= string("\r\n\r\n");
#  Credentials manager:friend
 req += string("\r\nAuthorization: Basic bWFuYWdlcjpmcmllbmQ=\r\n\r\n");
 res = http_keepalive_send_recv(port:port, data:req);
 if (res == NULL ) exit(0);
 if ( egrep ( pattern:"^HTTP/.* 200 .*", string:res) )
	security_hole(port);
}

