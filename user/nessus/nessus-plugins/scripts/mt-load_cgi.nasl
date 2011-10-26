#
# This script was written by Rich Walchuck (rich.walchuck at gmail.com)
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(16169);
 script_version ("$Revision: 1.2 $");
 script_name(english:"Movable Type initialization script found");
 desc["english"]="
mt-load.cgi is installed by the Movable Type Publishing  
Platform. 

Failure to remove mt-load.cgi could enable someone else to create
a weblog in your Movable Type installation, and possibly gain access to 
your data.

Solution: Remove the mt-load.cgi script after installation. 
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Checks for the existence of /mt/mt-load.cgi");
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004 Rich Walchuck");
 script_family(english:"CGI abuses");
 script_require_ports("Services/www",80);
 script_dependencies("http_version.nasl");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);

if(is_cgi_installed_ka(item:"/mt/mt-load.cgi",port:port))
       security_hole(port);

