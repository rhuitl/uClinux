#
# This script was written by Rich Walchuck (rich.walchuck at gmail.com)
#
# See the Nessus Scripts License for details
#

#

if(description)
{
 script_id(16170);
 script_version ("$Revision: 1.2 $");
 script_name(english:"Movable Type config file");
 desc["english"]="
/mt/mt.cfg is installed by the Movable Type Publishing  
Platform and contains information that should not be exposed. 

Solution: Configure your web server not to serve .cfg files. 
Risk factor : Low";

 script_description(english:desc["english"]);
 script_summary(english:"Checks for the presence of /mt/mt.cfg");
 
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

if(is_cgi_installed_ka(item:"/mt/mt.cfg",port:port))
   security_warning(port);

