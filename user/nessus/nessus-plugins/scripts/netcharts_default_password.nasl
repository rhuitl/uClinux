#
# This script is Copyright (C) 2003 Renaud Deraison
#
# See the Nessus Scripts License for details
#

if(description)
{
	script_id(11600);
	script_version("$Revision: 1.3 $");
	name["english"] = "NetCharts Server Default Password";
	script_name(english:name["english"]);
	desc["english"] = "
The remote host is running the NetCharts server on this port,
with the default login and password of 'Admin/Admin'.

An attacker may use this misconfiguration to administrate
the remote server.

Solution : Change the password of the 'Admin' account to a 
           stronger one
	   
Risk factor : High";
	script_description(english:desc["english"]);
	summary["english"] = "NetCharts Server Default Password";
	script_summary(english:summary["english"]);
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
	family["english"] = "General";
	script_family(english:family["english"]);
	script_dependencie("http_version.nasl");
	script_require_ports("Services/www", 8001);
	exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:8001);
if ( ! port ) exit(0);

# HTTP auth = "Admin:Admin"
req = string("GET /Admin/index.jsp HTTP/1.1\r\nHost: ", get_host_name(), "\r\n", "Authorization: Basic QWRtaW46QWRtaW4=\r\n\r\n");
res = http_keepalive_send_recv(port:port, data:req);
if(res != NULL && egrep(pattern:"HTTP.* 200 .*", string:res) && "NetCharts Server" >< res) security_hole(port);
