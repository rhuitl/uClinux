#
# This script is Copyright (C) 2002 Digital Defense Inc.
# Author: Forrest Rae <forrest.rae@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
	script_id(10999);
	script_version("$Revision: 1.6 $");
	script_cve_id("CVE-1999-0508");
	name["english"] = "Linksys Router Default Password";
	script_name(english:name["english"]);
	desc["english"] = "
This Linksys Router has the default password 
set for the web administration console. 
This console provides read/write access to the
router's configuration. An attacker could take
advantage of this to reconfigure the router and 
possibly re-route traffic.

Solution: Please assign the web administration 
          console a difficult to guess password.

Risk factor : High";
	script_description(english:desc["english"]);
	summary["english"] = "Linksys Router Default Password";
	script_summary(english:summary["english"]);
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2002 Digital Defense Inc.");
	family["english"] = "General";
	script_family(english:family["english"]);
	script_dependencie("find_service.nes");
	script_require_ports("Services/www", 80);
	exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);

if (!get_port_state(port))port = 8080;

if(get_port_state(port))
{
	soc = open_sock_tcp(port);
	if (soc)
	{
	
		# HTTP auth = ":admin"
		# req = string("GET / HTTP/1.0\r\nAuthorization: Basic OmFkbWlu\r\n\r\n");
		
		# HTTP auth = "admin:admin"
		req = string("GET / HTTP/1.0\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n");
		
		# Both work, second is used to be RFC compliant.
		
		send(socket:soc, data:req);
		buf = http_recv(socket:soc);
		close(soc);
		if (("Status.htm" >< buf) && ("DHCP.htm" >< buf) && ("Log.htm" >< buf) && ("Security.htm" >< buf))
		{
			security_hole(port:port);
		}
	}
}
