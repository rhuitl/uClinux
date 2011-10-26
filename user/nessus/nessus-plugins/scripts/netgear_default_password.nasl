#
# (C) Tenable Network Security
#

if(description)
{
	script_id(11737);
	script_version("$Revision: 1.2 $");
	name["english"] = "NetGear Router Default Password";
	script_name(english:name["english"]);
	desc["english"] = "
This NetGear Router/Access Point has the default password 
set for the web administration console. 
('admin'/'password').

This console provides read/write access to the
router's configuration. An attacker could take
advantage of this to reconfigure the router and 
possibly re-route traffic.

Solution: Please assign the web administration 
          console a difficult to guess password.

Risk factor : High";
	script_description(english:desc["english"]);
	summary["english"] = "NetGear Router Default Password";
	script_summary(english:summary["english"]);
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
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


if(get_port_state(port))
{
	soc = open_sock_tcp(port);
	if (soc)
	{
	
		req = string("GET /top.html HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\nReferer: http://192.168.0.1/\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n");
		send(socket:soc, data:req);
		buf = http_recv(socket:soc);
		close(soc);
		if("<title>NETGEAR</title>" >< buf && "img/hm_icon.gif" >< buf && "Server: Embedded HTTPD v1.00" >< buf)
		{
			security_hole(port:port);
		}
	}
}
