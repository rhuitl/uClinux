#
# This script was written by Forrest Rae <forrest.rae@digitaldefense.net>
# 


if(description)
{
	script_id(11208);
	script_version("$Revision: 1.8 $");
	name["english"] = "Netscape Enterprise Default Administrative Password";
	script_cve_id("CVE-1999-0502");
	script_name(english:name["english"]);
	desc["english"] = "
This host is running the Netscape Enterprise Server.  The Administrative 
interface for this web server, which operates on port 8888/TCP, is using
the default username and password of 'admin'.  An attacker can use this to 
reconfigure the web server, cause a denial of service condition, or
gain access to this host.

Solution: Please assign the web administration console a difficult to guess 
password.

Risk factor : High";
	script_description(english:desc["english"]);
	summary["english"] = "Netscape Enterprise Default Administrative Password";
	script_summary(english:summary["english"]);
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2003 Digital Defense Inc.");
	family["english"] = "General";
	script_family(english:family["english"]);
	script_require_ports("Services/www", 8888);
	script_dependencies("find_service.nes");
	exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("misc_func.inc");

debug = 0;

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8888);

foreach port (ports)
{
	if ( !get_port_state(port) ) continue;
	banner = get_http_banner(port:port);
	if ( ! banner || ("Netscape" >!< banner && "iPlanet" >!< banner ) ) continue;
	soc = http_open_socket(port);
	
	if (soc)
	{
		
		# HTTP auth = "admin:admin"
		
		
		req = http_get(item:"/https-admserv/bin/index", port:port);
    		req = req - string("\r\n\r\n");
    		req = string(req, "\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n");
    
		
		send(socket:soc, data:req);
		buf = http_recv(socket:soc);
		
		if(debug == 1) display("\n\n", buf, "\n\n");
		
		http_close_socket(soc);
		
		if (("Web Server Administration Server" >< buf) && ("index?tabs" >< buf))
		{
			security_hole(port:port);
		}
	}
}
