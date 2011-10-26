#
# (C) Tenable Network Security
#

if(description)
{
	script_id(12203);
	script_cve_id("CVE-2004-1920");
	script_bugtraq_id(10095);
	script_version("$Revision: 1.7 $");
	name["english"] = "X-Micro Router Default Password";
	script_name(english:name["english"]);
	desc["english"] = "
The remote host (probably a X-Micro Wireless Broadband router)
has its default username and password set (super/super) for the
management console.

This console provides read/write access to the router's configuration. 
An attacker could take advantage of this to reconfigure the router and 
possibly re-route traffic.

Solution: Please assign the web administration 
          console a difficult to guess password.

Risk factor : High";
	script_description(english:desc["english"]);
	summary["english"] = "X-Micro Router Default Password";
	script_summary(english:summary["english"]);
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
	family["english"] = "General";
	script_family(english:family["english"]);
	script_dependencie("http_version.nasl");
	script_require_ports("Services/www", 80);
	exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
		req = string("GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\n",
			     "Host: ", get_host_name(), "\r\nAuthorization: Basic LXIgbmVzc3VzOm4zc3N1cwo=\r\n\r\n");
		res = http_keepalive_send_recv(port:port, data:req);
		if ( ! res ) exit(0);

		if ( egrep(pattern:"^HTTP.* 403 .*", string:res) )
		{
		req = string("GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\n",
			     "Host: ", get_host_name(), "\r\nAuthorization: Basic c3VwZXI6c3VwZXI=\r\n\r\n");
		res = http_keepalive_send_recv(port:port, data:req);
		if ( res == NULL ) exit(0);
		if ( egrep(pattern:"^HTTP.* 200 .*", string:res) ) security_hole(port);
		}
}
