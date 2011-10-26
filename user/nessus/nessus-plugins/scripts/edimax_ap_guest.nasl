#
# (C) Tenable Network Security
#
# Date: 10 Jun 2004 14:26:29 -0000
# From: <msl@velmans-industries.nl>
# To: bugtraq@securityfocus.com
# Subject: Edimax 7205APL
#

if(description)
{
 script_id(12269);
 script_bugtraq_id(10512);
 script_version("$Revision: 1.1 $");
 name["english"] = "EdiMax AP Hidden Password Check";
 script_name(english:name["english"]);
 desc["english"] = "
The remote EdiMax Access Point ships with a default account 
('guest'/'1234') which has backup privileges on the remote configuration
file.

If the guest user does a backup of the remote config file, he will be able
to obtain the password for the administrator account, since it's saved in
cleartext in the config.

Solution: Contact vendor for a fix.  As a temporary workaround,
disable the webserver or filter the traffic to this access point
webserver via an upstream firewall.

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Edimax Hidden Password Check";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


# start check


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0); 

init = string("GET / HTTP/1.1\r\nHost: ", get_host_name(), "\r\n\r\n");

reply = http_keepalive_send_recv(data:init, port:port);
if (reply == NULL) exit(0);

if ( egrep(pattern:"^HTTP/. 40[13] .*", string:reply ) )
{
   req = string("GET / HTTP/1.1\r\nHost: ", get_host_name(), 
		     "\r\nAuthorization: Basic Z3Vlc3Q6MTIzNA==\r\n\r\n");
   reply = http_keepalive_send_recv(data:req, port:port);
   if ( egrep(string:reply, pattern:"^HTTP/.* 200 ") )
	{
		security_hole(port);
		exit(0);
	}
}
