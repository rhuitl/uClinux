#
# (C) Tenable Network Security
#


if(description)
{
 script_id(14817);
 script_cve_id("CVE-2004-1552", "CVE-2004-1553");
 script_bugtraq_id(11246);
 script_version("$Revision: 1.5 $");
 name["english"] = "aspWebAlbum SQL Injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running aspWebAlbum, an ASP script
designed to faciliate the integration of multiple photo albums in a
web-based application.

There is a flaw in the remote software which may allow anyone
to inject arbitrary SQL commands, which may in turn be used to
gain administrative access on the remote host.

Solution : Upgrade to the latest version of this software
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


function check(req)
{
  host = get_host_name();
  variables = "txtUserName=%27&txtPassword=&LoginButton=Login";
  req = string("POST ", req, " HTTP/1.1\r\n", 
  	      "Host: ", host, ":", port, "\r\n", 
	      "Content-Type: application/x-www-form-urlencoded\r\n", 
	      "Content-Length: ", strlen(variables), "\r\n\r\n", variables);

  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);

  if("error '80040e14'" >< buf &&
     "'Gal_UserUserName = ''''" >< buf )
  	{
	security_hole(port);
	exit(0);
	}
 
 
 return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_asp(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  if ( is_cgi_installed_ka(item:dir + "/album.asp", port:port) ) check(req:dir + "/album.asp?action=processlogin");
 }
