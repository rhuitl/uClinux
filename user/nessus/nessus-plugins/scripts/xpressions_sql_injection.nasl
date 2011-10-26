#
# (C) Tenable Network Security
#
# Ref: 
#  From: "Paul Craig" <pimp@brainwave.net.nz>
#  To: <bugtraq@securityfocus.com>
#  Subject: Xpressions Software:          Multiple SQL Injection Attacks To Manage WebStore
#  Date: Thu, 5 Jun 2003 01:02:17 +1200

if(description)
{
 script_id(11698);
 script_bugtraq_id(7804);

 script_version("$Revision: 1.8 $");
 name["english"] = "SQL injection in XPression Software";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running on of XPression Software's 
product (trueCoonect, FlowerLink, eVision or WebSite integration).

There is a flaw in the remote software which may allow anyone
to inject arbitrary SQL commands, which may in turn be used to
gain administrative access on the remote host.

Solution : Upgrade to the latest version of this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
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
  variables = string("c=1&ref=&Uname=nessus&Upass='&submit1=Submit");
  req = string("POST ", req, " HTTP/1.1\r\n", 
  	      "Host: ", host, ":", port, "\r\n", 
	      "Content-Type: application/x-www-form-urlencoded\r\n", 
	      "Content-Length: ", strlen(variables), "\r\n\r\n", variables);

  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);

  if("Microsoft OLE DB Provider for SQL Server" >< buf && "error '" >< buf)
  	{
	security_hole(port);
	exit(0);
	}
 
 
 return(0);
}

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);



foreach dir ( cgi_dirs() )
{
  if ( is_cgi_installed_ka(item:dir + "/manage/login.asp", port:port) ) check(req:dir + "/manage/login.asp");
}
