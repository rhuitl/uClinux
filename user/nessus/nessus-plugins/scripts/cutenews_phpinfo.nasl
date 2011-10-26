#
# (C) Tenable Network Security
#

if(description)
{
 script_version ("$Revision: 1.5 $");
 script_id(11940);
 script_bugtraq_id(9130);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"2880");
 }
 
 name["english"] = "CuteNews Debug Info Disclosure";
 script_name(english:name["english"]);

 desc["english"] = "
Synopsis : 

The remote web server contains a PHP script that is prone to information
disclosure. 

Description : 

There is a bug in the remote version of CuteNews that allows an attacker
to obtain information from a call to the phpinfo() PHP function such as
the username of the user who installed php, if they are a SUDO user, the
IP address of the host, the web server version, the system version (unix
/ linux), and the root directory of the web server. 

See also : 

http://www.securityfocus.com/archive/1/346013

Solution: 

Disable CuteNews or upgrade to the newest version.

Risk factor: 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 summary["english"] = "Checks for the presence of cutenews";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 80);
 script_dependencies("cutenews_detect.nasl");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if(!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  req = http_get(item:string(dir, "/index.php?debug"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if( res == NULL ) exit(0);
  if("CuteNews Debug Information:" >< res)
  {
    security_note(port);
    exit(0);
  }
}

