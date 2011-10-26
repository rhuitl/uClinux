#
# (C) Tenable Network Security
#

if(description)
{
  script_id(16175);
  script_bugtraq_id(12194);
  script_version("$Revision: 1.2 $");
  
  script_name(english:"Novell GroupWise WebAccess Information Disclosure");

 desc["english"] = "
The remote host is running Novell GroupWise WebAccess, a commercial
commercial groupware package.

The remote version of this software is vulnerable to an information
disclosure vulnerability. An attacker may request the file
/com/novell/webaccess/WebAccessUninstall.ini and will obtain some information
about the remote host paths and setup.

Solution: Delete /com/novell/webaccess/WebAccessUninstall.ini
Risk factor : Low";

  script_description(english:desc["english"]);
  script_summary(english:"Checks GroupWare XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);


buf = http_get(item:"/com/novell/webaccess/WebAccessUninstall.ini", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

if("NovellRoot=" >< r )
{
  security_warning(port);
  exit(0);
}
