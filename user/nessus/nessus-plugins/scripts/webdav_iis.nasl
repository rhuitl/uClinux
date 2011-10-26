#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(10526);
  script_bugtraq_id(1756);
 script_version ("$Revision: 1.11 $");
  script_cve_id("CVE-2000-0951");
  name["english"] = "IIS : Directory listing through WebDAV";

  script_name(english:name["english"]);
  desc["english"] = "
It is possible to retrieve the listing of the remote 
directories accessible via HTTP, rather than their index.html, 
using the Index Server service which provides WebDav capabilities
to this server.

This problem allows an attacker to gain more knowledge
about the remote host, and may make him aware of hidden
HTML files.

Solution : disable the Index Server service, or
see http://www.microsoft.com/technet/support/kb.asp?ID=272079
Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "Checks the presence of the Index Server service";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");

 family["english"] = "Web Servers";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

if(get_port_state(port))
{
  soc = http_open_socket(port);
  if(soc)
  {
  quote = raw_string(0x22);
  req = string("SEARCH / HTTP/1.1\r\n",
    	     "Host: ", get_host_name(), "\r\n",
	     "Content-Type: text/xml\r\n",
	     "Content-Length: 133\r\n\r\n",
	     "<?xml version=", quote, "1.0", quote, "?>\r\n",
	     "<g:searchrequest xmlns:g=", quote, "DAV:", quote, ">\r\n",
	     "<g:sql>\r\n",
	     "Select ", quote, "DAV:displayname", quote, " from scope()\r\n",
	     "</g:sql>\r\n",
	     "</g:searchrequest>\r\n");
  send(socket:soc, data:req);
  result = recv_line(socket:soc, length:2048);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if("HTTP/1.1 207 " >< result)
   {
    if(("DAV:" >< r) && ((".asp" >< r)||(".inc" >< r)))security_warning(port);
   }
  }
}
