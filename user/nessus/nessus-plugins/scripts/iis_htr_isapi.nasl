#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Based on Matt Moore's iis_htr_isapi.nasl
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# TODO: internationalisation ?
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10932);
 script_bugtraq_id(4474);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2002-0071");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-A-0002");
 name["english"] = "IIS .HTR ISAPI filter applied";
 script_name(english:name["english"]);
 
 desc["english"] = "
The IIS server appears to have the .HTR ISAPI filter mapped.

At least one remote vulnerability has been discovered for the .HTR
filter. This is detailed in Microsoft Advisory
MS02-018, and gives remote SYSTEM level access to the web server. 

It is recommended that, even if you have patched this vulnerability, 
you unmap the .HTR extension and any other unused ISAPI extensions
if they are not required for the operation of your site.

Solution : 
To unmap the .HTR extension:
 1.Open Internet Services Manager. 
 2.Right-click the Web server choose Properties from the context menu. 
 3.Master Properties 
 4.Select WWW Service -> Edit -> HomeDirectory -> Configuration 
and remove the reference to .htr from the list.

In addition, you may wish to download and install URLSCAN from the
Microsoft Technet Website.  URLSCAN, by default, blocks all requests
for .htr files.

Risk factor : High"; # until a better check is written :(

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for IIS .htr ISAPI filter";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check makes a request for NULL.htr

include("http_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( "Microsoft-IIS" >!< banner ) exit(0);

if(get_port_state(port) && ! get_kb_item("Services/www/" + port + "/embedded") )
{ 
 req = string("GET /NULL.htr HTTP/1.1\r\n",
		"Host: ", get_host_name(), "\r\n\r\n");

 soc = http_open_socket(port);
 if(soc)
 {
 i = 0;
 send(socket:soc, data:req);
 r = http_recv_headers2(socket:soc);
 body = http_recv_body(socket:soc, headers:r);
 http_close_socket(soc);
 lookfor = "<html>Error: The requested file could not be found. </html>";
 if(lookfor >< body)security_hole(port);
 }
}
