#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# www.westpoint.ltd.uk
#
#
# Modified by rd to have a language independant pattern matching, thanks
# to the remarks from Nicolas Gregoire <ngregoire@exaprobe.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10695);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-a-0008");
 script_bugtraq_id(2880);
 script_cve_id("CVE-2001-0500");
 script_version ("$Revision: 1.26 $");
 name["english"] = "IIS .IDA ISAPI filter applied";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Indexing Service filter is enabled on the remote Web server.

Description :

The IIS server appears to have the .IDA ISAPI filter mapped.

At least one remote vulnerability has been discovered for the .IDA
(indexing service) filter. This is detailed in Microsoft Advisory
MS01-033, and gives remote SYSTEM level access to the web server. 

It is recommended that even if you have patched this vulnerability that
you unmap the .IDA extension, and any other unused ISAPI extensions
if they are not required for the operation of your site.

Solution :

To unmap the .IDA extension:
 1.Open Internet Services Manager. 
 2.Right-click the Web server choose Properties from the context menu. 
 3.Master Properties 
 4.Select WWW Service -> Edit -> HomeDirectory -> Configuration 
and remove the reference to .ida from the list.

In addition, you may wish to download and install URLSCAN from the
Microsoft Technet web site.  URLSCAN, by default, blocks all .ida
requests to the IIS server.

Risk factor :

None / CVSS Base Score : 0 
(AV:R/AC:L/Au:NR/C:N/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for IIS .ida ISAPI filter";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Matt Moore");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check makes a request for NULL.ida
include("http_func.inc");

port = get_http_port(default:80);

if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);
sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);
if(get_port_state(port))
{ 
 req = http_get(item:"/NULL.ida", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 look = strstr(r, "<HTML>");
 look = look - string("\r\n");
 if(egrep(pattern:"^.*HTML.*IDQ.*NULL\.ida.*$", string:look)) security_note(port);
 }
}
