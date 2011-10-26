#
# This script was written by Matt Moore <matt@westpoint.ltd.uk>
# Majority of code from plugin fragment and advisory by H D Moore <hdm@digitaloffense.net>
#
# no relation :-)
#


if(description)
{
 script_id(10956);
 script_cve_id("CVE-1999-0739");
 script_version("$Revision: 1.8 $");
 name["english"] = "Codebrws.asp Source Disclosure Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Microsoft's IIS 5.0 web server is shipped with a set of
sample files to demonstrate different features of the ASP
language. One of these sample files allows a remote user to
view the source of any file in the web root with the extension
.asp, .inc, .htm, or .html.

Solution: 

Remove the /IISSamples virtual directory using the Internet Services Manager. 
If for some reason this is not possible, removing the following ASP script will
fix the problem: 
        
This path assumes that you installed IIS in c:\inetpub
        
c:\inetpub\iissamples\sdk\asp\docs\CodeBrws.asp


Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for presence of Codebrws.asp";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore / HD Moore");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check simpy tests for presence of Codebrws.asp. Could be improved
# to use the output of webmirror.nasl, and actually exploit the vulnerability.

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


req = http_get(item:"/iissamples/sdk/asp/docs/codebrws.asp", port:port);
res = http_keepalive_send_recv(data:req, port:port);
if ("View Active Server Page Source" >< res)
{
    security_hole(port);
}
