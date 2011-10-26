#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11395);
 script_bugtraq_id(1594, 1595);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2000-0746");

 name["english"] = "Microsoft Frontpage XSS";
 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The remote web server is vulnerable to a cross site scripting attack.

Description :

The remote web server is running with Front Page extensions.
The remote version of the FrontPage extensions are vulnerable to 
a cross site scripting issue when the CGI /_vti_bin/shtml.dll is 
provided with improper parameters.

Solution : 

http://www.microsoft.com/technet/security/bulletin/ms00-060.mspx

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";



 script_description(english:desc["english"]);

 summary["english"] = "Checks for the presence of a Frontpage XSS";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if ( banner && "IIS" >!< banner ) exit(0);


req = http_get(item:"/_vti_bin/shtml.dll/<script>alert(document.domain)</script>", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if( res == NULL ) exit(0);

if("<script>alert(document.domain)</script>" >< res)security_note(port);
