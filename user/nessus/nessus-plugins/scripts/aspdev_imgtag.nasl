#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# Fixed by Tenable:
#  - Improved description
#  - Adjusted version regex.
#  - Streamlined code.

#
# This script is released under the GNU GPLv2
#


if(description)
{
 script_id(18357);
 script_cve_id("CVE-2005-1008");
 script_bugtraq_id(12958);
 script_version("$Revision: 1.7 $");
 name["english"] = "ASP-DEv XM Forum IMG Tag Script Injection Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains an ASP script which is vulnerable to a
cross site scripting issue.

Description :

The remote host appears to be running the ASP-DEV XM Forum.

There is a flaw in the remote software which may allow anyone
to inject arbitrary HTML and script code through the BBCode IMG tag
to be executed in a user's browser within the context of the affected
web site.

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "ASP-DEV XM Forum IMG Tag Script Injection Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"Copyright (C) 2005 Josh Zlatin-Amishav");
 script_family(english:"CGI abuses : XSS");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if (!can_host_asp(port:port)) exit(0);

function check(url)
{
 req = http_get(item:url +"/default.asp", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(0);
 if ( res =~ '<a href="http://www\\.asp-dev\\.com">Powered by ASP-DEv XM Forums RC [123]<' )
 {
        security_note(port);
        exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
  check(url:dir);
}

