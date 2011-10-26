#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# Fixed by Tenable:
#  - Improved description
#  - Adjusted XSS regex.
#
# This script is released under the GNU GPLv2
#

if (description)
{
 script_id(18359);
 script_cve_id("CVE-2005-1183");
 script_bugtraq_id(13213);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"15760");
 }
 script_version ("$Revision: 1.4 $");

 script_name(english:"MVNForum Search Cross-Site Scripting Vulnerability");
 desc["english"] = "
The version of mvnForum installed on the remote host is prone to
cross-site scripting attacks due to its failure to sanitize
user-supplied input to the search field. 

Solution: Unknown at this time.
Risk factor : Low";

 script_description(english:desc["english"]);
 script_summary(english:"MVNForum Search Cross-Site Scripting Vulnerability");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"Copyright (C) 2005 Josh Zlatin-Amishav");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);

function check(url)
{
 req = http_get(item:url +"/search=%3Cscript%3Ealert('XSS')%3C/script%3E", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(0);
 if ( "matching entry in OnlineMember for '/search=<script>alert('XSS'" >< res )
 {
        security_warning(port);
        exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(url:dir);
}
