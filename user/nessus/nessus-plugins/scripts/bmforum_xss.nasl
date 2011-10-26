#
# This script was written by Josh Zlatin-Amishav <josh at ramat dot cc>
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(19500);
 script_bugtraq_id(14396);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"18306");
   script_xref(name:"OSVDB", value:"18307");
   script_xref(name:"OSVDB", value:"18308");
   script_xref(name:"OSVDB", value:"18309");
   script_xref(name:"OSVDB", value:"18310");
   script_xref(name:"OSVDB", value:"18311");
   script_xref(name:"OSVDB", value:"18312");
   script_xref(name:"OSVDB", value:"18313");
   script_xref(name:"OSVDB", value:"18314");
 }
 script_version ("$Revision: 1.4 $");

 name["english"] = "BMForum multiple XSS flaws";
 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The remote web server contains a PHP script which is vulnerable to a 
cross site scripting issue.


Description : 

The remote host is running BMForum, a web forum written in PHP.

The remote version of this software is affected by several cross-site
scripting vulnerabilities.  The issues are due to failures of the
application to properly sanitize user-supplied input. 

See also : 

http://lostmon.blogspot.com/2005/07/multiple-cross-site-scripting-in.html

Solution : 

Unknown at this time 

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for XSS in topic.php";

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
include("url_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);
if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);

# A simple alert.
xss = '"><script>alert(" + SCRIPT_NAME + ")</script>';
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
 req = http_get(
   item:string(
     dir, "/topic.php?filename=1",
     exss
   ), 
   port:port
 );


 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if ( xss >< res )
 {
        security_note(port);
        exit(0);
 }
}
