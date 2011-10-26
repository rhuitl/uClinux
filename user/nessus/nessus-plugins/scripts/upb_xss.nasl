#
# This script was written by Josh Zlatin-Amishav <josh at ramat dot cc>
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(19498);

 script_cve_id("CVE-2005-2004");
 script_bugtraq_id(13971);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"17365");
   script_xref(name:"OSVDB", value:"17366");
   script_xref(name:"OSVDB", value:"17367");
   script_xref(name:"OSVDB", value:"17368");
   script_xref(name:"OSVDB", value:"17369");
   script_xref(name:"OSVDB", value:"17370");
   script_xref(name:"OSVDB", value:"17371");
   script_xref(name:"OSVDB", value:"17372");
   script_xref(name:"OSVDB", value:"17373");
 }
 script_version ("$Revision: 1.4 $");

 name["english"] = "Ultimate PHP Board multiple XSS flaws";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running Ultimate PHP Board (UPB).

The remote version of this software is affected by several cross-site
scripting vulnerabilities.  These issues are due to a failure of the
application to properly sanitize user-supplied input. 

See also : http://www.myupb.com/forum/viewtopic.php?id=26&t_id=118
           http://securityfocus.com/archive/1/402461 
Solution : Install vendor patch 
Risk factor : Medium";

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
include("url_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);
if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);

# A simple alert.
xss = "'><script>alert(" + SCRIPT_NAME + ")</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
 req = http_get(
   item:string(
     dir, "/login.php?ref=",
     exss
   ), 
   port:port
 );


 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if ( xss >< res )
 {
        security_warning(port);
        exit(0);
 }
}
