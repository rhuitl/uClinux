#
# This script was written by Josh Zlatin-Amishav <josh at ramat dot cc>
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(19499);
 script_bugtraq_id(14348, 14350);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"18143");
   script_xref(name:"OSVDB", value:"18144");
   script_xref(name:"OSVDB", value:"18145");
   script_xref(name:"OSVDB", value:"18146");
   script_xref(name:"OSVDB", value:"18147");
 }
 script_version ("$Revision: 1.3 $");

 name["english"] = "Ultimate PHP Board multiple XSS vulnerabilities";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running Ultimate PHP Board (UPB).

The remote version of this software is affected by several
cross-site scripting vulnerabilities. This issue is due to a failure 
of the application to properly sanitize user-supplied input.

See also : http://www.retrogod.altervista.org/upbgold196xssurlspoc.txt
           http://securityfocus.com/archive/1/402461
           http://www.retrogod.altervista.org/upbgold196poc.php.txt
Solution : Unknown at this time 
Risk factor : Medium";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for XSS in send.php";

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
xss = "<script>alert(" + SCRIPT_NAME + ")</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
 req = http_get(
   item:string(
     dir, "/chat/send.php?css=",
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
