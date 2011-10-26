#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#
# Fixed by Tenable:
#   - added CVE and OSVDB xrefs.
#   - added See also.
#   - lowered Risk Factor from Medium.
#   - changed exploit from SQL injection to XSS, which is what these BIDs cover.


if(description)
{
 script_id(19392);
 script_cve_id("CVE-2005-2324", "CVE-2005-2325", "CVE-2005-2326");
 script_bugtraq_id(14278, 14395, 14397);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"17919");
   script_xref(name:"OSVDB", value:"18349");
   script_xref(name:"OSVDB", value:"18350");
   script_xref(name:"OSVDB", value:"18351");
   script_xref(name:"OSVDB", value:"18352");
   script_xref(name:"OSVDB", value:"18353");
   script_xref(name:"OSVDB", value:"18354");
   script_xref(name:"OSVDB", value:"18355");
   script_xref(name:"OSVDB", value:"18356");
   script_xref(name:"OSVDB", value:"18357");
   script_xref(name:"OSVDB", value:"18358");
   script_xref(name:"OSVDB", value:"18359");
   script_xref(name:"OSVDB", value:"18360");
   script_xref(name:"OSVDB", value:"18361");
   script_xref(name:"OSVDB", value:"18509");
 }
 script_version ("$Revision: 1.6 $");

 name["english"] = "Multiple vulnerabilities in Clever Copy";
 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple issues. 

Description :

The remote host is running Clever Copy, a free, fully-scalable web
site portal and news posting system written in PHP

The remote version of this software contains multiple vulnerabilities
that can lead to path disclosure, cross-site scripting and
unauthorized access to private messages

See also : 

http://lostmon.blogspot.com/2005/07/clever-copy-calendarphp-yr-variable.html
http://lostmon.blogspot.com/2005/07/clever-copy-path-disclosure-and-xss.html
http://lostmon.blogspot.com/2005/07/clever-copy-unauthorized-read-delete.html

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for XSS in results.php";

 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);

 script_family(english:"CGI abuses");
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
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
 req = http_get(
   item:string(
     dir, "/results.php?",
     'searchtype=">', exss, "category&",
     "searchterm=Nessus"
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
