#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(18375);
 script_version ("$Revision: 1.6 $");

 script_cve_id("CVE-2005-1782", "CVE-2005-1783");
 script_bugtraq_id(13783);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"16871");
  script_xref(name:"OSVDB", value:"16872");
  script_xref(name:"OSVDB", value:"16873");
  script_xref(name:"OSVDB", value:"16874");
  script_xref(name:"OSVDB", value:"16875");
  script_xref(name:"OSVDB", value:"16876");
  script_xref(name:"OSVDB", value:"16877");
  script_xref(name:"OSVDB", value:"16878");
  script_xref(name:"OSVDB", value:"16879");
  script_xref(name:"OSVDB", value:"16880");
  script_xref(name:"OSVDB", value:"16881");
 }

 name["english"] = "BookReview Multiple Cross-Site Scripting Vulnerabilities";
 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The remote web server contains a CGI which is vulnerable to multiple
cross site scripting vulnerabilities. 

Description :

The remote host is running the BookReview software. 

The remote version of this software is vulnerable to multiple
cross-site scripting vulnerabilities due to a lack of sanitization of
user-supplied data. 

Successful exploitation of this issue may allow an attacker to use the
remote server to perform an attack against a third-party user. 

See also :

http://lostmon.blogspot.com/2005/05/bookreview-10-multiple-variable-xss.html

Solution :

None at this time

Risk factor :

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for unathentication access to admin.asp";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"Copyright (C) 2005 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);

function check(url)
{
 req = http_get(item:url +"/add_url.htm?node=%3Cscript%3Ealert('XSS')%3C/script%3E", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( "<script>alert('XSS')</script>XSS" >< res && 'Powered by BookReview' >< res )
 {
        security_note(port);
        exit(0);
 }
}

foreach dir ( cgi_dirs() )
  check(url:dir);
