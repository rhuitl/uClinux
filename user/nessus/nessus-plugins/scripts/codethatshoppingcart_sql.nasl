#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(18255);
 script_cve_id("CVE-2005-1593", "CVE-2005-1594", "CVE-2005-1595");
 script_bugtraq_id(13560);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"16155");
   script_xref(name:"OSVDB", value:"16156");
   script_xref(name:"OSVDB", value:"16157");
 }
 script_version ("$Revision: 1.4 $");

 name["english"] = "CodeThatShoppingCart Input Validation Vulnerabilities";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running the CodeThat.com ShoppingCart, a shopping cart 
program written in PHP.

The remote version of this software contains an input validation flaw leading
to a SQL injection vulnerability. An attacker may exploit this flaw to execute
arbitrary commands against the remote database.

Solution : Unknown at this time
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for an SQL injection in CodeThatShoppingCart";

 script_summary(english:summary["english"]);

 script_family(english:"CGI abuses");
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"Copyright (C) 2005 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

function check(url)
{
 req = http_get(item:url +"/catalog.php?action=category_show&id='", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( "select id from products P, category_products CP where P.id=CP.product_id and CP.category_id=" >< res )
 {
        security_hole(port);
        exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
  check(url:dir);
}


