#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(18290);
 script_bugtraq_id(13385, 13384, 13383, 13382, 13639);
 script_version ("$Revision: 1.2 $");

 name["english"] = "MetaCart E-Shop ProductsByCategory.ASP SQL and XSS Injection Vulnerabilities";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running the MetaCart e-Shop, an online store written in ASP.

Due to a lack of user input validation, the remote version of this software is vulnerable
to various SQL injection vulnerabilities and cross site scripting attacks.

An attacker may exploit these flaws to execute arbitrary SQL commands against the remote
database or to perform a cross site scripting attack using the remote host.

Solution : None at this time
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "MetaCart E-Shop ProductsByCategory.ASP XSS and SQL injection Vulnerabilities";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_family(english:"CGI abuses");
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
if ( ! can_host_asp(port:port) ) exit(0);

function check(url)
{
 req = http_get(item:url +"/productsByCategory.asp?intCatalogID=3'&strCatalog_NAME=Nessus", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 # Check for the SQL injection
 if ("80040e14" >< res && "cat_ID = 3'" >< res )
 {
     security_hole(port);
     exit(0);
 }
}

foreach dir ( make_list (cgi_dirs()) )
{
  check(url:dir);
}
