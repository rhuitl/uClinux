#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(18289);
 script_bugtraq_id(13650);
 script_version ("$Revision: 1.3 $");

 name["english"] = "JGS-Portal Multiple XSS and SQL injection Vulnerabilities";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running the JGS-Portal, a web portal written in PHP.

The remote version of this software contains an input validation flaw leading
multiple SQL injection and XSS vulnerabilities. An attacker may exploit these 
flaws to execute arbirtrary SQL commands against the remote database and to 
cause arbitrary code execution for third party users.

Solution : Unknown at this time
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "JGS-Portal Multiple XSS and SQL injection Vulnerabilities";

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
if ( ! can_host_php(port:port) ) exit(0);

function check(url)
{
 req = http_get(item:url + "/jgs_portal_statistik.php?meinaction=themen&month=1&year=1'", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if (("SQL-DATABASE ERROR" >< res ) && ("SELECT starttime FROM bb1_threads WHERE FROM_UNIXTIME" >< res ))
 {
     security_hole(port);
     exit(0);
 }
}

foreach dir ( make_list (cgi_dirs()) )
{
  check(url:dir);
}
