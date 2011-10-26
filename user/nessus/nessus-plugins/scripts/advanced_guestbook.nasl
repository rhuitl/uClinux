#
# This script was written by Josh Zlatin-Amishav
#
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(18217);
 script_cve_id("CVE-2005-1548");
 script_bugtraq_id(13548);
 script_version("$Revision: 1.6 $");

 name["english"] = "Advanced Guestbook Index.PHP SQL Injection Vulnerability";

 script_name(english:name["english"]);
 script_version ("$Revision: 1.6 $");

 desc["english"] = "
The remote host is running Advanced Guestbook - a guestbook written in PHP.

The remote version of this software contains an input validation flaw leading
to a SQL injection vulnerability. An attacker may exploit this flaw to execute
arbirtrary commands against the remote database.


Solution : Upgrade to the newest version of this software
Risk factor : High";



 script_description(english:desc["english"]);

 summary["english"] = "Checks for an SQL injection attack in Advanced Guestbook ";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_family(english:"CGI abuses");
 script_copyright(english:"english:Copyright (C) 2005 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

function check(url)
{
 req = http_get(item:url +"/index.php?entry='", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if (  "Query Error" >< res && '1064 You have an error in your SQL syntax.' >< res  )
 {
        security_hole(port);
        exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
  check(url:dir);
}


