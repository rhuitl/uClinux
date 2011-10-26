#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(18254);
 script_cve_id("CVE-2005-1373");
 script_bugtraq_id(13412, 13413);
 script_version ("$Revision: 1.4 $");

 name["english"] = "Dream4 Koobi CMS Index.PHP SQL Injection Vulnerability";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running the Dream4 Koobi CMS, a CMS written in PHP.

The remote version of this software contains an input validation flaw leading
to a SQL injection vulnerability. An attacker may exploit this flaw to execute
arbirtrary SQL commands against the remote database.

Solution : None at this time.
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for an SQL injection in the Koobi CMS";

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

function check(url)
{
 req = http_get(item:url +"/index.php?p='nessus", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( 'KOOBI-ERROR' >< res && egrep(pattern:"SQL.*MySQL.* 'nessus", string:res) )
 {
        security_hole(port);
        exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
  check(url:dir);
}


