#
# This script was written by Josh Zlatin-Amishav <josh at ramat doti cc>
#
# This script is released under the GNU GPLv2


if(description)
{
 script_id(19603);
 script_cve_id("CVE-2005-2788", "CVE-2005-2884");
 script_bugtraq_id(14685, 14746, 14820);
 script_version ("$Revision: 1.6 $");

 name["english"] = "Land Down Under <= 801 Multiple Vulnerabilities";
 script_name(english:name["english"]);

 desc["english"] = "
Synopsis : 

The remote web server contains several PHP scripts that permit SQL
injection and cross-site scripting attacks. 

Description :

The remote version of Land Down Under is prone to several SQL injection
and cross-site scripting attacks due to its failure to sanitize
user-supplied input to several parameters used by the 'events.php',
'index.php', and 'list.php' scripts.  A malicious user can exploit
exploit these flaws to manipulate SQL queries, steal authentication
cookies, and the like. 

See also : 

http://securityfocus.com/archive/1/409511
http://www.packetstormsecurity.org/0509-advisories/LDU801.txt

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:H/Au:NR/C:P/A:N/I:P/B:N)";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for SQL injection in LDU's list.php";

 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);

 script_family(english:"CGI abuses");
 script_copyright(english:"Copyright (C) 2005 Josh Zlatin-Amishav");
 script_dependencie("ldu_detection.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/ldu"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 req = http_get(
   item:string(
     dir, "/list.php?",
     "c='&s=title&w=asc&o=", 
     SCRIPT_NAME, 
     "&p=1"
   ), 
   port:port
 );
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if 
 ( 
   "MySQL error" >< res && 
   egrep(string:res, pattern:string("syntax to use near '(asc&o=|0.+page_", SCRIPT_NAME, ")"))
 )
 {
        security_warning(port);
        exit(0);
 }
}
