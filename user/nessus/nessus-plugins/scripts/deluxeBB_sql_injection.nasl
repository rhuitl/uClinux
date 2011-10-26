#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: abducter
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(19750);
 script_cve_id("CVE-2005-2989");
 script_bugtraq_id(14851);
 script_version("$Revision: 1.4 $");
 
 name["english"] = "DeluxeBB Multiple SQL injection flaws";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using DeluxeBB, a web application forum
written in PHP.

Multiple vulnerabilities exist in this version which may allow 
an attacker to execute arbitrary SQL queries against the
database.

Solution : Upgrade to the latest version of this software.
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks DeluxeBB version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if ( !get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/topic.php?tid='select"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if (("Error querying the database" >< r) && ("DeluxeBB tried to execute: SELECT" >< r))
 {
   security_warning(port);
   exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}
