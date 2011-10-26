#
# This script was written by Tenable Network Security
#

if(description)
{
 script_id(16275);
 script_bugtraq_id(12392); 
 script_version ("$Revision: 1.3 $");

 name["english"] = "CoolForum SQL Injection flaw";

 script_name(english:name["english"]);
 
 desc["english"] = "
There is a flaw in the remote CoolForum, a bulletin board written in PHP.

This version of CoolForum is vulnerable to a remote SQL Injection attack.
An attacker, exploiting this flaw, would be able to manipulate data and
execute commands on the remote system.

Solution: Upgrade to CoolForum 0.7.3 or higher

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of CoolForum";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
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

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/index.php"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if ( egrep(pattern:"Powered by <b>CoolForum v\.0\.([0-6]\..*|7\.[0-2])", string:r) ) 
 {
   security_hole(port);
   exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

