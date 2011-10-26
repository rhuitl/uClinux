#
# (C) Ami Chayun GPLv2
#

if(description)
{
 script_id(16086);
 script_version("$Revision: 1.4 $");
 script_cve_id("CVE-2004-1430");
 script_bugtraq_id(12138);
 
 name["english"] = "IBProArcade index.php SQL Injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running ibProArcade a web based score board system written 
in PHP.

One of the application's CGIs, index.php, is vulnerable to an SQL injection 
vulnerability in the 'gameid' parameter. An attacker may exploit this flaw to 
execute arbitrary SQL statements against the remote database.

Solution : Upgrade to the newest version of this program
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an SQL injection in index.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Ami Chayun");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
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

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/index.php?act=Arcade&do=stats&gameid=1'"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if( "SELECT COUNT(s_id) AS amount FROM ibf_games_scores" >< r )
 {
 	security_hole(port);
	exit(0);
 }
}


foreach dir (cgi_dirs())
{
 check(loc:dir);
}

