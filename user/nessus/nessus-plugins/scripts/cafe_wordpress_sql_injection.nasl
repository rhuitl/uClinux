#
# This script is (C) Tenable Network Security
#
#
# Ref:
#
# From: Seth Woolley <seth@tautology.org>
# To: bugtraq@securityfocus.com
# Cc: full-disclosure@lists.netsys.com
# Subject: Cafelog WordPress / b2 SQL injection vulnerabilities discovered and
#   fixed in CVS



if(description)
{
 script_id(11866);
 
 script_version ("$Revision: 1.7 $");

 name["english"] = "Cafe Wordpress SQL injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to execute arbitrary SQL commands on the remote host
by using the Cafe WordPress CGI suite.

An attacker may exploit this flaw to read the content of the remote 
database and gain further access on this host.


Solution : Upgrade to the latest version
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of cafe wordpress";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
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
if(!can_host_php(port:port)) exit(0);



function check(loc)
{
 req = http_get(item:string(loc, "/index.php?cat='"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:"SQL.*post_date <=", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}



dirs = make_list(cgi_dirs());


foreach dir (dirs)
{
 check(loc:dir);
}
